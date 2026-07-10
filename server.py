import os
import json
import asyncio
import subprocess
import base64
import re
import socket
import ssl
import sys
import shutil
import signal
import uuid
from http.cookies import SimpleCookie
from contextlib import suppress
from datetime import datetime, timedelta
from urllib.parse import quote, unquote, urljoin, urlsplit
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field
import glob
import httpx

import adobe_admin
import firefly_protocol

app = FastAPI()

# Config storage
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv("DATA_DIR", APP_DIR)
SCREENSHOT_DIR = os.path.join(DATA_DIR, "screenshots")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
TASKS_FILE = os.path.join(DATA_DIR, "tasks.json")
TASK_LOG_DIR = os.path.join(DATA_DIR, "task_logs")
CHILD_ACCOUNTS_FILE = os.path.join(DATA_DIR, "child_accounts.json")
CHILD_MONITOR_LOG_FILE = os.path.join(DATA_DIR, "child_monitor_logs.json")
CHILD_MONITOR_LOG_RETENTION_SECONDS = 12 * 60 * 60
CHILD_MONITOR_LOG_MAX_ITEMS = 500
os.makedirs(SCREENSHOT_DIR, exist_ok=True)
os.makedirs(TASK_LOG_DIR, exist_ok=True)

DEFAULT_CONFIG = {
    "api_key": "",
    "api_base": "https://rossa.cfd/api",
    "email_domain": "rossa.cfd",
    "email_domains": "rossa.cfd",
    "yescaptcha_key": "",
    "proxy_enabled": False,
    "proxy_scheme": "http",
    "proxy_url": "",
    "adobe_proxy_enabled": False,
    "adobe_proxy_scheme": "http",
    "adobe_proxy_url": "",
    "token_pool_enabled": False,
    "token_pool_site": "",
    "token_pool_key": "",
    "token_pools": [],
    "token_pool_cursor": 0,
    "child_monitor_enabled": False,
    "child_monitor_threshold": 100,
    "child_monitor_interval": 600,
    "child_monitor_max_failures": 3,
    "child_monitor_pool_ids": [],
    "self_email_accounts": "",
    "self_email_cursor": 0,
    "self_email_used": [],
    "adobe_accounts": [],
}

ADOBE_INVITE_PRODUCT_NAMES = (
    "Creative Cloud Pro",
    "Complimentary Membership Teams",
)

WORKER_TIMEOUT_SECONDS = max(180, int(os.getenv("WORKER_TIMEOUT_SECONDS", "900")))
INVITE_EMAIL_WAIT_SECONDS = max(0, int(os.getenv("INVITE_EMAIL_WAIT_SECONDS", "300")))
STALE_PROFILE_SECONDS = max(300, int(os.getenv("STALE_PROFILE_SECONDS", "1800")))
PROFILE_PREFIX = "chrome_profile_"
ADMIN_USERNAME = "link"
ADMIN_PASSWORD = "199887"
LOGIN_PATH = "/login"
LOGIN_API_PATH = "/api/login"
LOGOUT_API_PATH = "/api/logout"
PUBLIC_PATHS = {
    LOGIN_PATH,
    LOGIN_API_PATH,
    LOGOUT_API_PATH,
    "/favicon.ico",
    "/style.css",
    "/app.js",
    "/login.html",
}


def extract_task_id_from_log(message: str) -> int | None:
    for pattern in (
        r"\[任务#(\d+)(?:[-\s·\]])",
        r"任务\s*#(\d+)",
        r"\[Task#(\d+)(?:[-:\s\]])",
        r"Task\s*#(\d+)",
        r"#(\d+)",
    ):
        try:
            match = re.search(pattern, message)
        except re.error:
            continue
        if match:
            return int(match.group(1))
    return None


def task_log_path(task_id: int) -> str:
    return os.path.join(TASK_LOG_DIR, f"task_{task_id}.log")


def append_task_log(task_id: int, message: str):
    timestamp = datetime.now().strftime("%H:%M:%S")
    with open(task_log_path(task_id), "a", encoding="utf-8") as log_file:
        log_file.write(f"[{timestamp}] {message}\n")


def read_task_logs(task_id: int, limit: int | None = None) -> list[str]:
    path = task_log_path(task_id)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as log_file:
        lines = [line.rstrip("\r\n") for line in log_file]
    if limit is None:
        return lines
    return lines[-max(1, limit):]


def is_authenticated(request: Request) -> bool:
    session = request.scope.get("session")
    if not isinstance(session, dict):
        return False
    return bool(session.get("admin_authenticated"))


class AdminAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in PUBLIC_PATHS:
            if path == LOGIN_PATH and is_authenticated(request):
                return RedirectResponse(url="/", status_code=302)
            return await call_next(request)

        if not is_authenticated(request):
            if path.startswith("/api/"):
                return JSONResponse(status_code=401, content={"error": "unauthorized"})
            return RedirectResponse(url=LOGIN_PATH, status_code=302)

        return await call_next(request)


app.add_middleware(AdminAuthMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "firefly-admin-session-secret"),
    max_age=60 * 60 * 12,
)

def normalize_proxy(proxy_url: str, proxy_scheme: str = "http") -> dict:
    raw = (proxy_url or "").strip()
    scheme = (proxy_scheme or "http").strip().lower()
    if scheme not in ("http", "https", "socks5"):
        scheme = "http"
    if not raw:
        raise ValueError("请填写代理地址")

    target = raw if "://" in raw else f"{scheme}://{raw}"
    parsed = urlsplit(target)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https", "socks5"):
        raise ValueError("仅支持 http、https、socks5 代理")

    host = parsed.hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")

    if (not host or not port) and "://" not in raw:
        if "@" in raw:
            left, right = raw.split("@", 1)
            left_parts = left.split(":")
            right_parts = right.split(":")
            if len(left_parts) >= 2 and left_parts[1].isdigit():
                host, port = left_parts[0], int(left_parts[1])
                username = right_parts[0] if len(right_parts) > 0 else ""
                password = ":".join(right_parts[1:]) if len(right_parts) > 1 else ""
            elif len(right_parts) >= 2 and right_parts[-1].isdigit():
                username = left_parts[0] if len(left_parts) > 0 else ""
                password = ":".join(left_parts[1:]) if len(left_parts) > 1 else ""
                host, port = ":".join(right_parts[:-1]), int(right_parts[-1])
        else:
            parts = raw.split(":")
            if len(parts) >= 4 and parts[1].isdigit():
                host, port = parts[0], int(parts[1])
                username = parts[2]
                password = ":".join(parts[3:])
            elif len(parts) == 2 and parts[1].isdigit():
                host, port = parts[0], int(parts[1])

    if not host or not port:
        raise ValueError("代理格式错误，请参考示例填写")

    auth = f"{username}:{password}@" if username or password else ""
    server = f"{scheme}://{host}:{port}"
    url = f"{scheme}://{auth}{host}:{port}"
    return {
        "scheme": scheme,
        "host": host,
        "port": int(port),
        "username": username,
        "password": password,
        "server": server,
        "url": url,
    }


def adobe_proxy_config() -> dict | None:
    if not config.get("adobe_proxy_enabled"):
        return None
    return normalize_proxy(
        config.get("adobe_proxy_url", ""),
        config.get("adobe_proxy_scheme", "http"),
    )


def adobe_httpx_client(**kwargs) -> httpx.AsyncClient:
    proxy = adobe_proxy_config()
    if proxy:
        kwargs["proxy"] = proxy["url"]
    return httpx.AsyncClient(**kwargs)


def adobe_playwright_proxy() -> dict | None:
    proxy = adobe_proxy_config()
    if not proxy:
        return None
    result = {"server": proxy["server"]}
    if proxy["username"]:
        result["username"] = proxy["username"]
    if proxy["password"]:
        result["password"] = proxy["password"]
    return result


def _proxy_auth_header(username: str, password: str) -> str:
    if not username and not password:
        return ""
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Proxy-Authorization: Basic {token}\r\n"

def _test_http_proxy(proxy: dict) -> tuple[bool, str]:
    sock = socket.create_connection((proxy["host"], proxy["port"]), timeout=8)
    if proxy["scheme"] == "https":
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=proxy["host"])
    with sock:
        sock.settimeout(8)
        req = (
            "CONNECT www.adobe.com:443 HTTP/1.1\r\n"
            "Host: www.adobe.com:443\r\n"
            f"{_proxy_auth_header(proxy['username'], proxy['password'])}"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode())
        data = sock.recv(1024).decode("iso-8859-1", errors="ignore")
        status = data.splitlines()[0] if data else ""
        if not status.startswith("HTTP/"):
            return False, "代理未返回有效 HTTP 响应"
        code = int(status.split()[1])
        if code == 200:
            tunnel = ssl.create_default_context().wrap_socket(sock, server_hostname="www.adobe.com")
            tunnel.sendall(b"HEAD / HTTP/1.1\r\nHost: www.adobe.com\r\nConnection: close\r\n\r\n")
            target_data = tunnel.recv(1024).decode("iso-8859-1", errors="ignore")
            target_status = target_data.splitlines()[0] if target_data else ""
            if target_status.startswith("HTTP/"):
                return True, f"代理可用，已连通 Adobe HTTPS ({target_status})"
            return True, "代理可用，HTTPS 隧道已建立"

    if status.startswith("HTTP/"):
        code = int(status.split()[1])
        if code == 407:
            return False, "代理需要认证，用户名或密码可能不正确"
        if code == 403:
            return False, "代理拒绝建立 HTTPS 隧道 (403)，请检查 IP 白名单、套餐权限、协议或端口"
        return False, f"代理连通但建立 HTTPS 隧道失败，状态码 {code}"
    return False, "代理未返回有效 HTTP 响应"

def _test_socks5_proxy(proxy: dict) -> tuple[bool, str]:
    with socket.create_connection((proxy["host"], proxy["port"]), timeout=8) as sock:
        sock.settimeout(8)
        methods = [0x00]
        if proxy["username"] or proxy["password"]:
            methods.append(0x02)
        sock.sendall(bytes([0x05, len(methods), *methods]))
        resp = sock.recv(2)
        if len(resp) < 2 or resp[0] != 0x05:
            if resp.startswith(b"H"):
                return False, "当前端口返回 HTTP 响应，不是 SOCKS5；请改选 http/https 或更换 SOCKS5 端口"
            return False, f"SOCKS5 握手失败，代理返回: {resp.hex() or '空响应'}"
        if resp[1] == 0xFF:
            return False, "SOCKS5 代理不接受当前认证方式"
        if resp[1] == 0x02:
            username = proxy["username"].encode()
            password = proxy["password"].encode()
            if len(username) > 255 or len(password) > 255:
                return False, "SOCKS5 用户名或密码过长"
            sock.sendall(bytes([0x01, len(username)]) + username + bytes([len(password)]) + password)
            auth = sock.recv(2)
            if len(auth) < 2 or auth[1] != 0x00:
                return False, "SOCKS5 用户名或密码错误"

        host = b"example.com"
        sock.sendall(bytes([0x05, 0x01, 0x00, 0x03, len(host)]) + host + (80).to_bytes(2, "big"))
        resp = sock.recv(10)
        if len(resp) < 2 or resp[1] != 0x00:
            return False, f"SOCKS5 连接目标站点失败，错误码 {resp[1] if len(resp) > 1 else '未知'}"
        sock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        data = sock.recv(1024).decode("iso-8859-1", errors="ignore")
    return (True, "SOCKS5 代理可用") if data.startswith("HTTP/") else (False, "SOCKS5 已连接但目标站点响应异常")

def test_proxy_connectivity(proxy_url: str, proxy_scheme: str) -> tuple[bool, str, dict | None]:
    try:
        proxy = normalize_proxy(proxy_url, proxy_scheme)
        if proxy["scheme"] == "socks5":
            ok, message = _test_socks5_proxy(proxy)
        else:
            ok, message = _test_http_proxy(proxy)
        return ok, message, proxy
    except Exception as e:
        return False, f"代理检测失败: {e}", None

def load_config():
    if os.path.exists(CONFIG_FILE):
        data = json.load(open(CONFIG_FILE, "r", encoding="utf-8"))
        # 兼容旧配置：如果只有 email_domain 没有 email_domains，自动迁移
        if "email_domains" not in data and "email_domain" in data:
            data["email_domains"] = data["email_domain"]
        for key, value in DEFAULT_CONFIG.items():
            data.setdefault(key, value)
        return data
    return DEFAULT_CONFIG.copy()

def save_config(data: dict):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)

def resolve_data_file(path: str) -> str:
    if os.path.isabs(path):
        return path
    data_path = os.path.join(DATA_DIR, path)
    if os.path.exists(data_path):
        return data_path
    return path

def sanitize_filename(name: str, fallback: str = "导出文件") -> str:
    cleaned = re.sub(r'[\\/:*?"<>|]+', "_", (name or "").strip())
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" ._")
    return cleaned[:80] if cleaned else fallback

def export_timestamp() -> str:
    return datetime.now().strftime("%m-%d_%H-%M")

config = load_config()
self_email_lock = asyncio.Lock()
self_email_reserved = set()
adobe_account_lock = asyncio.Lock()
token_pool_lock = asyncio.Lock()
child_accounts_lock = asyncio.Lock()
child_monitor_task: asyncio.Task | None = None
child_replacement_locks: dict[str, asyncio.Lock] = {}

# ─── Task Management ───
class Task:
    def __init__(
        self,
        task_id,
        quantity,
        concurrency=1,
        show_browser=False,
        name="",
        email_source="temp",
        registration_mode="standard",
        adobe_account_ids=None,
        batch_quantity=None,
        invite_remove_members=True,
    ):
        self.id = task_id
        self.quantity = quantity
        self.batch_quantity = batch_quantity or quantity
        self.concurrency = concurrency
        self.show_browser = show_browser
        self.email_source = email_source if email_source in ("temp", "self") else "temp"
        self.registration_mode = registration_mode if registration_mode in ("standard", "invite") else "standard"
        self.adobe_account_ids = list(adobe_account_ids or [])
        self.invite_remove_members = bool(invite_remove_members)
        self.name = (name or "").strip() or f"任务 #{task_id}"
        self.status = "pending"     # pending -> running -> stopping -> completed/stopped
        self.completed = 0
        self.failed = 0
        self.token_pool_imported = 0
        self.token_pool_imported_files = []
        self.created_at = datetime.now().strftime("%m-%d %H:%M")
        self.result_files = []
        self.replacement_child_id = ""
        self.replacement_child_ids = []
        self.replacement_done_child_ids = []
        self.asyncio_tasks = []
        self.active_processes = {}
        self.active_profiles = {}

    def to_dict(self):
        return {
            "id": self.id,
            "quantity": self.quantity,
            "batch_quantity": self.batch_quantity,
            "concurrency": self.concurrency,
            "show_browser": self.show_browser,
            "email_source": self.email_source,
            "registration_mode": self.registration_mode,
            "adobe_account_ids": self.adobe_account_ids,
            "invite_remove_members": self.invite_remove_members,
            "name": self.name,
            "status": self.status,
            "completed": self.completed,
            "failed": self.failed,
            "token_pool_imported": self.token_pool_imported,
            "token_pool_imported_files": self.token_pool_imported_files,
            "token_pool_unpooled": max(0, len(self.result_files) - len(self.token_pool_imported_files))
                if self.token_pool_imported_files
                else max(0, len(self.result_files) - self.token_pool_imported),
            "created_at": self.created_at,
            "result_count": len(self.result_files),
            "result_files": self.result_files,
            "replacement_child_id": self.replacement_child_id,
            "replacement_child_ids": self.replacement_child_ids,
            "replacement_done_child_ids": self.replacement_done_child_ids,
        }


def collect_active_profile_paths(tasks: dict[int, "Task"]) -> set[str]:
    active = set()
    for task in tasks.values():
        active.update(task.active_profiles.values())
    return active


def consume_replacement_child_id(task: Task) -> str:
    pending = list(getattr(task, "replacement_child_ids", []) or [])
    if not pending and getattr(task, "replacement_child_id", ""):
        pending = [task.replacement_child_id]
    if not pending:
        task.replacement_child_id = ""
        return ""
    child_id = pending.pop(0)
    done = list(getattr(task, "replacement_done_child_ids", []) or [])
    done.append(child_id)
    task.replacement_child_ids = pending
    task.replacement_done_child_ids = done
    task.replacement_child_id = pending[0] if pending else ""
    return child_id


async def prepare_replacement_children_for_task(task: Task, account: dict, prefix: str) -> list[str]:
    child_ids = list(getattr(task, "replacement_child_ids", []) or [])
    if not child_ids and getattr(task, "replacement_child_id", ""):
        child_ids = [task.replacement_child_id]
    if not child_ids:
        return []

    records = await list_child_accounts_raw()
    prepared = []
    failed = []
    await task_manager.broadcast(f"{prefix} Step 0/3：准备从母号组织移除 {len(child_ids)} 个旧子号")
    for child_id in child_ids:
        record = find_child_record(records, child_id)
        if not record:
            failed.append(child_id)
            continue
        email = record.get("email", child_id)
        try:
            await update_child_account(child_id, status="replacing", failure_reason="", replacement_reason="补号任务执行中")
            await task_manager.broadcast(f"{prefix} Step 0/3：正在移除旧子号 {email}")
            removed = await remove_child_member(record, "补号任务执行中")
            prepared.append(removed.get("id", child_id))
            await task_manager.broadcast(f"{prefix} Step 0/3：已移除旧子号 {email}")
        except Exception as exc:
            failed.append(email)
            await update_child_account(child_id, status="active", failure_reason=f"补号任务移除失败：{exc}")
            await task_manager.broadcast(f"{prefix} ⚠️ 旧子号 {email} 移除失败，本次不补：{exc}")

    task.replacement_child_ids = prepared
    task.replacement_child_id = prepared[0] if prepared else ""
    if failed:
        await task_manager.broadcast(f"{prefix} Step 0/3：旧子号移除失败 {len(failed)} 个：{', '.join(failed)}")
    await task_manager.broadcast("__STATE_UPDATE__")
    return prepared


def cleanup_stale_profiles(active_paths: set[str] | None = None) -> int:
    active_paths = {os.path.abspath(path) for path in (active_paths or set())}
    removed = 0
    now = datetime.now().timestamp()

    for entry in os.listdir(APP_DIR):
        if not entry.startswith(PROFILE_PREFIX):
            continue
        path = os.path.abspath(os.path.join(APP_DIR, entry))
        if path in active_paths or not os.path.isdir(path):
            continue
        try:
            age_seconds = now - os.path.getmtime(path)
        except OSError:
            continue
        if age_seconds < STALE_PROFILE_SECONDS:
            continue
        try:
            shutil.rmtree(path, ignore_errors=False)
            removed += 1
        except Exception:
            continue
    return removed

class TaskManager:
    def __init__(self):
        self.tasks: dict[int, Task] = {}
        self.next_id = 1
        self.websockets = []
        self.queue = asyncio.Queue()
        self._worker_running = False
        self.load_tasks()

    def save_tasks(self):
        data = {
            "next_id": self.next_id,
            "tasks": [t.to_dict() for t in self.tasks.values()]
        }
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(TASKS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def load_tasks(self):
        if os.path.exists(TASKS_FILE):
            try:
                with open(TASKS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.next_id = data.get("next_id", 1)
                    for t_data in data.get("tasks", []):
                        t = Task(
                            t_data["id"],
                            t_data["quantity"],
                            t_data.get("concurrency", 1),
                            t_data.get("show_browser", False),
                            t_data.get("name", ""),
                            t_data.get("email_source", "temp"),
                            t_data.get("registration_mode", "standard"),
                            t_data.get("adobe_account_ids", []),
                            t_data.get("batch_quantity"),
                            t_data.get("invite_remove_members", True),
                        )
                        t.status = t_data["status"]
                        t.completed = t_data.get("completed", 0)
                        t.failed = t_data.get("failed", 0)
                        t.token_pool_imported = t_data.get("token_pool_imported", 0)
                        t.token_pool_imported_files = t_data.get("token_pool_imported_files", [])
                        t.created_at = t_data.get("created_at", "")
                        t.result_files = t_data.get("result_files", [])
                        t.replacement_child_id = t_data.get("replacement_child_id", "")
                        t.replacement_child_ids = t_data.get("replacement_child_ids", [])
                        if not t.replacement_child_ids and t.replacement_child_id:
                            t.replacement_child_ids = [t.replacement_child_id]
                        t.replacement_done_child_ids = t_data.get("replacement_done_child_ids", [])
                        # Mark interrupted tasks as stopped
                        if t.status in ("running", "pending", "stopping"):
                            t.status = "stopped"
                        self.tasks[t.id] = t
            except Exception as e:
                print(f"Failed to load tasks: {e}")

    def create_task(
        self,
        quantity,
        concurrency=1,
        show_browser=False,
        name="",
        email_source="temp",
        registration_mode="standard",
        adobe_account_ids=None,
        invite_remove_members=True,
    ) -> Task:
        account_ids = list(adobe_account_ids or [])
        total_quantity = quantity * len(account_ids) if registration_mode == "invite" else quantity
        task = Task(
            self.next_id,
            total_quantity,
            concurrency,
            show_browser,
            name,
            email_source,
            registration_mode,
            account_ids,
            quantity,
            invite_remove_members,
        )
        self.tasks[self.next_id] = task
        self.next_id += 1
        return task

    def delete_tasks(self, ids: list[int]):
        for tid in ids:
            if tid in self.tasks:
                t = self.tasks[tid]
                # Only delete non-running tasks
                if t.status not in ("running", "pending"):
                    del self.tasks[tid]
                    with suppress(OSError):
                        os.remove(task_log_path(tid))

    async def stop_tasks(self, ids: list[int]):
        for tid in ids:
            if tid in self.tasks:
                t = self.tasks[tid]
                if t.status == "pending":
                    t.status = "stopped"
                elif t.status == "running":
                    t.status = "stopping"
                    await self.broadcast(f"任务 #{tid} 已请求停止：正在进行的注册会先执行完，未开始的注册将跳过")

    async def broadcast(self, message: str):
        if message == "__STATE_UPDATE__":
            self.save_tasks()
        else:
            task_id = extract_task_id_from_log(message)
            if task_id:
                append_task_log(task_id, message)

        disconnected = []
        for ws in self.websockets:
            try:
                await ws.send_text(message)
            except WebSocketDisconnect:
                disconnected.append(ws)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            self.websockets.remove(ws)

    async def start_queue_worker(self):
        """Single worker that processes tasks from the queue one by one."""
        if self._worker_running:
            return
        self._worker_running = True
        try:
            while True:
                task = await self.queue.get()
                if task.status == "stopped":
                    self.queue.task_done()
                    continue
                try:
                    await run_task(task)
                except Exception as e:
                    await self.broadcast(f"❌ 任务 #{task.id} 异常: {e}")
                    task.status = "completed"
                finally:
                    self.queue.task_done()
        finally:
            self._worker_running = False

task_manager = TaskManager()

# ─── Models ───
class ConfigUpdate(BaseModel):
    api_key: str
    api_base: str
    email_domain: str = "rossa.cfd"
    email_domains: str = ""  # 逗号分隔的多域名列表
    yescaptcha_key: str = ""
    proxy_enabled: bool = False
    proxy_scheme: str = "http"
    proxy_url: str = ""
    adobe_proxy_enabled: bool = False
    adobe_proxy_scheme: str = "http"
    adobe_proxy_url: str = ""
    token_pool_enabled: bool = False
    token_pool_site: str = ""
    token_pool_key: str = ""
    token_pools: list[dict] = Field(default_factory=list)
    child_monitor_enabled: bool = False
    child_monitor_threshold: float = 100
    child_monitor_interval: int = 600
    child_monitor_max_failures: int = 3
    child_monitor_pool_ids: list[str] = Field(default_factory=list)


class SelfEmailUpdate(BaseModel):
    accounts: str = ""


class SelfEmailDeleteRequest(BaseModel):
    emails: list[str]


class ProxyTestRequest(BaseModel):
    proxy_scheme: str = "http"
    proxy_url: str = ""

class TaskStart(BaseModel):
    quantity: int
    concurrency: int = 1
    show_browser: bool = False
    name: str = ""
    email_source: str = "temp"
    registration_mode: str = "standard"
    adobe_account_ids: list[str] = Field(default_factory=list)
    invite_remove_members: bool = True

class TaskDeleteRequest(BaseModel):
    ids: list[int]


class ChildAccountDeleteRequest(BaseModel):
    ids: list[str]


class AdobeAccountBulkRequest(BaseModel):
    ids: list[str]


class AdobeAccountUpdate(BaseModel):
    id: str = ""
    name: str = ""
    email: str = ""
    hotmail_password: str = ""
    adobe_password: str = ""
    client_id: str = ""
    refresh_token: str = ""
    cookie: str = ""


class AdobeAccountBatchImport(BaseModel):
    content: str = ""
    on_duplicate: str = "skip"


class AdobeTeamActionRequest(BaseModel):
    account_id: str
    emails: list[str]

# ─── Auth Endpoints ───
@app.get(LOGIN_PATH)
async def login_page():
    return FileResponse(os.path.join(APP_DIR, "static", "login.html"))


@app.post(LOGIN_API_PATH)
async def login(data: dict, request: Request):
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        return JSONResponse(status_code=401, content={"ok": False, "message": "账号或密码错误"})
    request.session["admin_authenticated"] = True
    return {"ok": True}


@app.post(LOGOUT_API_PATH)
async def logout(request: Request):
    request.session.clear()
    return {"ok": True}


# ─── Config Endpoints ───
@app.post("/api/config")
async def update_config(item: ConfigUpdate):
    global config
    proxy_scheme = item.proxy_scheme if item.proxy_scheme in ("http", "https", "socks5") else "http"
    adobe_proxy_scheme = item.adobe_proxy_scheme if item.adobe_proxy_scheme in ("http", "https", "socks5") else "http"
    token_pools = normalize_token_pools(item.token_pools)
    legacy_site = item.token_pool_site.strip()
    legacy_key = item.token_pool_key.strip()
    if not token_pools and (legacy_site or legacy_key):
        token_pools.append({
            "id": "legacy",
            "name": "1号池",
            "site": legacy_site,
            "key": legacy_key,
            "enabled": True,
            "success": 0,
            "failed": 0,
        })
    legacy_pool = next((pool for pool in token_pools if pool.get("site") and pool.get("key")), None)
    if legacy_pool:
        legacy_site = legacy_pool.get("site", "")
        legacy_key = legacy_pool.get("key", "")
    config = {
        "api_key": item.api_key,
        "api_base": item.api_base,
        "email_domain": item.email_domain,
        "email_domains": item.email_domains,
        "yescaptcha_key": item.yescaptcha_key,
        "proxy_enabled": item.proxy_enabled,
        "proxy_scheme": proxy_scheme,
        "proxy_url": item.proxy_url.strip(),
        "adobe_proxy_enabled": item.adobe_proxy_enabled,
        "adobe_proxy_scheme": adobe_proxy_scheme,
        "adobe_proxy_url": item.adobe_proxy_url.strip(),
        "token_pool_enabled": item.token_pool_enabled,
        "token_pool_site": legacy_site,
        "token_pool_key": legacy_key,
        "token_pools": token_pools,
        "token_pool_cursor": config.get("token_pool_cursor", 0),
        "child_monitor_enabled": bool(item.child_monitor_enabled),
        "child_monitor_threshold": max(0, float(item.child_monitor_threshold or 0)),
        "child_monitor_interval": max(60, int(item.child_monitor_interval or 600)),
        "child_monitor_max_failures": max(1, int(item.child_monitor_max_failures or 3)),
        "child_monitor_pool_ids": [str(pool_id) for pool_id in item.child_monitor_pool_ids],
        "self_email_accounts": config.get("self_email_accounts", ""),
        "self_email_cursor": config.get("self_email_cursor", 0),
        "self_email_used": config.get("self_email_used", []),
        "adobe_accounts": config.get("adobe_accounts", []),
    }
    save_config(config)
    ensure_child_monitor_started()
    return {"status": "ok"}

@app.post("/api/test-proxy")
async def test_proxy(item: ProxyTestRequest):
    ok, message, proxy = test_proxy_connectivity(item.proxy_url, item.proxy_scheme)
    return {
        "valid": ok,
        "message": message,
        "normalized": proxy["url"] if proxy else "",
    }

@app.post("/api/test-config")
async def test_config(item: ConfigUpdate):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{item.api_base}/emails",
                headers={"X-API-Key": item.api_key},
                timeout=5.0
            )
            if response.status_code == 401:
                return {"valid": False, "message": "API Key 无效 (401 Auth Error)"}
            elif response.status_code in (301, 302, 307, 308):
                return {"valid": False, "message": f"连接被重定向 ({response.status_code})，请检查 URL 是否缺少 '/api' 结尾"}
            elif response.status_code == 200:
                return {"valid": True, "message": "API 配置有效可用！"}
            else:
                 return {"valid": False, "message": f"连接异常，状态码: {response.status_code}"}
    except Exception as e:
        return {"valid": False, "message": f"连接异常: {str(e)}"}

@app.post("/api/test-captcha-config")
async def test_captcha_config(data: dict):
    key = data.get("yescaptcha_key", "")
    if not key:
        return {"valid": False, "message": "请填写 API Key"}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.yescaptcha.com/getBalance",
                json={"clientKey": key},
                timeout=10.0
            )
            result = resp.json()
            if result.get("errorId") == 0:
                balance = result.get("balance", 0)
                return {"valid": True, "message": f"有效！余额: {balance} 点"}
            else:
                return {"valid": False, "message": f"无效: {result.get('errorDescription', '未知错误')}"}
    except Exception as e:
        return {"valid": False, "message": f"连接异常: {str(e)}"}

@app.get("/api/config")
async def get_config():
    return {key: value for key, value in config.items() if key != "adobe_accounts"}


def normalize_email_list(emails: list[str]) -> list[str]:
    normalized = []
    seen = set()
    for value in emails:
        email = (value or "").strip().lower()
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) and email not in seen:
            seen.add(email)
            normalized.append(email)
    return normalized


def adobe_account_summary(account: dict) -> dict:
    normalize_adobe_account(account)
    cookie = account.get("cookie", "")
    try:
        cookie_count = len(parse_adobe_cookies(cookie)) if cookie else 0
    except ValueError:
        cookie_count = 0
    has_protocol = bool(account.get("client_id") and account.get("refresh_token"))
    display_name = account.get("name") or account.get("email") or ""
    assignment_count = len(account.get("product_assignments") or [])
    return {
        "id": account.get("id", ""),
        "name": display_name,
        "email": account.get("email", ""),
        "hotmail_password": account.get("hotmail_password", ""),
        "adobe_password": account.get("adobe_password", ""),
        "client_id": account.get("client_id", ""),
        "refresh_token": account.get("refresh_token", ""),
        "cookie_configured": bool(cookie),
        "credential_configured": has_protocol,
        "cookie_preview": (
            "protocol credentials configured"
            if has_protocol else (f"cookie configured ? {cookie_count} items" if cookie else "")
        ),
        "product_count": assignment_count or (1 if account.get("product_id") else len(account.get("invite_product_ids", []))),
        "organization_id": account.get("org_id") or account.get("organization_id", ""),
        "org_id": account.get("org_id", ""),
        "product_name": account.get("product_name", ""),
        "member_count": account.get("member_count", 0),
        "has_org": account.get("has_org"),
        "is_valid": account.get("is_valid"),
        "check_message": account.get("check_message", ""),
        "subscriptions": account.get("subscriptions", []),
        "last_token_check_at": account.get("last_token_check_at", ""),
        "token_expires_at": account.get("token_expires_at", ""),
        "last_login_at": account.get("last_login_at", ""),
        "last_checked_at": account.get("last_checked_at", ""),
        "updated_at": account.get("updated_at", ""),
    }


@app.post("/api/test-adobe-proxy")
async def test_adobe_proxy(item: ProxyTestRequest):
    ok, message, proxy = test_proxy_connectivity(item.proxy_url, item.proxy_scheme)
    exit_ip = ""
    if ok and proxy:
        try:
            async with httpx.AsyncClient(proxy=proxy["url"], timeout=15.0) as client:
                response = await client.get("https://api.ipify.org", params={"format": "json"})
                response.raise_for_status()
                exit_ip = str(response.json().get("ip") or "").strip()
        except Exception as exc:
            return {
                "valid": False,
                "message": f"Adobe HTTPS 已连通，但出口 IP 检测失败: {type(exc).__name__}: {exc}",
                "normalized": proxy["url"],
                "exit_ip": "",
                "scope": "仅用于账号凭证刷新与团队成员操作",
            }
    return {
        "valid": ok,
        "message": f"代理出口 IP: {exit_ip}" if exit_ip else message,
        "normalized": proxy["url"] if proxy else "",
        "exit_ip": exit_ip,
        "scope": "仅用于账号凭证刷新与团队成员操作",
    }


def summarize_adobe_subscriptions(products: list[dict]) -> list[dict]:
    subscriptions = []
    for product in products:
        quantities = product.get("licenseQuantities") or []
        end_dates = [item.get("endDate") for item in quantities if item.get("endDate")]
        end_date = min(end_dates) if end_dates else ""
        remaining_days = None
        if end_date:
            with suppress(Exception):
                expires_at = datetime.fromisoformat(end_date)
                remaining_days = max(0, (expires_at - datetime.now(expires_at.tzinfo)).days)
        subscriptions.append({
            "name": product.get("longName") or product.get("shortName") or "Adobe 产品",
            "created_date": (product.get("createdDate") or "")[:10],
            "end_date": end_date[:10],
            "remaining_days": remaining_days,
            "status": product.get("licenseStatus", ""),
            "offer_type": product.get("applicableOfferType", ""),
        })
    return subscriptions


def find_adobe_account(account_id: str) -> dict | None:
    return next(
        (account for account in config.get("adobe_accounts", []) if account.get("id") == account_id),
        None,
    )


def adobe_proxy_url() -> str:
    proxy = adobe_proxy_config()
    return proxy["url"] if proxy else ""


def adobe_account_email(account: dict) -> str:
    return (account.get("email") or account.get("name") or "").strip()


def normalize_adobe_account(account: dict) -> dict:
    email = adobe_account_email(account)
    if email:
        account["email"] = email
    account.setdefault("name", email or account.get("id", ""))
    for key in (
        "hotmail_password", "adobe_password", "client_id", "refresh_token",
        "admin_token", "admin_cookie", "org_id", "product_id", "product_name",
        "license_group_id", "check_message", "last_login_at", "last_checked_at",
    ):
        account.setdefault(key, "")
    account.setdefault("product_assignments", [])
    account.setdefault("member_count", 0)
    account.setdefault("has_org", False)
    account.setdefault("is_valid", None)
    return account


def protocol_account_ready(account: dict) -> bool:
    normalize_adobe_account(account)
    return bool(account.get("email") and account.get("client_id") and account.get("refresh_token"))


def apply_admin_login_result(account: dict, result: dict) -> None:
    rotated = result.get("rotated_refresh_token") or ""
    if rotated and rotated != account.get("refresh_token"):
        account["refresh_token"] = rotated
    account["admin_token"] = result.get("token") or ""
    account["admin_cookie"] = result.get("cookie") or ""
    account["org_id"] = result.get("org_id") or ""
    account["organization_id"] = account["org_id"]
    account["product_id"] = result.get("product_id") or ""
    account["product_name"] = result.get("product_name") or ""
    account["license_group_id"] = result.get("license_group_id") or ""
    assignments = result.get("product_assignments") or []
    account["product_assignments"] = assignments if isinstance(assignments, list) else []
    account["has_org"] = bool(result.get("has_org"))
    account["is_valid"] = bool(result.get("has_org"))
    account["last_login_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    account["last_checked_at"] = account["last_login_at"]
    account["check_message"] = (
        f"组织 {result.get('org_count', 0)} 个 / 产品 {result.get('product_count', 0)} 个"
        if result.get("has_org") else result.get("message", "")
    )


async def ensure_protocol_admin(account: dict, log=None) -> dict:
    normalize_adobe_account(account)
    proxy_url = adobe_proxy_url()

    def emit(message: str) -> None:
        if callable(log):
            log(message)

    has_cached = bool(
        account.get("admin_token") and account.get("org_id")
        and account.get("product_id") and account.get("license_group_id")
    )
    if has_cached:
        try:
            check_result = await asyncio.to_thread(
                adobe_admin.check_admin,
                token=account["admin_token"],
                org_id=account["org_id"],
                proxy_url=proxy_url,
            )
            for key in ("product_id", "product_name", "license_group_id", "product_assignments"):
                if key in check_result:
                    account[key] = check_result.get(key) or ([] if key == "product_assignments" else "")
            account["has_org"] = bool(check_result.get("has_org", True))
            account["is_valid"] = True
            account["last_checked_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            account["check_message"] = (
                f"组织 {check_result.get('org_count', 0)} 个 / 产品 {check_result.get('product_count', 0)} 个"
            )
            save_config(config)
            return account
        except Exception as exc:
            emit(f"管理 token 已失效，重新协议登录: {str(exc)[:160]}")

    if not protocol_account_ready(account):
        raise RuntimeError("账号缺少 email / ClientID / RefreshToken，无法协议登录")

    result = await asyncio.to_thread(
        adobe_admin.login_account,
        email=account["email"],
        adobe_password=account.get("adobe_password", ""),
        refresh_token=account.get("refresh_token", ""),
        client_id=account.get("client_id", ""),
        proxy_url=proxy_url,
        otp_timeout=180,
        log=emit,
    )
    apply_admin_login_result(account, result)
    save_config(config)
    if not account.get("has_org"):
        raise RuntimeError(account.get("check_message") or "登录成功但未发现可用组织/产品")
    return account


def parse_adobe_account_import(content: str, on_duplicate: str = "skip") -> dict:
    result = {"created": 0, "updated": 0, "skipped": 0, "failed": 0, "errors": []}
    accounts = config.setdefault("adobe_accounts", [])
    by_email = {
        adobe_account_email(normalize_adobe_account(account)).lower(): account
        for account in accounts
        if adobe_account_email(account)
    }
    overwrite = on_duplicate == "overwrite"
    for line_no, raw in enumerate((content or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("----")]
        if len(parts) < 5 or not parts[0] or "@" not in parts[0]:
            result["failed"] += 1
            result["errors"].append(f"第 {line_no} 行格式应为 邮箱----邮箱密码----Adobe密码----ClientID----RefreshToken")
            continue
        email = parts[0]
        fields = {
            "email": email,
            "name": email,
            "hotmail_password": parts[1],
            "adobe_password": parts[2],
            "client_id": parts[3],
            "refresh_token": "----".join(parts[4:]).strip(),
        }
        key = email.lower()
        existing = by_email.get(key)
        if existing:
            if not overwrite:
                result["skipped"] += 1
                continue
            existing.update(fields)
            existing["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            result["updated"] += 1
            continue
        account = {"id": uuid.uuid4().hex, **fields, "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M")}
        normalize_adobe_account(account)
        accounts.append(account)
        by_email[key] = account
        result["created"] += 1
    save_config(config)
    return result


def parse_adobe_cookies(cookie_header: str) -> list[dict]:
    jar = SimpleCookie()
    try:
        jar.load(cookie_header or "")
    except Exception as exc:
        raise ValueError(f"Cookie 格式无效: {exc}") from exc
    cookies = [
        {
            "name": name,
            "value": morsel.value,
            "domain": ".adobe.com",
            "path": "/",
            "secure": True,
            "httpOnly": False,
            "sameSite": "Lax",
        }
        for name, morsel in jar.items()
    ]
    if not cookies:
        raise ValueError("Cookie 为空，请粘贴浏览器导出的完整 Cookie 字符串")
    return cookies


async def click_first_visible(page, selectors: list[str], timeout: int = 8000):
    last_error = None
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            await locator.wait_for(state="visible", timeout=timeout)
            await locator.click()
            return locator
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"未找到可操作按钮: {selectors[0]}") from last_error


async def open_adobe_admin(cookie_header: str, target_url: str = "https://adminconsole.adobe.com/", on_request=None):
    from playwright.async_api import async_playwright

    playwright = await async_playwright().start()
    launch_options = {"headless": True}
    proxy = adobe_playwright_proxy()
    if proxy:
        launch_options["proxy"] = proxy
    browser = await playwright.chromium.launch(**launch_options)
    context = await browser.new_context(locale="zh-CN")
    await context.add_cookies(parse_adobe_cookies(cookie_header))
    page = await context.new_page()
    if on_request:
        page.on("request", on_request)
    await page.goto(target_url, wait_until="domcontentloaded", timeout=60000)
    await page.wait_for_timeout(2500)
    if "auth.services.adobe.com" in page.url or "signin" in page.url.lower():
        await browser.close()
        await playwright.stop()
        raise RuntimeError("Cookie 已失效或不包含 Adobe Admin Console 登录状态")
    return playwright, browser, page


async def get_adobe_api_session(account: dict, include_protected: bool = False) -> dict:
    cookie = account.get("cookie", "")
    try:
        async with adobe_httpx_client() as client:
            token_response = await client.post(
                "https://adobeid-na1.services.adobe.com/ims/check/v6/token",
                headers={
                    "Cookie": cookie,
                    "Origin": "https://firefly.adobe.com",
                    "Referer": "https://firefly.adobe.com/",
                    "User-Agent": "Mozilla/5.0",
                },
                data={
                    "client_id": "clio-playground-web",
                    "guest_allowed": "true",
                    "scope": "AdobeID,openid",
                },
                timeout=30.0,
            )
            if token_response.status_code != 200:
                raise RuntimeError(f"IMS Token 请求失败 ({token_response.status_code})")
            token_data = token_response.json()
            access_token = (token_data.get("access_token") or "").strip()
            if not access_token:
                raise RuntimeError("IMS 响应中没有 access_token")
            headers = {
                "authorization": f"Bearer {access_token}",
                "x-api-key": "ONESIE1",
                "x-jil-feature": "use_clam,pa_4280",
                "accept": "application/json",
                "referer": "https://adminconsole.adobe.com/",
                "user-agent": "Mozilla/5.0",
            }
            organizations_response = await client.get(
                "https://bps-il.adobe.io/jil-api/v2/organizations",
                headers=headers,
                timeout=30.0,
            )
            if organizations_response.status_code != 200:
                raise RuntimeError(f"组织查询失败 ({organizations_response.status_code})")
            organizations = organizations_response.json()
            if not isinstance(organizations, list) or not organizations:
                raise RuntimeError("当前账号没有可管理的 Adobe 组织")
            organization_id = account.get("organization_id", "")
            if not any(org.get("id") == organization_id for org in organizations):
                organization_id = organizations[0].get("id", "")
            protected_emails = set()
            login_email = (token_data.get("email") or "").strip().lower()
            if login_email:
                protected_emails.add(login_email)
            products_response = await client.get(
                f"https://bps-il.adobe.io/jil-api/v2/organizations/{quote(organization_id, safe='@')}/products",
                params={
                    "include_created_date": "true",
                    "include_expired": "true",
                    "include_groups_quantity": "false",
                    "include_inactive": "false",
                    "include_legacy_ls_fields": "true",
                    "include_license_activations": "true",
                    "include_license_allocation_info": "false",
                    "include_pricing_data": "false",
                    "includeFulfillableItemCodesOnly": "true",
                    "processing_instruction_codes": "administration",
                },
                headers=headers,
                timeout=30.0,
            )
            if products_response.status_code == 200 and isinstance(products_response.json(), list):
                products = products_response.json()
                account["subscriptions"] = summarize_adobe_subscriptions(products)
                by_name = {
                    (product.get("longName") or product.get("shortName") or "").strip(): product.get("id")
                    for product in products
                    if product.get("id") and product.get("licenseStatus") == "ACTIVE"
                }
                account["invite_product_ids"] = [
                    by_name[name] for name in ADOBE_INVITE_PRODUCT_NAMES if by_name.get(name)
                ]

        expires_in = float(token_data.get("expires_in") or 0)
        if expires_in > 864000:
            expires_in /= 1000
        account["organization_id"] = organization_id
        account["last_token_check_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
        account["token_expires_at"] = (
            datetime.now() + timedelta(seconds=max(0, expires_in))
        ).strftime("%Y-%m-%d %H:%M")
        if account in config.get("adobe_accounts", []):
            save_config(config)
        return {
            "source": "ims",
            "organization_id": organization_id,
            "headers": headers,
            "protected_emails": protected_emails,
        }
    except Exception as ims_error:
        playwright = browser = None
        captured_requests = []
        try:
            def capture_jil_request(request):
                if "bps-il.adobe.io/jil-api/" in request.url and "/users/" in request.url:
                    captured_requests.append(request)

            playwright, browser, page = await open_adobe_admin(
                cookie,
                "https://adminconsole.adobe.com/users",
                capture_jil_request,
            )
            await page.wait_for_timeout(10000)
            if not captured_requests:
                raise RuntimeError("未捕获到 Adobe JIL 鉴权请求")
            captured = captured_requests[-1]
            match = re.search(r"/organizations/([^/]+)/users/", captured.url)
            if not match:
                raise RuntimeError("无法识别 Adobe 组织 ID")
            organization_id = unquote(match.group(1))
            headers = {
                key: value
                for key, value in captured.headers.items()
                if key in {
                    "authorization", "x-api-key", "x-include-roles", "x-jil-feature",
                    "accept", "referer", "user-agent",
                }
            }
            protected_emails = await get_protected_adobe_member_emails(page) if include_protected else set()
            return {
                "source": "browser",
                "organization_id": organization_id,
                "headers": headers,
                "protected_emails": protected_emails,
            }
        except Exception as fallback_error:
            raise RuntimeError(f"Cookie 鉴权失败: IMS={ims_error}; Admin Console={fallback_error}") from fallback_error
        finally:
            if browser:
                await browser.close()
            if playwright:
                await playwright.stop()


async def test_adobe_account_cookie(account: dict) -> dict:
    session = await get_adobe_api_session(account)
    return {
        "ok": True,
        "message": f"Cookie 有效，已通过 {session['source'].upper()} 获取管理凭据",
        "organization_id": session["organization_id"],
    }


async def get_protected_adobe_member_emails(page) -> set[str]:
    protected = set()
    checkboxes = page.locator('input[type="checkbox"]')
    for index in range(await checkboxes.count()):
        checkbox = checkboxes.nth(index)
        if not await checkbox.is_disabled():
            continue
        row = checkbox.locator('xpath=ancestor::*[@role="row"]')
        if not await row.count():
            continue
        text = await row.inner_text()
        protected.update(email.lower() for email in re.findall(r"[^@\s]+@[^@\s]+\.[^@\s]+", text))
    return protected


def adobe_member_summary(member: dict, protected_emails: set[str] | None = None) -> dict:
    products = member.get("products") or []
    email = member.get("email") or member.get("userName") or ""
    protected = email.strip().lower() in (protected_emails or set())
    return {
        "id": member.get("id", ""),
        "email": email,
        "first_name": member.get("firstName", ""),
        "last_name": member.get("lastName", ""),
        "type": member.get("type", ""),
        "account_status": member.get("accountStatus", ""),
        "protected": protected,
        "protection_reason": "当前登录主账号" if protected else "",
        "removable": bool(member.get("removable")) and not protected,
        "editable": bool(member.get("editable")),
        "products": len(products),
    }


async def fetch_adobe_members(account: dict, page_number: int = 0, page_size: int = 20, search: str = "") -> dict:
    session = await get_adobe_api_session(account, include_protected=True)
    organization_id = session["organization_id"]
    allowed_headers = session["headers"]
    protected_emails = session["protected_emails"]
    try:
        api_url = f"https://bps-il.adobe.io/jil-api/v2/organizations/{quote(organization_id, safe='@')}/users/"
        params = {
            "filter_exclude_domain": "techacct.adobe.com",
            "page": max(0, page_number),
            "page_size": min(max(1, page_size), 100),
            "search_query": search.strip(),
            "sort": "FNAME_LNAME",
            "sort_order": "ASC",
            "currentPage": max(0, page_number) + 1,
            "filterQuery": "",
            "include": "DOMAIN_ENFORCEMENT_EXCEPTION_INDICATOR",
        }
        response = None
        last_error = ""
        async with adobe_httpx_client() as client:
            for attempt in range(1, 4):
                try:
                    response = await client.get(api_url, params=params, headers=allowed_headers, timeout=45.0)
                    if response.status_code == 200 or response.status_code not in (429, 500, 502, 503, 504):
                        break
                    last_error = f"HTTP {response.status_code}"
                except httpx.HTTPError as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                    response = None
                if attempt < 3:
                    await asyncio.sleep(attempt * 2)
        if response is None:
            raise RuntimeError(f"Adobe JIL API 请求失败: {last_error}")
        if response.status_code != 200:
            message = response.text[:300]
            with suppress(Exception):
                message = response.json().get("message", message)
            raise RuntimeError(f"Adobe JIL API 返回 {response.status_code}: {message}")
        members = response.json()
        if not isinstance(members, list):
            raise RuntimeError("Adobe JIL API 返回了未知成员数据格式")
        return {
            "organization_id": organization_id,
            "page": params["page"],
            "page_size": params["page_size"],
            "has_more": len(members) >= params["page_size"],
            "members": [adobe_member_summary(member, protected_emails) for member in members],
        }
    finally:
        pass


async def invite_adobe_members(account: dict, emails: list[str]) -> list[dict]:
    results = []
    session = await get_adobe_api_session(account)
    organization_id = session["organization_id"]
    allowed_headers = session["headers"]
    try:
        allowed_headers["content-type"] = "application/json"
        jil_users_url = (
            "https://bps-il.adobe.io/jil-api/v2/organizations/"
            f"{quote(organization_id, safe='@')}/users"
        )
        invite_url = (
            "https://abpapi.adobe.io/abpapi/organizations/"
            f"{quote(organization_id, safe='@')}/users"
        )
        product_ids = account.get("invite_product_ids", [])
        if not product_ids:
            raise RuntimeError("当前组织未找到可用于邀请的有效产品")
        async with adobe_httpx_client() as client:
            async def lookup_member(email: str, email_key: str, attempts: int = 5) -> dict | None:
                lookup_params = {
                    "filter_exclude_domain": "techacct.adobe.com",
                    "page": 0,
                    "page_size": 20,
                    "search_query": email,
                    "sort": "FNAME_LNAME",
                    "sort_order": "ASC",
                    "currentPage": 1,
                    "filterQuery": email,
                }
                for attempt in range(attempts):
                    try:
                        lookup = await client.get(
                            jil_users_url + "/",
                            params=lookup_params,
                            headers=allowed_headers,
                            timeout=45.0,
                        )
                        if lookup.status_code == 200:
                            member = next(
                                (
                                    item for item in lookup.json()
                                    if (item.get("email") or item.get("userName") or "").strip().lower() == email_key
                                ),
                                None,
                            )
                            if member:
                                return member
                    except httpx.HTTPError:
                        pass
                    if attempt < attempts - 1:
                        await asyncio.sleep(2)
                return None

            for email in emails:
                try:
                    email_key = email.strip().lower()
                    already_exists = False
                    invite_error = ""
                    try:
                        response = await client.post(
                            invite_url,
                            json={"email": {"primary": email}},
                            headers=allowed_headers,
                            timeout=45.0,
                        )
                        already_exists = response.status_code == 400 and "user_already_exists" in response.text
                        if response.status_code not in (200, 201, 202, 204) and not already_exists:
                            message = response.text[:300]
                            with suppress(Exception):
                                body = response.json()
                                message = body.get("message") or body.get("error_description") or message
                            invite_error = f"邀请失败 ({response.status_code}): {message}"
                    except httpx.HTTPError as exc:
                        invite_error = f"邀请请求异常: {type(exc).__name__}: {exc}"

                    member = await lookup_member(email, email_key, attempts=8)
                    if not member:
                        raise RuntimeError(invite_error or "邀请已提交，但暂未查询到新成员，无法分配产品")

                    failures = []
                    for product_id in product_ids:
                        existing_ids = {
                            str(product.get("id") or product)
                            for product in member.get("products", [])
                        }
                        if product_id in existing_ids:
                            continue

                        assignment_error = ""
                        for attempt in range(1, 4):
                            try:
                                assignment = await client.patch(
                                    jil_users_url,
                                    json=[{"op": "add", "path": f"/{member['id']}/products/{product_id}"}],
                                    headers=allowed_headers,
                                    timeout=60.0,
                                )
                                if assignment.status_code in (200, 202, 204):
                                    assignment_error = ""
                                    break
                                message = assignment.text[:180]
                                with suppress(Exception):
                                    body = assignment.json()
                                    message = body.get("message") or body.get("detail") or message
                                assignment_error = f"HTTP {assignment.status_code}: {message}"
                            except httpx.HTTPError as exc:
                                assignment_error = f"{type(exc).__name__}: {exc}"

                            member = await lookup_member(email, email_key, attempts=3) or member
                            existing_ids = {
                                str(product.get("id") or product)
                                for product in member.get("products", [])
                            }
                            if product_id in existing_ids:
                                assignment_error = ""
                                break
                            if attempt < 3:
                                await asyncio.sleep(2)
                        if assignment_error:
                            failures.append(f"{product_id} ({assignment_error})")
                    if failures:
                        raise RuntimeError(f"成员已创建，但产品分配失败: {', '.join(failures)}")
                    results.append({
                        "email": email,
                        "ok": True,
                        "message": f"{'成员已存在' if already_exists else '邀请已提交'}，已分配 {len(product_ids)} 个产品",
                    })
                except Exception as exc:
                    message = str(exc) or type(exc).__name__
                    results.append({"email": email, "ok": False, "message": message})
        return results
    finally:
        pass


async def remove_adobe_members(account: dict, emails: list[str]) -> list[dict]:
    results = []
    session = await get_adobe_api_session(account, include_protected=True)
    organization_id = session["organization_id"]
    allowed_headers = session["headers"]
    protected_emails = session["protected_emails"]
    try:
        allowed_headers["content-type"] = "application/json"
        users_url = f"https://bps-il.adobe.io/jil-api/v2/organizations/{quote(organization_id, safe='@')}/users"

        async with adobe_httpx_client() as client:
            async def lookup_member(email: str, email_key: str, attempts: int = 3) -> dict | None:
                lookup_params = {
                    "filter_exclude_domain": "techacct.adobe.com",
                    "page": 0,
                    "page_size": 20,
                    "search_query": email,
                    "sort": "FNAME_LNAME",
                    "sort_order": "ASC",
                    "currentPage": 1,
                    "filterQuery": email,
                }
                for attempt in range(1, attempts + 1):
                    try:
                        lookup = await client.get(
                            users_url + "/",
                            params=lookup_params,
                            headers=allowed_headers,
                            timeout=45.0,
                        )
                        if lookup.status_code == 200:
                            return next(
                                (
                                    member for member in lookup.json()
                                    if (member.get("email") or member.get("userName") or "").strip().lower() == email_key
                                ),
                                None,
                            )
                    except httpx.HTTPError:
                        pass
                    if attempt < attempts:
                        await asyncio.sleep(attempt * 2)
                return None

            for email in emails:
                try:
                    email_key = email.strip().lower()
                    if email_key in protected_emails:
                        raise RuntimeError("当前登录主账号不可移除")
                    member = await lookup_member(email, email_key)
                    if not member:
                        results.append({"email": email, "ok": True, "message": "成员已不存在"})
                        continue
                    if not member.get("removable", False):
                        raise RuntimeError("该成员不可移除")
                    removal_error = ""
                    for attempt in range(1, 4):
                        try:
                            response = await client.patch(
                                users_url,
                                json=[{"op": "remove", "path": f"/{member['id']}"}],
                                headers=allowed_headers,
                                timeout=60.0,
                            )
                            if response.status_code in (200, 202, 204):
                                removal_error = ""
                                break
                            message = response.text[:300]
                            with suppress(Exception):
                                message = response.json().get("message", message)
                            removal_error = f"HTTP {response.status_code}: {message}"
                        except httpx.HTTPError as exc:
                            removal_error = f"{type(exc).__name__}: {exc}"

                        if not await lookup_member(email, email_key, attempts=2):
                            removal_error = ""
                            break
                        if attempt < 3:
                            await asyncio.sleep(attempt * 2)
                    if removal_error:
                        raise RuntimeError(f"移除失败: {removal_error}")
                    results.append({"email": email, "ok": True, "message": "成员已移除"})
                except Exception as exc:
                    results.append({"email": email, "ok": False, "message": str(exc) or type(exc).__name__})
        return results
    finally:
        pass


def protocol_member_summary(item: dict, protected: set[str] | None = None) -> dict:
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else item
    email = (item.get("email") or raw.get("email") or raw.get("userName") or "").strip()
    member_id = item.get("member_id") or raw.get("id") or raw.get("memberId") or ""
    protected = protected or set()
    return {
        "id": member_id,
        "email": email,
        "first_name": raw.get("firstName", ""),
        "last_name": raw.get("lastName", ""),
        "type": raw.get("type", ""),
        "account_status": raw.get("accountStatus", raw.get("status", "")),
        "protected": email.lower() in protected,
        "protection_reason": "admin account" if email.lower() in protected else "",
        "removable": bool(member_id) and email.lower() not in protected,
        "editable": True,
        "products": len(raw.get("products") or []),
    }


async def fetch_adobe_members(account: dict, page_number: int = 0, page_size: int = 20, search: str = "") -> dict:
    await ensure_protocol_admin(account)
    proxy_url = adobe_proxy_url()
    members = await asyncio.to_thread(
        adobe_admin.fetch_members,
        token=account["admin_token"],
        org_id=account["org_id"],
        proxy_url=proxy_url,
        search=search.strip(),
        pages=max(1, page_number + 1),
    )
    protected = {adobe_account_email(account).lower()}
    start = max(0, page_number) * min(max(1, page_size), 100)
    size = min(max(1, page_size), 100)
    page_members = members[start:start + size]
    account["member_count"] = len(members)
    save_config(config)
    return {
        "organization_id": account.get("org_id", ""),
        "page": max(0, page_number),
        "page_size": size,
        "has_more": start + size < len(members),
        "members": [protocol_member_summary(member, protected) for member in page_members],
    }


async def invite_adobe_members(account: dict, emails: list[str]) -> list[dict]:
    await ensure_protocol_admin(account)
    assignments = account.get("product_assignments") or []
    if not assignments and account.get("product_id") and account.get("license_group_id"):
        assignments = [{
            "product_id": account["product_id"],
            "license_group_id": account["license_group_id"],
            "product_name": account.get("product_name", ""),
        }]
    if not assignments:
        raise RuntimeError("账号尚未发现可用产品或授权组，请先协议检测母号")
    proxy_url = adobe_proxy_url()

    async def grant(email: str) -> dict:
        result = await asyncio.to_thread(
            adobe_admin.grant_member,
            token=account["admin_token"],
            org_id=account["org_id"],
            product_id=account["product_id"],
            license_group_id=account["license_group_id"],
            product_assignments=assignments,
            email=email,
            proxy_url=proxy_url,
        )
        ok = bool(result.get("ok"))
        return {
            "email": email,
            "ok": ok,
            "member_id": result.get("member_id", ""),
            "message": result.get("message") or ("authorized" if ok else "authorization failed"),
        }

    return [await grant(email) for email in emails]


async def remove_adobe_members(account: dict, emails: list[str]) -> list[dict]:
    await ensure_protocol_admin(account)
    proxy_url = adobe_proxy_url()
    protected = {adobe_account_email(account).lower()}
    results = []
    for email in emails:
        if email.strip().lower() in protected:
            results.append({"email": email, "ok": False, "message": "cannot remove admin account"})
            continue
        result = await asyncio.to_thread(
            adobe_admin.remove_member,
            token=account["admin_token"],
            org_id=account["org_id"],
            email=email,
            proxy_url=proxy_url,
        )
        message = result.get("message") or ""
        already_removed = "未找到成员" in message or "成员已不存在" in message or "not found" in message.lower()
        results.append({
            "email": email,
            "ok": bool(result.get("ok")) or already_removed,
            "message": "成员已不存在" if already_removed else message,
        })
    return results


@app.get("/api/adobe-accounts")
async def get_adobe_accounts():
    return [adobe_account_summary(account) for account in config.get("adobe_accounts", [])]


@app.post("/api/adobe-accounts")
async def save_adobe_account(item: AdobeAccountUpdate):
    global config
    email = (item.email or item.name).strip()
    name = (item.name or email).strip()
    if not email or "@" not in email:
        return JSONResponse(status_code=400, content={"message": "请输入有效的母号邮箱"})
    accounts = config.setdefault("adobe_accounts", [])
    account = find_adobe_account(item.id) if item.id else None
    if not account:
        existing = next(
            (acc for acc in accounts if adobe_account_email(normalize_adobe_account(acc)).lower() == email.lower()),
            None,
        )
        if existing:
            account = existing
    if not account:
        account = {"id": uuid.uuid4().hex}
        accounts.append(account)

    account.update({
        "name": name,
        "email": email,
        "hotmail_password": item.hotmail_password.strip(),
        "adobe_password": item.adobe_password.strip(),
        "client_id": item.client_id.strip(),
        "refresh_token": item.refresh_token.strip(),
    })
    if item.cookie.strip():
        try:
            parse_adobe_cookies(item.cookie.strip())
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"message": str(exc)})
        account["cookie"] = item.cookie.strip()
    normalize_adobe_account(account)
    account["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    save_config(config)
    return adobe_account_summary(account)


@app.post("/api/adobe-accounts/batch-import")
async def batch_import_adobe_accounts(item: AdobeAccountBatchImport):
    if item.on_duplicate not in ("skip", "overwrite"):
        return JSONResponse(status_code=400, content={"message": "on_duplicate must be skip or overwrite"})
    return parse_adobe_account_import(item.content, item.on_duplicate)


@app.delete("/api/adobe-accounts/{account_id}")
async def delete_adobe_account(account_id: str):
    global config
    before = len(config.get("adobe_accounts", []))
    config["adobe_accounts"] = [
        account for account in config.get("adobe_accounts", []) if account.get("id") != account_id
    ]
    if len(config["adobe_accounts"]) == before:
        return JSONResponse(status_code=404, content={"message": "账号不存在"})
    save_config(config)
    return {"ok": True}


@app.post("/api/adobe-accounts/delete")
async def delete_adobe_accounts_bulk(req: AdobeAccountBulkRequest):
    global config
    ids = {item.strip() for item in req.ids if item and item.strip()}
    if not ids:
        return JSONResponse(status_code=400, content={"message": "请选择母号"})
    before = len(config.get("adobe_accounts", []))
    config["adobe_accounts"] = [
        account for account in config.get("adobe_accounts", []) if account.get("id") not in ids
    ]
    deleted = before - len(config["adobe_accounts"])
    save_config(config)
    return {"ok": True, "deleted": deleted}


async def run_adobe_account_test(account: dict) -> dict:
    logs: list[str] = []
    try:
        async with adobe_account_lock:
            await ensure_protocol_admin(account, log=logs.append)
            account["last_checked_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            account["is_valid"] = True
            save_config(config)
            return {
                "ok": True,
                "id": account.get("id", ""),
                "email": adobe_account_email(account),
                "message": account.get("check_message") or "协议登录成功，已获取管理权限",
                "organization_id": account.get("org_id", ""),
                "product_name": account.get("product_name", ""),
                "logs": logs[-80:],
            }
    except Exception as exc:
        account["is_valid"] = False
        account["check_message"] = str(exc)[:500]
        account["last_checked_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
        save_config(config)
        return {
            "ok": False,
            "id": account.get("id", ""),
            "email": adobe_account_email(account),
            "message": str(exc),
            "logs": logs[-80:],
        }


@app.post("/api/adobe-accounts/{account_id}/test")
async def test_adobe_account(account_id: str):
    account = find_adobe_account(account_id)
    if not account:
        return JSONResponse(status_code=404, content={"message": "账号不存在"})
    logs: list[str] = []
    try:
        async with adobe_account_lock:
            await ensure_protocol_admin(account, log=logs.append)
            account["last_checked_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            account["is_valid"] = True
            save_config(config)
            return {
                "ok": True,
                "message": account.get("check_message") or "协议登录成功，已获取管理权限",
                "organization_id": account.get("org_id", ""),
                "product_name": account.get("product_name", ""),
                "logs": logs[-80:],
            }
    except Exception as exc:
        account["is_valid"] = False
        account["check_message"] = str(exc)[:500]
        account["last_checked_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
        save_config(config)
        return JSONResponse(
            status_code=400,
            content={"ok": False, "message": str(exc), "logs": logs[-80:]},
        )


@app.post("/api/adobe-accounts/test")
async def test_adobe_accounts_bulk(req: AdobeAccountBulkRequest):
    ids = [item.strip() for item in req.ids if item and item.strip()]
    if not ids:
        return JSONResponse(status_code=400, content={"message": "请选择母号"})
    by_id = {account.get("id"): account for account in config.get("adobe_accounts", [])}
    results = []
    for account_id in ids:
        account = by_id.get(account_id)
        if not account:
            results.append({"ok": False, "id": account_id, "email": account_id, "message": "账号不存在", "logs": []})
            continue
        results.append(await run_adobe_account_test(account))
    success = sum(1 for item in results if item.get("ok"))
    return {
        "ok": success == len(results),
        "total": len(results),
        "success": success,
        "failed": len(results) - success,
        "results": results,
    }


@app.get("/api/adobe-accounts/{account_id}/members")
async def get_adobe_account_members(account_id: str, page: int = 0, page_size: int = 20, search: str = ""):
    account = find_adobe_account(account_id)
    if not account:
        return JSONResponse(status_code=404, content={"message": "账号不存在"})
    try:
        async with adobe_account_lock:
            return await fetch_adobe_members(account, page, page_size, search)
    except Exception as exc:
        return JSONResponse(status_code=400, content={"message": str(exc)})


@app.post("/api/adobe-team/invite")
async def invite_adobe_team_members(item: AdobeTeamActionRequest):
    account = find_adobe_account(item.account_id)
    emails = normalize_email_list(item.emails)
    if not account:
        return JSONResponse(status_code=404, content={"message": "账号不存在"})
    if not emails:
        return JSONResponse(status_code=400, content={"message": "请输入有效邮箱"})
    try:
        async with adobe_account_lock:
            results = await invite_adobe_members(account, emails)
    except Exception as exc:
        return JSONResponse(status_code=400, content={"message": str(exc)})
    return {"ok": all(result["ok"] for result in results), "results": results}


@app.post("/api/adobe-team/remove")
async def remove_adobe_team_members(item: AdobeTeamActionRequest):
    account = find_adobe_account(item.account_id)
    emails = normalize_email_list(item.emails)
    if not account:
        return JSONResponse(status_code=404, content={"message": "账号不存在"})
    if not emails:
        return JSONResponse(status_code=400, content={"message": "请输入有效邮箱"})
    try:
        async with adobe_account_lock:
            results = await remove_adobe_members(account, emails)
    except Exception as exc:
        return JSONResponse(status_code=400, content={"message": str(exc)})
    return {"ok": all(result["ok"] for result in results), "results": results}


@app.get("/api/self-emails")
async def get_self_emails():
    return build_self_email_overview()


@app.post("/api/self-emails")
async def update_self_emails(item: SelfEmailUpdate):
    global config, self_email_reserved
    accounts = parse_self_email_accounts(item.accounts)
    present = {account["email"].strip().lower() for account in accounts}
    used = normalize_self_email_used(config.get("self_email_used", []))
    config["self_email_accounts"] = item.accounts
    config["self_email_used"] = sorted(email for email in used if email in present)
    config["self_email_cursor"] = len(config["self_email_used"])
    self_email_reserved = {email for email in self_email_reserved if email in present}
    save_config(config)
    return {"status": "ok", **build_self_email_overview()}


@app.post("/api/self-emails/reset-used")
async def reset_self_email_used():
    global config, self_email_reserved
    config["self_email_used"] = []
    config["self_email_cursor"] = 0
    self_email_reserved = set()
    save_config(config)
    return {"status": "ok", **build_self_email_overview()}

# ─── Task Endpoints ───
@app.post("/api/self-emails/delete")
async def delete_self_emails(item: SelfEmailDeleteRequest):
    global config, self_email_reserved
    targets = {email.strip().lower() for email in item.emails if email.strip()}
    accounts = parse_self_email_accounts(config.get("self_email_accounts", ""))
    kept_accounts = [
        account for account in accounts
        if account["email"].strip().lower() not in targets
    ]
    used = normalize_self_email_used(config.get("self_email_used", []))
    config["self_email_accounts"] = serialize_self_email_accounts(kept_accounts)
    config["self_email_used"] = sorted(email for email in used if email not in targets)
    config["self_email_cursor"] = len(config["self_email_used"])
    self_email_reserved = {email for email in self_email_reserved if email not in targets}
    save_config(config)
    return {"status": "ok", "deleted": len(accounts) - len(kept_accounts), **build_self_email_overview()}


@app.post("/api/self-emails/clean-used")
async def clean_used_self_emails():
    global config, self_email_reserved
    used = normalize_self_email_used(config.get("self_email_used", []))
    accounts = parse_self_email_accounts(config.get("self_email_accounts", ""))
    kept_accounts = [
        account for account in accounts
        if account["email"].strip().lower() not in used
    ]
    removed = len(accounts) - len(kept_accounts)
    config["self_email_accounts"] = serialize_self_email_accounts(kept_accounts)
    config["self_email_used"] = []
    config["self_email_cursor"] = 0
    self_email_reserved = set()
    save_config(config)
    return {"status": "ok", "deleted": removed, **build_self_email_overview()}


@app.post("/api/tasks")
async def start_task(item: TaskStart):
    conc = max(1, min(item.concurrency, 10))
    registration_mode = item.registration_mode if item.registration_mode in ("standard", "invite") else "standard"
    account_ids = []
    if registration_mode == "invite":
        account_ids = [
            account_id for account_id in dict.fromkeys(item.adobe_account_ids)
            if find_adobe_account(account_id)
        ]
        if not account_ids:
            return JSONResponse(status_code=400, content={"message": "邀请模式至少选择一个有效账号"})
        available = build_self_email_overview()["available"]
        required = max(1, item.quantity) * len(account_ids)
        if available < required:
            return JSONResponse(
                status_code=400,
                content={"message": f"自备邮箱不足，需要 {required} 个，当前可用 {available} 个"},
            )
        email_source = "self"
    else:
        email_source = item.email_source if item.email_source in ("temp", "self") else "temp"
    task = task_manager.create_task(
        max(1, item.quantity),
        conc,
        item.show_browser,
        item.name,
        email_source,
        registration_mode,
        account_ids,
        item.invite_remove_members,
    )
    await task_manager.queue.put(task)

    # Ensure queue worker is running
    asyncio.create_task(task_manager.start_queue_worker())

    return task.to_dict()

@app.get("/api/tasks")
async def list_tasks():
    return [t.to_dict() for t in reversed(task_manager.tasks.values())]


@app.get("/api/tasks/{task_id}/logs")
async def get_task_logs(task_id: int, limit: int | None = None):
    if task_id not in task_manager.tasks:
        return JSONResponse(status_code=404, content={"message": "任务不存在"})
    return {"task_id": task_id, "logs": read_task_logs(task_id, limit)}


@app.get("/api/tasks/{task_id}/logs/download")
async def download_task_logs(task_id: int):
    task = task_manager.tasks.get(task_id)
    if not task:
        return JSONResponse(status_code=404, content={"message": "任务不存在"})
    path = task_log_path(task_id)
    if not os.path.exists(path):
        return JSONResponse(status_code=404, content={"message": "该任务暂无日志"})
    filename = f"{sanitize_filename(task.name, f'任务_{task_id}')}_#{task_id}.log"
    return FileResponse(
        path,
        media_type="text/plain; charset=utf-8",
        filename=filename,
    )


@app.get("/api/child-accounts")
async def get_child_accounts(
    status: str = "",
    account_id: str = "",
    flag: str = "",
    search: str = "",
    mother_status: str = "",
    pool_status: str = "",
):
    records = await list_child_accounts_raw()
    query = (search or "").strip().lower()
    threshold = float(config.get("child_monitor_threshold", 100) or 0)
    filtered = []
    for record in records:
        archived = record.get("status") in ("removed", "replaced")
        mother_email = record.get("adobe_account_email") or record.get("adobe_account_name") or ""
        if mother_status == "removed" and not archived:
            continue
        elif mother_status.startswith("mother:"):
            mother_key = mother_status[7:].strip().lower()
            if archived or mother_email.strip().lower() != mother_key:
                continue
        external_status = record.get("external_pool_status") or ""
        external_pool_id = record.get("external_pool_id") or ""
        external_pool_name = record.get("external_pool_name") or ""
        if pool_status == "unpooled":
            if external_status in ("imported", "failed"):
                continue
        elif pool_status == "imported_unknown":
            if external_status != "imported" or external_pool_id or external_pool_name:
                continue
        elif pool_status == "failed":
            if external_status != "failed":
                continue
        elif pool_status.startswith("pool_removed:"):
            pool_key = pool_status[13:]
            if not archived or external_status != "imported" or pool_key not in (external_pool_id, external_pool_name):
                continue
        elif pool_status.startswith("pool:"):
            pool_key = pool_status[5:]
            if archived or external_status != "imported" or pool_key not in (external_pool_id, external_pool_name):
                continue
        if status and record.get("status") != status:
            continue
        if account_id and record.get("adobe_account_id") != account_id:
            continue
        if flag in ("low_credits", "exhausted"):
            if record.get("status") != "exhausted":
                continue
        elif flag == "check_failed" and record.get("status") != "check_failed":
            continue
        elif flag == "external_failed" and record.get("external_pool_status") != "failed":
            continue
        elif flag == "replacement_failed" and not (
            record.get("status") == "removed" and record.get("replacement_task_id") and record.get("failure_reason")
        ):
            continue
        if query:
            haystack = " ".join([
                str(record.get("email", "")),
                str(record.get("adobe_account_email", "")),
                str(record.get("product_name", "")),
                str(record.get("failure_reason", "")),
                str(record.get("exhausted_token_delete_error", "")),
                str(record.get("source_task_id", "")),
                str(record.get("replacement_task_id", "")),
            ]).lower()
            if query not in haystack:
                continue
        filtered.append(public_child_account(record))

    summary = {
        "total": len(records),
        "active": sum(1 for item in records if item.get("status") == "active"),
        "low_credits": sum(1 for item in records if item.get("status") == "exhausted"),
        "exhausted": sum(1 for item in records if item.get("status") == "exhausted"),
        "check_failed": sum(1 for item in records if item.get("status") == "check_failed"),
        "replacing": sum(1 for item in records if item.get("status") == "replacing"),
        "replacement_failed": sum(
            1 for item in records
            if item.get("status") == "removed" and item.get("replacement_task_id") and item.get("failure_reason")
        ),
        "external_failed": sum(1 for item in records if item.get("external_pool_status") == "failed"),
        "monitor_enabled": bool(config.get("child_monitor_enabled")),
        "threshold": threshold,
    }
    pool_options = [
        {"id": pool.get("id", ""), "name": pool.get("name") or "Token 池"}
        for pool in normalize_token_pools()
        if pool.get("enabled")
    ]
    configured_pool_keys = {
        str(pool.get("id", "")).strip().lower()
        for pool in pool_options
        if str(pool.get("id", "")).strip()
    } | {
        str(pool.get("name", "")).strip().lower()
        for pool in pool_options
        if str(pool.get("name", "")).strip()
    }
    for record in records:
        pool_id = str(record.get("external_pool_id") or "").strip()
        pool_name = str(record.get("external_pool_name") or "").strip()
        key = (pool_id or pool_name).lower()
        if record.get("external_pool_status") == "imported" and key and key not in configured_pool_keys:
            pool_options.append({"id": pool_id or pool_name, "name": pool_name or pool_id})
            configured_pool_keys.add(key)
    archived_pool_keys = set()
    for record in records:
        if record.get("status") not in ("removed", "replaced") or record.get("external_pool_status") != "imported":
            continue
        pool_id = str(record.get("external_pool_id") or "").strip()
        pool_name = str(record.get("external_pool_name") or "").strip()
        key = (pool_id or pool_name).lower()
        if key:
            archived_pool_keys.add(key)
    for pool in pool_options:
        key = (str(pool.get("id", "")).strip() or str(pool.get("name", "")).strip()).lower()
        pool["has_removed"] = key in archived_pool_keys

    mother_seen = set()
    mother_options = []
    for record in records:
        if record.get("status") in ("removed", "replaced"):
            continue
        email = str(record.get("adobe_account_email") or record.get("adobe_account_name") or "").strip()
        if not email:
            continue
        key = email.lower()
        if key in mother_seen:
            continue
        mother_seen.add(key)
        mother_options.append({"email": email})
    filtered.sort(key=parse_child_created_ts, reverse=True)
    return {
        "accounts": filtered,
        "summary": summary,
        "pool_options": pool_options,
        "mother_options": mother_options,
    }


@app.post("/api/child-accounts/monitor/run")
async def run_child_monitor_now():
    summary = await monitor_child_accounts_once("manual")
    await task_manager.broadcast("__STATE_UPDATE__")
    return {"status": "ok", **summary}


@app.get("/api/child-accounts/monitor/logs")
async def get_child_monitor_logs(limit: int = 50):
    logs = list_child_monitor_logs_sync()
    count = max(1, min(int(limit or 50), CHILD_MONITOR_LOG_MAX_ITEMS))
    return {"logs": list(reversed(logs[-count:]))}


@app.get("/api/child-accounts/monitor/logs/download")
async def download_child_monitor_logs():
    logs = list_child_monitor_logs_sync()
    export_filename = f"子账号池监测日志_{export_timestamp()}.json"
    from fastapi.responses import Response
    return Response(
        json.dumps(logs, ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(export_filename)}"
        },
    )


@app.post("/api/child-accounts/{child_id}/refresh-credits")
async def refresh_child_account_credits(child_id: str):
    try:
        record = await check_child_exhausted(child_id)
        return {"status": "ok", "account": public_child_account(record)}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"message": str(exc)})


@app.post("/api/child-accounts/{child_id}/remove")
async def remove_child_account_member(child_id: str):
    records = await list_child_accounts_raw()
    record = find_child_record(records, child_id)
    if not record:
        return JSONResponse(status_code=404, content={"message": "子账号不存在"})
    try:
        updated = await remove_child_member(record, "手动移除")
        return {"status": "ok", "account": public_child_account(updated)}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"message": str(exc)})


@app.post("/api/child-accounts/{child_id}/replace")
async def replace_child_account_api(child_id: str):
    try:
        updated = await replace_child_account(child_id, "手动补号")
        return {"status": "ok", "account": public_child_account(updated)}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"message": str(exc)})


@app.post("/api/child-accounts/replace")
async def replace_child_accounts_bulk(req: ChildAccountDeleteRequest):
    ids = [str(item) for item in req.ids if str(item)]
    if not ids:
        return JSONResponse(status_code=400, content={"message": "请选择要补号的子账号"})
    results = []
    records = await list_child_accounts_raw()
    selected_records = []
    for child_id in ids:
        record = find_child_record(records, child_id)
        if not record:
            results.append({"id": child_id, "email": child_id, "ok": False, "skipped": False, "message": "子账号不存在"})
            continue
        email = record.get("email", "")
        if record.get("status") == "replaced":
            results.append({"id": child_id, "email": email, "ok": False, "skipped": True, "message": "已替换记录不重复补号"})
            continue
        selected_records.append(record)
    grouped_records: dict[str, list[dict]] = {}
    for record in selected_records:
        grouped_records.setdefault(record.get("adobe_account_id", ""), []).append(record)

    for account_id, group_records in grouped_records.items():
        lock = child_replacement_locks.setdefault(account_id, asyncio.Lock())
        async with lock:
            try:
                task = await create_replacement_batch_task(group_records, "批量补号")
                for record in group_records:
                    updated = await update_child_account(
                        record.get("id", ""),
                        status="replacing",
                        replacement_task_id=task.id,
                        replaced_at="",
                        failure_reason="",
                        replacement_reason="批量补号，等待任务开始移除",
                    )
                    results.append({
                        "id": record.get("id", ""),
                        "email": record.get("email", ""),
                        "ok": True,
                        "skipped": False,
                        "message": f"已加入补号任务 #{task.id}，等待任务开始后移除旧子号",
                        "account": public_child_account(updated or record),
                    })
            except Exception as exc:
                for record in group_records:
                    await update_child_account(record.get("id", ""), failure_reason=f"创建补号任务失败：{exc}")
                    results.append({
                        "id": record.get("id", ""),
                        "email": record.get("email", ""),
                        "ok": False,
                        "skipped": False,
                        "message": str(exc),
                    })
    success = sum(1 for item in results if item.get("ok"))
    skipped = sum(1 for item in results if item.get("skipped"))
    failed = len(results) - success - skipped
    return {
        "status": "ok" if failed == 0 else "partial",
        "total": len(results),
        "success": success,
        "skipped": skipped,
        "failed": failed,
        "results": results,
    }


@app.post("/api/child-accounts/{child_id}/import-token-pool")
async def import_child_account_token_pool(child_id: str):
    records = await list_child_accounts_raw()
    record = find_child_record(records, child_id)
    if not record:
        return JSONResponse(status_code=404, content={"message": "子账号不存在"})
    external_enabled = bool(config.get("token_pool_enabled"))
    result = await import_payload_to_token_pool_result(child_cookie_payload(record), f"[子账号池 · {record.get('email', '')}]")
    ok = bool(result.get("ok"))
    updated = await update_child_account(
        child_id,
        external_pool_status="imported" if external_enabled and ok else "skipped" if not external_enabled else "failed",
        external_pool_id=result.get("pool_id", "") if external_enabled and ok else "",
        external_pool_name=result.get("pool_name", "") if external_enabled and ok else "",
        external_pool_error="" if ok else result.get("error", "") or "外部 Token 池导入失败",
    )
    return {"status": "ok" if ok else "failed", "account": public_child_account(updated or record)}


@app.get("/api/child-accounts/{child_id}/export-cookie")
async def export_child_account_cookie(child_id: str):
    records = await list_child_accounts_raw()
    record = find_child_record(records, child_id)
    if not record:
        return JSONResponse(status_code=404, content={"message": "子账号不存在"})
    if not record.get("cookie"):
        return JSONResponse(status_code=400, content={"message": "该子账号没有可导出的 cookie"})
    payload = child_cookie_export_payload(record)
    export_filename = f"{sanitize_filename(record.get('email', ''), '子账号')}_cookie.json"
    from fastapi.responses import Response
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(export_filename)}"
        },
    )


@app.post("/api/child-accounts/delete")
async def delete_child_account_records(req: ChildAccountDeleteRequest):
    ids = {str(item) for item in req.ids}
    if not ids:
        return JSONResponse(status_code=400, content={"message": "请选择要删除的子账号记录"})
    async with child_accounts_lock:
        records = load_child_accounts_sync()
        kept = [record for record in records if str(record.get("id", "")) not in ids]
        deleted = len(records) - len(kept)
        save_child_accounts_sync(kept)
    await task_manager.broadcast("__STATE_UPDATE__")
    return {"status": "ok", "deleted": deleted}


@app.post("/api/tasks/delete")
async def delete_tasks(req: TaskDeleteRequest):
    task_manager.delete_tasks(req.ids)
    await task_manager.broadcast("__STATE_UPDATE__")
    return {"status": "ok", "deleted": len(req.ids)}

@app.post("/api/tasks/stop")
async def stop_tasks(req: TaskDeleteRequest):
    await task_manager.stop_tasks(req.ids)
    await task_manager.broadcast("__STATE_UPDATE__")
    return {"status": "ok", "stopped": len(req.ids)}

# ─── Worker Logic ───
async def terminate_process(process: asyncio.subprocess.Process | None):
    if process is None or process.returncode is not None:
        return

    if os.name != "nt" and process.pid:
        with suppress(ProcessLookupError):
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    else:
        with suppress(ProcessLookupError):
            process.terminate()

    try:
        await asyncio.wait_for(process.wait(), timeout=5)
        return
    except asyncio.TimeoutError:
        pass

    if os.name != "nt" and process.pid:
        with suppress(ProcessLookupError):
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    else:
        with suppress(ProcessLookupError):
            process.kill()

    with suppress(asyncio.TimeoutError):
        await asyncio.wait_for(process.wait(), timeout=5)


async def stream_process_output(
    process: asyncio.subprocess.Process,
    prefix: str,
    self_email: str = "",
    email_state: dict | None = None,
):
    while True:
        line = await process.stdout.readline()
        if not line:
            break
        decoded = line.decode("utf-8", errors="ignore").strip()
        if decoded:
            if "__SELF_EMAIL_VERIFICATION_SENT__" in decoded and self_email:
                if email_state is not None and not email_state.get("used_marked"):
                    await mark_self_email_used(self_email)
                    email_state["used_marked"] = True
                    await task_manager.broadcast(f"{prefix} ✅ 自备邮箱已走到发送验证码，标记为已使用")
                    await task_manager.broadcast("__STATE_UPDATE__")
                continue
            await task_manager.broadcast(f"{prefix} {decoded}")


async def finalize_output_task(output_task: asyncio.Task):
    try:
        await asyncio.wait_for(output_task, timeout=5)
    except asyncio.TimeoutError:
        output_task.cancel()
        with suppress(asyncio.CancelledError):
            await output_task


def build_token_pool_import_url(site: str) -> str:
    raw = (site or "").strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    if "/api/v1/automation/import-cookie" in raw:
        return raw
    return urljoin(raw.rstrip("/") + "/", "api/v1/automation/import-cookie")


def build_token_pool_exhausted_url(site: str) -> str:
    raw = (site or "").strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    if "/api/v1/automation/exhausted-accounts" in raw:
        return raw
    return urljoin(raw.rstrip("/") + "/", "api/v1/automation/exhausted-accounts")


def normalize_token_pools(raw_pools=None) -> list[dict]:
    pools = raw_pools if raw_pools is not None else config.get("token_pools")
    normalized: list[dict] = []
    if isinstance(pools, list):
        for index, pool in enumerate(pools, 1):
            if not isinstance(pool, dict):
                continue
            site = (pool.get("site") or pool.get("url") or "").strip()
            key = (pool.get("key") or pool.get("token_pool_key") or "").strip()
            if not site and not key:
                continue
            normalized.append({
                "id": (pool.get("id") or uuid.uuid4().hex).strip(),
                "name": (pool.get("name") or f"{index}号池").strip(),
                "site": site,
                "key": key,
                "enabled": bool(pool.get("enabled", True)),
                "success": int(pool.get("success", 0) or 0),
                "failed": int(pool.get("failed", 0) or 0),
            })

    legacy_site = (config.get("token_pool_site") or "").strip()
    legacy_key = (config.get("token_pool_key") or "").strip()
    if not normalized and (legacy_site or legacy_key):
        normalized.append({
            "id": "legacy",
            "name": "1号池",
            "site": legacy_site,
            "key": legacy_key,
            "enabled": True,
            "success": 0,
            "failed": 0,
        })
    return normalized


def save_token_pool_stats(pools: list[dict], cursor: int) -> None:
    config["token_pools"] = pools
    config["token_pool_cursor"] = cursor
    save_config(config)


async def reserve_token_pool_order() -> list[dict]:
    async with token_pool_lock:
        pools = normalize_token_pools()
        enabled_pools = [pool for pool in pools if pool.get("enabled")]
        if not enabled_pools:
            return []

        cursor = int(config.get("token_pool_cursor", 0) or 0)
        start = cursor % len(enabled_pools)
        ordered = enabled_pools[start:] + enabled_pools[:start]
        next_cursor = (start + 1) % len(enabled_pools)
        save_token_pool_stats(pools, next_cursor)
        return [dict(pool) for pool in ordered]


async def record_token_pool_result(pool_id: str, success: bool) -> None:
    async with token_pool_lock:
        pools = normalize_token_pools()
        source_pool = next((item for item in pools if item.get("id") == pool_id), None)
        if not source_pool:
            return
        stat_key = "success" if success else "failed"
        source_pool[stat_key] = int(source_pool.get(stat_key, 0) or 0) + 1
        save_token_pool_stats(pools, int(config.get("token_pool_cursor", 0) or 0))


async def import_cookie_to_single_token_pool(prefix: str, pool: dict, payload: dict) -> tuple[bool, str]:
    import_url = build_token_pool_import_url(pool.get("site", ""))
    token_pool_key = (pool.get("key") or "").strip()
    pool_name = pool.get("name") or "Token 池"
    if not import_url or not token_pool_key:
        return False, "网站地址或 Token 池密钥未配置"

    headers = {
        "Authorization": f"Bearer {token_pool_key}",
        "X-Token-Pool-Key": token_pool_key,
        "Content-Type": "application/json",
    }

    last_error = ""
    for attempt in range(1, 4):
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(import_url, json=payload, headers=headers)
            if 200 <= response.status_code < 300:
                return True, ""
            detail = response.text[:200].replace("\n", " ")
            last_error = f"HTTP {response.status_code} {detail}"
        except Exception as e:
            last_error = str(e)

        if attempt < 3:
            await task_manager.broadcast(
                f"{prefix} ⚠️ {pool_name} 入池失败，第 {attempt}/3 次：{last_error}，2 秒后重试"
            )
            await asyncio.sleep(2)
    return False, last_error


async def import_cookie_to_token_pool(cookie_file: str, prefix: str) -> bool:
    result = await import_cookie_to_token_pool_result(cookie_file, prefix)
    return bool(result.get("ok"))


async def import_cookie_to_token_pool_result(cookie_file: str, prefix: str) -> dict:
    if not config.get("token_pool_enabled"):
        return {"ok": True, "status": "skipped", "pool_id": "", "pool_name": "", "error": ""}

    try:
        with open(cookie_file, "r", encoding="utf-8") as f:
            cookie_data = json.load(f)
    except Exception as e:
        await task_manager.broadcast(f"{prefix} ⚠️ 自动入池失败：无法读取 Cookie 文件 ({e})")
        return {"ok": False, "status": "failed", "pool_id": "", "pool_name": "", "error": str(e)}

    payload = {
        "name": cookie_data.get("name", ""),
        "cookie": cookie_data.get("cookie", ""),
    }
    if not payload["cookie"]:
        await task_manager.broadcast(f"{prefix} ⚠️ 自动入池失败：Cookie 内容为空")
        return {"ok": False, "status": "failed", "pool_id": "", "pool_name": "", "error": "Cookie 内容为空"}

    return await import_payload_to_token_pool_result(payload, prefix)


async def import_payload_to_token_pool(payload: dict, prefix: str) -> bool:
    result = await import_payload_to_token_pool_result(payload, prefix)
    return bool(result.get("ok"))


async def import_payload_to_token_pool_result(payload: dict, prefix: str) -> dict:
    if not config.get("token_pool_enabled"):
        return {"ok": True, "status": "skipped", "pool_id": "", "pool_name": "", "error": ""}

    if not payload.get("cookie"):
        await task_manager.broadcast(f"{prefix} ⚠️ 自动入池失败：Cookie 内容为空")
        return {"ok": False, "status": "failed", "pool_id": "", "pool_name": "", "error": "Cookie 内容为空"}

    ordered = await reserve_token_pool_order()
    if not ordered:
        await task_manager.broadcast(f"{prefix} ⚠️ 自动入池已开启，但没有启用的 Token 池")
        return {"ok": False, "status": "failed", "pool_id": "", "pool_name": "", "error": "没有启用的 Token 池"}

    last_error = ""
    for pool in ordered:
        pool_name = pool.get("name") or "Token 池"
        await task_manager.broadcast(f"{prefix} 正在自动入池：{pool_name}")
        ok, error = await import_cookie_to_single_token_pool(prefix, pool, payload)
        if ok:
            await record_token_pool_result(pool.get("id", ""), True)
            await task_manager.broadcast(f"{prefix} ✅ 已自动导入 {pool_name}")
            return {
                "ok": True,
                "status": "imported",
                "pool_id": pool.get("id", ""),
                "pool_name": pool_name,
                "error": "",
            }
        await record_token_pool_result(pool.get("id", ""), False)
        last_error = error
        await task_manager.broadcast(f"{prefix} ⚠️ {pool_name} 入池失败，尝试下一个池：{error}")

    await task_manager.broadcast(f"{prefix} ⚠️ 自动入池失败：全部 Token 池均失败；最后错误：{last_error}")
    return {"ok": False, "status": "failed", "pool_id": "", "pool_name": "", "error": last_error}


def now_text() -> str:
    return datetime.now().isoformat(timespec="seconds")


def now_ts() -> int:
    return int(datetime.now().timestamp())


def parse_child_created_ts(record: dict) -> float:
    created_at = str(record.get("created_at") or "").strip()
    if not created_at:
        return 0
    with suppress(Exception):
        return datetime.fromisoformat(created_at).timestamp()
    return 0


def load_child_accounts_sync() -> list[dict]:
    if not os.path.exists(CHILD_ACCOUNTS_FILE):
        return []
    try:
        with open(CHILD_ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
    except Exception:
        return []
    return []


def save_child_accounts_sync(accounts: list[dict]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CHILD_ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(accounts, f, ensure_ascii=False, indent=2)


def load_child_monitor_logs_sync() -> list[dict]:
    if not os.path.exists(CHILD_MONITOR_LOG_FILE):
        return []
    try:
        with open(CHILD_MONITOR_LOG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
    except Exception:
        return []
    return []


def prune_child_monitor_logs(logs: list[dict]) -> list[dict]:
    cutoff = datetime.now() - timedelta(seconds=CHILD_MONITOR_LOG_RETENTION_SECONDS)
    kept = []
    for item in logs:
        created_at = item.get("created_at", "")
        try:
            created_dt = datetime.fromisoformat(created_at)
        except (TypeError, ValueError):
            created_dt = datetime.now()
        if created_dt >= cutoff:
            kept.append(item)
    return kept[-CHILD_MONITOR_LOG_MAX_ITEMS:]


def save_child_monitor_logs_sync(logs: list[dict]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    logs = prune_child_monitor_logs(logs)
    with open(CHILD_MONITOR_LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, ensure_ascii=False, indent=2)


def list_child_monitor_logs_sync() -> list[dict]:
    logs = prune_child_monitor_logs(load_child_monitor_logs_sync())
    save_child_monitor_logs_sync(logs)
    return logs


async def append_child_monitor_log(entry: dict) -> dict:
    log = {
        "id": uuid.uuid4().hex,
        "created_at": now_text(),
        **entry,
    }
    async with child_accounts_lock:
        logs = load_child_monitor_logs_sync()
        logs.append(log)
        save_child_monitor_logs_sync(logs)
    return log


def public_child_account(record: dict) -> dict:
    hidden = dict(record)
    for key in ("cookie", "access_token", "refresh_token", "email_password", "password"):
        if hidden.get(key):
            hidden[key] = "********"
    return hidden


def find_child_record(records: list[dict], child_id: str) -> dict | None:
    return next((item for item in records if item.get("id") == child_id), None)


async def list_child_accounts_raw() -> list[dict]:
    async with child_accounts_lock:
        return load_child_accounts_sync()


async def save_child_accounts_raw(records: list[dict]) -> None:
    async with child_accounts_lock:
        save_child_accounts_sync(records)


async def upsert_child_account(record: dict) -> dict:
    async with child_accounts_lock:
        records = load_child_accounts_sync()
        email_key = (record.get("email") or "").strip().lower()
        account_id = record.get("adobe_account_id", "")
        existing = next(
            (
                item for item in records
                if (item.get("email") or "").strip().lower() == email_key
                and item.get("adobe_account_id", "") == account_id
                and item.get("status") not in ("removed", "replaced")
            ),
            None,
        )
        if existing:
            existing.update(record)
            existing["updated_at"] = now_text()
            saved = existing
        else:
            saved = {
                "id": uuid.uuid4().hex,
                "created_at": now_text(),
                "updated_at": now_text(),
                **record,
            }
            records.append(saved)
        save_child_accounts_sync(records)
        return saved


async def update_child_account(child_id: str, **updates) -> dict | None:
    async with child_accounts_lock:
        records = load_child_accounts_sync()
        record = find_child_record(records, child_id)
        if not record:
            return None
        record.update(updates)
        record["updated_at"] = now_text()
        save_child_accounts_sync(records)
        return record


def child_cookie_payload(record: dict) -> dict:
    return {
        "name": record.get("email", ""),
        "cookie": record.get("cookie", ""),
    }


def child_cookie_export_payload(record: dict) -> dict:
    return {
        "cookie": record.get("cookie", ""),
        "name": record.get("email", ""),
        "email": record.get("email", ""),
        "password": record.get("password", ""),
        "access_token": record.get("access_token", ""),
        "credits": record.get("credits_available"),
        "expires_at": record.get("expires_at"),
        "display_name": record.get("display_name", ""),
        "user_id": record.get("user_id", ""),
        "refresh_token": record.get("refresh_token", ""),
    }


def build_child_account_record(
    *,
    account: dict,
    reserved: dict,
    cookie_file: str,
    cookie_data: dict,
    task: Task | None,
) -> dict:
    credits = cookie_data.get("credits")
    try:
        credits_value = float(credits) if credits is not None else None
    except (TypeError, ValueError):
        credits_value = None
    return {
        "email": (reserved.get("email") or cookie_data.get("email") or "").strip(),
        "password": reserved.get("password") or cookie_data.get("password", ""),
        "email_password": reserved.get("password", ""),
        "api_url": reserved.get("api_url", ""),
        "client_id": reserved.get("client_id", ""),
        "refresh_token": cookie_data.get("refresh_token") or reserved.get("refresh_token", ""),
        "adobe_account_id": account.get("id", ""),
        "adobe_account_email": account.get("email", ""),
        "adobe_account_name": account.get("name", ""),
        "org_id": account.get("organization_id", "") or account.get("org_id", ""),
        "product_id": account.get("product_id", ""),
        "product_name": account.get("product_name", ""),
        "license_group_id": account.get("license_group_id", ""),
        "member_id": reserved.get("_member_id", ""),
        "cookie_file": cookie_file,
        "cookie": cookie_data.get("cookie", ""),
        "access_token": cookie_data.get("access_token", ""),
        "user_id": cookie_data.get("user_id", ""),
        "display_name": cookie_data.get("display_name", ""),
        "expires_at": cookie_data.get("expires_at"),
        "credits_available": credits_value,
        "credits_updated_at": now_ts() if credits_value is not None else None,
        "status": "active",
        "external_pool_status": "pending",
        "external_pool_error": "",
        "last_checked_at": "",
        "check_failures": 0,
        "failure_reason": "",
        "source_task_id": getattr(task, "id", None),
    }


async def create_child_account_from_cookie(
    *,
    account: dict,
    reserved: dict,
    cookie_file: str,
    task: Task | None,
) -> dict | None:
    try:
        with open(cookie_file, "r", encoding="utf-8") as f:
            cookie_data = json.load(f)
    except Exception as exc:
        await task_manager.broadcast(f"[子账号池] ⚠️ 无法读取子账号 cookie 文件：{exc}")
        return None
    record = build_child_account_record(
        account=account,
        reserved=reserved,
        cookie_file=cookie_file,
        cookie_data=cookie_data,
        task=task,
    )
    saved = await upsert_child_account(record)
    await task_manager.broadcast(f"[子账号池] ✅ 已保存 {saved.get('email')} 到内部子账号池")
    return saved


def child_needs_token_refresh(record: dict) -> bool:
    expires_at = record.get("expires_at")
    try:
        return bool(expires_at) and int(expires_at) <= now_ts() + 120
    except (TypeError, ValueError):
        return False


async def refresh_child_firefly_login(record: dict, prefix: str = "[子账号池]") -> dict:
    email = record.get("email", "")
    refresh_token = record.get("refresh_token", "")
    client_id = record.get("client_id", "")
    mail_url = record.get("api_url", "")
    if not mail_url and not (refresh_token and client_id):
        raise RuntimeError("缺少子号取件配置，无法重新协议登录刷新 token")

    loop = asyncio.get_running_loop()

    def log(message: str) -> None:
        loop.call_soon_threadsafe(
            asyncio.create_task,
            task_manager.broadcast(f"{prefix} {email} {message}"),
        )

    result = await asyncio.to_thread(
        firefly_protocol.register_account,
        email=email,
        refresh_token=refresh_token,
        client_id=client_id,
        mail_url=mail_url,
        proxy_url=adobe_proxy_url(),
        otp_timeout=180,
        log=log,
    )
    rotated = result.get("rotated_refresh_token") or ""
    updates = {
        "access_token": result.get("access_token", ""),
        "cookie": result.get("cookie", ""),
        "user_id": result.get("user_id", ""),
        "display_name": result.get("display_name", ""),
        "expires_at": result.get("expires_at"),
        "failure_reason": "",
    }
    if rotated:
        updates["refresh_token"] = rotated
        await update_self_email_refresh_token(email, rotated)
    credits = result.get("credits")
    if credits is not None:
        updates["credits_available"] = float(credits)
        updates["credits_updated_at"] = now_ts()
    updated = await update_child_account(record.get("id", ""), **updates)
    return updated or {**record, **updates}


async def refresh_child_credits(child_id: str, *, allow_relogin: bool = True) -> dict:
    records = await list_child_accounts_raw()
    record = find_child_record(records, child_id)
    if not record:
        raise RuntimeError("子账号不存在")
    if record.get("status") not in ("active", "check_failed"):
        raise RuntimeError("该子账号不是可检测状态")

    working = record
    if allow_relogin and child_needs_token_refresh(working):
        working = await refresh_child_firefly_login(working)

    credits = await asyncio.to_thread(
        firefly_protocol.fetch_credits,
        working.get("access_token", ""),
        working.get("user_id", ""),
        adobe_proxy_url(),
    )
    if credits is None and allow_relogin:
        working = await refresh_child_firefly_login(working)
        credits = await asyncio.to_thread(
            firefly_protocol.fetch_credits,
            working.get("access_token", ""),
            working.get("user_id", ""),
            adobe_proxy_url(),
        )

    if credits is None:
        failures = int(working.get("check_failures", 0) or 0) + 1
        status = "check_failed" if failures >= int(config.get("child_monitor_max_failures", 3) or 3) else working.get("status", "active")
        updated = await update_child_account(
            child_id,
            check_failures=failures,
            status=status,
            last_checked_at=now_text(),
            failure_reason="积分查询失败",
        )
        raise RuntimeError((updated or working).get("failure_reason", "积分查询失败"))

    updated = await update_child_account(
        child_id,
        credits_available=float(credits),
        credits_updated_at=now_ts(),
        check_failures=0,
        status="active",
        last_checked_at=now_text(),
        failure_reason="",
    )
    return updated or working


def monitored_token_pools() -> list[dict]:
    pools = [pool for pool in normalize_token_pools() if pool.get("enabled")]
    selected = set(str(pool_id) for pool_id in config.get("child_monitor_pool_ids", []) if str(pool_id))
    if selected:
        pools = [pool for pool in pools if pool.get("id") in selected]
    return pools


async def fetch_exhausted_emails_from_pool(pool: dict) -> tuple[set[str], str, int]:
    url = build_token_pool_exhausted_url(pool.get("site", ""))
    key = (pool.get("key") or "").strip()
    if not url or not key:
        return set(), "Token 池地址或密钥未配置", 1
    headers = {
        "Authorization": f"Bearer {key}",
        "X-Token-Pool-Key": key,
        "Accept": "application/json",
    }
    last_error = ""
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=headers)
            if response.status_code < 200 or response.status_code >= 300:
                last_error = f"HTTP {response.status_code} {(response.text or '')[:160]}"
            else:
                data = response.json()
                emails = data.get("emails") if isinstance(data, dict) else []
                if not isinstance(emails, list):
                    last_error = "响应缺少 emails 数组"
                else:
                    return {
                        str(email).strip().lower()
                        for email in emails
                        if str(email or "").strip()
                    }, "", attempt
        except Exception as exc:
            last_error = str(exc)

        if attempt < max_attempts:
            await asyncio.sleep(2)

    return set(), last_error, max_attempts


async def fetch_exhausted_email_index() -> tuple[dict[str, set[str]], dict[str, str], list[dict]]:
    exhausted: dict[str, set[str]] = {}
    errors: dict[str, str] = {}
    pool_results: list[dict] = []
    for pool in monitored_token_pools():
        pool_id = pool.get("id") or ""
        emails, error, attempts = await fetch_exhausted_emails_from_pool(pool)
        if error:
            errors[pool_id] = error
            pool_results.append({
                "pool_id": pool_id,
                "pool_name": pool.get("name") or "Token 池",
                "site": pool.get("site", ""),
                "ok": False,
                "count": 0,
                "error": error,
                "attempts": attempts,
            })
            continue
        pool_results.append({
            "pool_id": pool_id,
            "pool_name": pool.get("name") or "Token 池",
            "site": pool.get("site", ""),
            "ok": True,
            "count": len(emails),
            "error": "",
            "attempts": attempts,
        })
        for email in emails:
            exhausted.setdefault(email, set()).add(pool_id)
    return exhausted, errors, pool_results


async def delete_exhausted_email_from_pool(pool: dict, email: str) -> dict:
    url = build_token_pool_exhausted_url(pool.get("site", ""))
    key = (pool.get("key") or "").strip()
    pool_id = pool.get("id") or ""
    pool_name = pool.get("name") or "Token 池"
    result = {
        "pool_id": pool_id,
        "pool_name": pool_name,
        "ok": False,
        "status": "failed",
        "deleted_count": 0,
        "missing_emails": [],
        "error": "",
    }
    if not url or not key:
        result["error"] = "Token 池地址或密钥未配置"
        return result
    headers = {
        "Authorization": f"Bearer {key}",
        "X-Token-Pool-Key": key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request("DELETE", url, json={"emails": [email]}, headers=headers)
        try:
            data = response.json() if response.content else {}
        except ValueError:
            data = {}
        if response.status_code < 200 or response.status_code >= 300:
            result["error"] = f"HTTP {response.status_code} {(response.text or '')[:160]}"
            return result
        deleted_count = int(data.get("deleted_count", 0) or 0) if isinstance(data, dict) else 0
        result.update({
            "ok": True,
            "status": data.get("status", "ok") if isinstance(data, dict) else "ok",
            "deleted_count": deleted_count,
            "missing_emails": data.get("missing_emails", []) if isinstance(data, dict) else [],
            "token_count": data.get("token_count", 0) if isinstance(data, dict) else 0,
        })
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


async def cleanup_replaced_child_token(child_id: str, prefix: str = "[子账号池]") -> list[dict]:
    records = await list_child_accounts_raw()
    record = find_child_record(records, child_id)
    if not record:
        return []
    email = (record.get("email") or "").strip()
    pool_ids = [str(pool_id) for pool_id in (record.get("exhausted_pool_ids") or []) if str(pool_id)]
    if not email or not pool_ids:
        await update_child_account(
            child_id,
            exhausted_token_delete_status="skipped",
            exhausted_token_delete_error="未记录耗尽来源池，跳过号池删除",
        )
        return []

    selected = set(pool_ids)
    pools = [pool for pool in monitored_token_pools() if pool.get("id") in selected]
    if not pools:
        await update_child_account(
            child_id,
            exhausted_token_delete_status="skipped",
            exhausted_token_delete_error="耗尽来源池未启用或不存在",
        )
        return []

    results = []
    for pool in pools:
        pool_name = pool.get("name") or "Token 池"
        await task_manager.broadcast(f"{prefix} 清理旧耗尽 token：{pool_name} / {email}")
        result = await delete_exhausted_email_from_pool(pool, email)
        results.append(result)
        if result.get("ok"):
            await task_manager.broadcast(
                f"{prefix} ✅ 已从 {pool_name} 删除旧耗尽 token：{email}，删除 {result.get('deleted_count', 0)} 个"
            )
        else:
            await task_manager.broadcast(
                f"{prefix} ⚠️ {pool_name} 删除旧耗尽 token 失败：{result.get('error', '')}"
            )

    failed = [item for item in results if not item.get("ok")]
    deleted_count = sum(int(item.get("deleted_count", 0) or 0) for item in results if item.get("ok"))
    await update_child_account(
        child_id,
        exhausted_token_deleted_at=now_text(),
        exhausted_token_delete_status="failed" if failed else "deleted" if deleted_count else "not_found",
        exhausted_token_delete_error="；".join(
            f"{item.get('pool_name')}: {item.get('error', '')}" for item in failed
        ),
        exhausted_token_delete_results=results,
        exhausted_token_deleted_count=deleted_count,
    )
    return results


async def check_child_exhausted(child_id: str) -> dict:
    records = await list_child_accounts_raw()
    record = find_child_record(records, child_id)
    if not record:
        raise RuntimeError("子账号不存在")
    exhausted, errors, _pool_results = await fetch_exhausted_email_index()
    email = (record.get("email") or "").strip().lower()
    pool_ids = sorted(exhausted.get(email, set()))
    updates = {
        "last_checked_at": now_text(),
        "exhausted_pool_ids": pool_ids,
        "exhausted_detected_at": now_text() if pool_ids else record.get("exhausted_detected_at", ""),
        "failure_reason": "" if not errors else "部分 Token 池查询失败",
    }
    if pool_ids and record.get("status") == "active":
        updates["status"] = "exhausted"
    elif not pool_ids and record.get("status") in ("exhausted", "check_failed"):
        updates["status"] = "active"
    updated = await update_child_account(child_id, **updates)
    return updated or record


async def remove_child_member(record: dict, reason: str = "手动移除") -> dict:
    account = find_adobe_account(record.get("adobe_account_id", ""))
    if not account:
        raise RuntimeError("所属母号不存在")
    email = record.get("email", "")
    if not email:
        raise RuntimeError("子账号邮箱为空")
    async with adobe_account_lock:
        results = await remove_adobe_members(account, [email])
    result = results[0] if results else {"ok": False, "message": "移除接口无返回"}
    if not result.get("ok"):
        raise RuntimeError(result.get("message") or "移除成员失败")
    updated = await update_child_account(
        record.get("id", ""),
        status="removed",
        removed_at=now_text(),
        failure_reason="",
        replacement_reason=reason,
    )
    return updated or record


async def create_replacement_task(record: dict, reason: str = "自动换号") -> Task:
    return await create_replacement_batch_task([record], reason)


async def create_replacement_batch_task(records: list[dict], reason: str = "自动换号") -> Task:
    if not records:
        raise RuntimeError("没有可补号的子账号")
    account_id = records[0].get("adobe_account_id", "")
    if any(record.get("adobe_account_id", "") != account_id for record in records):
        raise RuntimeError("批量补号请选择同一个母号下的子账号")
    if not find_adobe_account(account_id):
        raise RuntimeError("所属母号不存在，无法补号")
    child_ids = [record.get("id", "") for record in records if record.get("id")]
    child_emails = [record.get("email", "") for record in records if record.get("email")]
    task = task_manager.create_task(
        len(child_ids),
        1,
        False,
        f"子号批量补号: {len(child_ids)} 个",
        "self",
        "invite",
        [account_id],
        False,
    )
    task.replacement_child_id = child_ids[0] if child_ids else ""
    task.replacement_child_ids = child_ids
    task.replacement_done_child_ids = []
    await task_manager.queue.put(task)
    asyncio.create_task(task_manager.start_queue_worker())
    if child_emails:
        await task_manager.broadcast(f"[Task#{task.id}] Step 0/3：已绑定旧子号，等待任务开始后移除：{', '.join(child_emails)}")
    await task_manager.broadcast(
        f"[子账号池] 已创建补号任务 #{task.id}：{reason}，旧子号 {len(child_ids)} 个"
        + (f"（{', '.join(child_emails[:5])}{'...' if len(child_emails) > 5 else ''}）" if child_emails else "")
    )
    await task_manager.broadcast("__STATE_UPDATE__")
    return task


async def replace_child_account(child_id: str, reason: str = "积分低于阈值") -> dict:
    records = await list_child_accounts_raw()
    record = find_child_record(records, child_id)
    if not record:
        raise RuntimeError("子账号不存在")
    account_id = record.get("adobe_account_id", "")
    lock = child_replacement_locks.setdefault(account_id, asyncio.Lock())
    async with lock:
        records = await list_child_accounts_raw()
        record = find_child_record(records, child_id)
        if not record:
            raise RuntimeError("子账号不存在")
        if record.get("status") in ("replacing", "replaced"):
            return record
        task = await create_replacement_task(record, reason)
        updated = await update_child_account(
            child_id,
            status="replacing" if record.get("status") != "removed" else "removed",
            replacement_task_id=task.id,
            replaced_at="",
            failure_reason="",
            replacement_reason=f"{reason}，等待任务开始移除",
        )
        return updated or record


async def monitor_child_accounts_once(source: str = "manual") -> dict:
    records = await list_child_accounts_raw()
    active = [record for record in records if record.get("status") in ("active", "exhausted", "check_failed")]
    exhausted, errors, pool_results = await fetch_exhausted_email_index()
    checked = len(active)
    matched = 0
    replaced = 0
    failed = 0
    matched_accounts = []
    replacements = []
    failed_accounts = []
    replacement_records: list[dict] = []
    replacement_reasons: dict[str, str] = {}
    for record in active:
        email = (record.get("email") or "").strip().lower()
        pool_ids = sorted(exhausted.get(email, set()))
        try:
            if pool_ids:
                matched += 1
                matched_accounts.append({
                    "child_id": record.get("id", ""),
                    "email": record.get("email", ""),
                    "adobe_account_email": record.get("adobe_account_email", ""),
                    "pool_ids": pool_ids,
                })
                await update_child_account(
                    record.get("id", ""),
                    status="exhausted",
                    exhausted_pool_ids=pool_ids,
                    exhausted_detected_at=now_text(),
                    last_checked_at=now_text(),
                    failure_reason="",
                )
                replacement_records.append(record)
                replacement_reasons[record.get("id", "")] = f"Token 池标记耗尽：{', '.join(pool_ids)}"
            else:
                updates = {
                    "last_checked_at": now_text(),
                    "exhausted_pool_ids": [],
                }
                if record.get("status") in ("exhausted", "check_failed"):
                    updates["status"] = "active"
                await update_child_account(record.get("id", ""), **updates)
        except Exception as exc:
            failed += 1
            failed_accounts.append({
                "child_id": record.get("id", ""),
                "email": record.get("email", ""),
                "error": str(exc),
            })
    grouped_records: dict[str, list[dict]] = {}
    for record in replacement_records:
        grouped_records.setdefault(record.get("adobe_account_id", ""), []).append(record)

    for account_id, group_records in grouped_records.items():
        lock = child_replacement_locks.setdefault(account_id, asyncio.Lock())
        async with lock:
            try:
                reason_items = []
                for record in group_records:
                    reason = replacement_reasons.get(record.get("id", ""), "Token 池标记耗尽")
                    if reason not in reason_items:
                        reason_items.append(reason)
                task = await create_replacement_batch_task(group_records, "；".join(reason_items[:3]))
                for record in group_records:
                    updated = await update_child_account(
                        record.get("id", ""),
                        status="replacing",
                        replacement_task_id=task.id,
                        replaced_at="",
                        failure_reason="",
                        replacement_reason=f"{replacement_reasons.get(record.get('id', ''), 'Token 池标记耗尽')}，等待任务开始移除",
                    )
                    replacements.append({
                        "child_id": record.get("id", ""),
                        "email": record.get("email", ""),
                        "replacement_task_id": task.id,
                        "status": (updated or record).get("status", ""),
                    })
                    replaced += 1
            except Exception as exc:
                for record in group_records:
                    failed += 1
                    await update_child_account(record.get("id", ""), failure_reason=f"创建补号任务失败：{exc}")
                    failed_accounts.append({
                        "child_id": record.get("id", ""),
                        "email": record.get("email", ""),
                        "error": str(exc),
                    })
    summary = {
        "checked": checked,
        "matched": matched,
        "refreshed": matched,
        "replaced": replaced,
        "failed": failed,
        "pool_errors": errors,
        "pool_results": pool_results,
        "matched_accounts": matched_accounts,
        "replacements": replacements,
        "failed_accounts": failed_accounts,
    }
    await append_child_monitor_log({
        "source": source,
        **summary,
    })
    return summary


async def child_monitor_loop():
    while True:
        interval = max(60, int(config.get("child_monitor_interval", 600) or 600))
        try:
            if config.get("child_monitor_enabled"):
                summary = await monitor_child_accounts_once("auto")
                if summary["checked"]:
                    await task_manager.broadcast(
                        "[子账号池] 监测完成："
                        f"检测 {summary['checked']}，命中 {summary['matched']}，"
                        f"换号 {summary['replaced']}，失败 {summary['failed']}"
                    )
        except Exception as exc:
            await append_child_monitor_log({
                "source": "auto",
                "checked": 0,
                "matched": 0,
                "refreshed": 0,
                "replaced": 0,
                "failed": 1,
                "pool_errors": {},
                "pool_results": [],
                "matched_accounts": [],
                "replacements": [],
                "failed_accounts": [{"error": str(exc)}],
            })
            await task_manager.broadcast(f"[子账号池] 监测异常：{exc}")
        await asyncio.sleep(interval)


def ensure_child_monitor_started() -> None:
    global child_monitor_task
    if child_monitor_task and not child_monitor_task.done():
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    child_monitor_task = loop.create_task(child_monitor_loop())


def write_protocol_cookie_result(cookie_id: str, email: str, password: str, record: dict) -> str:
    cookie_file = os.path.join(SCREENSHOT_DIR, f"cookie_{cookie_id}.json")
    data = {
        "cookie": record.get("cookie", ""),
        "name": email,
        "email": email,
        "password": password,
        "access_token": record.get("access_token", ""),
        "credits": record.get("credits"),
        "expires_at": record.get("expires_at"),
        "display_name": record.get("display_name", ""),
        "user_id": record.get("user_id", ""),
        "refresh_token": record.get("rotated_refresh_token", ""),
    }
    with open(cookie_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    return cookie_file


async def register_invited_self_email(account: dict, reserved: dict, cookie_id: str, prefix: str) -> str:
    email = reserved["email"]
    password = reserved.get("password", "")
    mail_url = reserved.get("api_url", "")
    refresh_token = reserved.get("refresh_token", "")
    client_id = reserved.get("client_id", "")
    if not mail_url and not (refresh_token and client_id):
        raise RuntimeError("子号缺少 API 取件链接，且没有 ClientID / RefreshToken 可用于 Graph/IMAP 收码")

    loop = asyncio.get_running_loop()

    def log(message: str) -> None:
        loop.call_soon_threadsafe(
            asyncio.create_task,
            task_manager.broadcast(f"{prefix} {message}"),
        )

    record = await asyncio.to_thread(
        firefly_protocol.register_account,
        email=email,
        refresh_token=refresh_token,
        client_id=client_id,
        mail_url=mail_url,
        proxy_url=adobe_proxy_url(),
        otp_timeout=180,
        log=log,
    )
    rotated = record.get("rotated_refresh_token") or ""
    if rotated:
        await update_self_email_refresh_token(email, rotated)
    return write_protocol_cookie_result(cookie_id, email, password, record)


def parse_self_email_accounts(raw: str) -> list[dict]:
    accounts = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "----" in line:
            parts = [part.strip() for part in line.split("----")]
        else:
            parts = [part.strip() for part in line.split("-", 2)]
        if len(parts) < 3 or not parts[0] or not parts[1]:
            continue
        api_url = ""
        client_id = ""
        refresh_token = ""
        if len(parts) >= 5:
            client_id = parts[2]
            refresh_token = parts[3]
            api_url = "----".join(parts[4:]).strip()
        elif len(parts) >= 4:
            client_id = parts[2]
            refresh_token = "----".join(parts[3:]).strip()
        elif parts[2].startswith(("http://", "https://", "moemail://")):
            api_url = parts[2]
        else:
            continue
        accounts.append({
            "email": parts[0],
            "password": parts[1],
            "api_url": api_url,
            "client_id": client_id,
            "refresh_token": refresh_token,
        })
    return accounts


def normalize_self_email_used(value) -> set[str]:
    if isinstance(value, list):
        return {str(item).strip().lower() for item in value if str(item).strip()}
    if isinstance(value, str):
        return {item.strip().lower() for item in value.splitlines() if item.strip()}
    return set()


def build_self_email_overview() -> dict:
    accounts = parse_self_email_accounts(config.get("self_email_accounts", ""))
    used = normalize_self_email_used(config.get("self_email_used", []))
    rows = []
    for idx, account in enumerate(accounts, 1):
        email_key = account["email"].strip().lower()
        password = account["password"]
        rows.append({
            "index": idx,
            "email": account["email"],
            "password_mask": "*" * min(max(len(password), 6), 12),
            "api_url": account["api_url"],
            "client_id": account.get("client_id", ""),
            "has_refresh_token": bool(account.get("refresh_token")),
            "receive_mode": "API" if account["api_url"] else ("Graph/IMAP" if account.get("client_id") and account.get("refresh_token") else ""),
            "used": email_key in used,
        })
    used_count = sum(1 for row in rows if row["used"])
    return {
        "accounts": rows,
        "raw": config.get("self_email_accounts", ""),
        "total": len(rows),
        "used": used_count,
        "available": len(rows) - used_count,
    }


def serialize_self_email_accounts(accounts: list[dict]) -> str:
    lines = []
    for account in accounts:
        if account.get("client_id") or account.get("refresh_token"):
            lines.append(
                f"{account['email']}----{account['password']}----"
                f"{account.get('client_id', '')}----{account.get('refresh_token', '')}----"
                f"{account.get('api_url', '')}"
            )
        else:
            lines.append(f"{account['email']}----{account['password']}----{account.get('api_url', '')}")
    return "\n".join(lines)


async def update_self_email_refresh_token(email: str, refresh_token: str):
    global config
    if not email or not refresh_token:
        return
    email_key = email.strip().lower()
    async with self_email_lock:
        accounts = parse_self_email_accounts(config.get("self_email_accounts", ""))
        changed = False
        for account in accounts:
            if account["email"].strip().lower() == email_key and account.get("refresh_token") != refresh_token:
                account["refresh_token"] = refresh_token
                changed = True
        if changed:
            config["self_email_accounts"] = serialize_self_email_accounts(accounts)
            save_config(config)


async def allocate_self_email_account() -> dict | None:
    global config, self_email_reserved
    async with self_email_lock:
        accounts = parse_self_email_accounts(config.get("self_email_accounts", ""))
        if not accounts:
            return None
        used = normalize_self_email_used(config.get("self_email_used", []))
        account = None
        for candidate in accounts:
            email_key = candidate["email"].strip().lower()
            if email_key not in used and email_key not in self_email_reserved:
                account = candidate
                self_email_reserved.add(email_key)
                break
        if not account:
            return None
        return account


async def mark_self_email_used(email: str):
    global config, self_email_reserved
    email_key = (email or "").strip().lower()
    if not email_key:
        return
    async with self_email_lock:
        used = normalize_self_email_used(config.get("self_email_used", []))
        used.add(email_key)
        self_email_reserved.discard(email_key)
        config["self_email_used"] = sorted(used)
        config["self_email_cursor"] = len(used)
        save_config(config)


async def release_self_email_account(email: str):
    global config, self_email_reserved
    email_key = (email or "").strip().lower()
    if not email_key:
        return
    async with self_email_lock:
        self_email_reserved.discard(email_key)
        accounts = parse_self_email_accounts(config.get("self_email_accounts", ""))
        kept_accounts = []
        moved_account = None
        for account in accounts:
            if account["email"].strip().lower() == email_key and moved_account is None:
                moved_account = account
            else:
                kept_accounts.append(account)
        if moved_account:
            kept_accounts.append(moved_account)
            config["self_email_accounts"] = serialize_self_email_accounts(kept_accounts)
            save_config(config)


async def execute_single_worker(task: Task, worker_index: int, assigned_self_email: dict | None = None):
    cleaned = cleanup_stale_profiles(collect_active_profile_paths(task_manager.tasks))
    if cleaned:
        await task_manager.broadcast(f"[任务#{task.id}-{worker_index}] 已清理 {cleaned} 个残留浏览器目录")

    env = os.environ.copy()
    env["API_KEY"] = config["api_key"]
    env["API_BASE"] = config["api_base"]
    env["EMAIL_DOMAIN"] = config.get("email_domain", "rossa.cfd")
    # 多域名列表：传给 worker 进程，实现均匀分布
    env["EMAIL_DOMAINS"] = config.get("email_domains", "") or config.get("email_domain", "rossa.cfd")
    env["YESCAPTCHA_KEY"] = config.get("yescaptcha_key", "")
    env["EMAIL_SOURCE"] = task.email_source
    env["INVITE_REGISTRATION"] = "1" if task.registration_mode == "invite" else "0"
    env["PROXY_ENABLED"] = "1" if config.get("proxy_enabled") else "0"
    env["PROXY_SCHEME"] = config.get("proxy_scheme", "http")
    env["PROXY_URL"] = config.get("proxy_url", "")
    env["DATA_DIR"] = DATA_DIR
    env["SCREENSHOT_DIR"] = SCREENSHOT_DIR
    env["CONFIG_FILE"] = CONFIG_FILE
    env["SHOW_BROWSER"] = "1" if task.show_browser else "0"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"

    # 给每个 worker 分配唯一的 Cookie 文件名，避免并发时互相"偷"文件
    cookie_id = f"task{task.id}_w{worker_index}"
    env["COOKIE_ID"] = cookie_id
    expected_cookie_file = os.path.join(SCREENSHOT_DIR, f"cookie_{cookie_id}.json")
    profile_id = f"{task.id}_{worker_index}_{uuid.uuid4().hex[:10]}"
    user_data_dir = os.path.join(APP_DIR, f"{PROFILE_PREFIX}{profile_id}")
    env["USER_DATA_DIR"] = user_data_dir
    task.active_profiles[worker_index] = user_data_dir

    self_email = ""
    self_email_state = {"used_marked": bool(assigned_self_email)}
    prefix = f"[任务#{task.id}-{worker_index}]"

    if task.email_source == "self":
        account = assigned_self_email or await allocate_self_email_account()
        if not account:
            task.failed += 1
            await task_manager.broadcast(f"{prefix} ❌ 自备邮箱模式未导入可用邮箱")
            await task_manager.broadcast("__STATE_UPDATE__")
            return
        self_email = account["email"]
        env["SELF_EMAIL_ADDRESS"] = account["email"]
        env["SELF_EMAIL_PASSWORD"] = account["password"]
        env["SELF_EMAIL_API_URL"] = account["api_url"]
        await task_manager.broadcast(f"{prefix} 📧 使用自备邮箱: {account['email']}")

    process = await asyncio.create_subprocess_exec(
        sys.executable, "-u", "auto_register_firefly.py",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        start_new_session=(os.name != "nt"),
    )
    task.active_processes[worker_index] = process
    output_task = asyncio.create_task(stream_process_output(process, prefix, self_email, self_email_state))

    try:
        try:
            await asyncio.wait_for(process.wait(), timeout=WORKER_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            await task_manager.broadcast(f"{prefix} 运行超时，已强制结束浏览器和脚本")
            await terminate_process(process)

        # 只检查该 worker 专属的 cookie 文件是否存在
        if os.path.exists(expected_cookie_file):
            if self_email and not self_email_state.get("used_marked"):
                await mark_self_email_used(self_email)
                self_email_state["used_marked"] = True
            task.completed += 1
            task.result_files.append(expected_cookie_file)
            await task_manager.broadcast(f"{prefix} ✅ 注册成功！(已导出完整 7 项 Cookie)")
            if await import_cookie_to_token_pool(expected_cookie_file, prefix):
                if config.get("token_pool_enabled"):
                    task.token_pool_imported += 1
                    task.token_pool_imported_files.append(expected_cookie_file)
        else:
            task.failed += 1
            await task_manager.broadcast(f"{prefix} ❌ 失败 (未导出完整 7 项 Cookie)")
    except asyncio.CancelledError:
        task.failed += 1
        await task_manager.broadcast(f"{prefix} 🛑 操作已取消")
        raise
    finally:
        await finalize_output_task(output_task)
        if self_email and not self_email_state.get("used_marked"):
            await release_self_email_account(self_email)
        task.active_processes.pop(worker_index, None)
        task.active_profiles.pop(worker_index, None)
        cleanup_stale_profiles(collect_active_profile_paths(task_manager.tasks))
        await task_manager.broadcast("__STATE_UPDATE__")

async def collect_removable_adobe_member_emails(account: dict) -> list[str]:
    removable = []
    page = 0
    while True:
        result = await fetch_adobe_members(account, page_number=page, page_size=100)
        removable.extend(
            member["email"] for member in result["members"]
            if member.get("removable") and member.get("email")
        )
        if not result["has_more"]:
            break
        page += 1
    return list(dict.fromkeys(removable))


async def allocate_self_email_batch(quantity: int) -> list[dict]:
    accounts = []
    for _ in range(quantity):
        account = await allocate_self_email_account()
        if not account:
            break
        accounts.append(account)
    return accounts


async def run_invite_task(task: Task):
    for account_position, account_id in enumerate(task.adobe_account_ids, 1):
        if task.status == "stopping":
            break
        account = find_adobe_account(account_id)
        if not account:
            task.failed += task.batch_quantity
            await task_manager.broadcast(f"[Task#{task.id}] ERROR: selected Adobe admin account no longer exists; skipping")
            continue

        account_label = account.get("email") or account.get("name") or account_id
        prefix = f"[Task#{task.id}: {account_label}]"
        target_success = max(1, int(task.batch_quantity or task.quantity or 1))
        if getattr(task, "replacement_child_ids", None) or getattr(task, "replacement_child_id", ""):
            prepared_child_ids = await prepare_replacement_children_for_task(task, account, prefix)
            if not prepared_child_ids:
                await task_manager.broadcast(f"{prefix} ⚠️ 没有旧子号被成功移除，补号任务取消")
                continue
            target_success = len(prepared_child_ids)
            task.quantity = target_success
            task.batch_quantity = target_success
        account_success = 0
        registration_attempts = 0
        max_attempts_per_slot = 8
        max_registration_attempts = target_success * max_attempts_per_slot
        await task_manager.broadcast(
            f"{prefix} 目标 {target_success} 个成功账号；每个目标最多换邮箱 {max_attempts_per_slot} 次，直到凑满或邮箱池耗尽"
        )

        if task.invite_remove_members:
            await task_manager.broadcast(f"{prefix} Step 1/3：读取并清理全部可移除成员...")
            try:
                async with adobe_account_lock:
                    removable = await collect_removable_adobe_member_emails(account)
                    removal_results = await remove_adobe_members(account, removable) if removable else []
                removal_failures = [result for result in removal_results if not result["ok"]]
                removed_count = len(removal_results) - len(removal_failures)
                suffix = f"，{len(removal_failures)} 个移除失败" if removal_failures else ""
                await task_manager.broadcast(f"{prefix} 成员清理完成：已移除 {removed_count} 个{suffix}")
            except Exception as exc:
                task.failed += target_success
                await task_manager.broadcast(f"{prefix} ❌ 成员清理失败，本母号取消：{exc}")
                continue
        else:
            await task_manager.broadcast(f"{prefix} Step 1/3：已关闭清理成员，直接开始授权")

        sem = asyncio.Semaphore(max(1, task.concurrency))

        async def run_invite_slot(slot_index: int) -> bool | None:
            nonlocal account_success, registration_attempts
            worker_prefix = f"[Task#{task.id}-{slot_index}: {account_label}]"
            async with sem:
                for attempt in range(1, max_attempts_per_slot + 1):
                    if task.status == "stopping":
                        return False

                    reserved = await allocate_self_email_account()
                    if not reserved:
                        await task_manager.broadcast(
                            f"{worker_prefix} ⚠️ 自备邮箱池已耗尽，子任务停止于第 {attempt}/{max_attempts_per_slot} 次"
                        )
                        return None

                    registration_attempts += 1
                    email = reserved["email"]
                    await task_manager.broadcast(
                        f"{worker_prefix} Step 2/3：第 {attempt}/{max_attempts_per_slot} 次尝试，授权 {email}"
                    )

                    try:
                        async with adobe_account_lock:
                            invite_results = await invite_adobe_members(account, [email])
                        invite_result = invite_results[0] if invite_results else {
                            "email": email, "ok": False, "message": "授权接口无返回"
                        }
                    except Exception as exc:
                        invite_result = {"email": email, "ok": False, "message": str(exc)}

                    if not invite_result.get("ok"):
                        await release_self_email_account(email)
                        task.failed += 1
                        await task_manager.broadcast(
                            f"{worker_prefix} ❌ [{email}] 授权失败：{invite_result.get('message', '')}，释放邮箱"
                        )
                        await task_manager.broadcast("__STATE_UPDATE__")
                        continue

                    reserved["_member_id"] = invite_result.get("member_id", "")
                    await task_manager.broadcast(f"{worker_prefix} ✅ [{email}] 授权成功")

                    if task.status == "stopping":
                        await mark_self_email_used(email)
                        with suppress(Exception):
                            async with adobe_account_lock:
                                await remove_adobe_members(account, [email])
                        await task_manager.broadcast("__STATE_UPDATE__")
                        return False

                    try:
                        await task_manager.broadcast(
                            f"{worker_prefix} Step 3/3：[{email}] 收码、补全资料并登录 Firefly"
                        )
                        cookie_id = f"task{task.id}_slot{slot_index}_try{attempt}"
                        cookie_file = await register_invited_self_email(
                            account, reserved, cookie_id, worker_prefix
                        )
                        await mark_self_email_used(email)
                        task.completed += 1
                        task.result_files.append(cookie_file)
                        account_success += 1
                        child_record = await create_child_account_from_cookie(
                            account=account,
                            reserved=reserved,
                            cookie_file=cookie_file,
                            task=task,
                        )
                        replacement_child_id = consume_replacement_child_id(task) if child_record else ""
                        if replacement_child_id and child_record:
                            await update_child_account(
                                replacement_child_id,
                                status="replaced",
                                replaced_at=now_text(),
                                replacement_child_id=child_record.get("id", ""),
                            )
                        await task_manager.broadcast(
                            f"{worker_prefix} ✅ [{email}] 子任务完成，已导出 Firefly cookie/token；"
                            f"累计成功 {account_success}/{target_success}"
                        )
                        external_enabled = bool(config.get("token_pool_enabled"))
                        external_result = await import_cookie_to_token_pool_result(cookie_file, worker_prefix)
                        external_ok = bool(external_result.get("ok"))
                        if child_record:
                            await update_child_account(
                                child_record.get("id", ""),
                                external_pool_status=(
                                    "imported" if external_enabled and external_ok
                                    else "skipped" if not external_enabled
                                    else "failed"
                                ),
                                external_pool_id=external_result.get("pool_id", "") if external_enabled and external_ok else "",
                                external_pool_name=external_result.get("pool_name", "") if external_enabled and external_ok else "",
                                external_pool_error="" if external_ok else external_result.get("error", "") or "外部 Token 池导入失败",
                            )
                        if external_ok:
                            if config.get("token_pool_enabled"):
                                task.token_pool_imported += 1
                                task.token_pool_imported_files.append(cookie_file)
                        if replacement_child_id and child_record:
                            await cleanup_replaced_child_token(replacement_child_id, worker_prefix)
                        await task_manager.broadcast("__STATE_UPDATE__")
                        return True
                    except Exception as exc:
                        task.failed += 1
                        await mark_self_email_used(email)
                        await task_manager.broadcast(
                            f"{worker_prefix} ❌ [{email}] 注册失败：{exc}，"
                            f"邮箱标记已使用并尝试移除成员，准备换邮箱"
                        )
                        with suppress(Exception):
                            async with adobe_account_lock:
                                await remove_adobe_members(account, [email])
                        await task_manager.broadcast("__STATE_UPDATE__")

                await task_manager.broadcast(f"{worker_prefix} ⚠️ 子任务已达到 {max_attempts_per_slot} 次尝试上限")
                return False

        await task_manager.broadcast(
            f"{prefix} Step 2/3：启动 {target_success} 个子任务，并发 {max(1, task.concurrency)}，每个最多 {max_attempts_per_slot} 次"
        )
        workers = [
            asyncio.create_task(run_invite_slot(slot_index))
            for slot_index in range(1, target_success + 1)
        ]
        task.asyncio_tasks = workers
        results = await asyncio.gather(*workers, return_exceptions=True)
        task.asyncio_tasks = []
        account_success = sum(1 for result in results if result is True)

        if account_success >= target_success:
            await task_manager.broadcast(f"{prefix} ✅ 已凑满目标 {target_success}/{target_success}")
        elif registration_attempts >= max_registration_attempts:
            await task_manager.broadcast(
                f"{prefix} ⚠️ 已达到重试上限，最终成功 {account_success}/{target_success}，"
                f"总尝试 {registration_attempts}/{max_registration_attempts}"
            )
        elif task.status != "stopping":
            await task_manager.broadcast(f"{prefix} ⚠️ 未凑满目标，最终成功 {account_success}/{target_success}")


async def run_task(task: Task):
    task.status = "running"
    task.asyncio_tasks = []
    task.active_processes = {}
    task.active_profiles = {}
    await task_manager.broadcast("__STATE_UPDATE__")

    if task.registration_mode == "invite":
        await run_invite_task(task)
    else:
        sem = asyncio.Semaphore(task.concurrency)

        async def wrapper(idx):
            async with sem:
                # 优雅停止：获取信号量后检查任务是否已标记停止
                if task.status == "stopping":
                    await task_manager.broadcast(f"[任务#{task.id}-{idx}] ⏭️ 任务已停止，跳过")
                    return
                await execute_single_worker(task, idx)

        workers = [asyncio.create_task(wrapper(i)) for i in range(1, task.quantity + 1)]
        task.asyncio_tasks = workers
        await asyncio.gather(*workers, return_exceptions=True)
    task.asyncio_tasks = []
    task.active_processes = {}
    task.active_profiles = {}

    if task.status == "stopping":
        task.status = "stopped"
        await task_manager.broadcast(f"🏁 任务 #{task.id} 已优雅停止 (成功 {task.completed}, 失败 {task.failed})")
    elif task.status != "stopped":
        task.status = "completed"
        await task_manager.broadcast(f"🏁 任务 #{task.id} 结束 (成功 {task.completed}, 失败 {task.failed})")
    replacement_done_ids = list(getattr(task, "replacement_done_child_ids", []) or [])
    replacement_pending_ids = list(getattr(task, "replacement_child_ids", []) or [])
    replacement_child_id = getattr(task, "replacement_child_id", "")
    if replacement_child_id and replacement_child_id not in replacement_pending_ids and replacement_child_id not in replacement_done_ids:
        replacement_pending_ids.append(replacement_child_id)
    replacement_total = len(replacement_done_ids) + len(replacement_pending_ids)
    if replacement_total:
        records = await list_child_accounts_raw()
        failed_emails = []
        for child_id in replacement_pending_ids:
            record = find_child_record(records, child_id)
            failed_emails.append(record.get("email", child_id) if record else child_id)
            await update_child_account(
                child_id,
                status="removed",
                failure_reason=f"补号任务 #{task.id} 未成功",
            )
        if failed_emails:
            await task_manager.broadcast(
                f"[子账号池] 补号任务 #{task.id} 结果：成功 {len(replacement_done_ids)}/{replacement_total}，"
                f"失败 {len(failed_emails)}；失败子号：{', '.join(failed_emails)}"
            )
        else:
            await task_manager.broadcast(f"[子账号池] 补号任务 #{task.id} 结果：成功 {len(replacement_done_ids)}/{replacement_total}，失败 0")
    await task_manager.broadcast("__STATE_UPDATE__")

# ─── WebSocket ───
@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    if not websocket.scope.get("session", {}).get("admin_authenticated"):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    task_manager.websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in task_manager.websockets:
            task_manager.websockets.remove(websocket)

# ─── Export ───
def get_task_result_files(task: Task) -> list[str]:
    files = []
    if task.result_files:
        files.extend(resolve_data_file(f) for f in task.result_files)
    else:
        files.extend(glob.glob(os.path.join(SCREENSHOT_DIR, f"cookie_task{task.id}_*.json")))

    unique_files = []
    seen = set()
    for f in files:
        resolved = os.path.abspath(resolve_data_file(f))
        if resolved in seen:
            continue
        if os.path.exists(resolved):
            seen.add(resolved)
            unique_files.append(resolved)
    return unique_files


def get_task_unpooled_files(task: Task) -> list[str]:
    result_files = get_task_result_files(task)
    if not result_files:
        return []

    imported_files = [
        os.path.abspath(resolve_data_file(f))
        for f in getattr(task, "token_pool_imported_files", [])
    ]
    imported_set = {f for f in imported_files if f}
    if imported_set:
        return [f for f in result_files if os.path.abspath(f) not in imported_set]

    imported_count = max(0, int(getattr(task, "token_pool_imported", 0) or 0))
    if imported_count <= 0:
        return result_files

    return result_files[imported_count:]


def load_cookie_exports(result_files: list[str]) -> list[dict]:
    combined = []
    for f in result_files:
        try:
            with open(f, "r", encoding="utf-8") as cookie_fp:
                data = json.load(cookie_fp)
            if "cookie" in data and "name" in data:
                combined.append(data)
        except Exception:
            pass
    return combined


@app.get("/api/export")
async def export_results(ids: str = ""):
    # Filter by task IDs if provided
    export_filename = ""
    if ids:
        target_ids = set(int(x) for x in ids.split(",") if x.strip().isdigit())
        selected_tasks = [t for t in task_manager.tasks.values() if t.id in target_ids]
        result_files = []
        for t in task_manager.tasks.values():
            if t.id in target_ids:
                if t.result_files:
                    result_files.extend(resolve_data_file(f) for f in t.result_files)
                else:
                    # Fallback for older tasks before result_files was saved to JSON
                    import glob
                    result_files.extend(glob.glob(os.path.join(SCREENSHOT_DIR, f"cookie_task{t.id}_*.json")))
        if len(selected_tasks) == 1:
            task = selected_tasks[0]
            export_filename = f"{sanitize_filename(task.name, f'任务_{task.id}')}_#{task.id}.json"
        else:
            export_filename = f"批量导出_{len(selected_tasks)}个任务_{export_timestamp()}.json"
    else:
        selected_tasks = list(task_manager.tasks.values())
        result_files = []
        for t in task_manager.tasks.values():
            if t.result_files:
                result_files.extend(resolve_data_file(f) for f in t.result_files)
            else:
                import glob
                result_files.extend(glob.glob(os.path.join(SCREENSHOT_DIR, f"cookie_task{t.id}_*.json")))
        export_filename = f"全部任务_{export_timestamp()}.json"

    combined = []
    for f in result_files:
        try:
            data = json.load(open(f, "r", encoding="utf-8"))
            if "cookie" in data and "name" in data:
                combined.append(data)
        except:
            pass

    if not combined:
        return JSONResponse(status_code=404, content={"error": "暂无成功记录可导出"})

    # 直接从内存返回 JSON，不再写临时文件到根目录
    from fastapi.responses import Response
    content = json.dumps(combined, ensure_ascii=False, indent=4)
    if not export_filename:
        export_filename = f"批量导出_{len(selected_tasks)}个任务_{export_timestamp()}.json"
    return Response(
        content=content.encode("utf-8"),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(export_filename)}"
        },
    )


@app.get("/api/export-unpooled")
async def export_unpooled_results(ids: str = ""):
    if ids:
        target_ids = set(int(x) for x in ids.split(",") if x.strip().isdigit())
        selected_tasks = [t for t in task_manager.tasks.values() if t.id in target_ids]
    else:
        selected_tasks = list(task_manager.tasks.values())

    result_files = []
    for task in selected_tasks:
        result_files.extend(get_task_unpooled_files(task))

    combined = load_cookie_exports(result_files)
    if not combined:
        return JSONResponse(status_code=404, content={"error": "暂无未入池记录可导出"})

    if ids and len(selected_tasks) == 1:
        task = selected_tasks[0]
        export_filename = f"{sanitize_filename(task.name, f'任务_{task.id}')}_未入池_#{task.id}.json"
    elif ids:
        export_filename = f"未入池导出_{len(selected_tasks)}个任务_{export_timestamp()}.json"
    else:
        export_filename = f"全部未入池_{export_timestamp()}.json"

    from fastapi.responses import Response
    content = json.dumps(combined, ensure_ascii=False, indent=4)
    return Response(
        content=content.encode("utf-8"),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(export_filename)}"
        },
    )


# Mount static frontend
os.makedirs("static", exist_ok=True)
app.mount("/", StaticFiles(directory="static", html=True), name="static")


@app.on_event("startup")
async def cleanup_profiles_on_startup():
    cleanup_stale_profiles(collect_active_profile_paths(task_manager.tasks))
    ensure_child_monitor_started()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
