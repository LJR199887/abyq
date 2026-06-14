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

app = FastAPI()

# Config storage
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv("DATA_DIR", APP_DIR)
SCREENSHOT_DIR = os.path.join(DATA_DIR, "screenshots")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
TASKS_FILE = os.path.join(DATA_DIR, "tasks.json")
TASK_LOG_DIR = os.path.join(DATA_DIR, "task_logs")
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
    for pattern in (r"\[任务#(\d+)(?:[-\s·\]])", r"任务\s*#(\d+)"):
        match = re.search(pattern, message)
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
        }


def collect_active_profile_paths(tasks: dict[int, "Task"]) -> set[str]:
    active = set()
    for task in tasks.values():
        active.update(task.active_profiles.values())
    return active


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


class AdobeAccountUpdate(BaseModel):
    id: str = ""
    name: str
    cookie: str = ""


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
        "token_pool_site": item.token_pool_site.strip(),
        "token_pool_key": item.token_pool_key.strip(),
        "self_email_accounts": config.get("self_email_accounts", ""),
        "self_email_cursor": config.get("self_email_cursor", 0),
        "self_email_used": config.get("self_email_used", []),
        "adobe_accounts": config.get("adobe_accounts", []),
    }
    save_config(config)
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
    cookie = account.get("cookie", "")
    try:
        cookie_count = len(parse_adobe_cookies(cookie)) if cookie else 0
    except ValueError:
        cookie_count = 0
    return {
        "id": account.get("id", ""),
        "name": account.get("name", ""),
        "cookie_configured": bool(cookie),
        "cookie_preview": f"已配置 · {cookie_count} 项" if cookie else "",
        "product_count": len(account.get("invite_product_ids", [])),
        "organization_id": account.get("organization_id", ""),
        "subscriptions": account.get("subscriptions", []),
        "last_token_check_at": account.get("last_token_check_at", ""),
        "token_expires_at": account.get("token_expires_at", ""),
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


@app.get("/api/adobe-accounts")
async def get_adobe_accounts():
    return [adobe_account_summary(account) for account in config.get("adobe_accounts", [])]


@app.post("/api/adobe-accounts")
async def save_adobe_account(item: AdobeAccountUpdate):
    global config
    name = item.name.strip()
    if not name:
        return JSONResponse(status_code=400, content={"message": "请输入账号名称"})
    accounts = config.setdefault("adobe_accounts", [])
    account = find_adobe_account(item.id) if item.id else None
    try:
        if account:
            account["name"] = name
            account.pop("product_ids", None)
            if item.cookie.strip():
                parse_adobe_cookies(item.cookie.strip())
                account["cookie"] = item.cookie.strip()
        else:
            parse_adobe_cookies(item.cookie.strip())
            account = {
                "id": uuid.uuid4().hex,
                "name": name,
                "cookie": item.cookie.strip(),
            }
            accounts.append(account)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"message": str(exc)})
    account["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    save_config(config)
    return adobe_account_summary(account)


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


@app.post("/api/adobe-accounts/{account_id}/test")
async def test_adobe_account(account_id: str):
    account = find_adobe_account(account_id)
    if not account:
        return JSONResponse(status_code=404, content={"message": "账号不存在"})
    try:
        async with adobe_account_lock:
            return await test_adobe_account_cookie(account)
    except Exception as exc:
        return JSONResponse(status_code=400, content={"ok": False, "message": str(exc)})


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


async def import_cookie_to_token_pool(cookie_file: str, prefix: str) -> bool:
    if not config.get("token_pool_enabled"):
        return True

    import_url = build_token_pool_import_url(config.get("token_pool_site", ""))
    token_pool_key = (config.get("token_pool_key") or "").strip()
    if not import_url or not token_pool_key:
        await task_manager.broadcast(f"{prefix} ⚠️ 自动入池已开启，但网站地址或 Token 池密钥未配置")
        return False

    try:
        with open(cookie_file, "r", encoding="utf-8") as f:
            cookie_data = json.load(f)
    except Exception as e:
        await task_manager.broadcast(f"{prefix} ⚠️ 自动入池失败：无法读取 Cookie 文件 ({e})")
        return False

    payload = {
        "name": cookie_data.get("name", ""),
        "cookie": cookie_data.get("cookie", ""),
    }
    if not payload["cookie"]:
        await task_manager.broadcast(f"{prefix} ⚠️ 自动入池失败：Cookie 内容为空")
        return False

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
                await task_manager.broadcast(f"{prefix} ✅ 已自动导入 Token 池")
                return True
            detail = response.text[:200].replace("\n", " ")
            last_error = f"HTTP {response.status_code} {detail}"
        except Exception as e:
            last_error = str(e)

        if attempt < 3:
            await task_manager.broadcast(f"{prefix} ⚠️ 自动入池失败，第 {attempt}/3 次：{last_error}，2 秒后重试")
            await asyncio.sleep(2)

    await task_manager.broadcast(f"{prefix} ⚠️ 自动入池失败：{last_error}")
    return False


def parse_self_email_accounts(raw: str) -> list[dict]:
    accounts = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("----")]
        if len(parts) < 3 or not parts[0] or not parts[1] or not parts[2]:
            continue
        accounts.append({
            "email": parts[0],
            "password": parts[1],
            "api_url": "----".join(parts[2:]).strip(),
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
    return "\n".join(
        f"{account['email']}----{account['password']}----{account['api_url']}"
        for account in accounts
    )


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
    worker_index = 0
    for account_position, account_id in enumerate(task.adobe_account_ids, 1):
        if task.status == "stopping":
            break
        account = find_adobe_account(account_id)
        if not account:
            task.failed += task.batch_quantity
            await task_manager.broadcast(f"[任务#{task.id}] ❌ 所选 Adobe 账号已不存在，跳过本批")
            continue

        account_label = account.get("name") or account_id
        prefix = f"[任务#{task.id} · {account_label}]"
        batch = await allocate_self_email_batch(task.batch_quantity)
        if len(batch) < task.batch_quantity:
            for reserved in batch:
                await release_self_email_account(reserved["email"])
            task.failed += task.batch_quantity
            await task_manager.broadcast(f"{prefix} ❌ 可用自备邮箱不足，跳过本批")
            continue

        if task.invite_remove_members:
            await task_manager.broadcast(f"{prefix} 正在获取并清理全部可移除成员...")
            try:
                async with adobe_account_lock:
                    removable = await collect_removable_adobe_member_emails(account)
                    removal_results = await remove_adobe_members(account, removable) if removable else []
                removal_failures = [result for result in removal_results if not result["ok"]]
                await task_manager.broadcast(
                    f"{prefix} 已清理 {len(removal_results) - len(removal_failures)} 个成员"
                    + (f"，{len(removal_failures)} 个移除失败" if removal_failures else "")
                )
            except Exception as exc:
                for reserved in batch:
                    await release_self_email_account(reserved["email"])
                task.failed += task.batch_quantity
                await task_manager.broadcast(f"{prefix} ❌ 清理成员失败，本批已取消: {exc}")
                continue
        else:
            await task_manager.broadcast(f"{prefix} 已关闭先移除成员，直接发送团队邀请...")

        emails = [reserved["email"] for reserved in batch]
        await task_manager.broadcast(f"{prefix} 正在发送 {len(emails)} 封团队邀请...")
        try:
            async with adobe_account_lock:
                invite_results = await invite_adobe_members(account, emails)
        except Exception as exc:
            invite_results = [{"email": email, "ok": False, "message": str(exc)} for email in emails]

        successful = []
        for reserved, result in zip(batch, invite_results):
            if result["ok"]:
                await mark_self_email_used(reserved["email"])
                successful.append(reserved)
                await task_manager.broadcast(f"{prefix} ✅ {reserved['email']} 邀请已发送")
            else:
                await release_self_email_account(reserved["email"])
                task.failed += 1
                await task_manager.broadcast(f"{prefix} ❌ {reserved['email']} 邀请失败: {result['message']}")

        await task_manager.broadcast("__STATE_UPDATE__")
        if not successful or task.status == "stopping":
            continue

        if INVITE_EMAIL_WAIT_SECONDS:
            await task_manager.broadcast(
                f"{prefix} 等待邀请邮件送达，{INVITE_EMAIL_WAIT_SECONDS} 秒后开始注册..."
            )
        else:
            await task_manager.broadcast(f"{prefix} 开始轮询邀请邮件并执行注册...")
        waited = 0
        while waited < INVITE_EMAIL_WAIT_SECONDS and task.status != "stopping":
            interval = min(5, INVITE_EMAIL_WAIT_SECONDS - waited)
            await asyncio.sleep(interval)
            waited += interval
        if task.status == "stopping":
            break

        sem = asyncio.Semaphore(task.concurrency)

        async def wrapper(reserved: dict):
            nonlocal worker_index
            worker_index += 1
            index = worker_index
            async with sem:
                if task.status == "stopping":
                    return
                await execute_single_worker(task, index, reserved)

        workers = [asyncio.create_task(wrapper(reserved)) for reserved in successful]
        task.asyncio_tasks = workers
        await asyncio.gather(*workers, return_exceptions=True)
        task.asyncio_tasks = []


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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
