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
from contextlib import suppress
from datetime import datetime
from urllib.parse import quote, unquote, urljoin, urlsplit
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
import glob
import httpx

app = FastAPI()

# Config storage
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv("DATA_DIR", APP_DIR)
SCREENSHOT_DIR = os.path.join(DATA_DIR, "screenshots")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
TASKS_FILE = os.path.join(DATA_DIR, "tasks.json")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

DEFAULT_CONFIG = {
    "api_key": "",
    "api_base": "https://rossa.cfd/api",
    "email_domain": "rossa.cfd",
    "email_domains": "rossa.cfd",
    "yescaptcha_key": "",
    "proxy_enabled": False,
    "proxy_scheme": "http",
    "proxy_url": "",
    "token_pool_enabled": False,
    "token_pool_site": "",
    "token_pool_key": "",
    "self_email_accounts": "",
    "self_email_cursor": 0,
    "self_email_used": [],
}

WORKER_TIMEOUT_SECONDS = max(180, int(os.getenv("WORKER_TIMEOUT_SECONDS", "900")))
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

# ─── Task Management ───
class Task:
    def __init__(self, task_id, quantity, concurrency=1, show_browser=False, name="", email_source="temp"):
        self.id = task_id
        self.quantity = quantity
        self.concurrency = concurrency
        self.show_browser = show_browser
        self.email_source = email_source if email_source in ("temp", "self") else "temp"
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
            "concurrency": self.concurrency,
            "show_browser": self.show_browser,
            "email_source": self.email_source,
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

    def create_task(self, quantity, concurrency=1, show_browser=False, name="", email_source="temp") -> Task:
        task = Task(self.next_id, quantity, concurrency, show_browser, name, email_source)
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

class TaskDeleteRequest(BaseModel):
    ids: list[int]

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
    config = {
        "api_key": item.api_key,
        "api_base": item.api_base,
        "email_domain": item.email_domain,
        "email_domains": item.email_domains,
        "yescaptcha_key": item.yescaptcha_key,
        "proxy_enabled": item.proxy_enabled,
        "proxy_scheme": proxy_scheme,
        "proxy_url": item.proxy_url.strip(),
        "token_pool_enabled": item.token_pool_enabled,
        "token_pool_site": item.token_pool_site.strip(),
        "token_pool_key": item.token_pool_key.strip(),
        "self_email_accounts": config.get("self_email_accounts", ""),
        "self_email_cursor": config.get("self_email_cursor", 0),
        "self_email_used": config.get("self_email_used", []),
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
    return config


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
    email_source = item.email_source if item.email_source in ("temp", "self") else "temp"
    task = task_manager.create_task(item.quantity, conc, item.show_browser, item.name, email_source)
    await task_manager.queue.put(task)

    # Ensure queue worker is running
    asyncio.create_task(task_manager.start_queue_worker())

    return task.to_dict()

@app.get("/api/tasks")
async def list_tasks():
    return [t.to_dict() for t in reversed(task_manager.tasks.values())]

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


async def execute_single_worker(task: Task, worker_index: int):
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
    self_email_state = {"used_marked": False}
    prefix = f"[任务#{task.id}-{worker_index}]"

    if task.email_source == "self":
        account = await allocate_self_email_account()
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

async def run_task(task: Task):
    task.status = "running"
    task.asyncio_tasks = []
    task.active_processes = {}
    task.active_profiles = {}
    await task_manager.broadcast("__STATE_UPDATE__")

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
