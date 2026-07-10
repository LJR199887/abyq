"""微软(Hotmail/Outlook)账号收邮件测试。

流程:
1. 用 refresh_token + client_id 向微软换取 access_token;
2. 通过 IMAP(outlook.office365.com)以 XOAUTH2 登录;
3. 选择收件箱,统计邮件数并读取最新一封的主题/发件人。

支持通过设置里的代理(http / socks5)发起请求。
"""

from __future__ import annotations

import base64
import imaplib
import socket
import ssl
from dataclasses import dataclass
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, urlparse

import requests
import urllib3

try:
    import socks  # PySocks
except ImportError:  # pragma: no cover
    socks = None

IMAP_HOST = "outlook.office365.com"
IMAP_PORT = 993
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_V2_CONSUMERS = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
_V2_COMMON = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
_LIVE = "https://login.live.com/oauth20_token.srf"

# Graph 收信用:新 GR / 老 GR / 资源 scope 依次尝试,只能走 v2.0 端点。
_GRAPH_SCOPE = "User.Read Mail.Read offline_access"
_GRAPH_OLD_SCOPE = "https://graph.microsoft.com/.default"
_GRAPH_RESOURCE_SCOPE = "https://graph.microsoft.com/Mail.Read offline_access"
GRAPH_TOKEN_STRATEGIES: list[tuple[str, dict[str, str]]] = [
    (_V2_CONSUMERS, {"scope": _GRAPH_SCOPE}),
    (_V2_COMMON, {"scope": _GRAPH_SCOPE}),
    (_V2_CONSUMERS, {"scope": _GRAPH_OLD_SCOPE}),
    (_V2_COMMON, {"scope": _GRAPH_OLD_SCOPE}),
    (_V2_CONSUMERS, {"scope": _GRAPH_RESOURCE_SCOPE}),
    (_V2_COMMON, {"scope": _GRAPH_RESOURCE_SCOPE}),
]

# IMAP 收信用:申请 outlook.office.com 的 IMAP 权限;兼容旧版 live.com token。
_IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
IMAP_TOKEN_STRATEGIES: list[tuple[str, dict[str, str]]] = [
    (_V2_CONSUMERS, {"scope": _IMAP_SCOPE}),
    (_V2_COMMON, {"scope": _IMAP_SCOPE}),
    (_LIVE, {"scope": "wl.imap wl.offline_access"}),
    (_LIVE, {}),
]


@dataclass
class MailTestResult:
    success: bool
    message: str
    inbox_total: int | None = None
    latest_subject: str | None = None
    latest_from: str | None = None
    # 微软轮换后返回的新 Refresh Token(换令牌成功即有值,需存回数据库)
    new_refresh_token: str | None = None


@dataclass
class MailSummary:
    id: str
    subject: str = ""
    from_addr: str = ""
    date: str = ""
    folder: str = ""
    preview: str = ""
    is_read: bool | None = None
    source: str = ""  # graph / imap


@dataclass
class MailListResult:
    success: bool
    message: str
    source: str = ""
    messages: list[MailSummary] | None = None
    new_refresh_token: str | None = None


@dataclass
class MailDetailResult:
    success: bool
    message: str
    subject: str = ""
    from_addr: str = ""
    to_addr: str = ""
    date: str = ""
    body_html: str = ""
    body_text: str = ""
    new_refresh_token: str | None = None


@dataclass
class ProxyConfig:
    scheme: str  # http / https / socks5 / socks4
    host: str
    port: int
    username: str | None = None
    password: str | None = None


def _parse_proxy(proxy_url: str) -> ProxyConfig | None:
    if not proxy_url:
        return None
    parsed = urlparse(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
    if not parsed.hostname or not parsed.port:
        return None
    return ProxyConfig(
        scheme=(parsed.scheme or "http").lower(),
        host=parsed.hostname,
        port=parsed.port,
        username=unquote(parsed.username) if parsed.username else None,
        password=unquote(parsed.password) if parsed.password else None,
    )


def _requests_proxies(proxy: ProxyConfig | None) -> dict | None:
    if not proxy:
        return None
    auth = ""
    if proxy.username:
        auth = f"{proxy.username}:{proxy.password or ''}@"
    url = f"{proxy.scheme}://{auth}{proxy.host}:{proxy.port}"
    return {"http": url, "https": url}


class _ProxyIMAP4SSL(imaplib.IMAP4_SSL):
    """支持通过 SOCKS 代理建立的 IMAP over SSL 连接。"""

    def __init__(self, host: str, port: int, timeout: int, proxy: ProxyConfig | None):
        self._proxy = proxy
        super().__init__(host=host, port=port, timeout=timeout)

    def _create_socket(self, timeout=None):  # type: ignore[override]
        timeout = timeout or 30
        proxy = self._proxy
        if proxy and proxy.scheme.startswith("socks") and socks is not None:
            sock = socks.socksocket()
            proxy_type = socks.SOCKS5 if "5" in proxy.scheme else socks.SOCKS4
            sock.set_proxy(
                proxy_type,
                proxy.host,
                proxy.port,
                username=proxy.username,
                password=proxy.password,
            )
            sock.settimeout(timeout)
            sock.connect((self.host, self.port))
        else:
            sock = socket.create_connection((self.host, self.port), timeout)
        return self.ssl_context.wrap_socket(sock, server_hostname=self.host)


def _short_host(url: str) -> str:
    return urlparse(url).hostname or url


def _strategy_label(url: str, extra: dict[str, str]) -> str:
    scope = (extra or {}).get("scope") or "(default)"
    return f"{_short_host(url)} scope={scope}"


def _get_access_token(
    refresh_token: str,
    client_id: str,
    proxies: dict | None,
    timeout: int,
    strategies: list[tuple[str, dict[str, str]]],
) -> tuple[str, str | None, str]:
    """依次尝试多个端点换令牌,返回 (access_token, 新 refresh_token 或 None, 来源端点 host)。"""
    if not refresh_token or not client_id:
        raise RuntimeError("缺少 Refresh Token 或 Client ID")

    errors: list[str] = []
    for url, extra in strategies:
        label = _strategy_label(url, extra)
        data = {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            **extra,
        }
        try:
            resp = requests.post(
                url, data=data, proxies=proxies, timeout=timeout, verify=False
            )
        except requests.RequestException as exc:
            errors.append(f"[{label}] 网络错误:{exc}")
            continue

        try:
            payload = resp.json()
        except ValueError:
            errors.append(f"[{label}] HTTP {resp.status_code} 返回非 JSON")
            continue

        token = payload.get("access_token")
        if token:
            return token, payload.get("refresh_token"), label

        err = payload.get("error_description") or payload.get("error") or "未知错误"
        # 只取首行,避免把微软的长串说明全带上
        errors.append(f"[{label}] {str(err).splitlines()[0]}")

    raise RuntimeError("获取访问令牌失败;各端点结果:" + " | ".join(errors))


def _graph_error(resp: requests.Response) -> str:
    try:
        err = resp.json().get("error", {})
        return f"HTTP {resp.status_code} {err.get('code', '')}:{err.get('message', '')}".strip()
    except ValueError:
        return f"HTTP {resp.status_code}"


def _graph_read(
    access_token: str, proxies: dict | None, timeout: int
) -> tuple[bool, str, tuple[int | None, str | None, str | None]]:
    """通过 Microsoft Graph 读取收件箱,返回 (是否成功, 详情, (总数, 最新主题, 最新发件人))。"""
    headers = {"Authorization": f"Bearer {access_token}"}

    folder = requests.get(
        f"{GRAPH_BASE}/me/mailFolders/inbox",
        headers=headers,
        proxies=proxies,
        timeout=timeout,
        verify=False,
    )
    if folder.status_code != 200:
        return False, _graph_error(folder), (None, None, None)
    total = folder.json().get("totalItemCount")

    latest = requests.get(
        f"{GRAPH_BASE}/me/mailFolders/inbox/messages",
        headers=headers,
        proxies=proxies,
        timeout=timeout,
        params={"$top": "1", "$orderby": "receivedDateTime desc", "$select": "subject,from"},
        verify=False,
    )
    subject = sender = None
    if latest.status_code == 200:
        items = latest.json().get("value", [])
        if items:
            subject = items[0].get("subject")
            addr = items[0].get("from", {}).get("emailAddress", {})
            sender = addr.get("address") or addr.get("name")
    return True, "", (total, subject, sender)


def _imap_xoauth2(imap: imaplib.IMAP4, email_addr: str, access_token: str) -> tuple[bool, str]:
    """手动执行 XOAUTH2,失败时抓取服务器返回的详细错误。返回 (是否成功, 详情)。"""
    auth = f"user={email_addr}\x01auth=Bearer {access_token}\x01\x01"
    auth_b64 = base64.b64encode(auth.encode()).decode()
    tag = imap._new_tag().decode()

    imap.send(f"{tag} AUTHENTICATE XOAUTH2\r\n".encode())
    resp = imap.readline().decode(errors="replace").strip()
    if not resp.startswith("+"):
        return False, f"未进入认证流程:{resp}"

    imap.send((auth_b64 + "\r\n").encode())
    detail = ""
    while True:
        line = imap.readline()
        if not line:
            return False, detail or "连接被服务器关闭"
        s = line.decode(errors="replace").strip()
        if s.startswith("+"):
            # 服务器返回 base64 编码的错误 JSON,需回一个空行才能拿到最终结果
            try:
                detail = base64.b64decode(s[1:].strip()).decode(errors="replace")
            except Exception:
                detail = s[1:].strip()
            imap.send(b"\r\n")
            continue
        if s.startswith(tag) or s.startswith("* "):
            if " OK" in s and s.startswith(tag):
                imap.state = "AUTH"
                return True, ""
            if s.startswith(tag):
                return False, detail or s


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _try_graph(
    email_addr: str,
    refresh_token: str,
    client_id: str,
    proxies: dict | None,
    timeout: int,
) -> tuple[MailTestResult | None, str | None, str]:
    """尝试 Graph 收信。返回 (成功结果或 None, 轮换 token, 诊断信息)。"""
    try:
        token, new_refresh, src = _get_access_token(
            refresh_token, client_id, proxies, timeout, GRAPH_TOKEN_STRATEGIES
        )
    except requests.RequestException as exc:
        return None, None, f"Graph 换令牌网络错误:{exc}"
    except RuntimeError as exc:
        return None, None, f"Graph 换令牌失败:{exc}"

    try:
        ok, detail, (total, subject, sender) = _graph_read(token, proxies, timeout)
    except requests.RequestException as exc:
        return None, new_refresh, f"Graph 读取网络错误:{exc}"
    if not ok:
        return None, new_refresh, f"Graph 读取失败(令牌来自 {src}):{detail}"

    return (
        MailTestResult(
            True,
            f"通过 Graph 收件成功,共 {total if total is not None else '?'} 封邮件",
            inbox_total=total,
            latest_subject=subject,
            latest_from=sender,
            new_refresh_token=new_refresh,
        ),
        new_refresh,
        "",
    )


def _try_imap(
    email_addr: str,
    refresh_token: str,
    client_id: str,
    proxy: ProxyConfig | None,
    proxies: dict | None,
    timeout: int,
) -> tuple[MailTestResult | None, str | None, str]:
    """尝试 IMAP 收信。返回 (成功结果或 None, 轮换 token, 诊断信息)。"""
    try:
        token, new_refresh, src = _get_access_token(
            refresh_token, client_id, proxies, timeout, IMAP_TOKEN_STRATEGIES
        )
    except requests.RequestException as exc:
        return None, None, f"IMAP 换令牌网络错误:{exc}"
    except RuntimeError as exc:
        return None, None, f"IMAP 换令牌失败:{exc}"

    imap_proxy = proxy if proxy and proxy.scheme.startswith("socks") else None
    imap: _ProxyIMAP4SSL | None = None
    try:
        imap = _ProxyIMAP4SSL(IMAP_HOST, IMAP_PORT, timeout, imap_proxy)
        ok, detail = _imap_xoauth2(imap, email_addr, token)
        if not ok:
            return None, new_refresh, f"IMAP 认证失败(令牌来自 {src}):{detail}"

        imap.select("INBOX", readonly=True)
        status, data = imap.search(None, "ALL")
        if status != "OK":
            return None, new_refresh, "IMAP 无法读取收件箱"

        ids = data[0].split()
        total = len(ids)
        latest_subject = latest_from = None
        if ids:
            _, msg_data = imap.fetch(ids[-1], "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])")
            raw = b""
            for part in msg_data:
                if isinstance(part, tuple):
                    raw += part[1]
            import email as email_lib

            headers = email_lib.message_from_bytes(raw)
            latest_subject = _decode(headers.get("Subject"))
            latest_from = _decode(headers.get("From"))

        return (
            MailTestResult(
                True,
                f"通过 IMAP 收件成功,共 {total} 封邮件",
                inbox_total=total,
                latest_subject=latest_subject,
                latest_from=latest_from,
                new_refresh_token=new_refresh,
            ),
            new_refresh,
            "",
        )
    except imaplib.IMAP4.error as exc:
        return None, new_refresh, f"IMAP 收信失败:{exc}"
    except (ssl.SSLError, OSError, socket.timeout) as exc:
        return None, new_refresh, f"IMAP 连接失败:{exc}"
    except Exception as exc:  # noqa: BLE001
        return None, new_refresh, f"IMAP 测试异常:{exc}"
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


def test_receive_email(
    *,
    email_addr: str,
    refresh_token: str,
    client_id: str,
    proxy_url: str = "",
    timeout: int = 30,
) -> MailTestResult:
    proxy = _parse_proxy(proxy_url)
    proxies = _requests_proxies(proxy)

    diagnostics: list[str] = []
    rotated: str | None = None

    # 1) 优先 Graph(对现代 token 兼容性更好)
    result, new_rt, info = _try_graph(email_addr, refresh_token, client_id, proxies, timeout)
    rotated = new_rt or rotated
    if result:
        return result
    if info:
        diagnostics.append(info)

    # 2) 回退 IMAP
    result, new_rt, info = _try_imap(
        email_addr, refresh_token, client_id, proxy, proxies, timeout
    )
    rotated = new_rt or rotated
    if result:
        return result
    if info:
        diagnostics.append(info)

    return MailTestResult(
        False, " ‖ ".join(diagnostics) or "收信失败", new_refresh_token=rotated
    )


# ----------------------------------------------------------------------------
# 收取邮件列表 / 查看邮件详情(供「邮箱管理」使用)
# ----------------------------------------------------------------------------

def _graph_list(
    access_token: str, proxies: dict | None, timeout: int, top: int
) -> tuple[bool, str, list[MailSummary]]:
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(
        f"{GRAPH_BASE}/me/mailFolders/inbox/messages",
        headers=headers,
        proxies=proxies,
        timeout=timeout,
        params={
            "$top": str(max(1, min(top, 100))),
            "$orderby": "receivedDateTime desc",
            "$select": "id,subject,from,receivedDateTime,bodyPreview,isRead",
        },
        verify=False,
    )
    if resp.status_code != 200:
        return False, _graph_error(resp), []
    out: list[MailSummary] = []
    for it in resp.json().get("value", []):
        addr = (it.get("from") or {}).get("emailAddress", {})
        out.append(
            MailSummary(
                id=it.get("id", ""),
                subject=it.get("subject") or "(无主题)",
                from_addr=addr.get("address") or addr.get("name") or "",
                date=it.get("receivedDateTime") or "",
                preview=(it.get("bodyPreview") or "").strip(),
                is_read=it.get("isRead"),
                source="graph",
            )
        )
    return True, "", out


def _graph_detail(
    access_token: str, proxies: dict | None, timeout: int, message_id: str
) -> tuple[bool, str, MailDetailResult]:
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(
        f"{GRAPH_BASE}/me/messages/{message_id}",
        headers=headers,
        proxies=proxies,
        timeout=timeout,
        params={"$select": "subject,from,toRecipients,receivedDateTime,body"},
        verify=False,
    )
    if resp.status_code != 200:
        return False, _graph_error(resp), MailDetailResult(False, "")
    it = resp.json()
    addr = (it.get("from") or {}).get("emailAddress", {})
    to_list = [
        (r.get("emailAddress") or {}).get("address") or ""
        for r in it.get("toRecipients", [])
    ]
    body = it.get("body") or {}
    content = body.get("content") or ""
    is_html = (body.get("contentType") or "").lower() == "html"
    return True, "", MailDetailResult(
        success=True,
        message="",
        subject=it.get("subject") or "(无主题)",
        from_addr=addr.get("address") or addr.get("name") or "",
        to_addr=", ".join([t for t in to_list if t]),
        date=it.get("receivedDateTime") or "",
        body_html=content if is_html else "",
        body_text="" if is_html else content,
    )


def _imap_open(
    email_addr: str, token: str, proxy: ProxyConfig | None, timeout: int
) -> _ProxyIMAP4SSL:
    imap_proxy = proxy if proxy and proxy.scheme.startswith("socks") else None
    imap = _ProxyIMAP4SSL(IMAP_HOST, IMAP_PORT, timeout, imap_proxy)
    ok, detail = _imap_xoauth2(imap, email_addr, token)
    if not ok:
        try:
            imap.logout()
        except Exception:
            pass
        raise RuntimeError(detail or "IMAP 认证失败")
    return imap


_IMAP_LIST_FOLDERS = ("INBOX", "Junk", "junkemail", "Junk Email")


def _mail_ts(value: str) -> float:
    if not value:
        return 0.0
    try:
        return parsedate_to_datetime(value).timestamp()
    except Exception:
        return 0.0


def _imap_message_id(folder: str, uid: bytes) -> str:
    return f"{folder}|{uid.decode(errors='ignore')}"


def _split_imap_message_id(message_id: str) -> tuple[str, str]:
    if "|" not in message_id:
        return "INBOX", message_id
    folder, uid = message_id.split("|", 1)
    return folder or "INBOX", uid


def _imap_list(
    email_addr: str, token: str, proxy: ProxyConfig | None, timeout: int, top: int
) -> tuple[bool, str, list[MailSummary]]:
    import email as email_lib

    imap: _ProxyIMAP4SSL | None = None
    try:
        imap = _imap_open(email_addr, token, proxy, timeout)
        out: list[MailSummary] = []
        errors: list[str] = []
        per_folder = max(1, min(top, 100))
        for folder in _IMAP_LIST_FOLDERS:
            try:
                status_, _ = imap.select(folder, readonly=True)
                if status_ != "OK":
                    continue
                status_, data = imap.uid("search", None, "ALL")
                if status_ != "OK":
                    errors.append(f"{folder}:search失败")
                    continue
                uids = data[0].split() if data and data[0] else []
                recent = uids[-per_folder:][::-1]
                for uid in recent:
                    _, msg_data = imap.uid(
                        "fetch", uid,
                        "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])",
                    )
                    raw = b""
                    for part in msg_data:
                        if isinstance(part, tuple):
                            raw += part[1]
                    if not raw:
                        continue
                    hdr = email_lib.message_from_bytes(raw)
                    out.append(
                        MailSummary(
                            id=_imap_message_id(folder, uid),
                            subject=_decode(hdr.get("Subject")) or "(无主题)",
                            from_addr=_decode(hdr.get("From")),
                            date=_decode(hdr.get("Date")),
                            folder=folder,
                            source="imap",
                        )
                    )
            except imaplib.IMAP4.error as exc:
                errors.append(f"{folder}:{exc}")
                continue
        out.sort(key=lambda m: _mail_ts(m.date), reverse=True)
        out = out[:max(1, min(top, 100))]
        if out:
            folders = sorted({m.folder for m in out if m.folder})
            return True, f"共 {len(out)} 封({', '.join(folders)})", out
        if errors:
            return False, "IMAP 无法读取邮件:" + " | ".join(errors[:3]), []
        return True, "暂无邮件", []
    except (imaplib.IMAP4.error, ssl.SSLError, OSError, socket.timeout) as exc:
        return False, f"IMAP 收信失败:{exc}", []
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


def _imap_detail(
    email_addr: str, token: str, proxy: ProxyConfig | None, timeout: int, uid: str
) -> tuple[bool, str, MailDetailResult]:
    import email as email_lib

    folder, raw_uid = _split_imap_message_id(uid)
    imap: _ProxyIMAP4SSL | None = None
    try:
        imap = _imap_open(email_addr, token, proxy, timeout)
        status_, _ = imap.select(folder, readonly=True)
        if status_ != "OK":
            return False, f"无法打开文件夹:{folder}", MailDetailResult(False, "")
        _, msg_data = imap.uid("fetch", raw_uid.encode(), "(RFC822)")
        raw = b""
        for part in msg_data:
            if isinstance(part, tuple):
                raw += part[1]
        if not raw:
            return False, "未找到该邮件", MailDetailResult(False, "")
        msg = email_lib.message_from_bytes(raw)
        html, text = _imap_body(msg)
        return True, "", MailDetailResult(
            success=True,
            message="",
            subject=_decode(msg.get("Subject")) or "(无主题)",
            from_addr=_decode(msg.get("From")),
            to_addr=_decode(msg.get("To")),
            date=_decode(msg.get("Date")),
            body_html=html,
            body_text=text,
        )
    except (imaplib.IMAP4.error, ssl.SSLError, OSError, socket.timeout) as exc:
        return False, f"IMAP 读取失败:{exc}", MailDetailResult(False, "")
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


def _imap_body(msg) -> tuple[str, str]:
    """从 email.message 提取 (html, text)。"""
    html = text = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.get("Content-Disposition", "").startswith("attachment"):
                continue
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                continue
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except Exception:
                decoded = payload.decode("utf-8", errors="replace")
            if ctype == "text/html" and not html:
                html = decoded
            elif ctype == "text/plain" and not text:
                text = decoded
    else:
        payload = msg.get_payload(decode=True) or b""
        charset = msg.get_content_charset() or "utf-8"
        decoded = payload.decode(charset, errors="replace") if payload else ""
        if msg.get_content_type() == "text/html":
            html = decoded
        else:
            text = decoded
    return html, text

def fetch_inbox(
    *,
    email_addr: str,
    refresh_token: str,
    client_id: str,
    proxy_url: str = "",
    timeout: int = 30,
    top: int = 20,
) -> MailListResult:
    """快速收取邮件列表(优先 IMAP,失败回退 Graph)。"""
    proxy = _parse_proxy(proxy_url)
    proxies = _requests_proxies(proxy)
    diagnostics: list[str] = []
    rotated: str | None = None

    # 1) IMAP: Outlook Graph Mail.Read 经常无授权,先走 IMAP 更快。
    for strategy in IMAP_TOKEN_STRATEGIES:
        try:
            token, new_rt, src = _get_access_token(
                refresh_token, client_id, proxies, timeout, [strategy]
            )
            rotated = new_rt or rotated
            ok, detail, msgs = _imap_list(email_addr, token, proxy, timeout, top)
            if ok:
                return MailListResult(True, detail or f"共 {len(msgs)} 封", "imap", msgs, rotated)
            diagnostics.append(f"IMAP({src}):{detail}")
        except (requests.RequestException, RuntimeError) as exc:
            diagnostics.append(f"IMAP:{exc}")

    # 2) Graph fallback
    try:
        token, new_rt, _src = _get_access_token(
            refresh_token, client_id, proxies, timeout, GRAPH_TOKEN_STRATEGIES
        )
        rotated = new_rt or rotated
        ok, detail, msgs = _graph_list(token, proxies, timeout, top)
        if ok:
            return MailListResult(True, f"共 {len(msgs)} 封", "graph", msgs, rotated)
        diagnostics.append(f"Graph:{detail}")
    except (requests.RequestException, RuntimeError) as exc:
        diagnostics.append(f"Graph 换令牌失败:{exc}")

    return MailListResult(
        False, " ‖ ".join(diagnostics) or "收取失败", "", [], rotated
    )


def fetch_message(
    *,
    email_addr: str,
    refresh_token: str,
    client_id: str,
    message_id: str,
    source: str,
    proxy_url: str = "",
    timeout: int = 30,
) -> MailDetailResult:
    """查看单封邮件详情(source 决定走 Graph 还是 IMAP,与列表来源一致)。"""
    proxy = _parse_proxy(proxy_url)
    proxies = _requests_proxies(proxy)
    rotated: str | None = None

    if source == "imap":
        diagnostics: list[str] = []
        for strategy in IMAP_TOKEN_STRATEGIES:
            try:
                token, new_rt, src = _get_access_token(
                    refresh_token, client_id, proxies, timeout, [strategy]
                )
                rotated = new_rt or rotated
                ok, detail, res = _imap_detail(email_addr, token, proxy, timeout, message_id)
                res.new_refresh_token = rotated
                if ok:
                    return res
                diagnostics.append(f"IMAP({src}):{detail}")
            except (requests.RequestException, RuntimeError) as exc:
                diagnostics.append(f"IMAP:{exc}")
        return MailDetailResult(
            False, " ‖ ".join(diagnostics) or "IMAP 读取失败",
            new_refresh_token=rotated,
        )

    # 默认 Graph
    try:
        token, new_rt, _src = _get_access_token(
            refresh_token, client_id, proxies, timeout, GRAPH_TOKEN_STRATEGIES
        )
        rotated = new_rt or rotated
        ok, detail, res = _graph_detail(token, proxies, timeout, message_id)
        res.new_refresh_token = rotated
        if not ok:
            res.message = detail
        return res
    except (requests.RequestException, RuntimeError) as exc:
        return MailDetailResult(False, f"换令牌失败:{exc}", new_refresh_token=rotated)
