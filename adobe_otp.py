"""通过 Microsoft Graph 收取 Adobe 发来的验证码(OTP)。

管理账号登录 adminconsole.adobe.com 时常需要邮箱验证码。本模块用账号自带的
Refresh Token + Client ID 调 Graph 读取收件箱/垃圾箱,提取 6 位 Adobe 验证码。

注意: Microsoft Graph / IMAP 默认**直连**,不走 Adobe 登录用的代理。
"""

from __future__ import annotations

import email as email_lib
import email.utils
import imaplib
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from mail_test import (
    GRAPH_BASE,
    GRAPH_TOKEN_STRATEGIES,
    IMAP_HOST,
    IMAP_PORT,
    IMAP_TOKEN_STRATEGIES,
    _ProxyIMAP4SSL,
    _decode,
    _get_access_token,
    _imap_body,
    _imap_xoauth2,
    _parse_proxy,
    _requests_proxies,
)

_IMAP_FOLDERS = ("INBOX", "Junk")
_OTP_FOLDERS = ("inbox", "junkemail")

_ADOBE_OTP_PATTERNS = [
    re.compile(
        r"(?:one[\s-]?time[\s-]?(?:password|code)|"
        r"verification\s+code|authentication\s+code|security\s+code|"
        r"your\s+code|code\s+is|code:|otp[:\s]+|otp\s+is|"
        r"pin\s+code\s+is|sign[\s-]?in\s+code|access\s+code)"
        r"[^\d]{0,50}(\d{6})(?!\d)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:\u9a8c\u8bc1\u7801|\u5b89\u5168\u4ee3\u7801|"
        r"\u60a8\u7684\u4ee3\u7801|\u4e00\u6b21\u6027\u5bc6\u7801|"
        r"\u52a8\u6001\u5bc6\u7801|PIN\s*\u7801)"
        r"[^\d]{0,40}(\d{6})(?!\d)"
    ),
]

_GRAPH_SELECT = "id,subject,from,receivedDateTime,bodyPreview"
_GRAPH_REQ_TIMEOUT = 12
_OTP_MAX_AGE_MIN = 20
_XIAOHEIFK_MAIL_API = "https://api.xiaoheifk.cn/api/mail-new"
_EXTERNAL_MAIL_FOLDERS = ("INBOX", "Junk", "junkemail")


def _strip_mail_headers(raw: str) -> str:
    if not raw or len(raw) < 50:
        return raw
    head = raw[:3000]
    rfc_headers = re.search(
        r"^(?:Return-Path|Received|From|To|Subject|Message-ID|"
        r"Date|MIME-Version|Content-Type|DKIM-Signature|X-[\w-]+):",
        head,
        re.MULTILINE | re.IGNORECASE,
    )
    if not rfc_headers:
        return raw
    sep = re.search(r"\r?\n\r?\n", raw)
    if sep:
        return raw[sep.end():]
    return raw


def _extract_adobe_otp(subject: str, body: str) -> str | None:
    body_clean = _strip_mail_headers(body or "")
    haystacks = (subject or "", body_clean)
    for pat in _ADOBE_OTP_PATTERNS:
        for hay in haystacks:
            m = pat.search(hay)
            if m:
                cand = m.group(1)
                if cand and cand != "000000":
                    return cand
    boundary = re.compile(r"(?<![\w.\-+/=])(\d{6})(?![\w.\-+/=])")
    for hay in haystacks:
        for cand in boundary.findall(hay):
            if cand != "000000":
                return cand
    return None


def _is_adobe_message(sender: str, subject: str) -> bool:
    s = (sender or "").lower()
    sub = (subject or "").lower()
    return "adobe" in s or "adobe" in sub


def _is_url(value: str) -> bool:
    parsed = urlparse((value or "").strip())
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _strip_html(raw: str) -> str:
    return re.sub(r"<[^>]+>", " ", raw or "")


def _brief_mail_text(value: str, limit: int = 90) -> str:
    text = re.sub(r"\s+", " ", value or "").strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def _is_recent(
    received: str,
    max_age_min: int = _OTP_MAX_AGE_MIN,
    not_before_ts: float | None = None,
) -> bool:
    if not received:
        return not_before_ts is not None  # 有发送时间戳时不接受无日期邮件
    try:
        dt = datetime.fromisoformat(received.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt <= datetime.now(timezone.utc) - timedelta(minutes=max_age_min):
            return False
        if not_before_ts is not None and dt.timestamp() < not_before_ts:
            return False
        return True
    except Exception:
        return not_before_ts is None


class OtpHolder:
    def __init__(self, refresh_token: str) -> None:
        self.refresh_token = refresh_token
        self.rotated = False


def make_otp_poller(
    *,
    refresh_token: str,
    client_id: str,
    mail_url: str = "",
    proxy_url: str = "",
    timeout: int = 180,
    use_proxy_for_mail: bool = False,
    log: Callable[[str], None] | None = None,
) -> tuple[Callable[..., str], OtpHolder]:
    """构造 poll_otp 兼容的收码函数。``timeout`` 同时作为默认等待上限(秒)。"""
    holder = OtpHolder(refresh_token)
    lf = log if callable(log) else (lambda _m: None)
    default_wait_s = max(90, min(int(timeout or 180), 300))
    req_timeout = _GRAPH_REQ_TIMEOUT

    mail_proxy = _parse_proxy(proxy_url) if use_proxy_for_mail and proxy_url else None
    mail_proxies = _requests_proxies(mail_proxy)
    imap_proxy = (
        mail_proxy if mail_proxy and mail_proxy.scheme.startswith("socks") else None
    )
    mail_mode = "直连" if not mail_proxies else "走代理"
    external_mail_url = (mail_url or "").strip()
    external_from_refresh_token = (
        not external_mail_url and _is_url(refresh_token)
    )
    prefer_external_mail = external_from_refresh_token or not refresh_token.startswith("M.")
    if (external_mail_url and prefer_external_mail) or external_from_refresh_token:
        mail_mode = "外部取信接口"
    elif use_proxy_for_mail and proxy_url:
        if imap_proxy:
            mail_mode = f"{mail_mode}/SOCKS代理"
        elif mail_proxies:
            mail_mode = f"{mail_mode}/HTTP代理(Graph)"

    state: dict[str, object] = {
        "graph_token": "",
        "graph_exp": 0.0,
        "imap_token": "",
        "imap_exp": 0.0,
        "imap_conn": None,
        "filter_ok": True,
    }
    http = requests.Session()

    def _moemail_config() -> tuple[str, str, str] | None:
        parsed = urlparse(external_mail_url)
        if parsed.scheme != "moemail":
            return None
        qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
        api_key = (qs.get("api_key") or qs.get("key") or "").strip()
        if not api_key:
            return None
        host = parsed.netloc or "edu6.site"
        base = f"https://{host.strip('/')}"
        email_id = (qs.get("email_id") or qs.get("emailId") or parsed.path.strip("/")).strip()
        return base, api_key, email_id

    def _moemail_headers(api_key: str) -> dict[str, str]:
        return {"X-API-Key": api_key, "Accept": "application/json"}

    def _moemail_resolve_email_id(base: str, api_key: str, email_addr: str) -> str:
        cursor = ""
        target = email_addr.lower()
        for _ in range(5):
            params = {"cursor": cursor} if cursor else None
            r = http.get(
                f"{base}/api/emails",
                headers=_moemail_headers(api_key),
                params=params,
                timeout=req_timeout,
            )
            if r.status_code != 200:
                lf(f"MoeMail 邮箱列表失败 {r.status_code}:{(r.text or '')[:80]}")
                return ""
            data = r.json() or {}
            for item in data.get("emails") or []:
                address = (item.get("address") or item.get("email") or "").lower()
                if address == target:
                    return str(item.get("id") or "")
            cursor = data.get("nextCursor") or ""
            if not cursor:
                break
        lf("MoeMail 未找到该邮箱 emailId")
        return ""

    def _moemail_message_is_fresh(msg: dict) -> bool:
        received = msg.get("received_at") or msg.get("receivedAt") or ""
        nb = state.get("not_before_ts")
        if isinstance(received, (int, float)):
            ts = float(received)
            if ts > 10_000_000_000:
                ts /= 1000
            if ts <= time.time() - _OTP_MAX_AGE_MIN * 60:
                return False
            if nb is not None and ts < float(nb):
                return False
            return True
        return _mail_is_fresh(str(received))

    def _scan_moemail_mail(email_addr: str) -> str | None:
        cfg = _moemail_config()
        if not cfg:
            return None
        base, api_key, email_id = cfg
        if not email_id:
            email_id = _moemail_resolve_email_id(base, api_key, email_addr)
            if not email_id:
                return None
        try:
            r = http.get(
                f"{base}/api/emails/{email_id}",
                headers=_moemail_headers(api_key),
                timeout=req_timeout,
            )
        except requests.RequestException as exc:
            lf(f"MoeMail 邮件列表请求失败({str(exc)[:80]})")
            return None
        if r.status_code != 200:
            lf(f"MoeMail 邮件列表失败 {r.status_code}:{(r.text or '')[:80]}")
            return None
        messages = (r.json() or {}).get("messages") or []
        for msg in messages[:10]:
            subject = msg.get("subject") or ""
            sender = msg.get("from_address") or msg.get("fromAddress") or ""
            if not _is_adobe_message(sender, subject):
                continue
            if not _moemail_message_is_fresh(msg):
                continue
            mid = msg.get("id")
            if not mid:
                continue
            try:
                detail = http.get(
                    f"{base}/api/emails/{email_id}/{mid}",
                    headers=_moemail_headers(api_key),
                    timeout=req_timeout,
                )
            except requests.RequestException:
                continue
            if detail.status_code != 200:
                continue
            payload = (detail.json() or {}).get("message") or {}
            text = " ".join(
                str(payload.get(k) or "")
                for k in ("subject", "content", "html", "from_address", "fromAddress")
            )
            code = _extract_adobe_otp(subject, _strip_html(text))
            if code:
                lf(f"✓ 已收到 Adobe 验证码 {code}(MoeMail)")
                return code
        return None

    def _external_urls(email_addr: str) -> list[str]:
        if external_mail_url:
            parsed = urlparse(external_mail_url)
            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            urls: list[str] = []
            folders = _EXTERNAL_MAIL_FOLDERS if "mailbox" in qs else ("",)
            for folder in folders:
                next_qs = dict(qs)
                if folder:
                    next_qs["mailbox"] = folder
                rebuilt = parsed._replace(query=urlencode(next_qs))
                urls.append(urlunparse(rebuilt))
            return urls

        urls = []
        if external_from_refresh_token:
            direct_url = holder.refresh_token.strip()
            urls.append(direct_url)
            parsed = urlparse(direct_url)
            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            for folder in _EXTERNAL_MAIL_FOLDERS:
                next_qs = dict(qs)
                next_qs["mailbox"] = folder
                next_qs["response_type"] = "html"
                urls.append(urlunparse(parsed._replace(query=urlencode(next_qs))))

        for folder in _EXTERNAL_MAIL_FOLDERS:
            params = {
                "refresh_token": holder.refresh_token,
                "client_id": client_id,
                "email": email_addr,
                "mailbox": folder,
                "response_type": "html",
                # xiaoheifk 的 mail-new 对这批链接需要该固定查询密码。
                "password": "520521",
            }
            urls.append(f"{_XIAOHEIFK_MAIL_API}?{urlencode(params)}")
        return urls

    def _external_payload_text(payload: object) -> str:
        if isinstance(payload, dict):
            chunks: list[str] = []
            for key in (
                "subject",
                "from",
                "from_addr",
                "sender",
                "date",
                "receivedDateTime",
                "preview",
                "bodyPreview",
                "body",
                "body_html",
                "body_text",
                "content",
                "html",
                "text",
                "message",
            ):
                val = payload.get(key)
                if isinstance(val, str):
                    chunks.append(val)
            data = payload.get("data")
            if data is not payload:
                chunks.append(_external_payload_text(data))
            if not chunks:
                chunks.append(str(payload))
            return " ".join(chunks)
        if isinstance(payload, list):
            return " ".join(_external_payload_text(item) for item in payload[:20])
        if payload is None:
            return ""
        return str(payload)

    def _scan_external_mail(
        email_addr: str,
        *,
        ignore_codes: set[str] | None = None,
        capture_baseline: bool = False,
    ) -> str | None:
        if _moemail_config():
            return _scan_moemail_mail(email_addr)
        ignore_codes = ignore_codes if ignore_codes is not None else set()
        for url in _external_urls(email_addr):
            try:
                r = http.get(url, timeout=req_timeout)
            except requests.RequestException as exc:
                lf(f"外部取信接口请求失败({str(exc)[:80]})")
                continue
            if r.status_code != 200:
                lf(f"外部取信接口返回 {r.status_code}")
                continue
            content_type = (r.headers.get("content-type") or "").lower()
            payload: object
            if "json" in content_type:
                try:
                    payload = r.json()
                except ValueError:
                    payload = r.text
            else:
                payload = r.text
            text = _strip_html(_external_payload_text(payload))
            code = _extract_adobe_otp("", text)
            if code:
                if code in ignore_codes:
                    return None
                if capture_baseline:
                    ignore_codes.add(code)
                    lf("检测到页面已有旧验证码,等待新验证码刷新…")
                    return None
                lf(f"✓ 已收到 Adobe 验证码 {code}(外部接口)")
                return code
        return None

    def _rotate(new_refresh: str | None) -> None:
        if new_refresh and new_refresh != holder.refresh_token:
            holder.refresh_token = new_refresh
            holder.rotated = True

    def _get_token_with_fallback(strategies: list) -> str:
        last_exc: Exception | None = None
        attempts: list[dict | None] = [mail_proxies, None] if mail_proxies else [None]
        for px in attempts:
            try:
                token, new_refresh, _src = _get_access_token(
                    holder.refresh_token, client_id, px, req_timeout, strategies
                )
                _rotate(new_refresh)
                return token
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
        raise last_exc or RuntimeError("获取 Microsoft 访问令牌失败")

    def _ensure_graph_token() -> str:
        now = time.time()
        if state["graph_token"] and now < float(state["graph_exp"]):
            return str(state["graph_token"])
        token = _get_token_with_fallback(GRAPH_TOKEN_STRATEGIES)
        state["graph_token"] = token
        state["graph_exp"] = now + 3000
        return token

    def _ensure_imap_token() -> str:
        now = time.time()
        if state["imap_token"] and now < float(state["imap_exp"]):
            return str(state["imap_token"])
        token = _get_token_with_fallback(IMAP_TOKEN_STRATEGIES)
        state["imap_token"] = token
        state["imap_exp"] = now + 3000
        return token

    def _graph_since_filter() -> str:
        nb = state.get("not_before_ts")
        if nb:
            since = datetime.fromtimestamp(float(nb) - 10, tz=timezone.utc)
        else:
            since = datetime.now(timezone.utc) - timedelta(minutes=_OTP_MAX_AGE_MIN)
        return since.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _mail_is_fresh(received: str) -> bool:
        nb = state.get("not_before_ts")
        if not received:
            return nb is None
        ts: float | None = None
        try:
            dt = datetime.fromisoformat(received.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts = dt.timestamp()
        except Exception:
            try:
                dt = email.utils.parsedate_to_datetime(received)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                ts = dt.timestamp()
            except Exception:
                return nb is None
        if ts <= time.time() - _OTP_MAX_AGE_MIN * 60:
            return False
        if nb is not None and ts < float(nb):
            return False
        return True

    def _fetch_graph_body(token: str, message_id: str) -> str:
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Prefer": 'outlook.body-content-type="text"',
        }
        url = f"{GRAPH_BASE}/me/messages/{message_id}?$select=body"
        try:
            r = http.get(
                url, headers=headers, proxies=mail_proxies, timeout=req_timeout
            )
        except requests.RequestException:
            return ""
        if r.status_code != 200:
            return ""
        body = (r.json().get("body") or {}).get("content") or ""
        return re.sub(r"<[^>]+>", " ", body)

    def _code_from_graph_item(token: str, m: dict, seen: set[str]) -> str | None:
        mid = m.get("id")
        if not mid or f"g:{mid}" in seen:
            return None
        seen.add(f"g:{mid}")
        sender = (
            m.get("from", {}).get("emailAddress", {}).get("address", "") or ""
        )
        subject = m.get("subject") or ""
        if not _is_adobe_message(sender, subject):
            return None
        if not _mail_is_fresh(m.get("receivedDateTime") or ""):
            lf(f"跳过旧 Adobe 邮件(Graph): { _brief_mail_text(subject) }")
            return None
        preview = m.get("bodyPreview") or ""
        code = _extract_adobe_otp(subject, preview)
        if not code:
            code = _extract_adobe_otp(subject, _fetch_graph_body(token, mid))
        if code:
            lf(f"✓ 已收到 Adobe 验证码 {code}")
            return code
        lf(f"读到 Adobe 邮件但未找到验证码(Graph): { _brief_mail_text(subject) }")
        return None

    def _scan_graph_filter(token: str, seen: set[str]) -> str | None:
        if not state["filter_ok"]:
            return None
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Prefer": 'outlook.body-content-type="text"',
        }
        since = _graph_since_filter()
        flt = (
            f"(contains(from/emailAddress/address,'adobe') or contains(subject,'Adobe')) "
            f"and receivedDateTime ge {since}"
        )
        url = f"{GRAPH_BASE}/me/messages"
        params = {
            "$top": "8",
            "$orderby": "receivedDateTime desc",
            "$select": _GRAPH_SELECT,
            "$filter": flt,
        }
        try:
            r = http.get(
                url,
                headers=headers,
                params=params,
                proxies=mail_proxies,
                timeout=req_timeout,
            )
        except requests.RequestException as exc:
            lf(f"Graph 过滤查询失败({str(exc)[:80]})")
            return None
        if r.status_code == 401:
            state["graph_token"] = ""
            state["graph_exp"] = 0.0
            return None
        if r.status_code == 400:
            state["filter_ok"] = False
            return None
        if r.status_code != 200:
            return None
        for m in r.json().get("value", []):
            code = _code_from_graph_item(token, m, seen)
            if code:
                return code
        return None

    def _scan_graph_folder(token: str, folder: str, seen: set[str]) -> str | None:
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Prefer": 'outlook.body-content-type="text"',
        }
        url = (
            f"{GRAPH_BASE}/me/mailFolders('{folder}')/messages"
            f"?$top=8&$orderby=receivedDateTime desc&$select={_GRAPH_SELECT}"
        )
        try:
            r = http.get(url, headers=headers, proxies=mail_proxies, timeout=req_timeout)
        except requests.RequestException:
            return None
        if r.status_code == 401:
            state["graph_token"] = ""
            state["graph_exp"] = 0.0
            return None
        if r.status_code != 200:
            return None
        for m in r.json().get("value", []):
            code = _code_from_graph_item(token, m, seen)
            if code:
                return code
        return None

    def _scan_graph_recent(token: str, seen: set[str]) -> str | None:
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Prefer": 'outlook.body-content-type="text"',
        }
        url = (
            f"{GRAPH_BASE}/me/messages"
            f"?$top=10&$orderby=receivedDateTime desc&$select={_GRAPH_SELECT}"
        )
        try:
            r = http.get(url, headers=headers, proxies=mail_proxies, timeout=req_timeout)
        except requests.RequestException as exc:
            lf(f"Graph 最近邮件查询失败({str(exc)[:80]})")
            return None
        if r.status_code == 401:
            state["graph_token"] = ""
            state["graph_exp"] = 0.0
            return None
        if r.status_code != 200:
            return None
        for m in r.json().get("value", []):
            code = _code_from_graph_item(token, m, seen)
            if code:
                return code
        return None

    def _scan_graph(token: str, seen: set[str]) -> str | None:
        found = _scan_graph_recent(token, seen)
        if found:
            return found
        found = _scan_graph_filter(token, seen)
        if found:
            return found
        with ThreadPoolExecutor(max_workers=len(_OTP_FOLDERS)) as ex:
            futures = {
                ex.submit(_scan_graph_folder, token, folder, seen): folder
                for folder in _OTP_FOLDERS
            }
            for fut in as_completed(futures):
                try:
                    code = fut.result()
                except Exception:  # noqa: BLE001
                    continue
                if code:
                    return code
        return None

    def _close_imap() -> None:
        imap = state.get("imap_conn")
        state["imap_conn"] = None
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass

    def _open_imap(email_addr: str) -> _ProxyIMAP4SSL:
        imap = state.get("imap_conn")
        if imap is not None:
            try:
                imap.noop()
                return imap  # type: ignore[return-value]
            except Exception:
                _close_imap()
        token = _ensure_imap_token()
        imap = _ProxyIMAP4SSL(IMAP_HOST, IMAP_PORT, req_timeout, imap_proxy)
        ok, detail = _imap_xoauth2(imap, email_addr, token)
        if not ok:
            state["imap_token"] = ""
            state["imap_exp"] = 0.0
            try:
                imap.logout()
            except Exception:
                pass
            raise RuntimeError(detail or "IMAP 认证失败")
        state["imap_conn"] = imap
        return imap

    def _scan_imap(email_addr: str, seen: set[str]) -> str | None:
        imap = _open_imap(email_addr)
        for folder in _IMAP_FOLDERS:
            try:
                typ, _ = imap.select(folder, readonly=True)
                if typ != "OK":
                    continue
                typ, data = imap.uid("search", None, "UNSEEN")
                uids = data[0].split() if typ == "OK" and data and data[0] else []
                if not uids:
                    typ, data = imap.uid("search", None, "ALL")
                    uids = data[0].split() if typ == "OK" and data and data[0] else []
            except imaplib.IMAP4.error:
                _close_imap()
                imap = _open_imap(email_addr)
                continue
            for uid in uids[-8:][::-1]:
                key = f"i:{folder}:{uid.decode()}"
                if key in seen:
                    continue
                seen.add(key)
                try:
                    _, msg_data = imap.uid(
                        "fetch",
                        uid,
                        "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])",
                    )
                except imaplib.IMAP4.error:
                    continue
                raw = b""
                for part in msg_data:
                    if isinstance(part, tuple):
                        raw += part[1]
                if not raw:
                    continue
                msg = email_lib.message_from_bytes(raw)
                sender = (_decode(msg.get("From")) or "").lower()
                subject = _decode(msg.get("Subject")) or ""
                if not _is_adobe_message(sender, subject):
                    continue
                date_hdr = _decode(msg.get("Date")) or ""
                if date_hdr and not _mail_is_fresh(date_hdr):
                    lf(f"跳过旧 Adobe 邮件(IMAP): { _brief_mail_text(subject) }")
                    continue
                try:
                    _, msg_data = imap.uid("fetch", uid, "(BODY.PEEK[])")
                except imaplib.IMAP4.error:
                    continue
                raw = b""
                for part in msg_data:
                    if isinstance(part, tuple):
                        raw += part[1]
                if not raw:
                    continue
                full = email_lib.message_from_bytes(raw)
                html, text_body = _imap_body(full)
                text = re.sub(r"<[^>]+>", " ", html) if html else text_body
                code = _extract_adobe_otp(subject, text)
                if code:
                    lf(f"✓ 已收到 Adobe 验证码 {code}(IMAP)")
                    return code
                lf(f"读到 Adobe 邮件但未找到验证码(IMAP): { _brief_mail_text(subject) }")
        return None

    def _scan_once(email: str, token: str, seen: set[str]) -> str | None:
        found = _scan_graph(token, seen)
        if found:
            return found
        try:
            return _scan_imap(email, seen)
        except Exception as exc:  # noqa: BLE001
            lf(f"IMAP 收码失败:{str(exc)[:120]}")
            _close_imap()
            return None

    def poll(
        email: str,
        timeout: int | None = None,
        interval: int = 2,
        base_url: str = "",
    ) -> str:
        del base_url
        wait_s = default_wait_s if timeout is None else max(25, int(timeout))
        deadline = time.time() + wait_s
        state["not_before_ts"] = time.time() - 15
        seen: set[str] = set()
        external_ignore_codes: set[str] = set()
        graph_ok = [True]
        scan_round = 0
        lf(f"收取 Adobe 验证码(邮件 {mail_mode},本轮 {wait_s}s)…")
        time.sleep(1)
        try:
            while time.time() < deadline:
                scan_round += 1
                elapsed = int(time.time() - (deadline - wait_s))
                if scan_round == 1 or scan_round % 5 == 0:
                    lf(f"扫描邮件(第 {scan_round} 次,已 {elapsed}s)…")
                found: str | None = None
                t0 = time.time()
                if (external_mail_url and prefer_external_mail) or external_from_refresh_token:
                    found = _scan_external_mail(
                        email,
                        ignore_codes=external_ignore_codes,
                        capture_baseline=scan_round == 1,
                    )
                elif graph_ok[0]:
                    try:
                        token = _ensure_graph_token()
                        if scan_round == 1:
                            lf("✓ Outlook token 就绪,读取邮件…")
                        found = _scan_once(email, token, seen)
                    except Exception as exc:  # noqa: BLE001
                        graph_ok[0] = False
                        lf(f"Graph 不可用,改 IMAP({str(exc)[:100]})")
                        try:
                            found = _scan_imap(email, seen)
                        except Exception as exc2:  # noqa: BLE001
                            lf(f"IMAP 收码失败:{str(exc2)[:120]}")
                            _close_imap()
                else:
                    try:
                        found = _scan_imap(email, seen)
                    except Exception as exc:  # noqa: BLE001
                        lf(f"IMAP 收码失败:{str(exc)[:120]}")
                        _close_imap()
                cost = time.time() - t0
                if cost > 3 and not found and scan_round <= 4:
                    lf(f"本轮 {cost:.1f}s,暂未发现验证码")
                if found:
                    return found
                sleep_s = interval if scan_round <= 8 else min(interval + 1, 4)
                time.sleep(sleep_s)
        finally:
            _close_imap()
            http.close()
        if (external_mail_url and prefer_external_mail) or external_from_refresh_token:
            raise RuntimeError("收取 Adobe 验证码超时(外部取信接口未取到)")
        raise RuntimeError("收取 Adobe 验证码超时(Graph/IMAP 均未取到)")

    return poll, holder
