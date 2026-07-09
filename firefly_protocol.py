"""子账号(Firefly / clio-playground-web)登录与额度查询(纯 API,best-effort)。

复用管理登录里的免密码/验证码流程,但使用 clio-playground-web 客户端拿到
firefly 域的 access_token + 会话 cookie,再查询 credits,组装 newbanana 字段。
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Callable, Optional
from urllib.parse import urlencode

import adobe_admin as _adm
from adobe_otp import make_otp_poller
from adobe_protocol import admin_member_protocol as _p
from adobe_protocol.admin_member_protocol import AdminAuth

try:
    from curl_cffi import requests as _cffi
    _HAS_CFFI = True
    from adobe_protocol.http_client import IMPERSONATE_TARGET
except ImportError:  # pragma: no cover
    import requests as _cffi  # type: ignore
    _HAS_CFFI = False
    IMPERSONATE_TARGET = "chrome124"

LogFn = Callable[[str], None]

CLIO_CLIENT_ID = "clio-playground-web"
FIREFLY_REDIRECT = "https://firefly.adobe.com/"
FIREFLY_SCOPE = (
    "AdobeID,firefly_api,openid,pps.read,pps.write,"
    "additional_info.projectedProductContext,additional_info.ownerOrg,"
    "uds_read,uds_write,ab.manage,read_organizations,"
    "additional_info.roles,account_cluster.read,creative_production"
)

IMS_CHECK_URL = (
    "https://adobeid-na1.services.adobe.com/ims/check/v6/token"
    "?jslVersion=v2-v0.48.0-1-g1e322cb"
)
IMS_PROFILE_URL = "https://ims-na1.adobelogin.com/ims/profile/v1"
CREDITS_URL = "https://firefly.adobe.io/v1/credits/balance"
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
)


def _mklog(log: Optional[LogFn]) -> LogFn:
    return log if callable(log) else (lambda _m: None)


def _proxies(proxy_url: str) -> dict | None:
    return {"http": proxy_url, "https": proxy_url} if proxy_url else None


def _new_session(proxy_url: str = ""):
    if _HAS_CFFI:
        return _cffi.Session(
            timeout=30, proxies=_proxies(proxy_url), verify=False,
            impersonate=IMPERSONATE_TARGET,
        )
    s = _cffi.Session()
    if proxy_url:
        s.proxies = _proxies(proxy_url)
    return s


def _decode_jwt(token: str) -> dict:
    if not token or "." not in token:
        return {}
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part.encode()))
    except Exception:
        return {}


def extract_jwt_expiry(token: str) -> int | None:
    claims = _decode_jwt(token)
    if not claims:
        return None
    if isinstance(claims.get("exp"), (int, float)):
        return int(claims["exp"])
    try:
        created = int(str(claims.get("created_at")))
        expires_in = int(str(claims.get("expires_in")))
        if created > 10_000_000_000:
            created //= 1000
        if expires_in > 86400 * 2:
            expires_in //= 1000
        return created + expires_in
    except Exception:
        return None


def extract_account_id(token: str) -> str:
    claims = _decode_jwt(token)
    for k in ("user_id", "aa_id", "sub"):
        v = claims.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def fetch_account_info(token: str, proxy_url: str = "") -> dict:
    if not token:
        return {}
    sess = _new_session(proxy_url)
    try:
        r = sess.get(
            IMS_PROFILE_URL,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        if r.status_code != 200:
            return {}
        data = r.json()
        return {
            "display_name": data.get("displayName") or "",
            "email": data.get("email") or "",
            "user_id": data.get("userId") or "",
        }
    except Exception:
        return {}
    finally:
        try:
            sess.close()
        except Exception:
            pass


def fetch_credits(token: str, account_id: str = "", proxy_url: str = "") -> float | None:
    """返回额度;None 表示查询失败(区分于余额为 0)。"""
    if not token:
        return None
    if not account_id:
        account_id = extract_account_id(token)
    if not account_id:
        return None
    sess = _new_session(proxy_url)
    try:
        r = sess.get(
            CREDITS_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "x-api-key": CLIO_CLIENT_ID,
                "x-account-id": account_id,
                "Accept": "application/json",
            },
        )
        if r.status_code != 200:
            return None
        data = r.json()
        quota = (data.get("total") or {}).get("quota") or {}
        if isinstance(quota.get("available"), (int, float)):
            return float(quota["available"])
        if isinstance(data.get("balance"), (int, float)):
            return float(data["balance"])
        return 0.0
    except Exception:
        return None
    finally:
        try:
            sess.close()
        except Exception:
            pass


def _complete_sub_account_with_retry(auth: "AdminAuth", email: str, lf: LogFn) -> None:
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            if attempt > 1:
                lf(f"第 {attempt}/3 次重试补全账号资料…")
            _adm.complete_sub_account(auth, email, lf, strict=True)
            return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            lf(f"补全/切换企业资料失败，第 {attempt}/3 次：{exc}")
            if attempt < 3:
                time.sleep(2 * attempt)
    raise _adm.AdminError(f"补全账号资料重试失败:{last_error}")


def _acquire_firefly_token(auth: "AdminAuth", lf: LogFn) -> str:
    """用已登录会话换取 clio/firefly 的正式 access_token。"""
    try:
        r = auth.client.post(
            f"{_p.AUTH_HOST}/signin/v1/ims/tokens",
            headers=auth.headers(),
            json={"rememberMe": True, "reauthenticate": None}, timeout=25,
        )
        tok = _p.extract_token_from_obj(r.json())
        if tok:
            auth.susi_token = tok
    except Exception:
        pass
    try:
        auth.from_susi_token(None)
    except Exception as e:
        lf(f"fromSusi 预热:{e}")

    r = auth.client.post(
        f"{_p.IMS_BACKEND}/ims/check/v6/token?jslVersion=v2-v0.48.0-1-g1e322cb",
        headers={
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "client_id": CLIO_CLIENT_ID,
            "Origin": "https://firefly.adobe.com",
            "Referer": "https://firefly.adobe.com/",
        },
        data=urlencode({
            "client_id": CLIO_CLIENT_ID,
            "guest_allowed": "true",
            "scope": FIREFLY_SCOPE,
        }),
        timeout=25,
    )
    try:
        data = r.json() if isinstance(r.json(), dict) else {}
    except Exception:
        data = {}
    tok = data.get("access_token") if isinstance(data, dict) else ""
    if r.status_code == 200 and tok:
        lf("✓ 子号 firefly token 获取成功")
        return tok
    raise _adm.AdminError(
        f"firefly check/v6/token 未返回 token status={r.status_code} "
        f"{(r.text or '')[:160]}"
    )


def register_account(
    *, email: str, refresh_token: str, client_id: str,
    mail_url: str = "", proxy_url: str = "", otp_timeout: int = 180,
    log: Optional[LogFn] = None,
) -> dict[str, Any]:
    """子账号自助登录(免密码验证码)→ 拿 firefly token + cookie + credits。

    返回 newbanana 记录:{access_token, cookie, credits, expires_at, display_name, user_id}。
    """
    lf = _mklog(log)
    if not ((refresh_token and client_id) or mail_url):
        raise _adm.AdminError("子号缺少 Refresh Token / Client ID 或取信配置,无法收验证码登录")

    # 显式传入收码器(不改全局),保证并发拉号时各子号互不干扰
    poller, holder = make_otp_poller(
        refresh_token=refresh_token, client_id=client_id,
        mail_url=mail_url, proxy_url=proxy_url, timeout=otp_timeout,
        use_proxy_for_mail=True, log=lf,
    )
    client = _p.HttpClient(proxy=proxy_url)
    try:
        auth = AdminAuth(
            client, client_id=CLIO_CLIENT_ID, scope=FIREFLY_SCOPE,
            redirect=FIREFLY_REDIRECT,
        )
        auth.authorize(email, "en_US")
        methods = _adm._probe_auth_methods(auth, email)
        lf(f"子号 {email} 认证方式:{', '.join(methods) if methods else '无(免密码)'}")
        # 子号(被邀请的 TYPE2E)通常是免密码账号,用验证码登录
        _adm._passwordless_login(auth, email, lf, poll=poller, otp_timeout=otp_timeout)
        # 首次登录的被邀请号需补全账号(姓名/密码/生日)并激活企业资料
        _complete_sub_account_with_retry(auth, email, lf)
        token = _acquire_firefly_token(auth, lf)
        cookie = _adm._session_cookie_str(client)

        info = fetch_account_info(token, proxy_url) or {}
        user_id = info.get("user_id") or extract_account_id(token)
        credits = fetch_credits(token, user_id, proxy_url)
        expires_at = extract_jwt_expiry(token)

        return {
            "access_token": token,
            "cookie": cookie,
            "credits": credits,
            "expires_at": expires_at,
            "display_name": info.get("display_name") or "",
            "user_id": user_id,
            "rotated_refresh_token": holder.refresh_token if holder.rotated else "",
        }
    finally:
        try:
            client.close()
        except Exception:
            pass
