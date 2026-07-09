from __future__ import annotations

"""独立版 Adobe Admin Console 成员协议(内置到本项目)。

1) 管理员登录,拿 Admin Console / JIL token
2) 拉成员:GET /jil-api/v2/organizations/{org_id}/users/
3) 添加/邀请成员:POST /users%3Abatch(同时分配产品=授权)
4) 删除成员:PATCH /users  body=[{"op":"remove","path":"/memberId"}]
"""

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from .http_client import HttpClient

IMS_HOST = "https://ims-na1.adobelogin.com"
IMS_BACKEND = "https://adobeid-na1.services.adobe.com"
AUTH_HOST = "https://auth.services.adobe.com"
JIL_BASE = "https://bps-il.adobe.io/jil-api/v2"

ONESIE_CLIENT_ID = "ONESIE1"
ADMIN_REDIRECT = "https://adminconsole.adobe.com/#old_hash=&from_ims=true"
ADMIN_SCOPE = (
    "openid,AdobeID,additional_info.projectedProductContext,read_organizations,"
    "read_members,read_countries_regions,additional_info.roles,adobeio_api,"
    "read_auth_src_domains,authSources.rwd,bis.read.pi,app_policies.read,"
    "app_policies.write,client.read,publisher.read,client.scopes.read,"
    "creative_cloud,service_principals.write,aps.read.app_merchandising,"
    "aps.eval_licensesforapps,ab.manage,aps.device_activation_mgmt,pps.read,"
    "ip_list_write_scope,ip_list_check_scope,jil.facs_role_read,"
    "jil.facs_role_write,ims_cai.orgPolicies.read,ims_cai.orgPolicies.write,"
    "security_profile.mfa_status.r"
)
AUTO = "auto"


class ProtocolError(RuntimeError):
    pass


def log(msg: str) -> None:
    try:
        print(time.strftime("%H:%M:%S"), msg, flush=True)
    except OSError:
        # In background/threaded workers stdout can become unavailable on Windows.
        # Logging must never break the Adobe protocol flow.
        pass


def parse_pair(line: str) -> tuple[str, str]:
    line = (line or "").strip()
    for sep in ("|", "----", ":"):
        if sep in line:
            a, b = line.split(sep, 1)
            return a.strip(), b.strip()
    raise ValueError("格式应为 email|password")


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.@-]+", "_", s)[:120]


def extract_token_from_obj(obj: Any) -> str:
    if isinstance(obj, str):
        return obj if obj.count(".") >= 2 else ""
    if isinstance(obj, dict):
        for k in ("tokenValue", "access_token", "accessToken", "token", "value", "ims_access_token"):
            v = obj.get(k)
            if isinstance(v, str) and v.count(".") >= 2:
                return v
        for v in obj.values():
            t = extract_token_from_obj(v)
            if t:
                return t
    if isinstance(obj, list):
        for v in obj:
            t = extract_token_from_obj(v)
            if t:
                return t
    return ""


def extract_otp_from_any(x: Any) -> str:
    if isinstance(x, dict):
        for k in ("otp", "code", "verifyCode", "verification_code", "data", "message", "text", "html"):
            if k in x:
                c = extract_otp_from_any(x[k])
                if c:
                    return c
        for v in x.values():
            c = extract_otp_from_any(v)
            if c:
                return c
    elif isinstance(x, list):
        for v in x:
            c = extract_otp_from_any(v)
            if c:
                return c
    else:
        m = re.search(r"(?<!\d)(\d{6})(?!\d)", str(x))
        return m.group(1) if m else ""
    return ""


def poll_otp(email: str, timeout: int = 120, interval: int = 4, base_url: str = "") -> str:
    """默认实现:从 OTP URL 轮询。本项目实际通过 Graph 收件,运行时会替换此函数。"""
    import os

    import requests

    base_url = base_url or os.environ.get("ADMIN_OTP_URL", "")
    if not base_url:
        raise ProtocolError("OTP URL is not configured")
    if "{email}" in base_url:
        url = base_url.format(email=email)
    elif base_url.endswith("email="):
        url = base_url + email
    elif "email=" not in base_url:
        sep = "&" if "?" in base_url else "?"
        url = f"{base_url}{sep}email={email}"
    else:
        url = base_url

    deadline = time.time() + timeout
    sess = requests.Session()
    sess.trust_env = False
    last = ""
    while time.time() < deadline:
        try:
            sep = "&" if "?" in url else "?"
            r = sess.get(f"{url}{sep}_t={int(time.time()*1000)}", timeout=15)
            last = r.text[:300]
            try:
                code = extract_otp_from_any(r.json())
            except Exception:
                code = extract_otp_from_any(r.text)
            if code:
                log(f"[otp] {email} code={code}")
                return code
        except Exception as e:
            log(f"[otp] poll error: {e}")
        time.sleep(interval)
    raise ProtocolError(f"OTP timeout for {email}, last={last[:200]!r}")


class AdminAuth:
    def __init__(
        self,
        client: HttpClient,
        client_id: str = ONESIE_CLIENT_ID,
        scope: str = ADMIN_SCOPE,
        redirect: str = ADMIN_REDIRECT,
    ):
        self.client = client
        self.client_id = client_id
        self.scope = scope
        self.redirect = redirect
        self.relay = ""
        self.ftrset = ""
        self.susi_token = ""
        self.debug_id = ""
        self.identity_verification_token = ""
        self.auth_state_encrypted = ""

    def _gen_debug_id(self) -> str:
        if not self.debug_id:
            self.debug_id = str(uuid.uuid4())
        return self.debug_id

    def headers(self) -> dict[str, str]:
        h = {
            "X-IMS-ClientId": self.client_id,
            "Content-Type": "application/json",
            "X-Debug-Id": self._gen_debug_id(),
        }
        if self.susi_token:
            h["Authorization"] = f"Bearer {self.susi_token}"
        if self.identity_verification_token:
            h["X-Identity-Verification-Token"] = self.identity_verification_token
        if self.auth_state_encrypted:
            h["X-IMS-Authentication-State-Encrypted"] = self.auth_state_encrypted
        return h

    def authorize(self, email: str, locale: str = "en_US") -> None:
        try:
            self.client.get(
                "https://adminconsole.adobe.com/",
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                },
                allow_redirects=True,
                timeout=30,
            )
        except Exception:
            pass
        redirect_uri = f"{self.redirect}?client_id={self.client_id}&api=authorize&scope={self.scope}"
        params = {
            "client_id": self.client_id,
            "scope": self.scope,
            "response_type": "token",
            "redirect_uri": redirect_uri,
            "puser": email,
            "locale": locale,
            "flow_type": "token",
            "idp_flow_type": "login",
            "code_challenge_method": "plain",
            "use_ms_for_expiry": "true",
        }
        r = self.client.get(
            f"{IMS_HOST}/ims/authorize/v1?{urlencode(params)}",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-site",
            },
            allow_redirects=False,
            timeout=30,
        )
        self.relay = self.client.cookies.get("relay", "") or self.client.session.cookies.get("relay", "")
        self.ftrset = self.client.cookies.get("ftrset", "") or self.client.session.cookies.get("ftrset", "")
        self.debug_id = self.relay or self.debug_id
        log(f"[login] authorize status={r.status_code} relay={bool(self.relay)}")

    def accounts_probe(self, email: str) -> None:
        r = self.client.post(f"{AUTH_HOST}/signin/v2/users/accounts", headers=self.headers(), json={"email": email}, timeout=20)
        self.auth_state_encrypted = r.headers.get("x-ims-authentication-state-encrypted", self.auth_state_encrypted)
        self.identity_verification_token = r.headers.get("x-identity-verification-token", self.identity_verification_token)
        log(f"[login] accounts status={r.status_code} body={r.text[:160]}")

    def password_susi(self, email: str, password: str) -> bool:
        r = self.client.post(
            f"{AUTH_HOST}/signin/v2/tokens?credential=password",
            headers=self.headers(),
            json={"email": email, "password": password, "accountType": "individual"},
            timeout=25,
        )
        if r.status_code == 200:
            try:
                token = (r.json() or {}).get("token") or (r.json() or {}).get("access_token") or ""
            except Exception:
                token = ""
            if token:
                self.susi_token = token
                log("[login] password SUSI ok")
                return True
        log(f"[login] password failed status={r.status_code} body={r.text[:500]}")
        return False

    def start_email_mfa(self, email: str) -> bool:
        r = self.client.post(
            f"{AUTH_HOST}/signin/v2/authenticationstate?purpose=multiFactorAuthentication",
            headers=self.headers(),
            json={
                "extraPbaChecks": False,
                "pbaPolicy": None,
                "username": email,
                "usernameType": "EMAIL",
                "accountType": "individual",
                "deviceInfo": {"lsId": str(uuid.uuid4()), "hdId": None},
            },
            timeout=15,
        )
        if r.status_code in (200, 201):
            self.identity_verification_token = r.headers.get("x-identity-verification-token", self.identity_verification_token)
            self.auth_state_encrypted = r.headers.get("x-ims-authentication-state-encrypted", self.auth_state_encrypted)
            return True
        log(f"[mfa] start failed status={r.status_code} body={r.text[:300]}")
        return False

    def send_email_challenge(self) -> bool:
        if not self.identity_verification_token:
            return False
        r = self.client.post(
            f"{AUTH_HOST}/signin/v3/challenges?purpose=multiFactorAuthentication&factor=email&extendedAuthState=false",
            headers=self.headers(),
            json={},
            timeout=15,
        )
        if r.status_code == 200:
            self.auth_state_encrypted = r.headers.get("x-ims-authentication-state-encrypted", self.auth_state_encrypted)
            return True
        log(f"[mfa] send failed status={r.status_code} body={r.text[:300]}")
        return False

    def verify_email_challenge(self, code: str) -> bool:
        r = self.client.put(
            f"{AUTH_HOST}/signin/v3/challenges?purpose=multiFactorAuthentication",
            headers=self.headers(),
            json={"code": str(code)},
            timeout=15,
        )
        if r.status_code == 200:
            self.auth_state_encrypted = r.headers.get("x-ims-authentication-state-encrypted", self.auth_state_encrypted)
            return True
        log(f"[mfa] verify failed status={r.status_code} body={r.text[:300]}")
        return False

    def try_email_mfa(self, email: str, otp_timeout: int, otp_url: str = "") -> bool:
        if not self.start_email_mfa(email):
            return False
        try:
            r = self.client.get(f"{AUTH_HOST}/signin/v3/challenges?purpose=multiFactorAuthentication", headers=self.headers(), timeout=15)
            self.auth_state_encrypted = r.headers.get("x-ims-authentication-state-encrypted", self.auth_state_encrypted)
            self.identity_verification_token = r.headers.get("x-identity-verification-token", self.identity_verification_token)
        except Exception:
            pass
        if not self.send_email_challenge():
            return False
        return self.verify_email_challenge(poll_otp(email, timeout=otp_timeout, base_url=otp_url))

    def filter_profile_mapping(self, prefer_forward: bool = True) -> bool:
        user_id = get_user_id_from_jwt(self.susi_token)
        if not user_id:
            return False
        filter_val = '{"preferForwardProfile": true};' if prefer_forward else '{"searchEntireCluster":true}; isAA()'
        r = self.client.put(
            f"{AUTH_HOST}/signin/v1/filterprofilemapping",
            headers=self.headers(),
            json={"filter": filter_val, "guid": user_id},
            timeout=10,
        )
        return r.status_code == 200

    def get_admin_access_token(self, debug_dir: Path | None = None) -> str:
        try:
            self.filter_profile_mapping(prefer_forward=True)
        except Exception:
            pass
        r = self.client.post(
            f"{AUTH_HOST}/signin/v1/ims/tokens",
            headers=self.headers(),
            json={"rememberMe": True, "reauthenticate": None},
            timeout=25,
        )
        token = ""
        try:
            data = r.json()
            token = extract_token_from_obj(data)
            if token:
                self.susi_token = token
        except Exception:
            data = r.text[:1000]
        log(f"[token] ims/tokens status={r.status_code} token={bool(token)}")
        fs = self.from_susi_token(debug_dir)
        if fs:
            return fs
        if token:
            return token
        raise ProtocolError(f"failed get token: {str(data)[:500]}")

    def from_susi_token(self, debug_dir: Path | None = None) -> str:
        callback = f"{IMS_HOST}/ims/adobeid/{self.client_id}/AdobeID/token?redirect_uri={self.redirect}&use_ms_for_expiry=true"
        form = {
            "remember_me": "true",
            "client_id": self.client_id,
            "scope": self.scope,
            "response_type": "token",
            "redirect_uri": self.redirect,
            "callback": callback,
            "relay": self.relay or self._gen_debug_id(),
            "locale": "en_US",
            "flow_type": "token",
            "idp_flow_type": "login",
            "s_p": "google,facebook,apple,microsoft,line,kakao",
            "use_ms_for_expiry": "true",
            "state": json.dumps({"ac": "adminconsole.adobe.com"}),
        }
        if self.susi_token:
            form["token"] = self.susi_token
        r = self.client.post(
            f"{IMS_BACKEND}/ims/fromSusi",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": AUTH_HOST,
                "Referer": f"{AUTH_HOST}/en_US/index.html",
            },
            data=urlencode(form),
            allow_redirects=False,
            timeout=25,
        )
        loc = r.headers.get("Location", "") or str(getattr(r, "url", "") or "")
        if not loc:
            m = re.search(r'url=([^"\'>\s]+)', r.text or "")
            if m:
                loc = m.group(1).replace("&amp;", "&")
        token = token_from_url_fragment(loc)
        log(f"[token] fromSusi status={r.status_code} token={bool(token)}")
        return token


def get_user_id_from_jwt(token: str) -> str:
    if not token or token.count(".") < 2:
        return ""
    try:
        import base64

        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(part.encode()).decode("utf-8", "ignore"))
        for k in ("user_id", "userId", "sub", "account_id", "accountId"):
            v = data.get(k)
            if isinstance(v, str) and v:
                return v
    except Exception:
        return ""
    return ""


def token_from_url_fragment(url: str) -> str:
    if not url:
        return ""
    p = urlparse(url)
    for part in (p.fragment, p.query, url):
        qs = parse_qs(part, keep_blank_values=True)
        for k in ("access_token", "token"):
            vals = qs.get(k)
            if vals and vals[0].count(".") >= 2:
                return vals[0]
        m = re.search(r"(?:access_token|token)=([^&#]+)", part)
        if m and m.group(1).count(".") >= 2:
            return m.group(1)
    return ""


def jil_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "x-api-key": ONESIE_CLIENT_ID,
        "x-include-roles": (
            "DEPLOYMENT_ADMIN,LICENSE_ADMIN,LICENSE_DEV_ADMIN,ORG_ADMIN,PRODUCT_ADMIN,"
            "PRODUCT_SUPPORT_ADMIN,STORAGE_ADMIN,SUPPORT_ADMIN,USER_GROUP_ADMIN,"
            "ADOBE_AGENT_ADMIN,ADOBE_AGENT_CUSTOMER_CARE,ADOBE_AGENT_PROFESSIONAL_SERVICES,"
            "ADOBE_AGENT_PROVISIONER,ADOBE_AGENT_READ,ADOBE_AGENT_RESELLER_LICENSING,CONTRACT_ADMIN"
        ),
        "x-jil-feature": "use_clam,pa_4280",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": "https://adminconsole.adobe.com",
        "Referer": "https://adminconsole.adobe.com/",
        "Accept-Language": "en_US",
    }


def login_admin(
    admin_line: str,
    proxy: str = "",
    locale: str = "en_US",
    otp_timeout: int = 120,
    debug_dir: Path | None = None,
    otp_url: str = "",
) -> str:
    email, password = parse_pair(admin_line)
    client = HttpClient(proxy=proxy)
    try:
        auth = AdminAuth(client)
        auth.authorize(email, locale)
        auth.accounts_probe(email)
        if not auth.password_susi(email, password):
            if auth.try_email_mfa(email, otp_timeout, otp_url=otp_url):
                if not auth.password_susi(email, password):
                    raise ProtocolError("admin password SUSI failed after MFA")
            else:
                raise ProtocolError("admin password SUSI failed")
        return auth.get_admin_access_token(debug_dir)
    finally:
        try:
            client.close()
        except Exception:
            pass


def get_organizations(client: HttpClient, token: str) -> list[dict[str, Any]]:
    r = client.get(f"{JIL_BASE}/organizations", headers=jil_headers(token), params={"include": "delegation_groups_migration_status,renga_tags,rso_values"}, timeout=20)
    if r.status_code != 200:
        raise ProtocolError(f"organizations failed {r.status_code}: {r.text[:800]}")
    data = r.json()
    items = data.get("items") or data.get("organizations") or data.get("list") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise ProtocolError(f"no organizations: {str(data)[:500]}")
    return items


def choose_org(orgs: list[dict[str, Any]]) -> dict[str, Any]:
    def score(o: dict[str, Any]) -> int:
        txt = json.dumps(o, ensure_ascii=False)
        return (100 if "ORG_ADMIN" in txt or "org_admin" in txt else 0) + (10 if str(o.get("type", "")).upper() in ("TEAM", "ENTERPRISE") else 0) + (1 if o.get("id") else 0)

    return sorted(orgs, key=score, reverse=True)[0]


def get_products(client: HttpClient, token: str, org_id: str) -> list[dict[str, Any]]:
    r = client.get(
        f"{JIL_BASE}/organizations/{org_id}/products/",
        headers=jil_headers(token),
        params={
            "include_created_date": "true",
            "include_expired": "true",
            "include_groups_quantity": "true",
            "include_inactive": "false",
            "include_license_activations": "true",
            "include_license_allocation_info": "false",
            "includeAcquiredOfferIds": "false",
            "includeConfiguredProductArrangementId": "false",
            "includeLegacyLSFields": "false",
            "license_group_limit": "100",
            "processing_instruction_codes": "administration,license_data",
        },
        timeout=25,
    )
    if r.status_code != 200:
        raise ProtocolError(f"products failed {r.status_code}: {r.text[:800]}")
    data = r.json()
    items = data.get("items") or data.get("products") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise ProtocolError(f"no products: {str(data)[:500]}")
    return items


def choose_product(products: list[dict[str, Any]]) -> tuple[str, str, dict[str, Any]]:
    candidates = []
    for p in products:
        lgs = p.get("licenseGroupSummaries") or p.get("licenseGroups") or []
        if not lgs:
            continue
        assigned = int(p.get("assignedQuantity") or 0)
        total = 0
        for q in p.get("licenseQuantities") or []:
            try:
                total += int(q.get("quantity") or 0)
            except Exception:
                pass
        name = f"{p.get('shortName','')} {p.get('longName','')} {p.get('code','')}"
        score = max(total - assigned, 0) + (1000 if "Creative Cloud" in name or p.get("code") == "CCLE" else 0)
        candidates.append((score, p, lgs[0]))
    if not candidates:
        raise ProtocolError("no product with license group found")
    _, p, lg = sorted(candidates, key=lambda x: x[0], reverse=True)[0]
    return str(p["id"]), str(lg["id"]), p


def product_assignments(products: list[dict[str, Any]]) -> list[dict[str, Any]]:
    assignments: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for p in products:
        pid = str(p.get("id") or "").strip()
        if not pid:
            continue
        lgs = p.get("licenseGroupSummaries") or p.get("licenseGroups") or []
        if not lgs:
            continue
        lgid = str((lgs[0] or {}).get("id") or "").strip()
        if not lgid or (pid, lgid) in seen:
            continue
        seen.add((pid, lgid))
        pname = (
            p.get("longName") or p.get("shortName") or p.get("code") or pid
        )
        assignments.append({
            "product_id": pid,
            "license_group_id": lgid,
            "product_name": str(pname).strip(),
        })
    return assignments


def discover_org_product(client: HttpClient, token: str, org_id: str = AUTO, product_id: str = AUTO, license_group_id: str = AUTO) -> dict[str, Any]:
    org_info: dict[str, Any] = {}
    if not org_id or org_id == AUTO:
        org_info = choose_org(get_organizations(client, token))
        org_id = str(org_info.get("id") or org_info.get("orgId") or "")
    if not product_id or product_id == AUTO or not license_group_id or license_group_id == AUTO:
        pid, lgid, pinfo = choose_product(get_products(client, token, org_id))
        if not product_id or product_id == AUTO:
            product_id = pid
        if not license_group_id or license_group_id == AUTO:
            license_group_id = lgid
    return {"org_id": org_id, "product_id": product_id, "license_group_id": license_group_id, "org_info": org_info}


def available_types(client: HttpClient, token: str, org_id: str, email: str) -> list[dict[str, Any]]:
    r = client.post(f"{JIL_BASE}/organizations/{org_id}/search/available-types", headers=jil_headers(token), json={"email": email}, timeout=25)
    if r.status_code not in (200, 201):
        raise ProtocolError(f"available-types failed {r.status_code}: {r.text[:500]}")
    return r.json()


def add_member(
    client: HttpClient,
    token: str,
    org_id: str,
    email: str,
    product_id: str,
    license_group_id: str,
    first_name: str = "",
    last_name: str = "",
    product_assignments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    types = available_types(client, token, org_id, email)
    if not next((x for x in types if x.get("userType") == "TYPE2E" and x.get("allowed")), None):
        raise ProtocolError(f"TYPE2E not allowed for {email}: {types}")
    assignments = product_assignments or [{
        "product_id": product_id,
        "license_group_id": license_group_id,
    }]
    products = [
        {
            "id": item["product_id"],
            "licenseGroups": [{"id": item["license_group_id"]}],
        }
        for item in assignments
        if item.get("product_id") and item.get("license_group_id")
    ]
    if not products:
        raise ProtocolError("no product assignments available")
    payload: list[dict[str, Any]] = [{
        "email": email,
        "type": "TYPE2E",
        "products": products,
        "roles": [],
        "userGroups": [],
    }]
    if first_name:
        payload[0]["firstName"] = first_name
    if last_name:
        payload[0]["lastName"] = last_name
    r = client.post(f"{JIL_BASE}/organizations/{org_id}/users%3Abatch", headers=jil_headers(token), json=payload, timeout=40)
    out: dict[str, Any] = {"status": r.status_code, "request": payload, "text": (r.text or "")[:4000]}
    try:
        out["json"] = r.json()
    except Exception:
        pass
    if r.status_code not in (200, 201, 202, 204, 207):
        raise ProtocolError(f"users:batch failed {r.status_code}: {r.text[:800]}")
    if r.status_code == 207 and isinstance(out.get("json"), list):
        bad = [x for x in out["json"] if int((x or {}).get("responseCode") or 0) >= 400]
        if bad:
            raise ProtocolError(f"users:batch partial error: {json.dumps(bad, ensure_ascii=False)[:1000]}")
    return out


def json_items(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("items", "users", "members", "list", "data"):
            if isinstance(data.get(k), list):
                return data[k]
    return []


def extract_email(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    candidates = [item.get("email"), item.get("emailAddress"), item.get("userEmail"), item.get("username"), item.get("userName"), item.get("id")]
    for k in ("profile", "user"):
        obj = item.get(k)
        if isinstance(obj, dict):
            candidates += [obj.get("email"), obj.get("emailAddress"), obj.get("userEmail"), obj.get("username"), obj.get("userName")]
    for v in candidates:
        if isinstance(v, str):
            m = re.search(r"[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}", v)
            if m:
                return m.group(0).lower()
    m = re.search(r"[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}", json.dumps(item, ensure_ascii=False))
    return m.group(0).lower() if m else ""


def member_id(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    for k in ("id", "userId", "memberId", "principalId", "imsUserId"):
        v = item.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for k in ("user", "profile"):
        obj = item.get(k)
        if isinstance(obj, dict):
            for kk in ("id", "userId", "memberId", "principalId", "imsUserId"):
                v = obj.get(kk)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return ""


def list_members(client: HttpClient, token: str, org_id: str, pages: int = 20, page_size: int = 100, search: str = "") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for page in range(max(1, pages)):
        params = {
            "filter_exclude_domain": "techacct.adobe.com",
            "page": page,
            "page_size": page_size,
            "sort": "FNAME_LNAME",
            "sort_order": "ASC",
            "currentPage": page + 1,
        }
        if search:
            params["search_query"] = search
            params["filterQuery"] = search
        r = client.get(f"{JIL_BASE}/organizations/{org_id}/users/?{urlencode(params)}", headers=jil_headers(token), timeout=25)
        if r.status_code >= 400:
            raise ProtocolError(f"list users failed {r.status_code}: {r.text[:800]}")
        items = json_items(r.json())
        for it in items:
            out.append({"email": extract_email(it), "member_id": member_id(it), "raw": it})
        if search or len(items) < page_size:
            break
    return out


def find_member_id_by_email(client: HttpClient, token: str, org_id: str, email: str) -> str:
    target = email.lower().strip()
    for m in list_members(client, token, org_id, pages=1, page_size=20, search=email):
        if m.get("email") == target and m.get("member_id"):
            return str(m["member_id"])
    return ""


def patch_json(client: HttpClient, url: str, headers: dict[str, str], body: Any, timeout: int = 40) -> Any:
    h = client._base_headers() if hasattr(client, "_base_headers") else {}
    h.update(headers)
    h.setdefault("Content-Type", "application/json")
    resp = client.session.patch(url, headers=h, json=body, timeout=timeout)
    if hasattr(client, "_merge_cookies_from_resp"):
        client._merge_cookies_from_resp(resp)
    return resp


def remove_members(client: HttpClient, token: str, org_id: str, member_ids: list[str]) -> dict[str, Any]:
    ids = [x.strip() for x in member_ids if x and x.strip()]
    if not ids:
        raise ProtocolError("member_ids empty")
    ops = [{"op": "remove", "path": f"/{mid}"} for mid in ids]
    r = patch_json(client, f"{JIL_BASE}/organizations/{org_id}/users", jil_headers(token), ops, timeout=45)
    out: dict[str, Any] = {"ok": r.status_code in (200, 202, 204, 207), "status": r.status_code, "request": ops, "text": (r.text or "")[:4000]}
    try:
        out["json"] = r.json()
        if r.status_code == 207 and isinstance(out["json"], list):
            out["ok"] = all(int((x or {}).get("responseCode") or 500) < 400 for x in out["json"])
    except Exception:
        pass
    return out


def client_from_state(st: dict[str, Any], proxy: str = "") -> HttpClient:
    return HttpClient(proxy=proxy or st.get("proxy", ""))
