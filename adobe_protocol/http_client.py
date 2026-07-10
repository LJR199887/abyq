from __future__ import annotations

"""Adobe IMS / JIL 请求用的最小 HTTP 客户端。

优先使用 curl_cffi 的 Chrome TLS 指纹(否则 Adobe IMS 很容易拦截请求);
未安装时回退到普通 requests。
"""

import random
import uuid

try:
    from curl_cffi import requests as _requests

    _HAS_CURL_CFFI = True
except ImportError:  # 没装 curl_cffi 时回退
    import requests as _requests

    _HAS_CURL_CFFI = False

CHROME_VERSIONS = ["136.0.0.0", "131.0.0.0"]
UA_TEMPLATES = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v} Safari/537.36",
]
LOCALE_POOL = ["en-US", "en-CA", "en-GB", "en-AU"]


def _pick_impersonate() -> str:
    """选当前已安装 curl_cffi 支持的最新 Chrome 指纹目标。

    不同版本的 curl_cffi 支持的目标不同(如 0.7.4 仅到 chrome124),
    硬编码 chrome131/136 会直接报 "Impersonating ... is not supported"。
    """
    if not _HAS_CURL_CFFI:
        return "chrome124"
    try:
        from curl_cffi.requests import BrowserType

        vals = [b.value for b in BrowserType]
    except Exception:
        return "chrome124"
    chromes = sorted(
        (v for v in vals if v.startswith("chrome") and v[len("chrome"):].isdigit()),
        key=lambda v: int(v[len("chrome"):]),
        reverse=True,
    )
    return chromes[0] if chromes else (vals[0] if vals else "chrome124")


# 进程启动时算一次:当前环境支持的最佳 Chrome 指纹
IMPERSONATE_TARGET = _pick_impersonate()


def normalize_proxy(proxy: str) -> str:
    proxy = (proxy or "").strip()
    if proxy.startswith("socks5://"):
        return proxy.replace("socks5://", "socks5h://", 1)
    return proxy


class HttpClient:
    def __init__(self, proxy: str = ""):
        ver = random.choice(CHROME_VERSIONS)
        self.user_agent = random.choice(UA_TEMPLATES).format(v=ver)
        self.locale = random.choice(LOCALE_POOL)
        self.accept_language = f"{self.locale},en;q=0.9"
        self.proxy = proxy
        self.cookies: dict[str, str] = {}
        self.session_id = str(uuid.uuid4())
        self._chrome_major = ver.split(".")[0]
        self._sec_ch_ua = (
            f'"Chromium";v="{self._chrome_major}", '
            f'"Google Chrome";v="{self._chrome_major}", "Not/A)Brand";v="99"'
        )
        self._sec_ch_ua_mobile = "?0"
        self._sec_ch_ua_platform = '"Windows"'
        p = normalize_proxy(proxy)
        if _HAS_CURL_CFFI:
            try:
                self.session = _requests.Session(impersonate=IMPERSONATE_TARGET)
            except Exception:
                self.session = _requests.Session()
        else:
            self.session = _requests.Session()
        if p:
            self.session.proxies = {"https": p, "http": p}

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass

    def _base_headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept-Language": self.accept_language,
            "Accept": "application/json, text/plain, */*",
            "sec-ch-ua": self._sec_ch_ua,
            "sec-ch-ua-mobile": self._sec_ch_ua_mobile,
            "sec-ch-ua-platform": self._sec_ch_ua_platform,
        }

    def _merge_cookies_from_resp(self, resp) -> None:
        try:
            for key, val in resp.cookies.items():
                self.cookies[key] = val
        except Exception:
            pass

    def get(self, url: str, headers: dict | None = None, allow_redirects=True, **kwargs):
        h = self._base_headers()
        if headers:
            h.update(headers)
        resp = self.session.get(
            url, headers=h, allow_redirects=allow_redirects,
            timeout=kwargs.pop("timeout", 30), **kwargs,
        )
        self._merge_cookies_from_resp(resp)
        return resp

    def post(self, url: str, headers: dict | None = None, json=None, data=None,
             allow_redirects=True, **kwargs):
        h = self._base_headers()
        if json is not None:
            h.setdefault("Content-Type", "application/json")
        if headers:
            h.update(headers)
        resp = self.session.post(
            url, headers=h, json=json, data=data, allow_redirects=allow_redirects,
            timeout=kwargs.pop("timeout", 30), **kwargs,
        )
        self._merge_cookies_from_resp(resp)
        return resp

    def put(self, url: str, headers: dict | None = None, json=None, **kwargs):
        h = self._base_headers()
        if json is not None:
            h.setdefault("Content-Type", "application/json")
        if headers:
            h.update(headers)
        resp = self.session.put(
            url, headers=h, json=json, timeout=kwargs.pop("timeout", 30), **kwargs,
        )
        self._merge_cookies_from_resp(resp)
        return resp
