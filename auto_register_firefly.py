"""
Adobe Firefly 自动注册 (直接注册模式)
==================================
1. 直接打开 Adobe 注册页面填写邮箱密码
2. 完成注册 + 验证码
3. 注册完成后导出 Cookie
"""

import asyncio
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime
from urllib.parse import unquote, urlsplit

# 全局配置控制台输出，解决Windows GBK编码闪退问题
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import httpx
from playwright.async_api import (
    async_playwright, Page, BrowserContext,
    TimeoutError as PlaywrightTimeout,
)

# ════════════════════════ 配置 ════════════════════════

API_KEY = os.getenv("API_KEY", "")
API_BASE = os.getenv("API_BASE", "https://rossa.cfd/api")
EMAIL_DOMAIN = os.getenv("EMAIL_DOMAIN", "rossa.cfd")
YESCAPTCHA_KEY = os.getenv("YESCAPTCHA_KEY", "")
EMAIL_SOURCE = os.getenv("EMAIL_SOURCE", "temp")
SELF_EMAIL_ADDRESS = os.getenv("SELF_EMAIL_ADDRESS", "")
SELF_EMAIL_API_URL = os.getenv("SELF_EMAIL_API_URL", "")
SHOW_BROWSER = os.getenv("SHOW_BROWSER", "0") == "1"
PROXY_ENABLED = os.getenv("PROXY_ENABLED", "0") == "1"
PROXY_SCHEME = os.getenv("PROXY_SCHEME", "http")
PROXY_URL = os.getenv("PROXY_URL", "")
API_PROXY_ENABLED = os.getenv("API_PROXY_ENABLED", "0") == "1"
DATA_DIR = os.getenv("DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.getenv("CONFIG_FILE", os.path.join(DATA_DIR, "config.json"))
BROWSER_LAUNCH_TIMEOUT_SECONDS = max(30, int(os.getenv("BROWSER_LAUNCH_TIMEOUT_SECONDS", "90")))
USER_DATA_DIR = os.getenv("USER_DATA_DIR", "")
SIGNUP_GOTO_TIMEOUT_MS = max(10000, int(os.getenv("SIGNUP_GOTO_TIMEOUT_MS", "50000")))

import random
import string
import base64

def normalize_proxy(proxy_url: str, proxy_scheme: str = "http") -> dict | None:
    raw = (proxy_url or "").strip()
    if not raw:
        return None

    scheme = (proxy_scheme or "http").strip().lower()
    if scheme not in ("http", "https", "socks5"):
        scheme = "http"
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
        raise ValueError("代理格式错误，请参考设置页示例填写")

    auth = f"{username}:{password}@" if username or password else ""
    return {
        "scheme": scheme,
        "host": host,
        "port": int(port),
        "username": username,
        "password": password,
        "server": f"{scheme}://{host}:{port}",
        "url": f"{scheme}://{auth}{host}:{port}",
    }

def get_proxy_config() -> dict | None:
    if not PROXY_ENABLED:
        return None
    return normalize_proxy(PROXY_URL, PROXY_SCHEME)

def build_playwright_proxy() -> dict | None:
    proxy = get_proxy_config()
    if not proxy:
        return None
    data = {"server": proxy["server"]}
    if proxy["username"] or proxy["password"]:
        data["username"] = proxy["username"]
        data["password"] = proxy["password"]
    return data

def build_api_httpx_proxy_kwargs() -> dict:
    if not API_PROXY_ENABLED:
        return {}
    proxy = get_proxy_config()
    if not proxy:
        return {}
    if proxy["scheme"] == "socks5":
        try:
            import socksio  # noqa: F401
        except Exception:
            return {}
    return {"proxy": proxy["url"]}

def open_url_with_proxy(request, timeout=60):
    import urllib.request
    if not API_PROXY_ENABLED:
        return urllib.request.urlopen(request, timeout=timeout)
    proxy = get_proxy_config()
    if not proxy or proxy["scheme"] == "socks5":
        return urllib.request.urlopen(request, timeout=timeout)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy["url"], "https": proxy["url"]})
    )
    return opener.open(request, timeout=timeout)

def random_string(length):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def random_password(length=14):
    """生成包含大小写字母、数字、符号的随机密码"""
    upper = random.choices(string.ascii_uppercase, k=3)
    lower = random.choices(string.ascii_lowercase, k=4)
    digits = random.choices(string.digits, k=3)
    symbols = random.choices('!@#$%&*', k=2)
    rest = random.choices(string.ascii_letters + string.digits, k=length - 12)
    pwd = upper + lower + digits + symbols + rest
    random.shuffle(pwd)
    return ''.join(pwd)

PASSWORD = os.getenv("PASSWORD", random_password())
FIRST_NAME = os.getenv("FIRST_NAME", random_string(6).capitalize())
LAST_NAME = os.getenv("LAST_NAME", random_string(5).capitalize())
BIRTH_YEAR = os.getenv("BIRTH_YEAR", str(random.randint(1990, 2000)))
BIRTH_MONTH = os.getenv("BIRTH_MONTH", str(random.randint(1, 12)))
SCREENSHOT_DIR = os.getenv("SCREENSHOT_DIR", os.path.join(DATA_DIR, "screenshots"))
os.makedirs(SCREENSHOT_DIR, exist_ok=True)


# ════════════════════════ 浏览器指纹随机化 ════════════════════════

def generate_fingerprint() -> dict:
    """
    生成随机浏览器指纹（参考指纹浏览器配置）
    每次注册使用不同身份，覆盖全部检测维度
    """

    # ── 1. 操作系统 + 浏览器版本 ──
    # 固定 Windows 10 平台（与注册场景匹配），Chrome 版本随机
    os_version = random.choice(["10.0", "10.0", "11.0"])
    chrome_major = random.randint(126, 140)
    chrome_build = random.randint(6200, 7400)
    chrome_patch = random.randint(40, 250)
    chrome_ver = f"{chrome_major}.0.{chrome_build}.{chrome_patch}"
    platform = "Win32"

    user_agent = (
        f"Mozilla/5.0 (Windows NT {os_version}; Win64; x64) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{chrome_ver} Safari/537.36"
    )

    # ── 2. 语言 / 时区（基于 IP 生成对应配置）──
    locales = [
        ("zh-CN", "Asia/Shanghai", ["zh-CN", "zh", "en-US", "en"]),
        ("zh-CN", "Asia/Shanghai", ["zh-CN", "zh"]),
        ("en-US", "America/New_York", ["en-US", "en"]),
        ("en-US", "America/Los_Angeles", ["en-US", "en"]),
        ("ja-JP", "Asia/Tokyo", ["ja", "en-US", "en"]),
    ]
    locale, timezone, languages = random.choice(locales)

    # ── 3. 硬件参数 ──
    hardware_concurrency = random.choice([4, 6, 8, 12, 16])
    device_memory = random.choice([4, 8, 16, 32])

    # ── 4. WebGL 元数据（厂商 + 渲染器）──
    webgl_configs = [
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) HD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11-27.20.100.7985)"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11-27.20.100.8935)"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11-30.0.101.1191)"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11-31.0.101.4255)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11-31.0.15.3623)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11-31.0.15.4601)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11-31.0.15.4601)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0, D3D11-32.0.15.6081)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11-32.0.15.6081)"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11-31.0.14011.5007)"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6600 XT Direct3D11 vs_5_0 ps_5_0, D3D11-31.0.24027.1012)"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 7600 Direct3D11 vs_5_0 ps_5_0, D3D11-32.0.11029.5007)"),
    ]
    gl_vendor, gl_renderer = random.choice(webgl_configs)

    # ── 5. 随机种子（Canvas / WebGL 图像 / AudioContext / ClientRects）──
    canvas_seed = random.randint(1, 0xFFFFFF)
    webgl_noise_seed = random.randint(1, 0xFFFFFF)
    audio_noise = round(random.uniform(0.00001, 0.00009), 8)
    rect_noise_x = round(random.uniform(0.001, 0.009), 6)
    rect_noise_y = round(random.uniform(0.001, 0.009), 6)

    # ── 6. Do Not Track ──
    do_not_track = random.choice(["1", None])

    # ── 7. 设备名称 / MAC 地址 ──
    device_name = f"DESKTOP-{''.join(random.choices(string.ascii_uppercase + string.digits, k=7))}"
    mac_parts = [format(random.randint(0, 255), '02X') for _ in range(6)]
    mac_address = '-'.join(mac_parts)

    # ── 8. 媒体设备 ID ──
    def _rand_device_id():
        return ''.join(random.choices('0123456789abcdef', k=64))

    audio_input_id = _rand_device_id()
    audio_output_id = _rand_device_id()
    video_input_id = _rand_device_id()

    # ── 9. Speech Voices 数量 ──
    speech_voice_count = random.randint(3, 8)

    # ── 10. 插件数量 ──
    plugin_count = random.randint(2, 5)

    # ── 配色偏好 ──
    color_scheme = random.choice(["dark", "light", "no-preference"])

    # ══════════════════════════════════════════════════════
    #  Navigator 属性覆盖脚本（在每个页面加载前注入）
    # ══════════════════════════════════════════════════════
    init_script = f"""
    (() => {{
    // ═══ 1. 隐藏 webdriver 标记 ═══
    Object.defineProperty(navigator, 'webdriver', {{ get: () => undefined }});
    try {{ delete navigator.__proto__.webdriver; }} catch(e) {{}}

    // ═══ 2. Navigator 基础属性 ═══
    Object.defineProperty(navigator, 'hardwareConcurrency', {{ get: () => {hardware_concurrency} }});
    Object.defineProperty(navigator, 'deviceMemory', {{ get: () => {device_memory} }});
    Object.defineProperty(navigator, 'platform', {{ get: () => '{platform}' }});
    Object.defineProperty(navigator, 'languages', {{ get: () => {languages} }});
    {f"Object.defineProperty(navigator, 'doNotTrack', {{ get: () => '{do_not_track}' }});" if do_not_track else ""}

    // ═══ 3. Chrome 对象修复 ═══
    if (!window.chrome) {{ window.chrome = {{}}; }}
    if (!window.chrome.runtime) {{
        window.chrome.runtime = {{ connect: function() {{}}, sendMessage: function() {{}} }};
    }}

    // ═══ 4. Plugins / MimeTypes 伪装 ═══
    const mockPlugins = [];
    const pluginNames = ['Chrome PDF Plugin', 'Chrome PDF Viewer', 'Native Client',
                         'Chromium PDF Plugin', 'Microsoft Edge PDF Viewer'];
    for (let i = 0; i < {plugin_count}; i++) {{
        mockPlugins.push({{ name: pluginNames[i % pluginNames.length], filename: 'internal-pdf-viewer',
                           description: 'Portable Document Format', length: 1 }});
    }}
    Object.defineProperty(navigator, 'plugins', {{
        get: () => {{ const p = mockPlugins; p.length = {plugin_count}; return p; }}
    }});

    // ═══ 5. WebGL 元数据覆盖 ═══
    const hookGetParam = (proto) => {{
        const orig = proto.getParameter;
        proto.getParameter = function(param) {{
            if (param === 37445) return '{gl_vendor}';
            if (param === 37446) return '{gl_renderer}';
            return orig.call(this, param);
        }};
    }};
    if (typeof WebGLRenderingContext !== 'undefined') hookGetParam(WebGLRenderingContext.prototype);
    if (typeof WebGL2RenderingContext !== 'undefined') hookGetParam(WebGL2RenderingContext.prototype);

    // ═══ 6. WebGL 图像噪声 ═══
    const _readPixels = WebGLRenderingContext.prototype.readPixels;
    WebGLRenderingContext.prototype.readPixels = function() {{
        _readPixels.apply(this, arguments);
        if (arguments[6] && arguments[6].length > 0) {{
            const seed = {webgl_noise_seed};
            for (let i = 0; i < Math.min(arguments[6].length, 10); i++) {{
                arguments[6][i] = (arguments[6][i] + ((seed >> (i % 8)) & 1)) & 0xFF;
            }}
        }}
    }};

    // ═══ 7. Canvas 指纹噪声 ═══
    const _toDataURL = HTMLCanvasElement.prototype.toDataURL;
    const _toBlob = HTMLCanvasElement.prototype.toBlob;
    const canvasSeed = {canvas_seed};

    HTMLCanvasElement.prototype.toDataURL = function(type) {{
        if (this.width > 16 && this.height > 16) {{
            const ctx = this.getContext('2d');
            if (ctx) {{
                const imgData = ctx.getImageData(0, 0, Math.min(this.width, 4), Math.min(this.height, 4));
                for (let i = 0; i < imgData.data.length; i += 4) {{
                    imgData.data[i]     = (imgData.data[i]     + ((canvasSeed >> (i % 8)) & 3)) & 0xFF;
                    imgData.data[i + 1] = (imgData.data[i + 1] + ((canvasSeed >> ((i+1) % 8)) & 3)) & 0xFF;
                }}
                ctx.putImageData(imgData, 0, 0);
            }}
        }}
        return _toDataURL.apply(this, arguments);
    }};

    HTMLCanvasElement.prototype.toBlob = function(cb, type, quality) {{
        if (this.width > 16 && this.height > 16) {{
            const ctx = this.getContext('2d');
            if (ctx) {{
                const imgData = ctx.getImageData(0, 0, Math.min(this.width, 4), 1);
                imgData.data[0] = (imgData.data[0] + (canvasSeed & 7)) & 0xFF;
                ctx.putImageData(imgData, 0, 0);
            }}
        }}
        return _toBlob.call(this, cb, type, quality);
    }};

    // ═══ 8. AudioContext 指纹噪声 ═══
    const _createOscillator = (window.OfflineAudioContext || window.webkitOfflineAudioContext || function(){{}}).prototype.createOscillator;
    if (_createOscillator) {{
        const _getChannelData = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function(channel) {{
            const data = _getChannelData.call(this, channel);
            if (this.numberOfChannels === 1 && this.length < 10000) {{
                for (let i = 0; i < Math.min(data.length, 100); i++) {{
                    data[i] += {audio_noise} * ((i % 2 === 0) ? 1 : -1);
                }}
            }}
            return data;
        }};
    }}

    // ═══ 9. ClientRects 噪声 ═══
    const _getBCR = Element.prototype.getBoundingClientRect;
    Element.prototype.getBoundingClientRect = function() {{
        const rect = _getBCR.call(this);
        return new DOMRect(
            rect.x + {rect_noise_x},
            rect.y + {rect_noise_y},
            rect.width + {rect_noise_x},
            rect.height + {rect_noise_y}
        );
    }};

    const _getClientRects = Element.prototype.getClientRects;
    Element.prototype.getClientRects = function() {{
        const rects = _getClientRects.call(this);
        const newRects = [];
        for (const r of rects) {{
            newRects.push(new DOMRect(
                r.x + {rect_noise_x}, r.y + {rect_noise_y},
                r.width + {rect_noise_x}, r.height + {rect_noise_y}
            ));
        }}
        return newRects;
    }};

    // ═══ 10. 媒体设备伪装 ═══
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {{
        const _enum = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
        navigator.mediaDevices.enumerateDevices = async function() {{
            return [
                {{ deviceId: '{audio_input_id}', kind: 'audioinput', label: '', groupId: '1' }},
                {{ deviceId: '{audio_output_id}', kind: 'audiooutput', label: '', groupId: '1' }},
                {{ deviceId: '{video_input_id}', kind: 'videoinput', label: '', groupId: '2' }},
            ];
        }};
    }}

    // ═══ 11. Speech Voices 伪装 ═══
    if (window.speechSynthesis) {{
        const voiceNames = [
            'Microsoft David - English (United States)', 'Microsoft Zira - English (United States)',
            'Microsoft Mark - English (United States)', 'Google US English', 'Google 日本語',
            'Microsoft Huihui - Chinese (Simplified)', 'Microsoft Kangkang - Chinese (Simplified)',
            'Microsoft Yaoyao - Chinese (Simplified)'
        ];
        const mockVoices = [];
        for (let i = 0; i < {speech_voice_count}; i++) {{
            mockVoices.push({{
                name: voiceNames[i % voiceNames.length], lang: i < 4 ? 'en-US' : 'zh-CN',
                default: i === 0, localService: true, voiceURI: voiceNames[i % voiceNames.length]
            }});
        }}
        const _getVoices = speechSynthesis.getVoices.bind(speechSynthesis);
        speechSynthesis.getVoices = function() {{ return mockVoices; }};
    }}

    // ═══ 12. Permissions API 伪装 ═══
    if (window.Permissions && Permissions.prototype.query) {{
        const _query = Permissions.prototype.query;
        Permissions.prototype.query = function(params) {{
            if (params.name === 'notifications')
                return Promise.resolve({{ state: Notification.permission }});
            return _query.call(this, params);
        }};
    }}

    // ═══ 13. 屏幕信息一致性 ═══
    // 让 screen 属性和 viewport 匹配（避免不一致检测）
    try {{
        Object.defineProperty(screen, 'colorDepth', {{ get: () => 24 }});
        Object.defineProperty(screen, 'pixelDepth', {{ get: () => 24 }});
    }} catch(e) {{}}

    }})();
    """

    # 提取显卡简称用于日志
    gl_short = gl_renderer.split(",")[1].strip().split(" Direct3D")[0] if "," in gl_renderer else gl_renderer

    return {
        "user_agent": user_agent,
        "locale": locale,
        "timezone": timezone,
        "color_scheme": color_scheme,
        "init_script": init_script,
        "chrome_ver": chrome_ver,
        "gl_renderer": gl_short,
        "device_name": device_name,
        "do_not_track": do_not_track,
    }


# ════════════════════════ YesCaptcha 浏览器插件模式 ════════════════════════

YESCAPTCHA_EXT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yescaptcha_ext")


def inject_yescaptcha_key(api_key):
    """
    直接修改扩展的 config.js 文件，将 API Key 写入。
    扩展首次加载时会读取 config.js 并存入 chrome.storage.local。
    """
    config_path = os.path.join(YESCAPTCHA_EXT_DIR, "config.js")
    if not os.path.exists(config_path):
        print(f"  ⚠️ 找不到 config.js: {config_path}")
        return False

    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Replace clientKey value
    import re as _re
    new_content = _re.sub(
        r"clientKey:\s*'[^']*'",
        f"clientKey: '{api_key}'",
        content
    )

    with open(config_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"  ✅ YesCaptcha Key 已写入 config.js (Key: {api_key[:8]}...)")
    return True


async def wait_for_captcha_solved(page, log_fn, shot_fn, max_wait=300):
    """
    使用 YesCaptcha 的 FunCaptchaClassification API 解决验证码
    纯代码实现，不依赖浏览器扩展。
    """
    import urllib.request
    import json
    import base64
    import time
    
    # 动态加载配置读取 Key
    yc_key = ""
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            yc_key = cfg.get("yescaptcha_key", "")
    except Exception:
        pass

    has_captcha = False
    for frame in page.frames:
        url = frame.url
        if "arkoselabs.com" in url or "arks-client.adobe.com" in url or "funcaptcha" in url or "/fc/" in url:
            has_captcha = True
            break

    if not has_captcha:
        log_fn("  ✅ 未检测到验证码，继续...")
        return True

    log_fn("  🛡️ 检测到 FunCaptcha，开始调用 YesCaptcha 图像识别 API...")
    await shot_fn(page, "captcha_detected")

    # 主动点击 Start puzzle / Verify 按钮
    click_time = time.time()
    clicked = False
    selectors = [
        "button:has-text('Start puzzle')",
        "button:has-text('Verify')",
        "button:has-text('验证')",
        "button:has-text('开始')",
        "#home_children_button",
        "[data-theme='home.verifyButton']"
    ]
    while time.time() - click_time < 15:
        for frame in page.frames:
            if "arks-client.adobe.com" in frame.url or "arkoselabs.com" in frame.url or "funcaptcha" in frame.url:
                for sel in selectors:
                    try:
                        btn = await frame.query_selector(sel)
                        if btn and await btn.is_visible():
                            await btn.click()
                            log_fn(f"  👉 成功点击验证起始按钮！")
                            clicked = True
                            break
                    except Exception:
                        pass
                if clicked: break
        if clicked: break
        await page.wait_for_timeout(1000)

    if not clicked:
        log_fn("  ⚠️ 没找到可点击的起始按钮，也许不需要...")

    # 等待题目加载
    game_frame = None
    start_time = time.time()
    while time.time() - start_time < 20:
        for frame in page.frames:
            if "game-core" in frame.url:
                game_frame = frame
                break
        if game_frame:
            break
        await page.wait_for_timeout(1000)

    if not game_frame:
        log_fn("  ❌ 无法找到验证码游戏核心框架！")
        return False

    # 循环解决所有回合
    round_count = 0
    while time.time() - start_time < max_wait:
        await page.wait_for_timeout(2000)
        
        # 检查是否已经验证通过（如果 iframe 消失或者提示成功）
        still_has_captcha = False
        for frame in page.frames:
            if "game-core" in frame.url or "enforcement" in frame.url:
                still_has_captcha = True
                break
        if not still_has_captcha:
            log_fn(f"  ✅ 验证码已通过！(共解决 {round_count} 题)")
            await shot_fn(page, "captcha_solved")
            return True

        # 尝试提取问题
        question = ""
        for header in ["h2", "#game_children_text", "p.challenge-instructions", ".html-challenge-instructions"]:
            els = await game_frame.query_selector_all(header)
            for el in els:
                text = await el.inner_text()
                if text and len(text) > 5 and not text.isdigit() and "Audio" not in text and "Restart" not in text:
                    question = text.strip()
                    break
            if question: break
            
        if not question:
            continue
            
        log_fn(f"  题目: {question}")
        
        # 截取图片
        challenge_el = await game_frame.query_selector("#challenge-image, #game_children_challenge, .challenge-container")
        if not challenge_el:
            challenge_el = await game_frame.query_selector("body")
            
        # 1. 尝试直接获取其内部图片的最原始完整图 (应对 Arkose 的 Sprite Sheet 抓娃娃机题)
        b64_img = None
        is_arrow_puzzle = False
        
        # 探测是否为带左右箭头的题
        right_arrow = await game_frame.query_selector("a.challenge-action-right, a[aria-label*='Right'], button[aria-label*='Next'], a[class*='right']")
        submit_btn = await game_frame.query_selector("button:has-text('Submit'), button:has-text('Submit'), button:has-text('提交'), button:has-text('验证'), button[type='submit']")
        if right_arrow and submit_btn:
            is_arrow_puzzle = True
            log_fn("  🔎 探测到左右箭头/抓娃娃机动态题")
            
        # 统一使用可视区域截图 (挑战区域框内包含了目标题目与左右箭头)，完全契合 YesCaptcha 的红框标准
        image_payload = None
        current_frame_cnt = 1
        
        if is_arrow_puzzle:
            log_fn("  🔁 开始截取所有帧序列...")
            slides_count = 5 # 默认5帧
            pip_container = await game_frame.query_selector(".pip-container")
            if pip_container:
                label = await pip_container.get_attribute("aria-label")
                if label and "of " in label:
                    import re
                    m = re.search(r'of (\d+)', label)
                    if m: slides_count = int(m.group(1))
            
            img_array = []
            for i in range(slides_count):
                img_bytes = await challenge_el.screenshot(type="jpeg", quality=80)
                img_array.append("data:image/jpeg;base64," + base64.b64encode(img_bytes).decode('utf-8'))
                if i < slides_count - 1:
                    await right_arrow.click()
                    await page.wait_for_timeout(400)
                else:
                    # 最后一帧后，再点一次回到初始帧（假设它是循环的，Arkose通常转满一圈回到原点）
                    await right_arrow.click()
                    await page.wait_for_timeout(400)
                    
            image_payload = img_array
            log_fn(f"  📸 已捕获完整的 {slides_count} 帧图像数组发给打码平台")
        else:
            img_bytes = await challenge_el.screenshot(type="jpeg", quality=80)
            image_payload = "data:image/jpeg;base64," + base64.b64encode(img_bytes).decode('utf-8')
        
        # 调用 YesCaptcha FunCaptchaClassification
        payload = {
            "clientKey": yc_key,
            "task": {
                "type": "FunCaptchaClassification",
                "image": image_payload,
                "question": question
            }
        }
        
        url = "https://api.yescaptcha.com/createTask"
        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
            with open_url_with_proxy(req, timeout=60) as resp:
                data = json.loads(resp.read().decode('utf-8'))
        except Exception as e:
            log_fn(f"  ❌ 调用 API 失败: {e}")
            await page.wait_for_timeout(3000)
            continue
            
        if data.get("errorId") == 0 and data.get("status") == "ready":
            objects = data.get("solution", {}).get("objects", [])
            log_fn(f"  🧠 AI 识别结果: {objects} (标签 {data.get('solution', {}).get('label')})")
            if objects:
                target_idx = int(objects[0])
                
                # 情况 A：箭头动态题
                if is_arrow_puzzle:
                    log_fn(f"  🖱️ 根据 AI 的多图数组索引，目标在第 {target_idx} 帧，正前往...")
                    for _ in range(target_idx):
                        await right_arrow.click()
                        await page.wait_for_timeout(300)
                    await page.wait_for_timeout(200)
                    await submit_btn.click()
                    log_fn(f"  ✅ 箭头题已提交")
                
                # 情况 B：普通静态九宫格 / 六宫格题型
                else:
                    links = await challenge_el.query_selector_all("a, button, li")
                    if links and len(links) > target_idx:
                        await links[target_idx].click()
                        log_fn(f"  🖱️ 已点击元素索引 {target_idx}")
                    else:
                        box = await challenge_el.bounding_box()
                        if box:
                            cols, rows = 3, 2
                            w, h = box["width"] / cols, box["height"] / rows
                            col, row = target_idx % cols, target_idx // cols
                            rel_x, rel_y = col * w + w / 2, row * h + h / 2
                            await challenge_el.click(position={"x": rel_x, "y": rel_y})
                            log_fn(f"  🖱️ 已点击坐标 ({int(rel_x)}, {int(rel_y)})")
                round_count += 1
                await page.wait_for_timeout(3000)
            else:
                log_fn("  ⚠️ API未能识别返回任何匹配对象。")
                await page.wait_for_timeout(5000)
        else:
            log_fn(f"  ⚠️ 识别异常或不支持的题目 (错误码 {data.get('errorId')})")
            await page.wait_for_timeout(5000)
            
    log_fn("  ❌ 验证码解决超时！")
    await shot_fn(page, "captcha_timeout")
    return False




# ════════════════════════ 临时邮箱 ════════════════════════

class TempMail:
    def __init__(self):
        self.client = httpx.AsyncClient(
            base_url=API_BASE,
            headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            timeout=30.0,
            **build_api_httpx_proxy_kwargs(),
        )
        self.email_id = None
        self.address = None

    def _pick_random_domain(self) -> str:
        """从配置的域名列表中均匀随机选一个"""
        # EMAIL_DOMAINS 环境变量：逗号分隔的多域名列表
        domains_str = os.getenv("EMAIL_DOMAINS", "")
        if domains_str:
            domains = [d.strip() for d in domains_str.split(",") if d.strip()]
            if domains:
                domain = random.choice(domains)
                log(f"  🌐 随机域名: {domain} (共 {len(domains)} 个可用)")
                return domain
        # 回退到单域名环境变量
        log(f"  🌐 使用默认域名: {EMAIL_DOMAIN}")
        return EMAIL_DOMAIN

    async def create(self) -> str:
        domain = self._pick_random_domain()
        prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        last_error = None
        for attempt in range(1, 4):
            try:
                r = await self.client.post("/emails/generate", json={
                    "name": prefix, "expiryTime": 3600000, "domain": domain,
                })
                r.raise_for_status()
                data = r.json()
                self.email_id = data["id"]
                self.address = data["email"]
                log(f"📬 临时邮箱: {self.address}")
                return self.address
            except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError, httpx.RemoteProtocolError) as e:
                last_error = e
                if attempt < 3:
                    delay = attempt * 2
                    log(f"  ⚠️ 临时邮箱创建失败，第 {attempt}/3 次: {type(e).__name__}，{delay}s 后重试")
                    await asyncio.sleep(delay)
                else:
                    break
        raise RuntimeError(f"临时邮箱创建失败，已重试 3 次: {last_error}")

    async def wait_for_code(self, max_wait=120, interval=5) -> str | None:
        log(f"⏳ 等待验证邮件 (最长 {max_wait}s)...")
        start = time.time()
        attempt = 0
        while time.time() - start < max_wait:
            attempt += 1
            elapsed = int(time.time() - start)
            try:
                r = await self.client.get(f"/emails/{self.email_id}")
                r.raise_for_status()
                messages = r.json().get("messages", [])
                if messages:
                    log(f"📨 收到 {len(messages)} 封邮件 ({elapsed}s)")
                    for msg in messages:
                        subj = str(msg.get("subject", ""))
                        if "驗證" in subj or "验证" in subj or "code" in subj.lower():
                            code = extract_code(msg)
                            if code:
                                log(f"🔑 验证码: {code} (来自: {subj})")
                                return code
                else:
                    if attempt % 3 == 1:
                        log(f"  轮询 #{attempt} ({elapsed}s) 暂无邮件...")
            except Exception as e:
                log(f"  轮询出错: {e}")
            await asyncio.sleep(interval)
        log("❌ 等待验证邮件超时")
        return None

    async def close(self):
        await self.client.aclose()


class SelfEmailMail:
    def __init__(self):
        self.email_id = SELF_EMAIL_ADDRESS
        self.address = SELF_EMAIL_ADDRESS
        self.api_url = SELF_EMAIL_API_URL
        self.client = httpx.AsyncClient(timeout=30.0, **build_api_httpx_proxy_kwargs())

    async def create(self) -> str:
        if not self.address or not self.api_url:
            raise RuntimeError("自备邮箱信息不完整")
        log(f"📬 自备邮箱: {self.address}")
        return self.address

    async def wait_for_code(self, max_wait=120, interval=5) -> str | None:
        log(f"⏳ 通过自备邮箱 API 等待验证码 (最长 {max_wait}s)...")
        start = time.time()
        attempt = 0
        while time.time() - start < max_wait:
            attempt += 1
            elapsed = int(time.time() - start)
            try:
                r = await self.client.get(self.api_url)
                r.raise_for_status()
                raw = r.text or ""
                code = None
                try:
                    data = r.json()
                    code = extract_code_from_api_payload(data)
                except Exception:
                    code = extract_code({"text": raw})
                if code:
                    log(f"🔐 验证码: {code}")
                    return code
                if attempt % 3 == 1:
                    log(f"  轮询 #{attempt} ({elapsed}s) 暂未获取验证码...")
            except Exception as e:
                log(f"  自备邮箱 API 轮询出错: {e}")
            await asyncio.sleep(interval)
        log("❌ 等待自备邮箱验证码超时")
        return None

    async def close(self):
        await self.client.aclose()


def extract_code_from_api_payload(data) -> str | None:
    if isinstance(data, dict):
        for key in ("code", "verify_code", "verification_code", "otp"):
            value = data.get(key)
            if value:
                m = re.search(r"\b(\d{4,8})\b", str(value))
                if m:
                    return m.group(1)
        for key in ("html", "content", "body", "text", "message", "data"):
            value = data.get(key)
            if value is None:
                continue
            if isinstance(value, (dict, list)):
                found = extract_code_from_api_payload(value)
            else:
                found = extract_code({"text": str(value)})
            if found:
                return found
    if isinstance(data, list):
        for item in data:
            found = extract_code_from_api_payload(item)
            if found:
                return found
    return None


def extract_code(mail: dict) -> str | None:
    body = (mail.get("html") or mail.get("content") or
            mail.get("body") or mail.get("text") or "")
    text = re.sub(r'<[^>]+>', ' ', body)
    # "验证码: 123456"
    m = re.search(r'(?:验证码|驗證碼|code|OTP)[:\s]*(\d{4,6})', text, re.I)
    if m:
        return m.group(1)
    # 独立 6 位数字
    m = re.search(r'\b(\d{6})\b', text)
    if m:
        return m.group(1)
    return None


# ════════════════════════ 工具 ════════════════════════

step_n = 0

def log(msg: str):
    t = datetime.now().strftime("%H:%M:%S")
    line = f"[{t}] {msg}"
    try:
        print(line)
    except UnicodeEncodeError:
        print(line.encode("utf-8", errors="replace").decode("utf-8", errors="replace"))

async def shot(page: Page, name: str):
    """截图已禁用，保留接口兼容"""
    pass

async def fill(page: Page, selectors: list, value: str) -> bool:
    for sel in selectors:
        try:
            await page.wait_for_selector(sel, timeout=8000, state="visible")
            await page.fill(sel, "")
            await page.fill(sel, value)
            return True
        except Exception:
            continue
    return False

async def click_any(page: Page, selectors: list) -> bool:
    for sel in selectors:
        try:
            el = await page.query_selector(sel)
            if el and await el.is_visible():
                await el.click()
                return True
        except Exception:
            continue
    return False

async def collect_core_cookies(ctx: BrowserContext, cookie_keys: list[str]) -> dict:
    all_cookies = await ctx.cookies([
        "https://firefly.adobe.com",
        "https://account.adobe.com",
        "https://auth.services.adobe.com",
        "https://www.adobe.com",
        "https://adobeid-na1.services.adobe.com",
        "https://ims-na1.adobelogin.com",
    ])
    if not all_cookies:
        all_cookies = await ctx.cookies()

    cookie_by_name = {}
    for c in all_cookies:
        if c["name"] in cookie_keys and c.get("value") and c["name"] not in cookie_by_name:
            cookie_by_name[c["name"]] = c
    return cookie_by_name

def is_auth_success_callback(url: str) -> bool:
    if not url:
        return False
    return (
        "auth-light.identity.adobe.com/wrapper-popup-helper/index.html" in url
        and "#access_token=" in url
    )

async def wait_for_complete_core_cookies(ctx: BrowserContext, page: Page, cookie_keys: list[str], timeout_seconds: int = 20) -> dict:
    log("Step 7: 进入 Firefly 页面补齐 Cookie")
    warmup_urls = [
        ("Adobe 首页", "https://www.adobe.com"),
        ("Adobe 账户页", "https://account.adobe.com"),
        ("Firefly 首页", "https://firefly.adobe.com"),
    ]
    try:
        label, url = warmup_urls[0]
        log(f"  → 打开 {label}")
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        await page.wait_for_timeout(5000)
    except Exception as e:
        log(f"  ⚠️ 打开 Firefly 首页失败，继续尝试读取 Cookie: {e}")

    refresh_done = False
    warmup_index = 1
    for attempt in range(1, max(2, timeout_seconds // 2) + 1):
        cookie_by_name = await collect_core_cookies(ctx, cookie_keys)
        found_keys = [key for key in cookie_keys if key in cookie_by_name]
        missing_keys = [key for key in cookie_keys if key not in cookie_by_name]
        if not missing_keys:
            log(f"  ✅ 已补齐完整 Cookie ({len(found_keys)}/7)")
            return cookie_by_name

        log(f"  ⏳ 第 {attempt} 次检查: 已有 {len(found_keys)}/7，缺少: {', '.join(missing_keys)}")
        if "fg" in missing_keys and not refresh_done:
            try:
                log("  → 刷新 Firefly 页面，等待补写 fg")
                await page.reload(wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(5000)
                refresh_done = True
                continue
            except Exception as e:
                log(f"  ⚠️ 刷新 Firefly 页面失败: {e}")
                refresh_done = True

        if warmup_index < len(warmup_urls) and attempt in (3, 6):
            try:
                label, url = warmup_urls[warmup_index]
                log(f"  → 打开 {label}，尝试补齐剩余 Cookie")
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(4000)
                warmup_index += 1
                continue
            except Exception as e:
                log(f"  ⚠️ 打开 {warmup_urls[warmup_index][0]} 失败: {e}")
                warmup_index += 1

        await page.wait_for_timeout(2000)

    return await collect_core_cookies(ctx, cookie_keys)

async def wait_for_login_session(ctx: BrowserContext, page: Page, timeout_seconds: int = 30) -> bool:
    log("Step 6.5: 等待 Adobe 登录态落地")
    session_keys = ["ims_sid", "aux_sid"]
    reload_done = False
    warmup_urls = [
        ("Adobe 首页", "https://www.adobe.com"),
        ("Adobe 账户页", "https://account.adobe.com"),
        ("Firefly 首页", "https://firefly.adobe.com"),
    ]
    warmup_index = 0

    for attempt in range(1, max(2, timeout_seconds // 2) + 1):
        if is_auth_success_callback(page.url):
            try:
                log("  ✅ 检测到 wrapper-popup-helper 回调，认证已成功")
                log("  → 直接进入 Firefly 首页，触发 Adobe 会话落地")
                await page.goto("https://firefly.adobe.com", wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(4000)
            except Exception as e:
                log(f"  ⚠️ 回调后打开 Firefly 首页失败: {e}")

        cookie_by_name = await collect_core_cookies(ctx, session_keys)
        found_keys = [key for key in session_keys if key in cookie_by_name]
        missing_keys = [key for key in session_keys if key not in cookie_by_name]
        if not missing_keys:
            log(f"  ✅ Adobe 主登录态已就绪 ({', '.join(found_keys)})")
            return True

        short_url = page.url[:80] if page.url else ""
        log(f"  ⏳ 第 {attempt} 次检查: 缺少 {', '.join(missing_keys)} | 当前页: {short_url}")

        if "challenge/email-verification" in page.url and not reload_done:
            try:
                log("  → 仍停留在验证页，刷新当前页面以继续 SSO")
                await page.reload(wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(4000)
                reload_done = True
                continue
            except Exception as e:
                log(f"  ⚠️ 刷新验证页失败: {e}")
                reload_done = True

        if attempt >= 3 and warmup_index < len(warmup_urls):
            try:
                label, url = warmup_urls[warmup_index]
                log(f"  → 主动打开 {label}，触发登录态落地")
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(4000)
                warmup_index += 1
                continue
            except Exception as e:
                log(f"  ⚠️ 打开 {warmup_urls[warmup_index][0]} 失败: {e}")
                warmup_index += 1

        await page.wait_for_timeout(2000)

    return False


# ════════════════════════ 注册页面 URL ════════════════════════

SIGNUP_URL = (
    "https://auth.services.adobe.com/zh_HANS/deeplink.html?"
    "deeplink=signup"
    "&callback=https%3A%2F%2Fims-na1.adobelogin.com%2Fims%2Fadobeid%2Fclio-playground-web%2FAdobeID%2Ftoken"
    "%3Fredirect_uri%3Dhttps%253A%252F%252Fauth-light.identity.adobe.com%252Fwrapper-popup-helper%252Findex.html"
    "%26state%3D%257B%2522name%2522%253A%2522AccessTokenFlow%2522%252C%2522side%2522%253A%2522popup%2522%252C"
    "%2522data%2522%253A%257B%2522access_token%2522%253A%2522%2522%252C%2522returnOrigin%2522%253A%2522https"
    "%253A%252F%252Fauth-light.identity.adobe.com%2522%252C%2522client_id%2522%253A%2522clio-playground-web"
    "%2522%252C%2522clientId%2522%253A%2522clio-playground-web%2522%252C%2522relay%2522%253A%25225f63be8b-2d0d"
    "-4c9c-ac94-09add7650fde%2522%252C%2522useMessageChannel%2522%253Atrue%257D%257D"
    "%26code_challenge_method%3Dplain%26use_ms_for_expiry%3Dfalse"
    "&client_id=clio-playground-web"
    "&scope=AdobeID%2Cfirefly_api%2Copenid%2Cpps.read%2Cpps.write%2Cadditional_info.projectedProductContext"
    "%2Cadditional_info.ownerOrg%2Cuds_read%2Cuds_write%2Cab.manage%2Cread_organizations%2Cadditional_info.roles"
    "%2Caccount_cluster.read%2Ccreative_production%2Cprofile"
    "&state=%7B%22name%22%3A%22AccessTokenFlow%22%2C%22side%22%3A%22popup%22%2C%22data%22%3A%7B%22access_token"
    "%22%3A%22%22%2C%22returnOrigin%22%3A%22https%3A%2F%2Fauth-light.identity.adobe.com%22%2C%22client_id%22"
    "%3A%22clio-playground-web%22%2C%22clientId%22%3A%22clio-playground-web%22%2C%22relay%22%3A%225f63be8b-2d0d"
    "-4c9c-ac94-09add7650fde%22%2C%22useMessageChannel%22%3Atrue%7D%7D"
    "&relay=5f63be8b-2d0d-4c9c-ac94-09add7650fde"
    "&locale=zh_HANS&flow_type=token&idp_flow_type=create_account&dl=true"
    "&s_p=google%2Cfacebook%2Capple%2Cmicrosoft%2Cline%2Ckakao"
    "&response_type=token&code_challenge_method=plain"
    "&redirect_uri=https%3A%2F%2Fauth-light.identity.adobe.com%2Fwrapper-popup-helper%2Findex.html"
    "&use_ms_for_expiry=false#/signup"
)

# ════════════════════════ 主流程 ════════════════════════

async def main():
    mail = SelfEmailMail() if EMAIL_SOURCE == "self" else TempMail()

    log("╔═══════════════════════════════════════════════════╗")
    log("║   Adobe Firefly 自动注册 (直接注册模式)          ║")
    log("╚═══════════════════════════════════════════════════╝")

    # ── Step 0: 准备邮箱 ──
    log("━" * 50)
    log("Step 0: 准备邮箱")
    try:
        email_addr = await mail.create()
    except Exception as e:
        log(f"❌ 邮箱准备失败，任务结束: {e}")
        await mail.close()
        return

    async with async_playwright() as p:
        # Use persistent context to load the YesCaptcha extension
        # Use UUID to guarantee unique profile dir (avoids PID collision)
        if USER_DATA_DIR:
            user_data_dir = USER_DATA_DIR
        else:
            import uuid
            unique_id = uuid.uuid4().hex[:12]
            user_data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"chrome_profile_{unique_id}")
        shutil.rmtree(user_data_dir, ignore_errors=True)
        os.makedirs(user_data_dir, exist_ok=True)
        ctx = None
        main_page = None

        ext_path = os.path.abspath(YESCAPTCHA_EXT_DIR)
        has_ext = os.path.exists(os.path.join(ext_path, "manifest.json"))

        # Inject API key into extension config.js BEFORE launching browser
        if has_ext and YESCAPTCHA_KEY:
            inject_yescaptcha_key(YESCAPTCHA_KEY)

        # ── 生成随机浏览器指纹 ──
        fp = generate_fingerprint()
        log(f"  🎭 浏览器指纹: Chrome/{fp['chrome_ver']} | {fp['locale']} | {fp['gl_renderer']} | {fp['device_name']}")

        launch_args = [
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-infobars",
            "--disable-dev-shm-usage",
            "--window-size=1280,800",
        ]
        # 移除原有的 YesCaptcha 扩展加载逻辑，改用纯 API 方案
        # 以防扩展窗口占用或引发崩溃
        browser_proxy = build_playwright_proxy()
        if browser_proxy:
            log(f"  🌐 浏览器代理: {browser_proxy['server']}")

        launch_variants = [
            {
                "label": "new-headless" if not SHOW_BROWSER else "headed",
                "headless": False,
                "extra_args": ["--headless=new"] if not SHOW_BROWSER else [],
            }
        ]
        if not SHOW_BROWSER:
            launch_variants.append({
                "label": "legacy-headless",
                "headless": True,
                "extra_args": [],
            })

        launch_error = None
        for idx, variant in enumerate(launch_variants, start=1):
            shutil.rmtree(user_data_dir, ignore_errors=True)
            os.makedirs(user_data_dir, exist_ok=True)
            variant_args = launch_args + variant["extra_args"]
            launch_options = {
                "headless": variant["headless"],
                "slow_mo": 200,
                "args": variant_args,
                "viewport": {"width": 1280, "height": 800},
                "locale": fp["locale"],
                "timezone_id": fp["timezone"],
                "color_scheme": fp["color_scheme"],
                "user_agent": fp["user_agent"],
            }
            if browser_proxy:
                launch_options["proxy"] = browser_proxy

            try:
                if len(launch_variants) > 1:
                    log(f"  🚀 尝试启动浏览器模式 {idx}/{len(launch_variants)}: {variant['label']}")
                ctx = await asyncio.wait_for(
                    p.chromium.launch_persistent_context(user_data_dir, **launch_options),
                    timeout=BROWSER_LAUNCH_TIMEOUT_SECONDS,
                )
                launch_error = None
                break
            except asyncio.TimeoutError:
                launch_error = f"浏览器启动超时（>{BROWSER_LAUNCH_TIMEOUT_SECONDS} 秒）"
            except Exception as e:
                launch_error = str(e)

            if idx < len(launch_variants):
                log(f"  ⚠️ 浏览器模式 {variant['label']} 启动失败，切换备用模式: {launch_error}")

        if ctx is None:
            log(f"❌ 浏览器启动失败: {launch_error}")
            return

        # 注入指纹伪装脚本（在每个页面加载前执行）
        await ctx.add_init_script(fp["init_script"])

        # 清除所有预存 Cookie，确保全新会话
        await ctx.clear_cookies()
        log("  🧹 已清除所有预存 Cookie (无痕模式)")

        # Close any default blank tabs the persistent context opened
        for extra_page in ctx.pages[1:]:
            await extra_page.close()
        main_page = ctx.pages[0] if ctx.pages else await ctx.new_page()
        main_page.set_default_timeout(30000)

        try:
            # ══════════════════════════════════════
            # Step 1: 直接打开 Adobe 注册页面
            # ══════════════════════════════════════
            log("━" * 50)
            log("Step 1: 直接打开 Adobe 注册页面")
            try:
                await main_page.goto(
                    SIGNUP_URL,
                    wait_until="domcontentloaded",
                    timeout=SIGNUP_GOTO_TIMEOUT_MS,
                )
            except PlaywrightTimeout:
                log(f"  ⚠️ 注册页首次加载超时（>{SIGNUP_GOTO_TIMEOUT_MS // 1000} 秒），正在重试 1/1")
                try:
                    await main_page.goto("about:blank", wait_until="load", timeout=10000)
                except Exception:
                    pass
                await main_page.wait_for_timeout(1000)
                await main_page.goto(
                    SIGNUP_URL,
                    wait_until="domcontentloaded",
                    timeout=SIGNUP_GOTO_TIMEOUT_MS,
                )
            await main_page.wait_for_timeout(5000)
            await shot(main_page, "signup_page")
            log("✅ 注册页面已加载")
            log(f"  URL: {main_page.url[:80]}")

            # ══════════════════════════════════════
            # Step 2: 填写邮箱 + 密码
            # ══════════════════════════════════════
            log("━" * 50)
            log("Step 2: 填写邮箱和密码")

            # 等待表单
            for sel in ["input[type='email']", "#Signup-EmailField", "input[name='email']"]:
                try:
                    await main_page.wait_for_selector(sel, timeout=15000, state="visible")
                    break
                except PlaywrightTimeout:
                    continue

            ok = await fill(main_page, [
                "#Signup-EmailField", "input[name='email']", "input[type='email']",
            ], email_addr)
            log(f"  邮箱: {'✅' if ok else '❌'} {email_addr}")

            await main_page.wait_for_timeout(500)

            ok = await fill(main_page, [
                "#Signup-PasswordField", "input[name='password']", "input[type='password']",
            ], PASSWORD)
            log(f"  密码: {'✅' if ok else '❌'} ●●●●●●●●")

            await shot(main_page, "credentials")
            await main_page.wait_for_timeout(1000)

            await click_any(main_page, [
                "button:has-text('继续')", "button:has-text('Continue')",
                "button[type='submit']",
            ])
            log("  → 点击「继续」")
            await main_page.wait_for_timeout(3000)
            await shot(main_page, "after_continue")

            # ══════════════════════════════════════
            # Step 3: 填写个人信息
            # ══════════════════════════════════════
            log("━" * 50)
            log("Step 3: 填写个人信息")

            # 检查是否邮箱已注册
            for err_sel in ["text=已经有一个帐户", "text=already has an account"]:
                try:
                    el = await main_page.query_selector(err_sel)
                    if el and await el.is_visible():
                        log("❌ 邮箱已被注册!")
                        return
                except Exception:
                    pass

            ok = await fill(main_page, [
                "#Signup-FirstNameField", "input[name='firstName']",
            ], FIRST_NAME)
            log(f"  名字: {'✅' if ok else '❌'} {FIRST_NAME}")

            ok = await fill(main_page, [
                "#Signup-LastNameField", "input[name='lastName']",
            ], LAST_NAME)
            log(f"  姓氏: {'✅' if ok else '❌'} {LAST_NAME}")

            ok = await fill(main_page, [
                "#Signup-DateOfBirthChooser-Year", "input[name='year']",
            ], BIRTH_YEAR)
            log(f"  年份: {'✅' if ok else '❌'} {BIRTH_YEAR}")

            # 月份下拉 (选项: 一月~十二月)
            month_clicked = await click_any(main_page, [
                "#Signup-DateOfBirthChooser-Month", "button[name='month']",
            ])
            if month_clicked:
                await main_page.wait_for_timeout(800)
                mi = int(BIRTH_MONTH)
                month_zh = ["","一月","二月","三月","四月","五月","六月",
                            "七月","八月","九月","十月","十一月","十二月"]
                target = month_zh[mi]
                # 方法: 用键盘 ArrowDown 选择第 mi 个选项，再 Enter 确认
                for _ in range(mi):
                    await main_page.keyboard.press("ArrowDown")
                    await main_page.wait_for_timeout(100)
                await main_page.keyboard.press("Enter")
                log(f"  月份: ✅ {target} (键盘选择)")

            await main_page.wait_for_timeout(300)
            log("  国家: 使用默认")
            await shot(main_page, "personal_info")

            # 点击「创建帐户」
            await main_page.wait_for_timeout(1000)
            await click_any(main_page, [
                "button:has-text('创建帐户')", "button:has-text('创建账户')",
                "button:has-text('Create account')", "button[type='submit']",
            ])
            log("→ 点击「创建帐户」")
            await main_page.wait_for_timeout(5000)
            await shot(main_page, "submitted")

            # ══════════════════════════════════════
            # Step 4: 等待 YesCaptcha 扩展自动解决验证码
            # ══════════════════════════════════════
            log("━" * 50)
            log("Step 4: 检测验证码 (扩展自动处理模式)")

            captcha_ok = await wait_for_captcha_solved(main_page, log, shot, max_wait=180)

            if not captcha_ok:
                log("❌ 验证码未能通过，注册失败")
                return

            await main_page.wait_for_timeout(2000)

            # ══════════════════════════════════════
            # Step 5: 等待验证邮件 + 输入验证码
            # ══════════════════════════════════════
            log("━" * 50)
            log("Step 5: 等待验证邮件")
            if EMAIL_SOURCE == "self":
                log("__SELF_EMAIL_VERIFICATION_SENT__")
            code = await mail.wait_for_code(max_wait=120, interval=5)

            if code:
                log("━" * 50)
                log(f"Step 6: 输入验证码 [{code}]")

                # Adobe 验证码是 6~7 个独立 input 框，逐位输入
                # 方法: 用 keyboard.type 逐字符输入
                await main_page.wait_for_timeout(500)

                # 先聚焦到第一个输入框
                first_input_ok = False
                for sel in [
                    "input[data-index='0']", "input[name='code']",
                    "input[aria-label*='1']", "input[type='tel']:first-of-type",
                    "input[inputmode='numeric']:first-of-type",
                    "#otp-input-0", "input[maxlength='1']:first-of-type",
                ]:
                    try:
                        el = await main_page.query_selector(sel)
                        if el and await el.is_visible():
                            await el.click()
                            first_input_ok = True
                            break
                    except Exception:
                        continue

                if not first_input_ok:
                    # 备选: 点击验证码区域的第一个可见 input
                    inputs = await main_page.query_selector_all("input")
                    for inp in inputs:
                        try:
                            if await inp.is_visible():
                                box = await inp.bounding_box()
                                if box and box["width"] < 80:  # 小输入框
                                    await inp.click()
                                    first_input_ok = True
                                    break
                        except Exception:
                            continue

                if first_input_ok:
                    # 逐位键入验证码
                    await main_page.wait_for_timeout(300)
                    await main_page.keyboard.type(code, delay=150)
                    log(f"  ✅ 验证码已逐位输入: {code}")
                else:
                    log(f"  ⚠️ 未找到验证码输入框，验证码: {code}")

                await main_page.wait_for_timeout(2000)
                await shot(main_page, "code_entered")

                # 如果需要点提交
                await click_any(main_page, [
                    "button:has-text('验证')", "button:has-text('Verify')",
                    "button:has-text('提交')", "button[type='submit']",
                ])
                log("  → 提交验证码")

                # 等待注册完成 — 需等 SSO 跳转设置 ims_sid / aux_sid
                log("  等待 SSO 跳转完成...")
                pre_url = main_page.url
                for _ in range(15):
                    await asyncio.sleep(1)
                    if main_page.url != pre_url:
                        log(f"  🔄 页面已跳转: {main_page.url[:60]}")
                        await asyncio.sleep(3)  # 跳转后再等 3 秒确保 cookie 写入
                        break
                    if is_auth_success_callback(main_page.url):
                        log("  ✅ 检测到 wrapper-popup-helper 成功回调")
                        await asyncio.sleep(2)
                        break
                else:
                    # 即使没跳转也等够 8 秒
                    await asyncio.sleep(5)

                session_ready = await wait_for_login_session(ctx, main_page, timeout_seconds=30)
                if not session_ready:
                    log("❌ Adobe 主登录态未完成落地，注册失败")
                    return

            else:
                log("❌ 验证邮件超时，注册失败")
                return

            # ══════════════════════════════════════
            # 注册完成
            # ══════════════════════════════════════
            log("━" * 50)
            log("🎉 注册流程已完成!")

            log("╔═══════════════════════════════════════════════════╗")
            log("║              🎉 注册流程完成!                    ║")
            log("╚═══════════════════════════════════════════════════╝")
            log(f"  📧 邮箱: {email_addr}")
            log(f"  🔑 密码: {PASSWORD}")
            log(f"  👤 姓名: {LAST_NAME} {FIRST_NAME}")
            log(f"  🌐 主页: {main_page.url[:80]}")

            # ══════════════════════════════════════
            # Step 7: 导出 Cookie
            # ══════════════════════════════════════
            log("━" * 50)
            AUTH_COOKIE_KEYS = [
                'ims_sid', 'aux_sid', 'fg', 'relay', 'ftrset',
                'filter-profile-map', 'filter-profile-map-permanent',
            ]
            try:
                cookie_by_name = await wait_for_complete_core_cookies(ctx, main_page, AUTH_COOKIE_KEYS, timeout_seconds=24)
                if cookie_by_name:
                    missing_keys = [key for key in AUTH_COOKIE_KEYS if key not in cookie_by_name]
                    if missing_keys:
                        found_keys = [key for key in AUTH_COOKIE_KEYS if key in cookie_by_name]
                        log(f"  ❌ Cookie 不完整，缺少 {len(missing_keys)} 个核心字段: {', '.join(missing_keys)}")
                        log(f"  ℹ️ 当前仅获取到 {len(found_keys)}/7: {', '.join(found_keys) if found_keys else '无'}")
                        return

                    unique = [cookie_by_name[key] for key in AUTH_COOKIE_KEYS]

                    cookie_header = "; ".join(
                        f"{c['name']}={c['value']}" for c in unique
                    )

                    # 使用 COOKIE_ID 生成唯一文件名（并发安全），无则回退到时间戳
                    cookie_id = os.getenv("COOKIE_ID", "")
                    if cookie_id:
                        cookie_file = os.path.join(SCREENSHOT_DIR, f"cookie_{cookie_id}.json")
                    else:
                        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                        cookie_file = os.path.join(SCREENSHOT_DIR, f"cookie_{ts}.json")
                    cookie_data = {
                        "cookie": cookie_header,
                        "name": email_addr
                    }
                    with open(cookie_file, "w", encoding="utf-8") as f:
                        json.dump(cookie_data, f, ensure_ascii=False, indent=4)
                    log(f"  🍪 已导出完整核心 Cookie ({len(unique)}/7)")
                    log(f"  📁 文件: {cookie_file}")
                else:
                    log("  ❌ 未获取到 Cookie，注册失败")
                    return
            except Exception as e:
                log(f"  ❌ Cookie 导出失败: {e}")
                return

            # 保存注册结果
            log("━" * 50)
            result = {
                "email": email_addr, "email_id": mail.email_id,
                "password": PASSWORD,
                "name": f"{LAST_NAME} {FIRST_NAME}",
                "url": main_page.url,
                "time": datetime.now().isoformat(),
            }
            with open(os.path.join(SCREENSHOT_DIR, "result.json"), "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=4)
            log(f"  结果已保存到 {os.path.join(SCREENSHOT_DIR, 'result.json')}")

        except Exception as e:
            log(f"❌ 出错: {e}")
            import traceback
            traceback.print_exc()
            try:
                await shot(main_page, "error")
            except Exception:
                pass
        finally:
            await mail.close()
            if ctx:
                await ctx.close()
            # Clean up temporary profile directory
            try:
                shutil.rmtree(user_data_dir, ignore_errors=True)
            except Exception:
                pass


if __name__ == "__main__":
    asyncio.run(main())
