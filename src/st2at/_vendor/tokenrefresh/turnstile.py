"""OpenAI sentinel turnstile VM solver (dx + p → t / so).

Browser flow (sentinel SDK):
1. XOR-decrypt base64(dx) with the challenge fingerprint ``p`` (gAAAAAC…)
2. Interpret the mutable bytecode queue in slot 9 (nested programs re-queue)
3. Success callback (op 3) returns base64 text used as sentinel field ``t``

Improvements vs early pure-string stubs (validated against har/*.har):
- Keep intermediate window.* as path refs so navigator.deviceMemory does not
  become the broken token \"[object Navigator].deviceMemory\".
- Resolve leaf properties (UA, screen, CF bootstrap, location, …) to browser-like
  values so XOR chains match real opcode streams more closely.
- Prefer last op-3 emission when multiple (matches longer SDK runs).
"""
from __future__ import annotations

import base64
import json
import os
import random
import time
from typing import Any


class _OrderedMap:
    def __init__(self) -> None:
        self.keys: list[str] = []
        self.values: dict[str, Any] = {}

    def add(self, key: str, value: Any) -> None:
        if key not in self.values:
            self.keys.append(key)
        self.values[key] = value

    def to_dict(self) -> dict[str, Any]:
        return {k: self.values[k] for k in self.keys}


class _PathRef:
    """Intermediate JS object path (window.navigator, window.document, …)."""

    __slots__ = ("path",)

    def __init__(self, path: str) -> None:
        self.path = path

    def __repr__(self) -> str:
        return f"PathRef({self.path!r})"


# Object [[Class]] tags when a PathRef is stringified (HAR-aligned)
_OBJECT_TAGS: dict[str, str] = {
    "window": "[object Window]",
    "window.navigator": "[object Navigator]",
    "window.navigator.userAgentData": "[object NavigatorUAData]",
    "window.navigator.connection": "[object NetworkInformation]",
    "window.navigator.plugins": "[object PluginArray]",
    "window.navigator.mimeTypes": "[object MimeTypeArray]",
    "window.navigator.mediaDevices": "[object MediaDevices]",
    "window.navigator.serviceWorker": "[object ServiceWorkerContainer]",
    "window.navigator.credentials": "[object CredentialsContainer]",
    "window.navigator.geolocation": "[object Geolocation]",
    "window.navigator.permissions": "[object Permissions]",
    "window.navigator.scheduling": "[object Scheduling]",
    "window.navigator.userActivation": "[object UserActivation]",
    "window.navigator.storage": "[object StorageManager]",
    "window.navigator.locks": "[object LockManager]",
    "window.navigator.wakeLock": "[object WakeLock]",
    "window.navigator.gpu": "[object GPU]",
    "window.navigator.ink": "[object Ink]",
    "window.navigator.hid": "[object HID]",
    "window.navigator.usb": "[object USB]",
    "window.navigator.serial": "[object Serial]",
    "window.navigator.xr": "[object XRSystem]",
    "window.navigator.keyboard": "[object Keyboard]",
    "window.navigator.virtualKeyboard": "[object VirtualKeyboard]",
    "window.navigator.windowControlsOverlay": "[object WindowControlsOverlay]",
    "window.navigator.deprecatedRunAdAuctionEnforcesKAnonymity": "false",
    "window.document": "[object HTMLDocument]",
    "window.document.documentElement": "[object HTMLHtmlElement]",
    "window.document.body": "[object HTMLBodyElement]",
    "window.document.head": "[object HTMLHeadElement]",
    "window.screen": "[object Screen]",
    "window.screen.orientation": "[object ScreenOrientation]",
    "window.localStorage": "[object Storage]",
    "window.sessionStorage": "[object Storage]",
    "window.performance": "[object Performance]",
    "window.performance.memory": "[object MemoryInfo]",
    "window.performance.navigation": "[object PerformanceNavigation]",
    "window.performance.timing": "[object PerformanceTiming]",
    "window.history": "[object History]",
    "window.crypto": "[object Crypto]",
    "window.crypto.subtle": "[object SubtleCrypto]",
    "window.chrome": "[object Object]",
    "window.chrome.runtime": "[object Object]",
    "window.Math": "[object Math]",
    "window.Reflect": "[object Reflect]",
    "window.Object": "function Object() { [native code] }",
    "window.JSON": "[object JSON]",
    "window.Date": "function Date() { [native code] }",
    "window.location": "https://auth.openai.com/email-verification",
    "window.visualViewport": "[object VisualViewport]",
    "window.speechSynthesis": "[object SpeechSynthesis]",
    "window.trustedTypes": "[object TrustedTypePolicyFactory]",
    "window.cookieStore": "[object CookieStore]",
    "window.launchQueue": "[object LaunchQueue]",
    "window.navigation": "[object Navigation]",
    "window.scheduler": "[object Scheduler]",
    "window.__reactRouterContext": "[object Object]",
    "window.__reactRouterContext.state": "[object Object]",
    "window.__reactRouterContext.state.loaderData": "[object Object]",
    "window.__reactRouterContext.state.loaderData.root": "[object Object]",
    "window.__reactRouterContext.state.loaderData.root.clientBootstrap": "[object Object]",
    "window.__reactRouterContext.state.loaderData.root.session": "[object Object]",
    "window.__reactRouterContext.state.loaderData.root.env": "[object Object]",
}


_PROFILE_CACHE: dict[str, dict[str, Any]] = {}

# Object.keys(localStorage) — turnstile runs in CF iframe / partitioned storage.
# JP-7 browser t plaintext field 17.92 was statsig-only (not main-page oai-did keys):
#   statsig.session_id.*, statsig.last_modified_time.evaluations,
#   statsig.stable_id.*, statsig.cached.evaluations.*
# IDs are randomized per process; override list for HAR A/B.
def _default_local_storage_keys() -> list[str]:
    sid = str(random.randint(400000000, 499999999))
    cache = str(random.randint(4000000000, 4294967295))
    return [
        f"statsig.session_id.{sid}",
        "statsig.last_modified_time.evaluations",
        f"statsig.stable_id.{sid}",
        f"statsig.cached.evaluations.{cache}",
    ]


# None → regenerate per solve (iframe statsig keys). Set list to pin for HAR A/B.
_LOCAL_STORAGE_KEYS: list[str] | None = None


def _chrome_ui_chrome(sw: int, sh: int, *, is_mac: bool) -> tuple[int, int, int]:
    """Return (avail_h, inner_h, outer_h) chrome offsets for screen geometry.

    Real HARs: Mac dock often sh-48 (JP-7 2560x1440 → avail 1392); Windows taskbar
    commonly sh-40..48. Browser chrome (~100px) reduces innerHeight.
    """
    dock = 48 if is_mac else 40
    # ultrawide / tall screens keep same dock, slightly thicker browser chrome
    browser_chrome = 100 if sh >= 900 else 80
    avail_h = max(sh - dock, sh // 2)
    outer_h = sh
    inner_h = max(avail_h - browser_chrome + dock // 2, sh // 3)
    # clamp: inner never exceeds avail
    inner_h = min(inner_h, avail_h - 8)
    return avail_h, inner_h, outer_h


def _apply_geometry(
    leaves: dict[str, Any],
    sw: int,
    sh: int,
    *,
    is_mac: bool | None = None,
    dpr: float | int | None = None,
) -> None:
    """Stamp consistent screen / viewport / visualViewport leaves from one size."""
    if sw <= 0 or sh <= 0:
        return
    if is_mac is None:
        ua = str(leaves.get("window.navigator.userAgent") or "")
        is_mac = "Macintosh" in ua or "Mac OS" in ua
    avail_h, inner_h, outer_h = _chrome_ui_chrome(sw, sh, is_mac=bool(is_mac))
    if dpr is None:
        dpr = 2 if is_mac else 1
    leaves["window.screen.width"] = sw
    leaves["window.screen.height"] = sh
    leaves["window.screen.availWidth"] = sw
    leaves["window.screen.availHeight"] = avail_h
    leaves["window.screen.availLeft"] = 0
    leaves["window.screen.availTop"] = 0
    leaves["window.innerWidth"] = sw
    leaves["window.innerHeight"] = inner_h
    leaves["window.outerWidth"] = sw
    leaves["window.outerHeight"] = outer_h
    leaves["window.devicePixelRatio"] = dpr
    leaves["window.document.documentElement.clientWidth"] = sw
    leaves["window.document.documentElement.clientHeight"] = inner_h
    leaves["window.document.body.clientWidth"] = sw
    leaves["window.document.body.clientHeight"] = inner_h
    leaves["window.visualViewport.width"] = float(sw)
    leaves["window.visualViewport.height"] = float(inner_h)


def _apply_profile_to_leaves(leaves: dict[str, Any], profile: dict | None) -> None:
    """Overlay registration persona onto VM leaves (beats stale env cache).

    Critical for multi-worker: env TOKENREFRESH_SENTINEL_* is process-global and
    races; profile passed into solve_turnstile is the source of truth for t.
    """
    if not profile:
        return
    ua = str(profile.get("user_agent") or "").strip()
    if ua:
        leaves["window.navigator.userAgent"] = ua
        leaves["window.navigator.appVersion"] = ua.replace("Mozilla/", "")
        is_mac = "Macintosh" in ua or "Mac OS" in ua
        major = "146"
        try:
            import re as _re

            m = _re.search(r"Chrome/(\d+)", ua)
            if m:
                major = m.group(1)
        except Exception:
            pass
        brands = f"Chromium,{major};Google Chrome,{major};Not.A/Brand,8"
        leaves["window.navigator.userAgentData.brands"] = brands
        leaves["window.navigator.userAgentData.mobile"] = False
        if is_mac:
            leaves["window.navigator.platform"] = "MacIntel"
            leaves["window.navigator.userAgentData.platform"] = "macOS"
        elif "Linux" in ua:
            leaves["window.navigator.platform"] = "Linux x86_64"
            leaves["window.navigator.userAgentData.platform"] = "Linux"
        else:
            leaves["window.navigator.platform"] = "Win32"
            leaves["window.navigator.userAgentData.platform"] = "Windows"
    lang = str(profile.get("language") or "").strip()
    langs = str(profile.get("languages") or "").strip()
    if langs:
        parts = []
        for part in langs.split(","):
            code = part.split(";")[0].strip()
            if code:
                parts.append(code)
        if parts:
            leaves["window.navigator.languages"] = ",".join(parts)
            leaves["window.navigator.language"] = parts[0]
    elif lang:
        short = lang.split("-")[0]
        leaves["window.navigator.language"] = lang
        leaves["window.navigator.languages"] = f"{lang},{short},en-US,en"
    for key in ("hardware_concurrency", "hardwareConcurrency", "cores"):
        raw = profile.get(key)
        if raw is None or raw == "":
            continue
        try:
            leaves["window.navigator.hardwareConcurrency"] = int(raw)
            break
        except (TypeError, ValueError):
            pass
    for key in ("device_memory", "deviceMemory"):
        raw = profile.get(key)
        if raw is None or raw == "":
            continue
        try:
            leaves["window.navigator.deviceMemory"] = int(raw)
            break
        except (TypeError, ValueError):
            pass
    screen = str(profile.get("screen") or "").strip().lower()
    if "x" in screen:
        try:
            w_s, h_s = screen.split("x", 1)
            sw, sh = int(w_s), int(h_s)
            ua_now = str(leaves.get("window.navigator.userAgent") or ua or "")
            is_mac = "Macintosh" in ua_now or "Mac OS" in ua_now
            dpr = profile.get("device_pixel_ratio") or profile.get("dpr")
            if dpr is None:
                dpr = 2 if is_mac else 1
            else:
                dpr = float(dpr)
            _apply_geometry(leaves, sw, sh, is_mac=is_mac, dpr=dpr)
        except Exception:
            pass
    # Exit IP / geo from registration proxy probe (must match HTTP path, not fake default)
    eip = str(
        profile.get("exit_ip")
        or profile.get("cf_connecting_ip")
        or profile.get("cfConnectingIp")
        or ""
    ).strip()
    city = str(profile.get("exit_city") or profile.get("cf_ip_city") or "").strip()
    lat = str(profile.get("exit_lat") or profile.get("cf_ip_lat") or "").strip()
    lon = str(profile.get("exit_lon") or profile.get("cf_ip_lon") or "").strip()
    reg = str(profile.get("proxy_region") or "").strip().upper()
    bootstrap = "window.__reactRouterContext.state.loaderData.root.clientBootstrap"
    # Also stamp alternate bootstrap path used in some builds
    for bkey in (
        bootstrap,
        "window.__reactRouterContext.state.loaderData.root.env",
    ):
        if eip:
            leaves[f"{bkey}.cfConnectingIp"] = eip
        if city:
            leaves[f"{bkey}.cfIpCity"] = city
        if lat:
            leaves[f"{bkey}.cfIpLatitude"] = lat
        if lon:
            leaves[f"{bkey}.cfIpLongitude"] = lon
        if reg:
            leaves[f"{bkey}.userRegion"] = reg
            leaves[f"{bkey}.cfIpCountry"] = reg
    did = str(profile.get("oai_did") or profile.get("device_id") or "").strip()
    if did:
        leaves[f"{bootstrap}.deviceId"] = did
    # Seeded Canvas / WebGL (protocol gpu_persona) — same profile as registration
    try:
        from .gpu_persona import apply_gpu_persona_to_leaves

        apply_gpu_persona_to_leaves(leaves, profile)
    except Exception:
        pass


def _env_browser_profile() -> dict[str, Any]:
    """Leaf values for property reads. Cached per full fingerprint key."""
    region = (os.environ.get("TOKENREFRESH_SENTINEL_REGION") or "JP").strip().upper()
    ua_e = (os.environ.get("TOKENREFRESH_SENTINEL_UA") or "").strip()
    lang_e = (os.environ.get("TOKENREFRESH_SENTINEL_LANG") or "").strip()
    cores_e = (os.environ.get("TOKENREFRESH_SENTINEL_CORES") or "").strip()
    mem_e = (os.environ.get("TOKENREFRESH_SENTINEL_DEVICE_MEMORY") or "").strip()
    sw_e = (os.environ.get("TOKENREFRESH_SENTINEL_SCREEN_W") or "").strip()
    sh_e = (os.environ.get("TOKENREFRESH_SENTINEL_SCREEN_H") or "").strip()
    # Must include screen/cores/lang or multi-persona workers poison the cache
    cache_key = "|".join((region, ua_e, lang_e, cores_e, mem_e, sw_e, sh_e))
    if cache_key in _PROFILE_CACHE:
        return _PROFILE_CACHE[cache_key]

    cf_ip = (os.environ.get("TOKENREFRESH_SENTINEL_CF_IP") or "").strip()
    city = (os.environ.get("TOKENREFRESH_SENTINEL_CF_CITY") or "").strip()
    lat = (os.environ.get("TOKENREFRESH_SENTINEL_CF_LAT") or "").strip()
    lon = (os.environ.get("TOKENREFRESH_SENTINEL_CF_LON") or "").strip()
    if not cf_ip:
        # Stable-looking regional defaults (override with TOKENREFRESH_SENTINEL_CF_IP)
        cf_ip = {
            "JP": "126.36.72.140",
            "KR": "211.36.148.22",
            "SG": "101.100.180.55",
            "US": "104.28.210.33",
        }.get(region, "126.36.72.140")
    if not city:
        city = {"JP": "Tokyo", "KR": "Seoul", "SG": "Singapore", "US": "Los Angeles"}.get(
            region, "Tokyo"
        )
    if not lat or not lon:
        coords = {
            "JP": ("35.6895", "139.6917"),
            "KR": ("37.5665", "126.9780"),
            "SG": ("1.3521", "103.8198"),
            "US": ("34.0522", "-118.2437"),
        }.get(region, ("35.6895", "139.6917"))
        lat, lon = lat or coords[0], lon or coords[1]

    ua = (
        ua_e
        or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
    ).strip()
    lang = (lang_e or "ja-JP").strip()
    loc = (
        os.environ.get("TOKENREFRESH_SENTINEL_LOCATION")
        or "https://auth.openai.com/email-verification"
    ).strip()
    cores = int(cores_e or "12")
    mem = int(mem_e or "8")
    sw = int(sw_e or "1920")
    sh = int(sh_e or "1080")

    bootstrap = "window.__reactRouterContext.state.loaderData.root.clientBootstrap"
    is_mac = "Macintosh" in ua or "Mac OS" in ua
    # Chrome major for userAgentData brands
    major = "146"
    try:
        import re as _re

        m = _re.search(r"Chrome/(\d+)", ua)
        if m:
            major = m.group(1)
    except Exception:
        pass
    brands = f"Chromium,{major};Google Chrome,{major};Not.A/Brand,8"
    dpr = 2 if is_mac else 1
    avail_h, inner_h, outer_h = _chrome_ui_chrome(sw, sh, is_mac=is_mac)
    # languages string: keep short primary when lang is bare 'ja' (HAR-like)
    lang_primary = lang
    lang_short = lang.split("-")[0]
    if lang.lower() in ("ja-jp", "ja"):
        languages = "ja,en-US,en"
        lang_primary = "ja"
    elif lang.lower() in ("ko-kr", "ko"):
        languages = "ko-KR,ko,en-US,en"
        lang_primary = lang if "-" in lang else "ko-KR"
    else:
        languages = f"{lang},{lang_short},en-US,en"
    leaves: dict[str, Any] = {
        "window.document.location": loc,
        "window.document.location.href": loc,
        "window.location": loc,
        "window.location.href": loc,
        "window.location.origin": "https://auth.openai.com",
        "window.location.protocol": "https:",
        "window.location.host": "auth.openai.com",
        "window.location.hostname": "auth.openai.com",
        "window.location.pathname": "/email-verification",
        "window.location.search": "",
        "window.location.hash": "",
        "window.origin": "https://auth.openai.com",
        "window.navigator.userAgent": ua,
        "window.navigator.language": lang_primary,
        "window.navigator.languages": languages,
        "window.navigator.platform": "MacIntel" if is_mac else "Win32",
        "window.navigator.hardwareConcurrency": cores,
        "window.navigator.deviceMemory": mem,
        "window.navigator.webdriver": False,
        "window.navigator.maxTouchPoints": 0,
        "window.navigator.cookieEnabled": True,
        "window.navigator.doNotTrack": None,
        "window.navigator.vendor": "Google Inc.",
        "window.navigator.vendorSub": "",
        "window.navigator.product": "Gecko",
        "window.navigator.productSub": "20030107",
        "window.navigator.appCodeName": "Mozilla",
        "window.navigator.appName": "Netscape",
        "window.navigator.appVersion": ua.replace("Mozilla/", ""),
        "window.navigator.onLine": True,
        "window.navigator.pdfViewerEnabled": True,
        "window.navigator.globalPrivacyControl": False,
        # userAgentData (Chrome CH client hints JS API)
        "window.navigator.userAgentData.brands": brands,
        "window.navigator.userAgentData.mobile": False,
        "window.navigator.userAgentData.platform": "macOS" if is_mac else "Windows",
        # NetworkInformation
        "window.navigator.connection.effectiveType": "4g",
        "window.navigator.connection.downlink": 10,
        "window.navigator.connection.rtt": 50,
        "window.navigator.connection.saveData": False,
        "window.navigator.connection.type": "wifi",
        # plugins length 0 or 5 — Chrome still reports 5 placeholders sometimes
        "window.navigator.plugins.length": 5,
        "window.navigator.mimeTypes.length": 2,
        "window.innerWidth": sw,
        "window.innerHeight": inner_h,
        "window.outerWidth": sw,
        "window.outerHeight": outer_h,
        "window.screenX": 0,
        "window.screenY": 0,
        "window.screenLeft": 0,
        "window.screenTop": 0,
        "window.devicePixelRatio": dpr,
        "window.screen.width": sw,
        "window.screen.height": sh,
        "window.screen.availWidth": sw,
        "window.screen.availHeight": avail_h,
        "window.screen.availLeft": 0,
        "window.screen.availTop": 0,
        "window.screen.colorDepth": 24,
        "window.screen.pixelDepth": 24,
        "window.screen.orientation.type": "landscape-primary",
        "window.screen.orientation.angle": 0,
        "window.document.hidden": False,
        "window.document.visibilityState": "visible",
        "window.document.readyState": "complete",
        "window.document.referrer": "https://chatgpt.com/",
        "window.document.title": "",
        "window.document.URL": loc,
        "window.document.documentURI": loc,
        "window.document.characterSet": "UTF-8",
        "window.document.charset": "UTF-8",
        "window.document.compatMode": "CSS1Compat",
        "window.document.contentType": "text/html",
        "window.document.documentElement.clientWidth": sw,
        "window.document.documentElement.clientHeight": inner_h,
        "window.document.documentElement.clientLeft": 0,
        "window.document.documentElement.clientTop": 0,
        "window.document.body.clientWidth": sw,
        "window.document.body.clientHeight": inner_h,
        # JP-7 field 56.04 decoded to 3 (history.length during auth multi-step)
        "window.history.length": 3,
        "window.history.scrollRestoration": "auto",
        "window.performance.timeOrigin": time.time() * 1000 - 4500.0,
        "window.performance.memory.jsHeapSizeLimit": 4294705152,
        "window.performance.memory.totalJSHeapSize": 45000000,
        "window.performance.memory.usedJSHeapSize": 32000000,
        "window.visualViewport.width": float(sw),
        "window.visualViewport.height": float(inner_h),
        "window.visualViewport.scale": 1,
        "window.visualViewport.offsetLeft": 0,
        "window.visualViewport.offsetTop": 0,
        "window.visualViewport.pageLeft": 0,
        "window.visualViewport.pageTop": 0,
        # Cloudflare / app bootstrap (expand for JP HARs)
        f"{bootstrap}.cfConnectingIp": cf_ip,
        f"{bootstrap}.cfIpCity": city,
        f"{bootstrap}.userRegion": region,
        f"{bootstrap}.cfIpLatitude": lat,
        f"{bootstrap}.cfIpLongitude": lon,
        f"{bootstrap}.cfIpCountry": region,
        f"{bootstrap}.cfRay": "",
        f"{bootstrap}.cfIpContinent": "AS" if region in ("JP", "KR", "SG") else "NA",
        f"{bootstrap}.cfIpTimezone": {
            "JP": "Asia/Tokyo",
            "KR": "Asia/Seoul",
            "SG": "Asia/Singapore",
            "US": "America/Los_Angeles",
        }.get(region, "Asia/Tokyo"),
        f"{bootstrap}.cfIpIsEuCountry": False,
        f"{bootstrap}.cfBotScore": 99,
        f"{bootstrap}.cfVerifiedBot": False,
        f"{bootstrap}.cfJa3Hash": "",
        f"{bootstrap}.cfJa4": "",
        f"{bootstrap}.authSessionLoggingId": "",
        f"{bootstrap}.statsigGateValues": "{}",
        f"{bootstrap}.deviceId": "",
        # session/env siblings under root loaderData
        "window.__reactRouterContext.state.loaderData.root.session.user": None,
        "window.__reactRouterContext.state.loaderData.root.env.environment": "production",
        "window.__reactRouterContext.state.loaderData.root.env.build": "production",
    }
    _PROFILE_CACHE[cache_key] = leaves
    return leaves


def _xor_crypt(data: str, key: str) -> str:
    if not key:
        return data
    kl = len(key)
    return "".join(chr(ord(ch) ^ ord(key[i % kl])) for i, ch in enumerate(data))


def _to_str(value: Any) -> str:
    if value is None:
        return "undefined"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return str(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, _PathRef):
        return _OBJECT_TAGS.get(value.path, "[object Object]")
    if isinstance(value, str):
        special = {
            "window.Math": "[object Math]",
            "window.Reflect": "[object Reflect]",
            "window.performance": "[object Performance]",
            "window.localStorage": "[object Storage]",
            "window.sessionStorage": "[object Storage]",
            "window.Object": "function Object() { [native code] }",
            "window.Reflect.set": "function set() { [native code] }",
            "window.performance.now": "function () { [native code] }",
            "window.Object.create": "function create() { [native code] }",
            "window.Object.keys": "function keys() { [native code] }",
            "window.Math.random": "function random() { [native code] }",
            "window.document.createElement": "function createElement() { [native code] }",
        }
        return special.get(value, value)
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return ",".join(value)
    if isinstance(value, _OrderedMap):
        return "[object Object]"
    return str(value)


def _b64encode_str(s: str) -> str:
    return base64.b64encode(s.encode("latin1")).decode("ascii")


def _b64decode_str(s: str) -> str:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s + pad).decode("latin1")


def _json_sanitize(value: Any) -> Any:
    """Chrome JSON.stringify: whole-number floats become ints (0 not 0.0)."""
    if isinstance(value, _OrderedMap):
        return {k: _json_sanitize(value.values[k]) for k in value.keys}
    if isinstance(value, dict):
        return {str(k): _json_sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_sanitize(v) for v in value]
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, _PathRef):
        return _to_str(value)
    return value


def _json_dumps(value: Any) -> str:
    def default(o: Any) -> Any:
        if isinstance(o, _OrderedMap):
            return _json_sanitize(o)
        if isinstance(o, _PathRef):
            return _to_str(o)
        if isinstance(o, float) and o.is_integer():
            return int(o)
        raise TypeError(type(o))

    return json.dumps(
        _json_sanitize(value),
        separators=(",", ":"),
        ensure_ascii=False,
        default=default,
    )


def _path_join(base: Any, prop: Any) -> str | None:
    """Build window.* path from base ref + property name."""
    if not isinstance(prop, str):
        return None
    if isinstance(base, _PathRef):
        return f"{base.path}.{prop}"
    if base == "window":
        return f"window.{prop}"
    if isinstance(base, str) and (base == "window" or base.startswith("window.")):
        return f"{base}.{prop}"
    return None


def _is_likely_intermediate(path: str) -> bool:
    """Object paths that should remain PathRef (not stringified into XOR yet)."""
    if path in _OBJECT_TAGS:
        return True
    # navigator / document sub-objects
    if path.startswith("window.navigator.") and path.count(".") <= 2:
        # e.g. window.navigator.userAgentData — object; deeper leaves are values
        leaf = path.rsplit(".", 1)[-1]
        value_leaves = {
            "userAgent",
            "language",
            "languages",
            "platform",
            "hardwareConcurrency",
            "deviceMemory",
            "webdriver",
            "maxTouchPoints",
            "cookieEnabled",
            "doNotTrack",
            "vendor",
            "vendorSub",
            "product",
            "productSub",
            "appVersion",
            "appCodeName",
            "appName",
            "onLine",
            "pdfViewerEnabled",
            "globalPrivacyControl",
        }
        if leaf in value_leaves:
            return False
        if path in (
            "window.navigator.userAgentData",
            "window.navigator.connection",
            "window.navigator.plugins",
            "window.navigator.mimeTypes",
            "window.navigator.mediaDevices",
            "window.navigator.serviceWorker",
            "window.navigator.credentials",
            "window.navigator.geolocation",
            "window.navigator.permissions",
            "window.navigator.scheduling",
            "window.navigator.storage",
        ):
            return True
    # react bootstrap chain up to clientBootstrap object
    if path.startswith("window.__reactRouterContext"):
        # leaves are cfConnectingIp / city / … (have values in leaves map)
        if path.endswith(
            (
                "cfConnectingIp",
                "cfIpCity",
                "userRegion",
                "cfIpLatitude",
                "cfIpLongitude",
                "cfIpCountry",
                "cfRay",
                "cfIpContinent",
                "cfIpTimezone",
                "cfIpIsEuCountry",
                "cfBotScore",
                "cfVerifiedBot",
                "cfJa3Hash",
                "cfJa4",
                "authSessionLoggingId",
                "statsigGateValues",
                "deviceId",
                "environment",
                "build",
                "user",
            )
        ):
            return False
        return True
    intermediates = {
        "window.navigator",
        "window.document",
        "window.document.documentElement",
        "window.document.body",
        "window.screen",
        "window.localStorage",
        "window.sessionStorage",
        "window.performance",
        "window.history",
        "window.crypto",
        "window.chrome",
        "window.Math",
        "window.Reflect",
        "window.Object",
    }
    return path in intermediates


def _sync_leaves_from_challenge_p(p: str, leaves: dict[str, Any]) -> None:
    """Pull UA / lang / cores / platform from challenge fingerprint p (HAR-aligned).

    JP-7 proved: browser ``t`` == btoa(opcode_stream); local VM matched the first
    ~180 raw bytes then diverged — leaf mismatches (UA platform, languages) are
    the main controllable cause. Always mirror challenge ``p`` leaves.
    """
    if not p or not (p.startswith("gAAAAAC") or p.startswith("gAAAAAB")):
        return
    try:
        payload = p[7:].split("~")[0]
        raw = base64.b64decode(payload + "=" * ((4 - len(payload) % 4) % 4))
        cfg = json.loads(raw.decode("utf-8"))
    except Exception:
        return
    if not isinstance(cfg, list) or len(cfg) < 17:
        return
    ua = cfg[4] if isinstance(cfg[4], str) else ""
    is_mac = False
    if ua:
        leaves["window.navigator.userAgent"] = ua
        leaves["window.navigator.appVersion"] = ua.replace("Mozilla/", "")
        # Platform from real UA (JP-6/7 fingerprint Mac vs Win)
        major = "146"
        try:
            import re as _re

            m = _re.search(r"Chrome/(\d+)", ua)
            if m:
                major = m.group(1)
        except Exception:
            pass
        brands = f"Chromium,{major};Google Chrome,{major};Not.A/Brand,8"
        leaves["window.navigator.userAgentData.brands"] = brands
        if "Macintosh" in ua or "Mac OS" in ua:
            is_mac = True
            leaves["window.navigator.platform"] = "MacIntel"
            leaves["window.navigator.maxTouchPoints"] = 0
            leaves["window.navigator.vendor"] = "Google Inc."
            leaves["window.navigator.vendorSub"] = ""
            leaves["window.navigator.userAgentData.platform"] = "macOS"
            # Retina default when profile did not set dpr
            if float(leaves.get("window.devicePixelRatio") or 1) < 2:
                leaves["window.devicePixelRatio"] = 2
        elif "Linux" in ua:
            leaves["window.navigator.platform"] = "Linux x86_64"
            leaves["window.navigator.userAgentData.platform"] = "Linux"
        else:
            leaves["window.navigator.platform"] = "Win32"
            leaves["window.navigator.userAgentData.platform"] = "Windows"
        leaves["window.navigator.userAgentData.mobile"] = False
    lang_short = cfg[7] if isinstance(cfg[7], str) else ""
    langs = cfg[8] if isinstance(cfg[8], str) else ""
    if langs:
        # Exact navigator.languages string from p[8] (e.g. ja,en-US,en)
        primary = langs.split(",")[0].strip()
        leaves["window.navigator.language"] = primary or lang_short
        leaves["window.navigator.languages"] = langs
    elif lang_short:
        # p[7] often bare 'ja' — Chrome fingerprint often keeps short form as language
        leaves["window.navigator.language"] = lang_short
        leaves["window.navigator.languages"] = f"{lang_short},en-US,en"
    try:
        cores = int(cfg[16])
        leaves["window.navigator.hardwareConcurrency"] = cores
    except Exception:
        pass
    # p[10] deviceMemory−N probe → keep navigator.deviceMemory in sync
    try:
        p10 = cfg[10] if isinstance(cfg[10], str) else ""
        if p10.startswith("deviceMemory") and "\u2212" in p10:
            mem_s = p10.split("\u2212", 1)[1].strip()
            if mem_s.isdigit():
                leaves["window.navigator.deviceMemory"] = int(mem_s)
        elif p10.startswith("deviceMemory") and "-" in p10:
            mem_s = p10.split("-", 1)[1].strip()
            if mem_s.isdigit():
                leaves["window.navigator.deviceMemory"] = int(mem_s)
    except Exception:
        pass
    # Re-stamp geometry after platform flip so Mac dock / Win taskbar match UA
    try:
        sw = int(leaves.get("window.screen.width") or 0)
        sh = int(leaves.get("window.screen.height") or 0)
        if sw > 0 and sh > 0:
            dpr = leaves.get("window.devicePixelRatio")
            _apply_geometry(
                leaves,
                sw,
                sh,
                is_mac=is_mac
                or ("Macintosh" in str(leaves.get("window.navigator.userAgent") or "")),
                dpr=float(dpr) if dpr is not None else None,
            )
    except Exception:
        pass
    # productSub appears in JP-6 p[10] probes
    leaves["window.navigator.productSub"] = "20030107"
    leaves["window.navigator.product"] = "Gecko"
    leaves["window.navigator.cookieEnabled"] = True
    leaves["window.navigator.webdriver"] = False
    leaves["window.navigator.onLine"] = True
    # perf now base: align with p[13]/p[17] scale if present
    try:
        if isinstance(cfg[13], (int, float)) and cfg[13] > 0:
            # performance.timeOrigin ≈ now - perf.now
            leaves["window.performance.timeOrigin"] = time.time() * 1000.0 - float(cfg[13])
    except Exception:
        pass


def solve_turnstile(
    dx: str,
    p: str,
    *,
    profile: dict | None = None,
    trace_reads: list[tuple[str, str]] | None = None,
    engine: str | None = None,
) -> str:
    """Solve ``turnstile.dx`` with challenge ``p``; return sentinel field ``t``.

    Engine (TOKENREFRESH_T_ENGINE / ``engine`` arg):
      - auto   : Node JSDOM VM if available, else pure Python (default)
      - node   : require Node subprocess
      - python : pure-Python VM only

    ``profile`` (registration fingerprint) overlays env leaves so concurrent
    workers do not race on TOKENREFRESH_SENTINEL_* process env.

    If ``trace_reads`` is a list, append (path, kind) for every property resolve:
    kind in leaf|native|pathref|unknown. (Python engine only.)
    """
    if not dx:
        return ""

    # ── Engine routing: Node (JSDOM / V8 Math.random) preferred ──
    eng = (engine or os.environ.get("TOKENREFRESH_T_ENGINE") or "auto").strip().lower()
    # force python when tracing (instrumentation only exists here)
    if trace_reads is not None:
        eng = "python"
    if eng in ("auto", "node", "js", "jsdom", "nodejs") and eng != "python":
        try:
            from .node_turnstile import (
                node_solver_available,
                solve_turnstile_node,
                t_engine as _t_eng,
            )

            want = eng if eng != "auto" else _t_eng()
            if want == "python":
                pass
            elif want == "node" or (want == "auto" and node_solver_available()):
                try:
                    return solve_turnstile_node(dx, p, profile=profile)
                except Exception as node_exc:
                    if want == "node" or eng in ("node", "js", "jsdom", "nodejs"):
                        raise RuntimeError(
                            f"node_turnstile_required_failed: {node_exc}"
                        ) from node_exc
                    # auto: fall through to Python
        except ImportError:
            if eng in ("node", "js", "jsdom", "nodejs"):
                raise RuntimeError("node_turnstile_module_missing") from None

    return _solve_turnstile_python(
        dx, p, profile=profile, trace_reads=trace_reads
    )


def _solve_turnstile_python(
    dx: str,
    p: str,
    *,
    profile: dict | None = None,
    trace_reads: list[tuple[str, str]] | None = None,
) -> str:
    """Pure-Python turnstile bytecode VM (legacy / fallback)."""
    if not dx:
        return ""
    try:
        raw = base64.b64decode(dx + "=" * ((4 - len(dx) % 4) % 4))
        decrypted = _xor_crypt(raw.decode("latin1"), p)
        program = json.loads(decrypted)
    except Exception as exc:
        raise RuntimeError(f"turnstile_decrypt_failed: {exc}") from exc

    if not isinstance(program, list):
        raise RuntimeError("turnstile_program_not_list")

    start_time = time.time()
    slots: dict[Any, Any] = {}
    # Collect emissions; prefer last non-empty (SDK may finalize late)
    emissions: list[str] = []
    leaves = dict(_env_browser_profile())
    # Persona first (screen/cores/mem), then p overwrites UA/lang/cores to match
    # the exact challenge blob used as XOR key.
    _apply_profile_to_leaves(leaves, profile)
    _sync_leaves_from_challenge_p(p, leaves)
    # If profile had screen, re-apply geometry after p-sync platform flip
    if profile and str(profile.get("screen") or "").strip():
        _apply_profile_to_leaves(
            leaves,
            {
                "screen": profile.get("screen"),
                "device_pixel_ratio": profile.get("device_pixel_ratio")
                or profile.get("dpr"),
                "user_agent": leaves.get("window.navigator.userAgent"),
            },
        )
    # Fresh statsig-shaped keys each solve unless test code pinned a list
    ls_keys = (
        list(_LOCAL_STORAGE_KEYS)
        if _LOCAL_STORAGE_KEYS is not None
        else _default_local_storage_keys()
    )

    def _trace(path: str, kind: str) -> None:
        if trace_reads is not None:
            try:
                trace_reads.append((path, kind))
            except Exception:
                pass

    def resolve_path(path: str) -> Any:
        # Turnstile iframe: parent React tree usually absent. JP-7 field 57.47 is
        # TypeError reading 'clientBootstrap' (root === undefined). Force that path.
        if path == "window.__reactRouterContext.state.loaderData.root":
            _trace(path, "undefined")
            return None
        if path in leaves:
            # Still allow non-bootstrap leaves; block clientBootstrap chain leaves
            # so we never "succeed" past the undefined root.
            if "clientBootstrap" in path:
                _trace(path, "undefined")
                return None
            _trace(path, "leaf")
            return leaves[path]
        # native function markers used as call targets / stringification
        native = {
            "window.Reflect.set": "window.Reflect.set",
            "window.Object.create": "window.Object.create",
            "window.Object.keys": "window.Object.keys",
            "window.Object.getOwnPropertyNames": "window.Object.getOwnPropertyNames",
            "window.Object.getOwnPropertyDescriptor": "window.Object.getOwnPropertyDescriptor",
            "window.performance.now": "window.performance.now",
            "window.Math.random": "window.Math.random",
            "window.document.createElement": "window.document.createElement",
            "window.document.body.appendChild": "window.document.body.appendChild",
            "window.document.body.removeChild": "window.document.body.removeChild",
            "window.document.body.prepend": "window.document.body.prepend",
            "window.document.head.appendChild": "window.document.head.appendChild",
            "window.localStorage.setItem": "window.localStorage.setItem",
            "window.localStorage.getItem": "window.localStorage.getItem",
            "window.localStorage.removeItem": "window.localStorage.removeItem",
            "window.sessionStorage.setItem": "window.sessionStorage.setItem",
            "window.sessionStorage.getItem": "window.sessionStorage.getItem",
            "window.JSON.stringify": "window.JSON.stringify",
            "window.JSON.parse": "window.JSON.parse",
            "window.Date.now": "window.Date.now",
            "window.navigator.userAgentData.getHighEntropyValues": (
                "window.navigator.userAgentData.getHighEntropyValues"
            ),
        }
        if path in native:
            _trace(path, "native")
            return native[path]
        if path in _OBJECT_TAGS or _is_likely_intermediate(path):
            _trace(path, "pathref")
            return _PathRef(path)
        # Unknown leaf: keep path string (old behavior) so XOR still gets a
        # stable token; empty string made t too short vs HAR (~780 vs ~1000).
        _trace(path, "unknown")
        return path

    def prop_get(base: Any, prop: Any) -> Any:
        # V8-style: reading property of undefined throws (caught by op-13 try/catch)
        if base is None or base == "undefined":
            raise TypeError(
                f"Cannot read properties of undefined (reading '{prop}')"
            )
        # DOM nodes created via createElement are OrderedMaps
        if isinstance(base, _OrderedMap):
            p = str(prop) if prop is not None else ""
            if p in base.values:
                return base.values[p]
            if p == "getBoundingClientRect":
                return "element.getBoundingClientRect"
            if p in ("style", "dataset", "classList", "attributes"):
                return _OrderedMap()
            if p in ("tagName", "nodeName"):
                return base.values.get("__tagName", "DIV")
            if p in (
                "offsetWidth",
                "offsetHeight",
                "clientWidth",
                "clientHeight",
                "scrollWidth",
                "scrollHeight",
            ):
                return int(base.values.get(p, 0) or 0)
            if p in ("innerHTML", "outerHTML", "textContent", "id", "className"):
                return base.values.get(p, "")
            return None
        path = _path_join(base, prop)
        if path is None:
            return None
        return resolve_path(path)

    def func_1(e: Any, t: Any) -> None:
        slots[e] = _xor_crypt(_to_str(slots.get(e)), _to_str(slots.get(t)))

    def func_2(e: Any, t: Any) -> None:
        slots[e] = t

    def func_3(e: Any) -> None:
        if isinstance(e, (bytes, bytearray)):
            emissions.append(base64.b64encode(bytes(e)).decode("ascii"))
            return
        if isinstance(e, list) and e and all(isinstance(x, int) for x in e):
            emissions.append(
                base64.b64encode(bytes(x & 0xFF for x in e)).decode("ascii")
            )
            return
        s = e if isinstance(e, str) else _to_str(e)
        emissions.append(_b64encode_str(s))

    def func_5(e: Any, t: Any) -> None:
        left = slots.get(e)
        right = slots.get(t)
        if isinstance(left, list):
            slots[e] = left + [right]
        elif isinstance(left, str) or isinstance(right, str):
            slots[e] = _to_str(left) + _to_str(right)
        elif isinstance(left, (int, float)) and isinstance(right, (int, float)):
            slots[e] = left + right
        else:
            slots[e] = "NaN"

    def func_6(e: Any, t: Any, n: Any) -> None:
        slots[e] = prop_get(slots.get(t), slots.get(n))

    def func_7(e: Any, *args: Any) -> None:
        call_args = [slots.get(a) for a in args]
        ev = slots.get(e)
        if ev == "window.Reflect.set":
            obj, key, val = call_args[0], call_args[1], call_args[2]
            if isinstance(obj, _OrderedMap):
                obj.add(str(key), val)
            elif isinstance(obj, dict):
                obj[str(key)] = val
        elif callable(ev):
            ev(*call_args)

    def func_8(e: Any, t: Any) -> None:
        slots[e] = slots.get(t)

    def func_13(e: Any, t: Any, *args: Any) -> None:
        try:
            fn = slots.get(t)
            if not callable(fn):
                raise TypeError(f"not callable: {t}")
            fn(*args)
        except Exception as exc:
            # JS Error#toString → "TypeError: message" (JP-7 field 57.47)
            slots[e] = f"{type(exc).__name__}: {exc}"

    def func_14(e: Any, t: Any) -> None:
        tv = slots.get(t)
        if isinstance(tv, str):
            try:
                slots[e] = json.loads(tv)
            except Exception:
                slots[e] = None
        else:
            slots[e] = None

    def func_15(e: Any, t: Any) -> None:
        slots[e] = _json_dumps(slots.get(t))

    def func_17(e: Any, t: Any, *args: Any) -> None:
        call_args = [slots.get(a) for a in args]
        tv = slots.get(t)
        res: Any = None
        # Normalize PathRef call targets to marker strings
        if isinstance(tv, _PathRef):
            tv = tv.path
        if tv == "window.performance.now":
            res = (time.time() - start_time) * 1000.0 + random.random()
        elif tv == "window.Date.now":
            res = int(time.time() * 1000)
        elif tv == "window.Object.create":
            res = _OrderedMap()
        elif tv in ("window.Object.keys", "window.Object.getOwnPropertyNames"):
            target = call_args[0] if call_args else None
            if target == "window.localStorage" or (
                isinstance(target, _PathRef) and target.path == "window.localStorage"
            ):
                res = list(ls_keys)
            elif isinstance(target, _OrderedMap):
                res = list(target.keys)
            elif isinstance(target, dict):
                res = list(target.keys())
            else:
                res = []
        elif tv == "window.Math.random":
            res = random.random()
        elif tv == "window.document.createElement":
            el = _OrderedMap()
            tag = str(call_args[0] if call_args else "div").upper() or "DIV"
            el.add("__tagName", tag)
            # stub layout boxes — getBoundingClientRect fills real-ish geometry
            el.add("offsetWidth", 34)
            el.add("offsetHeight", 21)
            el.add("clientWidth", 34)
            el.add("clientHeight", 21)
            res = el
        elif tv in (
            "window.document.body.appendChild",
            "window.document.body.removeChild",
            "window.document.body.prepend",
            "window.document.head.appendChild",
        ):
            # DOM no-ops — return the node arg (browser-ish)
            res = call_args[0] if call_args else None
        elif tv == "element.getBoundingClientRect":
            # JP-7 field 22.45: DOMRect for CF widget (1/32 px fractions)
            # y ≈ mid-form of viewport (browser ~0.55 * innerHeight)
            try:
                inner_h = float(leaves.get("window.innerHeight") or 980)
            except Exception:
                inner_h = 980.0
            base = max(360.0, min(inner_h - 80.0, inner_h * 0.55))
            # Snap to 1/32 CSS px like Chrome layout
            y = (int(base * 32) + random.randint(0, 31)) / 32.0
            w = 33.46875  # 33 + 15/32
            h = 21
            x = 0
            om = _OrderedMap()
            om.add("x", x)
            om.add("y", y)
            om.add("width", w)
            om.add("height", h)
            om.add("top", y)
            om.add("right", x + w)
            om.add("bottom", y + h)
            om.add("left", x)
            res = om
        elif tv in (
            "window.localStorage.setItem",
            "window.sessionStorage.setItem",
            "window.localStorage.removeItem",
            "window.sessionStorage.removeItem",
        ):
            res = None
        elif tv in ("window.localStorage.getItem", "window.sessionStorage.getItem"):
            res = None  # miss → null
        elif tv == "window.navigator.userAgentData.getHighEntropyValues":
            # Promise-like not supported — return high-entropy map as OrderedMap
            om = _OrderedMap()
            ua_s = str(leaves.get("window.navigator.userAgent") or "")
            try:
                import re as _re

                mm = _re.search(r"Chrome/(\d+(?:\.\d+){0,3})", ua_s)
                maj = mm.group(1).split(".")[0] if mm else "146"
                full_ver = mm.group(1) if mm and mm.group(1).count(".") >= 1 else f"{maj}.0.0.0"
                if full_ver.count(".") == 0:
                    full_ver = f"{full_ver}.0.0.0"
            except Exception:
                maj = "146"
                full_ver = "146.0.0.0"
            plat = str(leaves.get("window.navigator.platform") or "")
            uad_plat = str(
                leaves.get("window.navigator.userAgentData.platform") or ""
            )
            is_mac = "Mac" in plat or uad_plat == "macOS"
            # Apple Silicon still reports MacIntel; arch from profile env if set
            arch_env = (os.environ.get("TOKENREFRESH_SENTINEL_ARCH") or "").strip()
            if arch_env:
                arch = arch_env
            elif is_mac:
                arch = "arm"
            else:
                arch = "x86"
            if is_mac:
                # macOS 14/15 common in recent HARs
                pver = (os.environ.get("TOKENREFRESH_SENTINEL_PLATFORM_VERSION") or "").strip() or "15.0.0"
            else:
                # Windows 10 → 10.0.0; Win11 often 15.0.0 / 19.0.0 in CH
                pver = (os.environ.get("TOKENREFRESH_SENTINEL_PLATFORM_VERSION") or "").strip() or "15.0.0"
            om.add("architecture", arch)
            om.add("bitness", "64")
            om.add("model", "")
            om.add("platformVersion", pver)
            om.add(
                "fullVersionList",
                leaves.get("window.navigator.userAgentData.brands") or "",
            )
            om.add("uaFullVersion", full_ver if full_ver.count(".") >= 3 else f"{maj}.0.0.0")
            res = om
        elif tv == "window.JSON.stringify":
            try:
                res = _json_dumps(call_args[0] if call_args else None)
            except Exception:
                res = "undefined"
        elif tv == "window.JSON.parse":
            try:
                res = json.loads(_to_str(call_args[0]) if call_args else "")
            except Exception:
                res = None
        elif callable(tv):
            res = tv(*call_args)
        slots[e] = res

    def func_18(e: Any) -> None:
        slots[e] = _b64decode_str(_to_str(slots.get(e)))

    def func_19(e: Any) -> None:
        slots[e] = _b64encode_str(_to_str(slots.get(e)))

    def func_20(e: Any, t: Any, n: Any, *args: Any) -> None:
        if slots.get(e) == slots.get(t):
            fn = slots.get(n)
            if callable(fn):
                fn(*args)

    def func_21(*_args: Any) -> None:
        return None

    def func_23(e: Any, t: Any, *args: Any) -> None:
        if e in slots:
            fn = slots.get(t)
            if callable(fn):
                fn(*args)

    def func_24(e: Any, t: Any, n: Any) -> None:
        # Same property-get shape as op 6 in many programs
        slots[e] = prop_get(slots.get(t), slots.get(n))

    slots.update(
        {
            1: func_1,
            2: func_2,
            3: func_3,
            5: func_5,
            6: func_6,
            7: func_7,
            8: func_8,
            10: "window",
            13: func_13,
            14: func_14,
            15: func_15,
            16: p,
            17: func_17,
            18: func_18,
            19: func_19,
            20: func_20,
            21: func_21,
            22: lambda *a: None,
            23: func_23,
            24: func_24,
            25: lambda *a: None,
        }
    )

    queue: list = list(program)
    slots[9] = queue
    max_steps = 200000
    steps = 0
    # Run full program (do not break on first t) — HAR length matches last emission better
    while steps < max_steps:
        q = slots.get(9)
        if not isinstance(q, list) or not q:
            break
        instr = q.pop(0)
        steps += 1
        if not isinstance(instr, (list, tuple)) or not instr:
            continue
        op = instr[0]
        args = instr[1:]
        fn = slots.get(op)
        if not callable(fn):
            continue
        try:
            fn(*args)
        except Exception:
            continue

    if not emissions:
        raise RuntimeError(f"turnstile_no_result after {steps} steps")

    # JP-7 HAR: browser t raw length ~1001–1036 (btoa full_hex == decoded t).
    # Prefer last emission in the real band; fall back to longest in-band, then last.
    def _raw_len(b64s: str) -> int:
        try:
            pad = "=" * ((4 - len(b64s) % 4) % 4)
            return len(base64.b64decode(b64s + pad))
        except Exception:
            return 0

    # Dedupe consecutive duplicates (func_3 sometimes fires twice same payload)
    uniq: list[str] = []
    for cand in emissions:
        if not uniq or uniq[-1] != cand:
            uniq.append(cand)

    def _score(b64s: str) -> float:
        rl = _raw_len(b64s)
        # sweet spot from JP-1/2/6/7 create+validate
        score = abs(rl - 1020)
        if 980 <= rl <= 1100:
            score -= 150  # strong bonus
        elif 900 <= rl <= 1200:
            score -= 40
        if rl < 700 or rl > 1600:
            score += 900
        elif rl < 850 or rl > 1300:
            score += 250
        # slight preference for later emissions (fuller program state)
        return score

    best = uniq[-1]
    best_score = 10**9
    for i, cand in enumerate(uniq):
        # later emissions win ties
        score = _score(cand) - i * 0.01
        if score <= best_score:
            best_score = score
            best = cand
    return best
