"""Shared utilities for tokenrefresh.

This module is intentionally self-contained. It must not import helpers from
older projects such as ref, RT, or sso.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import secrets
import time
import uuid
from typing import Any
from urllib.parse import urlparse

import requests
import urllib3

from . import constants as C

urllib3.disable_warnings()


def generate_pkce() -> tuple[str, str]:
    """Return a PKCE ``(code_verifier, code_challenge)`` pair."""
    verifier = secrets.token_urlsafe(96)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def decode_jwt_segment(segment: str) -> dict:
    """Decode a JWT header/payload segment without verifying its signature."""
    raw = str(segment or "").strip()
    if not raw:
        return {}
    raw += "=" * ((4 - len(raw) % 4) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(raw.encode("ascii")).decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def token_exp(access_token: str) -> int:
    """Extract the ``exp`` claim from an access token."""
    parts = str(access_token or "").split(".")
    if len(parts) >= 2:
        try:
            return int((decode_jwt_segment(parts[1]) or {}).get("exp", 0))
        except Exception:
            return 0
    return 0


def is_short_refresh_token(rt: str) -> bool:
    """Return whether a refresh token looks like the short OpenAI OAuth form."""
    token = str(rt or "").strip()
    return bool(token and token.startswith("rt.1.") and 20 < len(token) < 300)


def extract_workspace_id_from_cookie(auth_cookie: str) -> str:
    """Extract a workspace id from the oai-client-auth-session JWT cookie."""
    raw = str(auth_cookie or "").strip()
    if not raw:
        return ""
    for segment in raw.split(".")[:3]:
        claims = decode_jwt_segment(segment)
        if not claims:
            continue
        auth = claims.get("https://api.openai.com/auth") or {}
        workspaces = auth.get("workspaces") or claims.get("workspaces") or []
        if isinstance(workspaces, list):
            for ws in workspaces:
                if isinstance(ws, dict) and ws.get("id"):
                    return str(ws["id"]).strip()
        for key in ("workspace_id", "workspaceId"):
            if claims.get(key):
                return str(claims[key]).strip()
    return ""


def extract_workspace_id_from_payload(payload: Any) -> str:
    """Recursively extract a workspace id from nested API payloads."""
    if isinstance(payload, dict):
        for key in ("workspace_id", "workspaceId", "id"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        auth = payload.get("https://api.openai.com/auth") or payload.get("auth") or {}
        if isinstance(auth, dict):
            workspaces = auth.get("workspaces") or []
            if isinstance(workspaces, list):
                for ws in workspaces:
                    if isinstance(ws, dict) and ws.get("id"):
                        return str(ws["id"]).strip()
        client = payload.get("oai-client-auth-session") or {}
        if isinstance(client, dict):
            for ws in (client.get("workspaces") or client.get("unified_sessions") or []):
                if isinstance(ws, dict) and ws.get("id"):
                    return str(ws["id"]).strip()
        for value in payload.values():
            found = extract_workspace_id_from_payload(value)
            if found:
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = extract_workspace_id_from_payload(item)
            if found:
                return found
    return ""


def extract_workspace_id_from_html(html: str) -> str:
    """Extract workspace id hints from consent HTML."""
    import re

    for pattern in (
        r'"workspace_id"\s*:\s*"([^"]+)"',
        r"'workspace_id'\s*:\s*'([^']+)'",
        r'"workspaceId"\s*:\s*"([^"]+)"',
        r'data-workspace-id="([^"]+)"',
    ):
        match = re.search(pattern, html or "")
        if match:
            return match.group(1).strip()
    return ""


def has_oauth_code(url: str) -> bool:
    return "code=" in str(url or "") and "state=" in str(url or "")


def response_json(resp) -> dict:
    if resp is None:
        return {}
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {"_text": str(getattr(resp, "text", "") or "")[:1000]}


def _retry_sleep(attempt: int) -> None:
    delay = min(8.0, C.NETWORK_RETRY_DELAY * (2 ** attempt))
    delay += random.uniform(0, 0.35)
    time.sleep(delay)


def _is_local_callback_url(url: str) -> bool:
    try:
        parsed = urlparse(str(url or ""))
        return parsed.hostname in {"127.0.0.1", "localhost"} and parsed.port is not None
    except Exception:
        return False


def _normalize_request_kwargs(kwargs: dict) -> dict:
    out = dict(kwargs)
    if "json_data" in out and "json" not in out:
        out["json"] = out.pop("json_data")
    else:
        out.pop("json_data", None)
    return out


def request_with_retry(session, method, url, retry_attempts=None, retry_statuses=None, **kwargs):
    """requests wrapper with retries and ``json_data`` compatibility."""
    attempts = int(retry_attempts or C.NETWORK_RETRY_ATTEMPTS)
    statuses = set(retry_statuses or C.RETRY_STATUS_CODES)
    req_kwargs = _normalize_request_kwargs(kwargs)
    timeout = req_kwargs.pop("timeout", 30)
    last_error = ""

    for attempt in range(max(1, attempts)):
        try:
            if _is_local_callback_url(url):
                old_proxies = dict(getattr(session, "proxies", {}) or {})
                old_trust_env = getattr(session, "trust_env", True)
                try:
                    session.proxies.clear()
                    session.trust_env = False
                    resp = session.request(method.upper(), url, timeout=timeout, **req_kwargs)
                finally:
                    session.proxies.update(old_proxies)
                    session.trust_env = old_trust_env
            else:
                resp = session.request(method.upper(), url, timeout=timeout, **req_kwargs)

            if resp.status_code in statuses and attempt < attempts - 1:
                last_error = f"HTTP {resp.status_code}"
                _retry_sleep(attempt)
                continue
            return resp, ""
        except (requests.exceptions.SSLError, requests.exceptions.ProxyError,
                requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectionError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt >= attempts - 1:
                return None, last_error
            _retry_sleep(attempt)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt >= attempts - 1:
                return None, last_error
            _retry_sleep(attempt)
    return None, last_error


def audit_fingerprint_consistency(
    profile: dict | None, *, impersonate: str = ""
) -> list[str]:
    """Zero-RTT checks: UA major ↔ TLS persona, required profile fields present."""
    issues: list[str] = []
    fp = profile or {}
    ua = str(fp.get("user_agent") or "")
    major = int(fp.get("chrome_major") or 0)
    imp = (impersonate or fp.get("impersonate") or "").strip()
    is_firefox = (
        str(fp.get("family") or fp.get("brand") or "").lower() == "firefox"
        or "Firefox/" in ua
        or imp.startswith("firefox")
    )
    if not ua:
        issues.append("missing_user_agent")
    if not is_firefox and not fp.get("sec_ch_ua"):
        issues.append("missing_sec_ch_ua")
    if not fp.get("language"):
        issues.append("missing_language")
    if not fp.get("timezone"):
        issues.append("missing_timezone")
    if is_firefox:
        if imp and not imp.startswith("firefox"):
            issues.append(f"firefox_ua_but_imp={imp}")
        if "Firefox/" not in ua:
            issues.append("firefox_family_missing_ua_token")
        return issues
    if imp:
        # Registration Chrome 150 uses the verified native TLS profile.
        tls_major = int(fp.get("tls_chrome_major") or 0)
        want = C.ua_major_for_impersonate(imp if imp != "chrome" else "chrome146")
        if imp == "chrome150":
            want = 150
        if imp == "chrome":
            want = int(getattr(C, "CHROME_MAJOR", 146) or 146)
        if major and want and major != want:
            issues.append(f"ua_tls_mismatch major={major} imp={imp} want={want}")
    if ua and major:
        import re

        m = re.search(r"Chrome/(\d+)", ua)
        if m and int(m.group(1)) != major:
            issues.append(f"ua_string_major={m.group(1)}!=chrome_major={major}")
    return issues


class SentinelTokenGenerator:
    """Local generator for OpenAI sentinel request payloads (25-field ``p``).

    Full-capture rules (抓包 139 samples, 2026-08 JP/KR/DE):
      FROZEN per registration session:
        p[0]=4000, p[2]=2**32, p[4] UA, p[7]/p[8] lang, p[14] sid uuid,
        p[15]='', p[16] cores, p[18:25]=0
      RE-ROLLED between auth steps (same id, validate→create):
        p[1] Date(), p[3] noise, p[5] sdk path (sometimes), p[9] noise,
        p[10–12] window probes, p[13] performance.now (grows)
    """

    MAX_ATTEMPTS = 500000
    # Real Chrome sentinel SDK (JP/KR 2026-08 manual HARs): always 2**32
    P2_NAVIGATOR_BITS = 4294967296

    # p[10] — minus sign is U+2212 (HAR real probe delimiter)
    _P10_POOL = (
        # high-frequency in full-capture scan
        "adAuctionComponents\u2212function adAuctionComponents() { [native code] }",
        "requestMIDIAccess\u2212function requestMIDIAccess() { [native code] }",
        "setAppBadge\u2212function setAppBadge() { [native code] }",
        "joinAdInterestGroup\u2212function joinAdInterestGroup() { [native code] }",
        "canShare\u2212function canShare() { [native code] }",
        "wakeLock\u2212[object WakeLock]",
        "getUserMedia\u2212function getUserMedia() { [native code] }",
        "credentials\u2212[object CredentialsContainer]",
        "getInterestGroupAdAuctionData\u2212function getInterestGroupAdAuctionData() { [native code] }",
        "deprecatedURNToURL\u2212function deprecatedURNToURL() { [native code] }",
        "protectedAudience\u2212[object ProtectedAudience]",
        "webkitTemporaryStorage\u2212[object DeprecatedStorageQuota]",
        "serviceWorker\u2212[object ServiceWorkerContainer]",
        "platform\u2212Win32",
        "productSub\u221220030107",
        "updateAdInterestGroups\u2212function updateAdInterestGroups() { [native code] }",
        "scheduling\u2212[object Scheduling]",
        "deprecatedRunAdAuctionEnforcesKAnonymity\u2212false",
        "cancelAnimationFrame\u2212function cancelAnimationFrame() { [native code] }",
        "requestAnimationFrame\u2212function requestAnimationFrame() { [native code] }",
        "windowControlsOverlay\u2212[object WindowControlsOverlay]",
        "navigation\u2212[object Navigation]",
        "mediaSession\u2212[object MediaSession]",
        "userAgentData\u2212[object NavigatorUAData]",
        "deviceMemory\u22128",
        "deviceMemory\u221216",
        "cookieStore\u2212[object CookieStore]",
        "launchQueue\u2212[object LaunchQueue]",
        "language\u2212ja",
    )
    # weights aligned to full-capture frequency (len must match _P10_POOL)
    _P10_WEIGHTS = (
        30,  # adAuctionComponents
        28,  # requestMIDIAccess
        10,  # setAppBadge
        8,  # joinAdInterestGroup
        6,  # canShare
        6,  # wakeLock
        5,  # getUserMedia
        5,  # credentials
        4,  # getInterestGroupAdAuctionData
        4,  # deprecatedURNToURL
        3,
        3,
        3,
        3,  # platform
        3,  # productSub
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,  # userAgentData
        2,
        2,
        1,
        1,
        2,  # language−ja
    )

    # p[12] — event / global name probes (full-capture top: ongotpointercapture, getComputedStyle, $RC)
    _P12_POOL = (
        "ongotpointercapture",
        "getComputedStyle",
        "$RC",
        "onkeydown",
        "ondurationchange",
        "oncuechange",
        "onmessageerror",
        "ononline",
        "opener",
        "onmouseup",
        "onmouseenter",
        "onkeyup",
        "onresize",
        "onscrollsnapchanging",
        "onpointercancel",
        "credentialless",
        "toolbar",
        "onsuspend",
        "onwebkitanimationiteration",
        "onplay",
        "styleMedia",
        "customElements",
        "getDigitalGoodsService",
        "__oai_so_lx",
        "__oai_so_spt",
        "__oai_so_kp",
        "__sentinel_init_pending",
    )
    _P12_WEIGHTS = (
        28,  # ongotpointercapture
        22,  # getComputedStyle
        14,  # $RC
        8,
        6,
        5,
        5,
        5,
        4,
        4,
        4,
        4,
        3,
        3,
        3,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        4,  # __sentinel_init_pending
    )

    def __init__(self, device_id: str, profile: dict | None = None):
        self.device_id = device_id
        self.sid = str(uuid.uuid4())
        self.profile = profile or {}
        self._frozen: list | None = None

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        return format(h & 0xFFFFFFFF, "08x")

    def _timezone_label(self, dt, tz_name: str) -> str:
        """Browser Date() parenthetical — localized names for JP/KR HARs."""
        lang = str(
            self.profile.get("navigator_language")
            or self.profile.get("language")
            or ""
        ).lower()
        reg = str(self.profile.get("proxy_region") or "").upper()
        fixed = {
            "Asia/Tokyo": "日本標準時",
            "Asia/Seoul": "한국 표준시",
            "America/New_York": "Eastern Daylight Time",
            "America/Los_Angeles": "Pacific Daylight Time",
            "America/Chicago": "Central Daylight Time",
            "Europe/Berlin": "Central European Summer Time",
            "Europe/London": "British Summer Time",
            "Asia/Ho_Chi_Minh": "Giờ Đông Dương",
        }
        if tz_name in fixed:
            # DST-aware-ish for US labels
            if tz_name.startswith("America/") and getattr(dt, "dst", lambda: None)():
                pass
            return fixed[tz_name]
        if reg == "JP" or lang.startswith("ja") or "Tokyo" in tz_name:
            return "日本標準時"
        if reg == "KR" or lang.startswith("ko") or "Seoul" in tz_name:
            return "한국 표준시"
        if reg == "DE" or lang.startswith("de"):
            return "Mitteleuropäische Sommerzeit"
        name = getattr(dt, "tzname", lambda: None)()
        if name and name not in ("UTC", "GMT") and not str(name).startswith("UTC"):
            return str(name)
        # avoid bare UTC+09:00 — looks synthetic vs real Chrome
        off = dt.strftime("%z") or "+0000"
        return f"GMT{off}"

    def _locale_time_string(self) -> str:
        """Browser-like Date() string bound to profile.timezone."""
        from datetime import datetime, timedelta, timezone as _tz

        tz_name = str(self.profile.get("timezone") or "").strip()
        lang = str(self.profile.get("language") or "").lower()
        try:
            from zoneinfo import ZoneInfo

            if tz_name:
                dt = datetime.now(ZoneInfo(tz_name))
            else:
                dt = datetime.now(ZoneInfo("America/New_York"))
                tz_name = "America/New_York"
        except Exception:
            if lang.startswith("en-us") or "America/" in tz_name:
                dt = datetime.now(_tz(timedelta(hours=-4)))
                tz_name = tz_name or "America/New_York"
            elif "Tokyo" in tz_name or lang.startswith("ja"):
                dt = datetime.now(_tz(timedelta(hours=9)))
                tz_name = tz_name or "Asia/Tokyo"
            elif "Seoul" in tz_name or lang.startswith("ko"):
                dt = datetime.now(_tz(timedelta(hours=9)))
                tz_name = tz_name or "Asia/Seoul"
            else:
                return time.strftime(
                    "%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)",
                    time.gmtime(),
                )
        off = dt.strftime("%z") or "+0000"
        off_js = f"GMT{off}"
        tz_label = self._timezone_label(dt, tz_name)
        return dt.strftime(f"%a %b %d %Y %H:%M:%S {off_js} ({tz_label})")

    def _navigator_language(self) -> str:
        """p[7] = navigator.language (Bit Chrome JP: ja-JP)."""
        explicit = str(self.profile.get("navigator_language") or "").strip()
        if explicit:
            return explicit
        lang = str(self.profile.get("language") or "en-US").strip() or "en-US"
        low = lang.lower()
        reg = str(self.profile.get("proxy_region") or "").upper()
        # Capture-grounded Bit Chrome JP: ja-JP (not short "ja")
        if low in ("ja", "ja-jp") or reg == "JP":
            return "ja-JP"
        if low in ("ko", "ko-kr") or reg == "KR":
            return "ko-KR"
        if low in ("de", "de-de") or reg == "DE":
            return "de-DE"
        if low.startswith("en"):
            return "en-US" if low in ("en", "en-us") else lang
        return lang

    def _languages_list(self) -> str:
        """p[8] = navigator.languages joined without q-weights.

        Prefer languages_list (array). Never expand Accept-Language q-strings
        into multi-tag navigator.languages — Bit Chrome JP is typically ["ja-JP"].
        """
        ll = self.profile.get("languages_list")
        if isinstance(ll, (list, tuple)) and ll:
            return ",".join(str(x).split(";")[0].strip() for x in ll if str(x).strip())
        langs = self.profile.get("languages")
        if isinstance(langs, (list, tuple)) and langs:
            return ",".join(str(x).split(";")[0].strip() for x in langs if str(x).strip())
        if isinstance(langs, str) and langs.strip():
            # q-weighted AL must not become navigator.languages CSV
            if "q=" in langs:
                return self._navigator_language()
            parts = []
            for part in langs.split(","):
                code = part.split(";")[0].strip()
                if code:
                    parts.append(code)
            if parts:
                # Capture-style: single primary when only one region tag intended
                return ",".join(parts)
        return self._navigator_language()

    def _pick_sdk_url(self) -> str:
        """Mix versioned + backend-api paths (both seen in real HARs)."""
        versioned = getattr(C, "SENTINEL_SDK_URL_VERSIONED", "") or (
            "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js"
        )
        backend = "https://sentinel.openai.com/backend-api/sentinel/sdk.js"
        # Full-capture: backend-api ~2:1 vs versioned
        if random.random() < 0.68:
            return backend
        return versioned

    def _p10_app_version_probe(self) -> str:
        """Real browsers often probe appVersion−<UA without Mozilla/>."""
        ua = str(self.profile.get("user_agent") or "").strip() or C.USER_AGENT
        app = ua.replace("Mozilla/", "") if ua.startswith("Mozilla/") else ua
        return "appVersion\u2212" + app

    def _roll_window_leaves(self) -> tuple[str, str, str]:
        """p[10], p[11], p[12] — re-sampled between auth steps."""
        # ~12% appVersion−UA (JP-8 heavy); else weighted pool
        if random.random() < 0.12:
            p10 = self._p10_app_version_probe()
        else:
            p10 = random.choices(self._P10_POOL, weights=self._P10_WEIGHTS, k=1)[0]
            # deviceMemory−N must match persona (t VM + p fingerprint share mem)
            if p10.startswith("deviceMemory"):
                mem = self._pick_device_memory()
                p10 = f"deviceMemory\u2212{mem}"
        # Full-capture: location is the single most common p[11]
        r = random.random()
        if r < 0.40:
            p11 = "location"
        elif r < 0.72:
            p11 = "_reactListening" + format(random.getrandbits(48), "x")[:11]
        elif r < 0.95:
            p11 = "__reactContainer$" + format(random.getrandbits(48), "x")[:10]
        else:
            p11 = "getDigitalGoodsService"
        p12 = random.choices(self._P12_POOL, weights=self._P12_WEIGHTS, k=1)[0]
        return p10, p11, p12

    def _pick_cores(self) -> int:
        """hardwareConcurrency — frozen per session; match full-capture set.

        Prefer explicit profile value; else stable hash from profile_index/device_id
        into {6,8,12,16,20,24,32} (seen across JP/KR/DE HARs).
        """
        for key in (
            "hardware_concurrency",
            "hardwareConcurrency",
            "cores",
            "navigator_hardware_concurrency",
        ):
            raw = self.profile.get(key)
            if raw is None or raw == "":
                continue
            try:
                n = int(raw)
                if n in (4, 6, 8, 10, 12, 16, 20, 24, 32):
                    return n
                if 2 <= n <= 64:
                    return n
            except (TypeError, ValueError):
                pass
        # Stable per persona (not re-rolled each generate_payload)
        seed = (
            str(self.profile.get("profile_index") or "")
            + "|"
            + str(self.device_id or "")
            + "|"
            + str(self.profile.get("screen") or "")
        )
        h = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16)
        choices = (6, 8, 12, 16, 20, 24, 32)
        # weights roughly mirror full-capture frequency
        weights = (18, 8, 12, 18, 22, 8, 6)
        # deterministic weighted pick
        total = sum(weights)
        x = h % total
        acc = 0
        for c, w in zip(choices, weights):
            acc += w
            if x < acc:
                return c
        return 12

    def _pick_device_memory(self) -> int:
        """navigator.deviceMemory (GB) — frozen; JP-7 field 56.21 uses this.

        Common Chrome values: 4 / 8 / 16. Wrong mem collapses t match hard.
        """
        for key in ("device_memory", "deviceMemory", "navigator_device_memory"):
            raw = self.profile.get(key)
            if raw is None or raw == "":
                continue
            try:
                n = int(raw)
                if n in (0, 1, 2, 4, 8, 16, 32):
                    return n if n > 0 else 8
                if 1 <= n <= 64:
                    # snap to nearest Chrome bucket
                    for b in (4, 8, 16, 32):
                        if n <= b:
                            return b
                    return 32
            except (TypeError, ValueError):
                pass
        seed = (
            str(self.profile.get("profile_index") or "")
            + "|"
            + str(self.device_id or "")
            + "|mem|"
            + str(self.profile.get("screen") or "")
        )
        h = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16)
        # 8 is dominant in HARs
        return (4, 8, 8, 8, 16)[h % 5]

    def _pick_p3(self) -> int:
        """p[3] step noise — full-capture mostly 0–21, rare 30–45."""
        if random.random() < 0.08:
            return random.randint(30, 45)
        return random.choice(
            [0, 0, 1, 1, 2, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 10, 11, 12, 14, 15, 15, 17, 20, 20, 21]
        )

    def _pick_p9(self) -> int | float:
        """p[9] noise — main mass 2–12, long tail up to ~160 (full-capture)."""
        r = random.random()
        if r < 0.72:
            return int(round(random.uniform(2, 12)))
        if r < 0.90:
            return int(round(random.uniform(12, 40)))
        if r < 0.98:
            return int(round(random.uniform(40, 120)))
        # rare half-int seen once in JP-2
        return round(random.uniform(2, 8), 1)

    def _build_frozen_config(self) -> list:
        """Identity skeleton for this registration session."""
        perf_now = random.uniform(8000, 55000)
        nav_lang = self._navigator_language()
        langs = self._languages_list()
        ua = str(self.profile.get("user_agent") or "").strip() or C.USER_AGENT
        sdk_url = self._pick_sdk_url()
        p10, p11, p12 = self._roll_window_leaves()
        cores = self._pick_cores()
        mem = self._pick_device_memory()
        # Persist on profile so turnstile leaves share the same FP
        try:
            self.profile["hardware_concurrency"] = cores
            self.profile["hardwareConcurrency"] = cores
            self.profile["device_memory"] = mem
            self.profile["deviceMemory"] = mem
        except Exception:
            pass
        elapsed = time.time() * 1000 + random.uniform(-50, 50)
        return [
            4000,
            self._locale_time_string(),
            self.P2_NAVIGATOR_BITS,  # p[2] — always 2**32 in real Chrome SDK
            0,  # 3 — re-rolled in generate_payload
            ua,
            sdk_url,
            None,
            nav_lang,  # p[7] navigator.language
            langs,  # p[8] navigator.languages
            0,  # 9 — re-rolled in generate_payload
            p10,
            p11,
            p12,
            perf_now,
            self.sid,
            "",
            cores,  # p[16] frozen
            elapsed,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]

    def prepare_new_challenge(self) -> None:
        """Between auth steps: re-roll window probes + sdk path; keep identity."""
        if self._frozen is None:
            self._frozen = self._build_frozen_config()
            return
        self._frozen[5] = self._pick_sdk_url()
        p10, p11, p12 = self._roll_window_leaves()
        self._frozen[10] = p10
        self._frozen[11] = p11
        self._frozen[12] = p12
        # performance.now() grows across the session
        try:
            prev = float(self._frozen[13] or 0)
        except (TypeError, ValueError):
            prev = 10000.0
        self._frozen[13] = prev + random.uniform(2000, 18000)

    def _get_config(self) -> list:
        """Copy of frozen skeleton with fresh Date() string (p[1])."""
        if self._frozen is None:
            self._frozen = self._build_frozen_config()
        data = list(self._frozen)
        data[1] = self._locale_time_string()
        return data

    @staticmethod
    def _b64(data: list) -> str:
        raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def generate_payload(self, prefix: str = "gAAAAAC") -> str:
        """Build challenge ``gAAAAAC…`` p (not PoW).

        PoW (``gAAAAAB…~S``) is solved separately: same frozen skeleton, but
        p[3]=attempt index and p[9]=elapsed_ms — matching JP-8 hook stringify
        sequences (0..N with rising p[9], then new probe round).
        """
        data = self._get_config()
        # Initial challenge is NOT mid-PoW: small p[3]/p[9] (full-capture first posts)
        data[3] = random.choice([0, 0, 0, 1, 1, 2, 3, 4, 5, 6])
        data[9] = int(round(random.uniform(2, 28)))
        # Keep persona cores/mem on profile so turnstile VM can share the same FP
        try:
            self.profile["hardware_concurrency"] = int(data[16])
            self.profile["hardwareConcurrency"] = int(data[16])
            mem = self._pick_device_memory()
            self.profile["device_memory"] = mem
            self.profile["deviceMemory"] = mem
        except Exception:
            pass
        return prefix + self._b64(data)


def _sentinel_browser_headers(profile: dict | None, *, for_script: bool = False) -> dict:
    fp = profile or {}
    al = str(fp.get("languages") or "").strip()
    if not al or "," not in al:
        lang = str(fp.get("language") or "en-US")
        short = lang.split("-")[0]
        al = f"{lang},{short};q=0.9,en;q=0.8"
    h = {
        "User-Agent": fp.get("user_agent") or C.USER_AGENT,
        "sec-ch-ua": fp.get("sec_ch_ua") or C.SEC_CH_UA,
        "sec-ch-ua-mobile": fp.get("sec_ch_ua_mobile") or "?0",
        "sec-ch-ua-platform": fp.get("sec_ch_ua_platform") or '"Windows"',
        "Accept-Language": al,
    }
    if for_script:
        h["Accept"] = "*/*"
        h["sec-fetch-dest"] = "script"
        h["sec-fetch-mode"] = "no-cors"
        h["sec-fetch-site"] = "same-site"
        h["Referer"] = C.SENTINEL_FRAME_REFERER
        h["Origin"] = "https://auth.openai.com"
    else:
        h["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        h["sec-fetch-dest"] = "iframe"
        h["sec-fetch-mode"] = "navigate"
        h["sec-fetch-site"] = "same-site"
        h["Referer"] = "https://auth.openai.com/"
        h["Upgrade-Insecure-Requests"] = "1"
    return h


def warm_sentinel_assets(session, profile: dict | None = None) -> None:
    """Browser loads frame.html + sdk.js before POST /sentinel/req (once per session).

    ~+0.1–0.5s on good proxy. Disable: TOKENREFRESH_SENTINEL_WARM=0.
    """
    if not getattr(C, "SENTINEL_WARM_ASSETS", True):
        return
    if getattr(session, "_sentinel_assets_warmed", False):
        return
    try:
        request_with_retry(
            session,
            "get",
            C.SENTINEL_FRAME_REFERER,
            headers=_sentinel_browser_headers(profile, for_script=False),
            timeout=min(12.0, float(C.SENTINEL_REQ_TIMEOUT)),
            verify=False,
            retry_attempts=1,
            allow_redirects=True,
        )
        request_with_retry(
            session,
            "get",
            C.SENTINEL_SDK_URL_VERSIONED,
            headers=_sentinel_browser_headers(profile, for_script=True),
            timeout=min(12.0, float(C.SENTINEL_REQ_TIMEOUT)),
            verify=False,
            retry_attempts=1,
            allow_redirects=True,
        )
    except Exception:
        pass
    try:
        session._sentinel_assets_warmed = True  # type: ignore[attr-defined]
    except Exception:
        pass


def _apply_sentinel_profile_env(profile: dict | None) -> None:
    """Align turnstile leaf env with registration fingerprint (same persona as p).

    p and t must share: UA, lang, region, screen, hardwareConcurrency, deviceMemory,
    and exit IP (same proxy as registration session).
    Prefer also passing ``profile=`` into solve_turnstile (avoids multi-worker env races).
    """
    if not profile:
        return

    def _replace_env(key: str, value: Any) -> None:
        text = str(value or "").strip()
        if text:
            os.environ[key] = text
        else:
            os.environ.pop(key, None)
    ua = str(profile.get("user_agent") or "").strip()
    if ua:
        os.environ["TOKENREFRESH_SENTINEL_UA"] = ua
    lang = str(profile.get("language") or "").strip()
    if lang:
        os.environ["TOKENREFRESH_SENTINEL_LANG"] = lang
    reg = str(profile.get("proxy_region") or "").strip().upper()
    _replace_env("TOKENREFRESH_SENTINEL_REGION", reg)
    screen = str(profile.get("screen") or "").strip().lower()
    if "x" in screen:
        try:
            w, h = screen.split("x", 1)
            os.environ["TOKENREFRESH_SENTINEL_SCREEN_W"] = str(int(w))
            os.environ["TOKENREFRESH_SENTINEL_SCREEN_H"] = str(int(h))
        except Exception:
            pass
    for key in ("hardware_concurrency", "hardwareConcurrency", "cores"):
        raw = profile.get(key)
        if raw is None or raw == "":
            continue
        try:
            os.environ["TOKENREFRESH_SENTINEL_CORES"] = str(int(raw))
            break
        except (TypeError, ValueError):
            pass
    for key in ("device_memory", "deviceMemory"):
        raw = profile.get(key)
        if raw is None or raw == "":
            continue
        try:
            os.environ["TOKENREFRESH_SENTINEL_DEVICE_MEMORY"] = str(int(raw))
            break
        except (TypeError, ValueError):
            pass
    # Exit IP / geo — same residential proxy as registration (not a default JP fake)
    eip = str(
        profile.get("exit_ip")
        or profile.get("cf_connecting_ip")
        or profile.get("cfConnectingIp")
        or ""
    ).strip()
    _replace_env("TOKENREFRESH_SENTINEL_CF_IP", eip if _looks_like_ip(eip) else "")
    city = str(profile.get("exit_city") or profile.get("cf_ip_city") or "").strip()
    _replace_env("TOKENREFRESH_SENTINEL_CF_CITY", city)
    lat = str(profile.get("exit_lat") or profile.get("cf_ip_lat") or "").strip()
    lon = str(profile.get("exit_lon") or profile.get("cf_ip_lon") or "").strip()
    _replace_env("TOKENREFRESH_SENTINEL_CF_LAT", lat)
    _replace_env("TOKENREFRESH_SENTINEL_CF_LON", lon)
    # Client Hints high-entropy (getHighEntropyValues)
    pver = str(
        profile.get("sec_ch_ua_platform_version")
        or profile.get("platform_version")
        or ""
    ).strip().strip('"')
    if pver:
        os.environ["TOKENREFRESH_SENTINEL_PLATFORM_VERSION"] = pver
    arch = str(
        profile.get("sec_ch_ua_arch") or profile.get("architecture") or ""
    ).strip().strip('"')
    if arch:
        os.environ["TOKENREFRESH_SENTINEL_ARCH"] = arch
    try:
        from . import turnstile as _ts

        _ts._PROFILE_CACHE.clear()
    except Exception:
        pass


def _normalize_country_code(value: Any) -> str:
    code = str(value or "").strip().upper()
    if len(code) == 2 and code.isascii() and code.isalpha():
        return code
    return ""


def apply_exit_ip_info_to_profile(profile: dict, info: dict | None) -> dict:
    """Attach one session's observed exit geo without changing its target region."""
    if not isinstance(info, dict) or not info.get("ip"):
        return profile
    profile["exit_ip"] = str(info.get("ip") or "").strip()
    if info.get("city"):
        profile["exit_city"] = str(info.get("city") or "").strip()
    observed_country = _normalize_country_code(
        info.get("region") or info.get("country") or info.get("country_code")
    )
    profile["exit_region"] = observed_country
    profile["observed_exit_country"] = observed_country
    if observed_country and not str(profile.get("proxy_region") or "").strip():
        profile["proxy_region"] = observed_country
    if info.get("lat"):
        profile["exit_lat"] = str(info.get("lat") or "").strip()
    if info.get("lon"):
        profile["exit_lon"] = str(info.get("lon") or "").strip()
    return profile


def bind_registration_persona(
    session: Any,
    device_id: str,
    profile: dict | None,
    *,
    probe_ip: bool = True,
) -> dict:
    """Single source of truth: registration fingerprint + exit IP for sentinel/t.

    Ensures formal-frame / turnstile VM / HTTP headers share:
      UA, screen, lang, cores, memory, oai-did, proxy-region, exit IP (via session proxy).
    """
    fp = dict(profile or {})
    did = str(device_id or "").strip()
    if did:
        fp["oai_did"] = did
        fp["device_id"] = did
    # Normalize screen string ↔ width/height
    screen = str(fp.get("screen") or "").strip().lower()
    if "x" in screen and not fp.get("screen_width"):
        try:
            w, h = screen.split("x", 1)
            fp["screen_width"] = int(w)
            fp["screen_height"] = int(h)
        except Exception:
            pass
    if not screen and fp.get("screen_width") and fp.get("screen_height"):
        fp["screen"] = f"{int(fp['screen_width'])}x{int(fp['screen_height'])}"

    # Canvas / WebGL seeded persona (user-level, consistent with UA family)
    try:
        from .gpu_persona import apply_gpu_persona_to_profile

        account_key = (
            did
            or str(fp.get("seed") or "")
            or str(fp.get("profile_id") or "")
            or str(fp.get("user_agent") or "")
        )
        apply_gpu_persona_to_profile(fp, account_key=account_key)
    except Exception:
        pass

    if probe_ip and session is not None:
        try:
            info = probe_exit_ip(session)
        except Exception:
            info = {}
        if isinstance(info, dict) and info.get("ip"):
            apply_exit_ip_info_to_profile(fp, info)

    _apply_sentinel_profile_env(fp)
    try:
        session._bound_sentinel_profile = dict(fp)  # type: ignore[attr-defined]
    except Exception:
        pass
    return fp


def validate_sentinel_t_field(t_value: str, *, flow: str = "") -> dict[str, Any]:
    """Sanity-check solved ``t`` against observed raw-byte bands.

    Bands (2026-08 full-token analysis, n≈300 Bit + gold20 protocol):
      - Chrome Bit browser: raw ≈954–1053 (p50≈999)
      - formal-frame Firefox: raw ≈700–865 (p50≈786)
    Gate accepts union; dual soft flags distinguish engines.

    Returns diagnostic dict; raises RuntimeError when TOKENREFRESH_T_GATE=1 (default)
    and t is clearly broken (empty / tiny / undefined).
    """
    t = (t_value or "").strip()
    out: dict[str, Any] = {"ok": False, "raw": 0, "b64_len": len(t), "flow": flow}
    if not t or t in ("undefined", "dW5kZWZpbmVk", "null"):
        out["reason"] = "empty_or_undefined"
        return out
    try:
        raw = base64.b64decode(t + "=" * ((4 - len(t) % 4) % 4))
    except Exception:
        out["reason"] = "b64_decode_fail"
        return out
    out["raw"] = len(raw)
    printable = sum(32 <= b < 127 for b in raw) / max(1, len(raw))
    out["print_pct"] = round(100.0 * printable, 1)
    # Accept wider gate for VM variance; reject only obviously dead tokens.
    if len(raw) < 200:
        out["reason"] = f"too_short_raw={len(raw)}"
        return out
    if len(raw) > 4000:
        out["reason"] = f"too_long_raw={len(raw)}"
        return out
    out["ok"] = True
    out["reason"] = "ok"
    n = len(raw)
    # Flow-aware bands (2026-08 Bit gold, full fixtures):
    #   oauth register flows (email-otp/validate, create_account, authorize):
    #     t raw 901-1093 (n=191 full fixtures; auth.openai.com realm localStorage
    #     is EMPTY per JP-8 storage_snap_boot → no oai/apps keys inflation)
    #   chat-requirements finalize: t raw 1739-2473 (n=5 same-session pairs;
    #     chatgpt.com top realm carries ~16 localStorage keys ≈ +700 chars)
    is_oauth = bool(re.search(r"email[-_]otp|create[-_]account|authorize|oauth", flow, re.I))
    is_firefox = bool(
        re.search(r"firefox|ff|eda|formal-frame", os.environ.get("TOKENREFRESH_FP_FAMILY") or "", re.I)
    )
    if is_firefox:
        out["in_har_band"] = 700 <= n <= 865 and 50.0 <= out["print_pct"] <= 90.0
        out["in_browser_bit_band"] = False
        out["in_protocol_formal_band"] = 700 <= n <= 865  # formal-frame Firefox gold
    elif is_oauth:
        out["in_har_band"] = 900 <= n <= 1100 and 50.0 <= out["print_pct"] <= 90.0
        out["in_browser_bit_band"] = 900 <= n <= 1100  # Bit oauth gold
        out["in_protocol_formal_band"] = False
    else:
        # chat-requirements / default: Bit chat-finalize gold
        out["in_har_band"] = 1700 <= n <= 2500 and 50.0 <= out["print_pct"] <= 90.0
        out["in_browser_bit_band"] = 1700 <= n <= 2500
        out["in_protocol_formal_band"] = False
    # Persona-expected band (FP family), for soft/hard match gate
    fp_family = (os.environ.get("TOKENREFRESH_FP_FAMILY") or "").strip().lower()
    if fp_family in ("firefox", "ff", "eda", "formal-frame", "firefox144"):
        out["expected_band"] = "protocol_formal"
        out["in_expected_band"] = bool(out["in_protocol_formal_band"])
    else:
        # chrome / default — Bit capture gold
        out["expected_band"] = "browser_bit"
        out["in_expected_band"] = bool(out["in_browser_bit_band"])
    return out


def apply_t_band_match_gate(t_diag: dict[str, Any], *, flow: str = "") -> None:
    """Optional persona t-band enforcement.

    TOKENREFRESH_T_BAND_MATCH:
      off/0     — no-op
      soft/1    — log-only via raised SoftBandNote? no: caller logs; we only annotate
      hard      — raise RuntimeError when t not in expected persona band
    """
    mode = (os.environ.get("TOKENREFRESH_T_BAND_MATCH") or "").strip().lower()
    if mode in ("", "0", "off", "false", "no", "none"):
        return
    if not t_diag.get("ok"):
        return
    if t_diag.get("in_expected_band"):
        return
    msg = (
        f"t_band_mismatch flow={flow} raw={t_diag.get('raw')} "
        f"expected={t_diag.get('expected_band')} "
        f"browser_bit={t_diag.get('in_browser_bit_band')} "
        f"protocol_formal={t_diag.get('in_protocol_formal_band')}"
    )
    t_diag["band_match_msg"] = msg
    if mode in ("hard", "strict", "fail", "error"):
        raise RuntimeError(msg)


# HAR create_account SO bands (Bit Chrome 2026-08); Ag== = btoa("\x02") slot collapse
_SO_B64_LO, _SO_B64_HI = 504, 600
_BTOA_02 = base64.b64encode(b"\x02").decode()  # Ag==


def validate_sentinel_so_field(so_value: str, *, flow: str = "") -> dict[str, Any]:
    """Sanity-check session-observer ``so`` body (inner field, not full header JSON).

    Real HAR create so: b64 ≈504–600. Historical formal bug: b64≈96
    ``btoa("0: SyntaxError: Unexpected token...")`` when snapshot ran without
    collector key / InjectSoActivity.
    """
    so = (so_value or "").strip()
    out: dict[str, Any] = {
        "ok": False,
        "b64_len": len(so),
        "raw": 0,
        "flow": flow,
        "looks_error": False,
        "ag_eq_count": 0,
        "head12": so[:12],
        "in_har_band": False,
    }
    if not so or so in ("undefined", "dW5kZWZpbmVk", "null"):
        out["reason"] = "empty_or_undefined"
        out["looks_error"] = True
        return out
    try:
        raw = base64.b64decode(so + "=" * ((4 - len(so) % 4) % 4))
    except Exception:
        out["reason"] = "b64_decode_fail"
        out["looks_error"] = True
        return out
    out["raw"] = len(raw)
    out["ag_eq_count"] = so.count(_BTOA_02) + raw.count(_BTOA_02.encode())
    try:
        as_text = raw.decode("utf-8", errors="replace")
    except Exception:
        as_text = ""
    if re.search(
        r"SyntaxError|Unexpected token|session_observer_vm_timeout|is not valid JSON",
        as_text,
        re.I,
    ):
        out["reason"] = "vm_error_shaped_so"
        out["looks_error"] = True
        return out
    if len(so) < 200:
        out["reason"] = f"too_short_b64={len(so)}"
        out["looks_error"] = True
        return out
    out["in_har_band"] = _SO_B64_LO <= len(so) <= _SO_B64_HI
    out["ok"] = True
    out["reason"] = "ok" if out["in_har_band"] else f"len_outside_har_band b64={len(so)}"
    # soft: still ok=True for structural non-error so outside band (measure via scorecard)
    if not out["in_har_band"]:
        out["ok"] = len(so) >= 200  # non-error but length soft
    return out


def _gate_sentinel_main_token(main_json: str, *, flow: str = "") -> None:
    """Parse openai-sentinel-token JSON and enforce t quality when gated."""
    gate = (os.environ.get("TOKENREFRESH_T_GATE") or "1").strip().lower()
    if gate in ("0", "false", "no", "off"):
        return
    try:
        obj = json.loads(main_json)
    except Exception as exc:
        raise RuntimeError(f"sentinel_token_not_json: {exc}") from exc
    if not isinstance(obj, dict):
        raise RuntimeError("sentinel_token_not_object")
    t = str(obj.get("t") or "")
    diag = validate_sentinel_t_field(t, flow=flow)
    if not diag.get("ok"):
        raise RuntimeError(
            f"sentinel_t_gate_fail flow={flow} reason={diag.get('reason')} "
            f"b64_len={diag.get('b64_len')} raw={diag.get('raw')}"
        )


def record_sentinel_t_diag(
    session: Any,
    *,
    main_json: str = "",
    flow: str = "",
    engine: str = "",
    profile: dict | None = None,
    extra: dict | None = None,
) -> dict[str, Any]:
    """Attach t diagnostics on session for later export into register phases.

    Stored as:
      session._sentinel_t_diags  — list of per-flow records (validate/create/…)
      session._sentinel_t_last   — last record
    Does not store full t/p (too large / sensitive); only metrics + short hashes.
    """
    fp = dict(profile or {})
    rec: dict[str, Any] = {
        "flow": str(flow or ""),
        "engine": str(engine or ""),
        "exit_ip": str(fp.get("exit_ip") or "")[:48],
        "exit_city": str(fp.get("exit_city") or "")[:40],
        "exit_region": str(fp.get("exit_region") or "")[:8],
        "observed_exit_country": str(fp.get("observed_exit_country") or "")[:8],
        "proxy_region": str(fp.get("proxy_region") or "")[:8],
        "device_id": str(fp.get("oai_did") or fp.get("device_id") or "")[:36],
        "ua_head": str(fp.get("user_agent") or "")[:64],
        "screen": str(fp.get("screen") or ""),
        "profile_index": fp.get("profile_index"),
        "webgl_renderer": str(fp.get("webgl_renderer") or "")[:72],
        "canvas_hash": str(fp.get("canvas_hash") or "")[:16],
        "gpu_persona_seed": str(fp.get("gpu_persona_seed") or "")[:16],
    }
    t = ""
    p = ""
    tok_id = ""
    c_head = ""
    if main_json:
        try:
            obj = json.loads(main_json)
            if isinstance(obj, dict):
                t = str(obj.get("t") or "")
                p = str(obj.get("p") or "")
                tok_id = str(obj.get("id") or "")
                c = str(obj.get("c") or "")
                c_head = c[:24] if c else ""
                rec["token_flow"] = str(obj.get("flow") or "")
        except Exception as exc:
            rec["parse_err"] = str(exc)[:80]
    t_diag = validate_sentinel_t_field(t, flow=flow)
    rec.update(
        {
            "t_ok": bool(t_diag.get("ok")),
            "t_reason": t_diag.get("reason"),
            "t_b64_len": t_diag.get("b64_len"),
            "t_raw": t_diag.get("raw"),
            "t_print_pct": t_diag.get("print_pct"),
            "t_in_har_band": t_diag.get("in_har_band"),
            "t_in_browser_bit_band": t_diag.get("in_browser_bit_band"),
            "t_in_protocol_formal_band": t_diag.get("in_protocol_formal_band"),
            "t_expected_band": t_diag.get("expected_band"),
            "t_in_expected_band": t_diag.get("in_expected_band"),
            "t_sha12": (
                __import__("hashlib").sha256(t.encode("utf-8", errors="replace")).hexdigest()[:12]
                if t
                else ""
            ),
            "p_b64_len": len(p),
            "p_sha12": (
                __import__("hashlib").sha256(p.encode("utf-8", errors="replace")).hexdigest()[:12]
                if p
                else ""
            ),
            "token_id": tok_id[:36],
            "c_head": c_head,
            "id_match_device": bool(tok_id and tok_id == str(fp.get("oai_did") or fp.get("device_id") or "")),
            "fp_family": (os.environ.get("TOKENREFRESH_FP_FAMILY") or "")[:24],
        }
    )
    if extra:
        for k, v in extra.items():
            if k not in rec:
                rec[k] = v
    try:
        hist = getattr(session, "_sentinel_t_diags", None)
        if not isinstance(hist, list):
            hist = []
        hist.append(rec)
        # keep last few flows only
        session._sentinel_t_diags = hist[-12:]  # type: ignore[attr-defined]
        session._sentinel_t_last = rec  # type: ignore[attr-defined]
    except Exception:
        pass
    return rec


def _looks_like_ip(ip: str) -> bool:
    ip = (ip or "").strip()
    if not ip or len(ip) < 7 or len(ip) > 45:
        return False
    # IPv4
    if ip.count(".") == 3:
        parts = ip.split(".")
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except Exception:
            return False
    # rough IPv6
    return ":" in ip and any(c.isdigit() for c in ip)


def probe_exit_ip(session, *, force: bool = False) -> dict[str, str]:
    """Fast exit-IP probe through session proxy (cached on session).

    Uses a **hard wall-clock budget** (default 1.5s) so failed endpoints cannot
    stack into multi-second delays. Prefer endpoints known to work via residential
    proxies (ip-api HTTP JSON). Region/city optional.

    Disable: TOKENREFRESH_SENTINEL_PROBE_IP=0
    Budget:  TOKENREFRESH_SENTINEL_PROBE_BUDGET (default 1.5)
    """
    out = {"ip": "", "city": "", "region": "", "lat": "", "lon": ""}
    flag = (os.environ.get("TOKENREFRESH_SENTINEL_PROBE_IP") or "1").strip().lower()
    if flag in ("0", "false", "no", "off"):
        return out

    if force:
        try:
            delattr(session, "_exit_ip_info")
        except Exception:
            pass
    else:
        cached = getattr(session, "_exit_ip_info", None)
        if isinstance(cached, dict) and cached.get("ip"):
            return dict(cached)

    trust_env = (
        os.environ.get("TOKENREFRESH_SENTINEL_TRUST_ENV_IP") or ""
    ).strip().lower() in ("1", "true", "yes", "on")
    if (
        not force
        and trust_env
        and (os.environ.get("TOKENREFRESH_SENTINEL_CF_IP") or "").strip()
    ):
        out["ip"] = (os.environ.get("TOKENREFRESH_SENTINEL_CF_IP") or "").strip()
        out["city"] = (os.environ.get("TOKENREFRESH_SENTINEL_CF_CITY") or "").strip()
        out["region"] = (os.environ.get("TOKENREFRESH_SENTINEL_REGION") or "").strip()
        out["lat"] = (os.environ.get("TOKENREFRESH_SENTINEL_CF_LAT") or "").strip()
        out["lon"] = (os.environ.get("TOKENREFRESH_SENTINEL_CF_LON") or "").strip()
        try:
            session._exit_ip_info = dict(out)  # type: ignore[attr-defined]
        except Exception:
            pass
        return out

    # Residential SOCKS RTT to public IP services is often ~2–3s (measured on
    # arxlabs JP). Cap total budget; single primary hop only.
    budget = float(os.environ.get("TOKENREFRESH_SENTINEL_PROBE_BUDGET") or "3.0")
    deadline = time.time() + max(0.5, budget)

    def _remaining() -> float:
        return max(0.05, deadline - time.time())

    def _get_text(url: str) -> str:
        rem = _remaining()
        if rem < 0.1:
            return ""
        try:
            resp, _err = request_with_retry(
                session,
                "get",
                url,
                timeout=rem,  # one shot: don't leave budget on the table
                retry_attempts=1,
                verify=False,
            )
        except Exception:
            return ""
        if resp is None or int(getattr(resp, "status_code", 0) or 0) != 200:
            return ""
        return (getattr(resp, "text", None) or "").strip()

    # Primary: one response binds the observed IP and country.
    raw = _get_text(
        "http://ip-api.com/json/?fields=status,query,city,countryCode,lat,lon"
    )
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            ip = str(data.get("query") or "").strip()
            if _looks_like_ip(ip):
                out["ip"] = ip
                out["city"] = str(data.get("city") or "").strip()
                out["region"] = _normalize_country_code(data.get("countryCode"))
                if data.get("lat") is not None:
                    out["lat"] = str(data.get("lat"))
                if data.get("lon") is not None:
                    out["lon"] = str(data.get("lon"))
        except Exception:
            pass

    # Low-latency fallback: retain an observed IP when geo JSON fails.
    if not out["ip"] and _remaining() > 0.4:
        text = _get_text("http://api.ipify.org")
        if text:
            ip = text.split()[0].strip().strip(",")
            if _looks_like_ip(ip):
                out["ip"] = ip
    if out["ip"]:
        try:
            session._exit_ip_info = dict(out)  # type: ignore[attr-defined]
        except Exception:
            pass
    return out


def _resolve_t_value(
    turnstile: dict,
    challenge_p: str,
    profile: dict | None = None,
) -> str:
    """Solve or inject t per TOKENREFRESH_T_MODE (normal|empty|garbage)."""
    mode = (getattr(C, "SENTINEL_T_MODE", None) or os.environ.get("TOKENREFRESH_T_MODE") or "normal")
    mode = str(mode).strip().lower()
    if mode in ("empty", "none", "off"):
        return ""
    if mode in ("garbage", "junk", "random"):
        # Binary-ish blob similar length to HAR t (~1kB decoded) for A/B only
        raw = secrets.token_bytes(random.randint(900, 1100))
        return base64.b64encode(raw).decode("ascii")
    from .turnstile import solve_turnstile

    if not turnstile.get("required") or not turnstile.get("dx"):
        return ""
    t_value = solve_turnstile(str(turnstile["dx"]), challenge_p, profile=profile)
    if t_value in ("undefined", "dW5kZWZpbmVk"):
        raise RuntimeError("turnstile_solved_undefined")
    return t_value


def build_sentinel_bundle(
    session, device_id, flow, profile=None
) -> dict[str, str]:
    """Build browser-like Sentinel header map for auth.openai.com.

    Returns keys among:
      - openai-sentinel-token   {p,t,c,id,flow}
      - openai-sentinel-so-token {so,c,id,flow}  when server sets so.required

    Default engine: **formal-frame** (Eda Firefox dual-realm Node/JSDOM).
    Set TOKENREFRESH_SENTINEL_ENGINE=legacy for the old leaf/pathref path.

    **Persona binding (mandatory):** ``t`` is computed under the same registration
    fingerprint + exit IP as HTTP (UA/screen/lang/did/proxy), never a free-floating env.
    """
    # Bind once: profile + device_id + exit IP through this session's proxy
    bound = bind_registration_persona(session, str(device_id or ""), profile, probe_ip=True)
    profile = bound

    # ── formal-frame (Firefox pool + dual-realm) ──────────────────────────
    try:
        from .formal_frame import formal_frame_enabled, build_formal_bundle

        if formal_frame_enabled():
            headers = build_formal_bundle(
                session, device_id, flow, profile=profile
            )
            main = headers.get("openai-sentinel-token") or ""
            if main:
                _gate_sentinel_main_token(main, flow=str(flow or ""))
            try:
                from .formal_frame import SDK_VERSION as _SV
            except Exception:
                _SV = ""
            record_sentinel_t_diag(
                session,
                main_json=main,
                flow=str(flow or ""),
                engine="formal-frame",
                profile=profile,
                extra={
                    "so_present": bool(headers.get("openai-sentinel-so-token")),
                    "sdk_version": _SV,
                },
            )
            return headers
    except Exception as _ff_exc:
        # still try to record failure context
        try:
            record_sentinel_t_diag(
                session,
                main_json="",
                flow=str(flow or ""),
                engine="formal-frame",
                profile=profile,
                extra={"error": str(_ff_exc)[:160]},
            )
        except Exception:
            pass
        # Explicit formal-only: do not silently degrade (ban-risk signal)
        eng = (os.environ.get("TOKENREFRESH_SENTINEL_ENGINE") or "formal-frame").strip().lower()
        if eng not in ("legacy", "leaf", "python", "old", "0", "off"):
            raise RuntimeError(f"formal_frame_sentinel_failed: {_ff_exc}") from _ff_exc

    from .turnstile import solve_turnstile

    # Align VM browser leaves with this registration persona (UA/lang/cores/IP → t)
    _apply_sentinel_profile_env(profile)
    # JP HARs: so.collector_dx often yields undefined; snapshot_dx is the real SO path
    # (enforced in solve preference below via build so loop order).

    # 1) 最小前端链：frame + sdk（会话内只一次）
    warm_sentinel_assets(session, profile)

    # Reuse generator across validate → create so sid/cores/lang stay stable;
    # re-roll window probes (p10–12) between steps like real browser HARs.
    did = str(device_id)
    gen = getattr(session, "_sentinel_token_gen", None)
    if (
        gen is None
        or getattr(gen, "device_id", None) != did
        or not isinstance(gen, SentinelTokenGenerator)
    ):
        gen = SentinelTokenGenerator(did, profile=profile)
        try:
            session._sentinel_token_gen = gen
        except Exception:
            pass
    else:
        gen.profile = profile or gen.profile
        gen.prepare_new_challenge()
    challenge_p = gen.generate_payload()
    # After p is built, cores/mem are frozen on gen.profile — push so t VM matches
    if profile is not None:
        for k in (
            "hardware_concurrency",
            "hardwareConcurrency",
            "device_memory",
            "deviceMemory",
        ):
            if gen.profile.get(k) is not None:
                profile[k] = gen.profile[k]
        # Keep screen from persona (generator never overwrites it)
        if not profile.get("screen") and gen.profile.get("screen"):
            profile["screen"] = gen.profile.get("screen")
        _apply_sentinel_profile_env(profile)
    # Effective persona for VM (gen.profile has frozen cores/mem even if profile None)
    vm_profile = profile if profile is not None else getattr(gen, "profile", None)
    plat = (profile or {}).get("sec_ch_ua_platform") or '"Windows"'
    resp, error = request_with_retry(
        session, "post", C.SENTINEL_REQ_URL,
        data=json.dumps({"p": challenge_p, "id": device_id, "flow": flow}),
        headers={
            "Content-Type": "text/plain;charset=UTF-8",
            "Referer": C.SENTINEL_FRAME_REFERER,
            "Origin": "https://sentinel.openai.com",
            "User-Agent": (profile or {}).get("user_agent", C.USER_AGENT),
            "sec-ch-ua": (profile or {}).get("sec_ch_ua", C.SEC_CH_UA),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": plat,
            "Accept": "*/*",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        },
        timeout=C.SENTINEL_REQ_TIMEOUT,
        verify=False,
    )
    if resp is None:
        raise RuntimeError(f"sentinel_req_failed: {error}")

    data = response_json(resp)
    token = str(data.get("token") or "").strip()
    if resp.status_code != 200 or not token:
        raise RuntimeError(f"sentinel_req_failed_{getattr(resp, 'status_code', '')}")

    # PoW: browser freezes fingerprint leaves; only p[3]/p[9] walk each attempt.
    # JP-8 mem-hook stringify sequence (57 samples):
    #   p[3]=0,1,2,…  p[9]≈elapsed_ms rising  p[10–12]/p[13] fixed per round
    #   then new probe round: p[3] resets, p[10]/p[12]/p[13] change
    p_value = challenge_p
    pow_data = data.get("proofofwork") or {}
    if pow_data.get("required") and pow_data.get("seed"):
        seed = str(pow_data["seed"])
        difficulty = str(pow_data.get("difficulty", "0"))
        start_t = time.time()
        # Fresh probe set for this PoW round (browser re-samples window keys)
        gen.prepare_new_challenge()
        config = gen._get_config()
        solved = False
        for idx in range(gen.MAX_ATTEMPTS):
            # Every ~28 attempts, re-roll probes like browser multi-round PoW
            if idx > 0 and idx % 28 == 0:
                gen.prepare_new_challenge()
                config = gen._get_config()
                start_t = time.time()
            config[3] = idx % 28  # browser-like counter within a probe round
            config[9] = max(1, round((time.time() - start_t) * 1000))
            payload = gen._b64(config)
            if gen._fnv1a_32(seed + payload)[: len(difficulty)] <= difficulty:
                p_value = "gAAAAAB" + payload + "~S"
                solved = True
                break
        if not solved:
            p_value = challenge_p

    # Turnstile t — normal VM / empty / garbage (TOKENREFRESH_T_MODE)
    t_value = ""
    turnstile = data.get("turnstile") or {}
    if turnstile.get("required") and turnstile.get("dx"):
        try:
            t_value = _resolve_t_value(turnstile, challenge_p, profile=vm_profile)
        except Exception as exc:
            raise RuntimeError(f"turnstile_solve_failed: {exc}") from exc
    elif (getattr(C, "SENTINEL_T_MODE", "normal") or "normal").lower() in (
        "garbage", "junk", "random",
    ):
        t_value = _resolve_t_value(
            {"required": True, "dx": "x"}, challenge_p, profile=vm_profile
        )

    # Gate broken t before shipping create/validate
    if t_value or (turnstile.get("required") and turnstile.get("dx")):
        diag = validate_sentinel_t_field(t_value, flow=str(flow or ""))
        gate = (os.environ.get("TOKENREFRESH_T_GATE") or "1").strip().lower()
        if gate not in ("0", "false", "no", "off") and not diag.get("ok"):
            raise RuntimeError(
                f"sentinel_t_gate_fail flow={flow} reason={diag.get('reason')} "
                f"raw={diag.get('raw')}"
            )

    headers: dict[str, str] = {
        "openai-sentinel-token": json.dumps(
            {"p": p_value, "t": t_value, "c": token, "id": device_id, "flow": flow},
            separators=(",", ":"),
        ),
    }

    # Session-observer / SO token (HAR create_account always pairs both headers).
    # JP-7: browser SO comes from snapshot_dx; collector_dx → local "undefined" (skip).
    so_meta = data.get("so") if isinstance(data.get("so"), dict) else {}
    if so_meta.get("required"):
        so_str = ""
        so_cands: list[str] = []
        for dx_key in ("snapshot_dx", "collector_dx"):
            dx = str(so_meta.get(dx_key) or "").strip()
            if not dx:
                continue
            try:
                cand = solve_turnstile(dx, challenge_p, profile=vm_profile)
            except Exception:
                continue
            if not cand or cand in ("undefined", "dW5kZWZpbmVk"):
                continue
            so_cands.append(cand)
        # Prefer length band seen in JP HAR so (~420–620 b64 chars)
        if so_cands:
            def _so_score(s: str) -> float:
                n = len(s)
                score = abs(n - 500)
                if 400 <= n <= 650:
                    score -= 200
                if n < 50:
                    score += 500
                return score

            so_str = min(so_cands, key=_so_score)
        if so_str:
            headers["openai-sentinel-so-token"] = json.dumps(
                {"so": so_str, "c": token, "id": device_id, "flow": flow},
                separators=(",", ":"),
            )

    record_sentinel_t_diag(
        session,
        main_json=headers.get("openai-sentinel-token") or "",
        flow=str(flow or ""),
        engine="legacy",
        profile=vm_profile if isinstance(vm_profile, dict) else profile,
        extra={"so_present": bool(headers.get("openai-sentinel-so-token"))},
    )
    return headers


def build_sentinel_token(session, device_id, flow, profile=None) -> str:
    """Backward-compatible: only the main openai-sentinel-token JSON string."""
    return build_sentinel_bundle(session, device_id, flow, profile=profile)[
        "openai-sentinel-token"
    ]


def apply_sentinel_headers(headers: dict, session, device_id, flow, profile=None) -> dict:
    """Merge full Sentinel header set into ``headers`` (mutates and returns it)."""
    bundle = build_sentinel_bundle(session, device_id, flow, profile=profile)
    headers.update(bundle)
    return headers


def exchange_code(code, code_verifier, redirect_uri, client_id, proxy_url, session=None):
    """Exchange an OAuth authorization code for access/refresh tokens."""
    if not code:
        return None
    close_session = False
    if session is None:
        from .session import create_session_with_proxy
        session = create_session_with_proxy(proxy_url)
        close_session = True
    try:
        resp, _ = request_with_retry(
            session, "post", f"{C.AUTH_BASE}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": code_verifier,
            },
            verify=False,
            timeout=60,
        )
        if resp is None:
            return None
        data = response_json(resp)
        if resp.status_code != 200 or not data.get("access_token") or not data.get("refresh_token"):
            return None
        return {
            "access_token": str(data.get("access_token") or "").strip(),
            "refresh_token": str(data.get("refresh_token") or "").strip(),
            "session_token": str(data.get("session_token") or "").strip(),
        }
    finally:
        if close_session:
            try:
                session.close()
            except Exception:
                pass


def save_debug(email: str, stage: str, payload: Any, status_code: Any = "",
               extra: dict | None = None) -> None:
    """Save a debug payload when TOKENREFRESH_DEBUG_DIR is configured."""
    if not C.DEBUG_DIR:
        return
    os.makedirs(C.DEBUG_DIR, exist_ok=True)
    safe = str(email or "account").replace("@", "_at_").replace(".", "_")
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(C.DEBUG_DIR, f"{safe}__{stage}__{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "stage": stage,
                "status_code": str(status_code),
                "payload": payload,
                "extra": extra or {},
            },
            f,
            ensure_ascii=False,
            indent=2,
            default=str,
        )


def log_line(msg: str) -> None:
    print(f"[tokenrefresh] {msg}", flush=True)
