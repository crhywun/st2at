"""Eda-aligned Firefox pool + formal-frame dual-realm Sentinel.

Ports the production contract from outlookEmail registrar:
  - Firefox 144 sticky pool (email → profile index)
  - Node/JSDOM formal-frame topology (parent + sentinel iframe)
  - requirements p from captured SDK, finalize t/so in dual-realm

Default on: TOKENREFRESH_SENTINEL_ENGINE=formal-frame
Fallback:   TOKENREFRESH_SENTINEL_ENGINE=legacy (old leaf/pathref path)
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import uuid
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
RUNTIME_DIR = ROOT / "formal_runtime"
RUNTIME_PATH = RUNTIME_DIR / "sentinel_protocol_runtime.js"
MANIFEST_PATH = RUNTIME_DIR / "sdk_manifest.json"
LIFECYCLE_PATH = (
    RUNTIME_DIR / "captures" / "sentinel_frame_lifecycle_desktop_pageassets_20260715.json"
)
FIREFOX_POOL_PATH = RUNTIME_DIR / "firefox-v1.json"

# The manifest is the source of truth for the vendored SDK.  Keep this value
# only as a diagnostic default for constants imported before the manifest is
# read; load_sdk_manifest() never falls back to it when assets are missing.
_DEFAULT_SDK_VERSION = "20260810913b"
SDK_BOOTSTRAP_URL = "https://sentinel.openai.com/backend-api/sentinel/sdk.js"
SDK_VERSION = _DEFAULT_SDK_VERSION
SDK_VERSION_URL = f"https://sentinel.openai.com/sentinel/{SDK_VERSION}/sdk.js"
SDK_PATH = RUNTIME_DIR / "captures" / f"auth_sentinel_sdk_{SDK_VERSION}.js"
SENTINEL_FRAME_URL = (
    f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SDK_VERSION}"
)
SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"


class FormalFrameError(RuntimeError):
    """Raised when the local formal-frame contract cannot be trusted."""


def _manifest_failure(message: str) -> FormalFrameError:
    return FormalFrameError(f"sentinel sdk manifest invalid: {message}")


def navigator_languages_from_profile(fp: dict[str, Any] | None) -> list[str]:
    """navigator.languages for formal-frame / SDK getConfig.

    Never expand Accept-Language q-weighted strings into multi-tag lists.
    Bit Chrome JP captures use a single primary tag (e.g. [\"ja-JP\"]).
    """
    fp = fp or {}
    ll = fp.get("languages_list")
    if isinstance(ll, (list, tuple)) and ll:
        return [str(x).split(";")[0].strip() for x in ll if str(x).strip()]
    langs = fp.get("languages")
    if isinstance(langs, (list, tuple)) and langs:
        return [str(x).split(";")[0].strip() for x in langs if str(x).strip()]
    if isinstance(langs, str) and langs.strip():
        # q-weighted HTTP AL must not become navigator.languages
        if "q=" in langs:
            primary = str(fp.get("navigator_language") or fp.get("language") or "ja-JP")
            return [primary]
        parts = [p.split(";")[0].strip() for p in langs.split(",") if p.strip()]
        if parts:
            return parts
    primary = str(fp.get("navigator_language") or fp.get("language") or "ja-JP")
    return [primary]


def _sentinel_dump_enabled() -> bool:
    return (os.environ.get("TOKENREFRESH_SENTINEL_DUMP") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _sentinel_dump_dir() -> Path:
    raw = (os.environ.get("TOKENREFRESH_SENTINEL_DUMP_DIR") or "").strip()
    if raw:
        return Path(raw)
    # Prefer analysis/protocol_emit (byte-compare corpus) then debug/
    for cand in (
        ROOT.parents[2] / "runs" / "analysis" / "protocol_emit",  # monorepo root
        ROOT.parents[1] / "runs" / "analysis" / "protocol_emit",
        Path.cwd() / "runs" / "analysis" / "protocol_emit",
        ROOT.parents[2] / "runs" / "debug" / "sentinel_emit",
        ROOT.parents[1] / "runs" / "debug" / "sentinel_emit",
        Path.cwd() / "runs" / "debug" / "sentinel_emit",
    ):
        try:
            if cand.parent.parent.is_dir() or cand.parent.is_dir():
                return cand
        except Exception:
            pass
    return Path.cwd() / "runs" / "analysis" / "protocol_emit"


def dump_sentinel_emit(
    *,
    flow: str,
    device_id: str,
    req_body: dict[str, Any] | str,
    headers: dict[str, str],
    sdk_version: str = "",
    t_diag: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Write protocol-emitted sentinel artifacts for offline capture compare.

    Controlled by TOKENREFRESH_SENTINEL_DUMP=1 and optional DUMP_DIR.
    Returns path written or "" if disabled/failed.
    """
    if not _sentinel_dump_enabled():
        return ""
    try:
        out_dir = _sentinel_dump_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_flow = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(flow or "flow"))[:48]
        safe_did = "".join(c if c.isalnum() or c in "-_" else "" for c in str(device_id or "x"))[:12]
        ts = __import__("time").strftime("%Y%m%dT%H%M%SZ", __import__("time").gmtime())
        path = out_dir / f"{ts}_{safe_flow}_{safe_did or 'nodid'}.json"
        payload: dict[str, Any] = {
            "ts": ts,
            "flow": flow,
            "device_id": device_id,
            "sdk_version": str(sdk_version or SDK_VERSION),
            "fp_family": (os.environ.get("TOKENREFRESH_FP_FAMILY") or "")[:32],
            "req_body": req_body,
            "openai_sentinel_token": headers.get("openai-sentinel-token")
            or headers.get("OpenAI-Sentinel-Token")
            or "",
            "openai_sentinel_so_token": headers.get("openai-sentinel-so-token")
            or headers.get("OpenAI-Sentinel-So-Token")
            or "",
            "t_diag": t_diag or {},
        }
        if extra:
            payload["extra"] = extra
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        # Append jsonl twin for offline batch compare (EQUIVALENCE_PLAN L1/L2)
        try:
            jsonl = out_dir / "sentinel_headers.jsonl"
            with jsonl.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception:
            pass
        return str(path)
    except Exception:
        return ""

_MANIFEST_CACHE: dict[str, Any] | None = None


def load_sdk_manifest(*, force: bool = False) -> dict[str, Any]:
    """Load and verify the versioned local SDK manifest.

    The SDK is a security-sensitive input to the protocol.  A missing,
    malformed, stale, or mixed-version asset set therefore fails closed.  An
    optional ``TOKENREFRESH_SENTINEL_SDK_VERSION`` override is accepted only
    when it names the exact version recorded by the manifest; it cannot select
    an arbitrary capture or trigger a legacy fallback.
    """
    global _MANIFEST_CACHE, SDK_VERSION, SDK_VERSION_URL, SDK_PATH, SENTINEL_FRAME_URL, SDK_BOOTSTRAP_URL
    if _MANIFEST_CACHE is not None and not force:
        return _MANIFEST_CACHE
    if not MANIFEST_PATH.is_file():
        raise _manifest_failure(f"manifest missing: {MANIFEST_PATH}")
    try:
        raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise _manifest_failure(f"manifest unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise _manifest_failure("manifest root must be an object")

    required = (
        "sdk_version",
        "versioned_url",
        "frame_url",
        "local_sdk_file",
        "sha256",
        "byte_len",
    )
    missing = [key for key in required if key not in raw]
    if missing:
        raise _manifest_failure(f"missing fields: {','.join(missing)}")

    ver = str(raw.get("sdk_version") or "").strip()
    # Version IDs are path/query components, not arbitrary URLs or filenames.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", ver):
        raise _manifest_failure("sdk_version is not a safe identifier")
    env_ver = (os.environ.get("TOKENREFRESH_SENTINEL_SDK_VERSION") or "").strip()
    if env_ver and env_ver != ver:
        raise _manifest_failure(
            f"environment version {env_ver!r} does not match manifest {ver!r}"
        )

    versioned_url = str(raw.get("versioned_url") or "").strip()
    expected_versioned_url = f"https://sentinel.openai.com/sentinel/{ver}/sdk.js"
    if versioned_url != expected_versioned_url:
        raise _manifest_failure(
            f"versioned_url must be {expected_versioned_url!r}, got {versioned_url!r}"
        )

    frame_url = str(raw.get("frame_url") or "").strip()
    expected_frame_path = "/backend-api/sentinel/frame.html"
    parsed_frame = urlparse(frame_url)
    frame_qs = parse_qs(parsed_frame.query)
    if (
        parsed_frame.scheme != "https"
        or parsed_frame.netloc != "sentinel.openai.com"
        or parsed_frame.path != expected_frame_path
        or parsed_frame.params
        or parsed_frame.query != f"sv={ver}"
        or parsed_frame.fragment
        or frame_qs.get("sv") != [ver]
    ):
        raise _manifest_failure(
            f"frame_url must target {expected_frame_path}?sv={ver!s}, got {frame_url!r}"
        )

    bootstrap_url = str(
        raw.get("bootstrap_url") or "https://sentinel.openai.com/backend-api/sentinel/sdk.js"
    ).strip()
    parsed_bootstrap = urlparse(bootstrap_url)
    if (
        bootstrap_url != "https://sentinel.openai.com/backend-api/sentinel/sdk.js"
        or parsed_bootstrap.scheme != "https"
        or parsed_bootstrap.netloc != "sentinel.openai.com"
        or parsed_bootstrap.path != "/backend-api/sentinel/sdk.js"
        or parsed_bootstrap.params
        or parsed_bootstrap.query
        or parsed_bootstrap.fragment
    ):
        raise _manifest_failure(f"bootstrap_url is not the Sentinel bootstrap endpoint: {bootstrap_url!r}")

    rel = str(raw.get("local_sdk_file") or "").strip()
    rel_path = Path(rel)
    if not rel or rel_path.is_absolute() or ".." in rel_path.parts:
        raise _manifest_failure("local_sdk_file must be a relative path inside formal_runtime")
    if rel_path.name != f"auth_sentinel_sdk_{ver}.js":
        raise _manifest_failure(
            f"local_sdk_file must name sdk_version {ver!r}, got {rel!r}"
        )
    cand = (RUNTIME_DIR / rel_path).resolve()
    runtime_root = RUNTIME_DIR.resolve()
    if runtime_root not in cand.parents or not cand.is_file():
        raise _manifest_failure(f"local SDK file missing: {cand}")

    digest = str(raw.get("sha256") or "").strip().lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise _manifest_failure("sha256 must be a 64-character hexadecimal digest")
    raw_byte_len = raw.get("byte_len")
    if isinstance(raw_byte_len, bool) or not isinstance(raw_byte_len, int):
        raise _manifest_failure("byte_len must be a positive integer")
    byte_len = raw_byte_len
    if byte_len <= 0:
        raise _manifest_failure("byte_len must be a positive integer")
    actual_len = cand.stat().st_size
    if actual_len != byte_len:
        raise _manifest_failure(
            f"SDK byte length mismatch: manifest={byte_len}, actual={actual_len}"
        )
    actual_digest = hashlib.sha256(cand.read_bytes()).hexdigest()
    if actual_digest != digest:
        raise _manifest_failure(
            f"SDK sha256 mismatch: manifest={digest}, actual={actual_digest}"
        )

    validated = {
        **raw,
        "sdk_version": ver,
        "versioned_url": versioned_url,
        "bootstrap_url": bootstrap_url,
        "frame_url": frame_url,
        "local_sdk_path": str(cand),
        "sha256": digest,
        "byte_len": byte_len,
    }
    # Mutate module state only after every check succeeds.
    SDK_VERSION = ver
    SDK_VERSION_URL = versioned_url
    SDK_BOOTSTRAP_URL = bootstrap_url
    SENTINEL_FRAME_URL = frame_url
    SDK_PATH = cand
    _MANIFEST_CACHE = validated
    return validated


# Apply the manifest at import so SDK_PATH/VERSION always match the verified
# on-disk asset.  A broken deployment consequently fails during startup.
load_sdk_manifest()

AUTH_POOL_NAMESPACE = "bc-auth-firefox144-jp-pool-v1"
FORMAL_FRAME_PROFILE = "jsdom-frame-profile"
OWNED_PROFILE = "owned-profile"

# Flows that use formal-frame dual-realm (create_account related)
_FRAME_FLOWS = frozenset({
    "oauth_create_account",
    "email_otp_validate",
})


def formal_frame_enabled() -> bool:
    """Whether formal-frame is the active Sentinel engine."""
    raw = (
        os.environ.get("TOKENREFRESH_SENTINEL_ENGINE")
        or os.environ.get("REG_CREATE_ACCOUNT_RUNTIME_PROFILE")
        or "formal-frame"
    ).strip().lower()
    if raw in ("0", "off", "legacy", "leaf", "python", "old"):
        return False
    if raw in (
        "1",
        "on",
        "formal",
        "formal-frame",
        "frame",
        "jsdom-frame-profile",
        "frame-profile",
        "eda",
        "auto",
        "",
    ):
        return True
    # baseline / formal single-realm still use Node formal runtime path
    if raw in ("baseline", "baseline-frame", "owned-profile", "jsdom-baseline"):
        return True
    return False


def runtime_profile_for_flow(flow: str) -> str:
    """Match Eda: create/otp use formal-frame; other flows use owned-profile."""
    env = (
        os.environ.get("TOKENREFRESH_RUNTIME_PROFILE")
        or os.environ.get("REG_CREATE_ACCOUNT_RUNTIME_PROFILE")
        or "formal-frame"
    ).strip().lower()
    aliases = {
        "formal-frame": FORMAL_FRAME_PROFILE,
        "frame-profile": FORMAL_FRAME_PROFILE,
        "jsdom-frame-profile": FORMAL_FRAME_PROFILE,
        "formal": OWNED_PROFILE,
        "owned-profile": OWNED_PROFILE,
        "baseline": "jsdom-baseline",
        "jsdom-baseline": "jsdom-baseline",
        "baseline-frame": "jsdom-frame-baseline",
        "jsdom-frame-baseline": "jsdom-frame-baseline",
    }
    create_profile = aliases.get(env, FORMAL_FRAME_PROFILE)
    f = str(flow or "").strip()
    if f in _FRAME_FLOWS:
        return create_profile
    return OWNED_PROFILE


def _find_node() -> str:
    env = (os.environ.get("TOKENREFRESH_NODE") or os.environ.get("NODE_BIN") or "").strip()
    if env and Path(env).is_file():
        return env
    which = shutil.which("node")
    if which:
        return which
    # Project-local portable Node (repo/.tools/node) + Windows/layout fallbacks
    repo_root = ROOT.parent.parent  # vendor/tokenrefresh → repo
    for cand in (
        repo_root / ".tools" / "node" / "bin" / "node",
        repo_root / ".tools" / "node" / "node.exe",
        RUNTIME_DIR / "node.exe",
        ROOT / "node_runtime" / "node.exe",
        ROOT / "node_runtime" / "bin" / "node",
        Path(r"C:\Program Files\nodejs\node.exe"),
    ):
        if cand.is_file():
            return str(cand)
    raise FormalFrameError("node executable not found (need Node 18+ for formal-frame)")


def _load_firefox_pool() -> list[dict[str, Any]]:
    if not FIREFOX_POOL_PATH.is_file():
        raise FormalFrameError(f"firefox pool missing: {FIREFOX_POOL_PATH}")
    data = json.loads(FIREFOX_POOL_PATH.read_text(encoding="utf-8"))
    profiles = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(profiles, list) or not profiles:
        raise FormalFrameError("firefox-v1.json has no profiles")
    return [dict(p) for p in profiles if isinstance(p, dict)]


_POOL_CACHE: list[dict[str, Any]] | None = None


def firefox_pooled_fingerprint(
    account_key: str,
    *,
    device_id: str | None = None,
    region: str = "jp",
) -> dict[str, Any]:
    """Email/account key → stable Firefox 144 pool entry (Eda AUTH pool)."""
    global _POOL_CACHE
    if _POOL_CACHE is None:
        _POOL_CACHE = _load_firefox_pool()
    pool = _POOL_CACHE
    key = str(account_key or device_id or uuid.uuid4().hex).strip().lower()
    selector = hashlib.sha256(f"{AUTH_POOL_NAMESPACE}|{key}".encode("utf-8")).digest()
    index = int.from_bytes(selector[:8], "big") % len(pool)
    base = dict(pool[index])
    # Normalize fields our stack expects
    sw = int(base.get("screen_width") or 1920)
    sh = int(base.get("screen_height") or 1080)
    langs = base.get("languages") or ["ja-JP", "ja", "en-US", "en"]
    if isinstance(langs, str):
        lang_list = [x.strip() for x in langs.split(",") if x.strip()]
    else:
        lang_list = list(langs)
    accept = str(base.get("accept_language") or "ja,en-US;q=0.9,en;q=0.8")
    nav_lang = str(base.get("language") or "ja-JP")
    # Our stack historically used languages as Accept-Language string
    fp: dict[str, Any] = {
        **base,
        "oai_did": str(device_id or base.get("oai_did") or ""),
        "impersonate": str(base.get("impersonate") or "firefox144"),
        "user_agent": str(
            base.get("user_agent")
            or "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"
        ),
        "accept_language": accept,
        "language": nav_lang,
        "languages": accept,  # string form for _apply_diverse_locale / headers
        "languages_list": lang_list,
        "navigator_language": "ja" if nav_lang.lower().startswith("ja") else nav_lang,
        "timezone": str(base.get("timezone") or "Asia/Tokyo"),
        "timezone_offset_minutes": int(base.get("timezone_offset_minutes") or -540),
        "screen": f"{sw}x{sh}",
        "screen_width": sw,
        "screen_height": sh,
        "screen_avail_width": int(base.get("screen_avail_width") or sw),
        "screen_avail_height": int(base.get("screen_avail_height") or max(sh - 40, 600)),
        "inner_width": int(base.get("inner_width") or sw),
        "inner_height": int(base.get("inner_height") or max(sh - 133, 600)),
        "outer_width": int(base.get("outer_width") or sw),
        "outer_height": int(base.get("outer_height") or sh),
        "color_depth": int(base.get("color_depth") or 24),
        "pixel_depth": int(base.get("pixel_depth") or 24),
        "device_pixel_ratio": float(base.get("device_pixel_ratio") or 1),
        "max_touch_points": int(base.get("max_touch_points") or 0),
        "hardware_concurrency": int(base.get("hardware_concurrency") or 8),
        "device_memory": int(base.get("device_memory") or 8),
        "platform": str(base.get("platform") or "Win32"),
        "vendor": str(base.get("vendor") or ""),
        "sec_ch_ua": "",  # Firefox: no Client Hints
        "sec_ch_ua_mobile": "",
        "sec_ch_ua_platform": "",
        "chrome_major": 0,
        "brand": "firefox",
        "proxy_region": str(region or base.get("region") or "JP").upper(),
        "profile_index": int(base.get("profile_index") if base.get("profile_index") is not None else index),
        "profile_id": str(base.get("profile_id") or f"bc-auth-{index:03d}"),
        "profile_namespace": str(base.get("profile_namespace") or AUTH_POOL_NAMESPACE),
        "profile_pool_size": len(pool),
        "profile_selector_sha12": hashlib.sha256(key.encode("utf-8")).hexdigest()[:12],
        "seed": str(base.get("seed") or f"{AUTH_POOL_NAMESPACE}:{len(pool)}:{index}"),
        "formal_frame": True,
        "family": "firefox",
        "name": f"firefox144_{index:03d}",
    }
    return fp


def _cookie_domain_matches(cookie_domain: str, host: str) -> bool:
    domain = str(cookie_domain or "").lstrip(".").lower()
    host = str(host or "").lower()
    return bool(domain and (host == domain or host.endswith("." + domain)))


def _cookie_path_matches(cookie_path: str, request_path: str) -> bool:
    value = str(cookie_path or "/")
    request = str(request_path or "/")
    if request == value:
        return True
    if not request.startswith(value):
        return False
    return value.endswith("/") or request[len(value) :].startswith("/")


def _iter_cookies(session: Any):
    jar = getattr(session, "cookies", None)
    if jar is None:
        return
    # curl_cffi / requests CookieJar
    try:
        for item in jar:
            yield item
        return
    except TypeError:
        pass
    inner = getattr(jar, "jar", None)
    if inner is not None:
        for item in inner:
            yield item


def cookie_string_for_page(session: Any, device_id: str, page_url: str) -> str:
    """Build document.cookie-like string; ensure oai-did is present for SDK."""
    parsed = urlparse(page_url) if page_url else None
    visible: list[tuple[str, str]] = []
    saw_did = False
    for item in _iter_cookies(session) or ():
        name = str(getattr(item, "name", "") or "")
        value = str(getattr(item, "value", "") or "")
        if not name:
            continue
        domain = str(getattr(item, "domain", "") or "")
        path = str(getattr(item, "path", "/") or "/")
        secure = bool(getattr(item, "secure", False))
        if parsed is not None and parsed.hostname:
            if domain and not _cookie_domain_matches(domain, parsed.hostname):
                continue
            if not _cookie_path_matches(path, parsed.path or "/"):
                continue
            if secure and parsed.scheme.lower() != "https":
                continue
        # skip HttpOnly for document.cookie projection
        rest = getattr(item, "_rest", None) or {}
        if any(str(k).lower() == "httponly" for k in rest):
            # still inject oai-did manually if HttpOnly (SDK needs it in fixture)
            if name.lower() == "oai-did":
                saw_did = True
            continue
        visible.append((name, value))
        if name.lower() == "oai-did":
            saw_did = True
    if not saw_did and device_id:
        visible.insert(0, ("oai-did", str(device_id)))
    # de-dupe names keeping first
    seen: set[str] = set()
    parts: list[str] = []
    for n, v in visible:
        if n in seen:
            continue
        seen.add(n)
        parts.append(f"{n}={v}")
    if "oai-did" not in seen and device_id:
        parts.insert(0, f"oai-did={device_id}")
    return "; ".join(parts)


def browser_headers_from_profile(
    profile: dict[str, Any] | None,
    extra: dict[str, Any] | None = None,
) -> dict[str, str]:
    fp = profile or {}
    result = {str(k): str(v) for k, v in dict(extra or {}).items()}
    ua = str(fp.get("user_agent") or "")
    al = str(fp.get("accept_language") or fp.get("languages") or "")
    locked = {"user-agent": ua, "accept-language": al}
    sec = str(fp.get("sec_ch_ua") or "").strip()
    # Firefox: strip any Chrome Client Hints that may have been copied
    if not sec or str(fp.get("family") or fp.get("brand") or "").lower() == "firefox":
        for existing in list(result):
            if existing.lower().startswith("sec-ch-ua"):
                del result[existing]
    else:
        locked.update(
            {
                "sec-ch-ua": sec,
                "sec-ch-ua-mobile": str(fp.get("sec_ch_ua_mobile") or "?0"),
                "sec-ch-ua-platform": str(fp.get("sec_ch_ua_platform") or '"Windows"'),
            }
        )
    for name, value in locked.items():
        if not value:
            continue
        for existing in list(result):
            if existing.lower() == name:
                del result[existing]
        result[name] = value
    return result


def _frame_lifecycle_settings() -> dict[str, str]:
    defaults = {
        "source": "desktop-pageassets-20260715",
        "timing_policy": "event-order-only",
        "message_contract": "unobserved",
        "desktop_trace_status": "pending",
    }
    try:
        payload = json.loads(LIFECYCLE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return defaults
    if not isinstance(payload, dict):
        return defaults
    for key in tuple(defaults):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            defaults[key] = value.strip()
    return defaults


class _NodeWorker:
    """Long-lived Node formal-frame runtime (one per account session)."""

    def __init__(
        self,
        fixture: dict[str, Any],
        timeout: float = 90,
        *,
        sdk_path: Path,
    ) -> None:
        self._sdk_path = Path(sdk_path)
        if not self._sdk_path.is_file() or not RUNTIME_PATH.is_file():
            raise FormalFrameError("formal-frame SDK/runtime file missing")
        self._timeout = max(5.0, float(timeout or 90))
        self._lock = threading.Lock()
        self._responses: queue.Queue[dict[str, Any]] = queue.Queue()
        self._stderr: deque[str] = deque(maxlen=40)
        self._request_id = 0
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        env = os.environ.copy()
        # Resolve the sibling package directly.  A formal_runtime/node_modules
        # symlink/junction remains a compatibility fallback, not a deployment
        # requirement.
        node_module_dirs = (
            ROOT / "node_runtime" / "node_modules",
            RUNTIME_DIR / "node_modules",
        )
        configured_node_path = [str(path) for path in node_module_dirs if path.is_dir()]
        inherited_node_path = env.get("NODE_PATH", "")
        if inherited_node_path:
            configured_node_path.append(inherited_node_path)
        if configured_node_path:
            env["NODE_PATH"] = os.pathsep.join(configured_node_path)
        self._process = subprocess.Popen(
            [_find_node(), str(RUNTIME_PATH), "--worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            creationflags=creationflags,
            cwd=str(RUNTIME_DIR),
            env=env,
        )
        self._stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()
        payload = dict(fixture)
        payload.update({"action": "init", "sdk_path": str(self._sdk_path)})
        try:
            ready = self.call(payload)
            if not ready.get("ready"):
                raise FormalFrameError("Node formal-frame worker did not become ready")
        except BaseException:
            self.close()
            raise

    @property
    def pid(self) -> int:
        return int(self._process.pid or 0)

    def _read_stdout(self) -> None:
        stream = self._process.stdout
        if stream is None:
            return
        for raw in stream:
            line = raw.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except Exception:
                self._stderr.append(f"stdout: {line[:500]}")
                continue
            if isinstance(value, dict):
                self._responses.put(value)

    def _read_stderr(self) -> None:
        stream = self._process.stderr
        if stream is None:
            return
        for raw in stream:
            line = raw.strip()
            if line:
                self._stderr.append(line[:1000])

    def _detail(self) -> str:
        return " | ".join(self._stderr)[:2000]

    def call(self, payload: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        with self._lock:
            if self._process.poll() is not None:
                raise FormalFrameError(
                    f"Node worker exited ({self._process.returncode}): {self._detail()}"
                )
            self._request_id += 1
            request_id = self._request_id
            request = dict(payload)
            request["request_id"] = request_id
            if self._process.stdin is None:
                raise FormalFrameError("Node runtime stdin unavailable")
            try:
                self._process.stdin.write(json.dumps(request, ensure_ascii=False) + "\n")
                self._process.stdin.flush()
            except Exception as exc:
                raise FormalFrameError(f"Node stdin write failed: {exc}") from exc
            deadline = timeout if timeout is not None else self._timeout
            end = __import__("time").monotonic() + max(5.0, float(deadline))
            while True:
                remaining = end - __import__("time").monotonic()
                if remaining <= 0:
                    raise FormalFrameError(f"Node worker timeout: {self._detail()}")
                try:
                    value = self._responses.get(timeout=min(1.0, remaining))
                except queue.Empty:
                    if self._process.poll() is not None:
                        raise FormalFrameError(
                            f"Node worker died: {self._detail()}"
                        )
                    continue
                if int(value.get("request_id") or 0) != request_id:
                    continue
                # Worker envelope: {request_id, ok, result|error}
                if value.get("ok") is False or (
                    value.get("error") and not value.get("ok")
                ):
                    raise FormalFrameError(
                        str(value.get("error") or "Node runtime action failed")[:1000]
                    )
                result = value.get("result")
                if isinstance(result, dict):
                    return result
                if value.get("ready") is not None or value.get("p") is not None:
                    return value
                if value.get("error"):
                    raise FormalFrameError(str(value.get("error"))[:1000])
                raise FormalFrameError(
                    f"Node runtime result is not an object: {str(value)[:200]}"
                )

    def close(self) -> None:
        try:
            if self._process.stdin:
                try:
                    self._process.stdin.write(
                        json.dumps({"action": "close", "request_id": 0}) + "\n"
                    )
                    self._process.stdin.flush()
                except Exception:
                    pass
            self._process.terminate()
        except Exception:
            pass
        try:
            self._process.wait(timeout=3)
        except Exception:
            try:
                self._process.kill()
            except Exception:
                pass


class FormalFrameContext:
    """One registration identity: Firefox profile + formal-frame Node lifecycle."""

    def __init__(
        self,
        session: Any,
        *,
        device_id: str,
        profile: dict[str, Any] | None = None,
        timeout: float = 75,
        log: Any = None,
    ) -> None:
        self.session = session
        self.device_id = str(device_id or "").strip()
        if not self.device_id:
            raise FormalFrameError("device_id missing")
        self.profile = dict(profile or {})
        self.timeout = max(15.0, float(timeout or 75))
        self.log = log if callable(log) else (lambda _m: None)
        # One account/session must never mix SDK versions.  New contexts pick
        # up a refreshed manifest, while existing contexts retain this verified
        # snapshot for their full lifecycle.
        self._sdk_manifest = dict(load_sdk_manifest())
        self._sdk_version = str(self._sdk_manifest["sdk_version"])
        self._sdk_version_url = str(self._sdk_manifest["versioned_url"])
        self._sdk_bootstrap_url = str(self._sdk_manifest["bootstrap_url"])
        self._sentinel_frame_url = str(self._sdk_manifest["frame_url"])
        self._sdk_path = Path(str(self._sdk_manifest["local_sdk_path"]))
        self._worker: _NodeWorker | None = None
        self._runtime_profile = ""
        self._requirements_p = ""
        self._page_group = ""
        self._sdk_ready = False
        self._frame_ready = False
        self._closed = False
        self._lock = threading.RLock()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._worker is not None:
                self._worker.close()
                self._worker = None

    def _runtime_payload(self, page_url: str, *, sdk_url: str = "") -> dict[str, Any]:
        lifecycle = _frame_lifecycle_settings()
        fp = self.profile
        langs = navigator_languages_from_profile(fp)
        sdk_u = (sdk_url or self._sdk_version_url).strip()
        nav_lang = str(
            fp.get("navigator_language") or fp.get("language") or (langs[0] if langs else "ja-JP")
        )
        return {
            "id": self.device_id,
            "site": "gpt",
            "page_url": page_url,
            "cookie_str": cookie_string_for_page(self.session, self.device_id, page_url),
            "require_server_did": False,  # softer than Eda: we inject oai-did
            "sdk_url": sdk_u,
            "sdk_bootstrap_url": self._sdk_bootstrap_url,
            "frame_sdk_url": self._sdk_version_url,
            "frame_url": self._sentinel_frame_url,
            "sdk_version": self._sdk_version,
            "sdk_path": str(self._sdk_path),
            "frame_lifecycle_source": lifecycle["source"],
            "frame_timing_policy": lifecycle["timing_policy"],
            "frame_message_contract": lifecycle["message_contract"],
            "frame_desktop_trace_status": lifecycle["desktop_trace_status"],
            "user_agent": str(fp.get("user_agent") or ""),
            "accept_language": str(
                fp.get("accept_language")
                or ("ja,en-US;q=0.9,en;q=0.8" if nav_lang.lower().startswith("ja") else "")
            ),
            "platform": str(fp.get("platform") or "Win32"),
            "vendor": str(fp.get("vendor") or ""),
            "language": nav_lang,
            "languages": langs,
            "timezone": str(fp.get("timezone") or "Asia/Tokyo"),
            "timezone_offset_minutes": int(fp.get("timezone_offset_minutes") or -540),
            "chrome_major": int(fp.get("chrome_major") or 0),
            "sec_ch_ua": str(fp.get("sec_ch_ua") or ""),
            "sec_ch_ua_mobile": str(fp.get("sec_ch_ua_mobile") or ""),
            "sec_ch_ua_platform": str(fp.get("sec_ch_ua_platform") or ""),
            "hardware_concurrency": int(fp.get("hardware_concurrency") or 8),
            "device_memory": int(fp.get("device_memory") or 8),
            "screen_width": int(fp.get("screen_width") or 1920),
            "screen_height": int(fp.get("screen_height") or 1080),
            "screen_avail_width": int(fp.get("screen_avail_width") or 1920),
            "screen_avail_height": int(fp.get("screen_avail_height") or 1040),
            "inner_width": int(fp.get("inner_width") or 1920),
            "inner_height": int(fp.get("inner_height") or 947),
            "outer_width": int(fp.get("outer_width") or 1920),
            "outer_height": int(fp.get("outer_height") or 1040),
            "color_depth": int(fp.get("color_depth") or 24),
            "pixel_depth": int(fp.get("pixel_depth") or 24),
            "device_pixel_ratio": float(fp.get("device_pixel_ratio") or 1),
            "max_touch_points": int(fp.get("max_touch_points") or 0),
            "profile_id": str(fp.get("profile_id") or "bc-auth"),
            # Exit IP from registration session proxy (bound in utils.bind_registration_persona).
            # Empty here is OK: installTurnstileProbeSurface.resolveExitGeo fills regional defaults
            # so nested t slot cf_headers_probe_array never collapses to ["","","","",""].
            "exit_ip": str(fp.get("exit_ip") or fp.get("cf_connecting_ip") or ""),
            "exit_city": str(fp.get("exit_city") or fp.get("cf_ip_city") or ""),
            "exit_lat": str(fp.get("exit_lat") or fp.get("cf_ip_lat") or ""),
            "exit_lon": str(fp.get("exit_lon") or fp.get("cf_ip_lon") or ""),
            "proxy_region": str(
                fp.get("proxy_region") or fp.get("user_region") or "JP"
            ),
            # Nested t: history.length (bag 72.03) + location spoof source (bag 39.35)
            "history_length": int(fp.get("history_length") or 5),
            "location_href": str(
                fp.get("location_href") or fp.get("page_url") or ""
            ),
            # Seeded GPU persona (not real pixels; stable per account)
            "webgl_vendor": str(fp.get("webgl_vendor") or ""),
            "webgl_renderer": str(fp.get("webgl_renderer") or ""),
            "webgl_unmasked_vendor": str(fp.get("webgl_unmasked_vendor") or fp.get("webgl_vendor") or ""),
            "webgl_unmasked_renderer": str(
                fp.get("webgl_unmasked_renderer") or fp.get("webgl_renderer") or ""
            ),
            "canvas_hash": str(fp.get("canvas_hash") or ""),
            "gpu_persona_seed": str(fp.get("gpu_persona_seed") or ""),
            # getConfig-stable Chrome capture fields (Bit)
            "js_heap_size_limit": int(fp.get("js_heap_size_limit") or 4294705152),
            "data_build": str(fp.get("data_build") or self._sdk_version),
            "script_srcs": list(
                fp.get("script_srcs")
                or [
                    self._sdk_version_url,
                    "https://cdn.oaistatic.com/assets/root.js",
                ]
            ),
            **({"runtime_profile": self._runtime_profile} if self._runtime_profile else {}),
        }

    def _ensure_worker(self, page_url: str, runtime_profile: str = "") -> _NodeWorker:
        if self._closed:
            raise FormalFrameError("formal-frame context closed")
        if self._worker is None:
            self._runtime_profile = str(runtime_profile or FORMAL_FRAME_PROFILE)
            self._worker = _NodeWorker(
                self._runtime_payload(page_url),
                timeout=self.timeout,
                sdk_path=self._sdk_path,
            )
            self.log(
                f"[formal-frame] worker pid={self._worker.pid} "
                f"profile={self._runtime_profile}"
            )
        return self._worker

    def _activate_page(self, page_group: str, page_url: str, runtime_profile: str = "") -> None:
        group = (page_group or page_url).strip()
        worker = self._ensure_worker(page_url, runtime_profile=runtime_profile)
        profile_changed = bool(runtime_profile) and runtime_profile != self._runtime_profile
        if not self._page_group:
            self._page_group = group
            if runtime_profile:
                self._runtime_profile = str(runtime_profile)
            return
        if group == self._page_group and not profile_changed:
            return
        if profile_changed:
            self._runtime_profile = str(runtime_profile)
        result = worker.call(
            {
                **self._runtime_payload(page_url),
                "action": "begin_page",
                "page_group": group,
            },
            timeout=self.timeout,
        )
        if not result.get("ready"):
            raise FormalFrameError("Node page reset failed")
        self._page_group = group
        self._requirements_p = ""
        self._sdk_ready = False
        self._frame_ready = False
        self.log(f"[formal-frame] page lifecycle={group}")

    def _requirements(self, page_url: str) -> str:
        if self._requirements_p:
            return self._requirements_p
        result = self._ensure_worker(page_url).call(
            {
                **self._runtime_payload(page_url, sdk_url=self._sdk_version_url),
                "mode": "requirements",
            },
            timeout=self.timeout,
        )
        proof = str(result.get("p") or "")
        if not proof.startswith("gAAAAAC"):
            raise FormalFrameError(f"requirements token shape mismatch: {proof[:40]!r}")
        self._requirements_p = proof
        self.log(
            f"[formal-frame] requirements sha="
            f"{hashlib.sha256(proof.encode()).hexdigest()[:12]}"
        )
        return proof

    def _session_get(self, url: str, headers: dict[str, str]) -> Any:
        # curl_cffi Session.get
        return self.session.get(
            url, headers=headers, allow_redirects=True, timeout=self.timeout, verify=False
        )

    def _session_post(self, url: str, data: str, headers: dict[str, str]) -> Any:
        return self.session.post(
            url,
            data=data,
            headers=headers,
            allow_redirects=True,
            timeout=self.timeout,
            verify=False,
        )

    def _ensure_sdk_assets(self, page_url: str) -> None:
        if self._sdk_ready:
            return
        common = {
            "accept": "*/*",
            "referer": page_url,
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "script",
        }
        h = browser_headers_from_profile(self.profile, common)
        try:
            r1 = self._session_get(self._sdk_bootstrap_url, h)
            if int(getattr(r1, "status_code", 0) or 0) != 200:
                self.log(f"[formal-frame] sdk bootstrap HTTP {getattr(r1, 'status_code', '?')}")
            r2 = self._session_get(self._sdk_version_url, h)
            if int(getattr(r2, "status_code", 0) or 0) != 200:
                self.log(f"[formal-frame] sdk versioned HTTP {getattr(r2, 'status_code', '?')}")
        except Exception as exc:
            self.log(f"[formal-frame] sdk warm ignore: {exc}")
        self._sdk_ready = True

    def _ensure_frame(self, page_url: str) -> str:
        if self._frame_ready:
            return self._sentinel_frame_url
        try:
            self._session_get(
                self._sentinel_frame_url,
                browser_headers_from_profile(
                    self.profile,
                    {
                        "accept": (
                            "text/html,application/xhtml+xml,application/xml;q=0.9,"
                            "image/avif,image/webp,*/*;q=0.8"
                        ),
                        "referer": page_url,
                        "sec-fetch-site": "same-site",
                        "sec-fetch-mode": "navigate",
                        "sec-fetch-dest": "iframe",
                    },
                ),
            )
            self._session_get(
                self._sdk_version_url,
                browser_headers_from_profile(
                    self.profile,
                    {
                        "accept": "*/*",
                        "referer": self._sentinel_frame_url,
                        "sec-fetch-site": "same-origin",
                        "sec-fetch-mode": "no-cors",
                        "sec-fetch-dest": "script",
                    },
                ),
            )
        except Exception as exc:
            self.log(f"[formal-frame] frame warm ignore: {exc}")
        self._frame_ready = True
        return self._sentinel_frame_url

    def issue(
        self,
        flow: str,
        *,
        page_url: str,
        page_group: str = "",
    ) -> dict[str, str]:
        """Return header map: openai-sentinel-token (+ so when required)."""
        with self._lock:
            runtime_profile = runtime_profile_for_flow(flow)
            self._activate_page(page_group or page_url, page_url, runtime_profile=runtime_profile)
            self._ensure_sdk_assets(page_url)
            frame_url = self._ensure_frame(page_url)
            request_proof = self._requirements(page_url)
            body = json.dumps(
                {"p": request_proof, "id": self.device_id, "flow": flow},
                separators=(",", ":"),
                ensure_ascii=False,
            )
            response = self._session_post(
                SENTINEL_REQ_URL,
                body,
                browser_headers_from_profile(
                    self.profile,
                    {
                        "accept": "*/*",
                        "content-type": "text/plain;charset=UTF-8",
                        "origin": "https://sentinel.openai.com",
                        "referer": frame_url,
                        "sec-fetch-site": "same-origin",
                        "sec-fetch-mode": "cors",
                        "sec-fetch-dest": "empty",
                    },
                ),
            )
            status = int(getattr(response, "status_code", 0) or 0)
            if status != 200:
                detail = str(getattr(response, "text", "") or "")[:200]
                raise FormalFrameError(f"sentinel req HTTP {status}: {detail}")
            challenge = response.json()
            if not isinstance(challenge, dict):
                raise FormalFrameError("sentinel response is not an object")
            for key in ("token", "proofofwork", "turnstile"):
                if key not in challenge:
                    raise FormalFrameError(f"sentinel response missing {key}")

            finalized = self._ensure_worker(page_url).call(
                {
                    **self._runtime_payload(page_url, sdk_url=self._sdk_bootstrap_url),
                    "mode": "finalize",
                    "flow": flow,
                    "initial_p": request_proof,
                    "response": challenge,
                },
                timeout=self.timeout,
            )
            runtime_name = str(finalized.get("runtime") or "")
            main = str(finalized.get("sentinel_token") or "")
            observer = str(
                finalized.get("session_observer_token")
                or finalized.get("sentinel_so_token")
                or ""
            )
            so_diag = finalized.get("so_diag") if isinstance(finalized, dict) else None
            if isinstance(so_diag, dict) and so_diag.get("observer_mode"):
                self.log(
                    f"[formal-frame] so_mode={so_diag.get('observer_mode')} "
                    f"so_b64={so_diag.get('so_b64_len')} "
                    f"err_shape={so_diag.get('so_looks_error')} "
                    f"activity={so_diag.get('activity')}"
                )
            if not main:
                raise FormalFrameError("formal-frame finalize returned empty main token")
            # validate shape lightly
            try:
                main_obj = json.loads(main)
            except Exception as exc:
                raise FormalFrameError("main token is not JSON") from exc
            if not {"p", "t", "c", "id", "flow"}.issubset(main_obj):
                raise FormalFrameError("main token fields mismatch")
            # Enforce: token id == registration device_id (persona consistency)
            tok_id = str(main_obj.get("id") or "")
            if tok_id and tok_id != self.device_id:
                raise FormalFrameError(
                    f"sentinel id mismatch token_id={tok_id[:16]}… "
                    f"device_id={self.device_id[:16]}…"
                )
            # Enforce: t computed under this persona is non-empty / sane length
            t_diag: dict[str, Any] = {}
            try:
                from .utils import (
                    apply_t_band_match_gate,
                    record_sentinel_t_diag,
                    validate_sentinel_t_field,
                )

                t_diag = validate_sentinel_t_field(
                    str(main_obj.get("t") or ""), flow=str(flow or "")
                )
                gate = (os.environ.get("TOKENREFRESH_T_GATE") or "1").strip().lower()
                if gate not in ("0", "false", "no", "off") and not t_diag.get("ok"):
                    raise FormalFrameError(
                        f"sentinel t gate fail reason={t_diag.get('reason')} "
                        f"raw={t_diag.get('raw')}"
                    )
                # Persona band soft/hard (TOKENREFRESH_T_BAND_MATCH)
                try:
                    apply_t_band_match_gate(t_diag, flow=str(flow or ""))
                except RuntimeError as band_exc:
                    raise FormalFrameError(str(band_exc)) from band_exc
                if t_diag.get("band_match_msg") and not t_diag.get("in_expected_band"):
                    self.log(f"[formal-frame] {t_diag.get('band_match_msg')}")
            except FormalFrameError:
                raise
            except Exception as te:
                gate = (os.environ.get("TOKENREFRESH_T_GATE") or "1").strip().lower()
                if gate not in ("0", "false", "no", "off"):
                    raise FormalFrameError(f"sentinel t validate error: {te}") from te
            headers: dict[str, str] = {"openai-sentinel-token": main}
            so_required = bool((challenge.get("so") or {}).get("required"))
            if observer:
                headers["openai-sentinel-so-token"] = observer
            elif so_required:
                raise FormalFrameError("observer SO required but missing")
            # Browser gold (289 captures): create/otp almost always ship BOTH tokens.
            # If server did not set so.required but formal-frame produced observer, keep it.
            # If so.required and missing — already raised above.
            # Structural rule check vs Bit overnight rules (p/t/c/id/flow + so).
            req_obj = {"p": request_proof, "id": self.device_id, "flow": flow}
            try:
                from chatgpt_register.protocol.sentinel_browser_rules import (
                    validate_sentinel_header_bundle,
                    validate_sentinel_req_body,
                )

                # req body we just posted
                req_probs = validate_sentinel_req_body(req_obj)
                if req_probs:
                    raise FormalFrameError(f"browser_rule_req:{req_probs}")
                # Auth steps that browser always pairs with SO: require when we have observer
                # or when so.required; for create/otp prefer require_so if observer exists
                require_so = so_required or bool(observer) or flow in (
                    "email_otp_validate",
                    "oauth_create_account",
                )
                # If so not required and observer empty, don't fail require_so
                if require_so and not observer and not so_required:
                    require_so = False
                hdr_probs = validate_sentinel_header_bundle(
                    headers,
                    device_id=self.device_id,
                    flow=str(flow or ""),
                    require_so=require_so and bool(observer or so_required),
                )
                if hdr_probs:
                    # Soft-fail only extra_keys; hard-fail structural
                    hard = [
                        p
                        for p in hdr_probs
                        if not str(p).startswith("main_extra_keys")
                    ]
                    if hard:
                        raise FormalFrameError(f"browser_rule_headers:{hard}")
                    self.log(f"[formal-frame] browser_rule soft: {hdr_probs}")
            except FormalFrameError:
                raise
            except Exception as br_exc:
                self.log(f"[formal-frame] browser_rule check ignore: {br_exc}")
            # Session diagnostics + offline dump (closes red-team not_decidable gap)
            try:
                from .utils import record_sentinel_t_diag

                sess = getattr(self, "_owner_session", None) or getattr(
                    self, "session", None
                )
                if sess is not None:
                    record_sentinel_t_diag(
                        sess,
                        main_json=main,
                        flow=str(flow or ""),
                        engine="formal-frame",
                        profile=self.profile,
                        extra={
                            "so_present": bool(observer),
                            "t_raw": t_diag.get("raw"),
                            "t_in_expected_band": t_diag.get("in_expected_band"),
                        },
                    )
            except Exception:
                pass
            dump_path = dump_sentinel_emit(
                flow=str(flow or ""),
                device_id=str(self.device_id or ""),
                req_body=req_obj,
                headers=headers,
                sdk_version=self._sdk_version,
                t_diag=t_diag,
                extra={
                    "runtime": runtime_name,
                    "so_required": so_required,
                    "so_diag": so_diag if isinstance(so_diag, dict) else {},
                    "observer_mode": str(finalized.get("observer_mode") or ""),
                },
            )
            topology = str(finalized.get("topology") or "")
            rp = str(finalized.get("runtime_profile") or self._runtime_profile)
            eip = str(self.profile.get("exit_ip") or "")[:40]
            self.log(
                f"[formal-frame] flow={flow} runtime={runtime_name or '?'} "
                f"topology={topology or '?'} profile={rp} "
                f"main_len={len(main)} so_len={len(observer)} "
                f"t_raw={t_diag.get('raw', '?')} in_band={t_diag.get('in_har_band')} "
                f"expected_band={t_diag.get('expected_band')} "
                f"in_expected={t_diag.get('in_expected_band')} "
                f"exit_ip={eip or '-'} ua={str(self.profile.get('user_agent') or '')[:48]}"
                + (f" dump={dump_path}" if dump_path else "")
            )
            return headers


def get_or_create_context(
    session: Any,
    device_id: str,
    profile: dict[str, Any] | None = None,
    log: Any = None,
) -> FormalFrameContext:
    """Bind one FormalFrameContext per session (reuse across flows)."""
    ctx = getattr(session, "_formal_frame_ctx", None)
    did = str(device_id)
    if (
        isinstance(ctx, FormalFrameContext)
        and ctx.device_id == did
        and not getattr(ctx, "_closed", False)
    ):
        if profile:
            ctx.profile = dict(profile)
        if log:
            ctx.log = log
        return ctx
    # close stale
    if isinstance(ctx, FormalFrameContext):
        try:
            ctx.close()
        except Exception:
            pass
    ctx = FormalFrameContext(
        session, device_id=did, profile=profile, log=log
    )
    try:
        session._formal_frame_ctx = ctx  # type: ignore[attr-defined]
    except Exception:
        pass
    return ctx


def page_url_for_flow(flow: str) -> str:
    f = str(flow or "")
    if f in ("email_otp_validate", "email_otp_resend", "email_otp_send"):
        return "https://auth.openai.com/email-verification"
    if f in ("oauth_create_account",):
        return "https://auth.openai.com/about-you"
    if f in ("password_create",):
        return "https://auth.openai.com/create-account/password"
    if f in ("password_verify",):
        return "https://auth.openai.com/log-in/password"
    if f in ("authorize_continue",):
        return "https://auth.openai.com/log-in-or-create-account"
    return "https://auth.openai.com/"


def build_formal_bundle(
    session: Any,
    device_id: str,
    flow: str,
    profile: dict[str, Any] | None = None,
    *,
    page_url: str = "",
    log: Any = None,
) -> dict[str, str]:
    """Public entry: formal-frame header bundle for one Auth API call."""
    ctx = get_or_create_context(session, device_id, profile=profile, log=log)
    url = (page_url or page_url_for_flow(flow)).strip()
    return ctx.issue(flow, page_url=url, page_group=url)
