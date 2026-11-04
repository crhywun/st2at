"""Seeded Canvas / WebGL persona fields for pure-protocol Sentinel leaves.

Not real GPU pixels by default — stable per-account diversity consistent with
UA family (Firefox vs Chrome). Optional **offline sample cache** loads real
toDataURL / WebGL strings captured once (no live browser required at register).

Used by ``bind_registration_persona`` → turnstile leaf overlay / formal-frame profile.
Disable: TOKENREFRESH_GPU_PERSONA=0

Offline cache layout::

  vendor/tokenrefresh/formal_runtime/canvas_cache/
    index.json          # optional list of sample files
    sample_*.json       # {webgl_vendor, webgl_renderer, canvas_data_url, canvas_hash, ...}

Env:
  TOKENREFRESH_CANVAS_CACHE=1          # enable cache lookup (default on if dir exists)
  TOKENREFRESH_CANVAS_CACHE_DIR=path   # override cache directory
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

_CACHE_DIR_DEFAULT = Path(__file__).resolve().parent / "formal_runtime" / "canvas_cache"
_cache_index: list[dict[str, Any]] | None = None


# Realistic ANGLE / desktop GPU strings for Win+Firefox / Win+Chrome stacks
_WIN_FIREFOX_WEBGL: list[tuple[str, str]] = [
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 2060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Ti Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1050 Ti Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 730 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) HD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580 Series Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)"),
]

_WIN_CHROME_WEBGL = _WIN_FIREFOX_WEBGL  # same ANGLE path on Windows

_MAC_WEBGL: list[tuple[str, str]] = [
    ("Google Inc. (Apple)", "ANGLE (Apple, Apple M1, OpenGL 4.1)"),
    ("Google Inc. (Apple)", "ANGLE (Apple, Apple M2, OpenGL 4.1)"),
    ("Intel Inc.", "Intel(R) Iris(TM) Plus Graphics OpenGL Engine"),
    ("ATI Technologies Inc.", "AMD Radeon Pro 5500M OpenGL Engine"),
]


def gpu_persona_enabled() -> bool:
    raw = (os.environ.get("TOKENREFRESH_GPU_PERSONA") or "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def canvas_cache_enabled() -> bool:
    raw = (os.environ.get("TOKENREFRESH_CANVAS_CACHE") or "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    # default: on if cache dir has real sample files (not only index/README)
    d = canvas_cache_dir()
    if not d.is_dir():
        return False
    return any(
        p.is_file() and p.name != "index.json" and p.suffix == ".json"
        for p in d.iterdir()
    )


def canvas_cache_dir() -> Path:
    raw = (os.environ.get("TOKENREFRESH_CANVAS_CACHE_DIR") or "").strip()
    if raw:
        return Path(raw)
    return _CACHE_DIR_DEFAULT


def load_canvas_cache() -> list[dict[str, Any]]:
    """Load offline canvas/webgl samples (thread-safe enough for read-only list)."""
    global _cache_index
    if _cache_index is not None:
        return _cache_index
    samples: list[dict[str, Any]] = []
    d = canvas_cache_dir()
    if not d.is_dir():
        _cache_index = []
        return _cache_index
    index_path = d / "index.json"
    files: list[Path] = []
    if index_path.is_file():
        try:
            idx = json.loads(index_path.read_text(encoding="utf-8"))
            for name in idx.get("samples") or idx if isinstance(idx, list) else []:
                if isinstance(name, str):
                    files.append(d / name)
                elif isinstance(name, dict) and name.get("file"):
                    files.append(d / str(name["file"]))
        except Exception:
            files = []
    if not files:
        files = sorted(p for p in d.glob("*.json") if p.name != "index.json")
    for p in files:
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(obj, dict) and (
                obj.get("webgl_renderer") or obj.get("canvas_data_url") or obj.get("canvas_hash")
            ):
                obj["_cache_file"] = p.name
                samples.append(obj)
        except Exception:
            continue
    _cache_index = samples
    return samples


def pick_canvas_cache_sample(account_key: str, *, family: str = "") -> dict[str, Any] | None:
    """Deterministic sample pick for account_key from offline cache."""
    if not canvas_cache_enabled():
        return None
    samples = load_canvas_cache()
    if not samples:
        return None
    if family:
        filtered = [
            s
            for s in samples
            if family.lower() in str(s.get("family") or s.get("gpu_persona_family") or "").lower()
            or family.lower() in str(s.get("user_agent") or "").lower()
        ]
        if filtered:
            samples = filtered
    si = _seed_int(account_key, "canvas_cache", family)
    return dict(samples[si % len(samples)])


def _seed_int(*parts: str) -> int:
    h = hashlib.sha256("|".join(str(p or "") for p in parts).encode("utf-8", errors="replace")).hexdigest()
    return int(h[:16], 16)


def _family_from_profile(fp: dict[str, Any]) -> str:
    ua = str(fp.get("user_agent") or "")
    brand = str(fp.get("brand") or fp.get("family") or "").lower()
    if "firefox" in brand or "Firefox/" in ua:
        return "firefox"
    if "Macintosh" in ua or "Mac OS" in ua:
        return "mac"
    if "Chrome/" in ua or brand in ("chrome", "edge", "chromium"):
        return "chrome"
    return "firefox" if "Firefox/" in ua else "chrome"


def build_gpu_persona(fp: dict[str, Any], *, account_key: str = "") -> dict[str, Any]:
    """Return canvas/webgl fields seeded by account + existing persona.

    Idempotent if fields already present (unless TOKENREFRESH_GPU_PERSONA_FORCE=1).
    """
    if not gpu_persona_enabled():
        return {}

    force = (os.environ.get("TOKENREFRESH_GPU_PERSONA_FORCE") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    if not force and fp.get("webgl_renderer") and fp.get("canvas_hash"):
        return {}

    key = (
        account_key
        or str(fp.get("seed") or "")
        or str(fp.get("oai_did") or fp.get("device_id") or "")
        or str(fp.get("profile_id") or fp.get("profile_index") or "")
        or str(fp.get("user_agent") or "default")
    )
    family = _family_from_profile(fp)

    # P3: offline real-sample cache (if present) beats pure seed strings
    cached = pick_canvas_cache_sample(key, family=family)
    if cached:
        out_c: dict[str, Any] = {
            "webgl_vendor": str(
                cached.get("webgl_vendor") or cached.get("webgl_unmasked_vendor") or ""
            ),
            "webgl_renderer": str(
                cached.get("webgl_renderer") or cached.get("webgl_unmasked_renderer") or ""
            ),
            "webgl_version": str(cached.get("webgl_version") or "WebGL 1.0"),
            "webgl_shading_language": str(
                cached.get("webgl_shading_language") or "WebGL GLSL ES 1.0"
            ),
            "webgl_max_texture_size": int(cached.get("webgl_max_texture_size") or 8192),
            "webgl_max_viewport_dims": str(
                cached.get("webgl_max_viewport_dims") or "8192,8192"
            ),
            "webgl_unmasked_vendor": str(
                cached.get("webgl_unmasked_vendor")
                or cached.get("webgl_vendor")
                or ""
            ),
            "webgl_unmasked_renderer": str(
                cached.get("webgl_unmasked_renderer")
                or cached.get("webgl_renderer")
                or ""
            ),
            "canvas_hash": str(cached.get("canvas_hash") or ""),
            "canvas_data_url": str(cached.get("canvas_data_url") or "")[:2048],
            "canvas_data_url_head": str(
                cached.get("canvas_data_url_head")
                or (cached.get("canvas_data_url") or "")[:96]
            ),
            "canvas_data_url_len": int(
                cached.get("canvas_data_url_len")
                or len(str(cached.get("canvas_data_url") or ""))
            ),
            "gpu_persona_seed": hashlib.sha256(key.encode()).hexdigest()[:16],
            "gpu_persona_family": family,
            "gpu_persona_source": "canvas_cache",
            "gpu_persona_cache_file": str(cached.get("_cache_file") or ""),
        }
        if not out_c["canvas_hash"] and out_c["canvas_data_url"]:
            out_c["canvas_hash"] = hashlib.sha256(
                out_c["canvas_data_url"].encode()
            ).hexdigest()
        return out_c

    pool = _MAC_WEBGL if family == "mac" else _WIN_FIREFOX_WEBGL
    # Prefer GPU vendor family from persona_diversify tier (intel|nvidia|amd)
    gpu_fam = str(fp.get("gpu_family") or "").strip().lower()
    if family != "mac" and gpu_fam in ("intel", "nvidia", "amd"):
        filtered = [
            pair
            for pair in pool
            if gpu_fam in pair[0].lower() or gpu_fam in pair[1].lower()
        ]
        if filtered:
            pool = filtered
    si = _seed_int(
        key,
        family,
        gpu_fam,
        str(fp.get("screen") or ""),
        str(fp.get("profile_index") or ""),
        str(fp.get("persona_tier") or ""),
    )
    vendor, renderer = pool[si % len(pool)]

    # Stable canvas fingerprint: length + hash (not real pixels)
    # Real PNG data-URLs are long; probes often hash content or length.
    canvas_body_len = 1800 + (si % 900)  # ~1.8–2.7k body-ish
    canvas_hash = hashlib.sha256(f"canvas|{key}|{renderer}|{canvas_body_len}".encode()).hexdigest()
    # data URL shaped stub (prefix real enough for string probes)
    png_b64_len = 1200 + (si % 400)
    # deterministic fake base64 alphabet chunk
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    rng = si
    chars = []
    for _ in range(min(64, png_b64_len)):
        rng = (rng * 1103515245 + 12345) & 0x7FFFFFFF
        chars.append(alphabet[rng % 64])
    canvas_data_url = (
        f"data:image/png;base64,{''.join(chars)}"
        f"{canvas_hash[:24]}{'A' * max(0, png_b64_len - 64 - 24)}"
    )

    max_tex = 8192 if (si % 3) else 16384
    webgl_version = "WebGL 1.0 (OpenGL ES 2.0 Chromium)"
    if family == "firefox":
        webgl_version = "WebGL 1.0"

    out: dict[str, Any] = {
        "webgl_vendor": vendor,
        "webgl_renderer": renderer,
        "webgl_version": webgl_version,
        "webgl_shading_language": "WebGL GLSL ES 1.0",
        "webgl_max_texture_size": max_tex,
        "webgl_max_viewport_dims": f"{max_tex},{max_tex}",
        "webgl_unmasked_vendor": vendor,
        "webgl_unmasked_renderer": renderer,
        "canvas_hash": canvas_hash,
        "canvas_data_url_len": len(canvas_data_url),
        "canvas_data_url_head": canvas_data_url[:96],
        "canvas_data_url": canvas_data_url[:512],  # keep short in profile logs
        "gpu_persona_seed": hashlib.sha256(key.encode()).hexdigest()[:16],
        "gpu_persona_family": family,
        "gpu_persona_source": "seeded",
    }
    # Common extension flags as 0/1 noise
    for i, ext in enumerate(
        (
            "WEBGL_debug_renderer_info",
            "EXT_texture_filter_anisotropic",
            "OES_texture_float",
            "OES_element_index_uint",
            "WEBGL_lose_context",
        )
    ):
        out[f"webgl_ext_{i}"] = ext
    return out


def apply_gpu_persona_to_profile(fp: dict[str, Any], *, account_key: str = "") -> dict[str, Any]:
    """Mutate/return profile with gpu persona fields merged in."""
    extra = build_gpu_persona(fp, account_key=account_key)
    if extra:
        fp.update(extra)
    return fp


def apply_gpu_persona_to_leaves(leaves: dict[str, Any], profile: dict[str, Any] | None) -> None:
    """Stamp common WebGL/Canvas property paths used by probe VMs."""
    if not profile or not gpu_persona_enabled():
        return
    vendor = str(profile.get("webgl_vendor") or profile.get("webgl_unmasked_vendor") or "").strip()
    renderer = str(
        profile.get("webgl_renderer") or profile.get("webgl_unmasked_renderer") or ""
    ).strip()
    if not vendor and not renderer:
        return

    # WebGL getParameter unmasked
    leaves["window.WebGLRenderingContext.prototype.getParameter.37445"] = vendor  # UNMASKED_VENDOR
    leaves["window.WebGLRenderingContext.prototype.getParameter.37446"] = renderer  # UNMASKED_RENDERER
    leaves["WebGLRenderingContext.getParameter.UNMASKED_VENDOR_WEBGL"] = vendor
    leaves["WebGLRenderingContext.getParameter.UNMASKED_RENDERER_WEBGL"] = renderer
    leaves["window.WebGLRenderingContext.prototype.getParameter.7936"] = vendor  # VENDOR
    leaves["window.WebGLRenderingContext.prototype.getParameter.7937"] = renderer  # RENDERER
    leaves["window.WebGLRenderingContext.prototype.getParameter.7938"] = str(
        profile.get("webgl_version") or "WebGL 1.0"
    )
    leaves["window.WebGLRenderingContext.prototype.getParameter.35724"] = str(
        profile.get("webgl_shading_language") or "WebGL GLSL ES 1.0"
    )
    try:
        mts = int(profile.get("webgl_max_texture_size") or 8192)
    except Exception:
        mts = 8192
    leaves["window.WebGLRenderingContext.prototype.getParameter.3379"] = mts  # MAX_TEXTURE_SIZE

    # Canvas
    head = str(profile.get("canvas_data_url_head") or profile.get("canvas_data_url") or "")
    if head:
        leaves["HTMLCanvasElement.prototype.toDataURL"] = head
        leaves["window.HTMLCanvasElement.prototype.toDataURL"] = head
        leaves["HTMLCanvasElement.toDataURL"] = head
    ch = str(profile.get("canvas_hash") or "")
    if ch:
        leaves["canvas.fingerprint"] = ch
        leaves["window.canvasHash"] = ch
    # getContext tokens
    leaves["HTMLCanvasElement.prototype.getContext"] = "function getContext() { [native code] }"
    leaves["WebGLRenderingContext"] = "[object WebGLRenderingContext]"
    leaves["WebGL2RenderingContext"] = "[object WebGL2RenderingContext]"
