"""Per-account persona diversification (protocol-only, curl_cffi / formal-frame).

Firefox pool is only ~32 base slots; 50-account batches collide on profile_index.
After pool pick + device_id, overlay seed-stable **session-unique** fields so
accounts are more independent: screen, cores, memory, dpr, lang variants, tz.

**Hardware tiers (2026-08 realism pass):** cores / mem / dpr / screen / gpu_family
are drawn as one coherent "device class" — no more 24-core + 2GB combos.

Disable: TOKENREFRESH_PERSONA_DIVERSE=0
"""
from __future__ import annotations

import hashlib
import os
from typing import Any


def diversify_enabled() -> bool:
    raw = (os.environ.get("TOKENREFRESH_PERSONA_DIVERSE") or "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _seed_int(*parts: str) -> int:
    h = hashlib.sha256(
        "|".join(str(p or "") for p in parts).encode("utf-8", errors="replace")
    ).hexdigest()
    return int(h[:16], 16)


# Coherent desktop device classes (Win + Firefox). Weights via repetition.
# gpu_family: nvidia | intel | amd — consumed by gpu_persona when present.
_TIERS: list[dict[str, Any]] = [
    # Office / school laptop
    {
        "name": "office_laptop",
        "screens": ((1366, 768), (1536, 864), (1920, 1080)),
        "cores": (4, 6, 8),
        "mem": (8, 8, 16),
        "dpr": (1.0, 1.0, 1.25),
        "gpu_family": "intel",
        "weight": 3,
    },
    # Thin & light (Iris / UHD)
    {
        "name": "ultrabook",
        "screens": ((1920, 1080), (1920, 1200), (2560, 1600), (2880, 1800)),
        "cores": (8, 10, 12),
        "mem": (16, 16, 32),
        "dpr": (1.25, 1.5, 1.5, 2.0),
        "gpu_family": "intel",
        "weight": 2,
    },
    # Mid gaming / creator (GTX / RTX 30)
    {
        "name": "gaming_mid",
        "screens": ((1920, 1080), (2560, 1440), (1920, 1200)),
        "cores": (8, 12, 16),
        "mem": (16, 16, 32),
        "dpr": (1.0, 1.0, 1.25),
        "gpu_family": "nvidia",
        "weight": 3,
    },
    # High end desktop
    {
        "name": "desktop_high",
        "screens": ((2560, 1440), (3440, 1440), (2560, 1600), (1920, 1080)),
        "cores": (12, 16, 20, 24),
        "mem": (16, 32, 32),
        "dpr": (1.0, 1.25, 1.5),
        "gpu_family": "nvidia",
        "weight": 2,
    },
    # AMD APU / Radeon box
    {
        "name": "amd_desktop",
        "screens": ((1920, 1080), (2560, 1440), (1680, 1050)),
        "cores": (6, 8, 12),
        "mem": (8, 16, 16),
        "dpr": (1.0, 1.0, 1.25),
        "gpu_family": "amd",
        "weight": 2,
    },
    # Budget / old office
    {
        "name": "budget",
        "screens": ((1366, 768), (1440, 900), (1600, 900), (1280, 800)),
        "cores": (2, 4, 4, 6),
        "mem": (4, 8, 8),
        "dpr": (1.0, 1.0, 1.25),
        "gpu_family": "intel",
        "weight": 2,
    },
]

_TIER_BAG: list[dict[str, Any]] = []
for _t in _TIERS:
    _TIER_BAG.extend([_t] * int(_t.get("weight") or 1))

# JP Accept-Language variants (all valid for region JP)
_JA_ACCEPT = (
    "ja,en-US;q=0.9,en;q=0.8",
    "ja;q=0.9,en-US;q=0.8,en;q=0.7",
    "ja,en;q=0.8",
    "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
    "ja-JP,en-US;q=0.9,en;q=0.8",
)
_JA_NAV = ("ja", "ja-JP", "ja-JP")
_JP_TZ = ("Asia/Tokyo", "Asia/Tokyo", "Asia/Tokyo", "Asia/Osaka")

_KR_ACCEPT = (
    "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "ko,en-US;q=0.9,en;q=0.8",
)
_US_ACCEPT = (
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.5",
    "en-US,en;q=0.8",
)


def diversify_profile(
    fp: dict[str, Any],
    *,
    account_key: str = "",
    device_id: str = "",
) -> dict[str, Any]:
    """Mutate fingerprint_profile for stronger per-account independence.

    Seed = account_key + device_id → stable within one registration session,
    different across accounts (and across retries with new DID).
    Hardware fields come from one tier (coherent device class).
    """
    if not diversify_enabled():
        return fp

    key = (
        f"{account_key}|{device_id}|{fp.get('profile_index')}|{fp.get('user_agent')}"
    )
    s0 = _seed_int("div", key)
    s1 = _seed_int("div2", key)
    s2 = _seed_int("div3", key)

    tier = _TIER_BAG[s0 % len(_TIER_BAG)]
    screens = tier["screens"]
    cores_l = tier["cores"]
    mem_l = tier["mem"]
    dpr_l = tier["dpr"]

    sw, sh = screens[s1 % len(screens)]
    fp["screen_width"] = sw
    fp["screen_height"] = sh
    fp["screen"] = f"{sw}x{sh}"
    bar = 40 + (s1 % 48)
    fp["screen_avail_width"] = sw
    fp["screen_avail_height"] = max(sh - bar, 600)
    fp["inner_width"] = max(sw - (s1 % 24), 800)
    fp["inner_height"] = max(sh - bar - 80 - (s2 % 40), 500)
    fp["outer_width"] = sw
    fp["outer_height"] = sh

    cores = cores_l[s1 % len(cores_l)]
    mem = mem_l[s2 % len(mem_l)]
    dpr = dpr_l[s0 % len(dpr_l)]
    fp["hardware_concurrency"] = cores
    fp["device_memory"] = mem
    fp["device_pixel_ratio"] = dpr
    fp["color_depth"] = 24 if (s1 % 5) else 30
    fp["pixel_depth"] = fp["color_depth"]
    fp["max_touch_points"] = 0 if (s2 % 7) else 1
    fp["persona_tier"] = str(tier.get("name") or "")
    fp["gpu_family"] = str(tier.get("gpu_family") or "nvidia")

    # Locale variants (keep region family)
    reg = str(fp.get("proxy_region") or "JP").upper()
    if reg == "JP":
        fp["accept_language"] = _JA_ACCEPT[s0 % len(_JA_ACCEPT)]
        # navigator.languages is capture-style single tag; AL stays q-weighted
        fp["language"] = "ja-JP"
        fp["navigator_language"] = "ja-JP"
        fp["languages_list"] = ["ja-JP"]
        fp["languages"] = ["ja-JP"]
        fp["timezone"] = _JP_TZ[s2 % len(_JP_TZ)]
        fp["timezone_offset_minutes"] = -540
    elif reg == "KR":
        fp["accept_language"] = _KR_ACCEPT[s0 % len(_KR_ACCEPT)]
        fp["language"] = "ko-KR"
        fp["navigator_language"] = "ko-KR"
        fp["languages_list"] = ["ko-KR"]
        fp["languages"] = ["ko-KR"]
        fp["timezone"] = "Asia/Seoul"
        fp["timezone_offset_minutes"] = -540
    elif reg in ("US", "CA"):
        fp["accept_language"] = _US_ACCEPT[s0 % len(_US_ACCEPT)]
        fp["language"] = "en-US"
        fp["navigator_language"] = "en-US"
        fp["languages_list"] = ["en-US"]
        fp["languages"] = ["en-US"]
        tzs = ("America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles")
        offs = (-300, -360, -420, -480)
        i = s2 % len(tzs)
        fp["timezone"] = tzs[i]
        fp["timezone_offset_minutes"] = offs[i]
    elif reg == "VN":
        fp["accept_language"] = "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7"
        fp["language"] = "vi-VN"
        fp["navigator_language"] = "vi-VN"
        fp["languages_list"] = ["vi-VN"]
        fp["languages"] = ["vi-VN"]
        fp["timezone"] = "Asia/Ho_Chi_Minh"
        fp["timezone_offset_minutes"] = -420

    plat = str(fp.get("platform") or "Win32")
    if "Win" in plat or plat == "Win32":
        fp["platform"] = "Win32"
        fp["vendor"] = str(fp.get("vendor") or "")

    fp["persona_diverse"] = True
    fp["persona_diverse_seed"] = hashlib.sha256(key.encode()).hexdigest()[:16]
    return fp
