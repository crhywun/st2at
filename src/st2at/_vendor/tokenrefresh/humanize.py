"""Minimal pacing + header helpers for pure-HTTP register.

Path warm / pre-auth spine / post-login telemetry / path_persona were **deleted**
after protocol experiments showed they do not drive ban outcomes. Keep only:

  - human_pause / humanize_mode (optional micro-delays)
  - accept_language_header / pick_impersonate (HTTP identity)

Core register + formal-frame sentinel (t/so) live elsewhere.
"""
from __future__ import annotations

import os
import random
import time

from . import constants as C


def _env_float(name: str, default: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool = True) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def humanize_mode() -> str:
    """fast (default) | realistic (opt-in long pauses)."""
    m = (os.environ.get("HUMANIZE_MODE") or "").strip().lower()
    if m in ("realistic", "real", "slow", "jp", "har"):
        return "realistic"
    return "fast"


def human_pause(
    kind: str = "step",
    *,
    lo: float | None = None,
    hi: float | None = None,
) -> float:
    """Optional short pause. Returns slept seconds."""
    if not _env_bool("HUMANIZE_ENABLE", True):
        return 0.0

    mode = humanize_mode()
    if mode == "fast":
        presets = {
            "micro": (0.04, 0.18),
            "step": (0.08, 0.42),
            "otp_ok": (0.12, 0.55),
            "pre_create": (0.15, 0.65),
            "post_create": (0.10, 0.50),
            "pre_callback": (0.08, 0.40),
            "pre_session": (0.10, 0.45),
            "warm": (0.05, 0.25),
            "pre_signin": (0.08, 0.35),
            "pre_otp_submit": (0.15, 0.60),
            "between_auth": (0.10, 0.45),
            "think": (0.20, 0.80),
            "refresh": (0.15, 0.50),
        }
    else:
        presets = {
            "micro": (0.12, 0.55),
            "step": (0.45, 1.8),
            "otp_ok": (0.8, 3.2),
            "pre_create": (1.2, 4.5),
            "post_create": (0.6, 2.0),
            "pre_callback": (0.4, 1.6),
            "pre_session": (0.5, 2.0),
            "warm": (0.3, 1.2),
            "pre_signin": (0.6, 2.5),
            "pre_otp_submit": (1.5, 5.5),
            "between_auth": (0.8, 3.0),
            "think": (1.0, 4.0),
            "refresh": (0.8, 2.5),
        }

    dlo, dhi = presets.get(kind, presets["step"])
    scale = max(0.1, _env_float("HUMANIZE_SCALE", 1.0))
    dlo *= scale
    dhi *= scale
    glo = _env_float("HUMANIZE_PAUSE_LO", -1.0)
    ghi = _env_float("HUMANIZE_PAUSE_HI", -1.0)
    if glo >= 0 and ghi > glo:
        dlo, dhi = glo, ghi
    if lo is not None:
        dlo = lo
    if hi is not None:
        dhi = hi
    if dhi < dlo:
        dhi = dlo

    u = random.random()
    slept = dlo + (dhi - dlo) * (u * u if random.random() < 0.5 else (1 - (1 - u) * (1 - u)))
    if slept > 0.001:
        time.sleep(slept)
    return slept


def accept_language_header(lang: str, languages: str = "") -> str:
    """Accept-Language — JP HAR: ja,en-US;q=0.9,en;q=0.8"""
    lang = (lang or "en-US").strip()
    short = lang.split("-")[0] if lang else "en"
    if languages and ("q=" in languages or languages.count(",") >= 1):
        if "q=" in languages:
            return languages
        parts = [p.strip() for p in languages.split(",") if p.strip()]
        if parts:
            out = [parts[0]]
            qs = [0.9, 0.8, 0.7, 0.6]
            for i, p in enumerate(parts[1:]):
                q = qs[i] if i < len(qs) else max(0.5, 0.9 - 0.1 * i)
                out.append(f"{p};q={q}")
            return ",".join(out)

    low = lang.lower()
    if low.startswith("ja"):
        return "ja,en-US;q=0.9,en;q=0.8"
    if low.startswith("ko"):
        return "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"
    return f"{lang},{short};q=0.9,en;q=0.8"


def pick_impersonate() -> str:
    """Fallback TLS persona when no fingerprint profile is available."""
    raw = (os.environ.get("CURL_IMPERSONATE") or "").strip()
    if raw:
        return raw
    eng = (
        os.environ.get("TOKENREFRESH_SENTINEL_ENGINE")
        or os.environ.get("TOKENREFRESH_FP_FAMILY")
        or "formal-frame"
    ).strip().lower()
    if eng in ("legacy", "leaf", "chrome", "chrome146", "0", "off"):
        return "chrome146"
    return "firefox144"
