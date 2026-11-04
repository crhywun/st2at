#!/usr/bin/env python3
"""Shared SMS provider helpers — stop re-implementing key/env sanitization."""
from __future__ import annotations

import os
import re
from typing import Any


def clean_api_key(raw: str | None) -> str:
    """Strip quotes/whitespace that break provider APIs (historical noService bug)."""
    s = str(raw or "").strip()
    # strip surrounding quotes and trailing junk like `"dr`
    s = s.strip().strip('"').strip("'").strip()
    # common pollution from shell: key" or "key
    s = re.sub(r'^["\']+|["\']+$', "", s)
    # remove embedded CR/LF
    s = s.replace("\r", "").replace("\n", "").strip()
    return s


def env_key(*names: str, default: str = "") -> str:
    for n in names:
        v = clean_api_key(os.environ.get(n) or "")
        if v:
            return v
    return clean_api_key(default)


def env_float(name: str, default: float) -> float:
    raw = (os.environ.get(name) or "").strip().strip('"').strip("'")
    try:
        return float(raw) if raw else float(default)
    except Exception:
        return float(default)


def env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip().strip('"').strip("'")
    try:
        return int(float(raw)) if raw else int(default)
    except Exception:
        return int(default)


def parse_countries(raw: str | None, default: str = "gb") -> list[str]:
    s = (raw or default or "gb").strip()
    parts = re.split(r"[,|;\s]+", s)
    out: list[str] = []
    for p in parts:
        c = p.strip().lower()
        if c and c not in out:
            out.append(c)
    return out or [default]


def max_price_from_env(*names: str, default: float = 0.03) -> float:
    for n in names:
        raw = (os.environ.get(n) or "").strip().strip('"').strip("'")
        if not raw:
            continue
        try:
            return float(raw)
        except Exception:
            continue
    return float(default)


def summarize_error(err: Any, limit: int = 180) -> str:
    s = str(err or "").replace("\n", " ").strip()
    return s[:limit]
