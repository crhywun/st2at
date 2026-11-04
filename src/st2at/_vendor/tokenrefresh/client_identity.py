"""ChatGPT SPA client identity headers (HAR-aligned).

Browser backend-api traffic (incl. MFA) consistently carries:

  - oai-device-id
  - oai-language
  - oai-session-id          (tab/session UUID; may rotate on settings)
  - oai-client-version      (prod-<gitsha>)
  - oai-client-build-number (numeric build)

Defaults from jp-10 / DE MFA HARs (2026-08). Override via env:

  TOKENREFRESH_OAI_CLIENT_VERSION
  TOKENREFRESH_OAI_CLIENT_BUILD
  TOKENREFRESH_OAI_CLIENT_APP_VERSION   # short hash for CES app_version
"""
from __future__ import annotations

import os
import threading
import uuid
from typing import Any

# jp-10 MFA.har majority (prod SPA at capture time)
_DEFAULT_CLIENT_VERSION = "prod-8dc46c0bf879fa365184a5977c27612ef03adb30"
_DEFAULT_CLIENT_BUILD = "8929561"

_tls = threading.local()


def client_version() -> str:
    raw = (os.environ.get("TOKENREFRESH_OAI_CLIENT_VERSION") or "").strip()
    return raw or _DEFAULT_CLIENT_VERSION


def client_build_number() -> str:
    raw = (os.environ.get("TOKENREFRESH_OAI_CLIENT_BUILD") or "").strip()
    return raw or _DEFAULT_CLIENT_BUILD


def app_version_short() -> str:
    """CES properties.app_version is the bare git sha (no prod- prefix)."""
    raw = (os.environ.get("TOKENREFRESH_OAI_CLIENT_APP_VERSION") or "").strip()
    if raw:
        return raw
    ver = client_version()
    if ver.startswith("prod-"):
        return ver[5:]
    return ver


def new_session_id() -> str:
    return str(uuid.uuid4())


def get_or_create_session_id(refresher: Any = None, *, rotate: bool = False) -> str:
    """Stable oai-session-id for the process/thread, optionally on a refresher."""
    if refresher is not None:
        if rotate or not str(getattr(refresher, "oai_session_id", "") or "").strip():
            sid = new_session_id()
            try:
                setattr(refresher, "oai_session_id", sid)
            except Exception:
                pass
            return sid
        return str(getattr(refresher, "oai_session_id", "") or "").strip()

    if rotate or not str(getattr(_tls, "oai_session_id", "") or "").strip():
        _tls.oai_session_id = new_session_id()
    return str(_tls.oai_session_id)


def apply_client_identity_headers(
    headers: dict[str, str],
    *,
    device_id: str = "",
    language: str = "",
    session_id: str = "",
    refresher: Any = None,
    rotate_session: bool = False,
) -> dict[str, str]:
    """Mutate and return headers with SPA client identity fields."""
    did = (device_id or "").strip()
    if not did and refresher is not None:
        did = str(getattr(refresher, "device_id", "") or "").strip()
    if did:
        headers["oai-device-id"] = did

    lang = (language or "").strip()
    if not lang and refresher is not None:
        fp = getattr(refresher, "fingerprint_profile", None) or {}
        lang = str(fp.get("language") or "").strip()
    if lang:
        headers["oai-language"] = lang

    sid = (session_id or "").strip()
    if not sid:
        sid = get_or_create_session_id(refresher, rotate=rotate_session)
    if sid:
        headers["oai-session-id"] = sid

    headers["oai-client-version"] = client_version()
    headers["oai-client-build-number"] = client_build_number()
    return headers


def bind_session_on_refresher(refresher: Any, *, rotate: bool = False) -> str:
    """Ensure refresher.oai_session_id is set; return it."""
    return get_or_create_session_id(refresher, rotate=rotate)
