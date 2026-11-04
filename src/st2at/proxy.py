"""Normalize 711/BestGo-style sticky proxies and rotate one exit per request."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit

DEFAULT_SCHEME = "socks5h"
DEFAULT_SESS_TIME = 180

_REGION_RE = re.compile(r"(?i)(^|-)region-([A-Za-z]{2})(?=-|$)")
_SESSION_RE = re.compile(r"(?i)-session-([A-Za-z0-9]+)")
_SID_RE = re.compile(r"(?i)-sid-([A-Za-z0-9]+)")
_SESS_TIME_RE = re.compile(r"(?i)-sessTime-(\d+)")
_PLACEHOLDER_RE = re.compile(r"\{[A-Za-z0-9_]+\}")


@dataclass(slots=True)
class ProxySpec:
    host: str
    port: int
    username: str = ""
    password: str = ""
    scheme: str = DEFAULT_SCHEME
    raw: str = ""
    region: str = ""
    session: str = ""
    sess_time: int = DEFAULT_SESS_TIME

    def to_uri(self) -> str:
        host = (
            f"[{self.host}]"
            if ":" in self.host and not self.host.startswith("[")
            else self.host
        )
        if not self.username:
            return f"{self.scheme}://{host}:{self.port}"

        placeholders: dict[str, str] = {}

        def stash(match: re.Match[str]) -> str:
            key = f"__PH{len(placeholders)}__"
            placeholders[key] = match.group(0)
            return key

        user = _PLACEHOLDER_RE.sub(stash, self.username)
        password = _PLACEHOLDER_RE.sub(stash, self.password)
        encoded_user = quote(user, safe="")
        encoded_password = quote(password, safe="")
        for key, value in placeholders.items():
            encoded_user = encoded_user.replace(key, value)
            encoded_password = encoded_password.replace(key, value)
        return f"{self.scheme}://{encoded_user}:{encoded_password}@{host}:{self.port}"

    def with_region(self, region: str | None) -> ProxySpec:
        code = str(region or "").strip().upper()
        if not code:
            return self
        if not re.fullmatch(r"[A-Z]{2}", code):
            raise ValueError("proxy region must be a two-letter country code")
        username = self.username
        if not username:
            return self
        if _REGION_RE.search(username):
            username = _REGION_RE.sub(
                lambda match: f"{match.group(1)}region-{code}", username, count=1
            )
        else:
            username = f"{username}-region-{code}"
        return ProxySpec(
            host=self.host,
            port=self.port,
            username=username,
            password=self.password,
            scheme=self.scheme,
            raw=self.raw,
            region=code,
            session=self.session,
            sess_time=self.sess_time,
        )

    def with_new_session(self, session: str | None = None) -> ProxySpec:
        sid = (session or secrets.token_hex(6)).strip()
        username = self.username
        if _SID_RE.search(username):
            username = _SID_RE.sub("", username)
            username = re.sub(r"-{2,}", "-", username).strip("-")
        if _SESSION_RE.search(username):
            username = _SESSION_RE.sub(f"-session-{sid}", username, count=1)
        elif _SESS_TIME_RE.search(username):
            username = _SESS_TIME_RE.sub(
                f"-session-{sid}-sessTime-{self.sess_time or DEFAULT_SESS_TIME}",
                username,
                count=1,
            )
        else:
            username = f"{username}-session-{sid}" if username else f"session-{sid}"

        if _SESS_TIME_RE.search(username):
            username = _SESS_TIME_RE.sub(
                f"-sessTime-{self.sess_time or DEFAULT_SESS_TIME}", username, count=1
            )
        else:
            username = f"{username}-sessTime-{self.sess_time or DEFAULT_SESS_TIME}"

        return ProxySpec(
            host=self.host,
            port=self.port,
            username=username,
            password=self.password,
            scheme=self.scheme,
            raw=self.raw,
            region=self.region,
            session=sid,
            sess_time=self.sess_time or DEFAULT_SESS_TIME,
        )


def parse_proxy(value: str) -> ProxySpec:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("proxy is empty")

    if "://" in raw:
        parsed = urlsplit(raw)
        if not parsed.hostname or not parsed.port:
            raise ValueError("proxy URL must include host and port")
        spec = ProxySpec(
            host=parsed.hostname,
            port=parsed.port,
            username=unquote(parsed.username or ""),
            password=unquote(parsed.password or ""),
            scheme=(parsed.scheme or DEFAULT_SCHEME).lower(),
            raw=raw,
        )
    else:
        parts = raw.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            spec = ProxySpec(host=parts[0], port=int(parts[1]), raw=raw)
        elif len(parts) >= 4 and parts[1].isdigit():
            spec = ProxySpec(
                host=parts[0],
                port=int(parts[1]),
                username=parts[2],
                password=":".join(parts[3:]),
                raw=raw,
            )
        else:
            raise ValueError("proxy must be host:port:user:pass or a supported URI")

    if spec.username:
        match = _REGION_RE.search(spec.username)
        if match:
            spec.region = match.group(2).upper()
        match = _SESSION_RE.search(spec.username)
        if not match:
            match = _SID_RE.search(spec.username)
        if match:
            spec.session = match.group(1)
        match = _SESS_TIME_RE.search(spec.username)
        if match:
            spec.sess_time = int(match.group(1))
    return spec


def prepare_proxy(
    value: str | None,
    *,
    region: str | None = None,
    rotate_session: bool = True,
    session: str | None = None,
) -> str | None:
    """Return a curl-ready URI with region pinned and a fresh sticky session.

    Bare ``host:port:user:pass`` strings default to ``socks5h://``. A session is
    replaced on every call so two requests do not share an exit IP. Static
    HTTP(S) proxy URLs without 711 markers are passed through unchanged.
    """

    if not value or not str(value).strip():
        return None
    raw = str(value).strip()
    spec = parse_proxy(raw)
    is_bare = "://" not in raw
    has_session_marker = bool(
        _SESSION_RE.search(spec.username) or _SID_RE.search(spec.username)
    )

    if region:
        spec = spec.with_region(region)
    if spec.username and (is_bare or has_session_marker):
        if rotate_session or not spec.session:
            spec = spec.with_new_session(session)

    return spec.to_uri()
