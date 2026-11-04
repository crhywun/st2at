"""Environment-only configuration for the service entry point."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True, slots=True)
class Settings:
    host: str = "0.0.0.0"
    port: int = 8000
    proxy: str | None = None
    impersonate: str = "chrome110"
    timeout: float = 30.0
    verify_tls: bool = True

    @classmethod
    def from_env(cls) -> Settings:
        proxy = os.getenv("ST2AT_PROXY", "").strip() or None
        return cls(
            host=os.getenv("ST2AT_HOST", "0.0.0.0"),
            port=int(os.getenv("ST2AT_PORT", "8000")),
            proxy=proxy,
            impersonate=os.getenv("ST2AT_IMPERSONATE", "chrome110"),
            timeout=_env_float("ST2AT_TIMEOUT", 30.0),
            verify_tls=_env_bool("ST2AT_VERIFY_TLS", True),
        )

    def client_kwargs(self) -> dict[str, object]:
        return {
            "proxy": self.proxy,
            "impersonate": self.impersonate,
            "timeout": self.timeout,
            "verify_tls": self.verify_tls,
        }
