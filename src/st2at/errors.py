"""Typed errors returned by the core client and the HTTP API."""

from __future__ import annotations


class ST2ATError(Exception):
    """Base error with a stable machine-readable code and HTTP status."""

    code = "st2at_error"
    http_status = 502

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class InvalidSessionTokenError(ST2ATError):
    code = "invalid_session_token"
    http_status = 400


class InvalidWorkspaceError(ST2ATError):
    code = "invalid_workspace"
    http_status = 400


class SessionRejectedError(ST2ATError):
    code = "session_rejected"
    http_status = 401


class RateLimitedError(ST2ATError):
    code = "upstream_rate_limited"
    http_status = 429


class UpstreamHTTPError(ST2ATError):
    code = "upstream_http_error"
    http_status = 502

    def __init__(self, message: str, upstream_status: int) -> None:
        super().__init__(message)
        self.upstream_status = upstream_status


class UpstreamResponseError(ST2ATError):
    code = "upstream_bad_response"
    http_status = 502


class UpstreamTransportError(ST2ATError):
    code = "upstream_transport_error"
    http_status = 502
