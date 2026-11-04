"""FastAPI wrapper around the single ST -> AT operation."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import __version__
from .client import ST2ATClient
from .config import Settings
from .errors import ST2ATError

DESCRIPTION = (
    "One endpoint, one job: exchange a ChatGPT "
    "`__Secure-next-auth.session-token` for a fresh `accessToken`."
)


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_token: str = Field(
        min_length=1,
        max_length=32_768,
        description="Raw ST, Cookie header, or full browser cookie string.",
    )
    workspace_id: str | None = Field(
        default=None,
        max_length=200,
        description="Optional workspace/account id for workspace token exchange.",
    )

    @field_validator("session_token")
    @classmethod
    def _strip_token(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("session_token is empty")
        return value

    @field_validator("workspace_id")
    @classmethod
    def _strip_workspace(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class RefreshResponse(BaseModel):
    access_token: str
    session_token: str | None = None
    id_token: str | None = None
    token_type: str = "Bearer"
    email: str | None = None
    user_id: str | None = None
    account_id: str | None = None
    plan_type: str | None = None
    expires_at: datetime | None = None


class ErrorResponse(BaseModel):
    error: dict[str, str]


def create_app(client: ST2ATClient | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if client is not None:
            app.state.client = client
        else:
            settings = Settings.from_env()
            app.state.client = ST2ATClient(**settings.client_kwargs())
        yield

    app = FastAPI(
        title="st2at",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/v1/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ST2ATError)
    async def _st2at_error(_request: Request, exc: ST2ATError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.http_status,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index() -> HTMLResponse:
        from .web import INDEX_HTML

        return HTMLResponse(INDEX_HTML)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post(
        "/v1/refresh",
        response_model=RefreshResponse,
        responses={
            400: {"model": ErrorResponse},
            401: {"model": ErrorResponse},
            429: {"model": ErrorResponse},
            502: {"model": ErrorResponse},
        },
    )
    async def refresh(payload: RefreshRequest, request: Request) -> RefreshResponse:
        result = await request.app.state.client.refresh(
            payload.session_token,
            workspace_id=payload.workspace_id,
        )
        return RefreshResponse(**result.to_dict())

    return app


app = create_app()
