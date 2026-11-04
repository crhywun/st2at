"""Command-line interface for one-off ST -> AT exchanges."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .client import DEFAULT_IMPERSONATE, ST2ATClient
from .errors import ST2ATError


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _read_token(args: argparse.Namespace) -> str:
    if args.st:
        return args.st
    if args.st_file:
        if args.st_file == "-":
            return sys.stdin.read()
        return Path(args.st_file).read_text(encoding="utf-8")
    env_token = os.getenv("ST2AT_SESSION_TOKEN", "").strip()
    if env_token:
        return env_token
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise ValueError("provide --st, --st-file, or ST2AT_SESSION_TOKEN")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="st2at",
        description="Exchange a ChatGPT session token (ST) for an access token (AT).",
    )
    parser.add_argument("--version", action="version", version=f"st2at {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    refresh = sub.add_parser("refresh", help="refresh one AT from one ST")
    source = refresh.add_mutually_exclusive_group()
    source.add_argument("--st", help="raw ST or a full Cookie header")
    source.add_argument("--st-file", help="file containing the ST; '-' reads stdin")
    refresh.add_argument("--workspace-id", help="optional workspace/account id")
    refresh.add_argument(
        "--proxy",
        default=os.getenv("ST2AT_PROXY", "").strip() or None,
        help="HTTP/SOCKS proxy URI or host:port:user:pass; defaults to ST2AT_PROXY",
    )
    refresh.add_argument(
        "--proxy-region",
        default=os.getenv("ST2AT_PROXY_REGION", "").strip().upper() or None,
        help="two-letter exit country code; overrides -region-XX in the proxy username",
    )
    refresh.add_argument(
        "--impersonate",
        default=os.getenv("ST2AT_IMPERSONATE", DEFAULT_IMPERSONATE),
        help=f"curl_cffi browser profile (default: {DEFAULT_IMPERSONATE})",
    )
    refresh.add_argument(
        "--timeout",
        type=float,
        default=_env_float("ST2AT_TIMEOUT", 30.0),
        help="request timeout in seconds (default: 30)",
    )
    refresh.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification",
    )
    refresh.add_argument(
        "--json",
        action="store_true",
        help="print the result as JSON",
    )

    login = sub.add_parser(
        "login",
        help="re-login with email + password + TOTP to obtain a fresh AT/ST",
    )
    login.add_argument("--email", required=True)
    login.add_argument(
        "--password",
        default=os.getenv("ST2AT_LOGIN_PASSWORD"),
        help="account password; defaults to ST2AT_LOGIN_PASSWORD",
    )
    login.add_argument(
        "--totp-secret",
        default=os.getenv("ST2AT_TOTP_SECRET"),
        help="base32 TOTP secret; defaults to ST2AT_TOTP_SECRET",
    )
    login.add_argument(
        "--proxy",
        default=os.getenv("ST2AT_PROXY", "").strip() or None,
        help="HTTP/SOCKS proxy URI or host:port:user:pass",
    )
    login.add_argument(
        "--proxy-region",
        default=os.getenv("ST2AT_PROXY_REGION", "").strip().upper() or "JP",
        help="two-letter exit country code (default: JP)",
    )
    login.add_argument(
        "--workspace-id",
        default=os.getenv("ST2AT_WORKSPACE_ID", "").strip() or "",
        help="optional workspace id to select during login",
    )
    login.add_argument(
        "--verbose",
        action="store_true",
        help="show upstream login progress on stderr",
    )
    login.add_argument(
        "--json",
        action="store_true",
        help="print the result as JSON",
    )
    return parser


async def _run(args: argparse.Namespace) -> int:
    try:
        token = _read_token(args)
    except (OSError, ValueError) as exc:
        print(f"st2at: {exc}", file=sys.stderr)
        return 2

    client = ST2ATClient(
        proxy=args.proxy,
        proxy_region=args.proxy_region,
        impersonate=args.impersonate,
        timeout=args.timeout,
        verify_tls=not args.insecure,
    )
    try:
        result = await client.refresh(token, workspace_id=args.workspace_id)
    except ST2ATError as exc:
        if args.json:
            print(
                json.dumps(
                    {"error": {"code": exc.code, "message": exc.message}},
                    ensure_ascii=False,
                ),
                file=sys.stderr,
            )
        else:
            print(f"st2at: [{exc.code}] {exc.message}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        return 130

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return 0

    data = result.to_dict()
    print(f"access_token: {data['access_token']}")
    if data["session_token"]:
        print(f"session_token: {data['session_token']}  # rotated, replace the old ST")
    else:
        print("session_token: (unchanged)")
    if data["email"]:
        print(f"email: {data['email']}")
    if data["account_id"]:
        print(f"account_id: {data['account_id']}")
    if data["plan_type"]:
        print(f"plan_type: {data['plan_type']}")
    if data["expires_at"]:
        print(f"expires_at: {data['expires_at']}")
    return 0


def _run_login(args: argparse.Namespace) -> int:
    from .login import login_with_password_totp

    if not args.password:
        print(
            "st2at: password is required (--password or ST2AT_LOGIN_PASSWORD)",
            file=sys.stderr,
        )
        return 2
    if not args.totp_secret:
        print(
            "st2at: totp secret is required (--totp-secret or ST2AT_TOTP_SECRET)",
            file=sys.stderr,
        )
        return 2

    log = (
        (lambda message: print(message, file=sys.stderr))
        if args.verbose
        else (lambda _message: None)
    )
    result = login_with_password_totp(
        args.email,
        password=args.password,
        totp_secret=args.totp_secret,
        proxy=args.proxy,
        region=args.proxy_region,
        workspace_id=args.workspace_id,
        log=log,
    )
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"ok: {result.ok}")
        print(f"email: {result.email}")
        if result.access_token:
            print(f"access_token: {result.access_token}")
        if result.session_token:
            print(f"session_token: {result.session_token}")
        if result.account_id:
            print(f"account_id: {result.account_id}")
        if result.expires_at:
            print(f"expires_at: {result.expires_at.isoformat()}")
        if result.error:
            print(f"error: {result.error}", file=sys.stderr)
    return 0 if result.ok else 3


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "refresh":
        try:
            return asyncio.run(_run(args))
        except KeyboardInterrupt:
            return 130
    if args.command == "login":
        try:
            return _run_login(args)
        except KeyboardInterrupt:
            return 130
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
