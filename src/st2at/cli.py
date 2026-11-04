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
        help="HTTP/SOCKS proxy URL; defaults to ST2AT_PROXY",
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
    return parser


async def _run(args: argparse.Namespace) -> int:
    try:
        token = _read_token(args)
    except (OSError, ValueError) as exc:
        print(f"st2at: {exc}", file=sys.stderr)
        return 2

    client = ST2ATClient(
        proxy=args.proxy,
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "refresh":
        try:
            return asyncio.run(_run(args))
        except KeyboardInterrupt:
            return 130
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
