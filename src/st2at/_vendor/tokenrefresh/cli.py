"""Command line interface for tokenrefresh."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__
from .api import (
    bind_phone,
    check_usage,
    init_hotmail,
    login_and_export,
    login_only,
    login_web_only,
    refresh_access_token,
)
from .export_format import export_from_csv
from .cpa import export_cpa_from_csv


def _print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _add_account_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", default="")
    parser.add_argument("--mail-url", default="")
    parser.add_argument("--proxy", default="")
    parser.add_argument("--account-id", default="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m tokenrefresh")
    parser.add_argument("--version", action="version", version=f"tokenrefresh {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("self-test", help="run offline import and helper checks")
    p.set_defaults(func=cmd_self_test)

    p = sub.add_parser("init-hotmail", help="configure Hotmail API for this process")
    p.add_argument("--doc-path", default="")
    p.add_argument("--api-base", default="")
    p.add_argument("--admin-password", default="")
    p.set_defaults(func=cmd_init_hotmail)

    p = sub.add_parser("login", help="run Codex OAuth login and print tokens")
    _add_account_args(p)
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("web-login", help="run ChatGPT web login only")
    _add_account_args(p)
    p.set_defaults(func=cmd_web_login)

    p = sub.add_parser("refresh", help="refresh access token using RT first")
    _add_account_args(p)
    p.add_argument("--refresh-token", required=True)
    p.set_defaults(func=cmd_refresh)

    p = sub.add_parser("bind-phone", help="login, bind phone if required, and print tokens")
    _add_account_args(p)
    p.add_argument("--sms-config", default="", help="JSON string or path")
    p.set_defaults(func=cmd_bind_phone)

    p = sub.add_parser("smsbower-mail", help="request an SMSBower mailbox activation")
    p.add_argument("--api-key", default="")
    p.add_argument("--service", default="")
    p.add_argument("--domain", default="gmail.com")
    p.add_argument("--alias", default="1")
    p.set_defaults(func=cmd_smsbower_mail)

    # SMSBower 手机 SMS（handler_api）查询 / 租号
    p = sub.add_parser(
        "smsbower-sms",
        help="SMSBower phone SMS: balance|services|countries|prices|top-countries|get-number",
    )
    p.add_argument(
        "action",
        choices=(
            "balance",
            "services",
            "countries",
            "prices",
            "prices-v2",
            "prices-v3",
            "top-countries",
            "get-number",
        ),
        help="query or get-number",
    )
    p.add_argument("--api-key", default="", help="or SMSBOWER_SMS_API_KEY / SMSBOWER_API_KEY")
    p.add_argument("--service", default="", help="service code e.g. dr / oi (for prices/get-number)")
    p.add_argument("--country", default="", help="country id e.g. 12")
    p.add_argument("--max-price", type=float, default=0.0)
    p.add_argument("--provider-ids", default="")
    p.add_argument("--except-provider-ids", default="")
    p.add_argument("--v1", action="store_true", help="use getNumber not V2")
    p.set_defaults(func=cmd_smsbower_sms)

    p = sub.add_parser("usage", help="check Codex usage for an access token")
    p.add_argument("--access-token", required=True)
    p.set_defaults(func=cmd_usage)

    p = sub.add_parser("login-export", help="login and export sub2api JSON")
    _add_account_args(p)
    p.add_argument("--output", default="")
    p.add_argument("--at-only", action="store_true")
    p.set_defaults(func=cmd_login_export)

    p = sub.add_parser("export-csv", help="convert existing token CSV to sub2api JSON")
    p.add_argument("--csv", required=True)
    p.add_argument("--output", default="")
    p.add_argument("--at-only", action="store_true")
    p.set_defaults(func=cmd_export_csv)

    p = sub.add_parser("export-cpa-csv", help="convert existing token CSV to CPA JSON files")
    p.add_argument("--csv", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--label", default="cpa")
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=cmd_export_cpa_csv)
    return parser


def cmd_self_test(args) -> int:
    from .getatext import build_getatext_provider
    from .smsbower_sms import build_smsbower_sms_provider, build_sms_provider
    from .utils import generate_pkce, token_exp

    verifier, challenge = generate_pkce()
    gt = build_getatext_provider() is not None
    sb = build_smsbower_sms_provider() is not None
    result = {
        "ok": bool(verifier and challenge),
        "version": __version__,
        "pkce": {"verifier_len": len(verifier), "challenge_len": len(challenge)},
        "bad_token_exp": token_exp("bad"),
        "getatext_configured": gt,
        "smsbower_sms_configured": sb,
        "sms_provider_configured": gt or sb,
        "unified_build": build_sms_provider() is not None,
    }
    _print_json(result)
    return 0 if result["ok"] else 1


def cmd_init_hotmail(args) -> int:
    api_base, admin_password = init_hotmail(
        doc_path=args.doc_path,
        api_base=args.api_base,
        admin_password=args.admin_password,
    )
    _print_json({"api_base": api_base, "admin_password_configured": bool(admin_password)})
    return 0


def cmd_login(args) -> int:
    _print_json(login_only(args.email, args.password, args.mail_url, args.proxy, args.account_id))
    return 0


def cmd_web_login(args) -> int:
    _print_json(login_web_only(args.email, args.password, args.mail_url, args.proxy, args.account_id))
    return 0


def cmd_refresh(args) -> int:
    _print_json(refresh_access_token(
        args.email,
        args.password,
        args.mail_url,
        args.proxy,
        args.refresh_token,
        args.account_id,
    ))
    return 0


def _load_sms_config(raw: str) -> dict | None:
    if not raw:
        return None
    try:
        if raw.strip().startswith("{"):
            data = json.loads(raw)
        else:
            with open(raw, "r", encoding="utf-8") as f:
                data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception as exc:
        raise SystemExit(f"invalid --sms-config: {exc}") from exc


def cmd_bind_phone(args) -> int:
    _print_json(bind_phone(
        args.email,
        args.password,
        args.mail_url,
        args.proxy,
        args.account_id,
        sms_config=_load_sms_config(args.sms_config),
    ))
    return 0


def cmd_smsbower_mail(args) -> int:
    from .email_ import smsbower_get_activation
    _print_json(smsbower_get_activation(
        api_key=args.api_key,
        service=args.service,
        domain=args.domain,
        alias=args.alias,
    ))
    return 0


def cmd_smsbower_sms(args) -> int:
    """SMSBower handler_api: 查询余额/服务/国家/价格 或 租号。"""
    import os
    from .smsbower_sms import SmsbowerSmsClient, build_smsbower_sms_provider

    key = (
        (args.api_key or "").strip()
        or os.environ.get("SMSBOWER_SMS_API_KEY", "").strip()
        or os.environ.get("SMSBOWER_API_KEY", "").strip()
    )
    if not key:
        raise SystemExit("need --api-key or SMSBOWER_SMS_API_KEY / SMSBOWER_API_KEY")

    client = SmsbowerSmsClient(key)
    action = args.action
    try:
        if action == "balance":
            _print_json(client.get_balance())
        elif action == "services":
            _print_json(client.get_services_list())
        elif action == "countries":
            _print_json(client.get_countries())
        elif action == "prices":
            _print_json(
                client.get_prices(service=args.service or "", country=args.country or "")
            )
        elif action == "prices-v2":
            _print_json(
                client.get_prices_v2(
                    service=args.service or "", country=args.country or ""
                )
            )
        elif action == "prices-v3":
            _print_json(
                client.get_prices_v3(
                    service=args.service or "", country=args.country or ""
                )
            )
        elif action == "top-countries":
            if not args.service:
                raise SystemExit("--service required for top-countries")
            _print_json(client.get_top_countries_by_service(args.service))
        elif action == "get-number":
            country: str | int = args.country or os.environ.get("SMSBOWER_SMS_COUNTRY") or "12"
            if str(country).isdigit():
                country = int(country)
            service = args.service or os.environ.get("SMSBOWER_SMS_SERVICE") or "dr"
            max_price = args.max_price or None
            if args.v1:
                _print_json(
                    client.get_number(
                        service,
                        country,
                        max_price=max_price,
                        provider_ids=args.provider_ids,
                        except_provider_ids=args.except_provider_ids,
                    )
                )
            else:
                _print_json(
                    client.get_number_v2(
                        service,
                        country,
                        max_price=max_price,
                        provider_ids=args.provider_ids,
                        except_provider_ids=args.except_provider_ids,
                    )
                )
        else:
            raise SystemExit(f"unknown action {action}")
    finally:
        client.close()
    return 0


def cmd_usage(args) -> int:
    data = check_usage(args.access_token)
    _print_json(data or {"ok": False, "error": "usage_check_failed"})
    return 0 if data else 1


def cmd_login_export(args) -> int:
    path = login_and_export(
        args.email,
        args.password,
        args.mail_url,
        args.proxy,
        args.output,
        args.at_only,
    )
    _print_json({"output": path})
    return 0


def cmd_export_csv(args) -> int:
    path = export_from_csv(args.csv, args.output, args.at_only)
    _print_json({"output": path})
    return 0


def cmd_export_cpa_csv(args) -> int:
    paths = export_cpa_from_csv(args.csv, args.out_dir, args.label, args.limit)
    _print_json({"count": len(paths), "files": [str(p) for p in paths]})
    return 0 if paths else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"tokenrefresh: {exc}", file=sys.stderr)
        return 1
