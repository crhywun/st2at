"""CPA per-account export format."""
from __future__ import annotations

import base64
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .utils import decode_jwt_segment


def _b64url_json(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _safe_name(value: str) -> str:
    return re.sub(r"[\\\\/:*?\"<>|]+", "_", value).strip()


def decode_access_token(access_token: str) -> dict:
    parts = str(access_token or "").split(".")
    if len(parts) < 2:
        return {}
    return decode_jwt_segment(parts[1])


def build_synthetic_id_token(email: str, account_id: str, plan_type: str,
                             user_id: str, access_payload: dict) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    exp = int(access_payload.get("exp") or (now + 90 * 24 * 3600))
    iat = int(access_payload.get("iat") or now)
    auth_time = int(access_payload.get("pwd_auth_time") or iat)
    sid_src = hashlib.md5(f"{email}|{account_id}|{user_id}".encode("utf-8")).hexdigest()
    jti_src = hashlib.md5(f"{email}|{account_id}|{exp}".encode("utf-8")).hexdigest()
    header = {"alg": "RS256", "typ": "JWT", "kid": "synthetic"}
    payload = {
        "amr": ["pwd", "otp", "mfa", "urn:openai:amr:otp_email"],
        "aud": [access_payload.get("client_id") or "app_EMoamEEZ73f0CkXaXp7hrann"],
        "auth_provider": "password",
        "auth_time": auth_time,
        "email": email,
        "email_verified": True,
        "exp": exp,
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account_id,
            "chatgpt_plan_type": plan_type,
            "chatgpt_user_id": user_id,
            "localhost": True,
            "user_id": user_id,
        },
        "iat": iat,
        "iss": "https://auth.openai.com",
        "jti": f"synthetic-{jti_src}",
        "name": email.split("@", 1)[0],
        "rat": iat,
        "sid": f"synthetic_session_{sid_src}",
        "sub": user_id,
    }
    return ".".join([
        _b64url_json(header),
        _b64url_json(payload),
        "c3ludGhldGljX3NpZ25hdHVyZV9mb3JfY3BhX3BhcnNpbmdfb25seQ",
    ])


def build_cpa_account(row: dict[str, Any], label: str = "cpa") -> dict:
    # 导出隐私：只取凭证字段，禁止 phone/getatext/sms 等进入 CPA 文件
    from .export_format import account_row_for_export, sanitize_for_export

    safe = account_row_for_export(row if isinstance(row, dict) else {})
    access_token = str(safe.get("access_token") or row.get("access_token") or "").strip()
    refresh_token = str(safe.get("refresh_token") or row.get("refresh_token") or "").strip()
    payload = decode_access_token(access_token)
    auth = payload.get("https://api.openai.com/auth", {}) or {}
    profile = payload.get("https://api.openai.com/profile", {}) or {}
    email = (
        str(safe.get("email") or row.get("email") or row.get("account") or "").strip()
        or str(profile.get("email") or "").strip()
    )
    account_id = str(safe.get("account_id") or row.get("account_id") or "").strip() or str(auth.get("chatgpt_account_id") or "")
    user_id = (
        str(auth.get("chatgpt_user_id") or auth.get("user_id") or "").strip()
        or f"user-{hashlib.md5(email.encode('utf-8')).hexdigest()[:24]}"
    )
    plan_type = str(safe.get("plan_type") or row.get("plan_type") or auth.get("chatgpt_plan_type") or "plus")
    exp = payload.get("exp")
    expired = None
    if isinstance(exp, (int, float)):
        expired = datetime.fromtimestamp(exp, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    exported_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    id_token = build_synthetic_id_token(email, account_id, plan_type, user_id, payload)
    obj = {
        "type": "codex",
        "account_id": account_id,
        "chatgpt_account_id": account_id,
        "email": email,
        "password": str(safe.get("password") or row.get("password") or "").strip(),
        "name": email,
        "plan_type": plan_type,
        "chatgpt_plan_type": plan_type,
        "id_token": id_token,
        "id_token_synthetic": True,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "last_refresh": exported_at,
        "expired": expired,
        "listing_status": label,
    }
    return sanitize_for_export(obj)


def export_cpa_account(row: dict[str, Any], out_dir: str | Path,
                       label: str = "cpa", index: int = 1) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    obj = build_cpa_account(row, label=label)
    filename = f"{index:03d}_{_safe_name(obj['email'])}_{label}.cpa.json"
    path = out / filename
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def export_cpa_from_csv(csv_path: str | Path, out_dir: str | Path,
                        label: str = "cpa", limit: int = 0) -> list[Path]:
    paths: list[Path] = []
    with Path(csv_path).open("r", encoding="utf-8-sig", newline="") as f:
        for idx, row in enumerate(csv.DictReader(f), start=1):
            if not (row.get("access_token") or "").strip():
                continue
            paths.append(export_cpa_account(row, out_dir, label=label, index=len(paths) + 1))
            if limit and len(paths) >= limit:
                break
    return paths
