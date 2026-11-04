"""导出模块 — CPA(sub2api) 格式导出
两种模式:
  at_only=True  → 只要 AT，不导出 refresh_token（用于不需要长期使用的场景）
  at_only=False → AT + RT 完整导出（用于需要 token 自动刷新的场景）
"""
import base64, hashlib, json, os, time
from datetime import datetime, timezone
from typing import Any


def _decode_jwt(token: str) -> dict:
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return {}
    seg = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:
        return {}


def _build_synthetic_id_token(email: str, account_id: str, plan_type: str,
                                user_id: str, at_payload: dict) -> str:
    """用 AT 的 JWT claim 拼出一个 id_token（sub2api 不需要验签，只要字段对）"""
    now = int(time.time())
    exp = at_payload.get("exp", now + 90 * 24 * 3600)
    iat = at_payload.get("iat", now)
    auth_time = at_payload.get("pwd_auth_time", iat)
    sid = hashlib.md5(f"{email}|{account_id}".encode()).hexdigest()
    jti = hashlib.md5(f"{email}|{exp}".encode()).hexdigest()

    header_b64 = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT", "kid": "synthetic"}).encode()
    ).rstrip(b"=").decode()

    payload = {
        "amr": ["pwd", "otp", "mfa", "urn:openai:amr:otp_email"],
        "aud": [at_payload.get("client_id", "app_EMoamEEZ73f0CkXaXp7hrann")],
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
        "jti": f"synthetic-{jti}",
        "name": email.split("@", 1)[0],
        "rat": iat,
        "sid": f"synthetic_session_{sid}",
        "sub": f"auth0|synthetic_{hashlib.md5(email.encode()).hexdigest()[:24]}",
    }
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    ).rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.synthetic"


def build_sub2api_account(email: str, access_token: str,
                           refresh_token: str = "",
                           password: str = "",
                           model_mapping: dict | None = None) -> dict:
    """构建单个 sub2api account 对象"""
    at_payload = _decode_jwt(access_token)
    auth = at_payload.get("https://api.openai.com/auth", {})
    profile = at_payload.get("https://api.openai.com/profile", {})

    account_id = auth.get("chatgpt_account_id", "")
    user_id = auth.get("chatgpt_user_id") or auth.get("user_id", "")
    plan_type = auth.get("chatgpt_plan_type", "free")
    exp = at_payload.get("exp", 0)
    org_id = auth.get("poid", "")

    expires_at = ""
    if exp:
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z")

    id_token = _build_synthetic_id_token(email, account_id, plan_type, user_id, at_payload)

    creds = {
        "access_token": access_token,
        "chatgpt_account_id": account_id,
        "chatgpt_user_id": user_id,
        "client_id": at_payload.get("client_id", "app_EMoamEEZ73f0CkXaXp7hrann"),
        "email": email,
        "expires_at": expires_at,
        "id_token": id_token,
        "organization_id": org_id,
        "plan_type": plan_type,
    }

    # 只有传了 RT 才导出
    if refresh_token:
        creds["refresh_token"] = refresh_token

    if model_mapping:
        creds["model_mapping"] = model_mapping

    return {
        "name": email,
        "platform": "openai",
        "type": "oauth",
        "credentials": creds,
        "extra": {
            "email": email,
            "privacy_mode": "training_off",
        },
        "concurrency": 10,
        "priority": 1,
        "rate_multiplier": 1,
        "auto_pause_on_expired": True,
    }


def export_sub2api(accounts: list[dict], output_path: str = "",
                    at_only: bool = False) -> str:
    """
    批量导出 sub2api JSON 格式。

    accounts: [{
        "email": str,           # 必填
        "access_token": str,    # 必填
        "refresh_token": str,   # 可选（at_only=True 时忽略）
        "password": str,        # 可选
        "model_mapping": dict,  # 可选
    }, ...]

    at_only: True = 只要 AT（不含 RT），False = AT + RT
    """
    exported_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    result_accounts = []

    for acct in accounts:
        email = acct.get("email", "")
        at = acct.get("access_token", "")
        if not email or not at:
            continue
        rt = "" if at_only else acct.get("refresh_token", "")
        pw = acct.get("password", "")
        mm = acct.get("model_mapping")

        obj = build_sub2api_account(email, at, refresh_token=rt,
                                     password=pw, model_mapping=mm)
        result_accounts.append(obj)

    export_obj = {
        "exported_at": exported_at,
        "proxies": [],
        "accounts": result_accounts,
    }

    if output_path:
        # Prefer shared writer (same shape as export_batch_store / gmail_k12_export)
        try:
            from export_batch_store import write_sub2api_file  # type: ignore
            from pathlib import Path as _P

            write_sub2api_file(_P(output_path), result_accounts)
        except Exception:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(export_obj, f, ensure_ascii=False, indent=2)
        print(f"[tokenrefresh] Exported {len(result_accounts)} accounts → {output_path}")
    else:
        # 没有路径就返回 JSON 字符串
        return json.dumps(export_obj, ensure_ascii=False, indent=2)

    return output_path


def export_from_csv(csv_path: str, output_path: str = "",
                    at_only: bool = False) -> str:
    """从 CSV 批量导出 sub2api 格式"""
    import csv as csv_mod

    rows = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        for r in csv_mod.DictReader(f):
            rows.append({
                "email": (r.get("email") or r.get("account") or "").strip(),
                "access_token": (r.get("access_token") or "").strip(),
                "refresh_token": (r.get("refresh_token") or "").strip(),
                "password": (r.get("password") or "").strip(),
            })

    if not output_path:
        output_path = csv_path.replace(".csv", "_sub2api.json")

    return export_sub2api(rows, output_path, at_only=at_only)
