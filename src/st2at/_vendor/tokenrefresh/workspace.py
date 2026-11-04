"""Workspace & Team 选择"""
import json, time
from typing import Any
from urllib.parse import urljoin

from . import constants as C
from .utils import (
    request_with_retry, response_json, save_debug, log_line,
    extract_workspace_id_from_cookie, extract_workspace_id_from_payload,
    extract_workspace_id_from_html, has_oauth_code, apply_sentinel_headers,
)


def select_workspace_and_follow(refresher, email: str, account_id: str,
                                  payload: dict) -> dict:
    """
    Codex OAuth workspace/consent 选择 + 跟随重定向拿到 OAuth code。
    6 个来源依次尝试提取 workspace_id：
      1. oai-client-auth-session cookie JWT
      2. payload 递归提取
      3. GET consent HTML 页面
      4. GET consent.data JSON
      5. GET client_auth_session_dump
      6. account_id 参数兜底
    """
    consent_url = f"{C.AUTH_BASE}/sign-in-with-chatgpt/codex/consent"

    # 1. Cookie JWT
    auth_cookie = ""
    try:
        auth_cookie = str(refresher.session.cookies.get("oai-client-auth-session") or "").strip()
    except Exception:
        pass
    refresher._log(f"Auth cookie present: {'yes' if auth_cookie else 'no'}")

    workspace_id = extract_workspace_id_from_cookie(auth_cookie)

    # 2. Payload 递归
    if not workspace_id and isinstance(payload, dict):
        workspace_id = extract_workspace_id_from_payload(payload)

    # 3. Consent HTML 页面
    if not workspace_id:
        page_resp, _ = request_with_retry(
            refresher.session, "get", consent_url,
            headers=refresher._navigate_headers(consent_url),
            allow_redirects=False, verify=False, timeout=20,
        )
        if page_resp is not None:
            location = str(page_resp.headers.get("Location") or page_resp.headers.get("location") or "").strip()
            final_url = urljoin(consent_url, location) if location else str(page_resp.url or consent_url)
            if has_oauth_code(final_url):
                save_debug(email, "codex_consent_oauth_callback",
                           {"continue_url": final_url, "method": "GET", "page": {"type": "oauth_callback"}},
                           status_code=getattr(page_resp, "status_code", ""))
                return {"continue_url": final_url, "page": {"type": "oauth_callback"}}
            workspace_id = extract_workspace_id_from_html(page_resp.text or "")

    # 4. Consent.data JSON
    if not workspace_id:
        data_resp, _ = request_with_retry(
            refresher.session, "get", consent_url + ".data",
            headers={"accept": "application/json", "referer": consent_url},
            verify=False, timeout=20,
        )
        if data_resp is not None:
            data_payload = response_json(data_resp)
            workspace_id = extract_workspace_id_from_payload(data_payload)

    # 5. Client auth session dump
    if not workspace_id:
        dump_resp, _ = request_with_retry(
            refresher.session, "get", f"{C.AUTH_BASE}/api/accounts/client_auth_session_dump",
            headers={"accept": "application/json", "referer": consent_url},
            verify=False, timeout=20,
        )
        if dump_resp is not None:
            dump_payload = response_json(dump_resp)
            workspace_id = extract_workspace_id_from_payload(dump_payload)

    # 6. account_id 兜底
    if not workspace_id:
        workspace_id = str(account_id or "").strip()
        if workspace_id:
            refresher._log("Workspace id recovered from target account_id")

    if not workspace_id:
        refresher._log("Workspace id missing from all sources")
        return payload

    # HAR-verified: Codex consent flow 不需要 sentinel token
    headers = refresher._json_headers(consent_url)
    resp, error = request_with_retry(
        refresher.session, "post",
        f"{C.AUTH_BASE}/api/accounts/workspace/select",
        json_data={"workspace_id": workspace_id},
        headers=headers, verify=False,
    )
    if resp is None:
        refresher._log(f"Workspace select failed: {error}")
        return payload

    ws_payload = response_json(resp)
    save_debug(email, "workspace_select", ws_payload,
               status_code=getattr(resp, "status_code", ""),
               extra={"workspace_id": workspace_id})

    # 409 invalid_state → sentinel token 重试
    ws_error = ws_payload.get("error") if isinstance(ws_payload, dict) else {}
    if getattr(resp, "status_code", 0) == 409 and isinstance(ws_error, dict) and str(ws_error.get("code") or "") == "invalid_state":
        retry_headers = dict(headers)
        try:
            apply_sentinel_headers(retry_headers, refresher.session, refresher.device_id, "workspace_select")
        except Exception:
            retry_headers = {}
        if retry_headers:
            resp2, _ = request_with_retry(
                refresher.session, "post",
                f"{C.AUTH_BASE}/api/accounts/workspace/select",
                json_data={"workspace_id": workspace_id},
                headers=retry_headers, verify=False,
            )
            if resp2 is not None:
                ws_payload = response_json(resp2)
                save_debug(email, "workspace_select_retry_sentinel", ws_payload,
                           status_code=getattr(resp2, "status_code", ""),
                           extra={"workspace_id": workspace_id})

    continue_url = str(ws_payload.get("continue_url") or "").strip()

    # Organization select（如果有 orgs 列表）
    orgs = (((ws_payload.get("data") or {}).get("orgs")) or []) if isinstance(ws_payload.get("data"), dict) else []
    if isinstance(orgs, list) and orgs:
        org = orgs[0] if isinstance(orgs[0], dict) else {}
        project = ((org.get("projects") or [{}])[0] if isinstance(org.get("projects"), list) and org.get("projects") else {})
        org_id = str(org.get("id") or org.get("public_id") or "").strip()
        project_id = str(project.get("id") or project.get("public_id") or "").strip()
        if org_id and project_id:
            refresher._log(f"Organization select: {org_id[:8]}... / {project_id[:8]}...")
            org_headers = refresher._json_headers(f"{C.AUTH_BASE}/sign-in-with-chatgpt/codex/organization")
            org_resp, _ = request_with_retry(
                refresher.session, "post",
                f"{C.AUTH_BASE}/api/accounts/organization/select",
                json_data={"org_id": org_id, "project_id": project_id},
                headers=org_headers, verify=False,
            )
            if org_resp is not None:
                org_payload = response_json(org_resp)
                save_debug(email, "organization_select", org_payload,
                           status_code=getattr(org_resp, "status_code", ""),
                           extra={"org_id": org_id, "project_id": project_id})
                if str(org_payload.get("continue_url") or "").strip():
                    ws_payload = org_payload
                    continue_url = str(ws_payload.get("continue_url") or "").strip()

    if not continue_url:
        refresher._log("Workspace select returned no continue_url")
        return ws_payload or payload

    # 跟随重定向链（最多 6 跳）
    current_url = continue_url
    for _ in range(6):
        if has_oauth_code(current_url):
            save_debug(email, "oauth_callback",
                       {"continue_url": current_url, "method": "GET", "page": {"type": "oauth_callback"}})
            return {"continue_url": current_url, "page": {"type": "oauth_callback"}}

        follow_resp, follow_error = request_with_retry(
            refresher.session, "get", current_url,
            headers=refresher._navigate_headers(consent_url),
            allow_redirects=False, verify=False, timeout=20,
        )
        if follow_resp is None:
            break
        location = str(follow_resp.headers.get("Location") or follow_resp.headers.get("location") or "").strip()
        if follow_resp.status_code not in (301, 302, 303, 307, 308) or not location:
            break
        next_url = urljoin(current_url, location)
        if has_oauth_code(next_url):
            save_debug(email, "oauth_callback",
                       {"continue_url": next_url, "method": "GET", "page": {"type": "oauth_callback"}})
            return {"continue_url": next_url, "page": {"type": "oauth_callback"}}
        current_url = next_url

    return ws_payload if isinstance(ws_payload, dict) and ws_payload else payload


def select_web_workspace(refresher, email: str, account_id: str,
                           payload: dict) -> dict:
    """
    Web 登录后用 client_auth_session_dump 的 workspaces 列表选择：
    1. 优先匹配 account_id
    2. 其次选 kind="organization"（Team）
    3. 兜底第一个
    """
    client = {}
    if isinstance(payload, dict):
        client = (
            payload.get("oai-client-auth-session")
            or payload.get("client_auth_session")
            or {}
        )
    workspaces = client.get("workspaces") if isinstance(client, dict) else []
    if not workspaces and isinstance(payload, dict):
        workspaces = payload.get("workspaces") or []
    workspace_id = ""

    if isinstance(workspaces, list):
        # 精确匹配 account_id
        for ws in workspaces:
            if isinstance(ws, dict) and str(ws.get("id") or "").strip() == str(account_id or "").strip():
                workspace_id = str(ws["id"]).strip()
                break
        # 优先选 Team（kind=organization）
        if not workspace_id:
            for ws in workspaces:
                if isinstance(ws, dict) and str(ws.get("kind") or "").lower() == "organization":
                    workspace_id = str(ws["id"]).strip()
                    break
        # 兜底第一个
        if not workspace_id and workspaces and isinstance(workspaces[0], dict):
            workspace_id = str(workspaces[0].get("id") or "").strip()

    # 调用方已知目标 workspace（K12 管理员同意后）时强制选择
    if not workspace_id and str(account_id or "").strip():
        workspace_id = str(account_id).strip()
        refresher._log(f"workspace list empty; using account_id={workspace_id}")

    if not workspace_id:
        save_debug(email, "web_workspace_select_skipped",
                   {"reason": "workspace_id_missing", "dump_keys": list(payload.keys()) if isinstance(payload, dict) else []})
        refresher._log("web workspace_select skipped: no workspace_id in dump")
        return payload

    headers = refresher._json_headers(f"{C.AUTH_BASE}/workspace")
    try:
        apply_sentinel_headers(headers, 
            refresher.session, refresher.device_id, "workspace_select")
    except Exception:
        pass

    resp, error = request_with_retry(
        refresher.session, "post",
        f"{C.AUTH_BASE}/api/accounts/workspace/select",
        json_data={"workspace_id": workspace_id},
        headers=headers, verify=False, timeout=30,
    )
    ws_payload = response_json(resp) if resp is not None else {"error": error}
    save_debug(email, "web_workspace_select", ws_payload,
               status_code=getattr(resp, "status_code", ""),
               extra={"workspace_id": workspace_id})
    refresher._log(f"web workspace_select: workspace_id={workspace_id}")
    return ws_payload if isinstance(ws_payload, dict) and ws_payload else payload


def extract_code_from_payload(payload: Any) -> str | None:
    """递归扫描 payload，提取 OAuth authorization code"""
    from urllib.parse import parse_qs, urlparse

    def _scan(v: Any) -> str | None:
        if isinstance(v, dict):
            for key in ("url", "redirect_url", "redirectUrl", "continue_url",
                         "continueUrl", "location", "href"):
                raw = v.get(key)
                if isinstance(raw, str) and "code=" in raw:
                    params = parse_qs(urlparse(raw).query)
                    c = str((params.get("code") or [""])[0]).strip()
                    if c:
                        return c
            for val in v.values():
                found = _scan(val)
                if found:
                    return found
        elif isinstance(v, list):
            for item in v:
                found = _scan(item)
                if found:
                    return found
        elif isinstance(v, str) and "code=" in v:
            params = parse_qs(urlparse(v).query)
            c = str((params.get("code") or [""])[0]).strip()
            if c:
                return c
        return None

    return _scan(payload)
