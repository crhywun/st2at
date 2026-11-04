"""Full browser automation for ChatGPT passwordless registration (P0+).

Runs the entire signup in Playwright (same sticky proxy/device/UA as account_env),
polls OTP via ``poll_email_direct(mail_url)``, completes about_you, extracts
session accessToken, returns payload for DB write.

Requires: playwright + chromium (and PySocks for SOCKS5 auth bridge).
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable

from .email_ import poll_email_direct
from .names import random_about_you
from .playwright_seed import (
    PlaywrightSeedError,
    _locale_from_env,
    _proxy_for_playwright,
    _timezone_from_env,
    _ua_from_env,
    _viewport_from_env,
    start_local_proxy_bridge,
)


def _log_fn(log_fn: Callable[[str], None] | None):
    return log_fn or (lambda _m: None)


def _env_bool(name: str, default: bool = True) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if raw == "":
        return default
    return raw in ("1", "true", "yes", "on")


def _env_float(name: str, default: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _click_first(page, selectors: list[str], *, timeout: float = 4000) -> bool:
    for sel in selectors:
        try:
            # exact role name (avoids "Continue with Google" matching "Continue")
            if sel.startswith("role="):
                # role=button|Continue or role=button|Continue|exact
                parts = sel.split("|")
                role = parts[0].split("=", 1)[1]
                name = parts[1] if len(parts) > 1 else None
                exact = len(parts) > 2 and parts[2] == "exact"
                loc = page.get_by_role(role, name=name, exact=exact).first
            else:
                loc = page.locator(sel).first
            if hasattr(loc, "count") and loc.count() == 0:
                continue
            loc.click(timeout=timeout)
            return True
        except Exception:
            continue
    return False


def _react_set_value(loc, value: str) -> bool:
    """Set input value in a React-friendly way (native setter + input/change)."""
    try:
        loc.evaluate(
            """(el, v) => {
                const setter =
                  Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value'
                  )?.set;
                if (setter) setter.call(el, v);
                else el.value = v;
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
                el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
            }""",
            value,
        )
        return True
    except Exception:
        return False


def _set_input(loc, page, value: str, *, timeout: float = 4000) -> bool:
    """Fill a single locator robustly (React controlled + sequential type)."""
    try:
        if hasattr(loc, "count") and loc.count() == 0:
            return False
        loc.wait_for(state="visible", timeout=timeout)
        loc.click(timeout=timeout)
        try:
            loc.fill("")
        except Exception:
            pass
        try:
            loc.fill(value, timeout=timeout)
        except Exception:
            pass
        try:
            val = loc.input_value(timeout=1000)
        except Exception:
            val = ""
        if value and value.lower() in (val or "").lower():
            return True
        # clear + type (fires key events)
        try:
            loc.click(timeout=timeout)
            loc.press("Meta+a")
            loc.press("Control+a")
            loc.press("Backspace")
            if hasattr(loc, "press_sequentially"):
                loc.press_sequentially(value, delay=35)
            else:
                loc.type(value, delay=35)
            try:
                val = loc.input_value(timeout=1000)
            except Exception:
                val = ""
            if value and value.lower() in (val or "").lower():
                return True
        except Exception:
            pass
        # last resort: React native setter
        if _react_set_value(loc, value):
            try:
                val = loc.input_value(timeout=1000)
            except Exception:
                val = value
            return bool(val)
        return False
    except Exception:
        return False


def _fill_first(page, selectors: list[str], value: str, *, timeout: float = 4000) -> bool:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if loc.count() == 0:
                continue
            if _set_input(loc, page, value, timeout=timeout):
                return True
        except Exception:
            continue
    return False


def _visible_text(page) -> str:
    try:
        return (page.inner_text("body") or "")[:4000]
    except Exception:
        return ""


def _page_looks_deactivated(text: str) -> bool:
    low = (text or "").lower()
    return (
        "account_deactivated" in low
        or "deleted or deactivated" in low
        or ("deactivated" in low and "account" in low)
    )


def _looks_like_otp_page(url: str, body: str) -> bool:
    u = (url or "").lower()
    b = body or ""
    if (
        "email-verification" in u
        or "email-otp" in u
        or "email/verify" in u
        or "/otp" in u
    ):
        return True
    return bool(
        re.search(
            r"enter.?code|verification code|one[- ]time code|验证码|"
            r"check your email|we (?:just )?sent|code we sent|6[- ]digit",
            b,
            re.I,
        )
    )


def _extract_session_token(page, context, log) -> str:
    """Try multiple ways to get ChatGPT web accessToken."""
    # 1) /api/auth/session via page request (shares cookies)
    for base in ("https://chatgpt.com", "https://chat.openai.com"):
        try:
            resp = page.request.get(f"{base}/api/auth/session", timeout=20000)
            st = getattr(resp, "status", None) or getattr(resp, "status_code", None)
            log(f"[browser-reg] session GET {base} HTTP={st}")
            if resp.ok:
                data = resp.json()
                if isinstance(data, dict):
                    t = str(data.get("accessToken") or data.get("access_token") or "").strip()
                    if t:
                        log(f"[browser-reg] session API token_len={len(t)}")
                        return t
                    keys = list(data.keys())[:12]
                    log(f"[browser-reg] session JSON keys={keys}")
        except Exception as e:
            log(f"[browser-reg] session API warn {base}: {e}")

    # 2) page evaluate fetch (same origin)
    try:
        page.goto("https://chatgpt.com/", wait_until="domcontentloaded", timeout=30000)
        time.sleep(1.0)
        data = page.evaluate(
            """async () => {
                try {
                  const r = await fetch('/api/auth/session', {credentials:'include'});
                  const t = await r.text();
                  return {status: r.status, body: t.slice(0, 500)};
                } catch (e) {
                  return {error: String(e)};
                }
            }"""
        )
        log(f"[browser-reg] page fetch result={str(data)[:200]}")
        if isinstance(data, dict) and data.get("body"):
            try:
                j = json.loads(data["body"])
                t = str(j.get("accessToken") or j.get("access_token") or "").strip()
                if t:
                    log(f"[browser-reg] page fetch token_len={len(t)}")
                    return t
            except Exception:
                pass
    except Exception as e:
        log(f"[browser-reg] page fetch warn: {e}")

    # 3) __NEXT_DATA__ / window vars
    try:
        t = page.evaluate(
            """() => {
              const w = window;
              if (w.__NEXT_DATA__) {
                try {
                  const s = JSON.stringify(w.__NEXT_DATA__);
                  const m = s.match(/"accessToken":"([^"]+)"/);
                  if (m) return m[1];
                } catch (e) {}
              }
              for (const k of Object.keys(localStorage||{})) {
                const v = localStorage.getItem(k) || '';
                if (v.split('.').length===3 && v.length>100 && v.startsWith('eyJ')) return v;
              }
              return '';
            }"""
        )
        if isinstance(t, str) and t.count(".") == 2 and len(t) > 40:
            log(f"[browser-reg] storage token_len={len(t)}")
            return t
    except Exception as e:
        log(f"[browser-reg] storage scan warn: {e}")
    return ""


def register_chatgpt_browser(
    *,
    email: str,
    mail_url: str,
    password: str = "x",
    proxy_url: str = "",
    env: dict[str, Any] | None = None,
    headless: bool | None = None,
    timeout_ms: int | None = None,
    otp_timeout_s: float | None = None,
    pure_ui: bool | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Full browser passwordless registration.

    ``pure_ui=True`` (or ``K12_BROWSER_PURE=1``): never call
    email-otp/validate or create_account via page.request / sentinel API —
    only Playwright typing + clicks. Default is hybrid (UI entry + API
    validate/create for reliability).

    Returns::
      {
        ok, status, error, access_token, at_len, plan, deactivated,
        cookies, device_id, hard, pure_ui
      }
    """
    log = _log_fn(log_fn)
    email = (email or "").strip().lower()
    mail_url = (mail_url or "").strip()
    if pure_ui is None:
        pure_ui = _env_bool("K12_BROWSER_PURE", default=False)
    out: dict[str, Any] = {
        "ok": False,
        "status": "",
        "error": "",
        "access_token": "",
        "at_len": 0,
        "pure_ui": bool(pure_ui),
        "plan": "",
        "deactivated": False,
        "hard": False,
        "cookies": [],
        "device_id": str((env or {}).get("device_id") or "") if env else "",
    }
    if not email or "@" not in email:
        out["status"] = "bad_email"
        out["error"] = "email required"
        return out
    if not mail_url:
        out["status"] = "no_mail_url"
        out["error"] = "mail_url required"
        return out

    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        out["status"] = "no_playwright"
        out["error"] = f"playwright not installed: {e}"
        out["hard"] = True
        return out

    if headless is None:
        headless = _env_bool("K12_BROWSER_HEADLESS", default=True)
    if timeout_ms is None:
        timeout_ms = int(_env_float("K12_BROWSER_TIMEOUT_MS", 60000))
    if otp_timeout_s is None:
        otp_timeout_s = _env_float("TOKENREFRESH_EMAIL_POLL_SECONDS", 90.0)

    device_id = str((env or {}).get("device_id") or "").strip() if env else ""
    use_proxy = (proxy_url or (env or {}).get("proxy_url") or "").strip() if env else (proxy_url or "")
    ua = _ua_from_env(env)
    locale = _locale_from_env(env)
    timezone_id = _timezone_from_env(env)
    viewport = _viewport_from_env(env)

    bridge = None
    play_proxy_url = use_proxy
    try:
        if use_proxy:
            try:
                bridge = start_local_proxy_bridge(use_proxy, log_fn=log)
                if bridge:
                    play_proxy_url = bridge.local_url
            except PlaywrightSeedError as e:
                # if not socks-auth, bridge returns None; other errors surface
                if "auth" in str(e).lower() or "pysocks" in str(e).lower() or "bridge" in str(e).lower():
                    log(f"[browser-reg] proxy bridge: {e}")
                    # try direct socks without auth conversion
                    play_proxy_url = use_proxy
    except Exception as e:
        log(f"[browser-reg] bridge warn: {e}")

    proxy = _proxy_for_playwright(play_proxy_url)
    log(
        f"[browser-reg] start email={email} headless={headless} pure_ui={pure_ui} "
        f"proxy={'yes' if proxy else 'no'} bridged={bool(bridge)} "
        f"lang={locale} tz={timezone_id}"
    )

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=headless,
                args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
            )
            try:
                ctx_kwargs: dict[str, Any] = {
                    "ignore_https_errors": True,
                    "locale": locale,
                    "timezone_id": timezone_id,
                    "viewport": viewport,
                    "user_agent": ua,
                    "extra_http_headers": {
                        "Accept-Language": f"{locale},{locale.split('-')[0]};q=0.9,en;q=0.8",
                    },
                }
                if proxy:
                    ctx_kwargs["proxy"] = proxy
                context = browser.new_context(**ctx_kwargs)
                try:
                    context.add_init_script(
                        "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                    )
                except Exception:
                    pass
                if device_id:
                    for domain in (".chatgpt.com", ".auth.openai.com", ".openai.com"):
                        try:
                            context.add_cookies(
                                [
                                    {
                                        "name": "oai-did",
                                        "value": device_id,
                                        "domain": domain,
                                        "path": "/",
                                    }
                                ]
                            )
                        except Exception:
                            pass

                page = context.new_page()
                page.set_default_timeout(timeout_ms)

                def _fill_email_field(p) -> bool:
                    # Never target ChatGPT chat composer (#prompt-textarea / contenteditable)
                    candidates = []
                    try:
                        candidates.append(p.get_by_label(re.compile(r"^email$", re.I)))
                    except Exception:
                        pass
                    try:
                        candidates.append(p.get_by_placeholder(re.compile(r"email address|email", re.I)))
                    except Exception:
                        pass
                    for sel in (
                        "input[name='email']",
                        "input[type='email']",
                        "input[id='email']",
                        "input[id='username']",
                        "input[name='username']",
                        "input[autocomplete='email']",
                        "input[autocomplete='username']",
                        "input[placeholder*='Email' i]",
                        "input[placeholder*='email' i]",
                        "form input[type='text']",
                        "form input:not([type='hidden']):not([type='password']):not([type='search'])",
                    ):
                        candidates.append(p.locator(sel).first)
                    for loc in candidates:
                        try:
                            if hasattr(loc, "count") and loc.count() == 0:
                                continue
                            # skip chat composer / prompt boxes
                            try:
                                tag = (loc.evaluate("el => (el.tagName||'').toLowerCase()") or "")
                                eid = (loc.get_attribute("id") or "").lower()
                                role = (loc.get_attribute("role") or "").lower()
                                ph = (loc.get_attribute("placeholder") or "").lower()
                                if tag == "textarea" or "prompt" in eid or role == "textbox" and "message" in ph:
                                    continue
                                if "message" in ph or "ask" in ph or "chat" in ph:
                                    continue
                            except Exception:
                                pass
                            if not _set_input(loc, p, email, timeout=3000):
                                continue
                            try:
                                val = loc.input_value(timeout=1000)
                            except Exception:
                                val = ""
                            log(f"[browser-reg] email filled val={val[:48]!r} url={p.url[:80]}")
                            if email.lower() in (val or "").lower():
                                return True
                        except Exception:
                            continue
                    return False

                def _dismiss_banners(p) -> None:
                    _click_first(
                        p,
                        [
                            "button:has-text('Accept all')",
                            "button:has-text('Accept')",
                            "button:has-text('Agree')",
                            "button:has-text('同意')",
                        ],
                        timeout=1500,
                    )

                def _click_continue(p) -> bool:
                    # Prefer exact "Continue" — has-text('Continue') matches
                    # "Continue with Google/Apple/phone" and never advances.
                    return _click_first(
                        p,
                        [
                            "role=button|Continue|exact",
                            "button[type='submit']",
                            "button >> text=/^Continue$/",
                            "form button[type='submit']",
                            "role=button|Next|exact",
                            "button:has-text('继续')",
                            "role=button|Sign up|exact",
                            "role=button|Create account|exact",
                        ],
                        timeout=4000,
                    )

                def _handle_session_ended(p) -> bool:
                    """Recover from auth.openai.com 'Your session has ended'."""
                    body = _visible_text(p)
                    if "session has ended" not in body.lower() and "session ended" not in body.lower():
                        return False
                    log("[browser-reg] session ended — re-enter via Log in")
                    _click_first(
                        p,
                        [
                            "button:has-text('Log in')",
                            "a:has-text('Log in')",
                            "button:has-text('Continue')",
                            "a:has-text('Continue')",
                            "button:has-text('logging in')",
                        ],
                        timeout=4000,
                    )
                    time.sleep(1.0)
                    return True

                def _open_email_surface(p) -> bool:
                    _dismiss_banners(p)
                    _handle_session_ended(p)
                    _click_first(
                        p,
                        [
                            "button:has-text('Sign up')",
                            "a:has-text('Sign up')",
                            "button:has-text('Create account')",
                            "a:has-text('Create account')",
                            "button:has-text('Continue with email')",
                            "button:has-text('Log in')",
                            "a:has-text('Log in')",
                            "[data-testid='signup-button']",
                        ],
                        timeout=2500,
                    )
                    time.sleep(0.5)
                    return _fill_email_field(p)

                # Warm CF on chatgpt.com, then go to auth/login (NOT chat home — avoids
                # filling the guest chat composer with the email).
                try:
                    log("[browser-reg] warm https://chatgpt.com/")
                    page.goto("https://chatgpt.com/", wait_until="domcontentloaded", timeout=timeout_ms)
                    time.sleep(1.5)
                    _dismiss_banners(page)
                except Exception as e:
                    log(f"[browser-reg] warm warn: {e}")
                # pure UI needs cf_clearance on auth.openai.com too (OTP validate XHR)
                if pure_ui:
                    try:
                        log("[browser-reg] warm https://auth.openai.com/")
                        page.goto(
                            "https://auth.openai.com/",
                            wait_until="domcontentloaded",
                            timeout=timeout_ms,
                        )
                        time.sleep(2.0)
                        for _cf_i in range(12):
                            bcf = _visible_text(page)
                            if not re.search(
                                r"just a moment|performing security verification|checking your browser",
                                bcf,
                                re.I,
                            ):
                                break
                            time.sleep(1.5)
                    except Exception as e:
                        log(f"[browser-reg] auth warm warn: {e}")

                start_urls = [
                    "https://chatgpt.com/auth/login",
                    "https://chatgpt.com/api/auth/signin/openai?prompt=login&screen_hint=signup",
                    "https://auth.openai.com/create-account",
                    "https://auth.openai.com/log-in",
                ]
                email_filled = False
                for url in start_urls:
                    try:
                        log(f"[browser-reg] goto {url}")
                        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                        time.sleep(1.5)
                    except Exception as e:
                        log(f"[browser-reg] goto warn {url}: {e}")
                        continue
                    if _open_email_surface(page):
                        email_filled = True
                        break
                    # session-ended recovery + refill
                    if _handle_session_ended(page) and _fill_email_field(page):
                        email_filled = True
                        break
                    # homepage-style CTA only if still on chatgpt without email field
                    _click_first(
                        page,
                        [
                            "button:has-text('Log in')",
                            "a:has-text('Log in')",
                            "button:has-text('Sign up')",
                            "a:has-text('Sign up for free')",
                            "a:has-text('Sign up')",
                        ],
                        timeout=3000,
                    )
                    time.sleep(1.0)
                    if _fill_email_field(page):
                        email_filled = True
                        break

                if not email_filled:
                    body = _visible_text(page)
                    if _page_looks_deactivated(body):
                        out["status"] = "deactivated"
                        out["deactivated"] = True
                        out["hard"] = True
                        out["error"] = "deactivated before email"
                        return out
                    out["status"] = "no_email_input"
                    out["error"] = f"cannot find email input url={page.url} body={body[:120]}"
                    return out

                # continue until OTP / password / about-you surfaces
                for cont_i in range(1, 8):
                    before_url = page.url or ""
                    # only submit if an email-like input is focused / present
                    has_email_input = False
                    try:
                        has_email_input = page.locator(
                            "input[type='email'], input[name='email'], input[autocomplete='email'], "
                            "input[id='email'], input[name='username']"
                        ).count() > 0
                    except Exception:
                        pass
                    if has_email_input:
                        if not _click_continue(page):
                            try:
                                page.keyboard.press("Enter")
                            except Exception:
                                pass
                    else:
                        # lost the form — go back to login
                        log("[browser-reg] no email input before continue — re-open login")
                        try:
                            page.goto(
                                "https://chatgpt.com/auth/login",
                                wait_until="domcontentloaded",
                                timeout=timeout_ms,
                            )
                            time.sleep(1.0)
                            _open_email_surface(page)
                        except Exception as e:
                            log(f"[browser-reg] re-open login warn: {e}")
                        continue
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=10000)
                    except Exception:
                        pass
                    # SPA navigation can be slow
                    time.sleep(1.5)
                    body = _visible_text(page)
                    url_now = page.url or ""
                    log(
                        f"[browser-reg] after continue#{cont_i} "
                        f"url={url_now[:120]} body={body[:80]!r}"
                    )
                    if _page_looks_deactivated(body):
                        out["status"] = "deactivated"
                        out["deactivated"] = True
                        out["hard"] = True
                        out["error"] = "deactivated after email continue"
                        return out
                    # accidentally submitted into guest chat
                    if re.search(r"/c/[0-9a-f-]{8,}", url_now) or (
                        "you said:" in body.lower() and "log in" in body.lower()
                    ):
                        log("[browser-reg] landed in guest chat — force auth/login")
                        try:
                            page.goto(
                                "https://chatgpt.com/auth/login",
                                wait_until="domcontentloaded",
                                timeout=timeout_ms,
                            )
                            time.sleep(1.0)
                            _open_email_surface(page)
                        except Exception:
                            pass
                        continue
                    if "session has ended" in body.lower() or "session ended" in body.lower():
                        log("[browser-reg] session ended mid-flow — recover + refill")
                        _handle_session_ended(page)
                        if not _fill_email_field(page):
                            try:
                                page.goto(
                                    "https://chatgpt.com/auth/login",
                                    wait_until="domcontentloaded",
                                    timeout=timeout_ms,
                                )
                                time.sleep(1.0)
                                _open_email_surface(page)
                            except Exception:
                                pass
                        continue
                    if "email is required" in body.lower() or "enter an email" in body.lower():
                        log("[browser-reg] email still required — refill")
                        _fill_email_field(page)
                        continue
                    if _looks_like_otp_page(url_now, body):
                        break
                    if re.search(r"enter (your )?password|create.?password|about you|your name|birth", body, re.I):
                        break
                    # chatgpt login?email=... still needs another continue
                    if url_now != before_url and "email=" in url_now:
                        _fill_email_field(page)
                        continue
                    if "auth.openai.com" in url_now and cont_i >= 3:
                        if not _looks_like_otp_page(url_now, body):
                            _fill_email_field(page)
                        continue

                # password page? switch to email code if offered (don't touch OTP page)
                body = _visible_text(page)
                url_chk = page.url or ""
                if (
                    not _looks_like_otp_page(url_chk, body)
                    and re.search(r"enter (your )?password|create.?password|your password", body, re.I)
                ):
                    log("[browser-reg] password surface — try email code path")
                    _click_first(
                        page,
                        [
                            "button:has-text('Email me a code')",
                            "button:has-text('Email')",
                            "button:has-text('email code')",
                            "a:has-text('email')",
                            "button:has-text('Continue with email')",
                            "button:has-text('验证码')",
                            "a:has-text('code')",
                            "button:has-text('Use a one-time code')",
                            "button:has-text('one-time')",
                        ],
                        timeout=3000,
                    )
                    time.sleep(1.0)

                # wait for OTP page
                otp_ready = False
                body = _visible_text(page)
                for wait_i in range(25):
                    body = _visible_text(page)
                    url = page.url or ""
                    if _page_looks_deactivated(body):
                        out["status"] = "deactivated"
                        out["deactivated"] = True
                        out["hard"] = True
                        out["error"] = "account_deactivated on auth page"
                        return out
                    if _looks_like_otp_page(url, body):
                        otp_ready = True
                        log(f"[browser-reg] OTP page ready url={url[:120]}")
                        break
                    # sometimes still need continue / email-code switch
                    _click_first(
                        page,
                        [
                            "button[type='submit']",
                            "button:has-text('Continue')",
                            "button:has-text('Email me a code')",
                            "button:has-text('Use a one-time code')",
                        ],
                        timeout=1500,
                    )
                    time.sleep(0.7)
                    if wait_i and wait_i % 5 == 0:
                        log(f"[browser-reg] waiting OTP page #{wait_i} url={url[:100]} body={body[:60]!r}")
                if not otp_ready:
                    out["status"] = "no_otp_page"
                    out["error"] = f"not on otp page url={page.url} body={body[:160]}"
                    return out

                # poll OTP (start slightly before continue to avoid missing early mail)
                not_before = time.time() - 15.0
                log(f"[browser-reg] waiting OTP up to {otp_timeout_s}s ...")
                code = None
                deadline = time.time() + max(30.0, float(otp_timeout_s))
                while time.time() < deadline:
                    code = poll_email_direct(mail_url, email, not_before=not_before)
                    if code:
                        break
                    time.sleep(2.0)
                if not code:
                    out["status"] = "otp_timeout"
                    out["error"] = "Could not get web email OTP"
                    return out
                log(f"[browser-reg] OTP code={code}")

                # fill OTP — prefer real key events so SPA auto-submits JSON validate
                # pure_ui: delay fill until expect_response is armed (see _pure_ui_submit_otp)
                code_s = str(code).strip()
                filled_otp = False
                otp_selectors = [
                    "input[name='code']",
                    "input[autocomplete='one-time-code']",
                    "input[inputmode='numeric']",
                    "input[type='tel']",
                    "input[placeholder*='code' i]",
                    "input[name='otp']",
                    "input[id*='code' i]",
                    "input[aria-label*='code' i]",
                    "input[data-testid*='code' i]",
                    "input[type='text']",
                    "input[type='number']",
                ]

                def _dump_inputs(p, tag: str) -> None:
                    try:
                        info = p.evaluate(
                            """() => Array.from(document.querySelectorAll('input,textarea,[contenteditable="true"]'))
                              .slice(0, 20)
                              .map(el => ({
                                tag: el.tagName,
                                type: el.getAttribute('type'),
                                name: el.getAttribute('name'),
                                id: el.id,
                                ac: el.getAttribute('autocomplete'),
                                mode: el.getAttribute('inputmode'),
                                max: el.getAttribute('maxlength'),
                                ph: el.getAttribute('placeholder'),
                                aria: el.getAttribute('aria-label'),
                                vis: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length),
                              }))"""
                        )
                        log(f"[browser-reg] {tag} inputs={info}")
                    except Exception as e:
                        log(f"[browser-reg] {tag} dump warn: {e}")

                def _type_otp_keys(loc) -> bool:
                    """Clear + digit-by-digit key events (triggers React onChange/auto-submit)."""
                    try:
                        loc.wait_for(state="visible", timeout=5000)
                        # label overlay often intercepts normal click
                        try:
                            loc.click(timeout=2000, force=True)
                        except Exception:
                            try:
                                loc.focus(timeout=2000)
                            except Exception:
                                pass
                        # clear
                        try:
                            loc.fill("")
                        except Exception:
                            pass
                        try:
                            loc.press("Meta+a")
                            loc.press("Control+a")
                            loc.press("Backspace")
                        except Exception:
                            pass
                        if hasattr(loc, "press_sequentially"):
                            loc.press_sequentially(code_s, delay=90)
                        else:
                            loc.type(code_s, delay=90)
                        try:
                            val = loc.input_value(timeout=1000)
                        except Exception:
                            val = ""
                        if code_s in (val or "") or len(val or "") >= min(4, len(code_s)):
                            return True
                        # React setter + synthetic input events as last resort
                        # (pure UI prefers key events; setter only if keys failed)
                        _react_set_value(loc, code_s)
                        return True
                    except Exception as e:
                        log(f"[browser-reg] type_otp warn: {e}")
                        return False

                def _try_fill_on(target) -> bool:
                    for _wait in range(10):
                        try:
                            n = target.locator("input").count()
                        except Exception:
                            n = 0
                        if n > 0:
                            break
                        time.sleep(0.4)
                    for sel in otp_selectors:
                        try:
                            loc = target.locator(sel).first
                            if loc.count() == 0:
                                continue
                            if _type_otp_keys(loc):
                                log(f"[browser-reg] OTP typed via {sel}")
                                return True
                        except Exception:
                            continue
                    # multi-box maxlength=1
                    try:
                        boxes = target.locator("input").all()
                        digit_boxes = []
                        for b in boxes:
                            try:
                                if b.get_attribute("maxlength") == "1":
                                    digit_boxes.append(b)
                            except Exception:
                                continue
                        if len(digit_boxes) >= len(code_s):
                            for i, d in enumerate(code_s):
                                digit_boxes[i].click(timeout=1000)
                                if hasattr(digit_boxes[i], "press_sequentially"):
                                    digit_boxes[i].press_sequentially(d, delay=40)
                                else:
                                    digit_boxes[i].type(d, delay=40)
                            log("[browser-reg] OTP typed via multi-box")
                            return True
                    except Exception as e:
                        log(f"[browser-reg] multi-box warn: {e}")
                    return False

                if not pure_ui:
                    filled_otp = _try_fill_on(page)
                    if not filled_otp:
                        try:
                            for fr in page.frames:
                                if fr == page.main_frame:
                                    continue
                                try:
                                    if _try_fill_on(fr):
                                        filled_otp = True
                                        log(f"[browser-reg] OTP filled in frame url={fr.url[:80]}")
                                        break
                                except Exception:
                                    continue
                        except Exception as e:
                            log(f"[browser-reg] frames warn: {e}")
                    if not filled_otp:
                        _dump_inputs(page, "otp_fill_fail")
                        out["status"] = "otp_fill_fail"
                        out["error"] = f"cannot fill otp input url={page.url}"
                        return out
                else:
                    # ensure input exists before pure path
                    try:
                        page.locator("input[name='code'], input[autocomplete='one-time-code']").first.wait_for(
                            state="visible", timeout=8000
                        )
                        filled_otp = True
                    except Exception:
                        filled_otp = page.locator("input").count() > 0
                    if not filled_otp:
                        _dump_inputs(page, "otp_fill_fail")
                        out["status"] = "otp_fill_fail"
                        out["error"] = f"cannot find otp input url={page.url}"
                        return out

                def _wait_cf_if_any(p, tag: str = "cf") -> None:
                    for i in range(20):
                        body_cf = _visible_text(p)
                        url_cf = p.url or ""
                        if not re.search(
                            r"performing security verification|just a moment|cf-browser-verification|"
                            r"checking your browser|security service to protect",
                            body_cf,
                            re.I,
                        ) and "__cf_chl" not in url_cf:
                            return
                        if i % 4 == 0:
                            log(f"[browser-reg] {tag} waiting CF challenge… url={url_cf[:100]}")
                        time.sleep(1.5)

                def _ui_click_continue(p) -> bool:
                    """Click SPA Continue without matching OAuth provider buttons."""
                    candidates = []
                    try:
                        candidates.append(p.get_by_role("button", name="Continue", exact=True))
                    except Exception:
                        pass
                    try:
                        candidates.append(p.get_by_role("button", name="Verify", exact=True))
                    except Exception:
                        pass
                    try:
                        candidates.append(p.get_by_role("button", name="Next", exact=True))
                    except Exception:
                        pass
                    for sel in (
                        "button >> text=/^Continue$/",
                        "button >> text=/^Verify$/",
                        "button >> text=/^Next$/",
                        "button:has-text('确认')",
                        "form button[type='submit']",
                        "button[type='submit']",
                    ):
                        candidates.append(p.locator(sel).first)
                    for loc in candidates:
                        try:
                            if hasattr(loc, "count") and loc.count() == 0:
                                continue
                            loc.click(timeout=3000, force=True, no_wait_after=True)
                            return True
                        except Exception:
                            continue
                    return False

                def _pure_ui_submit_otp() -> bool:
                    """Type OTP + wait for SPA validate XHR / navigation (no API, no reload)."""
                    log("[browser-reg] pure_ui OTP submit (no API)")
                    left_otp = False

                    def _is_validate(r) -> bool:
                        u = (r.url or "").lower()
                        return "email-otp/validate" in u or "email_otp/validate" in u

                    def _handle_validate_resp(resp) -> str:
                        """Return ok|deact|wrong|cf|fail."""
                        try:
                            st = int(getattr(resp, "status", None) or 0)
                        except Exception:
                            st = 0
                        try:
                            txt = resp.text()
                        except Exception:
                            txt = ""
                        log(
                            f"[browser-reg] pure_ui validate XHR HTTP={st} "
                            f"body={ (txt or '')[:180]!r}"
                        )
                        low = (txt or "").lower()
                        ctype = ""
                        try:
                            ctype = (resp.headers.get("content-type") or "").lower()
                        except Exception:
                            pass
                        if st == 200 and (
                            low.strip().startswith("{") or "application/json" in ctype
                        ):
                            return "ok"
                        if "deactivat" in low or "account_deactivated" in low:
                            return "deact"
                        if "just a moment" in low or "cf-browser" in low or (
                            st in (403, 503) and "<html" in low
                        ):
                            return "cf"
                        if "wrong" in low or ("invalid" in low and "code" in low):
                            return "wrong"
                        return "fail"

                    # Pass 1: type only — SPA often auto-submits at 6 digits (no button)
                    for pass1 in range(1, 4):
                        try:
                            with page.expect_response(_is_validate, timeout=15000) as resp_info:
                                _try_fill_on(page)
                            kind = _handle_validate_resp(resp_info.value)
                            if kind == "ok":
                                left_otp = True
                                break
                            if kind == "deact":
                                out["status"] = "deactivated"
                                out["deactivated"] = True
                                out["hard"] = True
                                out["error"] = "account_deactivated after otp (xhr)"
                                return False
                            if kind == "wrong":
                                out["status"] = "wrong_otp"
                                out["error"] = "wrong_email_otp_code"
                                return False
                            if kind == "cf":
                                log(f"[browser-reg] pure_ui validate CF block pass={pass1} — wait")
                                _wait_cf_if_any(page, f"validate-cf-{pass1}")
                                time.sleep(1.5)
                                continue
                            break
                        except Exception as e:
                            log(f"[browser-reg] pure_ui auto-submit wait: {e}")
                            break

                    # Pass 2: exact Continue click once (not provider buttons)
                    if not left_otp and _looks_like_otp_page(page.url or "", _visible_text(page)):
                        try:
                            with page.expect_response(_is_validate, timeout=12000) as resp_info:
                                if not _ui_click_continue(page):
                                    # keyboard Enter as last soft trigger
                                    try:
                                        page.keyboard.press("Enter")
                                    except Exception:
                                        pass
                            kind = _handle_validate_resp(resp_info.value)
                            if kind == "ok":
                                left_otp = True
                            elif kind == "deact":
                                out["status"] = "deactivated"
                                out["deactivated"] = True
                                out["hard"] = True
                                out["error"] = "account_deactivated after otp (xhr)"
                                return False
                            elif kind == "wrong":
                                out["status"] = "wrong_otp"
                                out["error"] = "wrong_email_otp_code"
                                return False
                        except Exception as e:
                            log(f"[browser-reg] pure_ui continue-submit wait: {e}")

                    # Poll leave email-verification (NO page.reload — triggers CF)
                    for sub_i in range(1, 14):
                        url_now = page.url or ""
                        body_now = _visible_text(page)
                        log(
                            f"[browser-reg] pure_ui OTP wait#{sub_i} "
                            f"url={url_now[:130]} body={body_now[:70]!r}"
                        )
                        if _page_looks_deactivated(body_now):
                            out["status"] = "deactivated"
                            out["deactivated"] = True
                            out["hard"] = True
                            out["error"] = "account_deactivated after otp"
                            return False
                        if re.search(
                            r"wrong.?code|invalid.?code|incorrect code|code is incorrect|"
                            r"didn't match|does not match",
                            body_now,
                            re.I,
                        ):
                            out["status"] = "wrong_otp"
                            out["error"] = "wrong_email_otp_code"
                            return False
                        if re.search(r"route error|invalid content type|oops, an error occurred", body_now, re.I):
                            # 用户确认：Route Error 刷新页面即可恢复 OTP 输入
                            log("[browser-reg] pure_ui route error — refresh page + retype")
                            try:
                                page.reload(wait_until="domcontentloaded", timeout=timeout_ms)
                            except Exception:
                                try:
                                    page.goto(
                                        "https://auth.openai.com/email-verification",
                                        wait_until="domcontentloaded",
                                        timeout=timeout_ms,
                                    )
                                except Exception as e:
                                    log(f"[browser-reg] pure_ui refresh warn: {e}")
                            time.sleep(2.0)
                            _wait_cf_if_any(page, "after-route-refresh")
                            _click_first(
                                page,
                                [
                                    "role=button|Try again|exact",
                                    "button:has-text('Try again')",
                                    "a:has-text('Try again')",
                                ],
                                timeout=2000,
                            )
                            time.sleep(1.0)
                            if _looks_like_otp_page(page.url or "", _visible_text(page)):
                                try:
                                    with page.expect_response(_is_validate, timeout=15000) as ri:
                                        _try_fill_on(page)
                                    kind2 = _handle_validate_resp(ri.value)
                                    if kind2 == "ok":
                                        left_otp = True
                                        continue
                                    if kind2 == "deact":
                                        out["status"] = "deactivated"
                                        out["deactivated"] = True
                                        out["hard"] = True
                                        out["error"] = "account_deactivated after otp (xhr)"
                                        return False
                                except Exception as e:
                                    log(f"[browser-reg] pure_ui retry type: {e}")
                            time.sleep(1.0)
                            continue
                        if re.search(
                            r"just a moment|performing security verification|checking your browser",
                            body_now,
                            re.I,
                        ):
                            log("[browser-reg] pure_ui CF interstitial — wait")
                            _wait_cf_if_any(page, "otp-cf")
                            continue
                        if "about-you" in url_now or re.search(
                            r"about you|your name|birth|tell us about", body_now, re.I
                        ):
                            left_otp = True
                            break
                        if not _looks_like_otp_page(url_now, body_now):
                            left_otp = True
                            break
                        if "chatgpt.com" in url_now and "auth" not in url_now:
                            left_otp = True
                            break
                        # wait for SPA navigation after successful XHR
                        if left_otp:
                            try:
                                page.wait_for_load_state("domcontentloaded", timeout=5000)
                            except Exception:
                                pass
                            break
                        if sub_i in (3, 6, 9):
                            _try_fill_on(page)
                            time.sleep(0.5)
                            _ui_click_continue(page)
                        time.sleep(1.2)
                    return left_otp

                def _api_validate_otp(code_val: str) -> dict[str, Any]:
                    """JSON validate via browser cookies (+ sentinel). Hybrid path only."""
                    did = device_id or ""
                    try:
                        if not did:
                            did = page.evaluate(
                                """() => {
                                  const m = document.cookie.match(/(?:^|;\\s*)oai-did=([^;]+)/);
                                  return m ? decodeURIComponent(m[1]) : '';
                                }"""
                            ) or ""
                    except Exception:
                        pass
                    headers: dict[str, str] = {
                        "content-type": "application/json",
                        "accept": "application/json",
                        "origin": "https://auth.openai.com",
                        "referer": "https://auth.openai.com/email-verification",
                    }
                    if did:
                        headers["oai-device-id"] = str(did)
                    try:
                        from .session import create_session_with_proxy
                        from .utils import apply_sentinel_headers

                        sess = create_session_with_proxy(use_proxy or "")
                        try:
                            for c in context.cookies():
                                try:
                                    name = str(c.get("name") or "")
                                    val = str(c.get("value") or "")
                                    dom = str(c.get("domain") or "")
                                    if name and val:
                                        sess.cookies.set(name, val, domain=dom.lstrip(".") or None)
                                except Exception:
                                    continue
                            apply_sentinel_headers(
                                headers, sess, str(did or "browser"), "email_otp_validate"
                            )
                            log("[browser-reg] sentinel headers attached for OTP validate")
                        finally:
                            try:
                                sess.close()
                            except Exception:
                                pass
                    except Exception as e:
                        log(f"[browser-reg] sentinel build warn: {e}")

                    try:
                        resp = page.request.post(
                            "https://auth.openai.com/api/accounts/email-otp/validate",
                            headers=headers,
                            data=json.dumps({"code": code_val}),
                            timeout=25000,
                        )
                        st = getattr(resp, "status", None) or 0
                        try:
                            body_txt = resp.text()
                        except Exception:
                            body_txt = ""
                        log(f"[browser-reg] OTP API validate HTTP={st} body={body_txt[:180]!r}")
                        data: dict[str, Any] = {}
                        try:
                            data = resp.json() if resp.ok else json.loads(body_txt or "{}")
                        except Exception:
                            data = {}
                        return {"status": int(st), "data": data, "body": body_txt[:500]}
                    except Exception as e:
                        log(f"[browser-reg] page.request validate warn: {e}")
                    return {"status": 0, "data": {}, "body": ""}

                def _api_create_account() -> dict[str, Any]:
                    """POST create_account (about_you) via browser cookies + sentinel. Hybrid only."""
                    name, birth = random_about_you(None)
                    log(f"[browser-reg] create_account API name={name!r} birth={birth}")
                    did = device_id or ""
                    headers: dict[str, str] = {
                        "content-type": "application/json",
                        "accept": "application/json",
                        "origin": "https://auth.openai.com",
                        "referer": "https://auth.openai.com/about-you",
                    }
                    if did:
                        headers["oai-device-id"] = str(did)
                    try:
                        from .session import create_session_with_proxy
                        from .utils import apply_sentinel_headers

                        sess = create_session_with_proxy(use_proxy or "")
                        try:
                            for c in context.cookies():
                                try:
                                    n = str(c.get("name") or "")
                                    v = str(c.get("value") or "")
                                    dom = str(c.get("domain") or "")
                                    if n and v:
                                        sess.cookies.set(n, v, domain=dom.lstrip(".") or None)
                                except Exception:
                                    continue
                            apply_sentinel_headers(
                                headers, sess, str(did or "browser"), "oauth_create_account"
                            )
                            log("[browser-reg] sentinel attached for create_account")
                        finally:
                            try:
                                sess.close()
                            except Exception:
                                pass
                    except Exception as e:
                        log(f"[browser-reg] create_account sentinel warn: {e}")
                    try:
                        resp = page.request.post(
                            "https://auth.openai.com/api/accounts/create_account",
                            headers=headers,
                            data=json.dumps({"name": name, "birthdate": birth}),
                            timeout=25000,
                        )
                        st = getattr(resp, "status", None) or 0
                        try:
                            body_txt = resp.text()
                        except Exception:
                            body_txt = ""
                        log(f"[browser-reg] create_account HTTP={st} body={body_txt[:200]!r}")
                        data: dict[str, Any] = {}
                        try:
                            data = resp.json() if st in (200, 201, 302, 303) else json.loads(body_txt or "{}")
                        except Exception:
                            data = {}
                        if st in (302, 303) and not data.get("continue_url"):
                            try:
                                loc = resp.headers.get("location") or resp.headers.get("Location") or ""
                                if loc:
                                    data = {"continue_url": loc, "page": {"type": "external_url"}}
                            except Exception:
                                pass
                        return {"status": int(st), "data": data, "body": body_txt[:500]}
                    except Exception as e:
                        log(f"[browser-reg] create_account request warn: {e}")
                        return {"status": 0, "data": {}, "body": str(e)}

                if pure_ui:
                    # ---- pure browser clicks only ----
                    ok_leave = _pure_ui_submit_otp()
                    if out.get("deactivated") or out.get("status") in ("wrong_otp", "deactivated"):
                        return out
                    if not ok_leave and _looks_like_otp_page(page.url or "", _visible_text(page)):
                        out["status"] = "otp_stuck"
                        out["error"] = (
                            f"pure_ui stuck on otp url={page.url} "
                            f"body={_visible_text(page)[:160]}"
                        )
                        return out
                    _wait_cf_if_any(page, "after-otp")
                else:
                    # ---- hybrid: API validate + create_account ----
                    api_res = _api_validate_otp(code_s)
                    api_ok = int(api_res.get("status") or 0) == 200
                    api_data = api_res.get("data") if isinstance(api_res.get("data"), dict) else {}
                    if api_ok:
                        page_type = str(((api_data.get("page") or {}).get("type")) or "")
                        cont = str(api_data.get("continue_url") or "")
                        log(f"[browser-reg] OTP API ok page_type={page_type!r} cont={cont[:80]!r}")
                        if page_type in ("about_you", "create_account") or "about-you" in cont:
                            ca = _api_create_account()
                            if int(ca.get("status") or 0) in (200, 201, 302, 303):
                                ca_data = ca.get("data") if isinstance(ca.get("data"), dict) else {}
                                cont2 = str(ca_data.get("continue_url") or "")
                                pt2 = str(((ca_data.get("page") or {}).get("type")) or "")
                                log(
                                    f"[browser-reg] create_account ok page_type={pt2!r} "
                                    f"cont={cont2[:100]!r}"
                                )
                                if cont2:
                                    cont = cont2
                            else:
                                log(
                                    f"[browser-reg] create_account fail HTTP={ca.get('status')} "
                                    f"body={str(ca.get('body') or '')[:160]}"
                                )
                        if cont:
                            try:
                                page.goto(cont, wait_until="domcontentloaded", timeout=timeout_ms)
                                time.sleep(1.5)
                                for _ in range(5):
                                    u = page.url or ""
                                    if "chatgpt.com" in u and "auth.openai.com" not in u:
                                        break
                                    if "callback" in u or "about-you" in u or "auth.openai.com" in u:
                                        try:
                                            page.wait_for_load_state("networkidle", timeout=8000)
                                        except Exception:
                                            pass
                                        time.sleep(1.0)
                                    else:
                                        break
                            except Exception as e:
                                log(f"[browser-reg] continue_url warn: {e}")
                    else:
                        for sub_i in range(1, 5):
                            url_now = page.url or ""
                            body_now = _visible_text(page)
                            log(
                                f"[browser-reg] OTP wait#{sub_i} "
                                f"url={url_now[:120]} body={body_now[:70]!r}"
                            )
                            if _page_looks_deactivated(body_now):
                                out["status"] = "deactivated"
                                out["deactivated"] = True
                                out["hard"] = True
                                out["error"] = "account_deactivated after otp"
                                return out
                            err_body = str(api_res.get("body") or "")
                            if re.search(
                                r"wrong.?code|invalid.?code|incorrect code|code is incorrect",
                                err_body + " " + body_now,
                                re.I,
                            ):
                                out["status"] = "wrong_otp"
                                out["error"] = "wrong_email_otp_code"
                                return out
                            if not _looks_like_otp_page(url_now, body_now):
                                break
                            if sub_i == 2:
                                _ui_click_continue(page)
                            time.sleep(1.2)
                        if not api_ok and _looks_like_otp_page(page.url or "", _visible_text(page)):
                            out["status"] = "otp_validate_fail"
                            out["error"] = (
                                f"OTP API HTTP={api_res.get('status')} "
                                f"body={str(api_res.get('body') or '')[:200]}"
                            )
                            return out
                log(f"[browser-reg] after OTP url={page.url}")

                body = _visible_text(page)
                if _page_looks_deactivated(body):
                    out["status"] = "deactivated"
                    out["deactivated"] = True
                    out["hard"] = True
                    out["error"] = "account_deactivated after otp"
                    return out

                def _do_about_you() -> None:
                    _wait_cf_if_any(page, "about-you")
                    name, birth = random_about_you(None)
                    log(f"[browser-reg] about_you name={name!r} birth={birth} pure_ui={pure_ui}")
                    if not _fill_first(
                        page,
                        [
                            "input[name='name']",
                            "input[name='fullName']",
                            "input[id='name']",
                            "input[autocomplete='name']",
                            "input[placeholder*='Name' i]",
                            "input[placeholder*='Full name' i]",
                        ],
                        name,
                    ):
                        parts = name.split(None, 1)
                        first = parts[0]
                        last = parts[1] if len(parts) > 1 else "Smith"
                        _fill_first(
                            page,
                            [
                                "input[name='firstName']",
                                "input[id='firstName']",
                                "input[autocomplete='given-name']",
                            ],
                            first,
                        )
                        _fill_first(
                            page,
                            [
                                "input[name='lastName']",
                                "input[id='lastName']",
                                "input[autocomplete='family-name']",
                            ],
                            last,
                        )
                    y, m, d = birth.split("-")
                    if not _fill_first(
                        page,
                        [
                            "input[name='birthday']",
                            "input[name='birthdate']",
                            "input[type='date']",
                            "input[id='birthday']",
                            "input[id='birthdate']",
                            "input[placeholder*='Birth' i]",
                        ],
                        birth,
                    ):
                        # common US about-you: MM/DD/YYYY text
                        alt = f"{int(m):02d}/{int(d):02d}/{y}"
                        if not _fill_first(
                            page,
                            [
                                "input[placeholder*='mm' i]",
                                "input[placeholder*='MM' i]",
                                "input[name='birthdate']",
                                "input[type='text']",
                            ],
                            alt,
                        ):
                            _fill_first(
                                page,
                                ["input[name='year']", "select[name='year']"],
                                y,
                            )
                            _fill_first(
                                page,
                                ["input[name='month']", "select[name='month']"],
                                str(int(m)),
                            )
                            _fill_first(
                                page,
                                ["input[name='day']", "select[name='day']"],
                                str(int(d)),
                            )
                            try:
                                selects = page.locator("select").all()
                                if len(selects) >= 3:
                                    for sel, val in zip(selects[:3], [m, d, y]):
                                        try:
                                            sel.select_option(str(int(val)))
                                        except Exception:
                                            try:
                                                sel.select_option(val)
                                            except Exception:
                                                pass
                            except Exception:
                                pass
                    # pure UI: force-click Continue; avoid double-submit storms
                    clicked = False
                    for sel in (
                        "button:has-text('Continue')",
                        "button:has-text('Next')",
                        "button:has-text('Agree')",
                        "button:has-text('继续')",
                        "button[type='submit']",
                    ):
                        try:
                            loc = page.locator(sel).first
                            if loc.count() == 0:
                                continue
                            loc.click(timeout=4000, force=True, no_wait_after=True)
                            clicked = True
                            break
                        except Exception:
                            continue
                    if not clicked:
                        _click_first(
                            page,
                            [
                                "button[type='submit']",
                                "button:has-text('Continue')",
                            ],
                            timeout=5000,
                        )
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=15000)
                    except Exception:
                        pass
                    time.sleep(1.5)
                    _wait_cf_if_any(page, "after-about-you")

                # about you / name / birthdate — poll longer
                for step in range(25):
                    body = _visible_text(page)
                    url = page.url or ""
                    log(f"[browser-reg] step={step} url={url[:100]}")
                    if _page_looks_deactivated(body):
                        out["status"] = "deactivated"
                        out["deactivated"] = True
                        out["hard"] = True
                        out["error"] = "account_deactivated on about_you"
                        return out
                    need_about = bool(
                        re.search(
                            r"about you|your name|birth|生日|姓名|full name|tell us about",
                            body,
                            re.I,
                        )
                    ) or ("about-you" in url or "create-account/about" in url or "about_you" in url)
                    # also detect empty name inputs
                    if not need_about:
                        try:
                            if page.locator("input[name='name'], input[autocomplete='name'], input[name='firstName']").count() > 0:
                                need_about = True
                        except Exception:
                            pass
                    if need_about:
                        _do_about_you()
                        continue

                    # password page sometimes after otp for new accounts — skip/set weak
                    if re.search(r"create.?password|choose.?password|set.?password", body, re.I):
                        pw = (password or "x") if len(password or "") >= 8 else "Aa123456!"
                        _fill_first(
                            page,
                            [
                                "input[name='password']",
                                "input[type='password']",
                                "input[autocomplete='new-password']",
                            ],
                            pw,
                        )
                        _click_first(
                            page,
                            ["button[type='submit']", "button:has-text('Continue')"],
                            timeout=4000,
                        )
                        time.sleep(1.2)
                        continue

                    # landed on chatgpt home / app
                    if "chatgpt.com" in url and not any(
                        x in url for x in ("auth", "login", "api/auth")
                    ):
                        try:
                            page.wait_for_load_state("domcontentloaded", timeout=15000)
                        except Exception:
                            pass
                        break
                    if "callback" in url:
                        try:
                            page.wait_for_load_state("domcontentloaded", timeout=20000)
                        except Exception:
                            pass
                        time.sleep(1.0)
                        continue
                    # accept terms / continue
                    clicked = _click_first(
                        page,
                        [
                            "button:has-text('Accept')",
                            "button:has-text('I agree')",
                            "button:has-text('Agree')",
                            "button:has-text('Continue')",
                            "button:has-text('Next')",
                            "button:has-text('Skip')",
                            "button:has-text('Not now')",
                            "button[type='submit']",
                        ],
                        timeout=2000,
                    )
                    if not clicked:
                        time.sleep(0.8)
                    else:
                        time.sleep(1.0)

                # if still stuck on OTP page, fail clearly
                url_final = page.url or ""
                if "email-verification" in url_final or "email-otp" in url_final:
                    body = _visible_text(page)
                    out["status"] = "otp_stuck"
                    out["error"] = (
                        f"stuck on otp page after submit url={url_final} "
                        f"body={body[:160]}"
                    )
                    return out

                # ensure on chatgpt.com
                try:
                    if "chatgpt.com" not in (page.url or ""):
                        page.goto(
                            "https://chatgpt.com/",
                            wait_until="domcontentloaded",
                            timeout=timeout_ms,
                        )
                        time.sleep(1.5)
                except Exception as e:
                    log(f"[browser-reg] final goto warn: {e}")

                # maybe still about_you after redirect
                body = _visible_text(page)
                if re.search(r"about you|your name|birth|姓名", body, re.I):
                    _do_about_you()
                    try:
                        page.goto(
                            "https://chatgpt.com/",
                            wait_until="domcontentloaded",
                            timeout=timeout_ms,
                        )
                    except Exception:
                        pass

                token = ""
                for attempt in range(1, 8):
                    log(f"[browser-reg] token poll #{attempt} url={page.url}")
                    token = _extract_session_token(page, context, log)
                    if token:
                        break
                    time.sleep(1.5)
                    try:
                        page.goto(
                            "https://chatgpt.com/",
                            wait_until="domcontentloaded",
                            timeout=timeout_ms,
                        )
                        # click through onboarding if any
                        _click_first(
                            page,
                            [
                                "button:has-text('Okay')",
                                "button:has-text('OK')",
                                "button:has-text('Next')",
                                "button:has-text('Continue')",
                                "button:has-text('Get started')",
                            ],
                            timeout=1500,
                        )
                    except Exception:
                        pass

                # dump cookies
                try:
                    raw = context.cookies()
                    out["cookies"] = [
                        {
                            "name": str(c.get("name") or ""),
                            "value": str(c.get("value") or ""),
                            "domain": str(c.get("domain") or ""),
                            "path": str(c.get("path") or "/") or "/",
                        }
                        for c in raw
                    ]
                except Exception:
                    pass

                if not token:
                    body = _visible_text(page)
                    if _page_looks_deactivated(body):
                        out["status"] = "deactivated"
                        out["deactivated"] = True
                        out["hard"] = True
                        out["error"] = "deactivated, no token"
                        return out
                    out["status"] = "no_token"
                    out["error"] = f"login ok-ish but no accessToken url={page.url}"
                    return out

                out["ok"] = True
                out["status"] = "at_ok"
                out["access_token"] = token
                out["at_len"] = len(token)
                out["plan"] = "free"
                # try plan from session
                try:
                    sess = page.request.get(
                        "https://chatgpt.com/api/auth/session", timeout=15000
                    ).json()
                    if isinstance(sess, dict):
                        acc = sess.get("account") if isinstance(sess.get("account"), dict) else {}
                        plan = str(
                            acc.get("planType")
                            or acc.get("plan")
                            or sess.get("plan")
                            or "free"
                        ).lower()
                        out["plan"] = plan or "free"
                except Exception:
                    pass
                log(f"[browser-reg] OK at_len={out['at_len']} plan={out['plan']}")
                return out
            finally:
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception as e:
        err = str(e)
        out["status"] = "fail"
        out["error"] = err[:500]
        low = err.lower()
        if "deactivat" in low and "not deactivated" not in low:
            out["deactivated"] = True
            out["hard"] = True
            out["status"] = "deactivated"
        log(f"[browser-reg] FAIL: {err[:200]}")
        return out
    finally:
        if bridge is not None:
            try:
                bridge.close()
            except Exception:
                pass
