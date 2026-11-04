"""Browser CF seed for first-registration / hard CF accounts (P0/P1).

Pure-curl cannot solve interactive managed challenges. Seed ``cf_clearance``
(+ related cookies) via a real Chromium (or optional Camoufox) session bound to
the same sticky proxy / device_id / UA, then reuse from account_env on curl.

Dependency (optional):
  pip install playwright && playwright install chromium
  # optional harder anti-detect:
  pip install camoufox && camoufox fetch

Never imports playwright/camoufox at module import time.
"""
from __future__ import annotations

import json
import os
import re
import socket
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlparse


class PlaywrightSeedError(RuntimeError):
    """Playwright/Camoufox missing or seed failed."""


class _LocalProxyBridge:
    """Chromium/Playwright cannot do SOCKS5 *with auth*.

    Bridge: remote socks5h://user:pass@host:port → local http://127.0.0.1:PORT
    via a tiny PySocks HTTP CONNECT forwarder thread.
    """

    def __init__(self, local_url: str, stop_fn: Callable[[], None]):
        self.local_url = local_url
        self._stop = stop_fn

    def close(self) -> None:
        try:
            self._stop()
        except Exception:
            pass

    def __enter__(self) -> "_LocalProxyBridge":
        return self

    def __exit__(self, *args) -> None:
        self.close()


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _needs_socks_auth_bridge(proxy_url: str) -> bool:
    u = (proxy_url or "").strip().lower()
    if not u:
        return False
    if not (u.startswith("socks5://") or u.startswith("socks5h://")):
        return False
    try:
        p = urlparse(proxy_url)
        return bool(p.username or p.password)
    except Exception:
        return "@" in u.split("://", 1)[-1]


def _parse_socks_proxy(proxy_url: str) -> tuple[str, int, str, str]:
    p = urlparse(proxy_url)
    host = p.hostname or ""
    port = int(p.port or 0)
    user = unquote(p.username or "")
    pw = unquote(p.password or "")
    if not host or not port:
        raise PlaywrightSeedError(f"bad socks proxy url: {proxy_url[:80]}")
    return host, port, user, pw


def start_local_proxy_bridge(
    proxy_url: str,
    *,
    log_fn: Callable[[str], None] | None = None,
) -> _LocalProxyBridge | None:
    """If proxy is socks5+auth, start local HTTP CONNECT forwarder; else None."""
    import select
    import threading

    _log = log_fn or (lambda _m: None)
    if not _needs_socks_auth_bridge(proxy_url):
        return None
    try:
        import socks  # PySocks
    except Exception as e:
        raise PlaywrightSeedError(
            "SOCKS5 proxy auth needs PySocks bridge: pip install pysocks"
        ) from e

    remote_host, remote_port, user, pw = _parse_socks_proxy(proxy_url)
    port = _free_port()
    local = f"http://127.0.0.1:{port}"
    stop_flag = {"stop": False}
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(64)
    server.settimeout(0.5)

    def _pipe(a: socket.socket, b: socket.socket) -> None:
        try:
            while True:
                r, _, _ = select.select([a], [], [], 30.0)
                if not r:
                    break
                data = a.recv(65536)
                if not data:
                    break
                b.sendall(data)
        except Exception:
            pass
        finally:
            try:
                a.close()
            except Exception:
                pass
            try:
                b.close()
            except Exception:
                pass

    def _handle(client: socket.socket) -> None:
        remote: socket.socket | None = None
        try:
            client.settimeout(30)
            req = b""
            while b"\r\n\r\n" not in req and len(req) < 65536:
                chunk = client.recv(4096)
                if not chunk:
                    break
                req += chunk
            first = req.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
            parts = first.split()
            if len(parts) < 2:
                client.close()
                return
            method, target = parts[0].upper(), parts[1]
            if method == "CONNECT":
                hostport = target
                if ":" in hostport:
                    th, tp = hostport.rsplit(":", 1)
                    tport = int(tp)
                else:
                    th, tport = hostport, 443
                remote = socks.socksocket()
                remote.set_proxy(socks.SOCKS5, remote_host, remote_port, True, user, pw)
                remote.settimeout(30)
                remote.connect((th, tport))
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                # plain HTTP absolute-form: GET http://host/path
                from urllib.parse import urlparse as _up

                u = _up(target)
                th = u.hostname or ""
                tport = int(u.port or 80)
                path = u.path or "/"
                if u.query:
                    path += "?" + u.query
                remote = socks.socksocket()
                remote.set_proxy(socks.SOCKS5, remote_host, remote_port, True, user, pw)
                remote.settimeout(30)
                remote.connect((th, tport))
                # rebuild request line as origin-form
                rest = req.split(b"\r\n", 1)[1] if b"\r\n" in req else b"\r\n"
                new_first = f"{method} {path} HTTP/1.1\r\n".encode("latin-1")
                remote.sendall(new_first + rest)
            t1 = threading.Thread(target=_pipe, args=(client, remote), daemon=True)
            t2 = threading.Thread(target=_pipe, args=(remote, client), daemon=True)
            t1.start()
            t2.start()
        except Exception:
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except Exception:
                pass
            try:
                client.close()
            except Exception:
                pass
            if remote is not None:
                try:
                    remote.close()
                except Exception:
                    pass

    def _serve() -> None:
        while not stop_flag["stop"]:
            try:
                client, _addr = server.accept()
            except socket.timeout:
                continue
            except Exception:
                if stop_flag["stop"]:
                    break
                continue
            threading.Thread(target=_handle, args=(client,), daemon=True).start()
        try:
            server.close()
        except Exception:
            pass

    def _stop() -> None:
        stop_flag["stop"] = True
        try:
            server.close()
        except Exception:
            pass

    th = threading.Thread(target=_serve, name="socks-http-bridge", daemon=True)
    th.start()
    _log(f"[browser-seed] local proxy bridge {local} → socks5(auth via PySocks)")
    # readiness
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            s.close()
            return _LocalProxyBridge(local, _stop)
        except Exception:
            time.sleep(0.05)
    _stop()
    raise PlaywrightSeedError("local socks HTTP bridge not ready")


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401

        return True
    except Exception:
        return False


def camoufox_available() -> bool:
    try:
        import camoufox  # noqa: F401

        return True
    except Exception:
        return False


def browser_seed_available() -> bool:
    return playwright_available() or camoufox_available()


def preferred_engine() -> str:
    """K12_BROWSER_ENGINE=auto|playwright|camoufox (default auto)."""
    raw = (os.environ.get("K12_BROWSER_ENGINE") or "auto").strip().lower()
    if raw in ("camoufox", "camo", "fox"):
        return "camoufox" if camoufox_available() else "playwright"
    if raw in ("playwright", "pw", "chromium", "chrome"):
        return "playwright"
    # auto: prefer camoufox when installed
    if camoufox_available():
        return "camoufox"
    return "playwright"


def _proxy_for_playwright(proxy_url: str) -> dict[str, str] | None:
    """Convert socks5h/http proxy URL to Playwright proxy dict."""
    u = (proxy_url or "").strip()
    if not u:
        return None
    try:
        p = urlparse(u)
        scheme = (p.scheme or "http").replace("socks5h", "socks5")
        host = p.hostname or ""
        port = p.port
        if not host or not port:
            return {"server": u}
        out: dict[str, str] = {"server": f"{scheme}://{host}:{port}"}
        if p.username:
            out["username"] = unquote(p.username)
        if p.password:
            out["password"] = unquote(p.password)
        return out
    except Exception:
        return {"server": u}


def _fp(env: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(env, dict):
        return {}
    fp = env.get("fingerprint_profile")
    return dict(fp) if isinstance(fp, dict) else {}


def _ua_from_env(env: dict[str, Any] | None) -> str:
    fp = _fp(env)
    ua = str(fp.get("user_agent") or fp.get("ua") or "").strip()
    if ua:
        return ua
    # synthesize a chrome UA from major if only impersonate present
    imp = str(fp.get("impersonate") or "chrome").strip()
    m = re.search(r"(\d{2,3})", imp)
    major = m.group(1) if m else "131"
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
    )


def _viewport_from_env(env: dict[str, Any] | None) -> dict[str, int]:
    fp = _fp(env)
    screen = str(fp.get("screen") or fp.get("screen_resolution") or "").strip()
    m = re.match(r"(\d{3,5})\s*[xX×]\s*(\d{3,5})", screen)
    if m:
        w, h = int(m.group(1)), int(m.group(2))
        # cap huge screens for headless stability
        w = max(1024, min(w, 2560))
        h = max(720, min(h, 1440))
        return {"width": w, "height": h}
    return {"width": 1440, "height": 900}


def _locale_from_env(env: dict[str, Any] | None) -> str:
    fp = _fp(env)
    return str(fp.get("language") or "en-US").strip() or "en-US"


def _timezone_from_env(env: dict[str, Any] | None) -> str:
    fp = _fp(env)
    return str(fp.get("timezone") or "America/New_York").strip() or "America/New_York"


def _nav_headers_from_env(env: dict[str, Any] | None) -> dict[str, str]:
    lang = _locale_from_env(env)
    short = lang.split("-")[0] if lang else "en"
    ua = _ua_from_env(env)
    return {
        "Accept-Language": f"{lang},{short};q=0.9,en;q=0.8",
        "User-Agent": ua,
    }


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


def seed_cf_with_playwright(
    *,
    proxy_url: str = "",
    env: dict[str, Any] | None = None,
    urls: list[str] | None = None,
    headless: bool | None = None,
    timeout_ms: int | None = None,
    wait_clearance_s: float | None = None,
    engine: str | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Open browser aligned to sticky env, visit CF origins, return cookies + meta.

    Returns::
      {
        "ok": bool,
        "cookies": [...],
        "cf": {...},
        "error": str,
        "source": "playwright"|"camoufox",
        "engine": str,
        "has_clearance": bool,
        "user_agent": str,
      }
    """
    _log = log_fn or (lambda _m: None)
    eng = (engine or preferred_engine()).strip().lower()
    if eng in ("camo", "fox"):
        eng = "camoufox"
    if eng not in ("playwright", "camoufox"):
        eng = preferred_engine()

    if headless is None:
        # P1: hard accounts often need headed; default headless on, override via env
        headless = _env_bool("K12_BROWSER_HEADLESS", default=True)
        # alias
        if os.environ.get("K12_PLAYWRIGHT_HEADLESS") is not None:
            headless = _env_bool("K12_PLAYWRIGHT_HEADLESS", default=True)

    if timeout_ms is None:
        timeout_ms = int(_env_float("K12_BROWSER_TIMEOUT_MS", 60000))
    if wait_clearance_s is None:
        wait_clearance_s = _env_float("K12_BROWSER_WAIT_CLEARANCE_S", 20.0)

    visit = urls or [
        "https://chatgpt.com/",
        "https://auth.openai.com/",
    ]
    device_id = str((env or {}).get("device_id") or "").strip() if isinstance(env, dict) else ""
    use_proxy = (proxy_url or (env or {}).get("proxy_url") or "").strip() if isinstance(env, dict) else (proxy_url or "")
    # Playwright cannot auth SOCKS5 — bridge to local HTTP when needed
    bridge: _LocalProxyBridge | None = None
    play_proxy_url = use_proxy
    try:
        if use_proxy and _needs_socks_auth_bridge(use_proxy):
            bridge = start_local_proxy_bridge(use_proxy, log_fn=_log)
            if bridge:
                play_proxy_url = bridge.local_url
    except PlaywrightSeedError as e:
        result_err = str(e)[:400]
        _log(f"[browser-seed] proxy bridge fail: {e}")
        return {
            "ok": False,
            "cookies": [],
            "cf": {},
            "error": result_err,
            "source": eng,
            "engine": eng,
            "has_clearance": False,
            "user_agent": _ua_from_env(env),
            "proxy": True,
            "device_id": device_id[:13] + "…" if device_id else "",
        }

    proxy = _proxy_for_playwright(play_proxy_url)
    extra_headers = _nav_headers_from_env(env)
    ua = extra_headers.get("User-Agent") or _ua_from_env(env)
    locale = _locale_from_env(env)
    timezone_id = _timezone_from_env(env)
    viewport = _viewport_from_env(env)

    result: dict[str, Any] = {
        "ok": False,
        "cookies": [],
        "cf": {},
        "error": "",
        "source": eng,
        "engine": eng,
        "has_clearance": False,
        "user_agent": ua,
        "proxy": bool(proxy),
        "device_id": device_id[:13] + "…" if device_id else "",
        "proxy_bridged": bool(bridge),
    }

    _log(
        f"[browser-seed] engine={eng} headless={headless} "
        f"proxy={'yes' if proxy else 'no'} bridged={bool(bridge)} "
        f"lang={locale} tz={timezone_id} "
        f"vp={viewport['width']}x{viewport['height']} device={(device_id[:8] + '…') if device_id else '-'}"
    )

    jar: list[dict[str, str]] = []
    meta: dict[str, Any] = {}
    err = ""
    try:
        try:
            if eng == "camoufox":
                jar, meta, err = _run_camoufox_seed(
                    proxy=proxy,
                    ua=ua,
                    locale=locale,
                    timezone_id=timezone_id,
                    viewport=viewport,
                    device_id=device_id,
                    extra_headers=extra_headers,
                    visit=visit,
                    headless=headless,
                    timeout_ms=timeout_ms,
                    wait_clearance_s=wait_clearance_s,
                    log_fn=_log,
                )
            else:
                jar, meta, err = _run_playwright_seed(
                    proxy=proxy,
                    ua=ua,
                    locale=locale,
                    timezone_id=timezone_id,
                    viewport=viewport,
                    device_id=device_id,
                    extra_headers=extra_headers,
                    visit=visit,
                    headless=headless,
                    timeout_ms=timeout_ms,
                    wait_clearance_s=wait_clearance_s,
                    log_fn=_log,
                )
        except PlaywrightSeedError as e:
            result["error"] = str(e)[:400]
            _log(f"[browser-seed] unavailable: {e}")
            return result
        except Exception as e:
            result["error"] = str(e)[:400]
            _log(f"[browser-seed] failed: {e}")
            return result

        result["cookies"] = jar
        result["cf"] = meta
        result["has_clearance"] = bool(meta.get("has_clearance"))
        result["ok"] = bool(meta.get("has_clearance"))
        if err and not result["ok"]:
            result["error"] = err
        elif not result["ok"]:
            result["error"] = "no cf_clearance captured (challenge may still be open)"
        else:
            _log(
                f"[browser-seed] ok clearance=1 cf_n={meta.get('cookie_count')} "
                f"total_cookies={len(jar)} source={eng}"
            )
        return result
    finally:
        if bridge is not None:
            try:
                bridge.close()
            except Exception:
                pass


def _inject_oai_did(context: Any, device_id: str) -> None:
    if not device_id:
        return
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


def _wait_clearance(context: Any, wait_s: float, log_fn: Callable[[str], None]) -> bool:
    deadline = time.time() + max(2.0, float(wait_s))
    while time.time() < deadline:
        try:
            cookies = context.cookies()
        except Exception:
            cookies = []
        if any(
            str(c.get("name") or "") == "cf_clearance" and str(c.get("value") or "")
            for c in cookies
        ):
            return True
        time.sleep(0.35)
    log_fn("[browser-seed] clearance wait timed out")
    return False


def _cookies_to_jar(raw: list) -> list[dict[str, str]]:
    jar: list[dict[str, str]] = []
    for c in raw or []:
        jar.append(
            {
                "name": str(c.get("name") or ""),
                "value": str(c.get("value") or ""),
                "domain": str(c.get("domain") or ""),
                "path": str(c.get("path") or "/") or "/",
            }
        )
    return jar


def _cf_meta_from_jar(jar: list[dict[str, str]], source: str) -> dict[str, Any]:
    from .cf_challenge import collect_cf_cookies_from_jar, cf_meta_summary

    cf_cookies = collect_cf_cookies_from_jar(jar)
    meta = cf_meta_summary(cf_cookies)
    meta["cookies"] = cf_cookies
    meta["captured_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    meta["source"] = source
    return meta


def _run_playwright_seed(
    *,
    proxy: dict | None,
    ua: str,
    locale: str,
    timezone_id: str,
    viewport: dict[str, int],
    device_id: str,
    extra_headers: dict[str, str],
    visit: list[str],
    headless: bool,
    timeout_ms: int,
    wait_clearance_s: float,
    log_fn: Callable[[str], None],
) -> tuple[list[dict[str, str]], dict[str, Any], str]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        raise PlaywrightSeedError(
            "playwright not installed; run: pip install playwright && playwright install chromium"
        ) from e

    err = ""
    with sync_playwright() as p:
        launch_kwargs: dict[str, Any] = {
            "headless": headless,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
            ],
        }
        browser = p.chromium.launch(**launch_kwargs)
        try:
            ctx_kwargs: dict[str, Any] = {
                "ignore_https_errors": True,
                "locale": locale,
                "timezone_id": timezone_id,
                "viewport": viewport,
                "user_agent": ua,
            }
            if proxy:
                ctx_kwargs["proxy"] = proxy
            # only non-UA extra headers
            hdrs = {k: v for k, v in extra_headers.items() if k.lower() != "user-agent"}
            if hdrs:
                ctx_kwargs["extra_http_headers"] = hdrs
            context = browser.new_context(**ctx_kwargs)
            try:
                # reduce webdriver flag a bit
                context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                )
            except Exception:
                pass
            _inject_oai_did(context, device_id)
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            got = False
            for url in visit:
                log_fn(f"[browser-seed] goto {url}")
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                except Exception as e:
                    log_fn(f"[browser-seed] goto warn {url}: {e}")
                if _wait_clearance(context, wait_clearance_s, log_fn):
                    got = True
                    break
                try:
                    page.wait_for_timeout(500)
                except Exception:
                    pass
            # brief settle
            try:
                page.wait_for_timeout(600)
            except Exception:
                pass
            jar = _cookies_to_jar(context.cookies())
            meta = _cf_meta_from_jar(jar, "playwright")
            if not got and not meta.get("has_clearance"):
                err = "no cf_clearance after navigations"
            try:
                context.close()
            except Exception:
                pass
            return jar, meta, err
        finally:
            try:
                browser.close()
            except Exception:
                pass


def _run_camoufox_seed(
    *,
    proxy: dict | None,
    ua: str,
    locale: str,
    timezone_id: str,
    viewport: dict[str, int],
    device_id: str,
    extra_headers: dict[str, str],
    visit: list[str],
    headless: bool,
    timeout_ms: int,
    wait_clearance_s: float,
    log_fn: Callable[[str], None],
) -> tuple[list[dict[str, str]], dict[str, Any], str]:
    """Camoufox path (optional). Falls back to PlaywrightSeedError if missing."""
    try:
        from camoufox.sync_api import Camoufox
    except Exception as e:
        # try playwright fallback explicitly
        log_fn(f"[browser-seed] camoufox unavailable ({e}); need playwright fallback")
        raise PlaywrightSeedError(
            "camoufox not installed; pip install camoufox && camoufox fetch "
            "(or set K12_BROWSER_ENGINE=playwright)"
        ) from e

    err = ""
    # Camoufox API is Playwright-compatible context
    launch_opts: dict[str, Any] = {
        "headless": headless,
        "os": ("windows",),
        "locale": locale,
        "window": (viewport["width"], viewport["height"]),
    }
    if proxy:
        # camoufox accepts proxy dict similar to playwright
        launch_opts["proxy"] = proxy
    # humanize optional
    if _env_bool("K12_CAMOUFOX_HUMANIZE", default=True):
        launch_opts["humanize"] = True

    with Camoufox(**launch_opts) as browser:
        # browser may be a browser or context depending on version
        try:
            context = browser.new_context(
                user_agent=ua,
                locale=locale,
                timezone_id=timezone_id,
                viewport=viewport,
                ignore_https_errors=True,
                extra_http_headers={
                    k: v for k, v in extra_headers.items() if k.lower() != "user-agent"
                },
            )
            owns_context = True
        except Exception:
            context = browser
            owns_context = False
        try:
            _inject_oai_did(context, device_id)
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            got = False
            for url in visit:
                log_fn(f"[browser-seed] camoufox goto {url}")
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                except Exception as e:
                    log_fn(f"[browser-seed] goto warn {url}: {e}")
                if _wait_clearance(context, wait_clearance_s, log_fn):
                    got = True
                    break
            try:
                page.wait_for_timeout(600)
            except Exception:
                pass
            jar = _cookies_to_jar(context.cookies())
            meta = _cf_meta_from_jar(jar, "camoufox")
            if not got and not meta.get("has_clearance"):
                err = "no cf_clearance after navigations"
            return jar, meta, err
        finally:
            if owns_context:
                try:
                    context.close()
                except Exception:
                    pass


def apply_seed_result_to_env(
    env: dict[str, Any],
    seed: dict[str, Any],
    *,
    merge_jar: bool = True,
) -> dict[str, Any]:
    """Write browser seed cookies into account env + cookies_path."""
    if not isinstance(env, dict) or not isinstance(seed, dict):
        return env
    jar = seed.get("cookies") if isinstance(seed.get("cookies"), list) else []
    cf = seed.get("cf") if isinstance(seed.get("cf"), dict) else {}
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if cf:
        env["cf"] = dict(cf)
        env["cf"]["last_seed_at"] = now
        env["cf"]["source"] = str(seed.get("source") or seed.get("engine") or "playwright")
        if seed.get("user_agent"):
            env["cf"]["user_agent"] = str(seed.get("user_agent"))
    # browser_seed metadata
    env["browser_seed"] = {
        "engine": str(seed.get("engine") or seed.get("source") or "playwright"),
        "ok": bool(seed.get("ok")),
        "has_clearance": bool(seed.get("has_clearance") or (cf or {}).get("has_clearance")),
        "last_seed_at": now,
        "user_agent": str(seed.get("user_agent") or ""),
        "error": str(seed.get("error") or "")[:200],
    }
    # keep fingerprint UA in sync with seed UA when present
    ua = str(seed.get("user_agent") or "").strip()
    if ua:
        fp = env.get("fingerprint_profile")
        if isinstance(fp, dict):
            fp = dict(fp)
            fp["user_agent"] = ua
            env["fingerprint_profile"] = fp

    cpath = str(env.get("cookies_path") or "").strip()
    if cpath and jar:
        path = Path(cpath)
        path.parent.mkdir(parents=True, exist_ok=True)
        existing: list[dict] = []
        if merge_jar and path.is_file():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    existing = [c for c in raw if isinstance(c, dict)]
            except Exception:
                existing = []
        idx = {
            (str(c.get("name") or ""), str(c.get("domain") or "")): i
            for i, c in enumerate(existing)
        }
        for c in jar:
            if not isinstance(c, dict):
                continue
            key = (str(c.get("name") or ""), str(c.get("domain") or ""))
            if key in idx:
                existing[idx[key]] = c
            else:
                idx[key] = len(existing)
                existing.append(c)
        # force sticky oai-did
        device_id = str(env.get("device_id") or "").strip()
        if device_id:
            for domain in (".chatgpt.com", ".auth.openai.com", ".openai.com"):
                key = ("oai-did", domain)
                cookie = {
                    "name": "oai-did",
                    "value": device_id,
                    "domain": domain,
                    "path": "/",
                }
                if key in idx:
                    existing[idx[key]] = cookie
                else:
                    idx[key] = len(existing)
                    existing.append(cookie)
        path.write_text(
            json.dumps(existing, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        env["cookies_path"] = str(path)
    env["updated_at"] = now
    note = str(env.get("notes") or "")
    if "browser_seed" not in note:
        env["notes"] = (note + " | browser_seed").strip(" |")
    return env
