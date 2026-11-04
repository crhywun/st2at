"""TokenRefresher 会话管理 — proxy, session, fingerprint, headers"""
import hashlib, json, os, random, uuid
from typing import Any

try:
    from curl_cffi import requests as cffi_requests
    _HAS_CFFI = True
except ImportError:
    _HAS_CFFI = False

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import constants as C


def _load_hotmail_config(doc_path: str = "", api_base: str = "", admin_password: str = ""):
    """加载 Hotmail API 配置。

    支持：
    1) 显式 api_base + admin_password
    2) 环境变量 HOTMAIL_API_BASE / HOTMAIL_ADMIN_PASSWORD
    3) 文档路径（KEY=value 或 outlook.aitokensale.com 文档里的 URL/密码）
    """
    import re

    # 默认禁用远程邮件池（outlook.aitokensale.com）；OTP 只用本地 Graph 令牌
    allow_remote = (os.environ.get("MAIL_ALLOW_REMOTE_HOTMAIL_API") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    if not allow_remote:
        C.HOTMAIL_API_BASE = ""
        C.HOTMAIL_ADMIN_PASSWORD = ""
        return "", ""

    base = str(api_base or os.environ.get("HOTMAIL_API_BASE") or C.HOTMAIL_API_BASE or "").strip().rstrip("/")
    password = str(
        admin_password or os.environ.get("HOTMAIL_ADMIN_PASSWORD") or C.HOTMAIL_ADMIN_PASSWORD or ""
    ).strip()

    if base and password:
        C.HOTMAIL_API_BASE = base
        C.HOTMAIL_ADMIN_PASSWORD = password
        return C.HOTMAIL_API_BASE, C.HOTMAIL_ADMIN_PASSWORD

    candidate_docs: list[str] = []
    if doc_path:
        candidate_docs.append(doc_path)

    # 常见文档位置：cwd、包旁、父项目 ref/mail_api
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    search_dirs = [
        os.getcwd(),
        here,
        root,
        os.path.join(root, "ref", "mail_api"),
        os.path.join(os.path.dirname(root), "ref", "mail_api") if os.path.basename(root) else "",
    ]
    for d in search_dirs:
        if not d or not os.path.isdir(d):
            continue
        for name in ("outlook_api.md", "hotmail.md", "新hotmail.md"):
            p = os.path.join(d, name)
            if os.path.isfile(p) and p not in candidate_docs:
                candidate_docs.append(p)
        try:
            for name in os.listdir(d):
                low = name.lower()
                if low.startswith("outlook") and low.endswith(".md"):
                    p = os.path.join(d, name)
                    if p not in candidate_docs:
                        candidate_docs.append(p)
        except OSError:
            pass

    for current_doc in candidate_docs:
        if not os.path.isfile(current_doc):
            continue
        try:
            with open(current_doc, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue

        for line in content.splitlines():
            if "HOTMAIL_API_BASE=" in line and not base:
                base = line.split("=", 1)[1].strip().strip('"').strip("'").rstrip("/")
            if "HOTMAIL_ADMIN_PASSWORD=" in line and not password:
                password = line.split("=", 1)[1].strip().strip('"').strip("'")

        if not base:
            m = re.search(r"https://outlook\.aitokensale\.com/?", content)
            if m:
                base = m.group(0).rstrip("/")
        if not password:
            # 文档里独立一行的长密码（排除 email----token 导入行）
            for candidate in re.findall(r"(?m)^([A-Za-z0-9+/_=\-]{20,})$", content):
                if "@" not in candidate and "----" not in candidate:
                    password = candidate.strip()
                    break

        if base and password:
            C.HOTMAIL_API_BASE = base
            C.HOTMAIL_ADMIN_PASSWORD = password
            return C.HOTMAIL_API_BASE, C.HOTMAIL_ADMIN_PASSWORD

    if base:
        C.HOTMAIL_API_BASE = base
    if password:
        C.HOTMAIL_ADMIN_PASSWORD = password
    return C.HOTMAIL_API_BASE, C.HOTMAIL_ADMIN_PASSWORD


def create_session_with_proxy(proxy_url: str, impersonate: str = "") -> Any:
    """创建带代理的 Session，优先使用 curl_cffi (TLS 指纹模拟)"""
    if impersonate == "chrome150":
        from registration_fingerprint import require_native_chrome

        require_native_chrome(150)
        kwargs = {"impersonate": "chrome150"}
        if proxy_url:
            kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}
        return cffi_requests.Session(**kwargs)
    if _HAS_CFFI:
        from .humanize import pick_impersonate

        imp = (impersonate or "").strip() or pick_impersonate()
        # 不支持的档位就近降级（避免运行中 ImpersonateError）
        _fallback_chain = {
            "chrome133": "chrome131",
            "chrome136": "chrome131",
            "chrome142": "chrome146",
            "chrome150": "chrome146",
            "firefox": "firefox144",
            "firefox135": "firefox144",
            "firefox133": "firefox144",
        }
        candidates = [imp]
        if imp in _fallback_chain:
            candidates.append(_fallback_chain[imp])
        # Family-aware fallbacks: stay on Firefox if started as Firefox
        if imp.startswith("firefox"):
            candidates.extend(["firefox144", "firefox147", "firefox135"])
        else:
            if imp not in ("chrome", "chrome146"):
                candidates.extend(["chrome146", "chrome", "chrome131"])
        last_err: Exception | None = None
        for cand in candidates:
            kwargs = {"impersonate": cand}
            if proxy_url:
                kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}
            try:
                return cffi_requests.Session(**kwargs)
            except Exception as exc:
                last_err = exc
                continue
        # last resort: no impersonate
        try:
            kwargs = {}
            if proxy_url:
                kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}
            return cffi_requests.Session(**kwargs)
        except Exception:
            if last_err:
                raise last_err
            raise
    # Fallback: requests
    s = requests.Session()
    if proxy_url:
        s.proxies = {"http": proxy_url, "https": proxy_url}
    s.verify = False
    adapter = HTTPAdapter(pool_connections=5, pool_maxsize=10, max_retries=Retry(total=0), pool_block=False)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def pick_fingerprint_profile(seed_text: str = "") -> dict:
    """按规则组合空间选指纹：有 seed 时确定性（同 seed 同 persona），空 seed 真随机。

    不物化几十万条表；O(1) 从 major×build×screen×平台版本 解码。
    Profile 已含 bound impersonate + screen；调用方不得再随机改 UA/TLS。
    """
    if hasattr(C, "pick_fingerprint_by_seed"):
        return C.pick_fingerprint_by_seed(seed_text or "")
    # 极旧回退
    if not getattr(C, "FINGERPRINT_POOL_SIZE", 0):
        raise RuntimeError("fingerprint space empty")
    h = hashlib.sha256((seed_text or str(random.random())).encode("utf-8", errors="replace")).hexdigest()
    idx = int(h[:16], 16) % int(C.FINGERPRINT_POOL_SIZE)
    fp = C.fingerprint_at(idx)
    fp["profile_index"] = idx
    return fp


def _stable_choice(items: list, seed_text: str, salt: str = "") -> Any:
    """Deterministic pick from list using seed (no random when seed present)."""
    if not items:
        raise ValueError("empty items")
    if not seed_text:
        return random.choice(items)
    h = hashlib.sha256(f"{salt}|{seed_text}".encode("utf-8", errors="replace")).hexdigest()
    return items[int(h[:12], 16) % len(items)]


def _apply_diverse_locale(profile: dict, proxy_url: str = "", locale: str = "",
                          seed_text: str = "", profile_region: str = "") -> None:
    """语言/时区默认跟代理 region；内部实验可显式指定画像地区。

    无 region 时默认 US 池（不抽全球随机语言）。
    """
    from . import constants as _C

    proxy_l = str(proxy_url or "").lower()
    seed_l = str(seed_text or "").lower()
    loc = (locale or "").strip()
    loc_l = loc.lower()
    seed_key = seed_text or proxy_url or profile.get("name") or "default"

    # 从代理 user 串解析 region-XX（勿用 host 名判断）
    import re as _re

    def _region_from_text(text: str) -> str:
        m = _re.search(r"region[-_]([a-z]{2,})", text or "", _re.I)
        return (m.group(1).upper() if m else "")

    route_region = _region_from_text(proxy_l) or _region_from_text(seed_l)
    requested_profile_region = str(profile_region or "").strip().upper()
    if not _re.fullmatch(r"[A-Z]{2}", requested_profile_region):
        requested_profile_region = ""
    region = requested_profile_region or route_region
    # locale 简写映射到 region
    loc_to_region = {
        "jp": "JP", "ja": "JP", "ja-jp": "JP", "ja_jp": "JP",
        "us": "US", "en-us": "US", "en_us": "US",
        "gb": "GB", "uk": "GB", "en-gb": "GB",
        "ca": "CA", "en-ca": "CA",
        "fr": "FR", "fr-fr": "FR",
        # hk 不支持 OpenAI，不映射
        "sg": "SG", "en-sg": "SG",
        "tw": "TW", "zh-tw": "TW",
        "de": "DE", "de-de": "DE",
        "kr": "KR", "ko": "KR", "ko-kr": "KR",
        "my": "MY", "ch": "CH",
        "vn": "VN", "vi": "VN", "vi-vn": "VN", "vi_vn": "VN",
    }
    # 若代理是 HK，当作未知区并尽量别用（加载层已过滤）
    if region == "HK":
        region = ""
    if not region and loc_l in loc_to_region:
        region = loc_to_region[loc_l]
    # 无 region → 默认 US（与多数安全代理一致），禁止全球乱抽
    if not region:
        region = "US"

    def _pick_region_pool(reg: str):
        pools = getattr(_C, "REGION_LOCALE_POOLS", {}) or {}
        attr = pools.get(reg.upper())
        if not attr:
            return None
        return getattr(_C, attr, None)

    reg_u = (region or "US").upper()
    us_langs = getattr(_C, "US_LANGS", None)
    us_tzs = getattr(_C, "US_TIMEZONES", None)

    if loc_l in ("", "auto", "diverse", "random") or loc_l in loc_to_region:
        if reg_u == "US" and us_langs and us_tzs:
            lang, langs = _stable_choice(list(us_langs), seed_key, salt="us_lang_v2")
            tz = _stable_choice(list(us_tzs), seed_key, salt="us_tz_v2")
        else:
            pool = _pick_region_pool(reg_u)
            if pool:
                lang, langs, tz = _stable_choice(
                    list(pool), seed_key, salt="locale_pool"
                )
            elif us_langs and us_tzs:
                # 未知区：仍用 US，不要全球随机
                lang, langs = _stable_choice(list(us_langs), seed_key, salt="us_lang_fallback")
                tz = _stable_choice(list(us_tzs), seed_key, salt="us_tz_fallback")
            else:
                lang, langs, tz = "en-US", "en-US,en;q=0.9", "America/New_York"
    else:
        # 显式固定 language：时区仍跟 region 池，避免语言固定但 tz 乱飞
        lang = loc
        langs = f"{loc},{loc.split('-')[0]};q=0.9"
        pool = _pick_region_pool(reg_u)
        if reg_u == "US" and us_tzs:
            tz = _stable_choice(list(us_tzs), seed_key, salt="us_tz_fixed_lang")
        elif pool:
            _l, _ls, tz = _stable_choice(list(pool), seed_key, salt="locale_pool_tz_only")
        else:
            tz = "America/New_York"

    # P0-5: region 语言强制——不依赖池子抽签（实测 KR 出口曾抽到 en-US）。
    # Accept-Language (HTTP) ≠ navigator.languages (SDK getConfig p[8]).
    # Bit Chrome JP captures: navigator.language=ja-JP, languages=["ja-JP"].
    # HTTP AL may still carry q-weights (ja,en-US;q=0.9,en;q=0.8).
    # HARD_LOCALE: (language, navigator_language, accept_language, languages_list)
    HARD_LOCALE = {
        "KR": ("ko-KR", "ko-KR", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7", ["ko-KR"]),
        "JP": ("ja-JP", "ja-JP", "ja,en-US;q=0.9,en;q=0.8", ["ja-JP"]),
        "US": ("en-US", "en-US", "en-US,en;q=0.9", ["en-US"]),
        "GB": ("en-GB", "en-GB", "en-GB,en;q=0.9,en-US;q=0.8", ["en-GB"]),
        "SG": ("en-SG", "en-SG", "en-SG,en;q=0.9,en-US;q=0.8", ["en-SG"]),
        "TW": ("zh-TW", "zh-TW", "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7", ["zh-TW"]),
        "DE": ("de-DE", "de-DE", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7", ["de-DE"]),
        "FR": ("fr-FR", "fr-FR", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", ["fr-FR"]),
        "CA": ("en-CA", "en-CA", "en-CA,en;q=0.9,en-US;q=0.8", ["en-CA"]),
        "MY": ("en-MY", "en-MY", "en-MY,en;q=0.9,en-US;q=0.8", ["en-MY"]),
        "VN": ("vi-VN", "vi-VN", "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7", ["vi-VN"]),
    }
    nav_lang = ""
    accept_al = ""
    lang_list: list[str] = []
    if reg_u in HARD_LOCALE:
        lang, nav_lang, accept_al, lang_list = HARD_LOCALE[reg_u]
    if requested_profile_region == "JP":
        tz = "Asia/Tokyo"

    profile["language"] = lang
    profile["navigator_language"] = nav_lang or (
        "ja-JP" if str(lang).lower().startswith("ja")
        else ("ko-KR" if str(lang).lower().startswith("ko") else lang)
    )
    if not lang_list:
        lang_list = [str(profile["navigator_language"] or lang or "ja-JP")]
    # navigator.languages for SDK / formal-frame (NOT the q-weighted AL string)
    profile["languages_list"] = list(lang_list)
    profile["languages"] = list(lang_list)
    profile["accept_language"] = accept_al or str(
        profile.get("accept_language") or ""
    )
    profile["locale"] = lang
    profile["timezone"] = tz
    profile["timezone_offset_minutes"] = _C.chrome_timezone_offset_min(tz)
    profile["proxy_region"] = (route_region or reg_u).upper()
    if requested_profile_region:
        profile["profile_region"] = reg_u
        profile["route_region"] = (route_region or reg_u).upper()


class TokenRefresher:
    """核心会话类：管理 proxy session、device_id、指纹、登录状态"""

    def __init__(
        self,
        proxy_url: str = "",
        fingerprint_seed: str = "",
        log_fn=None,
        locale: str = "auto",
        device_id: str = "",
        profile_region: str = "",
        chrome_major: int | None = None,
    ):
        self.proxy_url = proxy_url
        self._log = log_fn or (lambda _: None)
        # When set, reuse this oai-did (MFA / re-login must match registration persona)
        _forced_did = str(device_id or "").strip()

        # ── 固定表指纹：先选 profile，再按其 impersonate 建 TLS session ──
        # 默认不加随机盐 → 同 fingerprint_seed（通常是邮箱）稳定落到同一套 persona。
        # TOKENREFRESH_FP_SALT=1 时恢复旧行为（每次随机盐，同一邮箱不同指纹）。
        use_salt = (os.environ.get("TOKENREFRESH_FP_SALT") or "").strip().lower() in (
            "1", "true", "yes", "on",
        )
        base_seed = (fingerprint_seed or proxy_url or "").strip()
        if base_seed and use_salt:
            seed = f"{base_seed}|{uuid.uuid4().hex[:8]}"
        else:
            seed = base_seed

        # ── HTTP fingerprint family (orthogonal to SENTINEL_ENGINE)
        # Do NOT fall back to TOKENREFRESH_SENTINEL_ENGINE — "formal-frame" is an
        # engine name, not an FP family (bug: forced Firefox whenever engine defaulted).
        # Bit full-token gold (t raw p50≈1000) is Chrome; register defaults FP=chrome.
        # Firefox pool: TOKENREFRESH_FP_FAMILY=firefox (Eda formal-frame companion).
        # Capture ground truth is Bit Chrome — default FP is always chrome.
        # Firefox only when explicitly requested (never via SENTINEL_ENGINE name).
        _fp_family = (os.environ.get("TOKENREFRESH_FP_FAMILY") or "").strip().lower()
        if not _fp_family:
            _fp_family = (
                os.environ.get("TOKENREFRESH_FP_DEFAULT") or "chrome"
            ).strip().lower()
        _use_firefox = _fp_family in (
            "firefox",
            "ff",
            "eda",
            "firefox144",
        )
        if chrome_major is not None:
            from registration_fingerprint import registration_chrome_major

            chrome_major = registration_chrome_major(chrome_major)
            _use_firefox = False
        if _use_firefox:
            try:
                from .formal_frame import firefox_pooled_fingerprint

                requested_profile_region = str(profile_region or "").strip().upper()
                if len(requested_profile_region) != 2 or not requested_profile_region.isalpha():
                    requested_profile_region = ""
                region_hint = requested_profile_region or "JP"
                try:
                    import re as _re

                    m = _re.search(
                        r"region[-_]([a-z]{2,})",
                        (proxy_url or fingerprint_seed or "").lower(),
                        _re.I,
                    )
                    if m and not requested_profile_region:
                        region_hint = m.group(1).upper()
                except Exception:
                    pass
                self.fingerprint_profile = firefox_pooled_fingerprint(
                    seed or fingerprint_seed or "",
                    region=region_hint,
                )
                # Locale overlay for non-JP regions while keeping Firefox identity
                if requested_profile_region or (region_hint and region_hint != "JP"):
                    _apply_diverse_locale(
                        self.fingerprint_profile,
                        proxy_url=proxy_url,
                        locale=locale,
                        seed_text=fingerprint_seed or seed or "",
                        profile_region=requested_profile_region,
                    )
                    # Re-strip Client Hints after locale helper
                    self.fingerprint_profile["sec_ch_ua"] = ""
                    self.fingerprint_profile["sec_ch_ua_mobile"] = ""
                    self.fingerprint_profile["sec_ch_ua_platform"] = ""
                    self.fingerprint_profile["brand"] = "firefox"
                    self.fingerprint_profile["family"] = "firefox"
                    if not str(self.fingerprint_profile.get("user_agent") or "").startswith(
                        "Mozilla/5.0"
                    ) or "Firefox/" not in str(
                        self.fingerprint_profile.get("user_agent") or ""
                    ):
                        self.fingerprint_profile["user_agent"] = (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) "
                            "Gecko/20100101 Firefox/144.0"
                        )
                imp = str(self.fingerprint_profile.get("impersonate") or "firefox144")
                self.fingerprint_profile["impersonate"] = imp
                self.impersonate = imp
                self.session = create_session_with_proxy(
                    proxy_url, impersonate=self.impersonate
                )
            except Exception as _ff_fp_err:
                self._log(f"[fingerprint] firefox pool failed ({_ff_fp_err}), chrome fallback")
                _use_firefox = False

        if not _use_firefox:
            self.fingerprint_profile = pick_fingerprint_profile(seed)
            # screen 以表内绑定为准；缺省再从池确定性补
            if not self.fingerprint_profile.get("screen"):
                self.fingerprint_profile["screen"] = _stable_choice(
                    list(C.SCREEN_RESOLUTIONS), seed or "screen", salt="screen"
                )
            # locale 跟代理 region（池内确定性）
            _apply_diverse_locale(
                self.fingerprint_profile,
                proxy_url=proxy_url,
                locale=locale,
                seed_text=fingerprint_seed or seed or "",
                profile_region=profile_region,
            )
            # 默认强制 Win + Chrome146 + TLS chrome146（与 curl_cffi 顶档对齐）。
            # TOKENREFRESH_FP_DIVERSE=1 恢复旧：mac/edge/多 major 组合池。
            force_win146 = (os.environ.get("TOKENREFRESH_FP_DIVERSE") or "").strip().lower() not in (
                "1", "true", "yes", "on",
            )
            if force_win146:
                keep_keys = (
                    "language", "languages", "languages_list", "accept_language",
                    "timezone", "timezone_offset_minutes", "proxy_region",
                    "profile_region", "route_region",
                    "navigator_language", "locale", "profile_index", "screen",
                )
                kept = {k: self.fingerprint_profile.get(k) for k in keep_keys if self.fingerprint_profile.get(k)}
                screen = str(kept.get("screen") or "1920x1080")
                idx = int(kept.get("profile_index") or 0)
                # 同 seed 稳定选 Win 平台版本，避免每人同一串 full-version
                win_pvs = list(getattr(C, "_FP_WIN_PV", ("19.0.0",)) or ("19.0.0",))
                pver = _stable_choice(win_pvs, seed or "pv", salt="win146_pv")
                builds = getattr(C, "_FP_CHROME_BUILD_TABLE", {}).get(146) or [(7663, 100)]
                bi = int(hashlib.sha256(f"b146|{seed}".encode()).hexdigest()[:8], 16) % len(builds)
                cb, cp = builds[bi]
                fixed = C._chrome_profile(
                    146,
                    brand="chrome",
                    chromium_build=cb,
                    chromium_patch=cp,
                    platform="Windows",
                    platform_version=str(pver),
                    screen=screen,
                    idx=idx,
                )
                self.fingerprint_profile = fixed
                for k, v in kept.items():
                    if v is not None and k != "screen":
                        self.fingerprint_profile[k] = v
                self.fingerprint_profile["screen"] = screen
                self.fingerprint_profile["forced_win146"] = True
                imp = "chrome146"
                # Bit captures use Chrome/147 UA while TLS may stay chrome146.
                # TOKENREFRESH_CHROME_MAJOR / UA_MAJOR_OVERRIDE aligns HTTP UA to capture.
                _ua_maj = (
                    os.environ.get("TOKENREFRESH_UA_MAJOR_OVERRIDE")
                    or os.environ.get("TOKENREFRESH_CHROME_MAJOR")
                    or ""
                ).strip()
                if _ua_maj.isdigit():
                    _m = int(_ua_maj)
                    self.fingerprint_profile["chrome_major"] = _m
                    self.fingerprint_profile["user_agent"] = (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        f"(KHTML, like Gecko) Chrome/{_m}.0.0.0 Safari/537.36"
                    )
                    # Match Bit sec-ch-ua style A (JP HARs)
                    self.fingerprint_profile["sec_ch_ua"] = (
                        f'"Google Chrome";v="{_m}", "Not.A/Brand";v="8", "Chromium";v="{_m}"'
                    )
                    self.fingerprint_profile["sec_ch_ua_full_version_list"] = (
                        f'"Google Chrome";v="{_m}.0.0.0", "Not.A/Brand";v="10.0.0.4", '
                        f'"Chromium";v="{_m}.0.0.0"'
                    )
                    self.fingerprint_profile["sec_ch_ua_mobile"] = "?0"
                    self.fingerprint_profile["sec_ch_ua_platform"] = '"Windows"'
                    self.fingerprint_profile["capture_chrome_ua"] = True
                # Bit capture extract defaults (network.jsonl has no cores/mem) → 8/8
                # Keep deterministic unless TOKENREFRESH_FP_DIVERSE or explicit env.
                _hw = (os.environ.get("TOKENREFRESH_HW_CONCURRENCY") or "").strip()
                _mem = (os.environ.get("TOKENREFRESH_DEVICE_MEMORY") or "").strip()
                self.fingerprint_profile["hardware_concurrency"] = (
                    int(_hw) if _hw.isdigit() else 8
                )
                self.fingerprint_profile["device_memory"] = (
                    int(_mem) if _mem.isdigit() else 8
                )
            else:
                # UA ↔ TLS：强制 major 与 impersonate 同代（表生成已钳；此处再保险一次）
                imp = (self.fingerprint_profile.get("impersonate") or "").strip()
                brand = str(self.fingerprint_profile.get("brand") or "chrome")
                if not imp:
                    major = int(self.fingerprint_profile.get("chrome_major") or 146)
                    imp = C.impersonate_for_ua(major=major, brand=brand)
                want_major = C.ua_major_for_impersonate(imp)
                got_major = int(self.fingerprint_profile.get("chrome_major") or 0)
                if got_major != want_major or not self.fingerprint_profile.get("user_agent"):
                    plat = str(self.fingerprint_profile.get("platform") or "Windows")
                    screen = str(self.fingerprint_profile.get("screen") or "1920x1080")
                    fixed = C._chrome_profile(
                        want_major,
                        brand=brand if brand in ("chrome", "edge") else "chrome",
                        platform="macOS" if "mac" in plat.lower() else "Windows",
                        screen=screen,
                        idx=int(self.fingerprint_profile.get("profile_index") or 0),
                    )
                    for k, v in fixed.items():
                        self.fingerprint_profile[k] = v
                    imp = fixed["impersonate"]
            if chrome_major is not None:
                from registration_fingerprint import apply_registration_chrome_profile

                apply_registration_chrome_profile(self.fingerprint_profile, chrome_major)
                imp = self.fingerprint_profile["impersonate"]
            self.fingerprint_profile["impersonate"] = imp
            self.impersonate = imp
            self.session = create_session_with_proxy(proxy_url, impersonate=self.impersonate)

        # device_id：默认每次新会话真随机（像浏览器）；落盘后 export 靠 restore。
        # 显式 device_id= 强制复用（注册→MFA 同会话/同人格必传）。
        # TOKENREFRESH_DEVICE_STABLE=1 时按邮箱 hash 稳定（旧行为，可聚类，不推荐）。
        # TOKENREFRESH_DEVICE_RANDOM=1 同默认随机（兼容旧开关）。
        dev_stable = (os.environ.get("TOKENREFRESH_DEVICE_STABLE") or "").strip().lower() in (
            "1", "true", "yes", "on",
        )
        dev_rand = (os.environ.get("TOKENREFRESH_DEVICE_RANDOM") or "").strip().lower() in (
            "1", "true", "yes", "on",
        )
        if _forced_did:
            self.device_id = _forced_did
            try:
                self._log(f"[fingerprint] reuse oai-did={self.device_id[:13]}…")
            except Exception:
                pass
        elif base_seed and dev_stable and not dev_rand:
            h = hashlib.sha256(f"oai-did|{base_seed}".encode()).hexdigest()
            self.device_id = str(uuid.UUID(h[:32]))
        else:
            self.device_id = str(uuid.uuid4())

        try:
            self._log(
                f"[fingerprint] idx={self.fingerprint_profile.get('profile_index', '?')} "
                f"name={self.fingerprint_profile.get('name')} "
                f"impersonate={self.impersonate} "
                f"ua_major={self.fingerprint_profile.get('chrome_major')} "
                f"screen={self.fingerprint_profile.get('screen')} "
                f"lang={self.fingerprint_profile.get('language')} "
                f"tz={self.fingerprint_profile.get('timezone')} "
                f"region={self.fingerprint_profile.get('proxy_region') or '-'} "
                f"pool={getattr(C, 'FINGERPRINT_POOL_SIZE', len(C.FINGERPRINT_PROFILES))}"
            )
        except Exception:
            pass

        # Phone state
        self.last_phone = ""
        self.last_sms_provider = ""
        self.last_sms_activation_id = ""
        self.last_sms_order_id = ""
        self.last_sms_phone = ""

        # Bind DID into fingerprint (formal-frame + retries share same identity)
        try:
            self.fingerprint_profile["oai_did"] = self.device_id
        except Exception:
            pass

        # Diversify screen/cores/lang/tz per DID — unless capture-chrome lock.
        # Bit capture extract defaults: 1920x1080, 8 cores, 8GB; languages_list single tag.
        _fp_diverse = (os.environ.get("TOKENREFRESH_FP_DIVERSE") or "").strip().lower() in (
            "1", "true", "yes", "on",
        )
        _capture_lock = (
            not _fp_diverse
            and str(self.fingerprint_profile.get("brand") or "").lower() != "firefox"
            and (
                self.fingerprint_profile.get("forced_win146")
                or self.fingerprint_profile.get("capture_chrome_ua")
                or (os.environ.get("TOKENREFRESH_FP_FAMILY") or "chrome").strip().lower()
                in ("", "chrome", "chrome146")
            )
        )
        try:
            from .persona_diversify import diversify_profile

            diversify_profile(
                self.fingerprint_profile,
                account_key=str(fingerprint_seed or base_seed or ""),
                device_id=str(self.device_id or ""),
            )
            self._log(
                f"[fingerprint] diverse screen={self.fingerprint_profile.get('screen')} "
                f"cores={self.fingerprint_profile.get('hardware_concurrency')} "
                f"mem={self.fingerprint_profile.get('device_memory')} "
                f"dpr={self.fingerprint_profile.get('device_pixel_ratio')} "
                f"tz={self.fingerprint_profile.get('timezone')} "
                f"seed={str(self.fingerprint_profile.get('persona_diverse_seed') or '')[:12]}"
            )
        except Exception as _div_exc:
            try:
                self._log(f"[fingerprint] diversify skip: {_div_exc}")
            except Exception:
                pass

        if _capture_lock:
            # Re-apply capture-grounded stable geometry after diversify
            _hw = (os.environ.get("TOKENREFRESH_HW_CONCURRENCY") or "").strip()
            _mem = (os.environ.get("TOKENREFRESH_DEVICE_MEMORY") or "").strip()
            self.fingerprint_profile["hardware_concurrency"] = (
                int(_hw) if _hw.isdigit() else 8
            )
            self.fingerprint_profile["device_memory"] = (
                int(_mem) if _mem.isdigit() else 8
            )
            self.fingerprint_profile["screen"] = "1920x1080"
            self.fingerprint_profile["screen_width"] = 1920
            self.fingerprint_profile["screen_height"] = 1080
            self.fingerprint_profile["screen_avail_width"] = 1920
            self.fingerprint_profile["screen_avail_height"] = 1040
            # Ensure navigator languages stay single-tag capture style
            reg = str(self.fingerprint_profile.get("proxy_region") or "JP").upper()
            if reg == "JP" or str(self.fingerprint_profile.get("language") or "").lower().startswith("ja"):
                self.fingerprint_profile["language"] = "ja-JP"
                self.fingerprint_profile["navigator_language"] = "ja-JP"
                self.fingerprint_profile["languages_list"] = ["ja-JP"]
                self.fingerprint_profile["languages"] = ["ja-JP"]
            self.fingerprint_profile["capture_chrome_lock"] = True

        # Seeded Canvas/WebGL persona (per email/device, UA-family consistent)
        try:
            from .gpu_persona import apply_gpu_persona_to_profile

            apply_gpu_persona_to_profile(
                self.fingerprint_profile,
                account_key=str(
                    f"{fingerprint_seed or base_seed}|{self.device_id}"
                ),
            )
            self._log(
                f"[fingerprint] gpu renderer="
                f"{str(self.fingerprint_profile.get('webgl_renderer') or '')[:56]} "
                f"canvas={str(self.fingerprint_profile.get('canvas_hash') or '')[:12]}"
            )
        except Exception as _gpu_exc:
            try:
                self._log(f"[fingerprint] gpu persona skip: {_gpu_exc}")
            except Exception:
                pass

        # Init cookies — 浏览器 oai-did 跨 auth / chatgpt 域；丢域会导致会话图不完整
        for _dom in (
            ".auth.openai.com",
            "auth.openai.com",
            ".chatgpt.com",
            "chatgpt.com",
            ".openai.com",
            "openai.com",
        ):
            try:
                self.session.cookies.set("oai-did", self.device_id, domain=_dom)
            except Exception:
                pass

        # Exit IP through registration proxy — bind into persona before any sentinel/t
        try:
            from .utils import apply_exit_ip_info_to_profile, probe_exit_ip

            _geo = probe_exit_ip(self.session)
            if isinstance(_geo, dict) and _geo.get("ip"):
                apply_exit_ip_info_to_profile(self.fingerprint_profile, _geo)
                self._log(
                    f"[fingerprint] exit_ip={self.fingerprint_profile.get('exit_ip')} "
                    f"country={self.fingerprint_profile.get('observed_exit_country') or '-'} "
                    f"city={self.fingerprint_profile.get('exit_city') or '-'}"
                )
        except Exception as _geo_exc:
            try:
                self._log(f"[fingerprint] exit_ip probe skip: {_geo_exc}")
            except Exception:
                pass

        # 协议自洽审计（0 RTT）：UA↔TLS、profile 关键字段；仅打日志不阻断
        try:
            from .utils import audit_fingerprint_consistency

            issues = audit_fingerprint_consistency(
                self.fingerprint_profile, impersonate=self.impersonate
            )
            if issues:
                self._log(f"[fingerprint] consistency: {'; '.join(issues[:6])}")
            else:
                self._log("[fingerprint] consistency: ok")
        except Exception:
            pass

    def close(self):
        try:
            ctx = getattr(self.session, "_formal_frame_ctx", None)
            if ctx is not None and hasattr(ctx, "close"):
                ctx.close()
        except Exception:
            pass
        try:
            self.session.close()
        except Exception:
            pass

    # ── Headers ────────────────────────────────────
    def _apply_client_hints(self, h: dict, *, extended: bool = True) -> None:
        """Client Hints — 8-2 HAR 分场景：

        extended=True  → 完整 CH（arch/bitness/full-version-list…）用于导航（callback 等）
        extended=False → 基础三件套（sec-ch-ua/mobile/platform），
                         8-2 validate/create_account 实测仅这三件。

        Firefox profiles never send Client Hints (Eda/formal-frame contract).
        """
        fp = self.fingerprint_profile or {}
        if fp.get("user_agent"):
            h["user-agent"] = fp["user_agent"]
        ua = h.get("user-agent") or str(fp.get("user_agent") or "")
        is_firefox = (
            str(fp.get("family") or fp.get("brand") or "").lower() == "firefox"
            or "Firefox/" in ua
            or str(fp.get("impersonate") or "").startswith("firefox")
        )
        if is_firefox:
            # Strip any Chrome CH that COMMON_HEADERS may have seeded
            for k in list(h):
                if k.lower().startswith("sec-ch-ua"):
                    del h[k]
            if fp.get("accept_language") or fp.get("languages"):
                # accept-language applied by callers; nothing else here
                pass
            return
        if extended and str(fp.get("signup_profile") or "") == "har_parity":
            # Neither trial-eligible capture ever sent the high-entropy hints:
            # chatgpt.com only advertises Accept-CH on a subresource, which
            # Chrome ignores, so even document navigations carry the basic set.
            extended = False
        if fp.get("sec_ch_ua"):
            h["sec-ch-ua"] = fp["sec_ch_ua"]
        h["sec-ch-ua-mobile"] = fp.get("sec_ch_ua_mobile") or "?0"
        if fp.get("sec_ch_ua_platform"):
            h["sec-ch-ua-platform"] = fp["sec_ch_ua_platform"]
        elif "Macintosh" in ua:
            h["sec-ch-ua-platform"] = '"macOS"'
        else:
            h["sec-ch-ua-platform"] = '"Windows"'
        if extended:
            # Extended hints — present on real Edge/Chrome 150 create_account
            # profile keys use underscore; HTTP headers use hyphen
            hint_map = {
                "sec_ch_ua_arch": "sec-ch-ua-arch",
                "sec_ch_ua_bitness": "sec-ch-ua-bitness",
                "sec_ch_ua_model": "sec-ch-ua-model",
                "sec_ch_ua_full_version": "sec-ch-ua-full-version",
                "sec_ch_ua_full_version_list": "sec-ch-ua-full-version-list",
                "sec_ch_ua_platform_version": "sec-ch-ua-platform-version",
            }
            for pk, hk in hint_map.items():
                if fp.get(pk):
                    h[hk] = fp[pk]
            if "sec-ch-ua-arch" not in h:
                h["sec-ch-ua-arch"] = '"x86"'
            if "sec-ch-ua-bitness" not in h:
                h["sec-ch-ua-bitness"] = '"64"'
            if "sec-ch-ua-model" not in h:
                h["sec-ch-ua-model"] = '""'
            if "sec-ch-ua-platform-version" not in h:
                h["sec-ch-ua-platform-version"] = (
                    '"14.5.0"' if "Macintosh" in ua else '"19.0.0"'
                )

    def _json_headers(self, referer: str = "", *, full_hints: bool = False) -> dict:
        """auth.openai.com API headers — align 25日/8-2 成功 HAR（SG/JP/KR）.

        full_hints=False（默认）：仅基础三件套 CH——8-2 validate/create_account
        实测不带 arch/bitness/full-version-list；导航类（callback）走完整 CH。

        零额外 RTT：只补浏览器同款头，不 sleep、不 humanize。
        关键：validate / create_account 均带 x-access-flow-invocation-id。
        """
        from .humanize import accept_language_header

        h = dict(C.COMMON_HEADERS)
        # 25日 HAR：validate/create 不带 oai-device-id / oai-language header（靠 cookie oai-did）
        # TOKENREFRESH_OAI_DEVICE_HEADER=1 时恢复旧行为多带头
        if (os.environ.get("TOKENREFRESH_OAI_DEVICE_HEADER") or "").strip().lower() in (
            "1", "true", "yes", "on",
        ):
            h["oai-device-id"] = self.device_id
        if referer:
            h["referer"] = referer
        if self.fingerprint_profile:
            self._apply_client_hints(h, extended=full_hints)
            lang = self.fingerprint_profile.get("language") or "en-US"
            al = str(self.fingerprint_profile.get("accept_language") or "").strip()
            langs = self.fingerprint_profile.get("languages") or ""
            if al:
                h["accept-language"] = al
            else:
                # languages may be a list (navigator); only pass str AL to helper
                lang_s = langs if isinstance(langs, str) else ""
                h["accept-language"] = accept_language_header(lang, lang_s)
            if (os.environ.get("TOKENREFRESH_OAI_DEVICE_HEADER") or "").strip().lower() in (
                "1", "true", "yes", "on",
            ):
                h["oai-language"] = lang
        # 25日真人 HAR：validate/create 每请求一个 UUID（零成本对齐）
        h["x-access-flow-invocation-id"] = str(uuid.uuid4())
        # Datadog APM — 15号 HAR: traceparent 00-0000…{16 zero}{16 hex}-{16 hex}-01
        # x-datadog-trace-id / parent-id are decimal; traceparent span is hex of parent
        parent_id = random.getrandbits(64)
        trace_id = random.getrandbits(64)
        h["traceparent"] = (
            f"00-0000000000000000{format(trace_id, '016x')}-"
            f"{format(parent_id, '016x')}-01"
        )
        h["tracestate"] = "dd=s:1;o:rum"
        h["x-datadog-origin"] = "rum"
        h["x-datadog-parent-id"] = str(parent_id)
        h["x-datadog-sampling-priority"] = "1"
        h["x-datadog-trace-id"] = str(trace_id)
        # JP-2/6/7 HAR: priority: u=1, i
        h["priority"] = random.choice(["u=1, i", "u=1, i", "u=1"])
        # CORS-ish fetch metadata (real create_account)
        h.setdefault("sec-fetch-dest", "empty")
        h.setdefault("sec-fetch-mode", "cors")
        h.setdefault("sec-fetch-site", "same-origin")
        # ~35% requests use extended Client Hints (JP-2/KR-1); rest basic 3-pack
        if not full_hints and random.random() < 0.35:
            self._apply_client_hints(h, extended=True)
        return h

    def _navigate_headers(self, referer: str = "") -> dict:
        """Document navigation headers (chatgpt.com callback / warm / authorize).

        Keep this close to the pre-ClientHints path that ran bulk thousands:
        UA + Accept-Language + basic sec-ch-ua only. Dumping full CH set
        (arch/bitness/full-version-list) on every document GET correlated with
        chatgpt.com callback HTTP 503 under concurrency — OAuth code never
        exchanged, workers then hung until stream TIMEOUT.
        Full Client Hints stay on ``_json_headers`` (auth.openai.com API).
        """
        from .humanize import accept_language_header

        h = dict(C.NAVIGATE_HEADERS)
        if referer:
            h["referer"] = referer
        fp = self.fingerprint_profile or {}
        if fp:
            if fp.get("user_agent"):
                h["user-agent"] = fp["user_agent"]
            # Basic CH only — matches older bulk path + sec-ch-ua consistency
            if fp.get("sec_ch_ua"):
                h["sec-ch-ua"] = fp["sec_ch_ua"]
            h["sec-ch-ua-mobile"] = fp.get("sec_ch_ua_mobile") or "?0"
            if fp.get("sec_ch_ua_platform"):
                h["sec-ch-ua-platform"] = fp["sec_ch_ua_platform"]
            lang = fp.get("language") or "en-US"
            al = str(fp.get("accept_language") or "").strip()
            langs = fp.get("languages") or ""
            if al:
                h["accept-language"] = al
            else:
                lang_s = langs if isinstance(langs, str) else ""
                h["accept-language"] = accept_language_header(lang, lang_s)
        h.setdefault("sec-fetch-dest", "document")
        h.setdefault("sec-fetch-mode", "navigate")
        h.setdefault("upgrade-insecure-requests", "1")
        return h
