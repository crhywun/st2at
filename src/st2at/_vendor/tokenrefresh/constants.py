"""常量 — 所有 URL、Client ID、Scope 集中管理"""
import os

AUTH_BASE = "https://auth.openai.com"
CODEX_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_OAUTH_REDIRECT_URI = "http://localhost:1455/auth/callback"
CODEX_OAUTH_AUDIENCE = "https://api.openai.com/v1"
CODEX_OAUTH_SCOPE = "openid email profile offline_access api.connectors.read api.connectors.invoke"
AUTH0_CLIENT = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
WHAM_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"

# curl_cffi 0.15 最高稳定档 chrome146（BrowserType 无 chrome147）；UA 必须与 TLS 同代
# 真机 HAR 已到 147，但伪造 147UA+146TLS 更差 → 诚实对齐 146
CHROME_MAJOR = 146
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    f"(KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36"
)
# 真机顺序：Google Chrome 在前；品牌串 Not.A/Brand（非 Not;A=Brand）
SEC_CH_UA = (
    f'"Google Chrome";v="{CHROME_MAJOR}", "Not.A/Brand";v="8", '
    f'"Chromium";v="{CHROME_MAJOR}"'
)

COMMON_HEADERS = {
    "accept": "application/json",
    "content-type": "application/json",
    "user-agent": USER_AGENT,
    "sec-ch-ua": SEC_CH_UA,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "origin": "https://auth.openai.com",
}
# 8-2 HAR 对齐：跨域导航（authorize/email-verification/callback）均为 cross-site，
# 且浏览器导航必带 sec-fetch-user=?1；原 none 只出现在地址栏直开场景，会被 CF/WAF 降权
NAVIGATE_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "user-agent": USER_AGENT,
    "sec-ch-ua": SEC_CH_UA,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "cross-site",
    "sec-fetch-user": "?1",
}


def _chrome_build(major: int, build: int = 0, patch: int = 0) -> str:
    return f"{major}.0.{build}.{patch}" if build else f"{major}.0.0.0"


# curl_cffi 可稳定模拟的 impersonate → UA major（必须与 TLS 同代，禁止 150UA+edge101）
IMPERSONATE_UA_MAJOR: dict[str, int] = {
    "chrome": 146,  # curl_cffi 0.15 别名（实测 = chrome146，非 150！）
    "chrome146": 146,
    "chrome142": 142,
    "chrome136": 136,
    "chrome133": 133,
    "chrome131": 131,
    "chrome124": 124,
    "chrome123": 123,
    "chrome120": 120,
    "chrome119": 119,
    "chrome116": 116,
    "chrome110": 110,
    "edge101": 101,
    "safari17_0": 17,
    "safari15_5": 15,
    # formal-frame / Eda Firefox pool (major = Gecko RV, not Chrome)
    "firefox144": 144,
    "firefox147": 147,
    "firefox135": 135,
    "firefox133": 133,
}


def impersonate_for_ua(*, major: int, brand: str = "chrome") -> str:
    """Bind curl_cffi TLS persona to HTTP UA major/brand (never random-mismatch).

    curl_cffi 0.15.x only exposes a finite set of impersonate targets; for
    Chrome majors newer than the highest named profile, map to the closest
    supported persona (chrome / chrome131).
    """
    b = (brand or "chrome").lower()
    if b == "edge":
        # 仅 edge101 可用 → 调用方必须把 UA 钳到 101（见 _chrome_profile）
        return "edge101"
    if b == "safari":
        return "safari17_0" if major >= 17 else "safari15_5"
    # Chrome / Chromium UA → nearest TLS profile（major 会被钳到 impersonate 档）
    # 必须与 curl_cffi 真实档位同代（0.15 支持到 chrome146；无 chrome150！）
    if major >= 146:
        return "chrome146"
    if major >= 142:
        return "chrome142"
    if major >= 136:
        return "chrome136"
    # chrome133 在部分 curl_cffi/运行时会 ImpersonateError，并入 131
    if major >= 131:
        return "chrome131"
    if major >= 124:
        return "chrome124"
    if major >= 123:
        return "chrome123"
    if major >= 120:
        return "chrome120"
    if major >= 119:
        return "chrome119"
    if major >= 116:
        return "chrome116"
    if major >= 110:
        return "chrome110"
    return "chrome110"


def ua_major_for_impersonate(impersonate: str) -> int:
    """TLS persona → must-match Chrome/Edge major in User-Agent / Client Hints."""
    return int(IMPERSONATE_UA_MAJOR.get((impersonate or "").strip(), 131))


def _chrome_profile(
    major: int,
    *,
    brand: str = "chrome",
    chromium_build: int = 7871,
    chromium_patch: int = 115,
    brand_build: int = 0,
    brand_patch: int = 0,
    platform: str = "Windows",
    platform_version: str = "19.0.0",
    screen: str = "1920x1080",
    idx: int = 0,
) -> dict:
    """UA + full Client Hints + bound TLS impersonate + fixed screen.

    关键：先选 impersonate，再把 UA major **钳到** TLS 档，避免 Chrome/150 + edge101。
    """
    is_mac = platform.lower() in ("macos", "mac os", "mac")
    brand_l = (brand or "chrome").lower()
    is_edge = brand_l == "edge"
    # 1) TLS 目标
    imp = impersonate_for_ua(major=major, brand=brand_l)
    # 2) UA major 必须与 TLS 一致
    major = ua_major_for_impersonate(imp)
    if is_mac:
        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        )
        plat = "macOS"
    else:
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        )
        if is_edge:
            ua += f" Edg/{major}.0.0.0"
        plat = "Windows"

    # JP fingerprint HARs:
    #  A) "Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"
    #  B) "Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"
    # TLS major stays curl_cffi-aligned; rotate brand order/string only.
    style_b = (int(idx) % 3 == 1)
    if style_b:
        not_brand = '"Not/A)Brand";v="99"'
        not_brand_full = '"Not/A)Brand";v="10.0.1.4"'
    else:
        not_brand = '"Not.A/Brand";v="8"'
        not_brand_full = '"Not.A/Brand";v="8.0.0.0"'
    if is_edge:
        sec = (
            f'"Microsoft Edge";v="{major}", {not_brand}, '
            f'"Chromium";v="{major}"'
        )
        full_ver = (
            f'"Microsoft Edge";v="{_chrome_build(major, brand_build or 4078, brand_patch or 65)}", '
            f'{not_brand_full}, '
            f'"Chromium";v="{_chrome_build(major, chromium_build, chromium_patch)}"'
        )
        name = f"{'mac' if is_mac else 'win'}_edge_{major}_{idx:03d}"
    else:
        if style_b:
            sec = (
                f'"Chromium";v="{major}", "Google Chrome";v="{major}", '
                f"{not_brand}"
            )
            full_ver = (
                f'"Chromium";v="{_chrome_build(major, chromium_build, chromium_patch)}", '
                f'"Google Chrome";v="{_chrome_build(major, chromium_build, chromium_patch)}", '
                f"{not_brand_full}"
            )
        else:
            sec = (
                f'"Google Chrome";v="{major}", {not_brand}, '
                f'"Chromium";v="{major}"'
            )
            full_ver = (
                f'"Google Chrome";v="{_chrome_build(major, chromium_build, chromium_patch)}", '
                f"{not_brand_full}, "
                f'"Chromium";v="{_chrome_build(major, chromium_build, chromium_patch)}"'
            )
        name = f"{'mac' if is_mac else 'win'}_chrome_{major}_{idx:03d}"

    return {
        "name": name,
        "user_agent": ua,
        "sec_ch_ua": sec,
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": f'"{plat}"',
        "sec_ch_ua_platform_version": f'"{platform_version}"',
        "sec_ch_ua_arch": '"x86"',
        "sec_ch_ua_bitness": '"64"',
        "sec_ch_ua_model": '""',
        "sec_ch_ua_full_version": f'"{_chrome_build(major, brand_build or chromium_build, brand_patch or chromium_patch)}"',
        "sec_ch_ua_full_version_list": full_ver,
        "screen": screen,
        "impersonate": imp,
        "chrome_major": major,
        "brand": brand_l,
        "platform": plat,
    }


# 屏幕池（组合轴之一；可增，不手写完整 persona）
SCREEN_RESOLUTIONS = [
    "1920x1080", "1366x768", "2560x1440", "1536x864", "1440x900", "1280x720",
    "1680x1050", "1600x900", "2560x1600", "2880x1800", "1920x1200", "1280x800",
    "3440x1440", "2048x1152", "1512x982", "1470x956",
    "1800x1169", "1728x1117", "2560x1080", "3840x2160",
    "1280x1024", "1400x1050", "1680x945", "1920x1440", "2048x1280",
    "2256x1504", "2304x1440", "2520x1680", "2736x1824", "3000x2000",
    "3200x1800", "3200x2000", "3360x2100", "3840x1600", "3840x2400",
    "4096x2160", "5120x1440", "5120x2160", "1360x768", "1600x1024",
    "1792x1120", "1856x1392", "2048x1536", "2220x1080", "2340x1080",
    "2400x1080", "2400x1350", "2538x1080",
]

# 仅 curl_cffi 可 TLS 对齐的 Chrome major（144/150 无档，不进池）
# 权重偏新：curl_cffi 顶档 146 为主（真机 147 但 TLS 无 147 档，不伪造 major 错配）
_FP_CHROME_MAJORS: tuple[int, ...] = (
    146, 146, 146, 146, 146, 146, 142, 142, 136, 136, 131, 131, 124, 123, 120, 119, 116,
)
_FP_WIN_PV: tuple[str, ...] = (
    "10.0.0", "10.0.19045", "13.0.0", "14.0.0", "15.0.0", "16.0.0", "19.0.0", "19.0.1",
)
_FP_MAC_PV: tuple[str, ...] = (
    "13.0.0", "13.6.0", "14.0.0", "14.5.0", "14.6.0", "15.0.0", "15.1.0", "15.2.0",
)

# 锚点 build（HAR / 公开版本）；下方规则展开为大量 (build, patch) 变体
_FP_CHROME_BUILD_ANCHORS: dict[int, list[tuple[int, int]]] = {
    110: [(5481, 77), (5481, 178), (5481, 179)],
    116: [(5845, 96), (5845, 187), (5845, 190)],
    119: [(6045, 105), (6045, 159), (6045, 200)],
    120: [(6099, 62), (6099, 109), (6099, 110), (6099, 130)],
    123: [(6312, 58), (6312, 86), (6312, 106), (6312, 122)],
    124: [(6367, 60), (6367, 78), (6367, 91), (6367, 118)],
    131: [(6778, 69), (6778, 85), (6778, 86), (6778, 99)],
    136: [(7103, 34), (7103, 45), (7103, 92), (7103, 93)],
    142: [(7455, 80), (7455, 100), (7460, 90)],  # 插值邻域
    146: [(7663, 80), (7663, 100), (7670, 95)],  # 插值邻域
}
_FP_EDGE_BUILD_ANCHORS: list[tuple[int, int]] = [
    (1210, 47), (1210, 53), (1210, 61), (1210, 70), (1210, 88),
]

# 每 major 展开多少 build 变体（规则生成，不手写全表）
_FP_BUILDS_PER_MAJOR = 96
_FP_EDGE_BUILDS = 48

# Edge 在组合空间中的占比约 4%（老 TLS，不宜过多）
_FP_EDGE_SHARE = 0.04


def _expand_build_variants(
    anchors: list[tuple[int, int]], n: int, *, salt: int = 0
) -> list[tuple[int, int]]:
    """从少量锚点规则展开 n 个 (build, patch)，落在同 major 真实量级附近。"""
    if not anchors:
        anchors = [(7000, 100)]
    out: list[tuple[int, int]] = []
    for i in range(n):
        ab, ap = anchors[i % len(anchors)]
        # 小幅抖动 build（同代内），patch 大范围轮换
        b = ab + ((i * 3 + salt * 7) % 11) - 5
        p = 10 + (ap + i * 13 + salt * 17) % 220
        if b < 100:
            b = ab
        out.append((b, p))
    return out


def _fp_chrome_builds(major: int) -> list[tuple[int, int]]:
    anchors = _FP_CHROME_BUILD_ANCHORS.get(major)
    if not anchors:
        # 线性邻域兜底
        base = 7559 + (major - 144) * 52
        anchors = [(base, 100), (base + 5, 80), (base - 3, 120)]
    return _expand_build_variants(anchors, _FP_BUILDS_PER_MAJOR, salt=major)


def _fp_edge_builds() -> list[tuple[int, int]]:
    return _expand_build_variants(_FP_EDGE_BUILD_ANCHORS, _FP_EDGE_BUILDS, salt=101)


# 预计算各轴（启动一次，内存只存轴，不存几十万完整 dict）
_FP_CHROME_BUILD_TABLE: dict[int, list[tuple[int, int]]] = {
    m: _fp_chrome_builds(m) for m in sorted(set(_FP_CHROME_MAJORS))
}
_FP_EDGE_BUILD_TABLE: list[tuple[int, int]] = _fp_edge_builds()

_FP_N_MAJORS = len(_FP_CHROME_MAJORS)
_FP_N_BUILDS = _FP_BUILDS_PER_MAJOR
_FP_N_SCREENS = len(SCREEN_RESOLUTIONS)
_FP_N_WIN_PV = len(_FP_WIN_PV)
_FP_N_MAC_PV = len(_FP_MAC_PV)

# Chrome 组合：major轴 × build × screen × (win_pv 全量 + mac_pv 全量)
_FP_CHROME_WIN = _FP_N_MAJORS * _FP_N_BUILDS * _FP_N_SCREENS * _FP_N_WIN_PV
_FP_CHROME_MAC = _FP_N_MAJORS * _FP_N_BUILDS * _FP_N_SCREENS * _FP_N_MAC_PV
_FP_CHROME_SPACE = _FP_CHROME_WIN + _FP_CHROME_MAC
_FP_EDGE_WIN = _FP_EDGE_BUILDS * _FP_N_SCREENS * _FP_N_WIN_PV
_FP_EDGE_MAC = _FP_EDGE_BUILDS * _FP_N_SCREENS * _FP_N_MAC_PV
_FP_EDGE_SPACE = _FP_EDGE_WIN + _FP_EDGE_MAC
# 逻辑空间：把 edge 嵌进统一 index（约 4% 落在 edge 区）
_FP_EDGE_ZONE = max(1, int(_FP_CHROME_SPACE * _FP_EDGE_SHARE / max(1e-9, 1.0 - _FP_EDGE_SHARE)))
FINGERPRINT_POOL_SIZE = int(_FP_CHROME_SPACE + _FP_EDGE_ZONE)


def fingerprint_at(index: int) -> dict:
    """按规则从组合空间解码第 index 套 persona（O(1)，不查巨表）。

    同 index → 完全相同 UA/CH/TLS/screen。调用方用 hash(seed)%POOL_SIZE 取 index。
    """
    n = FINGERPRINT_POOL_SIZE
    if n <= 0:
        raise RuntimeError("fingerprint space empty")
    idx = int(index) % n

    # 高段映射到 edge 子空间（稀疏）
    if idx >= _FP_CHROME_SPACE:
        eidx = (idx - _FP_CHROME_SPACE) % _FP_EDGE_SPACE
        if eidx < _FP_EDGE_WIN:
            rest = eidx
            bi = rest % _FP_EDGE_BUILDS
            rest //= _FP_EDGE_BUILDS
            si = rest % _FP_N_SCREENS
            rest //= _FP_N_SCREENS
            pvi = rest % _FP_N_WIN_PV
            cb, cp = _FP_EDGE_BUILD_TABLE[bi]
            eb, ep = _FP_EDGE_BUILD_TABLE[(bi + 3) % _FP_EDGE_BUILDS]
            return _chrome_profile(
                101,
                brand="edge",
                chromium_build=cb,
                chromium_patch=cp,
                brand_build=eb,
                brand_patch=ep,
                platform="Windows",
                platform_version=_FP_WIN_PV[pvi],
                screen=SCREEN_RESOLUTIONS[si],
                idx=idx,
            )
        rest = eidx - _FP_EDGE_WIN
        bi = rest % _FP_EDGE_BUILDS
        rest //= _FP_EDGE_BUILDS
        si = rest % _FP_N_SCREENS
        rest //= _FP_N_SCREENS
        pvi = rest % _FP_N_MAC_PV
        cb, cp = _FP_EDGE_BUILD_TABLE[bi]
        eb, ep = _FP_EDGE_BUILD_TABLE[(bi + 5) % _FP_EDGE_BUILDS]
        return _chrome_profile(
            101,
            brand="edge",
            chromium_build=cb,
            chromium_patch=cp,
            brand_build=eb,
            brand_patch=ep,
            platform="macOS",
            platform_version=_FP_MAC_PV[pvi],
            screen=SCREEN_RESOLUTIONS[si],
            idx=idx,
        )

    # Chrome 子空间
    if idx < _FP_CHROME_WIN:
        rest = idx
        platform = "Windows"
        pv_list = _FP_WIN_PV
        n_pv = _FP_N_WIN_PV
    else:
        rest = idx - _FP_CHROME_WIN
        platform = "macOS"
        pv_list = _FP_MAC_PV
        n_pv = _FP_N_MAC_PV

    mi = rest % _FP_N_MAJORS
    rest //= _FP_N_MAJORS
    bi = rest % _FP_N_BUILDS
    rest //= _FP_N_BUILDS
    si = rest % _FP_N_SCREENS
    rest //= _FP_N_SCREENS
    pvi = rest % n_pv

    major = _FP_CHROME_MAJORS[mi]
    builds = _FP_CHROME_BUILD_TABLE[major]
    cb, cp = builds[bi % len(builds)]
    return _chrome_profile(
        major,
        brand="chrome",
        chromium_build=cb,
        chromium_patch=cp,
        platform=platform,
        platform_version=pv_list[pvi],
        screen=SCREEN_RESOLUTIONS[si],
        idx=idx,
    )


def pick_fingerprint_by_seed(seed_text: str = "") -> dict:
    """seed → 稳定 persona；空 seed → 真随机 index。"""
    import hashlib
    import random as _random

    if seed_text:
        h = hashlib.sha256(seed_text.encode("utf-8", errors="replace")).hexdigest()
        idx = int(h[:16], 16) % FINGERPRINT_POOL_SIZE
    else:
        idx = _random.randrange(FINGERPRINT_POOL_SIZE)
    fp = fingerprint_at(idx)
    fp["profile_index"] = idx
    return fp


# 兼容旧代码：不再物化几十万 dict；按需访问会很慢，仅保留空壳长度信息
# 真正取指纹请用 pick_fingerprint_by_seed / fingerprint_at
FINGERPRINT_PROFILES: list = []  # deprecated materialization; size via FINGERPRINT_POOL_SIZE
# 随机语言（全球）
LANGUAGES = ["en-US", "en-GB", "en-CA", "en-AU", "ja-JP", "ko-KR", "de-DE", "fr-FR", "es-ES", "es-MX", "pt-BR", "zh-CN"]
# US 代理：语言 × 时区独立组合（见 session._apply_diverse_locale），覆盖多州/多时区
# 语言侧重 en-US，夹杂西语/双语（真实美区常见），Accept-Language q 值也拉开
US_LANGS = [
    ("en-US", "en-US,en;q=0.9"),
    ("en-US", "en-US,en;q=0.8"),
    ("en-US", "en-US,en;q=0.9,es;q=0.5"),
    ("en-US", "en-US,en;q=0.9,es-US;q=0.6,es;q=0.4"),
    ("en-US", "en-US,es-US;q=0.8,en;q=0.7"),
    ("en-US", "en-US,en;q=0.9,zh-CN;q=0.4"),
    ("en-US", "en-US,en;q=0.9,ko;q=0.4"),
    ("en-US", "en-US,en;q=0.9,vi;q=0.4"),
    ("es-US", "es-US,es;q=0.9,en-US;q=0.8,en;q=0.7"),
    ("es-MX", "es-MX,es;q=0.9,en-US;q=0.7"),
    ("en-US", "en-US,en;q=0.95"),
    ("en-US", "en-US,en-GB;q=0.7,en;q=0.6"),
]
# 美国本土 + 属地：东部/中部/山地/太平洋/阿拉斯加/夏威夷等
US_TIMEZONES = [
    # Eastern
    "America/New_York",
    "America/Detroit",
    "America/Kentucky/Louisville",
    "America/Kentucky/Monticello",
    "America/Indiana/Indianapolis",
    "America/Indiana/Vincennes",
    "America/Indiana/Winamac",
    "America/Indiana/Marengo",
    "America/Indiana/Petersburg",
    "America/Indiana/Vevay",
    "America/Indiana/Tell_City",
    "America/Indiana/Knox",
    # Central
    "America/Chicago",
    "America/Menominee",
    "America/North_Dakota/Center",
    "America/North_Dakota/New_Salem",
    "America/North_Dakota/Beulah",
    # Mountain
    "America/Denver",
    "America/Boise",
    "America/Phoenix",  # AZ no DST
    "America/Shiprock",
    # Pacific
    "America/Los_Angeles",
    # Alaska / Hawaii / territories
    "America/Anchorage",
    "America/Juneau",
    "America/Sitka",
    "America/Metlakatla",
    "America/Yakutat",
    "America/Nome",
    "America/Adak",
    "Pacific/Honolulu",
    "America/Puerto_Rico",
    "America/St_Thomas",
    "Pacific/Guam",
    "Pacific/Saipan",
]
# 兼容旧 (lang, langs, tz) 三元组表：供测试/回退
US_LOCALES = [
    (lang, langs, tz)
    for (lang, langs) in US_LANGS
    for tz in (
        "America/New_York",
        "America/Chicago",
        "America/Denver",
        "America/Los_Angeles",
        "America/Phoenix",
        "America/Indiana/Indianapolis",
        "America/Anchorage",
        "Pacific/Honolulu",
    )
]
# JP 代理：日区语言+时区池（不要误用 US 指纹）
JP_LOCALES = [
    ("ja-JP", "ja,en-US;q=0.9,en;q=0.8", "Asia/Tokyo"),
    ("ja-JP", "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7", "Asia/Tokyo"),
    ("ja-JP", "ja,en;q=0.8", "Asia/Tokyo"),
    ("en-US", "en-US,en;q=0.9,ja;q=0.8", "Asia/Tokyo"),  # 部分用户用英文 UI
    ("ja-JP", "ja-JP,ja;q=0.9", "Asia/Osaka"),
]
GB_LOCALES = [
    ("en-GB", "en-GB,en;q=0.9", "Europe/London"),
    ("en-GB", "en-GB,en-US;q=0.8,en;q=0.7", "Europe/London"),
    ("en-GB", "en-GB,en;q=0.9", "Europe/Dublin"),
]
CA_LOCALES = [
    ("en-CA", "en-CA,en;q=0.9", "America/Toronto"),
    ("en-CA", "en-CA,en-US;q=0.9,en;q=0.8", "America/Vancouver"),
    ("fr-CA", "fr-CA,fr;q=0.9,en-CA;q=0.8", "America/Montreal"),
    ("en-CA", "en-CA,en;q=0.9", "America/Edmonton"),
]
FR_LOCALES = [
    ("fr-FR", "fr-FR,fr;q=0.9,en;q=0.8", "Europe/Paris"),
    ("fr-FR", "fr,en-US;q=0.8,en;q=0.7", "Europe/Paris"),
    ("fr-FR", "fr-FR,fr;q=0.9", "Europe/Brussels"),
]
# HK 已禁用：OpenAI unsupported_country_region_territory
SG_LOCALES = [
    ("en-SG", "en-SG,en;q=0.9", "Asia/Singapore"),
    ("en-GB", "en-GB,en;q=0.9,zh;q=0.8", "Asia/Singapore"),
    ("zh-CN", "zh-CN,zh;q=0.9,en;q=0.8", "Asia/Singapore"),
    ("en-US", "en-US,en;q=0.9", "Asia/Singapore"),
]
TW_LOCALES = [
    ("zh-TW", "zh-TW,zh;q=0.9,en;q=0.8", "Asia/Taipei"),
    ("zh-TW", "zh-TW,zh-CN;q=0.8,en;q=0.7", "Asia/Taipei"),
    ("en-US", "en-US,en;q=0.9,zh-TW;q=0.8", "Asia/Taipei"),
]
# multi 池常见区：必须有 locale，禁止随机语言+错时区
DE_LOCALES = [
    ("de-DE", "de-DE,de;q=0.9,en;q=0.8", "Europe/Berlin"),
    ("de-DE", "de,en-US;q=0.8,en;q=0.7", "Europe/Berlin"),
    ("de-DE", "de-DE,de;q=0.9", "Europe/Munich"),
]
CH_LOCALES = [
    ("de-CH", "de-CH,de;q=0.9,en;q=0.8", "Europe/Zurich"),
    ("fr-CH", "fr-CH,fr;q=0.9,en;q=0.8", "Europe/Zurich"),
    ("it-CH", "it-CH,it;q=0.9,en;q=0.8", "Europe/Zurich"),
]
MY_LOCALES = [
    ("en-MY", "en-MY,en;q=0.9", "Asia/Kuala_Lumpur"),
    ("ms-MY", "ms,en;q=0.9", "Asia/Kuala_Lumpur"),
    ("zh-CN", "zh-CN,zh;q=0.9,en;q=0.8", "Asia/Kuala_Lumpur"),
]
# KR 出口必须 ko-KR（原池混 en-US，被 OpenAI 判定语言/IP 错配）
KR_LOCALES = [
    ("ko-KR", "ko-KR,ko;q=0.9,en;q=0.8", "Asia/Seoul"),
    ("ko-KR", "ko,en-US;q=0.8,en;q=0.7", "Asia/Seoul"),
    ("ko-KR", "ko-KR,ko;q=0.8,en;q=0.7", "Asia/Seoul"),
]
VN_LOCALES = [
    ("vi-VN", "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7", "Asia/Ho_Chi_Minh"),
]
# region code -> locale pool name
REGION_LOCALE_POOLS = {
    "US": "US_LOCALES",
    "JP": "JP_LOCALES",
    "GB": "GB_LOCALES",
    "UK": "GB_LOCALES",
    "CA": "CA_LOCALES",
    "FR": "FR_LOCALES",
    # "HK" 故意不收录
    "SG": "SG_LOCALES",
    "TW": "TW_LOCALES",
    "DE": "DE_LOCALES",
    "CH": "CH_LOCALES",
    "MY": "MY_LOCALES",
    "KR": "KR_LOCALES",
    "VN": "VN_LOCALES",
}
# 通用时区池
TIMEZONES = [
    "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
    "America/Toronto", "Europe/London", "Europe/Berlin", "Europe/Paris",
    "Asia/Tokyo", "Asia/Osaka", "Asia/Seoul", "Asia/Singapore", "Asia/Hong_Kong",
    "Asia/Taipei", "Australia/Sydney",
]


def chrome_timezone_offset_min(timezone_name: str = "") -> int:
    """Return Chrome getTimezoneOffset semantics for fixed regional profiles."""
    return {
        "Asia/Ho_Chi_Minh": -420,
        "Asia/Tokyo": -540,
        "Asia/Seoul": -540,
        "America/New_York": 240,
    }.get(str(timezone_name or "").strip(), 240)

CHATGPT_LOGIN_URL = "https://chatgpt.com/auth/login?next=%2F"
CHATGPT_SESSION_URL = "https://chatgpt.com/api/auth/session"
CHATGPT_ACCOUNTS_CHECK_URL = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
CHATGPT_WEB_REFERER = "https://chatgpt.com/"

DEBUG_DIR = os.environ.get("TOKENREFRESH_DEBUG_DIR", "")

# 网络重试
NETWORK_RETRY_ATTEMPTS = int(os.environ.get("TOKENREFRESH_NETWORK_RETRIES", "4"))
NETWORK_RETRY_DELAY = float(os.environ.get("TOKENREFRESH_RETRY_DELAY", "2.0"))
RETRY_STATUS_CODES = {429, 500, 502, 503, 504}

# ChatGPT Web OAuth（对齐浏览器抓包）
CHATGPT_WEB_CLIENT_ID = os.environ.get(
    "TOKENREFRESH_CHATGPT_WEB_CLIENT_ID", "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"
)
CHATGPT_WEB_REDIRECT_URI = "https://chatgpt.com/api/auth/callback/openai"
CHATGPT_WEB_SCOPE = (
    "openid email profile offline_access model.request model.read "
    "organization.read organization.write"
)
# 浏览器抓包: login_or_signup → passwordless OTP
CHATGPT_WEB_SCREEN_HINT = os.environ.get(
    "TOKENREFRESH_CHATGPT_WEB_SCREEN_HINT", "login_or_signup"
)

# Sentinel — versioned sdk path; prefer formal_runtime/sdk_manifest.json (sync script)
SENTINEL_REQ_TIMEOUT = float(os.environ.get("TOKENREFRESH_SENTINEL_TIMEOUT", "20"))


def _load_sentinel_sdk_version_default() -> str:
    env = (os.environ.get("TOKENREFRESH_SENTINEL_SDK_VERSION") or "").strip()
    if env:
        return env
    try:
        from pathlib import Path as _P

        man = _P(__file__).resolve().parent / "formal_runtime" / "sdk_manifest.json"
        if man.is_file():
            import json as _json

            d = _json.loads(man.read_text(encoding="utf-8"))
            v = str((d or {}).get("sdk_version") or "").strip()
            if v:
                return v
    except Exception:
        pass
    return "20260219f9f6"


SENTINEL_SDK_VERSION = _load_sentinel_sdk_version_default()
SENTINEL_SDK_URL_VERSIONED = (
    f"https://sentinel.openai.com/sentinel/{SENTINEL_SDK_VERSION}/sdk.js"
)
# p[5] / 指纹默认 versioned（可用 env 覆盖）
SENTINEL_SDK_URL = os.environ.get(
    "TOKENREFRESH_SENTINEL_SDK_URL",
    SENTINEL_SDK_URL_VERSIONED,
)
# frame 亦可用 versioned；backend-api/frame.html?sv= 仍兼容
SENTINEL_FRAME_REFERER = os.environ.get(
    "TOKENREFRESH_SENTINEL_FRAME_REFERER",
    f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_SDK_VERSION}",
)
SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
# 浏览器在 sentinel/req 前会加载 frame.html + sdk.js；默认预热 1 次/会话（+0.1~0.5s）
# TOKENREFRESH_SENTINEL_WARM=0 关闭（A/B）
SENTINEL_WARM_ASSETS = os.environ.get("TOKENREFRESH_SENTINEL_WARM", "1").strip().lower() in (
    "1", "true", "yes", "on",
)
# t 字段模式：normal=VM 求解；empty / garbage 仅用于对照实验（TOKENREFRESH_T_MODE）
SENTINEL_T_MODE = (os.environ.get("TOKENREFRESH_T_MODE") or "normal").strip().lower()

# Email OTP
EMAIL_OTP_POLL_INTERVAL = float(os.environ.get("TOKENREFRESH_EMAIL_POLL_INTERVAL", "0.5"))
# 前几轮快速轮询（毫秒级邮件 API），之后退回 EMAIL_OTP_POLL_INTERVAL
EMAIL_OTP_POLL_FAST_INTERVAL = float(os.environ.get("TOKENREFRESH_EMAIL_POLL_FAST", "0.2"))
EMAIL_OTP_POLL_FAST_ROUNDS = int(os.environ.get("TOKENREFRESH_EMAIL_POLL_FAST_ROUNDS", "12"))
# 默认 45s：失败快速放弃，避免 1 母号+4 分裂时单号空等 90s 拖垮整轮
# 默认 24s 空等上限（成功码通常 <15s）；收不到码立刻失败腾槽
EMAIL_OTP_POLL_SECONDS = int(os.environ.get("TOKENREFRESH_EMAIL_POLL_SECONDS", "24"))
EMAIL_OTP_VALIDATION_ROUNDS = int(os.environ.get("TOKENREFRESH_EMAIL_VALIDATION_ROUNDS", "1"))
# 真人 resend 节奏：≥30s（原 2s 会在 OTP 失败时形成 resend 风暴 = 强 bot 信号）
EMAIL_RESEND_WAIT_SECONDS = float(os.environ.get("TOKENREFRESH_EMAIL_RESEND_WAIT", "30"))
EMAIL_OTP_MAX_AGE_SECONDS = float(os.environ.get("TOKENREFRESH_EMAIL_MAX_AGE", "300.0"))
EMAIL_OTP_TIME_SKEW = float(os.environ.get("TOKENREFRESH_EMAIL_TIME_SKEW", "30.0"))
# 跳过 chatgpt.com 预热/CSRF，直连 auth authorize。
# 默认关闭：缺少 chatgpt.com 会话 cookie 时 /api/auth/session 常拿不到 accessToken。
# 需要极速可 export TOKENREFRESH_FAST_WEB_LOGIN=1（仍建议 callback 后补 chatgpt.com 访问）。
FAST_WEB_LOGIN = os.environ.get("TOKENREFRESH_FAST_WEB_LOGIN", "0").lower() in (
    "1", "true", "yes",
)

# Hotmail 远程邮件池（outlook.aitokensale.com）— 默认禁用。
# 读 OTP 只走货源 refresh_token + 本地 Graph/Outlook REST。
# 若必须开远程池：MAIL_ALLOW_REMOTE_HOTMAIL_API=1 且配置 HOTMAIL_API_BASE/PASSWORD
def _remote_hotmail_api_allowed() -> bool:
    return (os.environ.get("MAIL_ALLOW_REMOTE_HOTMAIL_API") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


if _remote_hotmail_api_allowed():
    HOTMAIL_API_BASE = os.environ.get("HOTMAIL_API_BASE", "").strip().rstrip("/")
    HOTMAIL_ADMIN_PASSWORD = os.environ.get("HOTMAIL_ADMIN_PASSWORD", "").strip()
else:
    HOTMAIL_API_BASE = ""
    HOTMAIL_ADMIN_PASSWORD = ""

# SMSBower mail API
SMSBOWER_MAIL_API_BASE = os.environ.get("SMSBOWER_MAIL_API_BASE", "https://smsbower.page")
SMSBOWER_MAIL_API_KEY = os.environ.get("SMSBOWER_API_KEY", os.environ.get("TOKENREFRESH_SMSBOWER_API_KEY", ""))
SMSBOWER_MAIL_SERVICE = os.environ.get("SMSBOWER_MAIL_SERVICE", os.environ.get("TOKENREFRESH_SMSBOWER_MAIL_SERVICE", ""))
SMSBOWER_MAIL_DOMAIN = os.environ.get("SMSBOWER_MAIL_DOMAIN", os.environ.get("TOKENREFRESH_SMSBOWER_MAIL_DOMAIN", "gmail.com"))
SMSBOWER_MAIL_ALIAS = os.environ.get("SMSBOWER_MAIL_ALIAS", os.environ.get("TOKENREFRESH_SMSBOWER_MAIL_ALIAS", "1"))

# Phone
PHONE_CHANNEL = "sms"
AUTO_PHONE_RETRIES = int(os.environ.get("TOKENREFRESH_PHONE_RETRIES", "2"))
SMS_POLL_ATTEMPTS = int(os.environ.get("TOKENREFRESH_SMS_POLL_ATTEMPTS", "30"))
