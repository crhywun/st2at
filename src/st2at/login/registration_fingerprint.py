"""Explicit registration browser profiles backed by native curl targets."""

from __future__ import annotations

import hashlib
from typing import Any


CHROME_150_FULL_VERSION = "150.0.7871.127"

# curl-impersonate has a verified Chrome 150 target in the deployed build.
REGISTRATION_TLS_CHROME_MAJOR = 150

# Both platforms share one TLS target; only the UA/Client-Hint identity differs.
REGISTRATION_PLATFORMS = ("Windows", "macOS")


def registration_platform(value: Any = "Windows") -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise ValueError("注册平台只支持 Windows 或 macOS")
    candidate = value.strip().lower()
    for known in REGISTRATION_PLATFORMS:
        if candidate == known.lower():
            return known
    raise ValueError("注册平台只支持 Windows 或 macOS")


SIGNUP_PROFILES = ("legacy", "har_parity")


def registration_signup_profile(value: Any = "legacy") -> str:
    if value in (None, ""):
        return "legacy"
    if isinstance(value, bool) or not isinstance(value, str):
        raise ValueError("signup_profile 只支持 legacy 或 har_parity")
    candidate = value.strip().lower()
    if candidate not in SIGNUP_PROFILES:
        raise ValueError("signup_profile 只支持 legacy 或 har_parity")
    return candidate


def signup_profile_overlay(value: Any, *, region: Any) -> dict[str, Any]:
    """Fingerprint overlay for one named signup identity.

    ``legacy`` keeps the deployed JP overlay (Windows, en-US).  ``har_parity``
    reproduces the identity shared by both trial-eligible signup captures:
    macOS, ja-JP navigator language, the ``ja,en-US;q=0.9,en;q=0.8`` header and
    Tokyo's -540 minute offset, held for the whole signup sequence.
    """
    name = registration_signup_profile(value)
    if name == "legacy":
        return {}
    if str(region or "").strip().upper() != "JP":
        raise ValueError("har_parity 画像只有 JP 注册地区有对照抓包")
    language = "ja-JP"
    return {
        "platform": "macOS",
        "language": language,
        "navigator_language": language,
        "locale": language,
        "languages_list": [language],
        "languages": [language],
        "accept_language": "ja,en-US;q=0.9,en;q=0.8",
        "timezone": "Asia/Tokyo",
        "timezone_offset_minutes": -540,
    }


def registration_chrome_major(value: Any = 150) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("chrome_major 目前只支持 150")
    try:
        major = int(value)
    except (TypeError, ValueError):
        raise ValueError("chrome_major 目前只支持 150") from None
    if major != 150 or str(value).strip() != "150":
        raise ValueError("chrome_major 目前只支持 150")
    return major


def require_native_chrome(major: int) -> None:
    major = registration_chrome_major(major)
    from curl_cffi import Curl

    handle = Curl()
    try:
        if (
            handle.impersonate(
                f"chrome{REGISTRATION_TLS_CHROME_MAJOR}", default_headers=False
            )
            != 0
        ):
            raise RuntimeError("原生 chrome150 不可用，需要 curl_cffi 0.16.3")
    finally:
        handle.close()


def apply_registration_chrome_profile(
    profile: dict[str, Any], major: int, platform: Any = "Windows"
) -> None:
    """Keep locale/device state while replacing the complete browser identity."""
    major = registration_chrome_major(major)
    platform = registration_platform(platform)
    full = CHROME_150_FULL_VERSION
    is_mac = platform == "macOS"
    if is_mac:
        # The trial-eligible signup captures ran on an Intel Mac, so the arch
        # hint stays x86 to match the reported UA.
        user_agent = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        )
    else:
        user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        )
    # Brand ordering and version come from curl-impersonate's Chrome 150 fixture.
    profile.update(
        {
            "name": f"{'mac' if is_mac else 'win'}_chrome_{major}",
            "registration_chrome_major": major,
            "registration_platform": platform,
            "brand": "chrome",
            "family": "chrome",
            "platform": platform,
            "chrome_major": major,
            "impersonate": f"chrome{REGISTRATION_TLS_CHROME_MAJOR}",
            "tls_chrome_major": REGISTRATION_TLS_CHROME_MAJOR,
            "tls_profile": "native",
            "user_agent": user_agent,
            "sec_ch_ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
            "sec_ch_ua_full_version": f'"{full}"',
            "sec_ch_ua_full_version_list": (
                f'"Not;A=Brand";v="8.0.0.0", "Chromium";v="{full}", '
                f'"Google Chrome";v="{full}"'
            ),
            "sec_ch_ua_mobile": "?0",
            "sec_ch_ua_platform": f'"{platform}"',
            "sec_ch_ua_platform_version": '"15.5.0"' if is_mac else '"19.0.0"',
            "sec_ch_ua_arch": '"x86"',
            "sec_ch_ua_bitness": '"64"',
            "sec_ch_ua_model": '""',
        }
    )


# Keep these tables byte-identical with tosub2/upstream/tls-transport.mjs.
_CHROME_FULL_VERSIONS = {
    150: [
        "150.0.7871.41",
        "150.0.7871.56",
        "150.0.7871.69",
        "150.0.7871.91",
        "150.0.7871.109",
        CHROME_150_FULL_VERSION,
        "150.0.7871.132",
    ],
}
_MAC_OS_VERSIONS = [
    "14.4.0",
    "14.5.0",
    "14.6.1",
    "15.0.0",
    "15.1.0",
    "15.2.0",
    "15.3.1",
    "15.5.0",
    "15.6.0",
]
_WIN_PLATFORM_VERSIONS = ["10.0.0", "13.0.0", "15.0.0", "19.0.0"]
_GREASE_BRANDS = (
    {"brand": "Not;A=Brand", "major": "8", "full": "8.0.0.0"},
    {"brand": "Not:A-Brand", "major": "99", "full": "99.0.0.0"},
    {"brand": "Not A(Brand", "major": "8", "full": "8.0.0.0"},
    {"brand": "Not/A)Brand", "major": "8", "full": "8.0.0.0"},
    {"brand": "Not=A?Brand", "major": "24", "full": "24.0.0.0"},
)
_OTHER_LOCALES = (
    {
        "locale": "en-US",
        "languages": ["en-US", "en"],
        "accept_language": "en-US,en;q=0.9",
        "timezone": "UTC",
        "timezone_offset_minutes": 0,
    },
    {
        "locale": "en-US",
        "languages": ["en-US", "en"],
        "accept_language": "en-US,en;q=0.9",
        "timezone": "America/New_York",
        "timezone_offset_minutes": 300,
    },
    {
        "locale": "en-US",
        "languages": ["en-US", "en"],
        "accept_language": "en-US,en;q=0.8,en;q=0.7",
        "timezone": "America/Los_Angeles",
        "timezone_offset_minutes": 480,
    },
    {
        "locale": "en-GB",
        "languages": ["en-GB", "en"],
        "accept_language": "en-GB,en;q=0.9",
        "timezone": "Europe/London",
        "timezone_offset_minutes": 0,
    },
)


class _SeededRng:
    def __init__(self, seed: str):
        self.pool = hashlib.sha256(str(seed).encode("utf-8")).digest()
        self.offset = 0

    def next_byte(self) -> int:
        if self.offset >= len(self.pool):
            self.pool = hashlib.sha256(self.pool).digest()
            self.offset = 0
        value = self.pool[self.offset]
        self.offset += 1
        return value

    def pick(self, items):
        return items[self.next_byte() % len(items)]


def device_id_from_seed(seed: str) -> str:
    raw = bytearray(hashlib.sha256(f"oai-did:{seed}".encode("utf-8")).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x50
    raw[8] = (raw[8] & 0x3F) | 0x80
    hex_value = raw.hex()
    return f"{hex_value[:8]}-{hex_value[8:12]}-{hex_value[12:16]}-{hex_value[16:20]}-{hex_value[20:]}"


def seeded_chrome_identity(
    *,
    seed: str,
    region: str = "JP",
    signup_profile: str = "",
    chrome_major: int = 150,
) -> dict[str, Any]:
    """Same chrome150 / JP-stable / seed-randomized CH identity as toSub2 rebind."""
    major = registration_chrome_major(chrome_major)
    region = str(region or "").strip().upper()
    profile_name = registration_signup_profile(
        signup_profile or ("har_parity" if region == "JP" else "legacy")
    )
    rng = _SeededRng(seed)
    jp_stable = region == "JP" or profile_name == "har_parity"
    overlay = signup_profile_overlay("har_parity", region="JP") if jp_stable else {}
    uses_macos = bool(overlay) or (not overlay and rng.pick((True, False)))
    locale = overlay or rng.pick(_OTHER_LOCALES)
    os_version = rng.pick(_MAC_OS_VERSIONS) if uses_macos else "10.0"
    platform_version = os_version if uses_macos else rng.pick(_WIN_PLATFORM_VERSIONS)
    full_version = rng.pick(_CHROME_FULL_VERSIONS.get(major) or [f"{major}.0.0.0"])
    grease = rng.pick(_GREASE_BRANDS)
    chrome = {"brand": "Google Chrome", "major": str(major), "full": full_version}
    chromium = {"brand": "Chromium", "major": str(major), "full": full_version}
    order = rng.pick(
        (
            (grease, chromium, chrome),
            (grease, chrome, chromium),
            (chrome, chromium, grease),
        )
    )
    arch = rng.pick(("x86", "arm")) if uses_macos else "x86"
    platform = "macOS" if uses_macos else "Windows"
    platform_token = (
        "Macintosh; Intel Mac OS X 10_15_7"
        if uses_macos
        else "Windows NT 10.0; Win64; x64"
    )
    language = str(locale.get("locale") or locale.get("language") or "en-US")
    languages = list(
        locale.get("languages") or locale.get("languages_list") or [language]
    )
    return {
        "signup_profile": profile_name,
        "chrome_major": major,
        "platform_name": platform,
        "user_agent": (
            f"Mozilla/5.0 ({platform_token}) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": ", ".join(
            f'"{item["brand"]}";v="{item["major"]}"' for item in order
        ),
        "sec_ch_ua_full_version": f'"{full_version}"',
        "sec_ch_ua_full_version_list": ", ".join(
            f'"{item["brand"]}";v="{item["full"]}"' for item in order
        ),
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": f'"{platform}"',
        "sec_ch_ua_platform_version": f'"{platform_version}"',
        "sec_ch_ua_arch": f'"{arch}"',
        "sec_ch_ua_bitness": '"64"',
        "sec_ch_ua_model": '""',
        "locale": language,
        "languages": languages,
        "accept_language": str(locale.get("accept_language") or "en-US,en;q=0.9"),
        "timezone": str(locale.get("timezone") or "UTC"),
        "timezone_offset_minutes": int(locale.get("timezone_offset_minutes") or 0),
        "device_id": device_id_from_seed(seed),
    }


def apply_seeded_chrome_identity(
    profile: dict[str, Any], identity: dict[str, Any]
) -> None:
    platform = identity["platform_name"]
    major = identity["chrome_major"]
    language = identity["locale"]
    profile.update(
        {
            "name": f"{'mac' if platform == 'macOS' else 'win'}_chrome_{major}_seeded",
            "registration_chrome_major": major,
            "registration_platform": platform,
            "signup_profile": identity["signup_profile"],
            "brand": "chrome",
            "family": "chrome",
            "platform": platform,
            "chrome_major": major,
            "impersonate": f"chrome{REGISTRATION_TLS_CHROME_MAJOR}",
            "tls_chrome_major": REGISTRATION_TLS_CHROME_MAJOR,
            "tls_profile": "native",
            "user_agent": identity["user_agent"],
            "sec_ch_ua": identity["sec_ch_ua"],
            "sec_ch_ua_full_version": identity["sec_ch_ua_full_version"],
            "sec_ch_ua_full_version_list": identity["sec_ch_ua_full_version_list"],
            "sec_ch_ua_mobile": identity["sec_ch_ua_mobile"],
            "sec_ch_ua_platform": identity["sec_ch_ua_platform"],
            "sec_ch_ua_platform_version": identity["sec_ch_ua_platform_version"],
            "sec_ch_ua_arch": identity["sec_ch_ua_arch"],
            "sec_ch_ua_bitness": identity["sec_ch_ua_bitness"],
            "sec_ch_ua_model": identity["sec_ch_ua_model"],
            "language": language,
            "navigator_language": language,
            "locale": language,
            "languages_list": list(identity["languages"]),
            "languages": list(identity["languages"]),
            "accept_language": identity["accept_language"],
            "timezone": identity["timezone"],
            "timezone_offset_minutes": identity["timezone_offset_minutes"],
            "device_id": identity["device_id"],
        }
    )
