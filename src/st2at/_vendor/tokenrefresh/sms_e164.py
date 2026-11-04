"""Shared E.164 phone normalization for all SMS providers (Getatext / VAK / Smsbower).

Getatext often returns national numbers + country field (e.g. usa + 10 digits).
VAK usually returns international digits (e.g. 4477…) but still needs ``+``.
OpenAI add-phone requires E.164 (``+1…`` / ``+44…``); bare ``+667…`` is invalid.
"""
from __future__ import annotations

import re

# ISO / common names → calling code (no +)
COUNTRY_DIAL: dict[str, str] = {
    "usa": "1",
    "us": "1",
    "united states": "1",
    "united states of america": "1",
    "america": "1",
    "canada": "1",
    "ca": "1",
    "uk": "44",
    "gb": "44",
    "united kingdom": "44",
    "england": "44",
    "au": "61",
    "australia": "61",
    "de": "49",
    "germany": "49",
    "fr": "33",
    "france": "33",
    "nl": "31",
    "netherlands": "31",
    "be": "32",
    "belgium": "32",
    "es": "34",
    "spain": "34",
    "it": "39",
    "italy": "39",
    "pl": "48",
    "poland": "48",
    "se": "46",
    "sweden": "46",
    "no": "47",
    "norway": "47",
    "fi": "358",
    "finland": "358",
    "ie": "353",
    "ireland": "353",
    "pt": "351",
    "portugal": "351",
    "at": "43",
    "austria": "43",
    "ch": "41",
    "switzerland": "41",
    "cz": "420",
    "czk": "420",
    "ph": "63",
    "philippines": "63",
    "id": "62",
    "indonesia": "62",
    "my": "60",
    "malaysia": "60",
    "sg": "65",
    "singapore": "65",
    "th": "66",
    "thailand": "66",
    "vn": "84",
    "vietnam": "84",
    "in": "91",
    "india": "91",
    "pk": "92",
    "pakistan": "92",
    "bd": "880",
    "bangladesh": "880",
    "mx": "52",
    "mexico": "52",
    "br": "55",
    "brazil": "55",
    "ar": "54",
    "argentina": "54",
    "co": "57",
    "colombia": "57",
    "cl": "56",
    "chile": "56",
    "pe": "51",
    "peru": "51",
    "za": "27",
    "south africa": "27",
    "ng": "234",
    "nigeria": "234",
    "ke": "254",
    "kenya": "254",
    "eg": "20",
    "egypt": "20",
    "tr": "90",
    "turkey": "90",
    "ru": "7",
    "russia": "7",
    "ua": "380",
    "ukraine": "380",
    "kz": "7",
    "kazakhstan": "7",
    "jp": "81",
    "japan": "81",
    "kr": "82",
    "korea": "82",
    "south korea": "82",
    "cn": "86",
    "china": "86",
    "hk": "852",
    "hong kong": "852",
    "tw": "886",
    "taiwan": "886",
    "nz": "64",
    "new zealand": "64",
    "il": "972",
    "israel": "972",
    "ae": "971",
    "uae": "971",
    "sa": "966",
    "saudi arabia": "966",
}


def dial_code(country: str) -> str:
    c = re.sub(r"[\s_\-]+", " ", str(country or "").strip().lower())
    if not c:
        return ""
    if c in COUNTRY_DIAL:
        return COUNTRY_DIAL[c]
    if c.isdigit() and 1 <= len(c) <= 3:
        return c
    return COUNTRY_DIAL.get(c.replace(" ", ""), "")


def normalize_e164(number: str, country: str = "") -> str:
    """Return E.164 ``+…`` for OpenAI add-phone / SMS providers."""
    raw = str(number or "").strip()
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return ""
    dial = dial_code(country)
    # Already has matching country dial
    if dial and digits.startswith(dial) and len(digits) >= len(dial) + 7:
        return f"+{digits}"
    # US/CA national 10-digit
    if dial == "1" and len(digits) == 10:
        return f"+1{digits}"
    # Other nationals: prepend dial when clearly shorter than E.164
    if dial and not digits.startswith(dial) and len(digits) <= 11:
        return f"+{dial}{digits}"
    if raw.startswith("+") and len(digits) >= 10:
        return f"+{digits}"
    # Last resort: 10-digit no country → US (common Getatext pool)
    if len(digits) == 10 and not dial:
        return f"+1{digits}"
    return f"+{digits}"
