"""Random display names for create_account (about_you).

US-heavy English pool by default; light regional variants when proxy/locale
hints JP/FR/etc. Goal: avoid a tiny 10x10 name fingerprint across thousands
of signups — not a silver bullet vs IP bans.
"""
from __future__ import annotations

import random
import re
from typing import Any

# ~90 common US/English given names (mixed gender)
US_FIRST = [
    "James", "Robert", "John", "Michael", "David", "William", "Richard", "Joseph",
    "Thomas", "Christopher", "Charles", "Daniel", "Matthew", "Anthony", "Mark",
    "Donald", "Steven", "Paul", "Andrew", "Joshua", "Kenneth", "Kevin", "Brian",
    "George", "Timothy", "Ronald", "Edward", "Jason", "Jeffrey", "Ryan", "Jacob",
    "Gary", "Nicholas", "Eric", "Jonathan", "Stephen", "Larry", "Justin", "Scott",
    "Brandon", "Benjamin", "Samuel", "Raymond", "Gregory", "Frank", "Alexander",
    "Patrick", "Jack", "Dennis", "Jerry", "Tyler", "Aaron", "Jose", "Adam", "Nathan",
    "Henry", "Douglas", "Zachary", "Peter", "Kyle", "Noah", "Ethan", "Jeremy",
    "Walter", "Christian", "Keith", "Roger", "Terry", "Austin", "Sean", "Gerald",
    "Carl", "Dylan", "Harold", "Jordan", "Bryan", "Billy", "Joe", "Bruce", "Gabriel",
    "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan", "Jessica",
    "Sarah", "Karen", "Lisa", "Nancy", "Betty", "Margaret", "Sandra", "Ashley",
    "Dorothy", "Kimberly", "Emily", "Donna", "Michelle", "Carol", "Amanda", "Melissa",
    "Deborah", "Stephanie", "Rebecca", "Sharon", "Laura", "Cynthia", "Kathleen",
    "Amy", "Angela", "Shirley", "Anna", "Brenda", "Pamela", "Emma", "Nicole",
    "Helen", "Samantha", "Katherine", "Christine", "Debra", "Rachel", "Carolyn",
    "Janet", "Catherine", "Maria", "Heather", "Diane", "Ruth", "Julie", "Olivia",
    "Joyce", "Virginia", "Victoria", "Kelly", "Lauren", "Christina", "Joan", "Evelyn",
    "Judith", "Megan", "Andrea", "Cheryl", "Hannah", "Jacqueline", "Martha", "Gloria",
    "Teresa", "Ann", "Sara", "Madison", "Frances", "Kathryn", "Janice", "Jean",
    "Abigail", "Alice", "Judy", "Sophia", "Grace", "Denise", "Amber", "Doris",
    "Marilyn", "Danielle", "Beverly", "Isabella", "Theresa", "Diana", "Natalie",
    "Brittany", "Charlotte", "Marie", "Kayla", "Alexis", "Lori",
]

# ~100 common US/English surnames
US_LAST = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
    "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker",
    "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales", "Murphy",
    "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson", "Bailey",
    "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson", "Watson",
    "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza", "Ruiz",
    "Hughes", "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long",
    "Ross", "Foster", "Jimenez", "Powell", "Jenkins", "Perry", "Russell", "Sullivan",
    "Bell", "Coleman", "Butler", "Henderson", "Barnes", "Gonzales", "Fisher", "Vasquez",
    "Simmons", "Romero", "Jordan", "Patterson", "Alexander", "Hamilton", "Graham",
    "Reynolds", "Griffin", "Wallace", "Moreno", "West", "Cole", "Hayes", "Bryant",
    "Herrera", "Gibson", "Ellis", "Tran", "Medina", "Aguilar", "Stevens", "Murray",
    "Ford", "Castro", "Marshall", "Owens", "Harrison", "Fernandez", "Mcdonald",
    "Woods", "Washington", "Kennedy", "Wells", "Vargas", "Henry", "Chen", "Freeman",
    "Webb", "Tucker", "Guzman", "Burns", "Crawford", "Olson", "Simpson", "Porter",
    "Hunter", "Gordon", "Mendez", "Silva", "Shaw", "Snyder", "Mason", "Dixon",
    "Munoz", "Hunt", "Hicks", "Holmes", "Palmer", "Wagner", "Black", "Robertson",
    "Boyd", "Rose", "Stone", "Salazar", "Fox", "Warren", "Mills", "Meyer", "Rice",
    "Schmidt", "Garza", "Daniels", "Ferguson", "Nichols", "Stephens", "Soto", "Weaver",
    "Ryan", "Gardner", "Payne", "Grant", "Dunn", "Kelley", "Spencer", "Hawkins",
]

# Expanded romaji pool. HAR create_account often uses a **single given name**
# (e.g. "yoko", "mas") — see random_display_name JP branch.
JP_FIRST = [
    "Haruto", "Yuto", "Sota", "Yuki", "Ren", "Hinata", "Aoi", "Hina", "Yui", "Sakura",
    "Kaito", "Riku", "Sosuke", "Mei", "Mio", "Akari", "Nanami", "Sora", "Daiki", "Kenta",
    "Yoko", "Mas", "Rina", "Kana", "Miku", "Nao", "Sho", "Ken", "Taro", "Mika", "Emi",
    "Aya", "Ryo", "Shin", "Yuji", "Asuka", "Nana", "Momo", "Risa", "Haruka", "Saki",
    "Yuna", "Koki", "Soma", "Itsuki", "Minato", "Rin", "Kai", "Ami", "Ena", "Iroha",
    "Himari", "Yua", "Rui", "Sui", "Toa", "Sota", "An", "Koji", "Jiro",
]
JP_LAST = [
    "Sato", "Suzuki", "Takahashi", "Tanaka", "Watanabe", "Ito", "Yamamoto", "Nakamura",
    "Kobayashi", "Kato", "Yoshida", "Yamada", "Sasaki", "Yamaguchi", "Matsumoto", "Inoue",
    "Kimura", "Hayashi", "Shimizu", "Yamazaki", "Mori", "Abe", "Ikeda", "Hashimoto",
    "Yamashita", "Ishikawa", "Nakajima", "Maeda", "Fujita", "Ogawa", "Goto", "Okada",
    "Hasegawa", "Murakami", "Kondo", "Ishii", "Saito", "Sakamoto", "Endo", "Aoki",
]

FR_FIRST = [
    "Lucas", "Louis", "Gabriel", "Arthur", "Hugo", "Leo", "Jules", "Adam", "Raphael", "Paul",
    "Emma", "Jade", "Louise", "Alice", "Chloe", "Lea", "Manon", "Camille", "Ines", "Sarah",
]
FR_LAST = [
    "Martin", "Bernard", "Thomas", "Petit", "Robert", "Richard", "Durand", "Dubois",
    "Moreau", "Laurent", "Simon", "Michel", "Lefebvre", "Leroy", "Roux", "David",
    "Bertrand", "Morel", "Fournier", "Girard",
]

GB_FIRST = US_FIRST  # English names work for GB/CA/AU/SG
GB_LAST = US_LAST


def _region_from_text(text: str) -> str:
    m = re.search(r"region[-_]([a-z]{2,})", text or "", re.I)
    return (m.group(1).upper() if m else "")


def region_hint_from_refresher(refresher: Any) -> str:
    """Best-effort region from proxy URL / fingerprint locale."""
    proxy = str(getattr(refresher, "proxy_url", "") or "")
    reg = _region_from_text(proxy)
    if reg and reg != "HK":
        return reg
    profile = getattr(refresher, "fingerprint_profile", None) or {}
    lang = str(profile.get("language") or profile.get("locale") or "").lower()
    if lang.startswith("ja"):
        return "JP"
    if lang.startswith("fr"):
        return "FR"
    if lang.startswith("en-gb"):
        return "GB"
    if lang.startswith("en-ca") or lang.startswith("fr-ca"):
        return "CA"
    if lang.startswith("zh-tw"):
        return "TW"
    if lang.startswith("en-sg"):
        return "SG"
    if lang.startswith("en-us") or lang.startswith("en"):
        return "US"
    return ""


def _pools_for_region(region: str) -> tuple[list[str], list[str]]:
    r = (region or "").upper()
    if r == "JP":
        # Prefer JP romaji; light English mix for expats
        return JP_FIRST + US_FIRST[:30], JP_LAST + US_LAST[:20]
    if r == "FR":
        return FR_FIRST + US_FIRST[:40], FR_LAST + US_LAST[:40]
    if r in ("GB", "UK", "CA", "SG", "TW", "AU", "US", ""):
        return US_FIRST, US_LAST
    return US_FIRST, US_LAST


def random_display_name(region: str = "", rng: random.Random | None = None) -> str:
    """Return display name for create_account body.

    JP HAR captures often post a **single given name** (age form, short string).
    Other regions keep ``First Last``.
    """
    r = rng or random
    reg = (region or "").upper()
    firsts, lasts = _pools_for_region(reg)
    if reg == "JP":
        roll = r.random()
        given = r.choice(JP_FIRST)
        if roll < 0.55:
            return given
        if roll < 0.85:
            return f"{r.choice(JP_LAST)} {given}"
        return f"{given} {r.choice(JP_LAST)}"
    first = r.choice(firsts)
    last = r.choice(lasts)
    if r.random() < 0.10:
        mid = r.choice("ABCDEFGHJKLMNPRSTW")
        return f"{first} {mid}. {last}"
    return f"{first} {last}"


def random_age(rng: random.Random | None = None, *, lo: int = 18, hi: int = 45) -> int:
    """Adult age as typed on about-you UI (not a calendar picker)."""
    r = rng or random
    lo = max(18, int(lo))
    hi = max(lo, min(80, int(hi)))
    return int(r.randint(lo, hi))


def birthdate_from_age(age: int, *, today=None) -> str:
    """Convert UI **age** → create_account ``birthdate`` (YYYY-MM-DD).

    Real about-you (JA/EN age field) does **not** ask Y/M/D segments in the
    common passwordless flow we capture: user types age, client posts
    ``birthdate`` derived as approximately ``today - age years`` (same
    month/day). HAR examples (2026-08-02 captures)::

        age~30 → 1995-08-03
        age~24 → 2001-08-03

    Do **not** randomize month/day independently — that looks like a
    calendar fill, not an age field.
    """
    from datetime import date, timedelta

    today = today or date.today()
    age = max(18, min(80, int(age)))
    # Prefer exact calendar anniversary: today minus age years.
    try:
        bd = today.replace(year=today.year - age)
    except ValueError:
        # Feb 29 → Feb 28 on non-leap target year
        bd = today.replace(year=today.year - age, day=28)
    # Guard: must be >= 18 on ``today``
    eighteen = today.replace(year=today.year - 18) if today.month != 2 or today.day != 29 else date(today.year - 18, 2, 28)
    if bd > eighteen:
        bd = eighteen - timedelta(days=1)
    return f"{bd.year:04d}-{bd.month:02d}-{bd.day:02d}"


def random_birthdate(rng: random.Random | None = None, *, today=None) -> str:
    """Adult birthdate via **age-first** (HAR-aligned). Prefer :func:`random_about_you`."""
    return birthdate_from_age(random_age(rng), today=today)


def random_about_you(refresher: Any = None) -> tuple[str, str]:
    """(name, birthdate) for about_you / create_account.

    Name + birthdate wire format matches API; birthdate is **derived from
    a sampled age** (what the real form collects), not a random Y-M-D.

    If ``refresher._person_card`` is set (protocol Person Card), use it so
    path/device/name/age stay one coherent person.
    """
    # Prefer bound Person Card (protocol mode)
    if refresher is not None:
        pc = getattr(refresher, "_person_card", None)
        if pc is not None:
            name = str(getattr(pc, "name", "") or "")
            birthdate = str(getattr(pc, "birthdate", "") or "")
            age = int(getattr(pc, "age", 0) or 0)
            if name and birthdate:
                try:
                    setattr(refresher, "_about_you_age", age)
                    setattr(refresher, "_about_you_name", name)
                    setattr(refresher, "_about_you_birthdate", birthdate)
                except Exception:
                    pass
                return name, birthdate
        # Pre-stashed by attach_person_card
        name0 = str(getattr(refresher, "_about_you_name", "") or "")
        bd0 = str(getattr(refresher, "_about_you_birthdate", "") or "")
        if name0 and bd0:
            return name0, bd0

    region = region_hint_from_refresher(refresher) if refresher is not None else ""
    seed = ""
    if refresher is not None:
        seed = str(
            getattr(refresher, "fingerprint_seed", "")
            or getattr(refresher, "email", "")
            or ""
        )
    if seed:
        import hashlib

        h = hashlib.sha256(f"about_you|{seed}".encode("utf-8", errors="replace")).hexdigest()
        rng = random.Random(int(h[:16], 16))
    else:
        rng = random.Random()
    name = random_display_name(region, rng=rng)
    age = random_age(rng)
    birthdate = birthdate_from_age(age)
    if refresher is not None:
        try:
            setattr(refresher, "_about_you_age", age)
            setattr(refresher, "_about_you_name", name)
            setattr(refresher, "_about_you_birthdate", birthdate)
        except Exception:
            pass
    return name, birthdate


def random_about_you_detailed(refresher: Any = None) -> dict[str, Any]:
    """name / age / birthdate dict (age is the UI field; birthdate is wire).

    Always re-derives birthdate from age via :func:`birthdate_from_age` so wire
    cannot ship random month/day even if a stale Person Card string is present.
    """
    name, birthdate = random_about_you(refresher)
    age = 0
    if refresher is not None:
        age = int(getattr(refresher, "_about_you_age", 0) or 0)
        if not age:
            pc = getattr(refresher, "_person_card", None)
            if pc is not None:
                age = int(getattr(pc, "age", 0) or 0)
    if not age and birthdate:
        from datetime import date

        try:
            y, m, d = (int(x) for x in birthdate.split("-")[:3])
            today = date.today()
            age = today.year - y - ((today.month, today.day) < (m, d))
        except Exception:
            age = 0
    if age < 18:
        age = 18
    # Force age → anniversary birthdate (today M/D)
    birthdate = birthdate_from_age(age)
    if refresher is not None:
        try:
            setattr(refresher, "_about_you_age", age)
            setattr(refresher, "_about_you_birthdate", birthdate)
        except Exception:
            pass
    return {"name": name, "age": age, "birthdate": birthdate}
