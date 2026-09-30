#!/usr/bin/env python3
"""
employment_evidence.py — Canonical evidence vocabulary for "does this person
actually work for the target".

WHY THIS EXISTS
---------------
The Organization card's "People & Positions" list reported dozens of people on a live
campaign and most of them did not work for the target. Every one of them was also
written to the graph as `Individual -[WORKS_FOR]-> Company`.

There was no attribution test at all. `org_people` is built from two providers:

  1. serp_client.SerpClient.people() runs `'"<company>" <role> site:linkedin.com/in'`
     once per role keyword. The ONLY thing tying a result to the target is that
     the search engine returned it for a query containing the company name. That
     matches former employees, vendors, recruiters, applicants, students, and
     anyone who merely mentions the company anywhere on their profile.
  2. site_rag's crawl promotes any `@type: Person` in JSON-LD, or any name the
     extraction model returns, from any in-scope page.

`parse_person_title()` does lift an employer out of "Name - Title at Employer",
and its own docstring warns that a wrong employer "silently mis-attributes a
person to the target company" -- but no caller ever compared that employer to the
company. The graph write's only test before `create_edge(..., 'WORKS_FOR', ...)`
was `if not name: continue`.

The company seed is soft as well: body.company_name -> linkedin_company_name ->
WHOIS registrant_org -> the domain label with '-'/'_' turned into spaces. So
`primer-avia.test` seeds a quoted search for "primer avia", and a Denver-based
LinkedIn profile that happens to contain that string is written as an employee of
a Russian target -- even though the SERP snippet parser already extracted the
person's location and WHOIS already gave the org's country. Nothing looked.

So employment is now asserted only from evidence, the strength of that evidence
is carried in the EDGE LABEL, and everything that fails the gate is kept in a
separate uncounted bucket rather than silently discarded or silently promoted.

WHY THE EDGE LABEL CARRIES THE TIER
-----------------------------------
Flowsint's importer drops edge `data` before it reaches Neo4j (see issues.md,
"Flowsint import drops edge props"). An edge cannot carry an `employment_score`
or an `evidence` string into the graph; the relationship type is the only durable
channel, which is why the tier is spelled into the label. Node properties DO
survive, so the score and the evidence sentence go there -- and that asymmetry is
exactly what makes `scripts/prune_org_people.py` possible: an org-recon-sourced
individual with no `employment_tier` property is, by construction, output of the
old ungated branch.

Same structure, and the same reasoning, as `scripts/asset_ownership.py`.

WHY A SEPARATE BUCKET RATHER THAN A FILTER
------------------------------------------
WF13 already solved this shape one level up. `org_units` holds real org units;
`org_mentions` holds companies that merely reference the target, kept apart
because "a live search for one company returned a licensing consultancy that
would otherwise have been rendered as its subsidiary". People get the same
treatment: `org_people` is what we can evidence, `org_people_unverified` is what
the search engine returned, labelled with why it did not qualify. An operator who
knows a held row is genuine can still see it; nothing about it reaches the graph,
the count, or an export of employees.

IMPORTING THIS FROM AN n8n CODE NODE
------------------------------------
`employment_evidence` MUST be listed in N8N_RUNNERS_EXTERNAL_ALLOW in the
`env-overrides` of the python runner in `deployment/n8n-task-runners.json`, or
`import employment_evidence` fails the WHOLE node with a security violation
before line 1 runs -- taking all of domain recon down, not just this feature.
Confirm which copy of that file is MOUNTED with `docker inspect
spotter-n8n-runners` -- a second, abandoned copy sits at
`/root/flowsint/n8n-task-runners.json` and has been stale since 2026-08-15, so
which one wins depends on the project directory of the last `compose up`.

Then confirm the value reached the runner PROCESS rather than only the file.
PID 1's environment is stale and is ALREADY missing serp_client/site_rag/
edgar_client while those imports work fine, so check `/proc/<python pid>/environ`
and not the launcher's. Note also that `docker restart` re-reads the mounted JSON
but does NOT pick up new compose `environment:` values -- a newly added
ORG_PEOPLE_* knob needs `compose up -d --no-deps task-runners`.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# name_score() is an existing 0-100 company-name matcher with suffix stripping and
# a documented word-aligned containment fix ("NFO INC" normalises to "nfo", which
# is a substring of "iNFOrmation" in "example harbor information security", so an
# unrelated registrant scored 70 against a security consultancy). Reusing it
# is the point: the same matcher refusing the same wrong company for the same
# reason it already refuses a wrong SEC filer.
#
# LOADED BY PATH IF THE PLAIN IMPORT DOES NOT YIELD THEM, and that is not
# paranoia. `edgar_client` is a NETWORK client for a source that can be disabled
# (EDGAR_ENABLED=0) and that test harnesses replace with a stub -- WF13's own
# smoke test installs a fake into sys.modules before the node runs. A stub
# without these two names would otherwise raise ImportError at line 1 of the
# code node and take ALL of domain recon down, not just this feature, over two
# pure string functions that have nothing to do with the network. Whichever
# module object is bound, the matcher this gate uses is the real one.
def _load_name_matcher():
    try:
        from edgar_client import name_score, normalise_company
        return name_score, normalise_company
    except Exception:      # noqa: BLE001 - absent, stubbed, or partially stubbed
        pass
    import importlib.util
    import os
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "edgar_client.py")
    spec = importlib.util.spec_from_file_location("_employment_edgar_matcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.name_score, module.normalise_company


_name_score, _normalise_company = _load_name_matcher()


# ── The three employment labels ──────────────────────────────────────────────
#
# WORKS_FOR         the ORGANISATION's own records place them there: an AD
#                   account, an address on the target domain, a name the company
#                   published on its own website, a recruiter on its own vacancy.
# CLAIMS_WORKS_FOR  the PERSON says so and we verified they named the target --
#                   but the claim is theirs, on a profile that may be years out
#                   of date. Evidence, not confirmation.
# LIKELY_WORKS_FOR  reserved, and deliberately UNWRITTEN. Inference from role
#                   keywords, search co-occurrence or name similarity stays off
#                   the graph entirely; the held bucket is where it goes. The
#                   label exists so a future writer has a slot with a weight
#                   already pinned at 0, exactly as LIKELY_MANAGES does.
#
# CLAIMS_WORKS_FOR outranks LIKELY_WORKS_FOR on purpose: a statement by the
# person is evidence; an inference by us is not.

WORKS_FOR = "WORKS_FOR"
CLAIMS_WORKS_FOR = "CLAIMS_WORKS_FOR"
LIKELY_WORKS_FOR = "LIKELY_WORKS_FOR"

EMPLOYMENT_LABELS: Tuple[str, ...] = (WORKS_FOR, CLAIMS_WORKS_FOR, LIKELY_WORKS_FOR)

# The only labels any writer may emit. LIKELY_WORKS_FOR is excluded by design.
WRITABLE_LABELS: Tuple[str, ...] = (WORKS_FOR, CLAIMS_WORKS_FOR)

# What each label may contribute to a person's score.
#
# NOTHING READS THIS TODAY. It exists so the regression guard has values to
# assert on -- that CLAIMS_WORKS_FOR ranks below WORKS_FOR and that
# LIKELY_WORKS_FOR is pinned at 0 -- in the same way OWNERSHIP_WEIGHTS pins
# LIKELY_MANAGES. A future scorer should read it rather than re-declare weights.
EMPLOYMENT_WEIGHTS: Dict[str, int] = {
    WORKS_FOR: 8,
    CLAIMS_WORKS_FOR: 3,
    LIKELY_WORKS_FOR: 0,
}


# ── Tiers ────────────────────────────────────────────────────────────────────
#
# `contradicted` is split from `weak` only so the operator reads "their profile
# names Globex" instead of "weak". That is the difference between dismissing a
# row and learning something from it. Both are held; neither gets an edge.

TIER_CONFIRMED = "confirmed"
TIER_REPORTED = "reported"
TIER_WEAK = "weak"
TIER_CONTRADICTED = "contradicted"

TIERS: Tuple[str, ...] = (TIER_CONFIRMED, TIER_REPORTED, TIER_WEAK, TIER_CONTRADICTED)
SHOWN_TIERS: Tuple[str, ...] = (TIER_CONFIRMED, TIER_REPORTED)
HELD_TIERS: Tuple[str, ...] = (TIER_WEAK, TIER_CONTRADICTED)

LABEL_FOR_TIER: Dict[str, str] = {
    TIER_CONFIRMED: WORKS_FOR,
    TIER_REPORTED: CLAIMS_WORKS_FOR,
    TIER_WEAK: "",           # no edge, ever
    TIER_CONTRADICTED: "",   # no edge, ever
}

# Sort order only. Higher is stronger.
_TIER_RANK: Dict[str, int] = {
    TIER_CONFIRMED: 3,
    TIER_REPORTED: 2,
    TIER_WEAK: 1,
    TIER_CONTRADICTED: 0,
}


# ── Evidence and contradiction codes ─────────────────────────────────────────

EV_AD_PRESENT = "ad_present"        # an account in the client's own Active Directory
EV_SITE_NAMED = "site_named"        # the org published them on its own website
EV_CORP_EMAIL = "corp_email"        # an address on the target domain
EV_RECRUITER = "recruiter"          # named contact on the employer's own vacancy
EV_EMPLOYER_MATCH = "employer_match"  # their profile names the target as employer
EV_ROLE_TITLE = "role_title"        # a real job title, not the company's own name

# Evidence that originates with the ORGANISATION rather than with the person.
ORG_SIDE_EVIDENCE: Tuple[str, ...] = (
    EV_AD_PRESENT, EV_SITE_NAMED, EV_CORP_EMAIL, EV_RECRUITER,
)

CX_EMPLOYER_OTHER = "employer_other"  # their profile names a DIFFERENT company
CX_GEO_CONFLICT = "geo_conflict"      # located in a country the org is not in
CX_NO_EMPLOYER = "no_employer"        # pure search-engine co-occurrence
CX_HEADLINE_ONLY = "headline_only"    # a company name where a role should be

CONTRADICTIONS: Tuple[str, ...] = (
    CX_EMPLOYER_OTHER, CX_GEO_CONFLICT, CX_NO_EMPLOYER, CX_HEADLINE_ONLY,
)

EVIDENCE_WEIGHTS: Dict[str, int] = {
    EV_AD_PRESENT: 50,
    EV_SITE_NAMED: 40,
    EV_CORP_EMAIL: 40,
    EV_RECRUITER: 40,
    EV_EMPLOYER_MATCH: 25,
    EV_ROLE_TITLE: 5,
}

CONTRADICTION_WEIGHTS: Dict[str, int] = {
    CX_EMPLOYER_OTHER: -60,
    CX_GEO_CONFLICT: -30,
    CX_NO_EMPLOYER: -20,
    CX_HEADLINE_ONLY: -5,
}

# The two floors.
#
# TIER_CONFIRMED_MIN = 40 is not a tuned number: every org-side weight is >= 40,
# so "any single piece of evidence originating with the organisation confirms
# employment" falls out of the table rather than being a special case in the
# code. EV_AD_PRESENT sits strictly above the rest so an AD-confirmed row is
# distinguishable by score alone.
#
# TIER_REPORTED_MIN = 25 == EV_EMPLOYER_MATCH, so a profile that names the target
# and nothing else lands exactly on the floor. That is the commonest TRUE
# positive on an external engagement and it must survive the gate.
#
# The gap between them is the whole point. EV_EMPLOYER_MATCH + EV_ROLE_TITLE is
# 30, which is below 40, so NOTHING PROFILE-ONLY CAN EVER REACH CONFIRMED however
# many profile-side signals stack up. A search engine cannot confirm employment,
# by construction rather than by threshold. check_workflow_regressions.py asserts
# that arithmetically, so raising EV_EMPLOYER_MATCH fails loudly instead of
# quietly re-admitting the 34.
TIER_CONFIRMED_MIN = 40
TIER_REPORTED_MIN = 25


# ── Company-name comparison ──────────────────────────────────────────────────
#
# Both thresholds are read off name_score's own documented behaviour rather than
# tuned against a sample.
#
# 72 is EDGAR_MIN_SCORE's default, chosen against the same measured failure.
# name_score returns 95 for a word-run containment covering >= 0.8 of the longer
# name, 82 for >= 0.6, and 64 below that; 72 sits in the 64 <-> 82 gap. So
# "Primer Avia" vs "Primer Avia LLC" is 2/2 -> 95, a match; "Example Harbor
# Information Security" vs "Example Harbor Corp" is 2/4 -> 64, not a match.
#
# 40 is not a guess either. name_score explicitly caps the no-shared-word band at
# `min(40, SequenceMatcher(...))`, so "<= 40" IS "not one word in common", read
# out of the matcher's source. The 41-71 band is a partial containment that
# neither confirms nor contradicts: it is `unclear` and it scores nothing.
EMPLOYER_MATCH_MIN = 72
EMPLOYER_OTHER_MAX = 40

VERDICT_MATCH = "match"
VERDICT_UNCLEAR = "unclear"
VERDICT_OTHER = "other"
VERDICT_ABSENT = "absent"

# WHOIS placeholders that are not company names. Same list WF13's seed
# precedence already rejects.
_PRIVACY_PLACEHOLDERS: Tuple[str, ...] = (
    "redacted for privacy", "privacy service", "whoisguard", "domains by proxy",
    "perfect privacy", "withheld for privacy", "data protected", "not disclosed",
    "statutory masking enabled", "privacy protect", "contact privacy inc",
)


def _txt(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def is_placeholder_org(name: str) -> bool:
    """True for a WHOIS privacy placeholder masquerading as a company name."""
    low = _txt(name).lower()
    if not low:
        return True
    return any(p in low for p in _PRIVACY_PLACEHOLDERS)


# ── Cyrillic, so a Russian company can be matched at all ─────────────────────
#
# `normalise_company()` strips everything outside [a-z0-9 ], so a name written in
# Cyrillic empties out entirely: "ООО ПРИМЕР АВИА" -> "". That is not a cosmetic
# gap. name_score would return 0 for it, 0 reads as "not one word in common", and
# the row lands in `other` -- marking a GENUINE Russian employee as "names a
# different company". The false negative is invisible on the card and it falls
# hardest on exactly the targets the geography rule was written for.
#
# So both sides are transliterated before they are compared. "ПРИМЕР АВИА" becomes
# "primer avia" and matches the company's own Latin branding, which is what its
# staff actually write on a LinkedIn profile.
#
# ONE SCHEME, NOT A SET OF VARIANTS. Several romanisations are in use and they
# disagree on a handful of letters (х as kh or h, й as y or i, ё as e or yo).
# Scoring every variant and taking the best would inflate every comparison,
# including the wrong ones, which is the opposite of what this module is for.
# One scheme is enough because name_score falls back to a sequence ratio when
# word containment fails, and that absorbs single-letter spelling drift on its
# own -- "khabarovsk" against "habarovsk" still scores in the nineties.
_CYRILLIC_TO_LATIN: Dict[str, str] = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
    # Ukrainian, Belarusian and Serbian letters the Russian table has no slot
    # for. Without them a Ukrainian company transliterates half-way and scores
    # worse than if nothing had been done at all.
    "і": "i", "ї": "yi", "є": "ye", "ґ": "g", "ў": "u",
    "ђ": "dj", "ј": "j", "љ": "lj", "њ": "nj", "ћ": "c", "џ": "dz",
    "ѓ": "g", "ќ": "k", "ѕ": "dz",
}

# Russian/CIS corporate forms, the equivalents of Inc / LLC / Ltd. They MUST be
# stripped for the same reason edgar_client strips the Latin ones, and the cost
# of missing them is not subtle: name_score's containment score is the ratio of
# the shorter name to the longer, so an unstripped "ooo" turns a perfect
# "primer avia" vs "ooo primer avia" (2/2 -> 95, a match) into 2/3 -> 82, and a
# three-word company name into 3/4 -> 64, which is below the floor.
#
# Listed in transliterated form because stripping happens after transliteration,
# and that also catches the very common case of a Russian company writing its own
# name in Latin as "OOO Primer Avia".
_CORPORATE_FORMS: Tuple[str, ...] = (
    "ooo",    # ООО  limited liability company
    "oao",    # ОАО  open joint-stock company
    "zao",    # ЗАО  closed joint-stock company
    "pao",    # ПАО  public joint-stock company
    "ao",     # АО   joint-stock company
    "nao",    # НАО  non-public joint-stock company
    "gk",     # ГК   group of companies
    "npo",    # НПО  research and production association
    "npp",    # НПП  research and production enterprise
    "too",    # ТОО  limited liability partnership (KZ)
    "tov",    # ТОВ  limited liability company (UA)
    "pat",    # ПАТ  public joint-stock company (UA)
    "fop",    # ФОП  sole proprietor (UA)
    "chp",    # ЧП   private enterprise
    "kompaniya", "kompania", "gruppa", "kontsern", "korporatsiya",
)
# NOT in the list, deliberately: "ip" (ИП, sole proprietor). ИП is rare inside a
# company-name string, while "IP" is a very common English token -- intellectual
# property, internet protocol -- so stripping it would turn "IP Solutions" into
# "Solutions" and match it against any target named Solutions. It costs more
# precision than it buys. Do not add it back.


def transliterate_cyrillic(text: str) -> str:
    """Romanise any Cyrillic in `text`, leaving everything else untouched.

    >>> transliterate_cyrillic("ООО ПРИМЕР АВИА")
    'OOO PRIMER AVIA'
    >>> transliterate_cyrillic("Primer Avia")
    'Primer Avia'
    """
    out: List[str] = []
    for ch in str(text or ""):
        low = ch.lower()
        if low in _CYRILLIC_TO_LATIN:
            latin = _CYRILLIC_TO_LATIN[low]
            out.append(latin.upper() if ch.isupper() and latin else latin)
        else:
            out.append(ch)
    return "".join(out)


def comparable_company(name: str) -> str:
    """The form both sides of a company comparison are reduced to.

    Transliterated, lowercased, punctuation dropped, corporate forms removed.
    Returns '' when nothing comparable survives -- which is the signal that this
    name is in a script the matcher cannot handle at all (see employer_verdict).
    """
    text = transliterate_cyrillic(_txt(name)).lower()
    words = [w for w in re.sub(r"[^a-z0-9]+", " ", text).split()
             if w and w not in _CORPORATE_FORMS]
    # Then the SHARED normaliser, which strips the Latin corporate suffixes
    # (Inc, Corp, Ltd, GmbH, …). Both halves are needed and leaving the second
    # one out is not a cosmetic miss: this function is also the dedupe key for
    # org_aliases, so without it "Example Corp." and "example" stop collapsing to
    # one alias and the weak domain-derived seed is promoted to a first-class
    # alias of its own. Confirmed live, where the alias list came back as
    # ['Example Corp.', 'example'] instead of one entry. It happened to change no
    # verdict on that run -- both aliases scored the same employers identically --
    # but a seed that is a common word would widen the gate on a name nobody
    # chose as an alias.
    return _normalise_company(" ".join(words))


def org_aliases(
    *,
    org_seed: str = "",
    linkedin_company_name: str = "",
    profile_name: str = "",
    legal_name: str = "",
    registrant_org: str = "",
    domain: str = "",
    extra: Optional[Iterable[str]] = None,
) -> Tuple[str, ...]:
    """Every name the target company is known by, strongest first.

    Build this AFTER every provider has run. The SERP query is necessarily spent
    on the weak `org_seed` before linkedin_company_name / EDGAR's legal name /
    registrant_org resolve, but the GATE has no such constraint -- so a weak seed
    costs recall on the query and nothing at all on precision.

    The bare domain label is included last and only when nothing better exists.
    It is a poor alias ("primer avia" from primer-avia.test) but excluding it entirely
    would make every alias-less target return `no_org_name` and hold everybody.
    """
    out: List[str] = []
    seen = set()

    def _add(value: Any) -> None:
        name = _txt(value)
        if not name or is_placeholder_org(name):
            return
        # Dedupe on the COMPARABLE form, so "ООО ПРИМЕР АВИА" and "OOO Primer Avia"
        # are recognised as one alias rather than two, and a wholly Cyrillic
        # name is no longer dropped for normalising to "".
        key = comparable_company(name)
        if not key or key in seen:
            return
        seen.add(key)
        out.append(name)

    for candidate in (linkedin_company_name, legal_name, profile_name,
                      org_seed, registrant_org):
        _add(candidate)
    for candidate in (extra or ()):
        _add(candidate)

    if not out and domain:
        label = _txt(domain).rsplit(".", 1)[0] if "." in _txt(domain) else _txt(domain)
        _add(label.replace("-", " ").replace("_", " "))

    return tuple(out)


# ── Which company is the target? ─────────────────────────────────────────────
#
# Everything above answers "does this PERSON work for the target". This half
# answers the question that has to be settled first and never was: "is this
# COMPANY the target at all".
#
# The asymmetry was a real finding, not a tidy-up. A campaign aimed at an
# aviation manufacturer, with the operator's Objectives naming the company, its
# domain and its Russian legal entity, rendered an Organization card for an
# unrelated military-history journal. Three things had to line up for that:
#
#   1. The operator's Additional Identifiers and Company Email never reached
#      WF13 at all, so the one place that knew the legal entity and the second
#      domain could not spend them.
#   2. Each provider was handed ONE seed string and picked the top row of
#      whatever came back. hh.ru's employer search matches DESCRIPTION text, so
#      a query about drones returns organisations that merely write about
#      drones; with no name floor, the tie-break (most open vacancies) chose
#      among them.
#   3. The wrong pick then became `org_profile.name`, which org_aliases() feeds
#      back in as an alias -- so the employment gate below spent the rest of the
#      run scoring people against the WRONG company's name. A mis-identification
#      here does not stay here.
#
# So a company is adopted only on evidence, by the same word-aligned, Cyrillic-
# aware matcher the employment gate uses, and a provider that cannot clear the
# floor reports `no_match` with the near miss named. An empty card an operator
# can act on beats a populated card about somebody else.

# Same band as EMPLOYER_MATCH_MIN, and for the same reason: 72 is the first
# score above name_score's 64 "the shorter name is only half the longer one"
# rung. It is deliberately NOT lower here -- adopting the wrong company is worse
# than adopting a wrong employer claim, because it poisons the alias list that
# every later gate reads.
COMPANY_MATCH_MIN = 72
# A candidate that is not the target but whose name is BUILT ON the target's
# ("Example" -> "Example Logistics") is a plausible sibling brand. This is a prefix
# test, not a score band, and the difference is not academic: "Example Advisors
# - Independent Contoso Spend Specialists" CONTAINS "Contoso" and scores 64
# for it, but it is a third-party licensing consultancy, and rendering it as a
# Contoso business unit is the exact mistake org_mentions was added to stop.
# A sub-brand leads with the parent's name; a vendor mentions it in passing.

REL_TARGET = "target"      # this IS the company
REL_UNIT = "unit"          # a sibling/subsidiary brand of it
REL_MENTION = "mention"    # came back from the search, no evidenced tie

# Multi-label public suffixes common enough to matter here. Not a full PSL --
# vendoring one into a code node is not worth it -- but without these,
# "example.co.uk" registers as "co.uk" and every .co.uk target corroborates
# against every other.
_TWO_LABEL_TLDS: Tuple[str, ...] = (
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "com.br", "com.mx", "com.ar", "com.co",
    "co.nz", "com.tr", "co.za", "com.sg", "com.hk", "com.cn", "net.cn",
    "org.cn", "co.kr", "co.in", "com.ua", "net.ua", "org.ua", "com.pl",
    "com.ru", "net.ru", "org.ru", "com.kz", "com.by", "co.il", "com.tw",
)

# Separators an operator actually types into a one-line Additional Identifiers
# field. Slash is NOT here: "Example Avionics / Example Aerospace" is one
# reading, but so is "AC/DC Industries", and splitting on it silently halves a
# legitimate name.
_ID_SPLIT = re.compile(r"[,;\n\r|]+")


def split_identifiers(raw: Any) -> Tuple[str, ...]:
    """The Additional Identifiers free-text field, as a list of identifiers.

    >>> split_identifiers("maket-aero.test, OOO Obrazets")
    ('maket-aero.test', 'OOO Obrazets')
    """
    out: List[str] = []
    seen = set()
    for part in _ID_SPLIT.split(str(raw or "")):
        item = _txt(part).strip(" \t\"'")
        if not item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return tuple(out)


def registrable_domain(value: Any) -> str:
    """The registrable domain inside a host, URL or email address, or ''.

    >>> registrable_domain("info@mail.example.co.uk")
    'example.co.uk'
    """
    text = _txt(value).lower().strip().rstrip(".")
    if not text:
        return ""
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    text = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", text)
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    text = text.split(":", 1)[0]
    text = re.sub(r"^www\.", "", text)
    if not re.fullmatch(r"[a-z0-9.\-]+", text) or "." not in text:
        return ""
    parts = [p for p in text.split(".") if p]
    if len(parts) < 2:
        return ""
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_LABEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def looks_like_domain(value: Any) -> bool:
    """True when an identifier is a hostname rather than a company name."""
    text = _txt(value).lower()
    if not text or " " in text:
        return bool(registrable_domain(text)) and " " not in text
    return bool(registrable_domain(text))


def domain_label(value: Any) -> str:
    """'maket-aero.test' -> 'maket aero'. The weakest name we will ever accept."""
    reg = registrable_domain(value) or _txt(value).lower()
    if not reg:
        return ""
    label = reg.split(".", 1)[0]
    return label.replace("-", " ").replace("_", " ").strip()


def build_identity(
    *,
    primary_name: str = "",
    additional_ids: Any = "",
    company_email: str = "",
    domain: str = "",
    linkedin_company_name: str = "",
    registrant_org: str = "",
    legal_name: str = "",
    profile_name: str = "",
    extra: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Everything known about WHO the target is, in one object.

    Built BEFORE the providers run, unlike org_aliases() which is built after
    them to score people. The distinction matters: this one decides what to
    search for and what to accept back, so it must not contain anything a
    provider inferred -- otherwise a wrong pick corroborates itself.

    `operator_names` and `operator_domains` are the subset the OPERATOR typed in
    Objectives. They outrank everything derived, because they are the only
    identifiers on the card that somebody actually verified.
    """
    op_names: List[str] = []
    op_domains: List[str] = []
    names: List[str] = []
    domains: List[str] = []
    seen_name = set()
    seen_dom = set()

    def _add_name(value: Any, operator: bool = False) -> None:
        name = _txt(value)
        if not name or is_placeholder_org(name):
            return
        key = comparable_company(name)
        if not key or key in seen_name:
            return
        seen_name.add(key)
        names.append(name)
        if operator:
            op_names.append(name)

    def _add_domain(value: Any, operator: bool = False) -> None:
        reg = registrable_domain(value)
        if not reg or reg in seen_dom:
            return
        seen_dom.add(reg)
        domains.append(reg)
        if operator:
            op_domains.append(reg)

    # 1. What the operator typed. A domain-shaped identifier is a domain, not a
    #    name -- "maket-aero.test" as a name would be scored against employer
    #    names it can never match, while as a domain it is the single strongest
    #    corroborator we have.
    _add_name(primary_name, operator=True)
    for ident in split_identifiers(additional_ids):
        if looks_like_domain(ident):
            _add_domain(ident, operator=True)
        else:
            _add_name(ident, operator=True)
    _add_domain(company_email, operator=True)
    _add_domain(domain)

    # 2. What earlier legs of the same run resolved. Weaker, and last.
    for cand in (linkedin_company_name, legal_name, profile_name, registrant_org):
        _add_name(cand)
    for cand in (extra or ()):
        if looks_like_domain(cand):
            _add_domain(cand)
        else:
            _add_name(cand)

    # 3. Only if nothing else names the company. "maket aero" off the domain is a
    #    poor name, but an identity with no name at all cannot search or score.
    if not names:
        _add_name(domain_label(domain) or domain_label(company_email))

    # Search terms: names only, and never the domain label when a real name
    # exists -- a job board queried for "maket aero" returns thematic noise,
    # which is exactly the failure this module was written for.
    terms = [n for n in names if comparable_company(n)]

    return {
        "names": tuple(names),
        "operator_names": tuple(op_names),
        "domains": tuple(domains),
        "operator_domains": tuple(op_domains),
        "search_terms": tuple(terms),
        "seed": terms[0] if terms else "",
        "match_min": COMPANY_MATCH_MIN,
        "operator_sourced": bool(op_names or op_domains),
    }


def identity_from_aliases(aliases: Iterable[str], domain: str = "") -> Dict[str, Any]:
    """An identity from a bare alias list, for callers that have nothing else."""
    alias_list = [a for a in (_txt(x) for x in aliases) if a]
    return build_identity(
        primary_name=alias_list[0] if alias_list else "",
        extra=alias_list[1:],
        domain=domain,
    )


def _name_affinity(candidate: str, identity: Mapping[str, Any]) -> Tuple[int, str]:
    """Best (score, alias) for a candidate name across every identity name."""
    cand = comparable_company(candidate)
    if not cand:
        return (0, "")
    best, best_alias = 0, ""
    for alias in (identity.get("names") or ()):
        acmp = comparable_company(alias)
        if not acmp:
            continue
        score = _name_score(acmp, cand)
        # An operator-typed name is the same comparison, but a tie between an
        # operator name and a provider-derived one should report the operator's.
        if score > best:
            best, best_alias = score, alias
    return (best, best_alias)


def _domain_hits(text: Any, identity: Mapping[str, Any]) -> List[str]:
    """Identity domains that appear in a candidate's own text, host-aligned.

    Word-aligned for the same reason name matching is: a bare `in` test makes
    "aket-aero.test" a hit for "maket-aero.test", and makes every subdomain of an
    unrelated registrar look like corroboration.
    """
    blob = _txt(text).lower()
    if not blob:
        return []
    hits: List[str] = []
    for dom in (identity.get("domains") or ()):
        if re.search(r"(?<![a-z0-9.\-])" + re.escape(dom) + r"(?![a-z0-9\-])", blob):
            hits.append(dom)
    return hits


def is_affiliate_name(candidate: Mapping[str, Any],
                      identity: Mapping[str, Any]) -> bool:
    """Is this candidate's name built on one of the target's names?

    Word-aligned prefix in either direction: "example" -> "example logistics" yes,
    "example logistics" -> "example" yes, "example advisors independent contoso
    spend specialists" -> "contoso" no. A single-word alias short enough to be a
    common word is not enough on its own, or every company whose name starts
    with "Global" becomes a sibling of every other.
    """
    forms = [_txt(candidate.get("name"))] + [
        _txt(a) for a in (candidate.get("alt_names") or ())]
    cands = [comparable_company(f).split() for f in forms if f]
    for alias in (identity.get("names") or ()):
        aw = comparable_company(alias).split()
        if not aw or (len(aw) == 1 and len(aw[0]) <= 3):
            continue
        for cw in cands:
            if not cw:
                continue
            if cw[:len(aw)] == aw or aw[:len(cw)] == cw:
                return True
    return False


def company_verdict(
    candidate: Mapping[str, Any],
    identity: Mapping[str, Any],
    *,
    match_min: Optional[int] = None,
) -> Dict[str, Any]:
    """Is this provider row the target company?

    `candidate` is a provider row: at least `name`, optionally `site`, `url`,
    `description` and any other text the provider captured about it.

    Returns the verdict AND its reasoning, because a refusal has to be
    explainable on the card -- "no match" with no near miss named is the same
    dead end as the wrong company, one screen earlier.
    """
    floor = int(match_min if match_min is not None else
                identity.get("match_min") or COMPANY_MATCH_MIN)
    name = _txt(candidate.get("name"))
    score, alias = _name_affinity(name, identity)
    # `alt_names` is for providers whose row carries more than one spelling of
    # the company: a LinkedIn result has a marketing title AND a URL slug, and
    # the slug is often the one that carries the identifier ("maket-aero" under a
    # page titled "Example Unmanned Systems"). Scoring only the display title
    # throws away the half of the row that is machine-assigned.
    for alt in (candidate.get("alt_names") or ()):
        alt_score, alt_alias = _name_affinity(alt, identity)
        if alt_score > score:
            score, alias = alt_score, alt_alias

    # The candidate's OWN web address, never the provider's profile URL: every
    # hh.ru row is hosted on hh.ru and every LinkedIn row on linkedin.com, so
    # scoring the profile URL would corroborate every candidate equally.
    site_hits = _domain_hits(candidate.get("site"), identity)
    text_hits = [d for d in _domain_hits(
        " ".join(_txt(candidate.get(k)) for k in ("description", "snippet", "text", "email")),
        identity) if d not in site_hits]

    evidence: List[str] = []
    if site_hits:
        evidence.append("its website is %s" % ", ".join(site_hits))
    if text_hits:
        evidence.append("its profile text names %s" % ", ".join(text_hits))
    if score >= floor and alias:
        evidence.append('its name matches "%s" (%d)' % (alias, score))

    # A candidate publishing the target's own domain IS the target, whatever it
    # calls itself -- that is how a legal entity ("OOO Obrazets") is recognised as
    # the company behind a trading name, which a name comparison alone can never
    # do. A domain match is a fact about an identifier; a name match is a
    # judgement about a string, so the domain outranks it.
    if site_hits:
        return {"accept": True, "relation": REL_TARGET, "score": max(score, 95),
                "alias": alias, "matched_domain": site_hits[0],
                "evidence": evidence, "reason": ""}
    if score >= floor:
        return {"accept": True, "relation": REL_TARGET, "score": score,
                "alias": alias, "matched_domain": "",
                "evidence": evidence, "reason": ""}
    if text_hits:
        # Naming the domain in prose is weaker than serving it: a reseller,
        # a recruiter or a news write-up does exactly that. Enough to keep the
        # row visible, never enough to adopt it as the company.
        return {"accept": False, "relation": REL_MENTION, "score": score,
                "alias": alias, "matched_domain": text_hits[0],
                "evidence": evidence,
                "reason": '%r only mentions %s in its text; that is a reference '
                          "to the target, not the target." % (name, text_hits[0])}

    relation = REL_UNIT if is_affiliate_name(candidate, identity) else REL_MENTION
    if not (identity.get("names") or ()):
        reason = ("no company name to check %r against — set Primary Target in "
                  "Objectives with Target Type: Organization" % name)
    elif score <= EMPLOYER_OTHER_MAX:
        reason = ('%r shares no word with %s' % (
            name, " / ".join('"%s"' % a for a in (identity.get("names") or ())[:3])))
    else:
        reason = ('%r scored %d against "%s", below the %d match floor'
                  % (name, score, alias or (identity.get("names") or ("",))[0], floor))
    return {"accept": False, "relation": relation, "score": score, "alias": alias,
            "matched_domain": "", "evidence": evidence, "reason": reason}


def pick_company(
    candidates: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    *,
    match_min: Optional[int] = None,
    tie_break: Optional[Any] = None,
) -> Dict[str, Any]:
    """Choose the target from a provider's result set, or choose nothing.

    Returns `best` (None when nothing cleared the floor), `units` (rows whose
    name is built on the target's — plausible sibling brands), `mentions`
    (everything else) and `reason` (why nothing was adopted, when nothing was).

    Choosing nothing is a first-class outcome. The previous behaviour — sort,
    take row 0 regardless — is what put another company's address, subsidiaries
    and staff on the card under the target's heading.
    """
    scored: List[Tuple[Dict[str, Any], Mapping[str, Any]]] = []
    for cand in (candidates or ()):
        scored.append((company_verdict(cand, identity, match_min=match_min), cand))

    accepted = [(v, c) for v, c in scored if v["accept"]]

    def _rank(pair: Tuple[Dict[str, Any], Mapping[str, Any]]):
        verdict, cand = pair
        extra = 0
        if tie_break:
            try:
                extra = int(tie_break(cand) or 0)
            except Exception:      # noqa: BLE001 - a tie-break must never decide the run
                extra = 0
        return (-verdict["score"], -extra)

    accepted.sort(key=_rank)
    best_pair = accepted[0] if accepted else None
    # Identity, not equality: two providers can return rows that compare equal.
    rest = [(v, c) for v, c in scored
            if best_pair is None or c is not best_pair[1]]

    units = [dict(c) for v, c in rest if v["accept"] or v["relation"] == REL_UNIT]
    mentions = [dict(c) for v, c in rest if not v["accept"] and v["relation"] != REL_UNIT]

    if best_pair is not None:
        return {
            "best": dict(best_pair[1]), "verdict": best_pair[0],
            "units": units, "mentions": mentions, "rejected": [],
            "reason": "",
        }

    # Nothing adopted: hand back the near misses, strongest first, so the card
    # can name what it saw and the operator can recognise the right one.
    near = sorted(scored, key=lambda p: -p[0]["score"])[:5]
    return {
        "best": None, "verdict": None, "units": units, "mentions": mentions,
        "rejected": [{"name": _txt(c.get("name")), "score": v["score"],
                      "url": _txt(c.get("url")), "reason": v["reason"]}
                     for v, c in near],
        "reason": (near[0][0]["reason"] if near else
                   "the provider returned no candidates to check"),
    }


def employer_verdict(
    employer: str,
    aliases: Iterable[str],
    *,
    match_min: int = EMPLOYER_MATCH_MIN,
    other_max: int = EMPLOYER_OTHER_MAX,
) -> Tuple[str, int]:
    """Compare a scraped employer string against the target's known names.

    Returns (verdict, best_score) where verdict is one of 'match', 'unclear',
    'other', 'absent'.

    >>> employer_verdict('Primer Avia LLC', ('Primer Avia',))[0]
    'match'
    >>> employer_verdict('Example Harbor Corp', ('Example Harbor Information Security',))
    ('unclear', 64)
    """
    text = _txt(employer)
    alias_list = [a for a in (_txt(x) for x in aliases) if a]
    if not text or not alias_list:
        return (VERDICT_ABSENT, 0)

    # Both sides are reduced to their transliterated, corporate-form-stripped
    # form before scoring, so a Cyrillic employer string can match the company's
    # Latin branding -- see comparable_company().
    subject = comparable_company(text)
    aliases_cmp = [(a, comparable_company(a)) for a in alias_list]

    # A SCRIPT WE CANNOT ROMANISE MUST NOT CONTRADICT. Transliteration covers
    # Cyrillic; it does nothing for Chinese, Japanese, Arabic or Hebrew, which
    # still reduce to "". name_score would score those 0, and 0 reads as "not one
    # word in common" -- landing the row in `other` and marking a GENUINE
    # employee as "names a different company". CN is one of the campaign regions,
    # so this is a live case and not a hypothetical. When either side has nothing
    # comparable, say so and score nothing.
    if not subject or not any(c for _, c in aliases_cmp):
        return (VERDICT_UNCLEAR, 0)

    best = 0
    for _raw, alias_cmp in aliases_cmp:
        if not alias_cmp:
            continue
        try:
            score = int(_name_score(subject, alias_cmp))
        except Exception:      # noqa: BLE001 - a matcher failure must not gate
            score = 0
        if score > best:
            best = score

    if best >= match_min:
        return (VERDICT_MATCH, best)
    if best <= other_max:
        return (VERDICT_OTHER, best)
    return (VERDICT_UNCLEAR, best)


def is_company_headline(job_title: str, aliases: Iterable[str]) -> bool:
    """True when the parsed 'title' is really just the company name.

    Many LinkedIn headlines are `Name - Example Corp` with no role at all, and the
    title parser cannot invent one. Left alone the company name flows into
    derive_specialty() -- and "Example Harbor Information Security" contains
    "information security", so four people in a live run were classified as
    Security Professionals on the strength of their employer's name.

    WORD-ALIGNED, via name_score. The previous implementation was a raw substring
    test (`len(t) > 6 and (t in c or c in t)` over punctuation-stripped strings),
    which is the exact bug name_score documents and fixed. It made
    is_company_headline("Information Security", ("Example Harbor Information
    Security",)) return True -- blanking a GENUINE job title because it happened
    to be a word-run inside the employer's name. Containment now has to cover
    most of the longer name before it counts.
    """
    title = _txt(job_title)
    if not title:
        return False
    verdict, _ = employer_verdict(title, aliases)
    return verdict == VERDICT_MATCH


# ── Geography ────────────────────────────────────────────────────────────────
#
# The rule an operator asked for: a person living in the United States is
# unlikely to be a public employee of a Russian company. It is a real signal and
# it is also the easiest one to get catastrophically wrong, so the whole section
# is built to fail towards silence.
#
# THE MODULE IS ONE-SIDED ON PURPOSE: AN UNRESOLVED LOCATION NEVER CONTRADICTS.
# Returning '' is always safe -- the row keeps whatever else it earned. Returning
# a wrong ISO2 silently hides a real employee, and a hidden true positive is
# invisible in a way a shown false positive is not.

GEO_MIN_CORROBORATION = 2

# Deliberately small. Country names, the handful of forms that are not the
# country's own name, and the US states -- because "Denver, Colorado" is how
# LinkedIn writes a US location and the country is often absent. WF13 donates its
# own ~250-entry country map as `resolver`, so the long tail is not copied here.
_LOCATION_ALIASES: Dict[str, str] = {
    "united states": "US", "united states of america": "US", "usa": "US",
    "u.s.": "US", "u.s.a.": "US", "us": "US", "america": "US", "american": "US",
    "united kingdom": "GB", "uk": "GB", "u.k.": "GB", "great britain": "GB",
    "britain": "GB", "england": "GB", "scotland": "GB", "wales": "GB",
    "northern ireland": "GB", "british": "GB",
    "russia": "RU", "russian federation": "RU", "russian": "RU",
    "china": "CN", "people's republic of china": "CN", "prc": "CN",
    "chinese": "CN", "hong kong": "HK", "taiwan": "TW",
    "germany": "DE", "german": "DE", "deutschland": "DE",
    "france": "FR", "french": "FR", "spain": "ES", "italy": "IT",
    "netherlands": "NL", "the netherlands": "NL", "holland": "NL",
    "belgium": "BE", "switzerland": "CH", "austria": "AT", "sweden": "SE",
    "norway": "NO", "denmark": "DK", "finland": "FI", "poland": "PL",
    "ireland": "IE", "portugal": "PT", "greece": "GR", "czechia": "CZ",
    "czech republic": "CZ", "romania": "RO", "hungary": "HU", "bulgaria": "BG",
    "ukraine": "UA", "belarus": "BY", "kazakhstan": "KZ", "turkey": "TR",
    "israel": "IL", "india": "IN", "indian": "IN", "pakistan": "PK",
    "japan": "JP", "japanese": "JP", "south korea": "KR", "korea": "KR",
    "singapore": "SG", "malaysia": "MY", "indonesia": "ID", "thailand": "TH",
    "vietnam": "VN", "philippines": "PH", "australia": "AU", "australian": "AU",
    "new zealand": "NZ", "canada": "CA", "canadian": "CA", "mexico": "MX",
    "brazil": "BR", "brasil": "BR", "argentina": "AR", "chile": "CL",
    "colombia": "CO", "peru": "PE", "south africa": "ZA", "nigeria": "NG",
    "kenya": "KE", "egypt": "EG", "morocco": "MA",
    "united arab emirates": "AE", "uae": "AE", "saudi arabia": "SA",
    "qatar": "QA", "estonia": "EE", "latvia": "LV", "lithuania": "LT",
    "serbia": "RS", "croatia": "HR", "slovenia": "SI", "slovakia": "SK",
    "armenia": "AM", "azerbaijan": "AZ", "uzbekistan": "UZ", "moldova": "MD",
}

_US_STATES: Tuple[str, ...] = (
    "alabama", "alaska", "arizona", "arkansas", "california", "colorado",
    "connecticut", "delaware", "florida", "hawaii", "idaho", "illinois",
    "indiana", "iowa", "kansas", "kentucky", "louisiana", "maine", "maryland",
    "massachusetts", "michigan", "minnesota", "mississippi", "missouri",
    "montana", "nebraska", "nevada", "new hampshire", "new jersey",
    "new mexico", "new york", "north carolina", "north dakota", "ohio",
    "oklahoma", "oregon", "pennsylvania", "rhode island", "south carolina",
    "south dakota", "tennessee", "texas", "utah", "vermont", "virginia",
    "washington", "west virginia", "wisconsin", "wyoming",
    "district of columbia", "washington dc", "washington d.c.",
)

# Names that are a country AND a US state, or otherwise genuinely ambiguous.
# These resolve to '' rather than guessing, because the safe direction is
# silence: "Atlanta, Georgia" and "Tbilisi, Georgia" are not distinguishable
# here, and picking either one wrongly suppresses a real employee.
_AMBIGUOUS_LOCATIONS: Tuple[str, ...] = ("georgia", "jersey", "new york city")

# A ccTLD is the country code, with the handful of exceptions where it is not.
_TLD_OVERRIDES: Dict[str, str] = {"uk": "GB", "su": "RU", "eu": "", "ac": "",
                                  "io": "", "co": "", "me": "", "tv": "",
                                  "cc": "", "ai": "", "ly": "", "sh": "",
                                  "gg": "", "to": "", "fm": "", "st": ""}


def country_from_location(text: str, resolver: Optional[Any] = None) -> str:
    """Best-effort ISO2 for a free-text location. '' when undecidable.

    Walks the comma-separated parts RIGHT TO LEFT, because every provider writes
    the country last when it writes it at all ("Denver, Colorado, United
    States"). Falls back to `resolver` -- WF13 donates its own country-name map
    -- and then gives up.

    No city table, by design. "Greater Boston Area" must resolve to '': guessing
    US from a city name is how a real employee gets silently suppressed.

    >>> country_from_location('Denver, Colorado, United States')
    'US'
    >>> country_from_location('Greater Boston Area')
    ''
    """
    raw = _txt(text)
    if not raw:
        return ""

    parts = [p.strip().lower().strip(".") for p in raw.split(",")]
    parts = [p for p in parts if p]
    # The whole string is tried last: "Russian Federation" has no comma, but a
    # part of a longer location should win over a loose whole-string match.
    candidates = list(reversed(parts)) + [raw.lower().strip(".")]

    for part in candidates:
        if part in _AMBIGUOUS_LOCATIONS:
            return ""
        if part in _LOCATION_ALIASES:
            return _LOCATION_ALIASES[part]
        if part in _US_STATES:
            return "US"

    if resolver is not None:
        for part in candidates:
            if part in _AMBIGUOUS_LOCATIONS:
                return ""
            try:
                iso = _txt(resolver(part)).upper()
            except Exception:      # noqa: BLE001 - a donor map must not raise here
                iso = ""
            if len(iso) == 2 and iso.isalpha():
                return iso
    return ""


def country_from_tld(domain: str) -> str:
    """ISO2 implied by a ccTLD, '' for a generic or repurposed one."""
    label = _txt(domain).lower().rstrip(".").rsplit(".", 1)
    if len(label) != 2:
        return ""
    tld = label[1]
    if len(tld) != 2 or not tld.isalpha():
        return ""
    if tld in _TLD_OVERRIDES:
        return _TLD_OVERRIDES[tld]
    return tld.upper()


def org_country(
    *,
    registrant_country: str = "",
    profile_country: str = "",
    domain: str = "",
    hh_matched: bool = False,
    resolver: Optional[Any] = None,
) -> Tuple[str, int]:
    """(ISO2, corroboration_count) for where the target company is.

    Corroboration counts INDEPENDENT attestations agreeing on the winner, drawn
    from the WHOIS registrant country, the org profile's country, the ccTLD, and
    whether the RU-only hh.ru provider matched the company.

    WHY CORROBORATION MATTERS, AND WHY THE FLOOR IS 2: a WHOIS registrant country
    is frequently the PRIVACY PROXY's country, not the company's, and a ccTLD is
    cheap for anyone to buy. A single attestation would arm the geography rule on
    a `.io` startup whose registrar happens to sit in Arizona, and start
    suppressing its actual staff. Two independent sources agreeing is the
    cheapest thing that is not that.
    """
    votes: Dict[str, int] = {}

    def _vote(iso: str) -> None:
        code = _txt(iso).upper()
        if len(code) == 2 and code.isalpha():
            votes[code] = votes.get(code, 0) + 1

    for value in (registrant_country, profile_country):
        text = _txt(value)
        if not text:
            continue
        if len(text) == 2 and text.isalpha():
            _vote(text)
        else:
            _vote(country_from_location(text, resolver=resolver))

    _vote(country_from_tld(domain))
    if hh_matched:
        # hh.ru is gated on the RU objective and only covers RU/CIS employers, so
        # a match there is an independent statement that the company is Russian.
        _vote("RU")

    if not votes:
        return ("", 0)
    winner = max(sorted(votes), key=lambda k: votes[k])
    return (winner, votes[winner])


# ── Person-name normalisation ────────────────────────────────────────────────

_HONORIFICS: Tuple[str, ...] = ("mr", "mrs", "ms", "miss", "dr", "prof", "sir")
_NAME_SUFFIXES: Tuple[str, ...] = ("jr", "sr", "ii", "iii", "iv", "phd", "mba",
                                   "cissp", "ocp", "pmp", "msc", "bsc")


def norm_person(name: str) -> str:
    """Case-folded, punctuation-stripped person name for set membership.

    Applied to BOTH sides of every name comparison, so a mismatch is a real
    mismatch rather than a stray period. Honorifics and credential suffixes go,
    because LinkedIn headlines carry them and Active Directory does not.
    """
    text = _txt(name).lower()
    text = re.sub(r"[^a-z0-9\s'-]+", " ", text)
    words = [w.strip("'-") for w in text.split()]
    words = [w for w in words if w and w not in _HONORIFICS and w not in _NAME_SUFFIXES]
    return " ".join(words)


def norm_person_set(names: Iterable[Any]) -> frozenset:
    """Normalise a collection of names, dropping anything that empties out."""
    out = set()
    for value in (names or ()):
        key = norm_person(value)
        if key:
            out.add(key)
    return frozenset(out)


# ── Why a run produced no shown people ───────────────────────────────────────
#
# After this change the card will often show far fewer people than before, and
# sometimes none. An empty section that used to be full reads as a regression
# unless it says WHICH KIND of empty it is -- the same reasoning as the Nessus
# panel's empty_kind and asset_ownership's.

EMPTY_NO_PROVIDER = "no_provider"      # SERP unusable AND the site crawl reached nothing
EMPTY_NO_ORG_NAME = "no_org_name"      # nothing to compare an employer against
EMPTY_NO_CANDIDATES = "no_candidates"  # providers ran and returned nobody
EMPTY_ALL_HELD = "all_held"            # candidates arrived; none carried evidence
EMPTY_KINDS: Tuple[str, ...] = (EMPTY_NO_PROVIDER, EMPTY_NO_ORG_NAME,
                                EMPTY_NO_CANDIDATES, EMPTY_ALL_HELD)

# What the card prints. EMPTY_ALL_HELD is the one that does the work: it lets
# "People & Positions (0)" read as "we looked and could not evidence anyone"
# rather than as a broken panel. EMPTY_NO_PROVIDER is the one that stops (0)
# being read as "nobody works there" when the truth is "we could not look".
EMPTY_MESSAGES: Dict[str, str] = {
    EMPTY_NO_PROVIDER: ("No people provider was reachable, so nobody was looked "
                        "for. This is not a finding that the company has no staff."),
    EMPTY_NO_ORG_NAME: ("No company name resolved, so no employer claim could be "
                        "checked. Set the campaign's company name and re-run."),
    EMPTY_NO_CANDIDATES: "The people providers ran and returned nobody.",
    EMPTY_ALL_HELD: ("Candidates were returned but none carried evidence of "
                     "employment. See Employment not established below."),
}


def empty_kind(*, providers_ok: bool, aliases: Sequence[str],
               candidates: int, shown: int) -> str:
    """Classify an empty people result. '' when it is not empty."""
    if shown:
        return ""
    if not providers_ok:
        return EMPTY_NO_PROVIDER
    if not aliases:
        return EMPTY_NO_ORG_NAME
    if not candidates:
        return EMPTY_NO_CANDIDATES
    return EMPTY_ALL_HELD


# ── The gate ─────────────────────────────────────────────────────────────────


def build_context(
    *,
    aliases: Iterable[str],
    org_iso2: str = "",
    org_corroboration: int = 0,
    ad_names: Optional[Iterable[str]] = None,
    corp_email_names: Optional[Iterable[str]] = None,
    site_names: Optional[Iterable[str]] = None,
    recruiter_names: Optional[Iterable[str]] = None,
    geo_gate: bool = True,
    employer_min: int = EMPLOYER_MATCH_MIN,
    reported_min: int = TIER_REPORTED_MIN,
    resolver: Optional[Any] = None,
) -> Dict[str, Any]:
    """Everything `assess` needs, resolved once for the whole roster.

    The four name sets are the org-side evidence. Each must be built from a
    source that is ALREADY attributed to the target -- AD accounts, addresses on
    the target domain, names the company published, contacts on the company's own
    vacancies -- and each is normalised here so callers cannot forget to.

    ad_names in particular must be derived from `source` starting with
    'sharphound', NOT from "is there already an individual with this name". WF13's
    own earlier ungated runs wrote individual nodes for the false positives, so a
    node-existence test would confirm its own garbage.
    """
    alias_list = tuple(a for a in (_txt(x) for x in (aliases or ())) if a)
    armed = bool(geo_gate and org_iso2 and org_corroboration >= GEO_MIN_CORROBORATION)
    return {
        "aliases": alias_list,
        "org_iso2": _txt(org_iso2).upper(),
        "org_corroboration": int(org_corroboration or 0),
        "ad_names": norm_person_set(ad_names or ()),
        "corp_email_names": norm_person_set(corp_email_names or ()),
        "site_names": norm_person_set(site_names or ()),
        "recruiter_names": norm_person_set(recruiter_names or ()),
        "geo_gate": bool(geo_gate),
        "geo_armed": armed,
        "geo_state": ("armed" if armed else ("off" if not geo_gate else "not_corroborated")),
        "employer_min": int(employer_min),
        "reported_min": int(reported_min),
        "resolver": resolver,
    }


def assess(person: Mapping[str, Any], ctx: Mapping[str, Any]) -> Dict[str, Any]:
    """Weigh one candidate against the target. Never raises, never mutates.

    Returns a dict carrying tier, score, edge_label, the evidence and
    contradiction code lists, the employer comparison, and `why` -- the sentence
    an operator reads.
    """
    aliases = ctx.get("aliases") or ()
    name_key = norm_person(person.get("name"))

    evidence: List[str] = []
    contradictions: List[str] = []

    # ── org-side evidence ────────────────────────────────────────────────────
    if name_key and name_key in (ctx.get("ad_names") or frozenset()):
        evidence.append(EV_AD_PRESENT)
    if person.get("site_named") or (name_key and name_key in (ctx.get("site_names") or frozenset())):
        evidence.append(EV_SITE_NAMED)
    if name_key and name_key in (ctx.get("corp_email_names") or frozenset()):
        evidence.append(EV_CORP_EMAIL)
    if name_key and name_key in (ctx.get("recruiter_names") or frozenset()):
        evidence.append(EV_RECRUITER)

    # ── the person's own claim ───────────────────────────────────────────────
    verdict, employer_score = employer_verdict(
        person.get("employer"), aliases, match_min=int(ctx.get("employer_min") or EMPLOYER_MATCH_MIN)
    )
    if verdict == VERDICT_MATCH:
        evidence.append(EV_EMPLOYER_MATCH)
    elif verdict == VERDICT_OTHER:
        contradictions.append(CX_EMPLOYER_OTHER)
    elif verdict == VERDICT_ABSENT:
        contradictions.append(CX_NO_EMPLOYER)

    job_title = _txt(person.get("job_title"))
    headline_only = bool(person.get("employer_from_headline")) or (
        not job_title and bool(_txt(person.get("headline")))
    )
    if job_title and not is_company_headline(job_title, aliases):
        evidence.append(EV_ROLE_TITLE)
    if headline_only:
        contradictions.append(CX_HEADLINE_ONLY)

    # ── geography ────────────────────────────────────────────────────────────
    person_iso2 = ""
    if ctx.get("geo_armed"):
        person_iso2 = country_from_location(person.get("location"),
                                            resolver=ctx.get("resolver"))
        if person_iso2 and person_iso2 != _txt(ctx.get("org_iso2")).upper():
            contradictions.append(CX_GEO_CONFLICT)

    # ── score ────────────────────────────────────────────────────────────────
    #
    # A contradiction drawn from the person's own public profile cannot rebut the
    # organisation's own records. Without this, a real AD user whose LinkedIn is
    # two jobs out of date takes -60 and ranks below a total stranger. The
    # contradictions are still recorded and still displayed -- they just score 0.
    score = sum(EVIDENCE_WEIGHTS.get(code, 0) for code in evidence)
    org_side = bool(set(evidence) & set(ORG_SIDE_EVIDENCE))
    if not org_side:
        score += sum(CONTRADICTION_WEIGHTS.get(code, 0) for code in contradictions)

    reported_min = int(ctx.get("reported_min") or TIER_REPORTED_MIN)
    if score >= TIER_CONFIRMED_MIN:
        tier = TIER_CONFIRMED
    elif score >= reported_min:
        tier = TIER_REPORTED
    elif CX_EMPLOYER_OTHER in contradictions:
        tier = TIER_CONTRADICTED
    else:
        tier = TIER_WEAK

    out: Dict[str, Any] = {
        "tier": tier,
        "employment_score": int(score),
        "edge_label": LABEL_FOR_TIER.get(tier, ""),
        "evidence": evidence,
        "contradictions": contradictions,
        "employer_verdict": verdict,
        "employer_score": int(employer_score),
        "employer_named": _txt(person.get("employer")),
        "person_country": person_iso2,
    }
    out["why"] = evidence_string(out, ctx)
    return out


# ── Operator-facing explanation ──────────────────────────────────────────────
#
# The tier says how much a row is worth; this says why. "weak" on its own tells
# an operator nothing they can act on or overrule.

_EVIDENCE_PHRASING: Dict[str, str] = {
    EV_AD_PRESENT: "has an Active Directory account",
    EV_SITE_NAMED: "named on the company's own website",
    EV_CORP_EMAIL: "has an address on the target domain",
    EV_RECRUITER: "listed on the company's own vacancy",
    EV_ROLE_TITLE: "states a role",
}

_CONTRADICTION_PHRASING: Dict[str, str] = {
    CX_NO_EMPLOYER: "names no employer; returned only by a search for the company name",
    CX_HEADLINE_ONLY: "headline carries a company name where a role should be",
}

# Contradictions that describe an ACTUAL CONFLICT rather than a missing signal.
# The distinction only matters once org-side evidence has suppressed the score
# penalty: "their profile names Globex" is still worth telling an operator,
# because it probably means a stale profile, while "names no employer" is just
# noise about a provider that was never going to supply one. Printing the latter
# on a person the company published on its own website produced the sentence
# "named on the company's own website; ...returned only by a search for the
# company name", which is both contradictory and untrue of that row.
_CONFLICT_CONTRADICTIONS: Tuple[str, ...] = (CX_EMPLOYER_OTHER, CX_GEO_CONFLICT)


def evidence_string(assessment: Mapping[str, Any],
                    ctx: Optional[Mapping[str, Any]] = None) -> str:
    """One sentence explaining a verdict, for the card and the export.

    >>> a = {'evidence': ['employer_match'], 'contradictions': [],
    ...      'employer_named': 'Primer Avia', 'employer_score': 95}
    >>> evidence_string(a)
    'profile names Primer Avia (95/100)'
    """
    parts: List[str] = []
    evidence = list(assessment.get("evidence") or ())
    contradictions = list(assessment.get("contradictions") or ())

    for code in evidence:
        if code == EV_EMPLOYER_MATCH:
            named = assessment.get("employer_named") or "the target"
            parts.append("profile names %s (%d/100)"
                         % (named, int(assessment.get("employer_score") or 0)))
        elif code in _EVIDENCE_PHRASING:
            parts.append(_EVIDENCE_PHRASING[code])

    # When the organisation's own records confirm the person, the contradictions
    # scored nothing (see `assess`), so rendering them as though they counted
    # misleads. Keep the real conflicts, drop the absent-signal ones.
    org_side = bool(set(evidence) & set(ORG_SIDE_EVIDENCE))
    for code in contradictions:
        if org_side and code not in _CONFLICT_CONTRADICTIONS:
            continue
        if code == CX_EMPLOYER_OTHER:
            named = assessment.get("employer_named") or "another company"
            suffix = " (profile may be out of date)" if org_side else ""
            parts.append("profile names %s, not the target%s" % (named, suffix))
        elif code == CX_GEO_CONFLICT:
            org_iso = _txt((ctx or {}).get("org_iso2")) or "the target's country"
            parts.append("located %s, target is %s"
                         % (assessment.get("person_country") or "elsewhere", org_iso))
        elif code in _CONTRADICTION_PHRASING:
            parts.append(_CONTRADICTION_PHRASING[code])

    return "; ".join(parts) if parts else "no employment evidence"


# ── Partition ────────────────────────────────────────────────────────────────


def partition(
    rows: Iterable[Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Split assessed rows into (shown, held, counters).

    Each row must already carry the keys `assess` returns. Both lists come back
    sorted by tier then score, descending -- which is also what makes the graph
    write's cap meaningful: truncating an unsorted list at 120 keeps an arbitrary
    120, while truncating this one keeps the best-evidenced 120.
    """
    shown: List[Dict[str, Any]] = []
    held: List[Dict[str, Any]] = []
    by_tier: Dict[str, int] = {tier: 0 for tier in TIERS}
    by_contradiction: Dict[str, int] = {}
    by_evidence: Dict[str, int] = {}

    for row in rows:
        tier = str(row.get("tier") or TIER_WEAK)
        by_tier[tier] = by_tier.get(tier, 0) + 1
        for code in (row.get("contradictions") or ()):
            by_contradiction[code] = by_contradiction.get(code, 0) + 1
        for code in (row.get("evidence") or ()):
            by_evidence[code] = by_evidence.get(code, 0) + 1
        (shown if tier in SHOWN_TIERS else held).append(dict(row))

    def _key(row: Mapping[str, Any]) -> Tuple[int, int, str]:
        return (
            -_TIER_RANK.get(str(row.get("tier") or ""), 0),
            -int(row.get("employment_score") or 0),
            str(row.get("name") or "").lower(),
        )

    shown.sort(key=_key)
    held.sort(key=_key)

    counters: Dict[str, Any] = {
        "candidates": len(shown) + len(held),
        "shown": len(shown),
        "held": len(held),
        "confirmed": by_tier.get(TIER_CONFIRMED, 0),
        "reported": by_tier.get(TIER_REPORTED, 0),
        "weak": by_tier.get(TIER_WEAK, 0),
        "contradicted": by_tier.get(TIER_CONTRADICTED, 0),
        "by_contradiction": by_contradiction,
        "by_evidence": by_evidence,
    }
    return (shown, held, counters)


def employment_labels() -> List[str]:
    """Every label a reader should treat as an employment assertion."""
    return sorted(EMPLOYMENT_LABELS)
