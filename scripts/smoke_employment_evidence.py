#!/usr/bin/env python3
"""
Offline smoke test for scripts/employment_evidence.py.

The cases are the live failure this module was written for: a domain recon on a
Russian target returned 34 "People & Positions", nearly all of whom were US-based
LinkedIn profiles that a quoted company-name search happened to surface, and all
34 were written to the graph as Individual -[WORKS_FOR]-> Company.

What it pins, and why each one is here rather than trusted:

  * NOTHING PROFILE-ONLY REACHES `confirmed`. A profile that names the target and
    states a role scores 30 against a floor of 40. This is the structural
    decision -- a search engine cannot confirm employment -- and it has to hold
    arithmetically, not just by convention.
  * Org-side evidence beats a profile-side contradiction. A real AD user whose
    LinkedIn is two jobs out of date must not be demoted below a stranger.
  * The geography rule stays DISARMED below two independent attestations. One
    WHOIS registrant country is frequently the privacy proxy's, so arming on it
    would suppress real staff at any `.io` startup with an Arizona registrar.
  * An unresolvable location NEVER contradicts. "Greater Boston Area" resolves to
    '' and the row keeps whatever it earned -- a suppressed true positive is
    invisible in a way a shown false positive is not.
  * is_company_headline() is WORD-ALIGNED. The previous raw-substring version
    returned True for the genuine job title "Information Security" against
    "Example Harbor Information Security", blanking it.
  * The 72 floor refuses "Example Harbor Corp" for "Example Harbor
    Information Security" -- the same case, and the same number, as EDGAR_MIN_SCORE.
  * Held rows carry NO edge label, in either held tier.

Usage:
    python3 scripts/smoke_employment_evidence.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import employment_evidence as ee  # noqa: E402

FAILURES: list[str] = []

ALIASES = ("Primer Avia", "PRIMER AVIA GROUP")


def check(label: str, cond: bool, detail: str = "") -> None:
    if cond:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s%s" % (label, (" -- " + detail) if detail else ""))
        FAILURES.append(label)


def section(t: str) -> None:
    print("\n-- %s" % t)


def ru_ctx(**over):
    """A Russian target with the geography rule armed (corroboration 2)."""
    kwargs = dict(aliases=ALIASES, org_iso2="RU", org_corroboration=2)
    kwargs.update(over)
    return ee.build_context(**kwargs)


# ── company-name comparison ──────────────────────────────────────────────────


def test_employer_verdict() -> None:
    section("employer_verdict")

    v, s = ee.employer_verdict("Primer Avia LLC", ALIASES)
    check("suffix-only difference is a match", v == ee.VERDICT_MATCH and s >= 72,
          "%s/%d" % (v, s))

    # The case that set EDGAR_MIN_SCORE: "example harbor" is half of "example
    # harbor information security", which is a weak claim to be the same company.
    v, s = ee.employer_verdict("Example Harbor Corp",
                               ("Example Harbor Information Security",))
    check("partial containment is NOT a match", v != ee.VERDICT_MATCH and s == 64,
          "%s/%d" % (v, s))

    v, s = ee.employer_verdict("Globex Industries", ALIASES)
    check("unrelated company is 'other'", v == ee.VERDICT_OTHER, "%s/%d" % (v, s))

    v, s = ee.employer_verdict("", ALIASES)
    check("empty employer is 'absent'", v == ee.VERDICT_ABSENT, v)

    v, s = ee.employer_verdict("Primer Avia", ())
    check("no aliases is 'absent', not a crash", v == ee.VERDICT_ABSENT, v)

    # A script the matcher cannot romanise must never read as "a different
    # company" -- that would mark a genuine employee contradicted. Cyrillic is
    # handled by transliteration (see test_transliteration); Japanese is not, and
    # CN/JP targets are live cases rather than hypotheticals.
    v, s = ee.employer_verdict("\u682a\u5f0f\u4f1a\u793e\u30c8\u30e8\u30bf", ALIASES)
    check("an unromanisable employer is 'unclear', never 'other'",
          v == ee.VERDICT_UNCLEAR, "%s/%d" % (v, s))
    a = ee.assess({"name": "I Petrov", "job_title": "Engineer",
                   "employer": "\u682a\u5f0f\u4f1a\u793e\u30c8\u30e8\u30bf",
                   "location": "Moscow, Russia"}, ru_ctx())
    check("...so the row is not contradicted",
          ee.CX_EMPLOYER_OTHER not in a["contradictions"], str(a["contradictions"]))


def test_is_company_headline() -> None:
    section("is_company_headline (the word-alignment fix)")

    # THE REGRESSION. The old raw-substring test normalised both sides, found
    # "informationsecurity" inside "exampleharborinformationsecurity" and returned
    # True -- blanking a genuine job title.
    check("genuine title inside the employer name is NOT a headline",
          ee.is_company_headline("Information Security",
                                 ("Example Harbor Information Security",)) is False)

    check("the company name itself IS a headline",
          ee.is_company_headline("Example Harbor Information Security",
                                 ("Example Harbor Information Security",)) is True)

    check("an ordinary role is not a headline",
          ee.is_company_headline("Security Engineer", ALIASES) is False)

    check("empty title is not a headline",
          ee.is_company_headline("", ALIASES) is False)


# ── Cyrillic ─────────────────────────────────────────────────────────────────


def test_transliteration() -> None:
    section("Cyrillic transliteration")

    check("Cyrillic romanises", ee.transliterate_cyrillic(
        "\u041e\u041e\u041e \u041f\u0420\u0418\u041c\u0415\u0420 \u0410\u0412\u0418\u0410") == "OOO PRIMER AVIA")
    check("Latin is left alone",
          ee.transliterate_cyrillic("Primer Avia") == "Primer Avia")
    check("multi-letter mappings", ee.transliterate_cyrillic(
        "\u0429\u0443\u043a\u0438\u043d").lower() == "shchukin")

    # Corporate forms must go: name_score scores containment as the ratio of the
    # shorter name to the longer, so an unstripped "ooo" drops a perfect match
    # from 95 to 82 and a three-word name below the floor entirely.
    check("Russian corporate form is stripped", ee.comparable_company(
        "\u041e\u041e\u041e \u041f\u0420\u0418\u041c\u0415\u0420 \u0410\u0412\u0418\u0410") == "primer avia")
    check("...also when the company wrote it in Latin itself",
          ee.comparable_company("OOO Primer Avia") == "primer avia")
    check("Ukrainian corporate form is stripped",
          ee.comparable_company("\u0422\u041e\u0412 Example").startswith("example"))

    # comparable_company doubles as org_aliases' DEDUPE KEY, so it has to strip
    # the Latin suffixes too. When it did not, "Example Corp." and the weak
    # domain-derived seed "example" stopped collapsing into one alias and the
    # seed was promoted to a first-class alias of its own -- confirmed live. A
    # seed that is a common word would then widen the gate on a name nobody
    # chose as an alias.
    check("Latin suffixes are stripped as well",
          ee.comparable_company("Example Corp.") == "example",
          ee.comparable_company("Example Corp."))
    check("...so a name and its bare form dedupe to ONE alias",
          ee.org_aliases(linkedin_company_name="Example Corp.",
                         org_seed="example") == ("Example Corp.",))

    # "IP" is a very common English token (intellectual property, internet
    # protocol) and ИП is rare inside a name string, so stripping it would cost
    # more precision than it buys.
    check("'IP' is NOT treated as a corporate form",
          ee.comparable_company("IP Solutions") == "ip solutions",
          ee.comparable_company("IP Solutions"))

    # THE POINT OF ALL OF IT: a profile written in Cyrillic can now earn a match
    # against the company's Latin branding, in both directions.
    v, s = ee.employer_verdict(
        "\u041e\u041e\u041e \u041f\u0420\u0418\u041c\u0415\u0420 \u0410\u0412\u0418\u0410", ALIASES)
    check("a Cyrillic employer MATCHES the Latin alias",
          v == ee.VERDICT_MATCH and s == 100, "%s/%d" % (v, s))
    v, s = ee.employer_verdict("Primer Avia", (
        "\u041e\u041e\u041e \u041f\u0420\u0418\u041c\u0415\u0420 \u0410\u0412\u0418\u0410",))
    check("...and a Latin employer matches a Cyrillic alias",
          v == ee.VERDICT_MATCH and s == 100, "%s/%d" % (v, s))

    # Precision must survive it: a DIFFERENT Russian company still fails.
    v, s = ee.employer_verdict(
        "\u0410\u041e \u0420\u043e\u043c\u0430\u0448\u043a\u0430", ALIASES)
    check("a different Russian company is still refused",
          v != ee.VERDICT_MATCH, "%s/%d" % (v, s))

    # A Cyrillic-only company name used to be dropped from the alias set for
    # normalising to "", leaving the gate nothing to compare against.
    al = ee.org_aliases(linkedin_company_name="\u041f\u0420\u0418\u041c\u0415\u0420 \u0410\u0412\u0418\u0410")
    check("a Cyrillic-only alias survives", len(al) == 1, str(al))
    al2 = ee.org_aliases(linkedin_company_name="\u041e\u041e\u041e \u041f\u0420\u0418\u041c\u0415\u0420 \u0410\u0412\u0418\u0410",
                         org_seed="OOO Primer Avia")
    check("the same name in two scripts dedupes to one alias", len(al2) == 1, str(al2))

    # End to end: the Russian employee the old code marked contradicted.
    a = ee.assess({"name": "Ivan Petrov", "job_title": "Security Engineer",
                   "employer": "\u041e\u041e\u041e \u041f\u0420\u0418\u041c\u0415\u0420 \u0410\u0412\u0418\u0410",
                   "location": "Moscow, Russia"}, ru_ctx())
    check("a Russian employee is now reported, not contradicted",
          a["tier"] == ee.TIER_REPORTED, "%s/%d" % (a["tier"], a["employment_score"]))


# ── geography ────────────────────────────────────────────────────────────────


def test_country_from_location() -> None:
    section("country_from_location")

    check("country wins over the state", ee.country_from_location(
        "Denver, Colorado, United States") == "US")
    check("bare US state resolves", ee.country_from_location("Austin, Texas") == "US")
    check("Russia resolves", ee.country_from_location("Moscow, Russia") == "RU")
    check("Russian Federation resolves",
          ee.country_from_location("Russian Federation") == "RU")

    # No city table, deliberately. Guessing US here is how a real employee gets
    # silently suppressed.
    check("a metro area does not resolve",
          ee.country_from_location("Greater Boston Area") == "")
    check("empty does not resolve", ee.country_from_location("") == "")

    # Country AND US state. Silence is the safe direction.
    check("ambiguous 'Georgia' does not resolve",
          ee.country_from_location("Atlanta, Georgia") == "")

    def resolver(part):
        return "PT" if part == "portugalia" else ""

    check("donated resolver is consulted",
          ee.country_from_location("Lisboa, Portugalia", resolver=resolver) == "PT")
    check("a raising resolver does not propagate",
          ee.country_from_location("x", resolver=lambda p: 1 / 0) == "")


def test_org_country() -> None:
    section("org_country corroboration")

    iso, n = ee.org_country(registrant_country="RU", domain="primer-avia.test",
                            hh_matched=True)
    check("WHOIS + hh.ru corroborate", (iso, n) == ("RU", 2), "%s/%d" % (iso, n))

    iso, n = ee.org_country(registrant_country="RU", domain="primer-avia.test")
    check("WHOIS alone is one attestation", (iso, n) == ("RU", 1), "%s/%d" % (iso, n))

    iso, n = ee.org_country(domain="example.ru")
    check("ccTLD alone is one attestation", (iso, n) == ("RU", 1), "%s/%d" % (iso, n))

    # A repurposed ccTLD is not a country claim.
    iso, n = ee.org_country(domain="example.io")
    check(".io contributes nothing", (iso, n) == ("", 0), "%s/%d" % (iso, n))

    iso, n = ee.org_country(registrant_country="Russia", profile_country="RU",
                            domain="example.com")
    check("a country NAME resolves and corroborates", (iso, n) == ("RU", 2),
          "%s/%d" % (iso, n))

    check(".uk maps to GB", ee.country_from_tld("example.co.uk") == "GB")


# ── the gate ─────────────────────────────────────────────────────────────────


def test_profile_only_cannot_confirm() -> None:
    section("profile-only evidence cannot reach 'confirmed'")

    row = {"name": "Ivan Petrov", "job_title": "Security Engineer",
           "employer": "Primer Avia", "location": "Moscow, Russia"}
    a = ee.assess(row, ru_ctx())
    check("named employer + role is 'reported'", a["tier"] == ee.TIER_REPORTED, a["tier"])
    check("  scores exactly 30", a["employment_score"] == 30, str(a["employment_score"]))
    check("  gets CLAIMS_WORKS_FOR", a["edge_label"] == ee.CLAIMS_WORKS_FOR,
          a["edge_label"])

    # The structural guarantee, restated as arithmetic.
    ceiling = (ee.EVIDENCE_WEIGHTS[ee.EV_EMPLOYER_MATCH]
               + ee.EVIDENCE_WEIGHTS[ee.EV_ROLE_TITLE])
    check("profile-side ceiling is below the confirmed floor",
          ceiling < ee.TIER_CONFIRMED_MIN, "%d < %d" % (ceiling, ee.TIER_CONFIRMED_MIN))


def test_org_side_confirms() -> None:
    section("org-side evidence confirms")

    row = {"name": "Ivan Petrov", "job_title": "Security Engineer",
           "employer": "Primer Avia", "location": "Moscow, Russia",
           "site_named": True}
    a = ee.assess(row, ru_ctx())
    check("named on the company's own site is 'confirmed'",
          a["tier"] == ee.TIER_CONFIRMED, a["tier"])
    check("  gets WORKS_FOR", a["edge_label"] == ee.WORKS_FOR, a["edge_label"])

    # Every org-side weight alone clears the floor -- by construction, not by
    # coincidence.
    for code in ee.ORG_SIDE_EVIDENCE:
        check("  %s alone clears the confirmed floor" % code,
              ee.EVIDENCE_WEIGHTS[code] >= ee.TIER_CONFIRMED_MIN)

    a = ee.assess({"name": "Carol Ops", "job_title": "Sysadmin"},
                  ru_ctx(ad_names=["Carol  Ops"]))
    check("AD presence confirms despite no employer string",
          a["tier"] == ee.TIER_CONFIRMED, a["tier"])


def test_contradicted() -> None:
    section("a profile that names a different company")

    row = {"name": "J Miller", "job_title": "Security Engineer",
           "employer": "Globex Industries", "location": "Moscow, Russia"}
    a = ee.assess(row, ru_ctx())
    check("tier is 'contradicted'", a["tier"] == ee.TIER_CONTRADICTED, a["tier"])
    check("  carries NO edge label", a["edge_label"] == "", a["edge_label"])
    check("  why names the other company", "Globex Industries" in a["why"], a["why"])

    # Org-side evidence beats a profile-side contradiction: the LinkedIn is
    # simply out of date. The contradiction is still recorded.
    a = ee.assess(row, ru_ctx(ad_names=["J Miller"]))
    check("AD account overrides the stale profile",
          a["tier"] == ee.TIER_CONFIRMED, a["tier"])
    check("  contradiction is still listed",
          ee.CX_EMPLOYER_OTHER in a["contradictions"], str(a["contradictions"]))
    # A real conflict still reaches the operator, framed as the stale profile it
    # probably is; an ABSENT-signal contradiction would be noise here and is
    # dropped, because it scored nothing once AD confirmed the person.
    check("  ...and reads as a possibly-stale profile",
          "out of date" in a["why"], a["why"])
    site = ee.assess({"name": "Jane Roe", "job_title": "CTO", "employer": "",
                      "site_named": True}, ru_ctx())
    check("a website-sourced person is not told they came from a search",
          "returned only by a search" not in site["why"], site["why"])


def test_co_occurrence_is_weak() -> None:
    section("pure search-engine co-occurrence")

    # The dominant false positive: an indexed profile that merely contains the
    # company string somewhere.
    row = {"name": "K Ortiz", "job_title": "Recruiter", "employer": "",
           "location": "Denver, Colorado, United States"}
    a = ee.assess(row, ru_ctx())
    check("tier is 'weak'", a["tier"] == ee.TIER_WEAK, a["tier"])
    check("  no employer is recorded as the contradiction",
          ee.CX_NO_EMPLOYER in a["contradictions"], str(a["contradictions"]))
    check("  carries NO edge label", a["edge_label"] == "", a["edge_label"])


def test_geo_conflict() -> None:
    section("geography")

    row = {"name": "R Chen", "job_title": "Cloud Engineer",
           "employer": "Primer Avia", "location": "Denver, Colorado, United States"}

    a = ee.assess(row, ru_ctx())
    check("US person + corroborated RU target is held",
          a["tier"] == ee.TIER_WEAK, a["tier"])
    check("  conflict is recorded",
          ee.CX_GEO_CONFLICT in a["contradictions"], str(a["contradictions"]))

    # THE GUARD. One attestation is not enough to arm the rule.
    a = ee.assess(row, ru_ctx(org_corroboration=1))
    check("uncorroborated org country leaves the rule disarmed",
          a["tier"] == ee.TIER_REPORTED, a["tier"])
    check("  and says so",
          ru_ctx(org_corroboration=1)["geo_state"] == "not_corroborated")

    a = ee.assess(row, ru_ctx(geo_gate=False))
    check("the operator can switch it off", a["tier"] == ee.TIER_REPORTED, a["tier"])
    check("  and that is reported as 'off'", ru_ctx(geo_gate=False)["geo_state"] == "off")

    # An unresolvable location never contradicts.
    a = ee.assess(dict(row, location="Greater Boston Area"), ru_ctx())
    check("an unresolvable location does not contradict",
          a["tier"] == ee.TIER_REPORTED, a["tier"])

    # Geography must not override the organisation's own records.
    a = ee.assess(dict(row, site_named=True), ru_ctx())
    check("org-side evidence survives a geo conflict",
          a["tier"] == ee.TIER_CONFIRMED, a["tier"])


def test_headline_only() -> None:
    section("company-name headline")

    row = {"name": "S Sidorov", "job_title": "", "headline": "Primer Avia",
           "employer": "Primer Avia", "employer_from_headline": True,
           "location": "Moscow, Russia"}
    a = ee.assess(row, ru_ctx())
    check("headline-derived employer is flagged",
          ee.CX_HEADLINE_ONLY in a["contradictions"], str(a["contradictions"]))
    # 25 (employer) - 5 (headline only) = 20, below the reported floor of 25.
    check("  and falls below the reported floor", a["tier"] == ee.TIER_WEAK,
          "%s/%d" % (a["tier"], a["employment_score"]))


# ── partition and counters ───────────────────────────────────────────────────


def test_partition() -> None:
    section("partition")

    ctx = ru_ctx()
    rows = []
    for person in (
        {"name": "Ivan Petrov", "job_title": "Security Engineer",
         "employer": "Primer Avia", "location": "Moscow, Russia", "site_named": True},
        {"name": "S Sidorov", "job_title": "DevOps", "employer": "Primer Avia",
         "location": "Moscow, Russia"},
        {"name": "J Miller", "job_title": "Engineer", "employer": "Globex",
         "location": "Denver, Colorado, United States"},
        {"name": "K Ortiz", "job_title": "Recruiter", "employer": "",
         "location": "Austin, Texas"},
    ):
        rows.append(dict(person, **ee.assess(person, ctx)))

    shown, held, counters = ee.partition(rows)

    check("two shown, two held", (len(shown), len(held)) == (2, 2),
          "%d/%d" % (len(shown), len(held)))
    check("shown is sorted strongest first", shown[0]["name"] == "Ivan Petrov",
          shown[0]["name"])
    check("every shown row has a writable label",
          all(r["edge_label"] in ee.WRITABLE_LABELS for r in shown))
    check("no held row has any label",
          all(r["edge_label"] == "" for r in held))
    check("counters add up",
          counters["candidates"] == 4 and counters["shown"] == 2
          and counters["confirmed"] == 1 and counters["reported"] == 1,
          str(counters))
    check("contradictions are tallied",
          counters["by_contradiction"].get(ee.CX_NO_EMPLOYER) == 1,
          str(counters["by_contradiction"]))
    check("partition does not mutate its input",
          rows[0].get("name") == "Ivan Petrov")


def test_empty_kind() -> None:
    section("empty_kind")

    check("not empty when something is shown",
          ee.empty_kind(providers_ok=True, aliases=ALIASES, candidates=4, shown=2) == "")
    check("no provider",
          ee.empty_kind(providers_ok=False, aliases=ALIASES, candidates=0,
                        shown=0) == ee.EMPTY_NO_PROVIDER)
    check("no org name",
          ee.empty_kind(providers_ok=True, aliases=(), candidates=0,
                        shown=0) == ee.EMPTY_NO_ORG_NAME)
    check("no candidates",
          ee.empty_kind(providers_ok=True, aliases=ALIASES, candidates=0,
                        shown=0) == ee.EMPTY_NO_CANDIDATES)
    # The one that makes "(0)" legible as correct rather than broken.
    check("all held",
          ee.empty_kind(providers_ok=True, aliases=ALIASES, candidates=34,
                        shown=0) == ee.EMPTY_ALL_HELD)
    check("every kind has a message",
          all(k in ee.EMPTY_MESSAGES for k in ee.EMPTY_KINDS))


# ── vocabulary invariants ────────────────────────────────────────────────────


def test_vocabulary() -> None:
    section("label vocabulary")

    check("LIKELY_WORKS_FOR is pinned at 0",
          ee.EMPLOYMENT_WEIGHTS[ee.LIKELY_WORKS_FOR] == 0)
    check("LIKELY_WORKS_FOR is not writable",
          ee.LIKELY_WORKS_FOR not in ee.WRITABLE_LABELS)
    check("a claim ranks below a confirmation",
          0 < ee.EMPLOYMENT_WEIGHTS[ee.CLAIMS_WORKS_FOR]
          < ee.EMPLOYMENT_WEIGHTS[ee.WORKS_FOR])
    check("no held tier maps to a label",
          all(ee.LABEL_FOR_TIER[t] == "" for t in ee.HELD_TIERS))
    check("every shown tier maps to a writable label",
          all(ee.LABEL_FOR_TIER[t] in ee.WRITABLE_LABELS for t in ee.SHOWN_TIERS))
    check("the employer floor matches EDGAR_MIN_SCORE's default",
          ee.EMPLOYER_MATCH_MIN == 72)


def test_org_aliases() -> None:
    section("org_aliases")

    a = ee.org_aliases(org_seed="primer avia", linkedin_company_name="PRIMER AVIA GROUP",
                       registrant_org="REDACTED FOR PRIVACY", domain="primer-avia.test")
    check("privacy placeholder is dropped",
          not any("REDACTED" in x.upper() for x in a), str(a))
    check("linkedin name leads", a[0] == "PRIMER AVIA GROUP", str(a))
    check("suffix-equivalent names dedupe",
          len(ee.org_aliases(org_seed="Example Inc", legal_name="EXAMPLE, INC.")) == 1)
    check("the domain label is the last resort",
          ee.org_aliases(domain="primer-avia.test") == ("primer avia",))
    check("nothing at all yields no aliases", ee.org_aliases() == ())


def test_identifier_parsing() -> None:
    section("identifier parsing")

    check("a comma-separated Additional Identifiers field splits",
          ee.split_identifiers("maket-aero.test, \u041e\u041e\u041e \u041e\u0411\u0420\u0410\u0417\u0415\u0426")
          == ("maket-aero.test", "\u041e\u041e\u041e \u041e\u0411\u0420\u0410\u0417\u0415\u0426"))
    check("semicolons and newlines split too",
          len(ee.split_identifiers("a; b\nc")) == 3)
    # A slash is NOT a separator: "AC/DC Industries" is one company.
    check("a slash is left alone", ee.split_identifiers("AC/DC Industries")
          == ("AC/DC Industries",))
    check("an email yields its registrable domain",
          ee.registrable_domain("info@mail.example.co.uk") == "example.co.uk")
    check("a URL yields its registrable domain",
          ee.registrable_domain("https://www.example.com/about") == "example.com")
    check("a company name is not a domain", ee.registrable_domain("Example Inc") == "")
    check("a two-label TLD is not mistaken for the registration",
          ee.registrable_domain("a.example.co.uk") == "example.co.uk")


def test_build_identity() -> None:
    section("build_identity")

    ident = ee.build_identity(
        primary_name="Maket Aero",
        additional_ids="maket-aero.test, \u041e\u041e\u041e \u041e\u0411\u0420\u0410\u0417\u0415\u0426",
        company_email="info@maket-aero.test",
        domain="maket-aero.test")
    check("a domain-shaped identifier is a DOMAIN, not a name",
          "maket-aero.test" in ident["domains"] and
          not any("maket-aero.test" == n for n in ident["names"]), str(ident))
    check("a Cyrillic legal entity survives as a name",
          any("\u041e\u0411\u0420\u0410\u0417\u0415\u0426" in n for n in ident["names"]), str(ident["names"]))
    check("the operator's own identifiers are marked as theirs",
          ident["operator_sourced"] is True and len(ident["operator_names"]) == 2,
          str(ident))
    check("every name becomes a search term, not just the first",
          len(ident["search_terms"]) == 2, str(ident["search_terms"]))
    # The domain label is a fallback, never an extra name -- a job board queried
    # for a domain label returns thematic noise. Here it would collide with the
    # operator's own name anyway, so the test uses a target whose domain label
    # differs from everything they typed.
    other = ee.build_identity(primary_name="Example Holdings", domain="holdco.test")
    check("the domain label is not added when a real name exists",
          other["names"] == ("Example Holdings",), str(other["names"]))
    bare = ee.build_identity(domain="primer-avia.test")
    check("...but it IS the name when nothing else exists",
          bare["names"] == ("primer avia",), str(bare["names"]))
    check("...and such a run is flagged as operator-unsourced",
          bare["operator_sourced"] is False, str(bare))


def test_company_verdict() -> None:
    section("company_verdict")

    ident = ee.build_identity(
        primary_name="Maket Aero", additional_ids="\u041e\u041e\u041e \u041e\u0411\u0420\u0410\u0417\u0415\u0426",
        company_email="info@maket-aero.test", domain="maket-aero.test")

    # THE BUG. Nothing about this name relates to any identifier, and it used to
    # be adopted because it was the top row of what a provider returned.
    v = ee.company_verdict({"name": "Placeholder History Journal"}, ident)
    check("an unrelated company is refused", v["accept"] is False, str(v))
    check("...and the refusal is explainable on the card", bool(v["reason"]), str(v))
    check("...and it is not offered as a subsidiary either",
          v["relation"] == ee.REL_MENTION, str(v))

    check("the operator's legal entity matches exactly",
          ee.company_verdict({"name": "\u041e\u041e\u041e \u041e\u0411\u0420\u0410\u0417\u0415\u0426"}, ident)["accept"] is True)
    check("a Cyrillic spelling of a Latin identifier matches",
          ee.company_verdict({"name": "\u041c\u0410\u041a\u0415\u0422 \u0410\u044d\u0440\u043e"}, ident)["accept"] is True,
          str(ee.company_verdict({"name": "\u041c\u0410\u041a\u0415\u0422 \u0410\u044d\u0440\u043e"}, ident)))

    # The identification that works across a rename AND a language change.
    dv = ee.company_verdict(
        {"name": "Example Unmanned Systems", "site": "https://maket-aero.test"}, ident)
    check("a candidate serving the target's domain IS the target",
          dv["accept"] is True, str(dv))
    check("...and says so, rather than claiming a name match",
          dv["matched_domain"] == "maket-aero.test", str(dv))

    # Serving the domain and mentioning it are different claims.
    mv = ee.company_verdict(
        {"name": "Drone Reseller LLC", "description": "authorised partner of maket-aero.test"},
        ident)
    check("merely NAMING the target's domain is not being the target",
          mv["accept"] is False, str(mv))

    # A bare `in` test makes any longer domain a hit for a shorter one.
    nv = ee.company_verdict(
        {"name": "Other", "site": "https://notmaket-aero.test.example.net"}, ident)
    check("domain corroboration is host-aligned, not a substring test",
          nv["accept"] is False, str(nv))


def test_pick_company() -> None:
    section("pick_company")

    ident = ee.build_identity(primary_name="Example", domain="example.com")
    rows = [{"name": "Globex Consulting", "vacancies_open": 900},
            {"name": "Example", "vacancies_open": 2},
            {"name": "Example Logistics", "vacancies_open": 5},
            {"name": "Initech Partners - Example Spend Specialists"}]
    pick = ee.pick_company(rows, ident, tie_break=lambda c: c.get("vacancies_open"))
    check("the target is chosen on evidence, not on the biggest number",
          pick["best"]["name"] == "Example", str(pick["best"]))
    unames = [u["name"] for u in pick["units"]]
    check("a name BUILT ON the target's is a sibling brand",
          "Example Logistics" in unames, str(unames))
    mnames = [m["name"] for m in pick["mentions"]]
    check("a third party that merely contains the name is not a sibling",
          "Initech Partners - Example Spend Specialists" in mnames, str(mnames))
    check("an unrelated company is a mention", "Globex Consulting" in mnames, str(mnames))

    empty = ee.pick_company([{"name": "Globex Consulting", "vacancies_open": 900}], ident)
    check("nothing is adopted when nothing matches", empty["best"] is None, str(empty))
    check("...and the near miss is handed back for the operator to recognise",
          empty["rejected"] and empty["rejected"][0]["name"] == "Globex Consulting",
          str(empty["rejected"]))
    check("pick_company survives an empty candidate set",
          ee.pick_company([], ident)["best"] is None)


def test_assess_never_raises() -> None:
    section("robustness")

    ctx = ru_ctx()
    for bad in ({}, {"name": None}, {"name": "x", "employer": None,
                                     "location": None, "job_title": None}):
        try:
            a = ee.assess(bad, ctx)
            check("assess survives %r" % (bad,), a["tier"] in ee.TIERS, str(a))
        except Exception as e:      # noqa: BLE001
            check("assess survives %r" % (bad,), False, repr(e))


def main() -> int:
    for t in (
        test_employer_verdict,
        test_is_company_headline,
        test_transliteration,
        test_country_from_location,
        test_org_country,
        test_profile_only_cannot_confirm,
        test_org_side_confirms,
        test_contradicted,
        test_co_occurrence_is_weak,
        test_geo_conflict,
        test_headline_only,
        test_partition,
        test_empty_kind,
        test_vocabulary,
        test_org_aliases,
        test_identifier_parsing,
        test_build_identity,
        test_company_verdict,
        test_pick_company,
        test_assess_never_raises,
    ):
        t()
    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("all employment_evidence checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
