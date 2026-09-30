#!/usr/bin/env python3
"""
Offline smoke test for scripts/edgar_client.py.

Fixtures are shaped after REAL SEC responses captured 2026-09-20. No network.
Every company name, CIK, ticker and filing in them is fictitious.

What it pins, and why each one is here rather than trusted:

  * THE FALSE-MATCH FLOOR. EDGAR name search is loose: "Example Harbor
    Information Security" returns EXAMPLE HARBOR CORP (an unrelated
    manufacturer) and PLACEHOLDER INFORMATION SYSTEMS. Adopting one would
    present another company's subsidiaries, registered address and state of
    incorporation as the target's. Scoring must keep them below the floor, and
    the refusal must say which registrant it declined.
  * Containment is WORD-ALIGNED. A raw substring test scored "NFO INC" at 70
    against Example Harbor Information Security, because "nfo" sits inside
    "iNFOrmation".
  * The Exhibit 21 filename pattern covers the run-on form. One large filer
    names it `xfab-2025x12x31xex211.htm` -- EX-21.1 with no separator -- and a
    `\\b` after "21" never matches it, which made its 300-entry subsidiary list
    invisible.
  * A file whose NAME matches but whose text never says "subsidiar" is refused:
    "ex21" is occasionally EX-2.1, a merger agreement.
  * Header rows are not returned as subsidiaries. Real exhibits head their
    columns "Name of Subsidiary" / "Jurisdiction of Incorporation", so an
    exact-match filter on "name" lets the header through as a company.
  * A company that is not an SEC filer reports no_match with an explanation --
    that is the NORMAL case for a private engagement target, not a failure.
  * SEC's 403-without-User-Agent is reported as a config problem, naming the
    variable.
  * A dead proxy fails closed.

Usage:
    python3 scripts/smoke_edgar_client.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ["SPOTTER_CACHE_DIR"] = tempfile.mkdtemp(prefix="spotter-smoke-edgar-")

import requests  # noqa: E402

import edgar_client  # noqa: E402
from edgar_client import (  # noqa: E402
    EdgarClient, EdgarError, name_score, normalise_company,
)

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    if cond:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s%s" % (label, (" -- " + detail) if detail else ""))
        FAILURES.append(label)


def section(t: str) -> None:
    print("\n-- %s" % t)


# ── fixtures ─────────────────────────────────────────────────────────────────

TICKERS = {
    "0": {"cik_str": 9999999, "ticker": "XCTO", "title": "CONTOSO CORP"},
    "1": {"cik_str": 2, "ticker": "EXHB", "title": "EXAMPLE HARBOR CORP"},
    "2": {"cik_str": 3, "ticker": "XPIS", "title": "PLACEHOLDER INFORMATION SYSTEMS INC"},
    "3": {"cik_str": 4, "ticker": "XNFO", "title": "NFO INC"},
    "4": {"cik_str": 5, "ticker": "XFAB", "title": "Fabrikam, Inc."},
}

SUBMISSIONS = {
    "cik": "9999999", "name": "CONTOSO CORP", "sic": "7372",
    "sicDescription": "Services-Prepackaged Software", "entityType": "operating",
    "stateOfIncorporation": "WA", "tickers": ["XCTO"], "exchanges": ["Nasdaq"],
    "formerNames": [], "website": "", "phone": "303-555-0100", "ein": "001234567",
    "fiscalYearEnd": "0630",
    "addresses": {"business": {"street1": "ONE CONTOSO WAY", "street2": None,
                               "city": "SPRINGFIELD", "stateOrCountry": "WA",
                               "zipCode": "99999-0001"}},
    "filings": {"recent": {
        "form": ["8-K", "10-K", "10-Q"],
        "accessionNumber": ["0000000001-26-000001", "0000000001-26-000002",
                            "0000000001-26-000003"],
        "filingDate": ["2026-08-01", "2026-07-29", "2026-05-01"],
    }},
}

# A real filer's filename shape (renamed): EX-21.1 with no separator at all.
FILING_INDEX = {"directory": {"item": [
    {"name": "0000000001-26-000002-index.html"},
    {"name": "xcto-20260630.htm"},
    {"name": "xcto-ex231.htm"},          # EX-23.1, must NOT match
    {"name": "xfab-2025x12x31xex211.htm"},   # EX-21.1 run-on, MUST match
    {"name": "xcto-ex311.htm"},
]}}

EX21_HTML = """<html><body>
<p>Exhibit 21 SUBSIDIARIES OF REGISTRANT. The following is a list of subsidiaries.</p>
<table>
<tr><td>Name of Subsidiary</td><td>Jurisdiction of Incorporation</td></tr>
<tr><td>Contoso Ireland Research Unlimited Company</td><td>Ireland</td></tr>
<tr><td>Contoso Networks Corporation</td><td>United States</td></tr>
<tr><td>Contoso Games, Inc.</td><td>United States</td></tr>
</table></body></html>"""

# Same filename shape, but it is a merger agreement.
EX21_WRONG = """<html><body><p>Exhibit 2.1 AGREEMENT AND PLAN OF MERGER by and
among Sample Corp and Beta Inc.</p><table><tr><td>Sample Corp</td><td>Delaware</td></tr>
</table></body></html>"""

ROUTES = {
    "/files/company_tickers.json": json.dumps(TICKERS),
    "/submissions/CIK0009999999.json": json.dumps(SUBMISSIONS),
    "/index.json": json.dumps(FILING_INDEX),
    "xfab-2025x12x31xex211.htm": EX21_HTML,
}


class FakeResponse:
    def __init__(self, body: str, status: int = 200):
        self._b = (body or "").encode("utf-8")
        self.status_code = status
        self.ok = 200 <= status < 400

    def iter_content(self, n):
        for i in range(0, len(self._b), n):
            yield self._b[i:i + n]

    def close(self):
        pass

    @property
    def text(self):
        return self._b.decode("utf-8")

    def json(self):
        return json.loads(self.text)


def install(extra: dict | None = None, status: int = 200, fail_with=None):
    seen: list[str] = []
    table = dict(ROUTES)
    table.update(extra or {})

    def fake_get(url, **kw):
        seen.append(url)
        if fail_with is not None:
            raise fail_with
        if status != 200:
            return FakeResponse("blocked", status)
        for suffix, body in table.items():
            if url.endswith(suffix):
                return FakeResponse(body)
        if "browse-edgar" in url:
            return FakeResponse("<feed><company-info><cik>0000000002</cik>"
                                "<conformed-name>EXAMPLE HARBOR CORP</conformed-name>"
                                "</company-info></feed>")
        return FakeResponse("not found", 404)

    edgar_client.requests.get = fake_get
    return seen


_REAL_GET = edgar_client.requests.get


def fresh(**kw) -> EdgarClient:
    kw.setdefault("cache_dir", tempfile.mkdtemp())
    return EdgarClient(**kw)


# ── tests ────────────────────────────────────────────────────────────────────

def test_normalisation():
    section("name normalisation")
    check("corporate suffixes stripped",
          normalise_company("Sample Corporation, Inc.") == "sample", normalise_company("Sample Corporation, Inc."))
    check("case and punctuation folded",
          normalise_company("FABRIKAM, INC.") == "fabrikam", normalise_company("FABRIKAM, INC."))
    check("multi-word names survive",
          normalise_company("Example Harbor Information Security")
          == "example harbor information security")


def test_scoring_floor():
    section("the false-match floor")
    check("exact match scores 100", name_score("Contoso", "CONTOSO CORP") == 100)
    check("suffix-only difference scores 100", name_score("Sample", "Sample Corporation") == 100)
    check("comma/period noise ignored", name_score("Fabrikam", "FABRIKAM, INC.") == 100)

    target = "Example Harbor Information Security"
    # Stand-ins for the three registrants a live search actually returned.
    for other in ("EXAMPLE HARBOR CORP", "PLACEHOLDER INFORMATION SYSTEMS INC", "NFO INC"):
        sc = name_score(target, other)
        check("%s stays below the 72 floor" % other, sc < 72, str(sc))
    check("'nfo' inside 'iNFOrmation' does not score as containment",
          name_score(target, "NFO INC") < 40, str(name_score(target, "NFO INC")))
    check("a genuinely unrelated name scores low",
          name_score("Sample", "Beta Industries") < 40)
    check("the real legal name still matches",
          name_score(target, "Example Harbor Information Security Inc") == 100)
    check("a short name does not match everything containing its letters",
          name_score("Ex Holding AG", "Zzyzx Nonexistent Widgets") < 40)


def test_profile():
    section("company record")
    install()
    c = fresh()
    r = c.organization_profile("Contoso")
    p = r["profile"]
    check("matched", r["matched"] is True, str(r["errors"]))
    check("source label", r["source"] == "sec-edgar")
    check("legal name", p["name"] == "CONTOSO CORP", str(p))
    check("CIK is zero-padded", p["cik"] == "0009999999", p["cik"])
    check("SIC description becomes the industry",
          p["industry"] == "Services-Prepackaged Software", p["industry"])
    check("state of incorporation", p["state_of_incorporation"] == "WA")
    check("registered address assembled",
          p["address"] == "ONE CONTOSO WAY, SPRINGFIELD, WA, 99999-0001", p["address"])
    check("tickers and exchanges", p["tickers"] == ["XCTO"] and p["exchanges"] == ["Nasdaq"])
    check("match score is carried so an operator can judge it",
          p.get("match_score") == 100, str(p.get("match_score")))
    check("the internal filings blob is not leaked into the profile",
          "_filings" not in p, str(sorted(p)))


def test_exhibit21():
    section("Exhibit 21")
    install()
    c = fresh()
    r = c.organization_profile("Contoso")
    names = [s["name"] for s in r["related"]]
    check("the run-on EX-21.1 filename is found (xfab-...ex211.htm)",
          len(names) == 3, str(names))
    check("subsidiaries carry their jurisdiction",
          r["related"][0]["jurisdiction"] == "Ireland", str(r["related"][:1]))
    check("a header row is not returned as a subsidiary",
          not any("Name of Subsidiary" in n or "Jurisdiction" in n for n in names), str(names))
    check("the source filing is recorded",
          r["filing"].get("form") == "10-K" and r["filing"].get("document"), str(r["filing"]))
    check("EX-23.1 is not mistaken for EX-21",
          "xcto-ex231.htm" not in "".join(edgar_client._EX21_RE.findall("xcto-ex231.htm")))

    # A file whose NAME matches but which is really EX-2.1.
    install(extra={"xfab-2025x12x31xex211.htm": EX21_WRONG})
    c2 = fresh()
    r2 = c2.organization_profile("Contoso")
    check("a merger agreement is not parsed as a subsidiary list",
          r2["related"] == [], str(r2["related"]))
    check("...and the refusal explains itself",
          any("subsidiar" in e for e in r2["errors"]), str(r2["errors"]))
    check("the company profile survives that refusal", r2["matched"] is True)


def test_no_match_is_normal():
    section("a company that is not an SEC filer")
    install()
    c = fresh()
    r = c.organization_profile("Example Harbor Information Security")
    check("matched is False", r["matched"] is False)
    check("no profile is invented", r["profile"] == {})
    check("the declined registrant is named",
          any("below the" in e and "floor" in e for e in r["errors"]), str(r["errors"]))
    check("candidates are still listed so the operator can see the near misses",
          len(r["candidates"]) >= 1, str(r["candidates"][:2]))
    check("the note says how to correct it",
          any("Primary Target" in e for e in r["errors"]), str(r["errors"]))

    check("an empty company name is refused with a reason",
          fresh().organization_profile("")["errors"] != [])


def test_contact_address_required():
    section("www.sec.gov requires a contact address")
    # Measured from one container in one minute, same path:
    #   "SPOTTER-recon/1.0 (security-assessment tooling)" -> 403, 403
    #   "SPOTTER-recon/1.0 (recon@example.com)"           -> 200, 200
    # data.sec.gov accepts either, so a run can return a full company record
    # and NO subsidiaries -- losing the one thing only EDGAR can supply.
    check("a UA with no address is detected",
          edgar_client.ua_has_contact("SPOTTER-recon/1.0 (security-assessment tooling)") is False)
    check("a UA with an address is accepted",
          edgar_client.ua_has_contact("SPOTTER (a@example.com)") is True)
    check("a bare address, no parentheses, also counts",
          edgar_client.ua_has_contact("SAMPLE SPOTTER x@example.org") is True)

    c = fresh()
    check("the warning is raised UP FRONT, before anything fails",
          any("no contact address" in e and "Exhibit 21" in e for e in c.errors),
          str(c.errors))
    check("...and says the company record still loads, so it is not alarming",
          any("company record itself still loads" in e for e in c.errors), str(c.errors))

    install(status=403)
    r = fresh().organization_profile("Contoso")
    errs = " ".join(r["errors"])
    check("a 403 with no contact address blames the right thing",
          "requires a CONTACT" in errs and "EDGAR_USER_AGENT" in errs, errs[:150])
    check("...and does NOT misattribute it to rate limiting",
          "rate limiting" not in errs, errs[:150])

    install(status=403)
    r2 = fresh(user_agent="SPOTTER (a@example.com)").organization_profile("Contoso")
    errs2 = " ".join(r2["errors"])
    check("a 403 WITH a contact address is attributed to rate limiting",
          "rate limiting" in errs2, errs2[:150])
    check("a throttled run is NOT reported as 'not an SEC filer'",
          "never actually searched" in errs2 and "NOT evidence" in errs2, errs2[:200])
    check("the default UA still invents no contact address",
          "@" not in EdgarClient(cache_dir=tempfile.mkdtemp()).user_agent)


def test_403_retry_clears():
    section("a transient 403 is retried")
    calls = {"n": 0}
    real = edgar_client.requests.get

    def flaky(url, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeResponse("blocked", 403)
        for suffix, body in ROUTES.items():
            if url.endswith(suffix):
                return FakeResponse(body)
        return FakeResponse("not found", 404)

    edgar_client.requests.get = flaky
    try:
        c = fresh()
        r = c.organization_profile("Contoso")
        check("a single 403 is retried rather than surfaced",
              r["matched"] is True, str(r["errors"])[:120])
        check("...and the operator is not told about a problem that cleared",
              not any("403" in e for e in r["errors"]), str(r["errors"])[:120])
        check("the retry actually happened", calls["n"] >= 2, str(calls["n"]))
    finally:
        edgar_client.requests.get = real


def test_proxy_fails_closed():
    section("proxy fail-closed")
    install(fail_with=requests.exceptions.ProxyError("tunnel refused"))
    try:
        c = fresh(proxy_url="socks5h://127.0.0.1:9050")
        try:
            c._get("https://www.sec.gov/files/company_tickers.json")
            check("a dead proxy raises instead of going direct", False, "no exception")
        except EdgarError as e:
            check("a dead proxy raises instead of going direct",
                  "refusing to fall back to direct egress" in str(e), str(e)[:80])
        r = fresh(proxy_url="socks5h://127.0.0.1:9050").organization_profile("Contoso")
        check("organization_profile surfaces it instead of raising",
              r["matched"] is False and r["errors"] != [], str(r["errors"])[:80])
    finally:
        edgar_client.requests.get = _REAL_GET


def test_budget():
    section("request budget")
    install()
    c = fresh(max_requests=1)
    c.organization_profile("Contoso")
    check("the budget is enforced", c.budget_exhausted() is True)
    check("...and the shortfall is recorded rather than silently truncating",
          any("budget exhausted" in e for e in c.errors), str(c.errors))


def main() -> int:
    for t in (
        test_normalisation,
        test_scoring_floor,
        test_profile,
        test_exhibit21,
        test_no_match_is_normal,
        test_contact_address_required,
        test_403_retry_clears,
        test_proxy_fails_closed,
        test_budget,
    ):
        t()
    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("all edgar_client checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
