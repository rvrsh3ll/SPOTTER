#!/usr/bin/env python3
"""
Offline smoke test for scripts/serp_client.py.

Fixtures are trimmed from REAL SerpAPI responses captured 2026-09-20, so the
parsers under test are exercised by the shapes they will actually meet. The
people, employers and profile slugs in them are placeholders.

What it pins, and why each one is here rather than trusted:

  * Country subdomains normalise instead of being dropped. The existing sidecar's
    _LI_URL_RE only matches `(?:www\\.)?linkedin\\.com/in/`, so `in.linkedin.com`
    and `uk.linkedin.com` vanish -- 2 of 5 results in the live capture.
  * All three title shapes parse (`- ... at`, `- ... @`, `Name. Title at Co |`).
    A missed parse is a person silently absent from the roster.
  * Technology extraction is WORD-BOUNDARY matched. Substring matching produced
    "Go" for three of five people, purely from surnames like "Goodexample".
  * A company page that merely MENTIONS the target is not promoted to an org
    unit. The live capture returned "Example Advisors - Independent Contoso
    Spend Specialists" (renamed) for a Contoso search -- a third-party vendor.
  * A free-engine transport that returns nothing records WHY in `errors`. The
    existing sidecar swallows this into `[]`, which reads as "the company has no
    LinkedIn presence" when it means "Bing ignored our query".
  * A dead proxy FAILS CLOSED -- never retried direct.
  * The search budget is enforced, and a missing SERP_API_KEY says so.
  * No request is EVER issued to a linkedin.com host.

Usage:
    python3 scripts/smoke_serp_client.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

import serp_client  # noqa: E402
from serp_client import (  # noqa: E402
    SerpClient, SerpError, canonical_company_url, canonical_person_url,
    parse_job_title, parse_person_snippet, parse_person_title,
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


# ── fixtures (real 2026-09-20 shapes, placeholder identities) ────────────────

COMPANY_RESULTS = {
    "organic_results": [
        {"title": "Contoso", "link": "https://www.linkedin.com/company/contoso",
         "snippet": "Contoso | 1234567 followers on LinkedIn. We make industrial systems."},
        {"title": "Contoso AI", "link": "https://www.linkedin.com/company/contoso-ai",
         "snippet": "At Contoso AI we're building a new class of safer, more capable systems."},
        # A FACET of the same company, not a sibling.
        {"title": "Contoso: Jobs", "link": "https://www.linkedin.com/company/contoso/jobs",
         "snippet": "Jobs at Contoso - Senior Software Engineer,Billing"},
        # A third party that merely mentions the target. The trap this pins.
        {"title": "Example Advisors - Independent Contoso Spend Specialists",
         "link": "https://www.linkedin.com/company/example-advisors",
         "snippet": "We help enterprises cut Contoso licensing costs."},
    ]
}

# google_jobs answers with `jobs_results`, not `organic_results` -- a different
# engine and a different row shape, which is why it needs its own transport.
JOBS_RESULTS = {
    "jobs_results": [
        {"title": "Senior Security Engineer", "company_name": "Contoso",
         "location": "Redmond, WA", "via": "via LinkedIn",
         "detected_extensions": {"posted_at": "3 days ago"},
         "share_link": "https://www.google.com/search?q=job1"},
        # A corporate-form variant of the same employer: must still match.
        {"title": "Systems Administrator", "company_name": "Contoso Corporation",
         "location": "Anywhere", "via": "via Indeed", "detected_extensions": {}},
        # The trap this gate exists for. google_jobs aggregates boards, so a
        # company-name query comes back carrying other companies' vacancies.
        {"title": "Java Developer", "company_name": "Example Advisors",
         "location": "Remote", "via": "via Glassdoor", "detected_extensions": {}},
    ]
}

# The fallback transport: ordinary organic results for a site: query. LinkedIn
# renders a posting title as "<Company> hiring <Role> in <Location>".
JOB_ORGANIC = {
    "organic_results": [
        {"title": "Contoso hiring Principal Security Engineer in Redmond, WA | LinkedIn",
         "link": "https://www.linkedin.com/jobs/view/4012345678",
         "snippet": "Posted 3 days ago."},
        # Not a posting shape at all. Kept as a "role" this is exactly how a
        # person's name came to be printed as an open vacancy.
        {"title": "Jobs at Contoso | LinkedIn",
         "link": "https://www.linkedin.com/jobs/view/9", "snippet": ""},
    ]
}

PEOPLE_RESULTS = {
    "organic_results": [
        {"title": "Jane D. - Security Engineer at Contoso",
         "link": "https://www.linkedin.com/in/jane-doe-example",
         "snippet": "Security Engineer at Contoso · Experience: Contoso · Education: "
                    "Example Technology Institute · Location: San Diego · 500+ connections on LinkedIn."},
        # Country subdomain -- the sidecar's regex drops this one entirely.
        {"title": "John Doe - Security Researcher at Contoso",
         "link": "https://in.linkedin.com/in/john-doe-12345678",
         "snippet": "As a Contoso researcher involved in Threat Hunting and M365 Defender."},
        # "@" instead of "at".
        {"title": "Sam Placeholder - Security Engineer ll @ Contoso",
         "link": "https://in.linkedin.com/in/samplaceholder",
         "snippet": "At Contoso for nearly five years, focused on network security."},
        # Surname containing a technology token as a substring.
        {"title": "Alex Goodexample - Principal Security Engineer at Contoso",
         "link": "https://www.linkedin.com/in/alex-goodexample",
         "snippet": "Principal Security Engineer at Contoso · Location: Austin, Texas "
                    "Metropolitan Area · 500+ connections."},
        # "Name. Title at Co" with no dash separator at all.
        {"title": "John Smith. Senior Security Engineer at Contoso | LinkedIn",
         "link": "https://www.linkedin.com/in/john-smith33",
         "snippet": "Cybersecurity Strategist. Uses Azure and PowerShell daily."},
        # A headline that is JUST the employer, with no role. Four of thirty
        # people in a live run looked like this.
        {"title": "Pat Example - Contoso",
         "link": "https://www.linkedin.com/in/pat-example",
         "snippet": "Contoso. Location: Seattle."},
    ]
}


def rows(payload: dict) -> list:
    return [{"title": r.get("title", ""), "link": r.get("link", ""),
             "snippet": r.get("snippet", "")}
            for r in payload.get("organic_results", [])]


def stub_client(**kw) -> SerpClient:
    """A client whose search() serves the fixtures, bypassing the transport."""
    c = SerpClient(mode=kw.pop("mode", "serpapi"), api_key=kw.pop("api_key", "fake"), **kw)
    c.search = lambda q, num=10: rows(COMPANY_RESULTS) if "/company" in q else rows(PEOPLE_RESULTS)
    return c


# ── tests ────────────────────────────────────────────────────────────────────

def test_url_normalisation():
    section("URL normalisation")
    check("country subdomain survives",
          canonical_person_url("https://in.linkedin.com/in/john-doe-12345678")
          == "https://www.linkedin.com/in/john-doe-12345678/")
    check("two-letter country subdomain with query params",
          canonical_person_url("https://uk.linkedin.com/in/someone?trk=public")
          == "https://www.linkedin.com/in/someone/")
    check("plain www form", canonical_person_url("https://www.linkedin.com/in/jane-doe-example")
          == "https://www.linkedin.com/in/jane-doe-example/")
    check("a company URL is not a person URL",
          canonical_person_url("https://www.linkedin.com/company/contoso") is None)
    check("a non-LinkedIn URL is rejected",
          canonical_person_url("https://example.com/in/bob") is None)

    got = canonical_company_url("https://www.linkedin.com/company/contoso/jobs")
    check("a company facet path canonicalises to the company itself",
          got == ("https://www.linkedin.com/company/contoso/", "contoso"), str(got))
    check("a bare facet slug is not a company",
          canonical_company_url("https://www.linkedin.com/company/jobs") is None)


def test_title_parsing():
    section("title parsing")
    a = parse_person_title("Jane D. - Security Engineer at Contoso")
    check("hyphen + 'at'", a == {"name": "Jane D.", "job_title": "Security Engineer",
                                 "employer": "Contoso"}, str(a))
    b = parse_person_title("Sam Placeholder - Security Engineer ll @ Contoso")
    check("'@' joiner", b["job_title"] == "Security Engineer ll" and b["employer"] == "Contoso", str(b))
    c = parse_person_title("John Smith. Senior Security Engineer at Contoso | LinkedIn")
    check("period separator, brand suffix stripped",
          c == {"name": "John Smith", "job_title": "Senior Security Engineer",
                "employer": "Contoso"}, str(c))
    d = parse_person_title("Jane Roe – Head of IT — Sample Ltd")
    check("en/em dashes", d["name"] == "Jane Roe", str(d))
    e = parse_person_title("Just A Name")
    check("an unparseable title yields no fabricated employer",
          e["name"] == "Just A Name" and e["employer"] == "", str(e))
    check("empty input is safe", parse_person_title("")["name"] == "")


def test_snippet_parsing():
    section("snippet parsing")
    s = parse_person_snippet(
        "Security Engineer at Contoso · Experience: Contoso · Education: Example "
        "Technology Institute · Location: San Diego · 500+ connections on LinkedIn.")
    check("location", s["location"] == "San Diego", str(s))
    check("education", s["education"].startswith("Example"), str(s))
    # Promised by this function's docstring for months while the loop read only
    # the other two. It is LinkedIn's own employer field and the ONLY employer
    # signal on a row whose title carries no "<role> at <employer>", so dropping
    # it meant those people reached the gate with employer="" and were held.
    check("experience", s["experience"] == "Contoso", str(s))

    # The word-boundary bug: substring matching found "Go" inside "Goodexample".
    g = parse_person_snippet("Principal Security Engineer at Contoso · Location: Austin, Texas")
    check("'Go' is NOT extracted from a surname or from 'Goodexample'-like text",
          "Go" not in g["technologies"], str(g["technologies"]))
    check("nor from 'Google'", "Go" not in parse_person_snippet("Works at Google")["technologies"])
    check("a real standalone mention IS extracted",
          "Go" in parse_person_snippet("Writes Go and Rust daily.")["technologies"])
    t = parse_person_snippet("Threat Hunting, Incident Response, and M365 Defender.")
    check("multi-word token", "M365 Defender" in t["technologies"], str(t["technologies"]))
    n = parse_person_snippet("Builds on .NET and C# every day.")
    check("punctuation-edged tokens (.NET / C#)",
          ".NET" in n["technologies"] and "C#" in n["technologies"], str(n["technologies"]))


def test_job_title_parsing():
    section("job title parsing")
    j = parse_job_title("Contoso hiring Senior Security Engineer in Redmond, WA | LinkedIn")
    check("company", j["company"] == "Contoso", str(j))
    check("role", j["title"] == "Senior Security Engineer", str(j))
    check("location", j["location"] == "Redmond, WA", str(j))
    check("the location clause is optional",
          parse_job_title("Sample hiring Systems Administrator")["title"] == "Systems Administrator")
    # The OPPOSITE contract to parse_person_title(), and deliberately so: an
    # unrecognised person title still names a person, but an unrecognised job
    # title is not known to name a role at all.
    for bad in ("Jobs at Contoso | LinkedIn", "Jane D. - Security Engineer at Contoso", ""):
        check("refuses %r rather than keeping it as a role" % bad[:28],
              parse_job_title(bad)["title"] == "", str(parse_job_title(bad)))


def test_jobs_employer_gate():
    section("open roles")
    c = SerpClient(mode="serpapi", api_key="fake")

    class _R:
        ok = True
        @staticmethod
        def json():
            return JOBS_RESULTS
    calls = []
    c._fetch = lambda url, **kw: (calls.append(kw.get("params") or {}), _R())[1]

    out = c.jobs("Contoso", country="us")
    check("the jobs engine is asked for, not plain google",
          calls and calls[0].get("engine") == "google_jobs", str(calls[:1]))
    check("the country becomes gl, so a non-US target is not given US postings",
          calls and calls[0].get("gl") == "us", str(calls[:1]))
    check("transport is reported", out["transport"] == "google_jobs", str(out["transport"]))

    titles = [r["title"] for r in out["rows"]]
    check("a matching employer's posting is kept",
          "Senior Security Engineer" in titles, str(titles))
    check("a corporate-form variant of the employer still matches",
          "Systems Administrator" in titles, str(titles))
    check("'via' is normalised off its prefix",
          out["rows"][0]["via"] == "LinkedIn", str(out["rows"][0]))
    check("posted age survives", out["rows"][0]["posted"] == "3 days ago", str(out["rows"][0]))

    # The gate. An ungated roles list is the company-identification bug one
    # level down: a competitor's vacancy would feed the Job Title Match card.
    check("another company's posting is NOT offered as an open role",
          "Java Developer" not in titles, str(titles))
    refused = {r["company"] for r in out["refused"]}
    check("...and is counted, not silently dropped", "Example Advisors" in refused, str(out["refused"]))

    # Without a country the params must simply omit gl, never guess one.
    calls.clear()
    c2 = SerpClient(mode="serpapi", api_key="fake")
    c2._fetch = lambda url, **kw: (calls.append(kw.get("params") or {}), _R())[1]
    c2.jobs("Contoso")
    check("no country means no gl parameter", "gl" not in (calls[0] if calls else {"gl": 1}),
          str(calls[:1]))


def test_jobs_falls_back_without_the_engine():
    section("open roles — fallback transport")
    # No API key: the jobs engine is unreachable. An account whose plan lacks
    # google_jobs lands here too, and must NOT report that nobody is hiring.
    c = SerpClient(mode="serpapi", api_key="")
    seen = []
    c.search = lambda q, num=10: (seen.append(q), rows(JOB_ORGANIC))[1]
    out = c.jobs("Contoso")
    check("it falls back instead of raising", out["transport"] == "linkedin-serp", str(out))
    check("the site: operator goes LAST -- leading with it returned 0 of 10 on-site",
          seen and seen[0].startswith('"Contoso" site:linkedin.com/jobs/view'), str(seen))
    titles = [r["title"] for r in out["rows"]]
    check("a parseable posting is kept", titles == ["Principal Security Engineer"], str(titles))
    check("an unparseable title is dropped, never kept as a role",
          "Jobs at Contoso" not in titles, str(titles))
    check("and the reason the engine was skipped is recorded",
          any("SERP_API_KEY" in e for e in out["errors"]), str(out["errors"]))


def test_query_shape():
    section("query shape")
    seen = []
    c = stub_client()
    _inner = c.search
    c.search = lambda q, num=10: (seen.append(q), _inner(q, num))[1]
    c.organization_profile("Sample Corp", ["security"])
    # Measured on a live company: `site:` FIRST returned 0 of 10 LinkedIn
    # results (Google relaxed the operator and served the company's own
    # domain); `site:` LAST returned 10 of 10.
    check("every query puts the site: operator last",
          all(q.rstrip().endswith("site:linkedin.com/company")
              or q.rstrip().endswith("site:linkedin.com/in") for q in seen), str(seen))
    check("the company name is quoted for precision",
          all('"Sample Corp"' in q for q in seen), str(seen))
    check("a company query and per-keyword people queries are issued",
          any("/company" in q for q in seen) and any("/in" in q for q in seen), str(seen))


def test_company_pages():
    section("company pages, units and mentions")
    c = stub_client()
    profile, units, mentions, pick = c.company_pages("Contoso")
    check("the exact slug becomes the profile", profile.get("slug") == "contoso", str(profile))
    names = [u["name"] for u in units]
    check("an affiliated sub-brand is an org unit", "Contoso AI" in names, str(names))
    check("a facet path does not become a second unit",
          not any("Jobs" in n for n in names), str(names))
    mnames = [m["name"] for m in mentions]
    check("a third party that merely mentions the target is NOT a unit",
          not any("Example Advisors" in n for n in names), str(names))
    check("...it is kept as a mention instead of being discarded",
          any("Example Advisors" in n for n in mnames), str(mnames))
    check("an adopted match carries its evidence, so the card can state a basis",
          bool((pick.get("verdict") or {}).get("evidence")), str(pick.get("verdict")))

    # THE REGRESSION THIS FILE EXISTS FOR, once the fallback was removed.
    # Searching for a company nobody in the result set is returns the SAME rows
    # -- Contoso's page, its sub-brands, and a vendor that mentions it. The
    # old code adopted row 0 of that set and rendered it under the target's
    # heading. Nothing here relates to "Northwind Traders", so nothing may be
    # adopted, and the near misses must still be reported.
    c2 = stub_client()
    profile2, units2, mentions2, pick2 = c2.company_pages("Northwind Traders")
    check("an unrelated result set is NOT adopted as the company",
          profile2 == {} and pick2.get("best") is None, str(profile2))
    check("...and the refusal names a near miss the operator can recognise",
          bool(pick2.get("rejected")) and bool(pick2["rejected"][0].get("name")),
          str(pick2.get("rejected")))
    check("...with a reason, not a bare empty block",
          bool(pick2.get("reason")), str(pick2.get("reason")))
    check("...and every row is still visible as a mention, never silently dropped",
          len(units2) + len(mentions2) >= 3, "%d/%d" % (len(units2), len(mentions2)))


def test_people():
    section("people roster")
    c = stub_client()
    ppl = c.people("Contoso", ["security"])
    check("every fixture person is parsed", len(ppl) == 6, str(len(ppl)))
    urls = [p["url"] for p in ppl]
    check("country-subdomain people are present, not dropped",
          "https://www.linkedin.com/in/john-doe-12345678/" in urls, str(urls))
    check("all URLs are canonical www form", all(u.startswith("https://www.linkedin.com/in/") for u in urls))
    check("no duplicates", len(set(urls)) == len(urls))
    alex = [p for p in ppl if p["name"].startswith("Alex")][0]
    check("no phantom technology from a surname", alex["technologies"] == [], str(alex))
    js = [p for p in ppl if p["name"] == "John Smith"][0]
    check("real technologies are captured",
          set(js["technologies"]) >= {"Azure", "PowerShell"}, str(js["technologies"]))

    # The shape that the dropped Experience field used to lose entirely: a real
    # role in the title, no "at <Company>" anywhere in it, employer only in the
    # snippet. Before this, employer was "" -> CX_NO_EMPLOYER -> held.
    c2 = SerpClient(mode="serpapi", api_key="fake")
    c2.search = lambda q, num=10: [{
        "title": "Jane Roe - Senior Security Engineer",
        "link": "https://www.linkedin.com/in/jane-roe",
        "snippet": "Senior Security Engineer \u00b7 Experience: Contoso \u00b7 "
                   "Location: Denver \u00b7 500+ connections on LinkedIn.",
    }]
    jane = c2.people("Contoso", ["security"])[0]
    check("an employer with no 'at <Co>' in the title is recovered from Experience",
          jane["employer"] == "Contoso", str(jane))
    check("...and is attributed to that field", jane["employer_source"] == "experience", str(jane))
    check("...and the role is untouched",
          jane["job_title"] == "Senior Security Engineer", str(jane))
    # employment_evidence.assess() reads employer_from_headline for
    # CX_HEADLINE_ONLY. Experience is a real employer field, not a guess at one.
    check("...and is NOT marked as a headline guess",
          jane["employer_from_headline"] is False, str(jane))

    # A headline that is only the employer must NOT become a job title: it flows
    # into derive_specialty(), and a company called "... Information Security"
    # would classify four people as Security Professionals on the strength of
    # their employer's name alone.
    pn = [p for p in ppl if p["name"] == "Pat Example"][0]
    check("an employer-only headline is not treated as a job title",
          pn["job_title"] == "", str(pn))
    check("...the raw headline is kept rather than discarded",
          pn["headline"] == "Contoso", str(pn))
    check("...and it is recorded as the employer",
          pn["employer"] == "Contoso", str(pn))
    # An employer recovered from a bare headline was never asserted to BE an
    # employer; the gate weighs it lower than one parsed from "<role> at <co>".
    check("...flagged as headline-derived, not a stated employer",
          pn["employer_from_headline"] is True, str(pn))

    janed = [p for p in ppl if p["name"].startswith("Jane D")][0]
    check("a real title is untouched by that rule",
          janed["job_title"] == "Security Engineer")
    check("a stated employer is not flagged as headline-derived",
          janed["employer_from_headline"] is False, str(janed))

    # THE WORD-ALIGNMENT FIX. _is_employer_headline used to be a raw substring
    # test, so a genuine job title that happens to be a word-run inside the
    # employer's name was blanked -- exactly the case that named this rule.
    check("a genuine title inside the employer name survives",
          SerpClient._is_employer_headline(
              "Information Security", "Example Harbor Information Security") is False)
    check("...while the company name itself is still caught",
          SerpClient._is_employer_headline(
              "Example Harbor Information Security",
              "Example Harbor Information Security") is True)


def test_organization_profile():
    section("organization_profile contract")
    c = stub_client()
    r = c.organization_profile("Contoso", ["security"])
    check("matched", r["matched"] is True)
    check("source label", r["source"] == "serpapi", r["source"])
    check("reliable flag set for the API transport", r["reliable"] is True)
    for k in ("matched", "source", "query", "profile", "related", "people", "mentions", "errors"):
        check("carries %s" % k, k in r)
    check("profile_url", r["profile"]["profile_url"].endswith("/company/contoso/"))
    check("no errors on the happy path", r["errors"] == [], str(r["errors"]))

    check("an empty company name is refused, with a reason",
          SerpClient(api_key="fake").organization_profile("")["errors"] != [])


def test_unreliable_transport_is_labelled():
    section("free-engine honesty")
    for k in ("SERP_API_KEY", "SERP_MODE"):
        os.environ.pop(k, None)
    c = SerpClient(api_key="")
    check("auto with no key falls back to a free engine", c.mode == "bing", c.mode)
    check("and is flagged unreliable", c.is_reliable is False)

    c.search = lambda q, num=10: []
    r = c.organization_profile("Sample Ltd")
    check("an empty free-engine result is EXPLAINED, not silently empty",
          any("unreliable" in e for e in r["errors"]), str(r["errors"]))
    check("...and names the fix", any("SERP_API_KEY" in e for e in r["errors"]), str(r["errors"]))
    check("matched stays False", r["matched"] is False)

    keyed = SerpClient(mode="serpapi", api_key="")
    try:
        keyed.search("anything")
        check("serpapi mode with no key refuses", False, "no exception")
    except SerpError as e:
        check("serpapi mode with no key refuses, naming the variable",
              "SERP_API_KEY" in str(e), str(e)[:80])


def test_proxy_fails_closed():
    section("proxy fail-closed")
    real = serp_client.requests.get
    calls = []

    def dead(url, **kw):
        calls.append(kw)
        raise requests.exceptions.ProxyError("tunnel refused")

    serp_client.requests.get = dead
    try:
        c = SerpClient(mode="serpapi", api_key="fake", proxy_url="socks5h://127.0.0.1:9050")
        try:
            c.search("test")
            check("a dead proxy raises instead of going direct", False, "no exception")
        except SerpError as e:
            check("a dead proxy raises instead of going direct",
                  "refusing to fall back to direct egress" in str(e), str(e)[:90])
        check("the proxy was handed to requests", bool(calls) and calls[0].get("proxies"))
        check("no direct retry followed", len(calls) == 1, str(len(calls)))
    finally:
        serp_client.requests.get = real


def test_budget():
    section("search budget")
    real = serp_client.requests.get

    class R:
        status_code, ok = 200, True
        text = '{"organic_results":[]}'
        def iter_content(self, n): yield b'{"organic_results":[]}'
        def close(self): pass
        def json(self): return {"organic_results": []}

    serp_client.requests.get = lambda url, **kw: R()
    try:
        c = SerpClient(mode="serpapi", api_key="fake", max_searches=2)
        c.search("a"); c.search("b")
        check("budget reports exhausted", c.budget_exhausted() is True)
        try:
            c.search("c")
            check("over-budget search is refused", False, "no exception")
        except SerpError as e:
            check("over-budget search is refused", "budget exhausted" in str(e), str(e)[:70])

        # The people sweep must stop at the budget and SAY it stopped.
        c2 = SerpClient(mode="serpapi", api_key="fake", max_searches=1)
        c2.people("Sample", ["a", "b", "c"])
        check("a truncated people sweep is recorded",
              any("budget exhausted" in e for e in c2.errors), str(c2.errors))
    finally:
        serp_client.requests.get = real


def test_never_touches_linkedin():
    section("never contacts linkedin.com")
    real_get, real_post = serp_client.requests.get, serp_client.requests.post
    seen = []

    class R:
        status_code, ok = 200, True
        text = '{"organic_results":[]}'
        def iter_content(self, n): yield b'{"organic_results":[]}'
        def close(self): pass
        def json(self): return {"organic_results": []}

    serp_client.requests.get = lambda url, **kw: (seen.append(url), R())[1]
    serp_client.requests.post = lambda url, **kw: (seen.append(url), R())[1]
    try:
        for mode in ("serpapi", "bing", "ddg"):
            c = SerpClient(mode=mode, api_key="fake", max_searches=20)
            try:
                c.organization_profile("Sample Ltd", ["security"])
            except SerpError:
                pass
        check("no request targeted a linkedin.com host",
              not any("linkedin.com" in u for u in seen), str(seen[:4]))
        check("requests did go somewhere", bool(seen))
    finally:
        serp_client.requests.get, serp_client.requests.post = real_get, real_post


def main() -> int:
    for t in (
        test_url_normalisation,
        test_title_parsing,
        test_job_title_parsing,
        test_snippet_parsing,
        test_jobs_employer_gate,
        test_jobs_falls_back_without_the_engine,
        test_query_shape,
        test_company_pages,
        test_people,
        test_organization_profile,
        test_unreliable_transport_is_labelled,
        test_proxy_fails_closed,
        test_budget,
        test_never_touches_linkedin,
    ):
        t()
    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("all serp_client checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
