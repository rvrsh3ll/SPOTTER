#!/usr/bin/env python3
"""
Offline smoke test for scripts/tavily_client.py.

Fixtures are shaped like real Tavily /search, /extract, /crawl and /map
responses, including the ones that are easy to mistake for success.

What it pins, and why each one is here rather than trusted:

  * NO query ever contains `site:`, a boolean ` OR `, or a quote character.
    Tavily is a semantic API, so all three are searched as literal TEXT. This
    is the counterpart of smoke_serp_client's "the operator goes LAST": there,
    getting the syntax wrong returned the wrong results; here it silently
    dilutes the query instead, which is harder to notice.
  * Every LinkedIn search restricts by include_domains, not by a path operator.
    That is what lets one company search also return /in rows.
  * The LinkedIn parsers are IMPORTED from serp_client, not copied. Asserted by
    object identity, which is the only version of this check that cannot rot.
  * include_answer and include_raw_content are False on EVERY search.
    include_answer would put an LLM-written summary into profile.description
    and present it as the company's own words; include_raw_content would have
    Tavily fetch linkedin.com on our behalf.
  * search() returns exactly {title, link, snippet}. Tavily's 0-1 `score` must
    NOT survive into a row, where it could be mistaken for the 0-100
    identification score employment_evidence produces.
  * /extract REFUSES linkedin.com, country subdomains included, and records the
    refusal. A blocklist with the same blind spot as the sidecar's old
    _LI_URL_RE would fail OPEN.
  * HTTP 200 with a populated failed_results is a PARTIAL failure, not success.
  * A dead proxy FAILS CLOSED -- never retried direct.
  * An auth failure never puts the API key in `errors`, which reach the
    operator's browser and the campaign export.
  * A truncated body is reported as truncated, not as unparseable JSON.
  * TAVILY_MAX_SEARCHES=0 disables the provider, rather than reading as unset.
  * /map parses defensively -- its public docs are thin.

Usage:
    python3 scripts/smoke_tavily_client.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

import serp_client  # noqa: E402
import tavily_client  # noqa: E402
from tavily_client import TavilyClient, TavilyError  # noqa: E402

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

# ONE response carrying company pages, a facet path, a third-party vendor AND
# two /in rows. This mixed shape is the thing include_domains produces and
# `site:linkedin.com/company` cannot, so it is the fixture the pooling win is
# measured against.
LI_MIXED = {
    "query": "Contoso",
    "results": [
        {"title": "Contoso", "url": "https://www.linkedin.com/company/contoso",
         "content": "Contoso | 120,000 followers on LinkedIn. Industrial systems.",
         "score": 0.98},
        {"title": "Contoso AI", "url": "https://www.linkedin.com/company/contoso-ai",
         "content": "At Contoso AI we build safer systems.", "score": 0.91},
        {"title": "Jobs at Contoso", "url": "https://www.linkedin.com/company/contoso/jobs",
         "content": "Open roles at Contoso.", "score": 0.80},
        {"title": "Example Advisors - Independent Contoso Spend Specialists",
         "url": "https://www.linkedin.com/company/example-advisors",
         "content": "Independent advisors on Contoso licensing.", "score": 0.55},
        {"title": "Chris Sample - Security Engineer at Contoso",
         "url": "https://www.linkedin.com/in/chris-sample-example",
         "content": "Security Engineer at Contoso - Experience: Contoso - "
                    "Education: Example Technology Institute - Location: San Diego",
         "score": 0.77},
        {"title": "Alex Example - Cloud Architect at Contoso",
         "url": "https://in.linkedin.com/in/alex-example",
         "content": "Cloud Architect at Contoso - Experience: Contoso - "
                    "Location: Pune - Azure and Kubernetes at scale",
         "score": 0.74},
    ],
    "response_time": 1.2,
    "request_id": "req-mixed",
    "usage": {"total_credits": 1},
}

LI_PEOPLE = {
    "query": "Contoso security",
    "results": [
        {"title": "Jane D. - Director of Information Security at Contoso",
         "url": "https://uk.linkedin.com/in/jane-d-example",
         "content": "Director of Information Security at Contoso - "
                    "Experience: Contoso - Location: London", "score": 0.88},
        # Employer only in the headline -- the weakest tier, and the one
        # employer_from_headline exists to mark.
        {"title": "Sam Goodexample - Contoso", "url": "https://www.linkedin.com/in/sam-goodexample",
         "content": "Contoso - Location: Austin", "score": 0.60},
    ],
    "response_time": 0.9,
    "request_id": "req-people",
    "usage": {"total_credits": 1},
}

EMPTY_SEARCH = {"query": "", "results": [], "response_time": 0.1,
                "request_id": "req-empty", "usage": {"total_credits": 1}}

EXTRACT_PARTIAL = {
    "results": [{"url": "https://sample.test/about", "raw_content": "# About\n\nWe make things."}],
    "failed_results": [{"url": "https://sample.test/secret", "error": "403 Forbidden"},
                       {"url": "https://sample.test/slow", "error": "request timed out"}],
    "response_time": 2.0,
    "request_id": "req-extract",
}


class R:
    """Minimal stand-in for requests.Response as _post_once/_parse use it."""

    def __init__(self, payload, status=200, headers=None):
        self._p = payload
        self.status_code = status
        self.ok = 200 <= status < 300
        self.headers = headers or {}
        self.text = payload if isinstance(payload, str) else json.dumps(payload)

    def iter_content(self, n):
        yield self.text.encode()

    def close(self):
        pass

    def json(self):
        if isinstance(self._p, str):
            raise ValueError("not json")
        return self._p


def stub_post(payload_for=None, *, capture=None, status=200, headers=None):
    """Replace tavily_client.requests.post, recording (url, payload) per call."""
    def _post(url, **kw):
        body = kw.get("json") or {}
        if capture is not None:
            capture.append({"url": url, "payload": body, "headers": kw.get("headers") or {},
                            "proxies": kw.get("proxies")})
        p = payload_for(url, body) if callable(payload_for) else payload_for
        return R(p if p is not None else EMPTY_SEARCH, status=status, headers=headers)
    return _post


def client(**kw):
    kw.setdefault("api_key", "fake-tavily-key")
    kw.setdefault("max_searches", 20)
    kw.setdefault("budget_credits", 200)
    return TavilyClient(**kw)


# ── tests ────────────────────────────────────────────────────────────────────

def test_parsers_are_imported_not_copied():
    section("reuse, not fork")
    for name in ("canonical_person_url", "canonical_company_url",
                 "parse_person_title", "parse_person_snippet", "_txt"):
        check("%s is serp_client's object" % name,
              getattr(tavily_client, name) is getattr(serp_client, name))


def test_company_title_cleaning():
    section("LinkedIn page titles reduced to company names")
    # Shapes captured LIVE from Tavily on 2026-09-23 (company renamed to
    # Fabrikam, tagline rewritten). serp_client never had to handle these
    # because Google rewrites a page title before it reaches a SERP; Tavily
    # returns LinkedIn's own, facet suffix and tagline included.
    for raw, want in (
        ("Fabrikam: Jobs | LinkedIn", "Fabrikam"),
        ("Fabrikam.ai - Useful, well-tested tooling for everyday teams. Built for "
         "builders who\u2019d rather ship.", "Fabrikam.ai"),
        ("Fabrikam Europe", "Fabrikam Europe"),
        ("Contoso: Careers", "Contoso"),
        ("Sample Corp | LinkedIn", "Sample Corp"),
        # Must NOT be split: the tail is too short to be a tagline, and this is
        # the shape a real hyphenated company name takes.
        ("Smith - Jones", "Smith - Jones"),
        # The employment gate scores against this string, so a genuine name
        # that merely CONTAINS a facet word must survive intact.
        ("Example Harbor Information Security", "Example Harbor Information Security"),
    ):
        got = tavily_client.clean_company_title(raw)
        check("%r -> %r" % (raw[:34], want), got == want, got)


def test_query_shape():
    section("query shape (no Google syntax)")
    real = tavily_client.requests.post
    seen = []
    tavily_client.requests.post = stub_post(lambda u, b: LI_MIXED, capture=seen)
    try:
        c = client()
        c.organization_profile("Contoso Industrial Ltd")
        qs = [s["payload"].get("query", "") for s in seen]
        check("at least one search was issued", bool(qs))
        check("no query contains a `site:` operator",
              not any("site:" in q for q in qs), str(qs[:3]))
        check("no query contains a boolean ` OR `",
              not any(" OR " in q for q in qs), str(qs[:3]))
        check("no query contains a quote character",
              not any('"' in q for q in qs), str(qs[:3]))
        doms = [s["payload"].get("include_domains") for s in seen]
        check("every search restricts to linkedin.com via include_domains",
              all(d == ["linkedin.com"] for d in doms), str(doms[:3]))
        check("include_domains_mode is restrict",
              all(s["payload"].get("include_domains_mode") == "restrict" for s in seen))
        check("include_answer is False on every search",
              all(s["payload"].get("include_answer") is False for s in seen))
        check("include_raw_content is False on every search",
              all(s["payload"].get("include_raw_content") is False for s in seen))
    finally:
        tavily_client.requests.post = real


def test_auth_and_endpoint():
    section("transport")
    real = tavily_client.requests.post
    seen = []
    tavily_client.requests.post = stub_post(lambda u, b: LI_MIXED, capture=seen)
    try:
        c = client()
        c.search("anything", include_domains=("linkedin.com",))
        check("posts to /search on the documented base",
              seen[0]["url"] == "https://api.tavily.com/search", seen[0]["url"])
        check("key travels as a Bearer header",
              seen[0]["headers"].get("Authorization") == "Bearer fake-tavily-key")
        check("key is not in the URL", "fake-tavily-key" not in seen[0]["url"])
        check("key is not in the body",
              "fake-tavily-key" not in json.dumps(seen[0]["payload"]))
    finally:
        tavily_client.requests.post = real


def test_row_shape():
    section("row shape matches SerpClient.search()")
    real = tavily_client.requests.post
    tavily_client.requests.post = stub_post(LI_MIXED)
    try:
        rows = client().search("Contoso")
        check("rows returned", bool(rows))
        check("exactly {title, link, snippet}",
              all(set(r) == {"title", "link", "snippet"} for r in rows),
              str(sorted(rows[0])) if rows else "")
        check("link came from Tavily `url`",
              rows[0]["link"] == "https://www.linkedin.com/company/contoso")
        check("snippet came from Tavily `content`",
              rows[0]["snippet"].startswith("Contoso | 120,000 followers"))
        check("Tavily's 0-1 score is dropped",
              not any("score" in r for r in rows))
    finally:
        tavily_client.requests.post = real


def test_max_results_clamped():
    section("max_results clamp")
    real = tavily_client.requests.post
    seen = []
    tavily_client.requests.post = stub_post(LI_MIXED, capture=seen)
    try:
        c = client()
        c.search("a", num=50)
        c.search("b", num=0)
        check("num=50 clamps to Tavily's ceiling of 20",
              seen[0]["payload"]["max_results"] == 20, str(seen[0]["payload"]["max_results"]))
        check("num=0 falls back to the configured default, never 0",
              seen[1]["payload"]["max_results"] == 15, str(seen[1]["payload"]["max_results"]))
    finally:
        tavily_client.requests.post = real


def test_depth_and_credits():
    section("search depth and credit projection")
    real = tavily_client.requests.post
    seen = []
    tavily_client.requests.post = stub_post(LI_MIXED, capture=seen)
    try:
        c = client(search_depth="advanced")
        c.search("a")
        check("advanced depth reaches the payload",
              seen[0]["payload"]["search_depth"] == "advanced")
        check("advanced projects 2 credits", c.credits_spent == 2, str(c.credits_spent))
        check("usage from the response is reported separately",
              c.credits_reported == 1, str(c.credits_reported))

        b = client(search_depth="sideways")
        b.search("a")
        check("an unknown depth falls back to basic", b.depth == "basic")
        check("and records that it did",
              any("sideways" in e for e in b.errors), str(b.errors))
    finally:
        tavily_client.requests.post = real


def test_pooling_win():
    section("one company search also yields people")
    real = tavily_client.requests.post
    seen = []

    def once(url, body):
        # Only the FIRST search returns rows; every later leg is empty. If the
        # roster is non-empty anyway, the /in rows must have come from the
        # company leg's pool rather than from a paid people query.
        return LI_MIXED if len(seen) <= 1 else EMPTY_SEARCH

    tavily_client.requests.post = stub_post(once, capture=seen)
    try:
        c = client()
        res = c.organization_profile("Contoso")
        names = [p["name"] for p in res["people"]]
        check("people were harvested from the company response",
              len(names) >= 2, str(names))
        check("the country-subdomain profile survived",
              any("Alex" in n for n in names), str(names))
        check("company page still identified", res["profile"].get("name") == "Contoso",
              str(res["profile"].get("name")))
        check("the /jobs facet is not a separate unit",
              not any("/contoso/jobs" in (u.get("url") or "") for u in res["related"]),
              str(res["related"]))
        check("the third-party vendor is a mention, not a unit",
              not any("example-advisors" in (u.get("url") or "") for u in res["related"]),
              str(res["related"]))
    finally:
        tavily_client.requests.post = real


def test_people_employer_tiers():
    section("employer precedence")
    real = tavily_client.requests.post
    tavily_client.requests.post = stub_post(lambda u, b: LI_PEOPLE)
    try:
        c = client()
        rows = c.people("Contoso", ["security"])
        by = {r["name"]: r for r in rows}
        check("Experience-backed employer is sourced as experience",
              by.get("Jane D.", {}).get("employer_source") in ("title", "experience"),
              str(by.get("Jane D.")))
        check("an Experience employer is NOT flagged headline-only",
              by.get("Jane D.", {}).get("employer_from_headline") is False)
        sam = by.get("Sam Goodexample", {})
        check("a bare company headline is marked headline-only",
              sam.get("employer_from_headline") is True, str(sam))
        check("and the company name is not kept as a job title",
              not sam.get("job_title"), str(sam.get("job_title")))
        check("word-boundary tech matching survived the reuse ('Go' from Goodexample)",
              "Go" not in (sam.get("technologies") or []), str(sam.get("technologies")))
    finally:
        tavily_client.requests.post = real


def test_company_refusal():
    section("company identification gate")
    real = tavily_client.requests.post
    unrelated = {"results": [
        {"title": "Northwind Traders", "url": "https://www.linkedin.com/company/northwind",
         "content": "Northwind Traders | logistics.", "score": 0.4}],
        "usage": {"total_credits": 1}}
    tavily_client.requests.post = stub_post(lambda u, b: unrelated)
    try:
        res = client().organization_profile("Contoso Industrial Ltd")
        check("an unrelated company is NOT adopted",
              not res["profile"].get("name"), str(res["profile"]))
        check("the near miss is reported", bool(res["rejected"]), str(res["rejected"]))
        check("with a reason", bool(res["match_reason"]), res["match_reason"])
    finally:
        tavily_client.requests.post = real


def test_extract_refuses_linkedin():
    section("never causes a LinkedIn fetch")
    real = tavily_client.requests.post
    seen = []
    tavily_client.requests.post = stub_post(lambda u, b: EXTRACT_PARTIAL, capture=seen)
    try:
        c = client()
        out = c.extract([
            "https://www.linkedin.com/in/x",
            "https://in.linkedin.com/in/y",
            "https://uk.linkedin.com/company/z",
            "https://sample.test/about",
        ])
        sent = json.dumps([s["payload"] for s in seen])
        check("no linkedin host reached any payload", "linkedin.com" not in sent, sent[:120])
        check("all three linkedin URLs were refused",
              len(out["refused"]) == 3, str(out["refused"]))
        check("the refusal is recorded, not silent",
              any("linkedin.com" in e for e in c.errors), str(c.errors[:1]))
        check("the ordinary URL still went",
              any("sample.test" in json.dumps(s["payload"]) for s in seen))
    finally:
        tavily_client.requests.post = real


def test_extract_batches_and_partial_failure():
    section("/extract batching and partial failure")
    real = tavily_client.requests.post
    seen = []
    tavily_client.requests.post = stub_post(lambda u, b: EXTRACT_PARTIAL, capture=seen)
    try:
        c = client(budget_credits=500)
        c.extract(["https://sample.test/p%d" % i for i in range(45)])
        sizes = [len(s["payload"]["urls"]) for s in seen]
        check("45 URLs batch as 20/20/5", sizes == [20, 20, 5], str(sizes))
        check("no batch exceeds Tavily's limit of 20", all(n <= 20 for n in sizes))

        c2 = client()
        out = c2.extract(["https://sample.test/about"])
        check("a 200 with failed_results is not read as total success",
              len(out["results"]) == 1 and len(out["failed_results"]) == 2,
              "%d ok / %d failed" % (len(out["results"]), len(out["failed_results"])))
        check("per-URL errors are preserved",
              any("403" in f["error"] for f in out["failed_results"]),
              str(out["failed_results"]))
    finally:
        tavily_client.requests.post = real


def test_crawl_scope_is_locked():
    section("/crawl scope parameters")
    real = tavily_client.requests.post
    seen = []
    tavily_client.requests.post = stub_post(
        lambda u, b: {"base_url": "https://sample.test/", "results": [], "usage": {}},
        capture=seen)
    try:
        c = client()
        c.crawl("https://sample.test/", max_depth=9, limit=60, timeout=900,
                select_domains=[r"^([A-Za-z0-9-]+\.)*sample\.test$"])
        p = seen[0]["payload"]
        check("allow_external is inverted to False", p["allow_external"] is False)
        check("select_domains is forwarded", bool(p.get("select_domains")))
        check("max_depth clamps to Tavily's 1-5", p["max_depth"] == 5, str(p["max_depth"]))
        check("timeout clamps to Tavily's 10-150", p["timeout"] == 150, str(p["timeout"]))
        check("no `instructions` is ever sent", "instructions" not in p)
        check("no `query` is sent on the crawl path", "query" not in p)
        check("no `chunks_per_source` is sent", "chunks_per_source" not in p)
    finally:
        tavily_client.requests.post = real


def test_map_is_defensive():
    section("/map response shapes")
    real = tavily_client.requests.post
    try:
        for label, payload, want in (
            ("list of strings", {"results": ["https://sample.test/a", "https://sample.test/b"]}, 2),
            ("list of objects", {"results": [{"url": "https://sample.test/a"}]}, 1),
            ("urls key", {"urls": ["https://sample.test/a"]}, 1),
        ):
            tavily_client.requests.post = stub_post(payload)
            got = client().map_site("https://sample.test/")
            check("/map parses a %s" % label, len(got) == want, str(got))

        tavily_client.requests.post = stub_post({"results": {"unexpected": True}})
        c = client()
        got = c.map_site("https://sample.test/")
        check("an unexpected /map shape yields [] and a note",
              got == [] and bool(c.errors), "%r %r" % (got, c.errors))
    finally:
        tavily_client.requests.post = real


def test_proxy_fails_closed():
    section("proxy fail-closed")
    real = tavily_client.requests.post
    calls = []

    def dead(url, **kw):
        calls.append(kw)
        raise requests.exceptions.ProxyError("tunnel refused")

    tavily_client.requests.post = dead
    try:
        c = client(proxy_url="socks5h://127.0.0.1:9050")
        try:
            c.search("test")
            check("a dead proxy raises instead of going direct", False, "no exception")
        except TavilyError as e:
            check("a dead proxy raises instead of going direct",
                  "refusing to fall back to direct egress" in str(e), str(e)[:90])
        check("the proxy was handed to requests", bool(calls) and calls[0].get("proxies"))
        check("no direct retry followed", len(calls) == 1, str(len(calls)))
    finally:
        tavily_client.requests.post = real


def test_auth_failure_never_leaks_the_key():
    section("auth failure")
    real = tavily_client.requests.post
    tavily_client.requests.post = stub_post({"detail": "invalid api key"}, status=401)
    try:
        c = client()
        res = c.organization_profile("Contoso")
        check("a 401 does not raise out of organization_profile", res["matched"] is False)
        check("the status is named", any("401" in e for e in c.errors), str(c.errors[:1]))
        check("the key appears in NO error string",
              not any("fake-tavily-key" in e for e in c.errors), str(c.errors[:1]))
    finally:
        tavily_client.requests.post = real


def test_rate_limit():
    section("429 handling")
    real = tavily_client.requests.post
    try:
        # Long Retry-After: a named error, no sleep, no hang inside the node.
        tavily_client.requests.post = stub_post(
            {"detail": "rate limited"}, status=429, headers={"Retry-After": "600"})
        c = client()
        try:
            c.search("a")
            check("an unaffordable Retry-After raises", False, "no exception")
        except TavilyError as e:
            check("an unaffordable Retry-After raises a named rate-limit error",
                  "429" in str(e) and "Retry-After" in str(e), str(e)[:90])

        # Short Retry-After: exactly one retry, then the real answer.
        seen = []
        state = {"n": 0}

        def flaky(url, **kw):
            state["n"] += 1
            seen.append(url)
            if state["n"] == 1:
                return R({"detail": "slow down"}, status=429, headers={"Retry-After": "0"})
            return R(LI_MIXED)

        tavily_client.requests.post = flaky
        c2 = client()
        rows = c2.search("a")
        check("a short Retry-After is retried once and succeeds", bool(rows), str(len(rows)))
        check("exactly two requests were made", len(seen) == 2, str(len(seen)))
        check("the retry is recorded", any("429" in e for e in c2.errors), str(c2.errors[:1]))
    finally:
        tavily_client.requests.post = real


def test_truncation_is_named():
    section("truncated body")
    real = tavily_client.requests.post
    tavily_client.requests.post = stub_post(LI_MIXED)
    try:
        c = client(max_bytes=64)
        try:
            c.search("a")
            check("a truncated body raises", False, "no exception")
        except TavilyError as e:
            check("a truncated body says TRUNCATED, not 'unparseable JSON'",
                  "truncated" in str(e).lower() and "unparseable" not in str(e).lower(),
                  str(e)[:100])
    finally:
        tavily_client.requests.post = real


def test_budget():
    section("budgets")
    real = tavily_client.requests.post
    tavily_client.requests.post = stub_post(LI_MIXED)
    try:
        c = client(max_searches=2)
        c.search("a"); c.search("b")
        check("search budget reports exhausted", c.budget_exhausted() is True)
        try:
            c.search("c")
            check("over-budget search is refused", False, "no exception")
        except TavilyError as e:
            check("over-budget search is refused", "budget exhausted" in str(e), str(e)[:70])
        check("no credits were charged for the call that never happened",
              c.credits_spent == 2, str(c.credits_spent))

        # The one that bit serp_client: a deliberate 0 must not read as unset.
        os.environ["TAVILY_MAX_SEARCHES"] = "0"
        try:
            z = TavilyClient(api_key="fake-tavily-key")
            check("TAVILY_MAX_SEARCHES=0 disables the provider",
                  z.max_searches == 0 and z.budget_exhausted() is True,
                  str(z.max_searches))
        finally:
            os.environ.pop("TAVILY_MAX_SEARCHES", None)

        cc = client(budget_credits=1)
        cc.search("a")
        try:
            cc.search("b")
            check("the credit ceiling is enforced", False, "no exception")
        except TavilyError as e:
            check("the credit ceiling is enforced, naming the knob",
                  "TAVILY_MAX_CREDITS" in str(e), str(e)[:90])

        # One account, one counter: /search and /crawl must not each get a budget.
        shared = client(budget_credits=3)
        shared.search("a")
        try:
            shared.crawl("https://sample.test/", limit=60)
            check("search and crawl share one credit budget", False, "no exception")
        except TavilyError as e:
            check("search and crawl share one credit budget",
                  "credit budget exhausted" in str(e), str(e)[:90])
    finally:
        tavily_client.requests.post = real


def test_no_key():
    section("no key configured")
    real = tavily_client.requests.post
    seen = []
    tavily_client.requests.post = stub_post(LI_MIXED, capture=seen)
    try:
        c = TavilyClient(api_key="")
        check("source_label is not_configured", c.source_label == "not_configured")
        check("is_reliable is False", c.is_reliable is False)
        res = c.organization_profile("Contoso")
        check("organization_profile returns rather than raising", res["matched"] is False)
        check("the error names TAVILY_API_KEY",
              any("TAVILY_API_KEY" in e for e in c.errors), str(c.errors[:1]))
        check("no request was issued without a key", not seen, str(seen))
    finally:
        tavily_client.requests.post = real


def test_survives_an_unexpected_exception():
    section("never raises")
    real = tavily_client.requests.post

    def boom(url, **kw):
        raise ValueError("something nobody predicted")

    tavily_client.requests.post = boom
    try:
        c = client()
        res = c.organization_profile("Contoso")
        check("an arbitrary transport exception is absorbed", res["matched"] is False)
        check("and recorded", bool(c.errors), str(c.errors[:1]))
    finally:
        tavily_client.requests.post = real


def test_egress_targets_only_tavily():
    section("egress")
    real = tavily_client.requests.post
    seen = []
    tavily_client.requests.post = stub_post(lambda u, b: LI_MIXED, capture=seen)
    try:
        client().organization_profile("Contoso")
        urls = [s["url"] for s in seen]
        check("every request went to api.tavily.com",
              all(u.startswith("https://api.tavily.com") for u in urls), str(urls[:3]))
        check("no request targeted a linkedin.com host",
              not any("linkedin.com" in u for u in urls), str(urls[:3]))
    finally:
        tavily_client.requests.post = real


def main() -> int:
    for t in (
        test_parsers_are_imported_not_copied,
        test_company_title_cleaning,
        test_query_shape,
        test_auth_and_endpoint,
        test_row_shape,
        test_max_results_clamped,
        test_depth_and_credits,
        test_pooling_win,
        test_people_employer_tiers,
        test_company_refusal,
        test_extract_refuses_linkedin,
        test_extract_batches_and_partial_failure,
        test_crawl_scope_is_locked,
        test_map_is_defensive,
        test_proxy_fails_closed,
        test_auth_failure_never_leaks_the_key,
        test_rate_limit,
        test_truncation_is_named,
        test_budget,
        test_no_key,
        test_survives_an_unexpected_exception,
        test_egress_targets_only_tavily,
    ):
        t()
    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("all tavily_client checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
