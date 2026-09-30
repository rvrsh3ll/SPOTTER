#!/usr/bin/env python3
"""
tavily_client.py — LinkedIn organization intelligence and page reading, via Tavily.

WHAT IT IS FOR
--------------
A second, independent web-search provider for WF13's `org` source, and the only
one that can also READ a page rather than just find it. serp_client.py is
SerpAPI-primary with Bing/DuckDuckGo as a labelled-unreliable fallback, which
left the deployment with exactly one paid search vendor and no alternative.

This module is a PEER of serp_client, not one of its transports. It emits its
own provider row, it is preferred over SerpAPI when both keys are present, and
it owns three endpoints SerpAPI has no equivalent for: /extract (read specific
URLs), /crawl and /map (traverse a site, used as an alternative fetch backend
for site_rag).

WHY NOT A FOURTH SerpClient TRANSPORT
-------------------------------------
Because it would have to lie about three things.

1. SerpClient.search() emulates Google. Tavily is a semantic search API, and
   the emulation does not survive the move -- see NO `site:` OPERATOR below.
2. SerpClient.mode is a transport label. Tavily has exactly one transport, so
   a `mode` would be a name with nothing behind it. The axis that actually
   varies here is search_depth, and it is the one that doubles the bill.
3. SerpClient.is_reliable distinguishes a paid API from a degraded free engine.
   Tavily has no keyless path at all: absent a key there is nothing to fall
   back TO, which is a different operator message ("not asked") from the free
   engines' ("asked, but do not trust the silence").

NO `site:` OPERATOR, EVER
-------------------------
Tavily is a semantic search API, not a Google proxy. `site:linkedin.com/in` is
not an operator here -- it is four words of query text. Domain restriction is
the first-class `include_domains` parameter, which is also why the measured
"the operator must go LAST" rule (serp_client.py:624-630) has no counterpart in
this file: there is no operator to place. The same applies to the boolean `OR`
in SerpAPI's role keywords and to the quoted-phrase idiom -- Tavily reads both
as literal characters -- so this module ships its own flattened keyword list.

That difference is also an advantage, and it is where the budget goes. Google's
`site:linkedin.com/company` is PATH-scoped, so a company query can only ever
return company pages. `include_domains=['linkedin.com']` is DOMAIN-scoped: the
same one-credit search returns /company rows AND /in rows. Those /in rows are
pooled and reused by the people sweep, so there is no separate org-units query
and the sub-brand list costs nothing extra.

WHY NOT FETCH LINKEDIN THROUGH /extract
---------------------------------------
serp_client.py:16-33 states the rule -- it never issues a request to any
linkedin.com host -- and smoke_serp_client.py pins it. Commissioning Tavily to
fetch the page instead violates both limbs of that rule:

1. The prohibition is about CAUSING the access, not about which socket it
   leaves from. serp_client justifies reading a SERP by LinkedIn's published
   allowance for LinkedInBot and Googlebot. Tavily has no such allowance.
2. It also fails the "it does not work" limb, and fails it dangerously. The
   likely outcomes are a failed_results entry or ~498 KB of login-page
   markdown -- and the second is WORSE than nothing, because it would be
   chunked, embedded and indexed, and would then retrieve as profile content.

So extract() refuses any linkedin.com host, country subdomains included, and
RECORDS the refusal rather than dropping it silently. include_raw_content is
likewise pinned False on every search: it would have Tavily fetch the live page
on our behalf, which is the same act by another name.

OPSEC
-----
Every query carries the target's company name, and /crawl carries a directive
to go touch the client's infrastructure. A proxy does NOT hide either: the API
key identifies the account regardless (serp_client.py:66-73 makes the same
point about SerpAPI). Worse than the SerpAPI case in one specific way -- on the
/crawl and /extract paths the requests that reach the CLIENT come from Tavily's
IP addresses, so the campaign proxy covers only the operator->Tavily leg and
the client's logs will not show the engagement at all. Documented in README and
.env.example, and the backend is off by default.

BUDGET
------
Two independent ceilings, because they bound different things:

  max_searches  a hard COUNT of requests, so the operator can plan in legs
                (2 company identifiers + 6 role keywords = 8, with slack).
  budget_credits  a projected CREDIT ceiling, shared across every endpoint on
                this client. It is per-account, so /search and /crawl must draw
                on one counter -- two counters drain one key at twice the
                configured rate on a run that uses both.

Credits are PROJECTED locally, never read back from the response as the source
of truth: `usage` is absent unless requested and is documented to read 0 until
five URL extractions have succeeded. The response's figure is reported
alongside the projection, not substituted for it.

SANDBOX CONSTRAINTS
-------------------
Runs inside the n8n Python task runner, whose import allowlist is scanned
STATICALLY -- `try: import tavily / except ImportError` does not help, the node
is killed before line 1. There is therefore NO Tavily SDK here: plain `requests`
against a documented REST API, and stdlib `re` for everything else.

This module imports serp_client for the LinkedIn parsers. The dependency is
ONE-WAY -- serp_client must never import tavily_client, or the runner dies on a
circular import before line 1.

Environment:
    TAVILY_API_KEY        from https://tavily.com          (enables the provider)
    TAVILY_MAX_SEARCHES   hard cap per run                 (default: 10)
    TAVILY_MAX_RESULTS    rows per search, 1-20            (default: 15)
    TAVILY_TIMEOUT        per-request seconds              (default: 45)
    TAVILY_SEARCH_DEPTH_ADVANCED  1 = advanced, 2 credits  (default: 0)
    TAVILY_MAX_CREDITS    projected credit ceiling         (default: 50)
    TAVILY_ROLE_KEYWORDS  comma-separated people queries   (default: see below)
    TAVILY_BASE_URL       override the API root            (default: api.tavily.com)
"""

from __future__ import annotations

import math
import os
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import requests

# The company-identification gate. Shared with serp_client and hh_client so one
# population is scored by one matcher -- a provider that brings its own would be
# adopting companies the others would have refused.
import employment_evidence

# The LinkedIn parsers, IMPORTED rather than copied. They parse LinkedIn's own
# rendering, not SerpAPI's envelope, so they are transport-independent -- and
# three bugs have already been fixed in them (country subdomains, word-boundary
# tech tokens, the ". " separator). A fork guarantees the fourth fix lands in
# only one copy.
#
# _txt / _first_set / _as_int are underscore-private by within-file convention,
# not because they are a package boundary. Re-declaring _first_set in
# particular is exactly how the "a deliberate 0 reads as unset" bug returns.
import serp_client
from serp_client import (  # noqa: F401 - re-exported for the smoke test's identity check
    _as_int,
    _first_set,
    _txt,
    canonical_company_url,
    canonical_person_url,
    parse_person_snippet,
    parse_person_title,
)

TAVILY_BASE = "https://api.tavily.com"

_SEARCH_PATH = "/search"
_EXTRACT_PATH = "/extract"
_CRAWL_PATH = "/crawl"
_MAP_PATH = "/map"

# 45, not 20, for the same measured reason as SERP_TIMEOUT: a search API that
# queries the live web behind the request is not a 20-second call, and losing
# the company lookup takes the org-unit list and every linkedin_* key with it.
_DEFAULT_TIMEOUT = 45
_DEFAULT_MAX_BYTES = 4 * 1024 * 1024
# 2 company identifiers + 6 role keywords = 8, so 10 leaves slack. Lower than
# serp_client's 12 because there is no separate org-units query and no jobs leg:
# include_domains returns the sub-brand pages from the company search itself.
_DEFAULT_MAX_SEARCHES = 10
_DEFAULT_MAX_SECONDS = 150
_DEFAULT_MAX_RESULTS = 15
_DEFAULT_MAX_CREDITS = 50

# Tavily's own documented ceilings. Clamp to them rather than posting a value
# the API will reject -- a 422 on the fifth leg of a sweep is an expensive way
# to discover a typo in .env.
_TAVILY_MAX_RESULTS = 20
_TAVILY_MAX_EXTRACT_URLS = 20
_TAVILY_MAX_INCLUDE_DOMAINS = 300
_TAVILY_MIN_CRAWL_TIMEOUT = 10
_TAVILY_MAX_CRAWL_TIMEOUT = 150
_TAVILY_MIN_DEPTH = 1
_TAVILY_MAX_DEPTH = 5

# How long we are willing to sit in a Retry-After sleep. The n8n task runner has
# its own task timeout, so an honest `Retry-After: 60` must become a named error
# rather than a 60-second hang that takes every other source in the run with it.
_RETRY_AFTER_MAX = 5

_DEPTHS = ("basic", "advanced", "fast", "ultra-fast")
_CREDIT_PER_SEARCH = {"basic": 1, "advanced": 2, "fast": 1, "ultra-fast": 1}

# Domain-scoped, not path-scoped -- that is the whole point. One edit widens it
# if a live run shows country subdomains being excluded; the cap is 300.
_LI_DOMAINS = ("linkedin.com",)

# NOT serp_client._DEFAULT_ROLE_KEYWORDS. Those carry Google's boolean OR
# ("systems administrator OR IT"), which Tavily reads as the literal word "or"
# and which therefore DILUTES a semantic query instead of widening it.
_DEFAULT_ROLE_KEYWORDS = (
    "security",
    "IT systems administrator",
    "devops cloud engineer SRE",
    "software engineer developer",
    "human resources recruiter",
    "director vice president chief officer",
)

# Hosts this module refuses to hand to /extract or /crawl. Country subdomains
# are covered deliberately: serp_client._LI_PERSON_RE documents that a naive
# `(?:www\.)?linkedin\.com` regex silently dropped ~40% of live hits, and the
# same blind spot in a refusal list fails OPEN.
#
# Kept to LinkedIn alone. facebook.com, x.com and instagram.com have the
# identical login-wall-plus-prohibition shape and are candidates, but a long
# blocklist is unmaintainable and LinkedIn is the one with a written rule in
# this repo and a test pinning it.
_REFUSED_HOST_RE = re.compile(r"(?:^|\.)linkedin\.com$", re.I)


# LinkedIn renders a company page's <title> as "<Name>: <Facet> | LinkedIn",
# and often "<Name> - <tagline>" on the overview. serp_client never had to deal
# with either because GOOGLE rewrites the title before it reaches a SERP;
# Tavily returns the page's own, so this file has to clean it.
#
# MEASURED, not anticipated (live target, 2026-09-23; renamed here to Fabrikam):
# the company came back as "Fabrikam: Jobs" and a unit as "Fabrikam.ai - Useful,
# well-tested tooling for everyday teams. Built for builders who'd rather ship."
# That is not cosmetic -- the company name becomes linkedin_company_name, which
# feeds build_identity() and org_aliases() and is therefore scored against every
# person by the employment gate.
_LI_TITLE_FACET_RE = re.compile(
    r":\s*(?:jobs|careers|overview|about|life|people|posts|videos|insights|"
    r"events|products)\s*$", re.I)
# An en/em dash or a spaced hyphen introduces a tagline. Kept deliberately
# conservative: only split when the tail is long enough to be prose, so a
# company genuinely called "Smith - Jones" survives. The slug is carried in
# alt_names either way, so a wrong split cannot cost the match.
_LI_TITLE_TAGLINE_RE = re.compile(r"\s+[-\u2013\u2014]\s+")


def clean_company_title(raw: str) -> str:
    """A LinkedIn page <title> reduced to the company name.

    "Fabrikam: Jobs | LinkedIn"       -> "Fabrikam"
    "Fabrikam.ai - Useful, well-test" -> "Fabrikam.ai"  (when the tail is prose)
    "Smith - Jones"                   -> "Smith - Jones" (tail too short to be one)
    """
    name = _txt(raw).split("|")[0].strip()
    for _ in range(3):                       # "Sample: Jobs: Overview" happens
        stripped = _LI_TITLE_FACET_RE.sub("", name).strip()
        if stripped == name:
            break
        name = stripped
    parts = _LI_TITLE_TAGLINE_RE.split(name, 1)
    if len(parts) == 2 and parts[0].strip() and len(parts[1]) >= 24:
        name = parts[0].strip()
    return name.strip(" .,-\u2013\u2014")


class TavilyError(Exception):
    """A request-level failure the caller should record, not raise through."""


def refused_host(url: str) -> str:
    """The refused hostname in `url`, or '' if it may be fetched.

    Returns the host rather than a bool so the caller can name it in the error
    an operator will read -- somebody who pasted a LinkedIn URL needs to learn
    WHY nothing happened, not just that nothing did.
    """
    try:
        host = (urlparse(str(url or "")).hostname or "").strip().lower()
    except Exception:                               # noqa: BLE001
        return ""
    return host if host and _REFUSED_HOST_RE.search(host) else ""


class TavilyClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        proxy_url: str = "",
        timeout: Optional[int] = None,
        search_depth: Optional[str] = None,
        max_searches: Optional[int] = None,
        max_results: Optional[int] = None,
        max_seconds: int = _DEFAULT_MAX_SECONDS,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        budget_credits: Optional[int] = None,
        role_keywords: Optional[List[str]] = None,
        base_url: str = "",
    ):
        self.api_key = (api_key if api_key is not None
                        else os.environ.get("TAVILY_API_KEY", "")).strip()
        self.base_url = ((base_url or os.environ.get("TAVILY_BASE_URL", "")).strip()
                         or TAVILY_BASE).rstrip("/")

        self.depth = self._resolve_depth(search_depth)

        self.proxy_url = (proxy_url or "").strip()
        self.proxies = (
            {"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None
        )

        # `or` chains would treat 0 as "unset". TAVILY_MAX_SEARCHES=0 is
        # documented as disabling the provider, and TAVILY_MAX_CREDITS=0 as
        # refusing to spend anything; both must survive the read.
        self.timeout = _first_set(timeout, _as_int(os.environ.get("TAVILY_TIMEOUT")),
                                  _DEFAULT_TIMEOUT)
        self.max_searches = _first_set(max_searches,
                                       _as_int(os.environ.get("TAVILY_MAX_SEARCHES")),
                                       _DEFAULT_MAX_SEARCHES)
        self.max_results = max(1, min(
            _first_set(max_results, _as_int(os.environ.get("TAVILY_MAX_RESULTS")),
                       _DEFAULT_MAX_RESULTS),
            _TAVILY_MAX_RESULTS))
        self.budget_credits = _first_set(
            budget_credits, _as_int(os.environ.get("TAVILY_MAX_CREDITS")),
            _DEFAULT_MAX_CREDITS)
        self.max_seconds = max_seconds
        self.max_bytes = max_bytes

        kws = role_keywords
        if kws is None:
            raw = os.environ.get("TAVILY_ROLE_KEYWORDS", "").strip()
            kws = ([k.strip() for k in raw.split(",") if k.strip()] if raw
                   else list(_DEFAULT_ROLE_KEYWORDS))
        self.role_keywords = kws

        self.errors: List[str] = []
        self.credits_spent = 0
        self.credits_reported = 0
        self._searches = 0
        self._started = time.time()
        # Rows harvested from the company leg that the people sweep can reuse
        # without paying for them again. See the module docstring.
        self._pool: List[Dict[str, str]] = []

    # ── depth + labels ────────────────────────────────────────────────────────

    def _resolve_depth(self, requested: Optional[str]) -> str:
        """serp_client._resolve_mode()'s counterpart.

        There is only one transport here, so a `mode` would be a label with
        nothing behind it; what actually varies is depth, and it is the axis
        that doubles the bill (advanced = 2 credits, everything else = 1). An
        unrecognised value falls back to 'basic' and SAYS SO, rather than being
        posted to the API and silently rejected mid-sweep.
        """
        raw = (requested or os.environ.get("TAVILY_SEARCH_DEPTH", "") or "").strip().lower()
        if not raw:
            adv = _as_int(os.environ.get("TAVILY_SEARCH_DEPTH_ADVANCED")) or 0
            return "advanced" if adv else "basic"
        if raw in _DEPTHS:
            return raw
        self._pending_depth_note = raw
        return "basic"

    @property
    def source_label(self) -> str:
        return "tavily" if self.api_key else "not_configured"

    @property
    def is_reliable(self) -> bool:
        """True whenever the key is present.

        Unlike serp_client's, this is not a judgement about a degraded
        transport -- there is no keyless Tavily path at all. The flag exists so
        every provider row carries the same field, and so a future degraded
        mode has somewhere to live.
        """
        return bool(self.api_key)

    @property
    def credit_cost(self) -> int:
        return _CREDIT_PER_SEARCH.get(self.depth, 1)

    # ── budget ────────────────────────────────────────────────────────────────

    def budget_exhausted(self) -> bool:
        return (self._searches >= self.max_searches
                or (time.time() - self._started) >= self.max_seconds)

    def _check_budget(self) -> None:
        if self.budget_exhausted():
            raise TavilyError("Tavily budget exhausted (%d searches / %ds)"
                              % (self.max_searches, self.max_seconds))

    def _spend(self, credits: int, what: str) -> None:
        """Charge a PROJECTED cost against the shared ceiling, or refuse.

        Projected, not billed: the response's `usage` block is absent unless
        requested and is documented to read 0 until five URL extractions have
        succeeded, so enforcing on it would let a run overspend and only find
        out afterwards.

        The SEARCH budget is checked first so that a run which has run out of
        requests does not also report having spent the credits for a call it
        never made -- the two ceilings bound different things and the numbers
        an operator reads afterwards have to stay honest about which one bit.
        """
        self._check_budget()
        want = max(0, int(credits))
        if self.credits_spent + want > self.budget_credits:
            raise TavilyError(
                "Tavily credit budget exhausted: %s needs %d more credit(s), "
                "%d of %d already projected. Raise TAVILY_MAX_CREDITS to continue."
                % (what, want, self.credits_spent, self.budget_credits))
        self.credits_spent += want

    def _note(self, msg: str) -> None:
        if msg not in self.errors:
            self.errors.append(msg)

    def _flush_pending_notes(self) -> None:
        """Depth fell back during __init__, before self.errors existed."""
        raw = getattr(self, "_pending_depth_note", "")
        if raw:
            self._pending_depth_note = ""
            self._note("TAVILY_SEARCH_DEPTH=%r is not one of %s; using 'basic'"
                       % (raw, ", ".join(_DEPTHS)))

    # ── transport ─────────────────────────────────────────────────────────────

    def _post_once(self, url: str, payload: dict, headers: dict) -> requests.Response:
        try:
            r = requests.post(url, json=payload, headers=headers,
                              timeout=self.timeout, proxies=self.proxies, stream=True)
        except requests.exceptions.ProxyError as e:
            # Never retried direct. A campaign that asked for proxied egress
            # must not leak a request because the proxy happened to be down.
            raise TavilyError("Tavily proxy unreachable; refusing to fall back to "
                              "direct egress: %s" % e)
        except Exception as e:                      # noqa: BLE001
            raise TavilyError("Tavily request failed (%s): %s" % (url, e))

        body = b""
        truncated = False
        try:
            for chunk in r.iter_content(64 * 1024):
                body += chunk
                if len(body) >= self.max_bytes:
                    body = body[: self.max_bytes]
                    truncated = True
                    break
        finally:
            r.close()
        r._content = body                           # noqa: SLF001
        r._content_consumed = True                  # noqa: SLF001
        # Tracked because a truncated JSON body fails DIFFERENTLY from a
        # truncated HTML one: r.json() raises, and "unparseable response" would
        # be reported for what is really "your byte cap is too small".
        r._spotter_truncated = truncated            # noqa: SLF001
        return r

    def _fetch(self, path: str, payload: dict, *, timeout: Optional[int] = None) -> Dict[str, Any]:
        """One POST, parsed. Raises TavilyError on anything that is not a result."""
        self._flush_pending_notes()
        if not self.api_key:
            raise TavilyError(
                "TAVILY_API_KEY is not set. Tavily has no keyless transport, so "
                "unlike the SERP provider there is nothing to fall back to and "
                "the Tavily organization source is disabled.")
        self._check_budget()
        self._searches += 1
        url = self.base_url + path
        headers = {
            # The key lives in a HEADER, never in the URL or the body, and is
            # never interpolated into an error message -- errors reach the
            # operator's browser and the campaign export.
            "Authorization": "Bearer %s" % self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        prev_timeout = self.timeout
        if timeout is not None:
            self.timeout = timeout
        try:
            r = self._post_once(url, payload, headers)
            if r.status_code == 429:
                r = self._retry_after_once(url, payload, headers, r)
            return self._parse(r, path)
        finally:
            self.timeout = prev_timeout

    def _retry_after_once(self, url: str, payload: dict, headers: dict,
                          first: requests.Response) -> requests.Response:
        """One bounded retry on a 429, or a named error.

        A 429 is billed nothing, so the retry does not re-consume the credit
        projection -- but it IS bounded to a single attempt and a short sleep,
        because the alternative is a task-runner timeout that costs the whole
        run rather than one leg of it.
        """
        wait = _as_int((first.headers or {}).get("Retry-After"))
        if wait is None or wait > _RETRY_AFTER_MAX:
            raise TavilyError(
                "Tavily rate limit (HTTP 429); Retry-After %s exceeds the %ds we "
                "are willing to wait inside a workflow node. The dev-key limit is "
                "100 requests/minute." % (wait if wait is not None else "unset",
                                          _RETRY_AFTER_MAX))
        if (time.time() - self._started) + wait >= self.max_seconds:
            raise TavilyError("Tavily rate limit (HTTP 429); no wall-clock budget "
                              "left to wait %ds and retry" % wait)
        self._note("Tavily rate limit (HTTP 429); waited %ds and retried once" % wait)
        time.sleep(max(0, wait))
        return self._post_once(url, payload, headers)

    def _parse(self, r: requests.Response, path: str) -> Dict[str, Any]:
        if getattr(r, "_spotter_truncated", False):
            raise TavilyError(
                "Tavily response for %s was truncated at the %d-byte cap before it "
                "could be parsed. This is a local limit, not a Tavily failure: "
                "lower max_results or raise the cap." % (path, self.max_bytes))
        if not getattr(r, "ok", False):
            # The body carries the reason on 401/403/432/433 and it is the only
            # way to tell "bad key" from "out of credits". The key is in a
            # header, so echoing a trimmed body cannot leak it.
            detail = (getattr(r, "text", "") or "")[:200].replace("\n", " ").strip()
            raise TavilyError("Tavily returned HTTP %s for %s%s"
                              % (r.status_code, path, (": " + detail) if detail else ""))
        try:
            data = r.json()
        except Exception as e:                      # noqa: BLE001
            raise TavilyError("Tavily returned unparseable JSON for %s: %s" % (path, e))
        if not isinstance(data, dict):
            raise TavilyError("Tavily returned a %s for %s, expected an object"
                              % (type(data).__name__, path))
        usage = data.get("usage")
        if isinstance(usage, dict):
            reported = _as_int(usage.get("total_credits"))
            if reported:
                self.credits_reported += reported
        return data

    # ── one search, one shape ─────────────────────────────────────────────────

    def search(self, query: str, num: int = 0, *,
               include_domains: Optional[Sequence[str]] = None,
               topic: str = "general") -> List[Dict[str, str]]:
        """Return [{title, link, snippet}] -- the SAME rows SerpClient.search()
        returns, so every parser in serp_client works on them unchanged.

        The mapping is the point of this method:

            Tavily `url`     -> `link`
            Tavily `content` -> `snippet`
            Tavily `title`   -> `title`

        Everything else Tavily carries (score, published_date, favicon, id) is
        dropped ON PURPOSE. `score` in particular is a 0-1 relevance figure,
        while the two *_score fields this card already shows are 0-100
        IDENTIFICATION scores from employment_evidence. Letting a relevance
        score reach a match_score key would present "Tavily thought this was on
        topic" as "this was identified as the target".
        """
        if not str(query or "").strip():
            return []
        payload: Dict[str, Any] = {
            "query": query,
            "search_depth": self.depth,
            "max_results": max(1, min(int(num or self.max_results), _TAVILY_MAX_RESULTS)),
            "topic": topic,
            # An LLM-written answer would flow into profile.description and be
            # presented as the company's own words: fabricated evidence inside
            # the module whose whole job is resisting fabricated signals.
            "include_answer": False,
            # Would have Tavily fetch the live page on our behalf. See the
            # module docstring.
            "include_raw_content": False,
            "include_usage": True,
        }
        if include_domains:
            payload["include_domains"] = list(include_domains)[:_TAVILY_MAX_INCLUDE_DOMAINS]
            payload["include_domains_mode"] = "restrict"

        self._spend(self.credit_cost, "search %r" % (query[:60],))
        data = self._fetch(_SEARCH_PATH, payload)
        rows: List[Dict[str, str]] = []
        for item in (data.get("results") or []):
            if not isinstance(item, dict):
                continue
            link = str(item.get("url") or "")
            if not link:
                continue
            rows.append({
                "title": str(item.get("title") or ""),
                "link": link,
                "snippet": str(item.get("content") or ""),
            })
        return rows

    def _linkedin_search(self, query: str) -> List[Dict[str, str]]:
        """One domain-restricted search, with every row also kept in self._pool.

        THE NATIVE ADVANTAGE, and the reason this is not a SerpClient
        transport. Google's `site:linkedin.com/company` is PATH-scoped, so a
        company query can only ever return company pages. include_domains is
        DOMAIN-scoped: the same one-credit search returns /company rows AND
        /in rows. Throwing the /in rows away and then paying again for them in
        the people sweep is the mistake this pool exists to avoid.
        """
        rows = self.search(query, include_domains=_LI_DOMAINS)
        self._pool.extend(rows)
        return rows

    # ── the org-shaped queries ────────────────────────────────────────────────

    def company_pages(self, company: str,
                      identity: Optional[Dict[str, Any]] = None,
                      match_min: Optional[int] = None,
                      max_terms: int = 2,
                      ) -> Tuple[Dict[str, Any], List[Dict[str, str]], List[Dict[str, str]], Dict[str, Any]]:
        """(profile, units, mentions, pick) for a company, via include_domains.

        Mirrors serp_client.company_pages() including its fourth outcome:
        when nothing clears the evidence floor the search REFUSES rather than
        adopting the top result, and `pick` carries the near misses so the card
        can say what was seen and why none of it was taken.

        No `site:` and no quotes -- see the module docstring.
        """
        ident = identity or employment_evidence.identity_from_aliases([company])
        terms = [t for t in (ident.get("search_terms") or ()) if t] or (
            [company] if (company or "").strip() else [])
        # Capped for the same reason serp_client caps: Tavily bills per search
        # and the people sweep spends six out of the same budget, so an
        # unbounded identifier loop would quietly truncate the roster.
        if max_terms and len(terms) > max_terms:
            self._note("searching the first %d of %d identifiers on LinkedIn; the "
                       "rest are still used to MATCH what comes back, and to search "
                       "the providers that are not billed per query"
                       % (max_terms, len(terms)))
            terms = terms[:max_terms]

        rows: List[Dict[str, str]] = []
        for term in terms:
            if self.budget_exhausted():
                self._note("Tavily budget exhausted before every identifier was "
                           "searched; %r and after were not tried" % term)
                break
            try:
                rows.extend(self._linkedin_search(term))
            except TavilyError as e:
                # Per-term, not per-call: one identifier's search failing must
                # not cost the others.
                self._note(str(e))

        candidates: List[Dict[str, Any]] = []
        seen = set()
        for row in rows:
            got = canonical_company_url(row.get("link", ""))
            if not got:
                continue
            url, slug = got
            if slug in seen:
                continue
            seen.add(slug)
            candidates.append({
                # clean_company_title(), not serp_client's split("|")[0]: Tavily
                # returns LinkedIn's own <title>, facet suffix and tagline
                # included. See the constant block above.
                "name": clean_company_title(row.get("title")) or slug,
                "url": url, "slug": slug,
                "description": _txt(row.get("snippet")),
                "alt_names": [slug.replace("-", " ")],
            })

        pick = employment_evidence.pick_company(candidates, ident, match_min=match_min)
        best = dict(pick["best"]) if pick["best"] else {}
        units = [{"name": u.get("name", ""), "url": u.get("url", ""), "kind": "unit"}
                 for u in pick["units"]]
        mentions = [{"name": m.get("name", ""), "url": m.get("url", ""), "kind": "mention"}
                    for m in pick["mentions"]]
        return best, units, mentions, pick

    def people(self, company: str, keywords: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Everyone the engine returned for a company query, unfiltered.

        SAME CONTRACT AS serp_client.people(), AND DO NOT "HELPFULLY" TIGHTEN
        IT HERE. These rows are candidates, not employees; deciding which of
        them actually work there is employment_evidence's job, applied once in
        WF13 over the union of every provider.

        MEASURED LIMITATION (live, 2026-09-23): 0 of 10 profiles came
        back with an employer. Tavily's `content` is ITS OWN extraction of the
        page rather than Google's rendering of LinkedIn's meta description, so
        the `Experience:` / `Location:` / `Education:` runs
        parse_person_snippet() looks for are NOT present, and the title is a
        bare name ("Jane Doe") rather than "Name - Role at Company".

        So this method contributes NAMES AND PROFILE URLS, not evidenced
        employment. Its rows reach the gate with employer='' and are held, and
        that is the correct outcome: inferring the employer from the query that
        found them is precisely the fabricated signal employment_evidence
        exists to reject. Do not "fix" it that way.

        It is also why WF13 FIELD-MERGES this roster with the SERP one rather
        than taking the first, and why the people sweep should not be
        Tavily-only. Note too that include_domains is domain-scoped, so role
        keywords pull in linkedin.com/jobs/ pages that Google's path-scoped
        site:linkedin.com/in would have excluded.
        """
        out: List[Dict[str, Any]] = []
        seen = set()
        # The company leg already paid for whatever /in rows came back with the
        # company pages; spend nothing to reuse them.
        pooled = [(row, "") for row in self._pool]
        searched: List[Tuple[Dict[str, str], str]] = []
        for kw in (keywords if keywords is not None else self.role_keywords):
            if self.budget_exhausted():
                self._note("Tavily budget exhausted before every role keyword was searched")
                break
            try:
                rows = self._linkedin_search("%s %s" % (company, kw))
            except TavilyError as e:
                self._note(str(e))
                continue
            except Exception as e:                  # noqa: BLE001
                self._note("Tavily search failed unexpectedly (%s): %r" % (kw, e))
                continue
            searched.extend((row, kw) for row in rows)

        for row, kw in pooled + searched:
            url = canonical_person_url(row.get("link", ""))
            if not url or url in seen:
                continue
            parsed = parse_person_title(row.get("title", ""))
            if not parsed["name"]:
                continue
            seen.add(url)
            snip = parse_person_snippet(row.get("snippet", ""))
            _title = parsed["job_title"]
            _headline = ""
            if employment_evidence.is_company_headline(_title, (company,)) and not parsed["employer"]:
                # Keep the raw headline so nothing is lost, but do not let a
                # company name be treated as a role.
                _headline, _title = _title, ""
            # Employer precedence, strongest first: an explicit "<role> at
            # <employer>" title, then LinkedIn's own Experience: field, then a
            # bare company-shaped headline. employer_from_headline marks only
            # that last case -- employment_evidence.assess() reads it for
            # CX_HEADLINE_ONLY, so it must stay False when Experience supplied
            # the employer, which is a real field and not a guess at one.
            _employer = parsed["employer"] or snip["experience"] or _headline
            if parsed["employer"]:
                _emp_src = "title"
            elif snip["experience"]:
                _emp_src = "experience"
            elif _headline:
                _emp_src = "headline"
            else:
                _emp_src = ""
            out.append({
                "name": parsed["name"],
                "job_title": _title,
                "headline": _headline,
                "employer": _employer,
                "employer_source": _emp_src,
                "employer_from_headline": _emp_src == "headline",
                "location": snip["location"],
                "education": snip["education"],
                "technologies": snip["technologies"],
                "url": url,
                "matched_keyword": kw,
            })
        return out

    # ── the whole profile in one call ─────────────────────────────────────────

    def organization_profile(self, company_name: str,
                             role_keywords: Optional[List[str]] = None,
                             identity: Optional[Dict[str, Any]] = None,
                             match_min: Optional[int] = None) -> Dict[str, Any]:
        """Mirrors serp_client.organization_profile()'s contract. Never raises.

        Same keys, so the WF13 call site is the SERP block with the class
        swapped. Every leg records into `errors` and the partially-filled
        result is returned, so the card renders whatever was reached.
        """
        self._flush_pending_notes()
        out: Dict[str, Any] = {
            "matched": False,
            "source": self.source_label,
            "reliable": self.is_reliable,
            "query": company_name,
            "queries": [],
            "profile": {},
            "related": [],
            "people": [],
            "mentions": [],
            "rejected": [],
            "match_reason": "",
            "match_evidence": [],
            "match_score": 0,
            "errors": self.errors,
        }
        if not self.api_key:
            self._note(
                "TAVILY_API_KEY is not set, so the Tavily provider was not asked. "
                "There is no keyless Tavily transport to fall back to -- this is "
                "'not asked', not 'nothing found'.")
            return out

        ident = identity or employment_evidence.identity_from_aliases([company_name])
        terms = [t for t in (ident.get("search_terms") or ()) if t] or (
            [company_name] if (company_name or "").strip() else [])
        out["queries"] = list(terms)
        if not terms:
            self._note("Tavily provider needs a company name; none was resolved")
            return out

        pick: Dict[str, Any] = {}
        try:
            profile, units, mentions, pick = self.company_pages(
                company_name, identity=ident, match_min=match_min)
        except TavilyError as e:
            self._note(str(e))
            profile, units, mentions = {}, [], []
        except Exception as e:                      # noqa: BLE001 - see below
            # Deliberately broad. This method is documented as never raising,
            # and it is called from a WF13 code node where an escaped exception
            # costs the operator every other source in the run, not just this
            # one. An unexpected parser failure is recorded and moved past.
            self._note("Tavily company lookup failed unexpectedly: %r" % (e,))
            profile, units, mentions = {}, [], []

        if profile:
            out["profile"] = {
                "id": profile.get("slug", ""),
                "name": profile.get("name", ""),
                "industries": [],
                "description": profile.get("description", ""),
                "site": "",
                "area": "", "address": "", "country": "",
                "size_category": "",
                "profile_url": profile.get("url", ""),
            }
            out["matched"] = bool(profile.get("name"))
            out["match_score"] = int((pick.get("verdict") or {}).get("score") or 0)
            out["match_evidence"] = list((pick.get("verdict") or {}).get("evidence") or [])
        elif pick:
            # Nothing cleared the floor. Say which near miss was refused and
            # why -- an unexplained empty company block is indistinguishable
            # from a search that returned nothing at all.
            out["rejected"] = pick.get("rejected") or []
            out["match_reason"] = pick.get("reason") or ""
            if out["rejected"]:
                self._note(
                    "LinkedIn search returned %d company page(s) for %s but none "
                    "is evidently the target — %s. Not adopted: a company-name "
                    "search also returns vendors, resellers, recruiters and "
                    "publications that merely mention it."
                    % (len(out["rejected"]), " / ".join(repr(t) for t in terms),
                       out["match_reason"]))
        out["related"] = units
        out["mentions"] = mentions

        try:
            # The people sweep uses the confirmed company page's name once
            # there is one: a LinkedIn profile headline spells the employer the
            # way LinkedIn does.
            _people_term = (out["profile"].get("name") or "").strip() or terms[0]
            out["people"] = self.people(_people_term, role_keywords)
        except TavilyError as e:
            self._note(str(e))
        except Exception as e:                      # noqa: BLE001 - see above
            self._note("Tavily people sweep failed unexpectedly: %r" % (e,))

        if out["people"] and not out["matched"]:
            # People found but no company page: still a match, and saying
            # otherwise would hide the roster.
            out["matched"] = True
        return out

    # ── reading pages: /extract, /crawl, /map ─────────────────────────────────

    def extract(self, urls: Sequence[str], *, extract_depth: str = "basic",
                fmt: str = "markdown", timeout: Optional[float] = None,
                query: str = "") -> Dict[str, Any]:
        """Read specific URLs. Batches at 20. Never raises.

        Returns {results: [{url, raw_content}], failed_results: [{url, error}],
        refused: [{url, reason}]}.

        THREE THINGS THAT ARE EASY TO GET WRONG HERE:

        1. A partial failure answers HTTP 200. Per-URL success lives in
           failed_results, so checking the status code alone reports success
           for a batch that fetched nothing.
        2. linkedin.com is REFUSED, country subdomains included, and the
           refusal is recorded -- see the module docstring. Never silently
           dropped: an operator who pasted a LinkedIn URL needs to learn why.
        3. `query` is accepted but forwarded ONLY when non-empty, because it
           makes Tavily rerank and chunk the content. site_rag re-chunks with
           its own chunk_text(), whose behaviour is pinned by smoke tests, so
           the crawl path deliberately leaves it unset.
        """
        out: Dict[str, Any] = {"results": [], "failed_results": [], "refused": []}
        wanted: List[str] = []
        for raw in (urls or ()):
            u = str(raw or "").strip()
            if not u:
                continue
            host = refused_host(u)
            if host:
                reason = ("%s is refused by policy: this deployment never causes a "
                          "request to LinkedIn, directly or through a third party. "
                          "The page is a login wall in any case." % host)
                out["refused"].append({"url": u, "reason": reason})
                self._note(reason)
                continue
            wanted.append(u)
        if not wanted:
            return out

        depth = extract_depth if extract_depth in ("basic", "advanced") else "basic"
        for i in range(0, len(wanted), _TAVILY_MAX_EXTRACT_URLS):
            batch = wanted[i:i + _TAVILY_MAX_EXTRACT_URLS]
            payload: Dict[str, Any] = {
                "urls": batch,
                "extract_depth": depth,
                "format": fmt if fmt in ("markdown", "text") else "markdown",
                "include_images": False,
                "include_favicon": False,
                "include_usage": True,
            }
            if timeout is not None:
                payload["timeout"] = float(max(1.0, min(60.0, timeout)))
            if query:
                payload["query"] = query
            # 1 credit per 5 successful URLs (2 advanced). Projected on the
            # batch size, which is the pessimistic read and the right one for a
            # ceiling.
            cost = int(math.ceil(len(batch) / 5.0)) * (2 if depth == "advanced" else 1)
            try:
                self._spend(cost, "extract of %d URL(s)" % len(batch))
                data = self._fetch(_EXTRACT_PATH, payload)
            except TavilyError as e:
                self._note(str(e))
                for u in batch:
                    out["failed_results"].append({"url": u, "error": str(e)})
                continue
            for item in (data.get("results") or []):
                if isinstance(item, dict) and item.get("url"):
                    out["results"].append({
                        "url": str(item.get("url") or ""),
                        "raw_content": str(item.get("raw_content") or ""),
                    })
            for item in (data.get("failed_results") or []):
                if isinstance(item, dict):
                    out["failed_results"].append({
                        "url": str(item.get("url") or ""),
                        "error": str(item.get("error") or "unspecified"),
                    })
        return out

    def crawl(self, url: str, *, max_depth: int = 1, max_breadth: int = 20,
              limit: int = 50, select_domains: Optional[Sequence[str]] = None,
              exclude_paths: Optional[Sequence[str]] = None,
              extract_depth: str = "basic", fmt: str = "markdown",
              timeout: Optional[int] = None) -> Dict[str, Any]:
        """Traverse a site from `url`. Returns {results, failed_results}.

        allow_external defaults to FALSE here, INVERTING Tavily's own default.
        That is deliberate and it is not sufficient on its own: Tavily
        documents allow_external against "the final results list", which is a
        results filter rather than a fetch constraint, so the caller must still
        re-check every returned URL against its own scope rule. site_rag does.
        """
        host = refused_host(url)
        if host:
            raise TavilyError("%s is refused by policy; this deployment never "
                              "causes a crawl of LinkedIn" % host)
        payload: Dict[str, Any] = {
            "url": url,
            "max_depth": max(_TAVILY_MIN_DEPTH, min(int(max_depth), _TAVILY_MAX_DEPTH)),
            "max_breadth": max(1, min(int(max_breadth), 500)),
            "limit": max(1, int(limit)),
            "allow_external": False,
            "extract_depth": extract_depth if extract_depth in ("basic", "advanced") else "basic",
            "format": fmt if fmt in ("markdown", "text") else "markdown",
            "include_images": False,
            "include_favicon": False,
            "include_usage": True,
        }
        if select_domains:
            payload["select_domains"] = list(select_domains)
        if exclude_paths:
            payload["exclude_paths"] = list(exclude_paths)
        if timeout is not None:
            payload["timeout"] = max(_TAVILY_MIN_CRAWL_TIMEOUT,
                                     min(int(timeout), _TAVILY_MAX_CRAWL_TIMEOUT))
        # `instructions` is deliberately never sent: it doubles the cost AND
        # ships a natural-language description of what the assessment is
        # looking for to a third party, which is a far richer disclosure than
        # a bare domain.
        cost = int(math.ceil(payload["limit"] / 10.0)) * (
            2 if payload["extract_depth"] == "advanced" else 1)
        self._spend(cost, "crawl of %s" % url[:80])
        data = self._fetch(_CRAWL_PATH, payload,
                           timeout=(payload.get("timeout") or 0) + 15 or None)
        out: Dict[str, Any] = {"results": [], "failed_results": []}
        for item in (data.get("results") or []):
            if isinstance(item, dict) and item.get("url"):
                out["results"].append({
                    "url": str(item.get("url") or ""),
                    "raw_content": str(item.get("raw_content") or ""),
                })
        for item in (data.get("failed_results") or []):
            if isinstance(item, dict):
                out["failed_results"].append({
                    "url": str(item.get("url") or ""),
                    "error": str(item.get("error") or "unspecified"),
                })
        return out

    def map_site(self, url: str, *, max_depth: int = 1, max_breadth: int = 20,
                 limit: int = 50, select_domains: Optional[Sequence[str]] = None,
                 exclude_paths: Optional[Sequence[str]] = None,
                 timeout: Optional[int] = None) -> List[str]:
        """Discover URLs under `url`. Returns a flat list of URL strings.

        Named map_site, not map, so it does not shadow the builtin.

        The public /map documentation is thin, so `results` is parsed
        DEFENSIVELY: a list of strings and a list of {url: ...} objects are
        both accepted, and anything else yields [] plus a recorded note rather
        than a traceback inside a workflow node.
        """
        host = refused_host(url)
        if host:
            raise TavilyError("%s is refused by policy" % host)
        payload: Dict[str, Any] = {
            "url": url,
            "max_depth": max(_TAVILY_MIN_DEPTH, min(int(max_depth), _TAVILY_MAX_DEPTH)),
            "max_breadth": max(1, min(int(max_breadth), 500)),
            "limit": max(1, int(limit)),
            "allow_external": False,
            "include_usage": True,
        }
        if select_domains:
            payload["select_domains"] = list(select_domains)
        if exclude_paths:
            payload["exclude_paths"] = list(exclude_paths)
        if timeout is not None:
            payload["timeout"] = max(_TAVILY_MIN_CRAWL_TIMEOUT,
                                     min(int(timeout), _TAVILY_MAX_CRAWL_TIMEOUT))
        self._spend(int(math.ceil(payload["limit"] / 10.0)), "map of %s" % url[:80])
        data = self._fetch(_MAP_PATH, payload,
                           timeout=(payload.get("timeout") or 0) + 15 or None)
        raw = data.get("results")
        if raw is None:
            raw = data.get("urls")
        if not isinstance(raw, list):
            self._note("Tavily /map returned %s where a list of URLs was expected; "
                       "no URLs were discovered" % type(raw).__name__)
            return []
        urls: List[str] = []
        for item in raw:
            if isinstance(item, str) and item.strip():
                urls.append(item.strip())
            elif isinstance(item, dict) and item.get("url"):
                urls.append(str(item["url"]).strip())
        if raw and not urls:
            self._note("Tavily /map returned %d entries in an unrecognised shape; "
                       "no URLs were discovered" % len(raw))
        return urls
