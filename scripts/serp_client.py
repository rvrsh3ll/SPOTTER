#!/usr/bin/env python3
"""
serp_client.py — LinkedIn organization intelligence, via search engines.

WHAT IT IS FOR
--------------
WF13's `org` source needs a company provider that works outside RU/CIS, where
hh.ru has no coverage. LinkedIn holds the data; LinkedIn itself will not give it
to us. Search engines have it indexed, and will.

This module asks Google (through SerpAPI) targeted `site:` queries and builds
relational data out of the results: the company page and its affiliated
sub-brands, the people who say they work there, the titles they hold, and the
technologies they name.

WHY NOT CRAWL LINKEDIN DIRECTLY
-------------------------------
Two independent reasons, both verified from this host on 2026-09-20.

1. It does not work. `https://www.linkedin.com/company/<slug>/about/` answers
   HTTP 200 with `<title>LinkedIn Login, Sign in | LinkedIn</title>` and ZERO
   company fields -- no company size, no headquarters, no specialties, no
   `application/ld+json`. The 498 KB response is the login page.
2. It is forbidden. `linkedin.com/robots.txt` is `User-agent: *` / `Disallow: /`,
   over a prose notice that automated access without permission "is strictly
   prohibited".

A search engine's index of those same pages is a different thing: LinkedIn
explicitly allows search crawlers (`User-agent: LinkedInBot / Allow: /`, and a
Googlebot section listing specific exclusions), and reading a SERP is reading the
search engine, not LinkedIn. So this module never issues a request to any
linkedin.com host. It only ever parses result titles, snippets and URLs.

TRANSPORTS, AND WHY ONE OF THEM IS THE DEFAULT
----------------------------------------------
Measured from this host, same query, same minute:

    SerpAPI                        -> works; company page, sub-brands, /jobs
    Bing HTML                      -> HTTP 200, but `site:` IGNORED; generic
                                      results behind the bing.com/ck/a? redirector
    DuckDuckGo HTML                -> HTTP 202 bot-anomaly page, 0 results

Free SERP scraping from a datacenter IP is not a dependable transport. SerpAPI is
therefore primary and the free engines are a labelled fallback, NOT a silent one:
when they return nothing they say so in `errors`. That distinction is the whole
point -- `linkedin-api/app.py` already scrapes DDG and Bing and swallows every
failure into `[]`, which is why its caller has believed for months that the
target simply had no LinkedIn presence.

WHAT THE SERP ACTUALLY CARRIES
------------------------------
Real result shapes, abbreviated (identities replaced with placeholders):

    title   "Jane D. - Security Engineer at Contoso"
    snippet "Security Engineer at Contoso - Experience: Contoso -
             Education: Example Technology Institute - Location: San Diego - ..."
    link    https://www.linkedin.com/in/jane-doe-example

    title   "Contoso AI"                        <- an affiliated sub-brand page
    link    https://www.linkedin.com/company/contoso-ai

So one search yields name, job title, employer, location, education and named
technologies, plus the org-unit structure from the company-page family. That is
the relational data; this module's job is to parse it reliably.

OPSEC
-----
The query contains the target's company name, so every search tells the SERP
provider which company interests us -- the same exposure class as the existing
Flare and hh.ru calls. Documented in README and .env.example rather than gated.
Note that a proxy does NOT hide this on the SerpAPI path: the API key identifies
the account regardless. The proxy is still honoured (and still fails closed) for
the free-engine paths, where source IP is what gets us blocked.

BUDGET
------
SerpAPI bills per search and a people sweep multiplies by role keyword, so the
budget is a hard count, not advice. Default 8 searches: 1 company + 1 sub-brands
+ 6 role keywords.

SANDBOX CONSTRAINTS
-------------------
Runs inside the n8n Python task runner, whose import allowlist is scanned
STATICALLY -- `try: import bs4 / except ImportError` does not help, the node is
killed before line 1. Parsing is stdlib `re` + `html` only.

Environment:
    SERP_MODE            auto | serpapi | bing | ddg     (default: auto)
    SERP_API_KEY         from https://serpapi.com        (enables the API path)
    SERP_MAX_SEARCHES    hard cap per run                (default: 8)
    SERP_ROLE_KEYWORDS   comma-separated people queries  (default: see below)
    SERP_TIMEOUT         per-request seconds             (default: 45)
"""

from __future__ import annotations

import html as _html
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

# The word-aligned company-name matcher. _is_employer_headline used to carry its
# own substring test and blanked genuine job titles that happened to sit inside
# the employer's name; employment_evidence owns that comparison now.
import employment_evidence

SERPAPI_BASE = "https://serpapi.com/search.json"
BING_BASE = "https://www.bing.com/search"
DDG_BASE = "https://html.duckduckgo.com/html/"

# 45, not 20: SerpAPI proxies a real Google query, and a live run lost the
# company lookup -- and with it the org-unit list and the linkedin_* keys --
# to a 20s read timeout while the people sweep on the same key succeeded.
_DEFAULT_TIMEOUT = 45
_DEFAULT_MAX_BYTES = 4 * 1024 * 1024
# 2 company identifiers + 1 org-units + 6 role keywords + 1 jobs = 10, so 12
# leaves slack. It was 8 while the legs already wanted 9, which truncated the
# people sweep on every run without ever saying so.
_DEFAULT_MAX_SEARCHES = 12
_DEFAULT_MAX_SECONDS = 150

# A browser UA for the free-engine paths. SerpAPI needs none.
_DEFAULT_WEB_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

# The six role families worth a search on an engagement. Each becomes one
# `site:linkedin.com/in "<company>" <keyword>` query, so this list IS the budget.
_DEFAULT_ROLE_KEYWORDS = (
    "security",
    "systems administrator OR IT",
    "devops OR cloud OR SRE",
    "engineer OR developer",
    "HR OR recruiter",
    "director OR VP OR chief",
)

# Canonical LinkedIn URL forms.
#
# The country subdomain is the part that matters and the part the existing
# sidecar gets wrong: linkedin-api/app.py's _LI_URL_RE only matches
# `(?:www\.)?linkedin\.com/in/`, so `in.linkedin.com/in/...` and
# `uk.linkedin.com/...` are discarded outright. Two of five results in a live
# test were country-subdomained, so that regex silently drops ~40% of real hits.
_LI_PERSON_RE = re.compile(
    r"https?://(?:[a-z]{2,3}\.)?(?:www\.)?linkedin\.com/in/([A-Za-z0-9_\-%.]+)",
    re.IGNORECASE,
)
_LI_COMPANY_RE = re.compile(
    r"https?://(?:[a-z]{2,3}\.)?(?:www\.)?linkedin\.com/company/([A-Za-z0-9_\-%.]+)",
    re.IGNORECASE,
)

# Sub-paths of a company page that are facets of the SAME company, not siblings.
# `/company/contoso/jobs` is Contoso; `/company/contoso-ai` is a unit.
_LI_COMPANY_FACETS = ("jobs", "life", "people", "about", "posts", "videos", "insights")

# Technology tokens worth lifting out of a profile snippet. Deliberately a
# curated list rather than "any capitalised word": a snippet is 160 characters of
# marketing prose, and a loose extractor turns "Experience: Contoso" and
# "Education: Example Institute" into technologies.
_TECH_TOKENS = (
    "Active Directory", "Azure", "AWS", "GCP", "Google Cloud", "Kubernetes", "Docker",
    "VMware", "Hyper-V", "Citrix", "Okta", "Duo", "CrowdStrike", "SentinelOne",
    "Defender", "M365 Defender", "Microsoft 365", "Office 365", "Exchange", "SharePoint",
    "Splunk", "Sentinel", "QRadar", "Elastic", "Palo Alto", "Fortinet", "Cisco",
    "Terraform", "Ansible", "Puppet", "Chef", "Jenkins", "GitLab", "GitHub",
    "Python", "PowerShell", "Java", "Kotlin", "Go", "Rust", "C#", ".NET",
    "Linux", "Windows Server", "Oracle", "SAP", "Salesforce", "ServiceNow",
    "Snowflake", "Databricks", "Kafka", "Postgres", "PostgreSQL", "MySQL", "MongoDB",
)

# Word-boundary matched, NOT substring. A plain `"go" in text` fires on
# "Goodexample", "Google" and "going"; a live test produced "Go" as a technology
# for three of five people purely from their surnames. \b does not work at the
# edge of "C#" or ".NET", so the boundary is asserted with lookarounds against
# the identifier character class instead.
_TECH_RE = {
    tok: re.compile(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % re.escape(tok), re.I)
    for tok in _TECH_TOKENS
}


def _first_set(*vals):
    """First value that is not None. Unlike `or`, keeps a deliberate 0."""
    for v in vals:
        if v is not None:
            return v
    return None


class SerpError(Exception):
    """A request-level failure the caller should record, not raise through."""


def _txt(raw: Any) -> str:
    """Strip tags and unescape, for the HTML-scrape paths."""
    if not raw:
        return ""
    s = re.sub(r"<[^>]+>", " ", str(raw))
    s = _html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def canonical_person_url(raw: str) -> Optional[str]:
    """`in.linkedin.com/in/x?trk=y` -> `https://www.linkedin.com/in/x/`."""
    if not raw:
        return None
    m = _LI_PERSON_RE.search(str(raw))
    if not m:
        return None
    slug = m.group(1).rstrip("/")
    return "https://www.linkedin.com/in/%s/" % slug if slug else None


def canonical_company_url(raw: str) -> Optional[Tuple[str, str]]:
    """Return (canonical_url, slug) for a company page, or None.

    A facet sub-path (`/company/sample/jobs`) canonicalises to the company itself,
    so the caller can tell a facet from a genuinely different org unit by
    comparing slugs.
    """
    if not raw:
        return None
    m = _LI_COMPANY_RE.search(str(raw))
    if not m:
        return None
    slug = m.group(1).rstrip("/")
    if not slug or slug.lower() in _LI_COMPANY_FACETS:
        return None
    return ("https://www.linkedin.com/company/%s/" % slug, slug.lower())


def parse_person_title(title: str) -> Dict[str, str]:
    """Split a LinkedIn SERP result title into name / job title / employer.

    Real shapes observed in one live search (names replaced):
        "Jane D. - Security Engineer at Contoso"
        "Sam Placeholder - Security Engineer ll @ Contoso"
        "John Smith - Senior Security Engineer at Contoso | LinkedIn"
        "Jane Roe – Head of IT — Sample Ltd"

    Separators vary (hyphen, en dash, em dash, pipe) and so does the
    title/employer joiner ("at", "@"). Anything unparseable returns the raw
    title as `job_title` with an empty employer rather than guessing, because a
    wrong employer silently mis-attributes a person to the target company.
    """
    t = _txt(title)
    if not t:
        return {"name": "", "job_title": "", "employer": ""}
    # Drop the trailing site brand.
    t = re.sub(r"\s*[|\-–—]\s*LinkedIn\s*$", "", t, flags=re.I).strip()

    parts = [p.strip() for p in re.split(r"\s+[-–—|]\s+", t) if p.strip()]
    if not parts:
        return {"name": "", "job_title": "", "employer": ""}

    name = parts[0]
    # "Name. Title at Co" — a period-separated variant with no dash at all.
    if len(parts) == 1 and ". " in name:
        head, _, tail = name.partition(". ")
        if len(head.split()) <= 4:
            name, parts = head.strip(), [head.strip(), tail.strip()]

    rest = " ".join(parts[1:]).strip()
    job_title, employer = rest, ""
    m = re.search(r"^(.*?)\s+(?:at|@)\s+(.+)$", rest, re.I)
    if m:
        job_title = m.group(1).strip()
        employer = m.group(2).strip()
    return {"name": name, "job_title": job_title, "employer": employer}


def parse_person_snippet(snippet: str) -> Dict[str, Any]:
    """Lift Location / Education / Experience and named technologies out.

    `Experience` is the one that matters most and it was promised by this
    docstring for months while the loop below only read the other two. It is
    LinkedIn's own employer field, and it is the ONLY employer signal on the
    very common row whose title carries no "<role> at <employer>" -- so dropping
    it meant the person reached the employment gate with employer="", took
    CX_NO_EMPLOYER (-20), and was held. One individual in the whole graph
    carried an employment_tier before this was fixed.
    """
    s = _txt(snippet)
    out: Dict[str, Any] = {"location": "", "education": "", "experience": "",
                           "technologies": []}
    if not s:
        return out
    # SerpAPI renders these as " · " or " - " separated key: value runs.
    for key, dest in (("Location", "location"), ("Education", "education"),
                      ("Experience", "experience")):
        m = re.search(r"%s:\s*([^·|]+?)(?:\s*[·|]|\s+\d+\+?\s+connections|$)" % key, s, re.I)
        if m:
            out[dest] = m.group(1).strip(" .,-–—")
    seen = []
    for tok in _TECH_TOKENS:
        if _TECH_RE[tok].search(s) and tok not in seen:
            seen.append(tok)
    out["technologies"] = seen[:12]
    return out


# LinkedIn renders a posting's <title> as "<Company> hiring <Role> in <Location>",
# with the " | LinkedIn" brand already stripped by the time we get here. Google's
# index reproduces it verbatim, which is what makes the fallback transport work
# at all.
_JOB_TITLE_RE = re.compile(
    r"^(?P<company>.+?)\s+hiring\s+(?P<title>.+?)(?:\s+in\s+(?P<location>.+?))?$",
    re.I,
)


def parse_job_title(title: str) -> Dict[str, str]:
    """Split a LinkedIn job-posting result title into company / role / location.

    Returns empty strings when the shape does not match. That is the OPPOSITE
    of parse_person_title()'s contract, and deliberately so: an unrecognised
    person title still names a person, but an unrecognised job title is not
    known to name a role at all. Keeping the raw string as a "role" is exactly
    how a person's name came to be printed as an open vacancy on the Job Title
    Match card -- see issues.md, "Job Title Match listed people who were not in
    the graph".
    """
    t = _txt(title)
    out = {"company": "", "title": "", "location": ""}
    if not t:
        return out
    t = re.sub(r"\s*[|\-–—]\s*LinkedIn\s*$", "", t, flags=re.I).strip()
    m = _JOB_TITLE_RE.match(t)
    if not m:
        return out
    out["company"] = (m.group("company") or "").strip(" .,-–—")
    out["title"] = (m.group("title") or "").strip(" .,-–—")
    out["location"] = (m.group("location") or "").strip(" .,-–—")
    if not out["company"] or not out["title"]:
        return {"company": "", "title": "", "location": ""}
    return out


class SerpClient:
    def __init__(
        self,
        mode: Optional[str] = None,
        proxy_url: str = "",
        user_agent: str = "",
        timeout: Optional[int] = None,
        api_key: Optional[str] = None,
        max_searches: Optional[int] = None,
        max_seconds: int = _DEFAULT_MAX_SECONDS,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        role_keywords: Optional[List[str]] = None,
    ):
        self.api_key = (api_key if api_key is not None
                        else os.environ.get("SERP_API_KEY", "")).strip()

        requested = (mode or os.environ.get("SERP_MODE", "auto") or "auto").strip().lower()
        if requested not in ("auto", "serpapi", "bing", "ddg"):
            requested = "auto"
        self.requested_mode = requested
        self.mode = self._resolve_mode(requested)

        self.proxy_url = (proxy_url or "").strip()
        self.proxies = (
            {"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None
        )
        self.user_agent = (user_agent or "").strip() or _DEFAULT_WEB_UA

        # `or` chains would treat 0 as "unset". SERP_MAX_SEARCHES=0 is
        # documented as disabling the LinkedIn provider, and it silently
        # resolved to the default instead, so the explicit None tests matter.
        self.timeout = _first_set(timeout, _as_int(os.environ.get("SERP_TIMEOUT")),
                                  _DEFAULT_TIMEOUT)
        self.max_searches = _first_set(max_searches,
                                       _as_int(os.environ.get("SERP_MAX_SEARCHES")),
                                       _DEFAULT_MAX_SEARCHES)
        self.max_seconds = max_seconds
        self.max_bytes = max_bytes

        kws = role_keywords
        if kws is None:
            raw = os.environ.get("SERP_ROLE_KEYWORDS", "").strip()
            kws = [k.strip() for k in raw.split(",") if k.strip()] if raw else list(_DEFAULT_ROLE_KEYWORDS)
        self.role_keywords = kws

        self.errors: List[str] = []
        self._searches = 0
        self._started = time.time()

    # ── mode ──────────────────────────────────────────────────────────────────

    def _resolve_mode(self, requested: str) -> str:
        if requested in ("serpapi", "bing", "ddg"):
            return requested
        return "serpapi" if self.api_key else "bing"

    @property
    def source_label(self) -> str:
        if self.mode == "serpapi":
            return "serpapi" if self.api_key else "not_configured"
        return self.mode

    @property
    def is_reliable(self) -> bool:
        """False for the free engines, which the UI must label as such.

        Not a style judgement: measured from this host, Bing ignored the `site:`
        operator entirely and DuckDuckGo answered a bot-anomaly page. Treating
        their empty results as "the company has no LinkedIn presence" is the
        exact mistake this flag exists to prevent.
        """
        return self.mode == "serpapi" and bool(self.api_key)

    # ── budget + transport ────────────────────────────────────────────────────

    def budget_exhausted(self) -> bool:
        return (self._searches >= self.max_searches
                or (time.time() - self._started) >= self.max_seconds)

    def _note(self, msg: str) -> None:
        if msg not in self.errors:
            self.errors.append(msg)

    def _fetch(self, url: str, *, params: Optional[dict] = None,
               headers: Optional[dict] = None, data: Optional[dict] = None) -> requests.Response:
        if self.budget_exhausted():
            raise SerpError("SERP budget exhausted (%d searches / %ds)"
                            % (self.max_searches, self.max_seconds))
        self._searches += 1
        try:
            if data is not None:
                r = requests.post(url, data=data, headers=headers, timeout=self.timeout,
                                  proxies=self.proxies, stream=True)
            else:
                r = requests.get(url, params=params, headers=headers, timeout=self.timeout,
                                 proxies=self.proxies, stream=True)
        except requests.exceptions.ProxyError as e:
            # Never retried direct. A campaign that asked for proxied egress must
            # not leak a request because the proxy happened to be down.
            raise SerpError("SERP proxy unreachable; refusing to fall back to direct egress: %s" % e)
        except Exception as e:
            raise SerpError("SERP request failed (%s): %s" % (url, e))

        body = b""
        try:
            for chunk in r.iter_content(64 * 1024):
                body += chunk
                if len(body) >= self.max_bytes:
                    body = body[: self.max_bytes]
                    break
        finally:
            r.close()
        r._content = body           # noqa: SLF001
        r._content_consumed = True  # noqa: SLF001
        return r

    # ── one search, three transports, one shape ───────────────────────────────

    def search(self, query: str, num: int = 10) -> List[Dict[str, str]]:
        """Return [{title, link, snippet}] for a query, whatever the transport."""
        if not query.strip():
            return []
        if self.mode == "serpapi":
            return self._search_serpapi(query, num)
        if self.mode == "bing":
            return self._search_bing(query)
        return self._search_ddg(query)

    def _search_serpapi(self, query: str, num: int) -> List[Dict[str, str]]:
        if not self.api_key:
            raise SerpError(
                "SERP_API_KEY is not set. Free engines are unreliable from a "
                "datacenter IP (Bing ignores `site:`, DuckDuckGo answers a bot "
                "challenge), so the LinkedIn organization source is disabled."
            )
        r = self._fetch(SERPAPI_BASE, params={
            "q": query, "api_key": self.api_key, "num": num, "engine": "google",
        })
        if not r.ok:
            raise SerpError("SerpAPI returned HTTP %s" % r.status_code)
        try:
            d = r.json() or {}
        except Exception as e:
            raise SerpError("SerpAPI returned unparseable JSON: %s" % e)
        if d.get("error"):
            raise SerpError("SerpAPI error: %s" % str(d["error"])[:200])
        out = []
        for row in (d.get("organic_results") or []):
            out.append({
                "title": str(row.get("title") or ""),
                "link": str(row.get("link") or ""),
                "snippet": str(row.get("snippet") or ""),
            })
        return out

    def _search_google_jobs(self, query: str, country: str = "") -> List[Dict[str, str]]:
        """SerpAPI's google_jobs engine. Returns normalized posting rows.

        A separate transport rather than a flag on search(): that one is pinned
        to engine=google and reads `organic_results`, while this engine answers
        with `jobs_results` and a different row shape entirely.

        `country` is an ISO-2. Without it SerpAPI answers as if from the US, so
        a European target comes back with American postings -- the kind of wrong
        answer that looks right.
        """
        if not self.api_key:
            raise SerpError(
                "SERP_API_KEY is not set, so the google_jobs engine is "
                "unavailable; falling back to a site: query."
            )
        params = {"q": query, "api_key": self.api_key, "engine": "google_jobs"}
        cc = (country or "").strip().lower()
        if len(cc) == 2:
            params["gl"] = cc
        r = self._fetch(SERPAPI_BASE, params=params)
        if not r.ok:
            raise SerpError("SerpAPI google_jobs returned HTTP %s" % r.status_code)
        try:
            d = r.json() or {}
        except Exception as e:
            raise SerpError("SerpAPI google_jobs returned unparseable JSON: %s" % e)
        if d.get("error"):
            # Includes "hasn't returned any results" AND a plan that does not
            # carry this engine. Both mean "use the other transport", which is
            # why jobs() treats any SerpError here as a fallback trigger.
            raise SerpError("SerpAPI google_jobs error: %s" % str(d["error"])[:200])
        out = []
        for row in (d.get("jobs_results") or []):
            ext = row.get("detected_extensions") or {}
            out.append({
                "title": str(row.get("title") or ""),
                "company": str(row.get("company_name") or ""),
                "location": str(row.get("location") or ""),
                "via": re.sub(r"^via\s+", "", str(row.get("via") or ""), flags=re.I),
                "posted": str(ext.get("posted_at") or ""),
                "url": str(row.get("share_link") or ""),
            })
        return out

    def _search_bing(self, query: str) -> List[Dict[str, str]]:
        r = self._fetch(BING_BASE, params={"q": query, "count": 20},
                        headers={"User-Agent": self.user_agent,
                                 "Accept-Language": "en-US,en;q=0.9"})
        if not r.ok:
            raise SerpError("Bing returned HTTP %s" % r.status_code)
        out = []
        for block in re.findall(r'<li class="b_algo".*?</li>', r.text or "", re.S):
            m = re.search(r'<a[^>]+href="(https?://[^"]+)"', block)
            h = re.search(r"<h2>(.*?)</h2>", block, re.S)
            p = re.search(r"<p[^>]*>(.*?)</p>", block, re.S)
            link = _html.unescape(m.group(1)) if m else ""
            # Bing wraps organic links in its own redirector, which carries no
            # target URL we can read; such a row is unusable for URL extraction.
            if "bing.com/ck/a" in link:
                link = ""
            out.append({"title": _txt(h.group(1)) if h else "",
                        "link": link,
                        "snippet": _txt(p.group(1)) if p else ""})
        if not out:
            raise SerpError(
                "Bing returned no parseable results. Measured from this host, Bing "
                "ignores the `site:` operator and wraps organic links in its ck/a "
                "redirector — treat an empty result as 'Bing is unusable here', not "
                "as 'the company has no LinkedIn presence'."
            )
        return out

    def _search_ddg(self, query: str) -> List[Dict[str, str]]:
        r = self._fetch(DDG_BASE, data={"q": query},
                        headers={"User-Agent": self.user_agent,
                                 "Content-Type": "application/x-www-form-urlencoded"})
        if r.status_code == 202 or "anomaly" in (r.text or "")[:4000].lower():
            raise SerpError(
                "DuckDuckGo answered a bot-challenge page (HTTP %s). It blocks "
                "datacenter IPs; an empty result here means 'blocked', not 'no "
                "presence'." % r.status_code
            )
        if not r.ok:
            raise SerpError("DuckDuckGo returned HTTP %s" % r.status_code)
        links = re.findall(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', r.text or "", re.S)
        snips = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text or "", re.S)
        out = []
        for i, (u, t) in enumerate(links):
            out.append({"title": _txt(t), "link": _html.unescape(u),
                        "snippet": _txt(snips[i]) if i < len(snips) else ""})
        if not out:
            raise SerpError("DuckDuckGo returned no parseable results (likely rate-limited)")
        return out

    # ── the org-shaped queries ────────────────────────────────────────────────

    def company_pages(self, company: str,
                      identity: Optional[Dict[str, Any]] = None,
                      match_min: Optional[int] = None,
                      max_terms: int = 2,
                      ) -> Tuple[Dict[str, Any], List[Dict[str, str]], List[Dict[str, str]], Dict[str, Any]]:
        """(profile, units, mentions, pick) from `site:linkedin.com/company "<company>"`.

        The best EVIDENCED slug match becomes the company; every other distinct
        company slug whose name is built on the target's is an affiliated page —
        a sub-brand or business unit — and the remainder are mentions.

        There used to be a fourth outcome, and it was the dangerous one: when no
        slug matched the seed, the first company result was adopted anyway "so a
        legal name that differs from the trading name still produces a profile".
        A quoted company-name search returns every page that MENTIONS the target,
        so that fallback adopted whichever vendor, reseller, recruiter or
        publication Google ranked first — under the target's own heading, with
        its description flowing into org_profile and its name into the alias list
        the employment gate scores people against. The legal-name case it existed
        for is served properly now: the operator's Additional Identifiers are in
        `identity`, so the legal name is SEARCHED and MATCHED rather than guessed
        at. Refusing is the correct fourth outcome.

        `pick` carries the refusal and the near misses, so the card can say what
        was seen and why none of it was adopted.
        """
        # `site:` goes LAST. Measured on the same company in the same minute:
        #   site:linkedin.com/company "Sample"  -> 0 of 10 results were LinkedIn
        #   "Sample" site:linkedin.com/company  -> 10 of 10
        # With the operator first, Google relaxes it and returns the company's
        # own domain instead. linkedin-api/app.py's _build_query documents the
        # same ordering rule for /in; this file reproduced the bug before
        # noticing the comment.
        ident = identity or employment_evidence.identity_from_aliases([company])
        terms = [t for t in (ident.get("search_terms") or ()) if t] or (
            [company] if (company or "").strip() else [])
        # CAPPED, unlike hh.ru's. SerpAPI bills per search and self.role_keywords
        # spends six of them on the people sweep out of the same budget, so an
        # unbounded identifier loop here would quietly truncate the roster --
        # trading a company the matcher can now identify for people it can no
        # longer find. Two is the useful case (trading name + legal entity);
        # beyond that the domain corroboration does the work.
        if max_terms and len(terms) > max_terms:
            self._note("searching the first %d of %d identifiers on LinkedIn; the "
                       "rest are still used to MATCH what comes back, and to search "
                       "the providers that are not billed per query"
                       % (max_terms, len(terms)))
            terms = terms[:max_terms]

        rows: List[Dict[str, str]] = []
        for term in terms:
            if self.budget_exhausted():
                self._note("SERP budget exhausted before every identifier was "
                           "searched; %r and after were not tried" % term)
                break
            try:
                rows.extend(self.search('"%s" site:linkedin.com/company' % term))
            except SerpError as e:
                # Per-term, not per-call: one identifier's search failing must
                # not cost the others, and with one search per identifier a
                # single transient 503 used to take the whole company lookup.
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
                "name": _txt(row.get("title")).split("|")[0].strip() or slug,
                "url": url, "slug": slug,
                "description": _txt(row.get("snippet")),
                # The slug scored as a second spelling of the name. It is
                # machine-assigned from the company's own page, so it is often
                # the half of the row that carries the identifier while the
                # title carries marketing copy.
                "alt_names": [slug.replace("-", " ")],
            })

        pick = employment_evidence.pick_company(candidates, ident, match_min=match_min)
        best = dict(pick["best"]) if pick["best"] else {}
        units = [{"name": u.get("name", ""), "url": u.get("url", ""), "kind": "unit"}
                 for u in pick["units"]]
        mentions = [{"name": m.get("name", ""), "url": m.get("url", ""), "kind": "mention"}
                    for m in pick["mentions"]]
        return best, units, mentions, pick

    @staticmethod
    def _is_employer_headline(job_title: str, company: str) -> bool:
        """True when the parsed 'title' is really just the company name.

        Many LinkedIn headlines are `Name - Sample Corp` with no role at all, and
        the title parser cannot invent one. Left alone, the company name flows
        into derive_specialty() -- and "Example Harbor Information Security"
        contains "information security", so four people in a live run were
        classified as Security Professionals on the strength of their employer's
        name. That is a fabricated signal in the job-title match, which is worse
        than an absent one.

        This used to be its own raw-substring test -- `len(t) > 6 and (t in c or
        c in t)` over punctuation-stripped strings -- which is the exact bug
        edgar_client.name_score documents and fixed ("NFO INC" normalises to
        "nfo", a substring of "iNFOrmation"). It meant the GENUINE job title
        "Information Security" was blanked against an employer named "Example
        Harbor Information Security", because the title is a word-run inside the
        company name. Delegating to the word-aligned matcher keeps the protection above
        and drops the collateral damage.
        """
        return employment_evidence.is_company_headline(job_title, (company,))

    def people(self, company: str, keywords: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Everyone the engine returned for a company-name query, unfiltered.

        NOTE THE CONTRACT, AND DO NOT "HELPFULLY" TIGHTEN IT HERE. These rows are
        candidates, not employees: a quoted company-name search also surfaces
        former staff, vendors, recruiters, applicants and anyone who merely
        mentions the company. Deciding which of them actually work there is
        employment_evidence's job, applied once in WF13 over the union of every
        provider. A provider that pre-filters would leave that gate scored
        against a population it cannot see, and the held bucket -- which is how
        an operator spots a gate false-negative -- would silently lose rows.
        """
        out: List[Dict[str, Any]] = []
        seen = set()
        for kw in (keywords if keywords is not None else self.role_keywords):
            if self.budget_exhausted():
                self._note("SERP budget exhausted before every role keyword was searched")
                break
            # Same ordering rule as company_pages(): the operator goes last.
            q = '"%s" %s site:linkedin.com/in' % (company, kw)
            try:
                rows = self.search(q)
            except SerpError as e:
                self._note(str(e))
                continue
            except Exception as e:                  # noqa: BLE001
                self._note("SERP search failed unexpectedly (%s): %r" % (kw, e))
                continue
            for row in rows:
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
                if self._is_employer_headline(_title, company) and not parsed["employer"]:
                    # Keep the raw headline so nothing is lost, but do not let a
                    # company name be treated as a role.
                    _headline, _title = _title, ""
                # Employer precedence, strongest first:
                #
                #   title      "<role> at <employer>" -- an explicit claim.
                #   experience LinkedIn's own Experience: field, lifted from the
                #              snippet. Just as much an assertion as the title,
                #              and present on the many rows whose title is only
                #              "<Name> - <role>" with no employer at all.
                #   headline   a bare company-shaped headline. The WEAKEST: it
                #              was never asserted to BE an employer, it is just
                #              the only company-shaped string on the row.
                #
                # employer_from_headline marks that last case and nothing else.
                # employment_evidence.assess() reads it for CX_HEADLINE_ONLY, so
                # it must stay False when Experience supplied the employer --
                # that is a real employer field, not a guess at one.
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

    # ── open roles ────────────────────────────────────────────────────────────

    def jobs(self, company: str, identity: Optional[Dict[str, Any]] = None,
             country: str = "", max_rows: int = 60) -> Dict[str, Any]:
        """Open roles the target is advertising. Never raises.

        Two transports, jobs engine first:

          1. SerpAPI engine=google_jobs -- structured postings, and the only one
             that returns actual vacancies rather than a company's jobs landing
             page. It aggregates LinkedIn, Indeed, Glassdoor and the rest, which
             is a feature for coverage and a hazard for attribution (below).
          2. `"<company>" site:linkedin.com/jobs/view` through the ordinary
             google engine. LinkedIn only, sparser, but it needs no particular
             SerpAPI plan -- so an account without the jobs engine degrades to
             this instead of reporting that nobody is hiring.

        EVERY row is gated on the employer name. A company-name query returns
        other companies' postings -- a recruiter reposting, a competitor named
        in the text, a job board's "similar roles" block -- and an ungated list
        is the company-identification bug one level down: it would feed foreign
        roles into the Job Title Match card and they would match. Refusals are
        COUNTED and returned, never silently dropped, so an operator can see
        when the target was identified wrongly.
        """
        out: Dict[str, Any] = {"rows": [], "refused": [], "transport": "",
                               "errors": self.errors}
        term = _txt(company)
        if not term:
            self._note("no company name to search open roles for")
            return out

        ident = identity or employment_evidence.identity_from_aliases([term])
        aliases = [a for a in (ident.get("names") or ()) if a] or [term]
        match_min = int(ident.get("match_min") or employment_evidence.EMPLOYER_MATCH_MIN)

        raw: List[Dict[str, str]] = []
        try:
            raw = self._search_google_jobs('"%s"' % term, country=country)
            out["transport"] = "google_jobs"
        except SerpError as e:
            self._note(str(e))
        except Exception as e:                      # noqa: BLE001
            self._note("google_jobs failed unexpectedly: %r" % e)

        if not raw:
            # Operator LAST -- the same measured ordering rule as company_pages()
            # and people(). Leading with site: returned 0 of 10 on-site results.
            try:
                for row in self.search('"%s" site:linkedin.com/jobs/view' % term):
                    parsed = parse_job_title(row.get("title", ""))
                    if not parsed["title"]:
                        continue
                    raw.append({
                        "title": parsed["title"], "company": parsed["company"],
                        "location": parsed["location"], "via": "LinkedIn",
                        "posted": "", "url": str(row.get("link") or ""),
                    })
                if raw:
                    out["transport"] = "linkedin-serp"
            except SerpError as e:
                self._note(str(e))
            except Exception as e:                  # noqa: BLE001
                self._note("LinkedIn jobs search failed unexpectedly: %r" % e)

        seen = set()
        for row in raw:
            title = _txt(row.get("title"))
            if not title:
                continue
            key = (title.lower(), _txt(row.get("company")).lower())
            if key in seen:
                continue
            seen.add(key)
            verdict, score = employment_evidence.employer_verdict(
                row.get("company"), aliases, match_min=match_min)
            if verdict == employment_evidence.VERDICT_MATCH:
                out["rows"].append(dict(row, employer_score=int(score)))
            else:
                out["refused"].append(dict(row, employer_score=int(score),
                                           verdict=verdict))
        out["rows"] = out["rows"][:max_rows]
        out["refused"] = out["refused"][:max_rows]
        return out

    # ── the whole profile in one call ─────────────────────────────────────────

    def organization_profile(self, company_name: str,
                             role_keywords: Optional[List[str]] = None,
                             identity: Optional[Dict[str, Any]] = None,
                             match_min: Optional[int] = None) -> Dict[str, Any]:
        """Mirrors hh_client.HHClient.organization_profile()'s never-raises contract.

        Every leg records into `errors` and the partially-filled result is
        returned, so the card renders whatever was reached.
        """
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
        ident = identity or employment_evidence.identity_from_aliases([company_name])
        terms = [t for t in (ident.get("search_terms") or ()) if t] or (
            [company_name] if (company_name or "").strip() else [])
        out["queries"] = list(terms)
        if not terms:
            self._note("SERP provider needs a company name; none was resolved")
            return out

        pick: Dict[str, Any] = {}
        try:
            profile, units, mentions, pick = self.company_pages(
                company_name, identity=ident, match_min=match_min)
        except SerpError as e:
            self._note(str(e))
            profile, units, mentions = {}, [], []
        except Exception as e:                      # noqa: BLE001 - see below
            # Deliberately broad. This method is documented as never raising,
            # and it is called from a WF13 code node where an escaped exception
            # costs the operator every other source in the run, not just this
            # one. An unexpected parser failure is recorded and moved past.
            self._note("SERP company lookup failed unexpectedly: %r" % (e,))
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
            # Nothing cleared the floor. Say which near miss was refused and why
            # — an unexplained empty company block is indistinguishable from a
            # search engine that returned nothing at all.
            out["rejected"] = pick.get("rejected") or []
            out["match_reason"] = pick.get("reason") or ""
            if out["rejected"]:
                self._note(
                    "LinkedIn search returned %d company page(s) for %s but none "
                    "is evidently the target — %s. Not adopted: a quoted "
                    "company-name search also returns vendors, resellers, "
                    "recruiters and publications that merely mention it."
                    % (len(out["rejected"]), " / ".join(repr(t) for t in terms),
                       out["match_reason"]))
        out["related"] = units
        out["mentions"] = mentions

        try:
            # The people sweep keeps the operator's STRONGEST name, and uses the
            # confirmed company page's name once there is one: a LinkedIn profile
            # headline spells the employer the way LinkedIn does.
            _people_term = (out["profile"].get("name") or "").strip() or terms[0]
            out["people"] = self.people(_people_term, role_keywords)
        except SerpError as e:
            self._note(str(e))
        except Exception as e:                      # noqa: BLE001 - see above
            self._note("SERP people sweep failed unexpectedly: %r" % (e,))

        if out["people"] and not out["matched"]:
            # People found but no company page: still a match, and saying
            # otherwise would hide the roster.
            out["matched"] = True
        if not self.is_reliable and not out["matched"]:
            self._note(
                "No results from the %s transport, which is unreliable from a "
                "datacenter IP. Set SERP_API_KEY to use SerpAPI before concluding "
                "the company has no LinkedIn presence." % self.mode
            )
        return out


def _as_int(v: Any) -> Optional[int]:
    try:
        return int(str(v).strip())
    except Exception:
        return None
