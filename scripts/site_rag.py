#!/usr/bin/env python3
"""
site_rag.py — crawl the target company's own website, extract org intelligence,
and index it for retrieval.

WHY THIS EXISTS
---------------
The Organization card's other providers each cover a slice of the world. hh.ru
covers RU/CIS employers. The SERP provider covers whoever LinkedIn indexes and a
search engine will show us. Neither covers the ordinary case: a private company
with no job-board presence and a thin LinkedIn page.

Every company has a website. It is the one source that always exists, it is the
target's own infrastructure and therefore in scope under the engagement's Rules
of Engagement, and it is usually the most candid thing about them -- leadership
pages name executives, careers pages name the stack, press pages name the
partners and customers.

WHAT IT PRODUCES
----------------
1. Org facts for the card (description, industry, HQ/offices, units).
2. Named people with titles, promotable to Individual nodes.
3. Named technologies and named partner/customer companies.
4. A per-campaign RAG collection so the Prompt tab can answer free-form
   questions about the company, with a citation back to the source page.

DISCOVERY: SITEMAP-FIRST, NEVER PATH-GUESSING
---------------------------------------------
The obvious design -- fetch /about, /team, /leadership, /contact -- was tested
against a real corporate site before this module was written, and it fails:

    /about  /about-us  /team  /leadership  /contact   ->  all HTTP 404
    application/ld+json blocks                        ->  0
    robots.txt "Sitemap:" directive                   ->  present
    sitemap.xml                                       ->  200, >1,000 <loc> entries

The org-relevant pages were there the whole time, at /our-team/,
/about/leadership-team/, /about/our-staff/ and /contact-us/ -- paths no
guess-list would ever produce. So the crawler DISCOVERS urls (sitemap first,
link-following as fallback) and then SCORES them, rather than guessing.

ROBOTS.TXT
----------
Its Disallow rules are deliberately not applied: this is the target's own site
under a documented RoE, and robots.txt routinely hides exactly the directories
worth reading. The file is still fetched, because its `Sitemap:` directive is
the cheapest map of the site. Ignore the restrictions, keep the map.

That makes robots.txt useless as a safety rail, so the rail is somewhere else:
SCOPE. Every candidate URL's host must be the campaign's registrable domain or a
subdomain of it, checked in `in_scope()` before any fetch. A robots-ignoring
crawler that cannot leave the target's own domain cannot wander onto a third
party. That check is the single most important thing in this file.

SANDBOX CONSTRAINTS
-------------------
Runs inside the n8n Python task runner, whose import allowlist is scanned
STATICALLY -- `try: import bs4 / except ImportError` does not help, the node dies
before line 1. So: stdlib `html.parser`, `xml.etree`, `re`, `urllib.parse`, plus
`requests`. No bs4, no lxml, no trafilatura, no readability.

Environment:
    SITE_ENABLED             1 to crawl                    (default: 1)
    SITE_MAX_PAGES           pages fetched per run         (default: 60)
    SITE_MAX_DEPTH           link-following depth          (default: 3)
    SITE_DELAY_MS            pause between requests        (default: 500)
    SITE_MAX_BYTES_PER_PAGE  bounded read per page         (default: 2 MiB)
    SITE_MAX_SECONDS         wall-clock ceiling            (default: 180)
    SITE_TIMEOUT             per-request timeout           (default: 20)
    SITE_PREFLIGHT_TIMEOUT   egress preflight, 0 to skip   (default: min(SITE_TIMEOUT, 10))
    SITE_CHUNK_CHARS         chunk size                    (default: 1500)
    SITE_CHUNK_OVERLAP       chunk overlap                 (default: 200)
"""

from __future__ import annotations

import html as _html
import json
import os
import re
import time
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import requests

_DEFAULT_MAX_PAGES = 60
_DEFAULT_MAX_DEPTH = 3
_DEFAULT_DELAY_MS = 500
_DEFAULT_MAX_BYTES = 2 * 1024 * 1024
_DEFAULT_MAX_SECONDS = 180
_DEFAULT_TIMEOUT = 20
# Ceiling on the egress preflight, which exists to fail fast: inheriting a
# generous per-page SITE_TIMEOUT would defeat the point of asking first.
_DEFAULT_PREFLIGHT_CAP = 10
_DEFAULT_CHUNK_CHARS = 1500
_DEFAULT_CHUNK_OVERLAP = 200

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

# URL tokens that mark a page as organizationally interesting, and how much.
# Scored on the path, so `/about/our-staff/` scores on both `about`
# and `staff`. Weighted because a leadership page is worth more than a
# generic news post, and the page budget is small.
_PATH_SCORES: Tuple[Tuple[str, int], ...] = (
    ("leadership", 10), ("executive", 10), ("management", 9), ("board", 9),
    ("who-we-are", 9), ("whoweare", 9), ("our-team", 9), ("meet-the-team", 9),
    ("team", 8), ("people", 8), ("staff", 8), ("employee", 7),
    ("about", 8), ("company", 6), ("mission", 5), ("history", 4), ("values", 4),
    ("contact", 7), ("location", 7), ("office", 7), ("address", 6),
    ("career", 6), ("job", 6), ("hiring", 6), ("vacan", 6), ("work-with-us", 6),
    ("partner", 6), ("customer", 5), ("client", 5), ("case-stud", 5),
    ("press", 4), ("news", 3), ("media", 3), ("blog", 1),
    ("technolog", 4), ("service", 3), ("solution", 3), ("product", 3),
    ("investor", 5), ("governance", 5), ("compliance", 4), ("certification", 4),
)

# Paths that are never worth a page of the budget.
_PATH_SKIP = re.compile(
    r"/(?:wp-(?:admin|includes|json)|feed|rss|atom|tag|category|author|search|"
    r"cart|checkout|account|login|signin|register|privacy|terms|cookie|"
    r"sitemap[^/]*\.xml)(?:/|$)", re.I,
)
_EXT_SKIP = re.compile(
    r"\.(?:jpe?g|png|gif|svg|webp|ico|css|js|mjs|json|xml|pdf|zip|gz|tar|"
    r"mp4|mp3|avi|mov|woff2?|ttf|eot|dmg|exe|msi)(?:\?|$)", re.I,
)

# Blocks whose text is navigation furniture, not content.
_DROP_TAGS = {"script", "style", "noscript", "nav", "footer", "header", "aside",
              "form", "svg", "iframe", "template"}
_HEADING_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
_BLOCK_TAGS = {"p", "div", "section", "article", "li", "tr", "br", "td", "th",
               "blockquote", "figcaption"} | _HEADING_TAGS


class SiteError(Exception):
    """A request-level failure the caller should record, not raise through."""


def _as_int(v: Any, default: int) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain: `www.a.example.co.uk` -> `example.co.uk`.

    Not a public-suffix-list implementation, and does not need to be: it is only
    used to decide whether two hosts belong to the same site, and it errs
    towards a LONGER (more specific) base, which makes the scope check stricter
    rather than looser.
    """
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    two_level = {"co.uk", "com.au", "co.jp", "com.br", "co.nz", "com.tr",
                 "co.za", "co.in", "com.mx", "co.kr", "com.sg", "com.hk"}
    if ".".join(parts[-2:]) in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def in_scope(url: str, base_domain: str) -> bool:
    """THE safety rail. True only for the target's own domain or a subdomain.

    robots.txt is deliberately ignored by this crawler, so this is what stops it
    reaching a third party. Everything that follows a link or reads a sitemap
    passes through here first.

    Rejects non-http(s) schemes too, so `javascript:`, `mailto:` and `data:`
    URLs can never be fetched.
    """
    if not url or not base_domain:
        return False
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").lower()
    if not host:
        return False
    base = base_domain.lower()
    return host == base or host.endswith("." + base)


def normalise_url(url: str) -> str:
    """Drop the fragment and any trailing '?', so one page has one identity."""
    try:
        p = urlparse(url)
    except Exception:
        return url
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))


def score_url(url: str) -> int:
    """How organizationally interesting a URL looks, from its path alone.

    Scored per PATH SEGMENT, not as a raw substring of the whole path. A live
    run against a real site showed why: a bare `"about" in path` scores
    `/weekly-notes-about-the-news-2024-02-06/` -- a blog post -- exactly as
    highly as `/about/our-staff/`, and the page budget then goes to the archive
    instead of the org pages.
    """
    try:
        path = (urlparse(url).path or "/").lower()
    except Exception:
        return 0
    if _PATH_SKIP.search(path) or _EXT_SKIP.search(path):
        return -1

    segments = [s for s in path.split("/") if s]
    score = 0
    for token, weight in _PATH_SCORES:
        for seg in segments:
            if seg == token:
                score += weight                     # /about/
                break
            # A short, focused slug built around the token still counts:
            # "about-us", "our-team", "leadership-team". A long one does not.
            words = [w for w in re.split(r"[-_]", seg) if w]
            if len(words) <= 3 and any(w.startswith(token) for w in words):
                score += weight
                break
    # Dated or long slugs are article-shaped, not org-shaped.
    if re.search(r"\d{1,2}-\d{1,2}-\d{2,4}|/(?:19|20)\d\d/", path):
        score -= 6
    longest = max((len(re.split(r"[-_]", s)) for s in segments), default=0)
    if longest >= 5:
        score -= 4
    # A shallow page is usually the canonical one ("/about/" over
    # "/about/2019/some-post/"), so depth is a mild penalty, not a filter.
    score -= max(0, len(segments) - 2)
    if not segments:
        score += 4          # the homepage always earns its slot
    return score


# ── HTML extraction ──────────────────────────────────────────────────────────

class _PageParser(HTMLParser):
    """Stdlib main-text + link + JSON-LD extractor.

    Keeps headings so a chunk can carry the heading it sits under, which is what
    makes a retrieved passage citable ("Leadership > Chief Technology Officer")
    rather than a floating paragraph.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.links: List[str] = []
        self.title = ""
        self.jsonld: List[Any] = []
        self._drop_depth = 0
        self._in_title = False
        self._in_ld = False
        self._ld_buf: List[str] = []
        self._heading: Optional[str] = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        a = dict(attrs)
        if tag == "script" and (a.get("type") or "").lower() == "application/ld+json":
            self._in_ld = True
            self._ld_buf = []
            return
        if tag in _DROP_TAGS:
            self._drop_depth += 1
            return
        if tag == "title":
            self._in_title = True
        if tag == "a":
            href = a.get("href")
            if href:
                self.links.append(href)
        if tag in _HEADING_TAGS:
            self._heading = tag
            self.parts.append("\n\n")
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "script" and self._in_ld:
            self._in_ld = False
            raw = "".join(self._ld_buf).strip()
            if raw:
                try:
                    self.jsonld.append(json.loads(raw))
                except Exception:
                    pass          # a malformed block is not worth failing over
            return
        if tag in _DROP_TAGS and self._drop_depth:
            self._drop_depth -= 1
        if tag == "title":
            self._in_title = False
        if tag in _HEADING_TAGS:
            self._heading = None
            self.parts.append("\n")

    def handle_data(self, data):
        if self._in_ld:
            self._ld_buf.append(data)
            return
        if self._drop_depth:
            return
        if self._in_title:
            self.title += data
            return
        text = data.strip()
        if text:
            # Mark headings inline so the chunker can recover the heading path
            # without a second parse.
            self.parts.append(("\x00H\x00" + text + "\x00/H\x00")
                              if self._heading else text)
            self.parts.append(" ")

    def text(self) -> str:
        raw = "".join(self.parts)
        raw = re.sub(r"[ \t\u00a0]+", " ", raw)
        raw = re.sub(r"\n\s*\n\s*\n+", "\n\n", raw)
        return raw.strip()


def extract_page(html_text: str) -> Dict[str, Any]:
    """{title, text, links, jsonld} from a page's HTML."""
    p = _PageParser()
    try:
        p.feed(html_text or "")
        p.close()
    except Exception:
        # HTMLParser can raise on genuinely broken markup; keep whatever it got
        # rather than losing the page.
        pass
    return {
        "title": re.sub(r"\s+", " ", p.title).strip(),
        "text": p.text(),
        "links": p.links,
        "jsonld": p.jsonld,
    }


def _strip_heading_marks(s: str) -> str:
    return s.replace("\x00H\x00", "").replace("\x00/H\x00", "")


# ── chunking ─────────────────────────────────────────────────────────────────

def chunk_text(text: str, *, size: int = _DEFAULT_CHUNK_CHARS,
               overlap: int = _DEFAULT_CHUNK_OVERLAP) -> List[Dict[str, str]]:
    """Split page text into overlapping chunks that carry their heading.

    The repo had no chunker: every index_* method stores one document per record
    and truncates at EMBEDDING_MAX_CHARS. A 40 KB About page stored whole is one
    vector averaging forty unrelated sentences, which retrieves nothing well.

    ~1500 characters sits far under the embedder's 8192-token window, so a chunk
    is never truncated, and is small enough that a hit points at a specific
    passage. Splits prefer paragraph then sentence boundaries and never cut
    mid-word. The overlap keeps a fact that straddles a boundary retrievable
    from either side.
    """
    size = max(200, size)
    overlap = max(0, min(overlap, size // 2))
    if not text:
        return []

    heading = ""
    out: List[Dict[str, str]] = []
    # Paragraphs first, so a boundary lands where the author put one.
    paras = [p for p in re.split(r"\n\s*\n", text) if p.strip()]
    buf = ""
    # Below this, a "chunk" is a heading or a stray caption on its own. Embedding
    # it produces a vector that matches everything weakly and cites nothing
    # useful, so it is carried forward into the next chunk instead.
    min_chars = max(80, size // 10)

    def _overlap_tail(b: str) -> str:
        """Last `overlap` characters, snapped forward to a word boundary.

        A raw slice cuts mid-word -- "...filler sentence" becomes "ence" -- and
        that fragment is then embedded as if it were a word.
        """
        if not overlap:
            return ""
        tail = _strip_heading_marks(b)[-overlap:]
        sp = tail.find(" ")
        return tail[sp + 1:].lstrip() if sp != -1 else tail.lstrip()

    # A too-small leading fragment (typically the page's own <h1>) has no
    # previous chunk to merge back into, so it waits here for the next one.
    carry: List[str] = []

    def flush(b: str, h: str) -> None:
        b = _strip_heading_marks(b).strip()
        if not b:
            return
        if carry:
            b = (carry.pop() + "\n\n" + b).strip()
        if len(b) < min_chars:
            # Too small to stand alone: embedding a bare heading yields a vector
            # that matches everything weakly and cites nothing useful.
            if out:
                out[-1]["text"] = (out[-1]["text"] + "\n\n" + b).strip()
            else:
                carry.append(b)
            return
        out.append({"text": b, "heading": h})

    for para in paras:
        m = re.search(r"\x00H\x00(.*?)\x00/H\x00", para)
        if m:
            heading = _strip_heading_marks(m.group(1)).strip()[:160]
        clean = para.strip()
        if len(buf) + len(clean) + 2 <= size:
            buf = (buf + "\n\n" + clean) if buf else clean
            continue
        if buf:
            flush(buf, heading)
            tail = _overlap_tail(buf)
            buf = (tail + "\n\n" + clean) if tail else clean
        else:
            buf = clean
        # A single paragraph longer than the window: split on sentences.
        while len(buf) > size:
            window = buf[:size]
            cut = max(window.rfind(". "), window.rfind("! "), window.rfind("? "),
                      window.rfind("\n"))
            if cut < size // 3:
                cut = window.rfind(" ")          # never mid-word
            if cut <= 0:
                cut = size
            head, rest = buf[:cut + 1], buf[cut + 1:]
            flush(head, heading)
            tail = _overlap_tail(head)
            buf = ((tail + " " + rest) if tail else rest).lstrip()
    flush(buf, heading)
    if carry:
        leftover = carry.pop()
        if out:
            out[-1]["text"] = (out[-1]["text"] + "\n\n" + leftover).strip()
        elif leftover:
            out.append({"text": leftover, "heading": heading})
    return out


# ── how an empty crawl is empty ───────────────────────────────────

# Four ways `pages_crawled: 0` happens, and only one of them is a finding about
# the target. They were indistinguishable on the card until 2026-09-21: a
# Russian defence-sector target that silently drops Tor exit traffic produced
# 0 pages, every fetch a read timeout, and the Organization card reported that
# as "no match" -- the status that means "we reached the site and it had
# nothing". A total transport failure read as a completed crawl.
#
# Same shape as job_titles.title_match_empty_kind(): a kind constant plus a
# message, rather than a boolean, because the operator's next action differs
# per kind (change the egress / accept the WAF / believe the zero).

SITE_DISABLED = "site_disabled"          # crawling is switched off here
SITE_UNREACHABLE = "site_unreachable"    # no HTTP response ever arrived
SITE_BLOCKED = "site_blocked"            # the site answered, refusing us
SITE_NO_PAGES = "site_no_pages"          # we got in; there was nothing to read
# The two Tavily-backend kinds. Both rank ABOVE blocked/unreachable in
# site_empty_kind() because in neither case did anything reach the target: they
# are configuration states, and reporting them as a property of the client's
# site is the same class of error as calling a WAF an empty estate.
SITE_BACKEND_UNCONFIGURED = "site_backend_unconfigured"   # Tavily picked, no key
SITE_PROVIDER_FAILED = "site_provider_failed"             # api.tavily.com refused us

SITE_EMPTY_MESSAGES: Dict[str, str] = {
    SITE_DISABLED: (
        "Website crawling is switched off for this deployment "
        "(SITE_ENABLED=0), so {domain} was never fetched. A configuration "
        "state, not a finding about the target."),
    SITE_UNREACHABLE: (
        "Nothing was fetched: every request to {domain} over {egress} failed "
        "at the transport layer -- a connect or read timeout, with no HTTP "
        "response at all. The site was NOT REACHED, which is not the same as "
        "the site having nothing on it. A target that silently drops this "
        "egress looks identical to an empty site until the egress is changed."),
    SITE_BLOCKED: (
        "Every request to {domain} over {egress} was refused by the site "
        "itself (HTTP 403/429/503), robots.txt included. The crawler was "
        "BLOCKED, not shown an empty site -- many corporate WAFs reject "
        "datacenter and Tor exit addresses outright."),
    SITE_NO_PAGES: (
        "{domain} answered over {egress}, but no in-scope page yielded "
        "readable text -- no sitemap, no in-scope links, or nothing but "
        "assets. This is the one empty that IS a finding about the site."),
    SITE_BACKEND_UNCONFIGURED: (
        "The website crawl is configured to use Tavily (SITE_TAVILY is set) but "
        "TAVILY_API_KEY is not, so {domain} was never fetched. It was NOT "
        "crawled with the built-in crawler instead: choosing Tavily is a choice "
        "not to contact the target from this deployment's egress, and silently "
        "reversing that would do the one thing the setting excluded. A "
        "configuration state, not a finding about the target."),
    SITE_PROVIDER_FAILED: (
        "Nothing was fetched: api.tavily.com refused or could not be reached. "
        "THE TARGET WAS NEVER CONTACTED, by this deployment or by Tavily, so "
        "this says nothing whatsoever about {domain} -- it is not a WAF, not a "
        "dropped egress and not an empty site. Check the API key, the credit "
        "balance, and this host's route to api.tavily.com."),
}


def egress_label(proxy_url: str, *, backend: int = 0) -> str:
    """Name the egress for an operator without printing its credentials.

    The campaign proxy URL can carry user:pass (Infrastructure -> proxy), and
    this string lands on the Organization card and in the workflow response.

    `backend` is keyword-only with a default so every existing call site is
    unchanged. On a Tavily backend naming the campaign proxy would be actively
    misleading -- the proxy carried the API call, while the requests that
    reached the CLIENT came from Tavily's addresses. That branch prints no URL
    at all, so it cannot leak a credential either.
    """
    if backend:
        tail = (", which carried only the call to api.tavily.com"
                if (proxy_url or "").strip() else "")
        return ("Tavily's own infrastructure (the requests to the site came from "
                "Tavily's IP addresses, not from this deployment%s)" % tail)
    raw = (proxy_url or "").strip()
    if not raw:
        return "direct egress (no campaign proxy is configured)"
    try:
        u = urlparse(raw)
        host = u.hostname or ""
        if host:
            port = ":%d" % u.port if u.port else ""
            return "the campaign proxy (%s://%s%s)" % (u.scheme or "proxy", host, port)
    except Exception:
        pass
    return "the campaign proxy"


def site_empty_kind(*, pages: int, blocked: bool, unreachable: bool,
                    enabled: bool = True, backend_ok: bool = True,
                    provider_failed: bool = False) -> str:
    """Classify an empty crawl. '' when the crawl fetched something.

    `blocked` outranks `unreachable`: an HTTP status is a stronger signal than
    a timeout, and a run can hold both (a WAF that 403s the homepage and drops
    everything else).

    `backend_ok` and `provider_failed` outrank BOTH, and are keyword-only with
    safe defaults so every existing caller is unchanged. They describe failures
    that happened before anything reached the target at all, so classifying
    them as blocked or unreachable would report a property of the client's site
    on the strength of our own misconfiguration.
    """
    if not enabled:
        return SITE_DISABLED
    if pages:
        return ""
    if not backend_ok:
        return SITE_BACKEND_UNCONFIGURED
    if provider_failed:
        return SITE_PROVIDER_FAILED
    if blocked:
        return SITE_BLOCKED
    if unreachable:
        return SITE_UNREACHABLE
    return SITE_NO_PAGES


def site_empty_message(kind: str, *, domain: str = "", proxy_url: str = "",
                       backend: int = 0) -> str:
    """The operator-facing sentence for a kind, with the egress named."""
    tmpl = SITE_EMPTY_MESSAGES.get(kind, "")
    if not tmpl:
        return ""
    return tmpl.format(domain=domain or "the target site",
                       egress=egress_label(proxy_url, backend=backend))


# ── the crawler ──────────────────────────────────────────────────────────────

class SiteCrawler:
    def __init__(
        self,
        domain: str,
        *,
        proxy_url: str = "",
        user_agent: str = "",
        timeout: Optional[int] = None,
        max_pages: Optional[int] = None,
        max_depth: Optional[int] = None,
        delay_ms: Optional[int] = None,
        max_bytes: Optional[int] = None,
        max_seconds: Optional[int] = None,
    ):
        self.base_domain = registrable_domain(domain)
        self.proxy_url = (proxy_url or "").strip()
        self.proxies = ({"http": self.proxy_url, "https": self.proxy_url}
                        if self.proxy_url else None)
        self.user_agent = (user_agent or "").strip() or _DEFAULT_UA

        env = os.environ.get
        self.timeout = timeout or _as_int(env("SITE_TIMEOUT"), _DEFAULT_TIMEOUT)
        # One bounded request before the crawl, so a target that drops this
        # egress costs a few seconds instead of the whole SITE_MAX_SECONDS
        # budget in timeouts. 0 skips it -- see reachable().
        self.preflight_timeout = _as_int(env("SITE_PREFLIGHT_TIMEOUT"),
                                         min(self.timeout, _DEFAULT_PREFLIGHT_CAP))
        self.max_pages = max_pages or _as_int(env("SITE_MAX_PAGES"), _DEFAULT_MAX_PAGES)
        self.max_depth = max_depth if max_depth is not None else _as_int(env("SITE_MAX_DEPTH"), _DEFAULT_MAX_DEPTH)
        self.delay_ms = delay_ms if delay_ms is not None else _as_int(env("SITE_DELAY_MS"), _DEFAULT_DELAY_MS)
        self.max_bytes = max_bytes or _as_int(env("SITE_MAX_BYTES_PER_PAGE"), _DEFAULT_MAX_BYTES)
        self.max_seconds = max_seconds or _as_int(env("SITE_MAX_SECONDS"), _DEFAULT_MAX_SECONDS)

        self.errors: List[str] = []
        # Distinct from "found nothing": if every attempt was refused by a WAF
        # we never got to look. Some large sites answer 403 to every request from a
        # datacenter IP, including robots.txt, and reporting that as an empty
        # site would be evidence of absence drawn from absence of access.
        self.blocked = 0
        # And the case one step earlier: no HTTP response at all. A site that
        # answers 403 has at least told us it exists; a site that swallows the
        # SYN or never replies has told us nothing, and calling that an empty
        # site is the same error one layer down.
        self.unreachable = 0
        self.fetched: List[str] = []
        self.refused: List[str] = []       # off-domain URLs the scope lock blocked
        self._requests = 0
        self._started = time.time()
        self._last_fetch = 0.0

    # ── budget + transport ────────────────────────────────────────────────────

    def budget_exhausted(self) -> bool:
        return (len(self.fetched) >= self.max_pages
                or (time.time() - self._started) >= self.max_seconds)

    def _note(self, msg: str) -> None:
        if msg not in self.errors:
            self.errors.append(msg)

    def _refuse(self, url: str) -> None:
        """Record an out-of-scope URL that was offered to the crawler.

        Called from every place a candidate is filtered, not only from _get():
        sitemap entries and page links are screened before any fetch, so
        without this the refusal count would read 0 on a site that links to a
        dozen third parties, and an operator could not tell the scope lock had
        done anything at all.
        """
        if url and url not in self.refused and len(self.refused) < 200:
            self.refused.append(url)

    def _get(self, url: str) -> Optional[str]:
        """Fetch one in-scope URL, rate-limited and bounded. None on failure."""
        if not in_scope(url, self.base_domain):
            # Never silently skipped: an operator reviewing a run needs to see
            # that the crawler was offered an off-domain URL and refused it.
            self._refuse(url)
            return None
        if self.budget_exhausted():
            raise SiteError("site crawl budget exhausted (%d pages / %ds)"
                            % (self.max_pages, self.max_seconds))

        gap = (time.time() - self._last_fetch) * 1000.0
        if self.delay_ms and gap < self.delay_ms:
            time.sleep((self.delay_ms - gap) / 1000.0)

        self._requests += 1
        try:
            r = requests.get(url, headers={
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
                "Accept-Language": "en-US,en;q=0.9",
            }, timeout=self.timeout, proxies=self.proxies,
                allow_redirects=True, stream=True)
        except requests.exceptions.ProxyError as e:
            raise SiteError("site proxy unreachable; refusing to fall back to "
                            "direct egress: %s" % e)
        except Exception as e:
            # Timeout, DNS failure, reset connection: we never reached the
            # site, so this request is evidence of nothing about its content.
            self.unreachable += 1
            self._note("fetch failed (%s): %s" % (url[:120], e))
            return None
        finally:
            self._last_fetch = time.time()

        try:
            # A redirect can leave the scope. Check where we actually landed.
            final = str(getattr(r, "url", url) or url)
            if not in_scope(final, self.base_domain):
                # A redirect can walk out of scope after the check passed.
                self._refuse(final)
                return None
            if not r.ok:
                if r.status_code in (401, 403, 406, 429, 503):
                    self.blocked += 1
                self._note("HTTP %s for %s" % (r.status_code, url[:120]))
                return None
            ctype = (r.headers.get("Content-Type") or "").lower() if hasattr(r, "headers") else ""
            if ctype and not any(t in ctype for t in ("html", "xml", "text/plain")):
                return None
            body = b""
            for chunk in r.iter_content(64 * 1024):
                body += chunk
                if len(body) >= self.max_bytes:
                    body = body[: self.max_bytes]
                    break
            return body.decode("utf-8", "replace")
        finally:
            try:
                r.close()
            except Exception:
                pass

    def reachable(self) -> Tuple[bool, str]:
        """Can the configured egress get an HTTP response out of the site?

        Returns (ok, reason). `ok` is True for ANY response, a 403 included:
        being refused by a WAF is `blocked`, a state the crawl itself records
        properly. Only a transport failure returns False.

        Deliberately not routed through _get(): the preflight must not spend a
        page of the budget, land in self.fetched, or count towards
        self.unreachable. It only reports.
        """
        if not self.base_domain:
            return True, ""
        if self.preflight_timeout <= 0:
            return True, "preflight skipped (SITE_PREFLIGHT_TIMEOUT=0)"
        url = "https://%s/" % self.base_domain
        try:
            r = requests.get(url, headers={"User-Agent": self.user_agent},
                             timeout=self.preflight_timeout, proxies=self.proxies,
                             allow_redirects=True, stream=True)
        except requests.exceptions.ProxyError as e:
            # Same words as the SiteError _get() raises: a dead proxy is a
            # fail-closed condition here too, never a reason to go direct.
            return False, ("proxy unreachable; refusing to fall back to "
                           "direct egress: %r" % (e,))
        except Exception as e:
            return False, ("no response within %ds: %r"
                           % (self.preflight_timeout, e))
        try:
            status = r.status_code
        finally:
            try:
                r.close()
            except Exception:
                pass
        return True, "HTTP %s" % (status,)

    # ── discovery ─────────────────────────────────────────────────────────────

    def sitemap_urls(self, roots: Optional[Iterable[str]] = None) -> List[str]:
        """Every <loc> reachable from robots.txt / sitemap.xml, scope-filtered.

        Follows one level of sitemap index nesting, which is how large sites
        split theirs.
        """
        found: List[str] = []
        seen_maps: Set[str] = set()
        queue = list(roots or [])
        if not queue:
            for scheme in ("https", "http"):
                queue.append("%s://%s/robots.txt" % (scheme, self.base_domain))
                queue.append("%s://www.%s/robots.txt" % (scheme, self.base_domain))
                break
            queue.append("https://%s/sitemap.xml" % self.base_domain)
            queue.append("https://www.%s/sitemap.xml" % self.base_domain)

        while queue and len(seen_maps) < 12:
            u = queue.pop(0)
            if u in seen_maps:
                continue
            seen_maps.add(u)
            try:
                body = self._get(u)
            except SiteError:
                break
            if not body:
                continue

            if u.endswith("robots.txt"):
                # The ONLY thing taken from robots.txt. Its Disallow rules are
                # deliberately not applied -- see the module docstring.
                for m in re.finditer(r"(?im)^\s*sitemap:\s*(\S+)", body):
                    sm = m.group(1).strip()
                    if in_scope(sm, self.base_domain):
                        queue.append(sm)
                    else:
                        self._refuse(sm)
                continue

            try:
                root = ET.fromstring(body.encode("utf-8", "replace"))
            except Exception:
                continue
            tag = root.tag.rsplit("}", 1)[-1].lower()
            locs = [e.text.strip() for e in root.iter()
                    if e.tag.rsplit("}", 1)[-1].lower() == "loc" and (e.text or "").strip()]
            if tag == "sitemapindex":
                for loc in locs[:12]:
                    if in_scope(loc, self.base_domain):
                        queue.append(loc)
                    else:
                        self._refuse(loc)
            else:
                for loc in locs:
                    if in_scope(loc, self.base_domain):
                        found.append(normalise_url(loc))
                    else:
                        self._refuse(loc)
        return found

    def discover(self) -> List[str]:
        """Ranked, in-scope, budget-sized page list."""
        urls = self.sitemap_urls()
        if urls:
            ranked = sorted({u for u in urls}, key=lambda u: (-score_url(u), len(u)))
            picked = [u for u in ranked if score_url(u) >= 0][: self.max_pages]
            if picked:
                return picked
            self._note("sitemap had no organizationally relevant pages; "
                       "falling back to link-following")
        else:
            self._note("no sitemap found; falling back to link-following")
        return []

    def crawl(self) -> List[Dict[str, Any]]:
        """Fetch and extract the ranked pages. Never raises."""
        pages: List[Dict[str, Any]] = []
        if not self.base_domain:
            self._note("no target domain resolved; nothing crawled")
            return pages

        try:
            targets = self.discover()
        except Exception as e:                       # noqa: BLE001
            self._note("discovery failed: %r" % (e,))
            targets = []

        seen: Set[str] = set()
        # BFS frontier. Seeded from the sitemap when there is one, from the
        # homepage when there is not.
        frontier: List[Tuple[str, int]] = [(u, 0) for u in targets]
        if not frontier:
            for scheme in ("https", "http"):
                frontier.append(("%s://www.%s/" % (scheme, self.base_domain), 0))
                frontier.append(("%s://%s/" % (scheme, self.base_domain), 0))
                break

        while frontier and not self.budget_exhausted():
            url, depth = frontier.pop(0)
            url = normalise_url(url)
            if url in seen:
                continue
            seen.add(url)
            try:
                body = self._get(url)
            except SiteError as e:
                self._note(str(e))
                break
            if not body:
                continue
            self.fetched.append(url)
            page = extract_page(body)
            page["url"] = url
            pages.append(page)

            if depth < self.max_depth and len(seen) < self.max_pages * 4:
                cand: List[Tuple[int, str]] = []
                for href in page.get("links") or []:
                    try:
                        nxt = normalise_url(urljoin(url, href))
                    except Exception:
                        continue
                    if not in_scope(nxt, self.base_domain):
                        self._refuse(nxt)
                        continue
                    if nxt in seen:
                        continue
                    sc = score_url(nxt)
                    if sc >= 0:
                        cand.append((sc, nxt))
                for sc, nxt in sorted(cand, key=lambda t: -t[0])[:20]:
                    frontier.append((nxt, depth + 1))
                # Keep the most promising work at the front of the queue.
                frontier.sort(key=lambda t: (-score_url(t[0]), t[1]))
        return pages


# ── the Tavily backend ───────────────────────────────────────────────────────
#
# A SEPARATE class, deliberately, rather than a branch inside SiteCrawler.
# There is no rate limit here, no per-page byte bound on the wire, no redirect
# re-check and no egress preflight, and making SiteCrawler pretend otherwise
# would have its attributes lie about what happened. SiteCrawler._get() -- the
# most safety-critical function in this file -- is left byte-identical.

# Hand-written from _PATH_SKIP, NOT machine-translated from the compiled
# pattern. A mistranslated regex evaluated by a foreign engine that happens to
# match everything produces a silently empty crawl, so this list is treated as
# a COST optimisation and never as a control. _EXT_SKIP is deliberately not
# translated at all: score_url() already returns -1 for those extensions here,
# locally and for free.
_TAVILY_EXCLUDE_PATHS = (
    r"/wp-admin(/|$)", r"/wp-includes(/|$)", r"/wp-json(/|$)",
    r"/feed(/|$)", r"/rss(/|$)", r"/atom(/|$)", r"/tag(/|$)",
    r"/category(/|$)", r"/author(/|$)", r"/search(/|$)", r"/cart(/|$)",
    r"/checkout(/|$)", r"/account(/|$)", r"/login(/|$)", r"/signin(/|$)",
    r"/register(/|$)", r"/privacy(/|$)", r"/terms(/|$)", r"/cookie(/|$)",
)

# Tavily reports a per-URL failure as a prose string, so classification is
# pattern matching on someone else's wording. An UNRECOGNISED error increments
# NEITHER counter: guessing would tell the operator the client runs a WAF on
# the strength of a string we did not understand.
_BLOCKED_RE = re.compile(
    r"\b(?:40[13]|406|429|503)\b|forbidden|access denied|blocked|captcha|"
    r"cloudflare|too many requests", re.I)
_UNREACH_RE = re.compile(
    r"timed? ?out|timeout|connection (?:refused|reset|error)|"
    r"name (?:or service )?not known|dns|ssl|certificate|unreachable", re.I)

SITE_BACKEND_BUILTIN = 0
SITE_BACKEND_MAP_EXTRACT = 1
SITE_BACKEND_CRAWL = 2

_BACKEND_LABELS = {
    SITE_BACKEND_BUILTIN: "builtin",
    SITE_BACKEND_MAP_EXTRACT: "tavily-map+extract",
    SITE_BACKEND_CRAWL: "tavily-crawl",
}


def site_backend() -> int:
    """0 builtin / 1 Tavily map+extract / 2 Tavily crawl. Never raises."""
    v = _as_int(os.environ.get("SITE_TAVILY"), SITE_BACKEND_BUILTIN)
    return v if v in _BACKEND_LABELS else SITE_BACKEND_BUILTIN


def backend_label(backend: int) -> str:
    return _BACKEND_LABELS.get(backend, "builtin")


def tavily_domain_regex(base_domain: str) -> str:
    """The regex form of in_scope(): the base domain, or any subdomain of it.

    ANCHORED AT BOTH ENDS AND ESCAPED, and both are load-bearing. Unanchored,
    `sample\\.test` also matches `sample.test.evil.example` -- the
    suffix-confusion case the scope-lock test exists to catch. Unescaped,
    `example.co.uk` matches `exampleXcoYuk`.

    This is sent to Tavily as a hint, NOT relied on as the rail. Tavily
    documents allow_external against "the final results list", which is a
    results filter rather than a fetch constraint, and we do not control their
    regex engine's anchoring semantics. Everything that comes back is still
    re-checked locally with in_scope().
    """
    return r"^([A-Za-z0-9-]+\.)*%s$" % re.escape(base_domain or "")


def markdown_to_page(url: str, raw: str, *, max_bytes: int = 0) -> Dict[str, Any]:
    """Tavily markdown -> the exact dict extract_page() produces, plus `url`.

    ATX headings are rewritten to the \x00H\x00...\x00/H\x00 marks that
    chunk_text() looks for, so a retrieved passage still carries its heading
    trail ("Leadership > Chief Technology Officer") and a citation reads the
    same whichever backend fetched the page.

    `links` and `jsonld` come back EMPTY and that is not an oversight: Tavily
    returns rendered text, so there is no application/ld+json to parse. The
    caller reports that gap rather than absorbing it -- see crawl_and_index().
    """
    text = str(raw or "")
    if max_bytes and len(text) > max_bytes:
        # The knob keeps its real purpose even though it no longer bounds the
        # wire: a 40 MB page must not reach the chunker or the index.
        text = text[:max_bytes]
    title = ""
    lines = []
    for line in text.split("\n"):
        m = re.match(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if m:
            heading = re.sub(r"\s+", " ", m.group(2)).strip()
            if heading:
                if not title and len(m.group(1)) == 1:
                    title = heading
                lines.append("\x00H\x00" + heading + "\x00/H\x00")
                continue
        lines.append(line)
    body = "\n".join(lines)
    # Same normalisation _PageParser.text() applies: collapse runs of blank
    # lines so chunk_text's paragraph split behaves identically.
    body = re.sub(r"\n{3,}", "\n\n", body).strip()
    if not title:
        seg = [x for x in urlparse(url or "").path.split("/") if x]
        title = re.sub(r"[-_]+", " ", seg[-1]).strip().title() if seg else ""
    return {"title": title, "text": body, "links": [], "jsonld": [], "url": url}


class TavilySiteCrawler:
    """Duck-compatible with SiteCrawler over the surface crawl_and_index uses.

    Two modes, and the difference is a real cost/quality trade:

      1  /map then /extract -- Tavily discovers the URLs, WE rank them with
         score_url() and spend extraction only on the top max_pages. Costs
         roughly 3x mode 2 (ceil(n/10) + ceil(n/5) vs ceil(n/10)), and buys
         keeping this module's own page ranking in the loop.
      2  /crawl -- one call, Tavily picks the pages. Cheapest, and the ranking
         that makes this module better than path-guessing is not applied.
    """

    def __init__(self, domain: str, *, proxy_url: str = "", user_agent: str = "",
                 backend: int = SITE_BACKEND_MAP_EXTRACT, client: Any = None,
                 timeout: Optional[int] = None, max_pages: Optional[int] = None,
                 max_depth: Optional[int] = None, max_seconds: Optional[int] = None,
                 max_bytes: Optional[int] = None, **_inert: Any):
        # **_inert is load-bearing. crawl_and_index(**crawl_kwargs) forwards
        # whatever the caller passed, and the existing tests pass delay_ms= and
        # other SiteCrawler-only knobs. Absorbing them here keeps every one of
        # those call sites working; the ones that no longer mean anything are
        # reported below rather than silently ignored.
        self.base_domain = registrable_domain(domain)
        self.domain = domain
        self.backend = backend
        self.proxy_url = (proxy_url or "").strip()
        self.user_agent = (user_agent or "").strip() or _DEFAULT_UA

        env = os.environ.get
        self.timeout = timeout or _as_int(env("SITE_TIMEOUT"), _DEFAULT_TIMEOUT)
        self.max_pages = max_pages or _as_int(env("SITE_MAX_PAGES"), _DEFAULT_MAX_PAGES)
        self.max_depth = (max_depth if max_depth is not None
                          else _as_int(env("SITE_MAX_DEPTH"), _DEFAULT_MAX_DEPTH))
        self.max_seconds = max_seconds or _as_int(env("SITE_MAX_SECONDS"),
                                                  _DEFAULT_MAX_SECONDS)
        self.max_bytes = max_bytes or _as_int(env("SITE_MAX_BYTES_PER_PAGE"),
                                              _DEFAULT_MAX_BYTES)
        self.max_breadth = _as_int(env("SITE_TAVILY_BREADTH"), 20)
        self.extract_depth = ("advanced"
                              if _as_int(env("SITE_TAVILY_ADVANCED"), 0) else "basic")

        self.errors: List[str] = []
        self.blocked = 0
        self.unreachable = 0
        self.provider_failed = False
        self.fetched: List[str] = []
        self.refused: List[str] = []       # off-domain URLs the scope lock blocked
        self.failed: List[Dict[str, str]] = []
        self.client = client
        self._started = time.time()

        for name, default in (("SITE_DELAY_MS", _DEFAULT_DELAY_MS),
                              ("SITE_PREFLIGHT_TIMEOUT", None)):
            raw = env(name)
            if raw is not None and str(raw).strip() and _as_int(raw, -1) != default:
                self._note(
                    "%s has no effect on the Tavily backend: Tavily paces its own "
                    "fetching, and no request leaves this host for the target."
                    % name)

    # ── the surface crawl_and_index uses ─────────────────────────────────────

    def _note(self, msg: str) -> None:
        if msg not in self.errors:
            self.errors.append(msg)

    def _refuse(self, url: str) -> None:
        if url not in self.refused:
            self.refused.append(url)

    def budget_exhausted(self) -> bool:
        return (len(self.fetched) >= self.max_pages
                or (time.time() - self._started) >= self.max_seconds)

    def reachable(self) -> Tuple[bool, str]:
        """No request, always True.

        The preflight is SKIPPED rather than emulated. Making it would contact
        the client from this host's IP, which is the exact thing choosing the
        Tavily backend was meant to avoid -- and our reaching the site would say
        nothing about whether Tavily's egress can.
        """
        return True, "preflight not applicable on the tavily backend"

    def _tavily_timeout(self) -> int:
        """Tavily's own per-call ceiling, clamped to what it accepts.

        SITE_MAX_SECONDS goes up to 900 and Tavily's crawl timeout stops at
        150, so the clamp is reported rather than applied silently.
        """
        want = int(self.max_seconds)
        if want > 150:
            self._note("SITE_MAX_SECONDS=%d exceeds Tavily's 150s per-call "
                       "ceiling; the crawl was capped at 150s." % want)
        return max(10, min(want, 150))

    def _classify_failures(self, failed: List[Dict[str, str]]) -> None:
        """failed_results -> blocked / unreachable / neither.

        HTTP 200 with entries here is a PARTIAL failure: per-URL success has to
        be read out of the body, because the status code does not carry it.
        """
        for row in (failed or [])[:200]:
            url = str((row or {}).get("url") or "")
            err = str((row or {}).get("error") or "")
            self.failed.append({"url": url[:300], "error": err[:200]})
            if _BLOCKED_RE.search(err):
                self.blocked += 1
            elif _UNREACH_RE.search(err):
                self.unreachable += 1
        if self.failed:
            shown = "; ".join("%s: %s" % (f["url"][:90], f["error"][:90])
                              for f in self.failed[:5])
            self._note("tavily could not read %d URL(s) -- %s%s"
                       % (len(self.failed), shown,
                          " (+%d more)" % (len(self.failed) - 5)
                          if len(self.failed) > 5 else ""))

    def _accept(self, url: str, raw: str) -> Optional[Dict[str, Any]]:
        """Local scope re-check, then convert. None when refused or empty.

        THE RAIL IS ASSERTED HERE, not in the request parameters. See
        tavily_domain_regex() for why allow_external is not enough, and note
        that a redirect can land somewhere else entirely -- SiteCrawler._get()
        re-checks r.url after redirects for exactly that reason, and Tavily
        hands us one URL per result without saying whether it is the one we
        asked for or the one it landed on.
        """
        norm = normalise_url(url)
        if not norm or not in_scope(norm, self.base_domain):
            self._refuse(url)
            return None
        page = markdown_to_page(norm, raw, max_bytes=self.max_bytes)
        if not page["text"].strip():
            return None
        self.fetched.append(norm)
        return page

    def crawl(self) -> List[Dict[str, Any]]:
        """Fetch pages through Tavily. Raises SiteError only on provider failure."""
        import tavily_client

        if self.client is None:
            self.client = tavily_client.TavilyClient(
                proxy_url=self.proxy_url, timeout=self.timeout)
        root = "https://%s/" % (self.base_domain or self.domain)
        scope = [tavily_domain_regex(self.base_domain)]
        pages: List[Dict[str, Any]] = []
        try:
            if self.backend == SITE_BACKEND_CRAWL:
                res = self.client.crawl(
                    root, max_depth=self.max_depth, max_breadth=self.max_breadth,
                    limit=self.max_pages, select_domains=scope,
                    exclude_paths=list(_TAVILY_EXCLUDE_PATHS),
                    extract_depth=self.extract_depth, timeout=self._tavily_timeout())
                results = res.get("results") or []
                self._classify_failures(res.get("failed_results") or [])
            else:
                found = self.client.map_site(
                    root, max_depth=self.max_depth, max_breadth=self.max_breadth,
                    limit=max(self.max_pages * 3, self.max_pages),
                    select_domains=scope,
                    exclude_paths=list(_TAVILY_EXCLUDE_PATHS),
                    timeout=self._tavily_timeout())
                # OUR ranking, not Tavily's. score_url() is the reason this
                # module beats path-guessing, and handing page selection to the
                # provider would throw it away.
                ranked = []
                for u in found:
                    norm = normalise_url(u)
                    if not norm or not in_scope(norm, self.base_domain):
                        self._refuse(u)
                        continue
                    sc = score_url(norm)
                    if sc >= 0:
                        ranked.append((sc, norm))
                ranked.sort(key=lambda t: -t[0])
                picked = [u for _, u in ranked[: self.max_pages]]
                if not picked:
                    return []
                res = self.client.extract(picked, extract_depth=self.extract_depth)
                results = res.get("results") or []
                self._classify_failures(res.get("failed_results") or [])
                for row in res.get("refused") or []:
                    self._refuse(str((row or {}).get("url") or ""))
        except Exception as e:                        # noqa: BLE001
            # Anything raised by the client is a PROVIDER failure, not a
            # statement about the target: the target was never contacted.
            self.provider_failed = True
            self._note("tavily backend failed: %r" % (e,))
            for err in (getattr(self.client, "errors", None) or []):
                self._note("tavily: %s" % err)
            return []

        for item in results:
            page = self._accept(str((item or {}).get("url") or ""),
                                str((item or {}).get("raw_content") or ""))
            if page:
                pages.append(page)
            if self.budget_exhausted():
                break
        for err in (getattr(self.client, "errors", None) or []):
            self._note("tavily: %s" % err)
        return pages


# ── org-fact extraction ──────────────────────────────────────────────────────

def facts_from_jsonld(pages: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Pull Organization / Person records out of any JSON-LD the site ships.

    Far higher signal than prose when present -- but the live probe found ZERO
    ld+json blocks on a real corporate site, so nothing may depend on it.
    """
    out: Dict[str, Any] = {"profile": {}, "people": []}

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for n in node:
                walk(n)
            return
        if not isinstance(node, dict):
            return
        for key in ("@graph", "itemListElement", "mainEntity"):
            if key in node:
                walk(node[key])
        t = node.get("@type")
        types = {str(x).lower() for x in (t if isinstance(t, list) else [t]) if x}
        if types & {"organization", "corporation", "localbusiness"}:
            addr = node.get("address") or {}
            if isinstance(addr, list):
                addr = addr[0] if addr else {}
            if isinstance(addr, dict):
                parts = [addr.get("streetAddress"), addr.get("addressLocality"),
                         addr.get("addressRegion"), addr.get("postalCode"),
                         addr.get("addressCountry")]
                address = ", ".join(str(p) for p in parts if p)
            else:
                address = str(addr)
            prof = out["profile"]
            prof.setdefault("name", str(node.get("name") or "").strip())
            prof.setdefault("description", str(node.get("description") or "").strip())
            prof.setdefault("site", str(node.get("url") or "").strip())
            if address:
                prof.setdefault("address", address)
            tel = node.get("telephone")
            if tel:
                prof.setdefault("phone", str(tel))
        if types & {"person"}:
            nm = str(node.get("name") or "").strip()
            if nm:
                out["people"].append({
                    "name": nm,
                    "job_title": str(node.get("jobTitle") or "").strip(),
                    "source": "jsonld",
                    # ORG-SIDE EVIDENCE. The company published this name on its
                    # own site, which is a statement by the organisation rather
                    # than a claim on someone's profile -- see
                    # employment_evidence.EV_SITE_NAMED. It must survive the
                    # merge in WF13, which used to drop it whenever the SERP had
                    # already returned the same person.
                    "site_named": True,
                    "site_evidence": "jsonld",
                })

    for p in pages:
        for block in p.get("jsonld") or []:
            try:
                walk(block)
            except Exception:
                continue
    return out


_LLM_SCHEMA_HINT = (
    '{"description": str, "industry": str, "headquarters": str, '
    '"offices": [str], "units": [str], "people": [{"name": str, "title": str}], '
    '"technologies": [str], "partners": [str]}'
)


def extract_with_llm(pages: List[Dict[str, Any]], company_hint: str = "",
                     max_chars: int = 12000,
                     errors: Optional[List[str]] = None) -> Dict[str, Any]:
    """Ask the analysis model for structured org facts over the best pages.

    Returns {} on any failure -- the caller keeps whatever the deterministic
    extractors found.

    Anti-hallucination is enforced in CODE, not in the prompt: every name the
    model returns must appear verbatim in the source text it was given, or it is
    dropped. Asking a model nicely not to invent names is not a control.
    """
    def _fail(why: str) -> Dict[str, Any]:
        # The reason matters. "LLM extraction returned nothing" sent an operator
        # to debug the model when the real cause was an empty corpus, and that
        # is exactly the kind of silent nothing this codebase keeps producing.
        if errors is not None and why not in errors:
            errors.append("LLM extraction: " + why)
        return {}

    try:
        import llm_client
    except Exception as e:
        return _fail("llm_client is not importable (%r)" % (e,))

    # Ranked, so a smaller budget drops the least organizationally relevant
    # pages first. 12000 chars rather than 24000: a live 60-page crawl timed
    # out at the model's 180s ceiling on the larger prompt, and a timeout costs
    # the whole extraction while a smaller corpus costs only its tail.
    ranked = sorted(pages, key=lambda p: -score_url(p.get("url", "")))
    corpus, used = [], 0
    for p in ranked:
        body = _strip_heading_marks(p.get("text") or "")[:3000]
        if not body:
            continue
        block = "## %s (%s)\n%s" % (p.get("title") or "", p.get("url") or "", body)
        if used + len(block) > max_chars:
            break
        corpus.append(block)
        used += len(block)
    if not corpus:
        return _fail("no page text to send (every crawled page extracted empty)")
    source_text = "\n\n".join(corpus)

    messages = [
        {"role": "system",
         "content": "You extract company facts from website text for an authorized "
                    "security assessment. Reply with JSON only, matching this shape: "
                    + _LLM_SCHEMA_HINT + ". Use only facts present in the supplied "
                    "text. Use an empty string or empty list when the text does not "
                    "say. Never guess a name."},
        {"role": "user",
         # Every known identifier, not just one. A site written in another
         # language states the operator's identifier in that language, and the
         # model matching a page against "Maket Aero" alone will not connect it
         # to the legal entity the same page names in Cyrillic. The identifiers
         # are STILL only a hint -- the verbatim-source check below is what
         # stops the model from echoing one back as a finding.
         "content": ("Company, known by these identifiers (any may be "
                     "approximate, and the site may use only one of them): %s"
                     "\n\nWebsite text:\n\n%s"
                     % (company_hint or "unknown", source_text))},
    ]
    try:
        raw = llm_client.chat_completion(messages, timeout=180)
    except Exception as e:
        return _fail("model call failed (%r)" % (e,))
    try:
        data = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception as e:
        return _fail("model returned unparseable JSON (%r): %.120s" % (e, raw))
    if not isinstance(data, dict):
        return _fail("model returned %s, expected an object" % type(data).__name__)

    low = source_text.lower()

    def verbatim(items: Any, key: Optional[str] = None) -> List[Any]:
        keep = []
        for it in (items or []):
            name = (it.get(key) if (key and isinstance(it, dict)) else it)
            if not name:
                continue
            if str(name).strip().lower() in low:
                keep.append(it)
        return keep

    return {
        "description": str(data.get("description") or "")[:1200],
        "industry": str(data.get("industry") or "")[:160],
        "headquarters": str(data.get("headquarters") or "")[:300],
        "offices": [str(o)[:200] for o in verbatim(data.get("offices"))][:30],
        "units": [str(u)[:160] for u in verbatim(data.get("units"))][:30],
        "people": [{"name": str(p.get("name"))[:120],
                    "title": str(p.get("title") or "")[:160]}
                   for p in verbatim(data.get("people"), "name")][:60],
        "technologies": [str(t)[:80] for t in verbatim(data.get("technologies"))][:60],
        "partners": [str(x)[:160] for x in verbatim(data.get("partners"))][:40],
    }


# ── the public entry point ───────────────────────────────────────────────────

def collection_name(sketch_id: str) -> str:
    """Per-campaign collection. The five built-ins are global; this must not be.

    A target's website corpus has nothing to say about another campaign's target
    and must never be retrieved for one.
    """
    return "company_site__%s" % re.sub(r"[^A-Za-z0-9_-]", "_", str(sketch_id or "none"))


def crawl_and_index(
    domain: str,
    *,
    sketch_id: str = "",
    company_hint: str = "",
    company_aliases: Optional[List[str]] = None,
    proxy_url: str = "",
    user_agent: str = "",
    indexer: Any = None,
    use_llm: bool = True,
    backend: Optional[int] = None,
    **crawl_kwargs: Any,
) -> Dict[str, Any]:
    """Crawl, extract, index. Never raises.

    Mirrors hh_client.organization_profile()'s contract: every leg records into
    `errors` and a partially-filled result comes back, so the card renders
    whatever was reached.
    """
    out: Dict[str, Any] = {
        "matched": False,
        "source": "website",
        "domain": domain,
        "profile": {},
        "people": [],
        "technologies": [],
        "partners": [],
        "units": [],
        "offices": [],
        "pages_crawled": 0,
        "pages_refused": 0,
        "blocked": False,
        # Distinct from `blocked` all the way to the card: refused by the site
        # vs never reached at all. See site_empty_kind().
        "unreachable": False,
        "empty_kind": "",
        "empty_message": "",
        "chunks_indexed": 0,
        "collection": "",
        # Additive, so a cached record written before the Tavily backend
        # existed still renders. `backend` answers the question an operator
        # gets asked after an engagement: did we send this client's domain to
        # a third party, and did the fetches come from our egress or theirs?
        "backend": SITE_BACKEND_BUILTIN,
        "backend_label": "builtin",
        # Distinct from pages_refused ALL THE WAY TO THE CARD. pages_refused
        # means "our scope lock stopped this" and is the number that proves the
        # rail works; pages_failed means "the fetch did not succeed". Folding
        # one into the other would report the lock doing work it never did.
        "pages_failed": 0,
        "failed_sample": [],
        "provider_credits": 0,
        "errors": [],
    }
    if not _as_int(os.environ.get("SITE_ENABLED", "1"), 1):
        out["errors"].append("website crawling is disabled (SITE_ENABLED=0)")
        out["empty_kind"] = SITE_DISABLED
        out["empty_message"] = site_empty_message(SITE_DISABLED, domain=domain,
                                                  proxy_url=proxy_url)
        return out

    backend = site_backend() if backend is None else backend
    out["backend"] = backend
    out["backend_label"] = backend_label(backend)

    if backend:
        # FAILS CLOSED, and deliberately does not fall back to SiteCrawler.
        # Selecting Tavily is a choice NOT to contact the target from this
        # deployment's egress; quietly reversing it would do the one thing the
        # operator excluded, which is also the failure mode this repo keeps
        # writing notes about (a provider that swallows its own unavailability
        # reads as "the target had nothing").
        why = ""
        if not os.environ.get("TAVILY_API_KEY", "").strip():
            why = "TAVILY_API_KEY is not set"
        else:
            try:
                import tavily_client  # noqa: F401
            except Exception as e:    # noqa: BLE001
                why = "tavily_client is not importable (%r)" % (e,)
        if why:
            out["errors"].append(
                "website crawl is set to the Tavily backend (SITE_TAVILY=%d) but "
                "%s, so %s was NOT fetched -- and was NOT crawled with the "
                "built-in crawler instead." % (backend, why, domain))
            out["empty_kind"] = SITE_BACKEND_UNCONFIGURED
            out["empty_message"] = site_empty_message(
                SITE_BACKEND_UNCONFIGURED, domain=domain, proxy_url=proxy_url,
                backend=backend)
            return out
        crawler = TavilySiteCrawler(domain, proxy_url=proxy_url,
                                    user_agent=user_agent, backend=backend,
                                    **crawl_kwargs)
    else:
        crawler = SiteCrawler(domain, proxy_url=proxy_url, user_agent=user_agent,
                              **crawl_kwargs)
    # Ask once, cheaply, before committing the budget. Without this a target
    # that drops the campaign egress burns all of SITE_MAX_SECONDS timing out
    # request after request, and still ends with nothing to show for it.
    reach_ok, reach_why = crawler.reachable()
    if not reach_ok:
        crawler.unreachable += 1
        crawler._note("egress preflight failed for https://%s/: %s"
                      % (crawler.base_domain or domain, reach_why))
        pages: List[Dict[str, Any]] = []
    else:
        try:
            pages = crawler.crawl()
        except Exception as e:                        # noqa: BLE001
            crawler._note("crawl failed unexpectedly: %r" % (e,))
            pages = []
    out["errors"] = crawler.errors
    out["pages_crawled"] = len(crawler.fetched)
    out["pages_refused"] = len(crawler.refused)
    out["refused_sample"] = crawler.refused[:10]
    out["blocked"] = bool(crawler.blocked and not crawler.fetched)
    out["unreachable"] = bool(crawler.unreachable and not crawler.fetched)
    out["pages_failed"] = len(getattr(crawler, "failed", ()) or ())
    out["failed_sample"] = list(getattr(crawler, "failed", ()) or ())[:10]
    out["provider_credits"] = int(
        getattr(getattr(crawler, "client", None), "credits_spent", 0) or 0)
    if not pages:
        out["empty_kind"] = site_empty_kind(
            pages=len(crawler.fetched), blocked=out["blocked"],
            unreachable=out["unreachable"],
            provider_failed=bool(getattr(crawler, "provider_failed", False)))
        out["empty_message"] = site_empty_message(
            out["empty_kind"], domain=crawler.base_domain or domain,
            proxy_url=proxy_url, backend=backend)
        if out["blocked"]:
            crawler._note(
                "every request to %s was refused by the site (HTTP 403/429 on "
                "robots.txt and the homepage). The crawler was BLOCKED, which is "
                "not the same as the site having nothing -- many corporate WAFs "
                "reject datacenter IPs outright. Retry through the campaign "
                "proxy." % (crawler.base_domain or domain))
        elif out["unreachable"]:
            crawler._note(out["empty_message"])
        return out
    out["matched"] = True

    if backend:
        # Stated, because "deterministic first, so a model failure cannot cost
        # us the structured data" stops being true here and does so silently.
        crawler._note(
            "tavily backend: /crawl and /extract return rendered text only, with "
            "no application/ld+json, so the deterministic Organization/Person "
            "extractor found nothing to read. Every fact on this card therefore "
            "came from the analysis model -- checked verbatim against the fetched "
            "text, but with no structured corroboration. The built-in crawler "
            "reads JSON-LD when a site ships it.")
    # Deterministic first, so a model failure cannot cost us the structured data.
    ld = facts_from_jsonld(pages)
    profile = dict(ld.get("profile") or {})
    people = list(ld.get("people") or [])

    if use_llm:
        # Every identifier the operator gave, joined — see extract_with_llm.
        hint = " / ".join(dict.fromkeys(
            [h for h in ([company_hint] + list(company_aliases or [])) if str(h or "").strip()]))
        llm = extract_with_llm(pages, hint, errors=crawler.errors)
        if llm:
            for k_src, k_dst in (("description", "description"), ("industry", "industry"),
                                 ("headquarters", "address")):
                if llm.get(k_src) and not profile.get(k_dst):
                    profile[k_dst] = llm[k_src]
            out["offices"] = llm.get("offices") or []
            out["units"] = llm.get("units") or []
            out["technologies"] = llm.get("technologies") or []
            out["partners"] = llm.get("partners") or []
            for p in llm.get("people") or []:
                # site_named marks this as the ORGANISATION's own statement --
                # the name was published on a page under the target's domain.
                # The verbatim() guard above proves the name really appeared in
                # the fetched text, but NOT that the page was about the target:
                # a partners or customers page yields people who work for the
                # partner. See issues.md; the gate treats this as strong
                # evidence, so that limit is worth knowing about.
                people.append({"name": p.get("name", ""),
                               "job_title": p.get("title", ""),
                               "source": "website",
                               "site_named": True,
                               "site_evidence": "llm"})
        elif not any(e.startswith("LLM extraction") for e in crawler.errors):
            crawler._note("LLM extraction returned nothing; card shows only "
                          "deterministic facts")

    # Dedup people by case-folded name, preferring a row that has a title.
    by_name: Dict[str, Dict[str, Any]] = {}
    for p in people:
        key = re.sub(r"\s+", " ", str(p.get("name") or "")).strip().lower()
        if not key:
            continue
        cur = by_name.get(key)
        if cur is None or (not cur.get("job_title") and p.get("job_title")):
            by_name[key] = p
    people = list(by_name.values())

    try:
        from job_titles import derive_specialty
        for p in people:
            p["specialty"] = derive_specialty(p.get("job_title")) or ""
    except Exception:
        pass

    out["profile"] = profile
    out["people"] = people[:100]

    # ── index for retrieval ──────────────────────────────────────────────────
    col = collection_name(sketch_id)
    out["collection"] = col
    try:
        if indexer is None:
            from rag_indexer import RAGIndexer
            indexer = RAGIndexer()
        size = _as_int(os.environ.get("SITE_CHUNK_CHARS"), _DEFAULT_CHUNK_CHARS)
        overlap = _as_int(os.environ.get("SITE_CHUNK_OVERLAP"), _DEFAULT_CHUNK_OVERLAP)
        crawled_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        docs: List[Dict[str, Any]] = []
        for page in pages:
            body = page.get("text") or ""
            for i, ch in enumerate(chunk_text(body, size=size, overlap=overlap)):
                docs.append({
                    "id": "%s#%d" % (page.get("url", ""), i),
                    "text": ch["text"],
                    "metadata": {
                        "url": page.get("url", ""),
                        "page_title": page.get("title", ""),
                        "heading": ch.get("heading", ""),
                        "sketch_id": str(sketch_id or ""),
                        "crawled_at": crawled_at,
                        "chunk_ix": i,
                    },
                })
        # Reset first: index_documents dedups by id and can never CHANGE a
        # document, so without this a re-crawl of an edited page keeps serving
        # the old text forever.
        indexer.reset_collection(col)
        out["chunks_indexed"] = indexer.index_documents(col, docs)
    except Exception as e:                            # noqa: BLE001
        crawler._note("site indexing failed: %r" % (e,))
    return out


def extract_urls(urls: List[str], *, sketch_id: str = "", base_domain: str = "",
                 allow_off_domain: bool = False, indexer: Any = None,
                 client: Any = None, extract_depth: str = "basic",
                 proxy_url: str = "") -> Dict[str, Any]:
    """Read specific URLs through Tavily /extract and index them. Never raises.

    SEPARATE from crawl_and_index() on purpose. This is the ONE path that may
    read a page outside the target's registrable domain -- a press release on a
    trade site naming the CTO, a careers page on greenhouse.io, a conference
    bio -- so the decision is explicit, per-call, OFF BY DEFAULT and recorded in
    the result. It is deliberately NOT a loosening of in_scope(), which stays
    absolute for the crawl: one URL chosen by a human or by a scored search
    result is a categorically different act from turning a crawler loose.

    Off-domain pages are indexed with in_scope=False in their metadata, so a
    retrieved passage can be rendered as somebody else's statement ABOUT the
    target rather than the target's own. The partners-page warning applies
    doubly here: a third-party page names third-party people.

    linkedin.com is refused by tavily_client regardless of allow_off_domain --
    see its module docstring.
    """
    out: Dict[str, Any] = {
        "matched": False,
        "source": "website_extract",
        "urls_requested": len([u for u in (urls or ()) if str(u or "").strip()]),
        "urls_read": 0,
        "urls_failed": 0,
        "urls_refused": 0,
        "failed_sample": [],
        "refused_sample": [],
        "off_domain": 0,
        "chunks_indexed": 0,
        "collection": "",
        "errors": [],
    }
    wanted = [str(u).strip() for u in (urls or ()) if str(u or "").strip()]
    if not wanted:
        out["errors"].append("extract_urls: no URLs given")
        return out
    if not os.environ.get("TAVILY_API_KEY", "").strip():
        out["errors"].append(
            "extract_urls needs TAVILY_API_KEY: reading a page outside the "
            "target's own domain is only available through Tavily, and there is "
            "no built-in path for it by design.")
        return out

    base = registrable_domain(base_domain) if base_domain else ""
    keep: List[str] = []
    for u in wanted:
        norm = normalise_url(u)
        if not norm:
            out["refused_sample"].append(u)
            continue
        on_domain = bool(base) and in_scope(norm, base)
        if not on_domain and not allow_off_domain:
            out["refused_sample"].append(norm)
            out["errors"].append(
                "%s is outside %s and allow_off_domain is not set; refused"
                % (norm[:120], base or "the target domain"))
            continue
        if not on_domain:
            out["off_domain"] += 1
        keep.append(norm)
    out["urls_refused"] = len(out["refused_sample"])
    out["refused_sample"] = out["refused_sample"][:10]
    if not keep:
        return out

    try:
        import tavily_client
        if client is None:
            client = tavily_client.TavilyClient(proxy_url=proxy_url)
        res = client.extract(keep, extract_depth=extract_depth)
    except Exception as e:                            # noqa: BLE001
        out["errors"].append("extract_urls: tavily failed: %r" % (e,))
        return out

    for row in (res.get("refused") or []):
        out["urls_refused"] += 1
        out["errors"].append(str((row or {}).get("reason") or "refused"))
    failed = [{"url": str((f or {}).get("url") or "")[:300],
               "error": str((f or {}).get("error") or "")[:200]}
              for f in (res.get("failed_results") or [])]
    out["urls_failed"] = len(failed)
    out["failed_sample"] = failed[:10]
    for err in (getattr(client, "errors", None) or []):
        if err not in out["errors"]:
            out["errors"].append(err)

    max_bytes = _as_int(os.environ.get("SITE_MAX_BYTES_PER_PAGE"), _DEFAULT_MAX_BYTES)
    pages: List[Dict[str, Any]] = []
    for item in (res.get("results") or []):
        url = str((item or {}).get("url") or "")
        page = markdown_to_page(url, str((item or {}).get("raw_content") or ""),
                               max_bytes=max_bytes)
        if page["text"].strip():
            page["in_scope"] = bool(base) and in_scope(url, base)
            pages.append(page)
    out["urls_read"] = len(pages)
    out["matched"] = bool(pages)
    if not pages:
        return out

    col = collection_name(sketch_id)
    out["collection"] = col
    try:
        if indexer is None:
            from rag_indexer import RAGIndexer
            indexer = RAGIndexer()
        size = _as_int(os.environ.get("SITE_CHUNK_CHARS"), _DEFAULT_CHUNK_CHARS)
        overlap = _as_int(os.environ.get("SITE_CHUNK_OVERLAP"), _DEFAULT_CHUNK_OVERLAP)
        read_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        docs: List[Dict[str, Any]] = []
        for page in pages:
            for i, ch in enumerate(chunk_text(page.get("text") or "",
                                              size=size, overlap=overlap)):
                docs.append({
                    "id": "%s#%d" % (page.get("url", ""), i),
                    "text": ch["text"],
                    "metadata": {
                        "url": page.get("url", ""),
                        "page_title": page.get("title", ""),
                        "heading": ch.get("heading", ""),
                        "sketch_id": str(sketch_id or ""),
                        "crawled_at": read_at,
                        "chunk_ix": i,
                        # The whole reason this path is separate. A passage from
                        # somebody else's site must be attributable as such.
                        "in_scope": bool(page.get("in_scope")),
                    },
                })
        # NOT reset_collection(): this adds to whatever the crawl indexed rather
        # than replacing it. index_documents dedups by id, so re-reading the
        # same URL is idempotent.
        out["chunks_indexed"] = indexer.index_documents(col, docs)
    except Exception as e:                            # noqa: BLE001
        out["errors"].append("extract_urls indexing failed: %r" % (e,))
    return out


def ask_site(question: str, sketch_id: str, n_results: int = 5,
             indexer: Any = None) -> List[Dict[str, Any]]:
    """Retrieve passages about the company, each with its citation URL."""
    try:
        if indexer is None:
            from rag_indexer import RAGIndexer
            indexer = RAGIndexer()
        hits = indexer.query(collection_name(sketch_id), question, n_results=n_results)
    except Exception:
        return []
    out = []
    for h in hits or []:
        md = h.get("metadata") or {}
        out.append({
            "text": h.get("document", ""),
            "url": md.get("url", ""),
            "page_title": md.get("page_title", ""),
            "heading": md.get("heading", ""),
            "score": h.get("score"),
        })
    return out
