#!/usr/bin/env python3
"""
Offline smoke test for scripts/site_rag.py and the rag_indexer extensions.

Runs a synthetic site through the whole path -- robots.txt, sitemap, crawl,
extract, chunk, index, retrieve -- with no network and no stack.

What it pins, and why:

  * OFF-DOMAIN URLS ARE REFUSED. This crawler deliberately ignores robots.txt,
    so scope is the only thing keeping it off third parties. Highest-value
    assertion in the file. Includes the suffix-confusion case
    (`sample.test.evil.example`) and non-http schemes.
  * robots.txt is read for `Sitemap:` and its Disallow rules are NOT applied.
  * Sitemap-first discovery beats path-guessing. The fixture reproduces the real
    finding that motivated the design: /about is a 404 and the org page lives at
    /our-team/, reachable only through the sitemap.
  * URL scoring puts org pages above article-shaped slugs. A live run scored the
    blog post `/weekly-notes-about-the-news-2024-02-06/` as highly as
    `/about/our-staff/`, because "about" matched mid-slug.
  * Chunking: no chunk is tiny, none starts with a word fragment from the
    overlap carry, and the heading survives onto the metadata.
  * reset_collection actually REPLACES a changed page. index_documents dedups by
    id and can never change a document, so without the reset a re-crawl serves
    stale text forever.
  * A collection name containing `../` cannot escape the index directory.
  * Extracted names absent from the source text are dropped -- the
    anti-hallucination check is in code, not in the prompt.
  * A dead proxy fails closed.
  * A TRANSPORT failure is not an empty site. Every fetch timing out reports
    `unreachable`, never a bare zero -- the 2026-09-21 defect, where a target
    that silently drops Tor exit traffic was indistinguishable on the card from
    a site with nothing on it.
  * The egress preflight short-circuits: one bounded request, crawl() never
    entered, the page budget untouched.

Usage:
    python3 scripts/smoke_site_rag.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Force the offline TF-IDF embedder: this test must not need vllm-embed.
os.environ["SPOTTER_CACHE_DIR"] = tempfile.mkdtemp(prefix="spotter-smoke-site-")
os.environ.pop("VLLM_EMBEDDING_MODE", None)
os.environ.pop("EMBEDDING_URL", None)

import requests  # noqa: E402

import site_rag  # noqa: E402
from rag_indexer import RAGIndexer  # noqa: E402
from site_rag import (  # noqa: E402
    SiteCrawler, chunk_text, collection_name, extract_page, facts_from_jsonld,
    in_scope, registrable_domain, score_url,
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


# ── a synthetic site ─────────────────────────────────────────────────────────
# Shaped after the real corporate site probed on 2026-09-20: /about 404s, the
# org page is at /our-team/, and there is no JSON-LD on most pages.

ROBOTS = """User-agent: *
Allow: /
Disallow: /our-team/
Disallow: /secret-roadmap/

Sitemap: https://sample.test/sitemap.xml
"""

SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://sample.test/</loc></url>
  <url><loc>https://sample.test/our-team/</loc></url>
  <url><loc>https://sample.test/about/leadership/</loc></url>
  <url><loc>https://sample.test/weekly-notes-about-the-news-2024-02-06/</loc></url>
  <url><loc>https://sample.test/blog/2019/some-old-post/</loc></url>
  <url><loc>https://evil.example/phishing/</loc></url>
</urlset>
"""

PAGES = {
    "https://sample.test/": """<html><head><title>Sample Corp</title>
      <script type="application/ld+json">{"@type":"Organization","name":"Sample Corp",
      "url":"https://sample.test","description":"We make industrial widgets.",
      "address":{"streetAddress":"1 Main St","addressLocality":"Denver","addressRegion":"CO"}}</script>
      </head><body><nav><a href="/cart">Cart</a></nav>
      <h1>Sample Corp</h1><p>We make industrial widgets for the mining sector.</p>
      <a href="/our-team/">Our team</a><a href="https://evil.example/x">Partner</a>
      <script>var t='tracker';</script><footer>Copyright Sample</footer></body></html>""",
    "https://sample.test/our-team/": """<html><head><title>Our Team | Sample</title>
      <script type="application/ld+json">{"@type":"Person","name":"Jane Roe",
      "jobTitle":"Chief Technology Officer"}</script></head>
      <body><h1>Our Team</h1>
      <p>Jane Roe is our Chief Technology Officer and runs the platform team.</p>
      <p>John Smith is Head of IT. He manages Active Directory and Azure.</p>
      <h2>Offices</h2><p>Denver, Colorado and Austin, Texas.</p></body></html>""",
    "https://sample.test/about/leadership/": """<html><head><title>Leadership</title></head>
      <body><h1>Leadership</h1><p>Our board is chaired by Alex Example.</p>
      <p>%s</p></body></html>""" % ("Filler sentence about governance. " * 90),
    "https://sample.test/weekly-notes-about-the-news-2024-02-06/":
        "<html><head><title>News</title></head><body><p>Weekly roundup.</p></body></html>",
    "https://sample.test/blog/2019/some-old-post/":
        "<html><head><title>Old</title></head><body><p>Old post.</p></body></html>",
}


class FakeResponse:
    def __init__(self, body: str, status: int = 200, url: str = "",
                 ctype: str = "text/html"):
        self._body = (body or "").encode("utf-8")
        self.status_code = status
        self.ok = 200 <= status < 400
        self.url = url
        self.headers = {"Content-Type": ctype}

    def iter_content(self, n):
        for i in range(0, len(self._body), n):
            yield self._body[i:i + n]

    def close(self):
        pass


def install_transport(extra: dict | None = None, fail_with=None):
    """Replace requests.get inside site_rag. Returns the fetched-URL list."""
    seen: list[str] = []
    table = dict(PAGES)
    table["https://sample.test/robots.txt"] = ROBOTS
    table["https://sample.test/sitemap.xml"] = SITEMAP
    table.update(extra or {})

    def fake_get(url, **kw):
        seen.append(url)
        if fail_with is not None:
            raise fail_with
        body = table.get(url)
        if body is None:
            # /about really is a 404 here -- the whole point of the fixture.
            return FakeResponse("not found", 404, url=url)
        ctype = "application/xml" if url.endswith(".xml") else (
            "text/plain" if url.endswith(".txt") else "text/html")
        return FakeResponse(body, 200, url=url, ctype=ctype)

    site_rag.requests.get = fake_get
    return seen


_REAL_GET = site_rag.requests.get


# ── tests ────────────────────────────────────────────────────────────────────

def test_scope_lock():
    section("scope lock (the rail that replaces robots.txt)")
    check("own domain", in_scope("https://sample.test/x", "sample.test"))
    check("www", in_scope("https://www.sample.test/x", "sample.test"))
    check("subdomain", in_scope("https://careers.sample.test/x", "sample.test"))
    check("unrelated host refused", not in_scope("https://evil.example/", "sample.test"))
    check("suffix-confusion refused (sample.test.evil.example)",
          not in_scope("https://sample.test.evil.example/", "sample.test"))
    check("prefix-confusion refused (notsample.test)",
          not in_scope("https://notsample.test/", "sample.test"))
    check("javascript: refused", not in_scope("javascript:alert(1)", "sample.test"))
    check("mailto: refused", not in_scope("mailto:a@b.c", "sample.test"))
    check("data: refused", not in_scope("data:text/html,<b>x", "sample.test"))
    check("empty base refuses everything", not in_scope("https://sample.test/", ""))

    check("registrable domain strips www", registrable_domain("www.sample.test") == "sample.test")
    check("two-level TLD", registrable_domain("a.b.example.co.uk") == "example.co.uk")


def test_scoring():
    section("URL scoring")
    org = score_url("https://sample.test/about/leadership/")
    post = score_url("https://sample.test/weekly-notes-about-the-news-2024-02-06/")
    check("an org page outranks an article whose slug merely contains 'about'",
          org > post, "org=%d post=%d" % (org, post))
    check("the dated article scores negative", post < 0, str(post))
    check("/our-team/ scores well", score_url("https://sample.test/our-team/") >= 8)
    check("the homepage earns a slot", score_url("https://sample.test/") > 0)
    check("wp-admin is excluded", score_url("https://sample.test/wp-admin/") == -1)
    check("an image is excluded", score_url("https://sample.test/logo.png") == -1)
    check("a dated archive path is penalised",
          score_url("https://sample.test/blog/2019/some-old-post/") < 0)


def test_discovery_and_crawl():
    section("discovery and crawl")
    seen = install_transport()
    c = SiteCrawler("sample.test", max_pages=4, delay_ms=0)
    pages = c.crawl()

    check("robots.txt was fetched for its Sitemap directive",
          any(u.endswith("/robots.txt") for u in seen), str(seen[:3]))
    check("the sitemap was followed",
          any(u.endswith("/sitemap.xml") for u in seen), str(seen[:4]))
    # The fixture's robots.txt Disallows /our-team/ — and we crawl it anyway.
    fetched = set(c.fetched)
    check("a robots-Disallowed page IS crawled (Disallow is deliberately ignored)",
          "https://sample.test/our-team/" in fetched, str(sorted(fetched)))
    check("sitemap-only pages are reached without path-guessing",
          "https://sample.test/about/leadership/" in fetched, str(sorted(fetched)))
    check("/about was never guessed", not any(u == "https://sample.test/about" for u in seen))
    check("the off-domain sitemap entry was refused",
          "https://evil.example/phishing/" in c.refused, str(c.refused))
    check("no request ever went off-domain",
          not any("evil.example" in u for u in seen), str([u for u in seen if "evil.example" in u]))
    check("the page budget held", len(c.fetched) <= 4, str(len(c.fetched)))
    check("pages were extracted", len(pages) >= 2, str(len(pages)))

    home = [p for p in pages if p["url"] == "https://sample.test/"]
    if home:
        t = home[0]["text"]
        check("nav, footer and script text are dropped",
              all(x not in t for x in ("Cart", "Copyright Sample", "tracker")), t[:80])


def test_extraction():
    section("extraction")
    pg = extract_page(PAGES["https://sample.test/"])
    check("title", pg["title"] == "Sample Corp", pg["title"])
    check("jsonld captured", bool(pg["jsonld"]))
    who_pg = extract_page(PAGES["https://sample.test/our-team/"])
    facts = facts_from_jsonld([pg, who_pg])
    check("Organization name from JSON-LD", facts["profile"].get("name") == "Sample Corp", str(facts))
    check("address assembled", "Denver" in (facts["profile"].get("address") or ""), str(facts))
    check("a JSON-LD Person is extracted",
          [p["name"] for p in facts.get("people") or []] == ["Jane Roe"],
          str(facts.get("people")))

    # site_named is ORG-SIDE evidence: the company published this name on its own
    # site. It is the strongest non-AD signal the employment gate has, and WF13's
    # merge used to discard it whenever the SERP had already returned the person.
    for p in facts.get("people") or []:
        check("jsonld person %r is marked site_named" % p.get("name"),
              p.get("site_named") is True and p.get("site_evidence") == "jsonld", str(p))

    who = extract_page(PAGES["https://sample.test/our-team/"])
    check("body text retained", "Chief Technology Officer" in who["text"], who["text"][:90])


def test_chunking():
    section("chunking")
    text = extract_page(PAGES["https://sample.test/about/leadership/"])["text"]
    chunks = chunk_text(text, size=600, overlap=100)
    check("more than one chunk for a long page", len(chunks) > 1, str(len(chunks)))
    check("no chunk is a bare heading", all(len(c["text"]) >= 80 for c in chunks),
          str([len(c["text"]) for c in chunks]))
    check("no chunk wildly exceeds the size", all(len(c["text"]) <= 800 for c in chunks),
          str([len(c["text"]) for c in chunks]))
    plain = site_rag._strip_heading_marks(text)
    words = {w.strip(".,") for w in plain.split()}
    starts = [c["text"].split()[0].strip(".,") for c in chunks if c["text"].split()]
    check("no chunk starts with a word fragment from the overlap carry",
          all(s in words for s in starts), str([s for s in starts if s not in words]))
    check("the heading is carried", any(c["heading"] for c in chunks),
          str([c["heading"] for c in chunks][:3]))
    check("empty input yields no chunks", chunk_text("") == [])
    check("a short page yields exactly one chunk", len(chunk_text("Sample Corp.")) == 1)


def test_index_and_retrieve():
    section("index, retrieve, re-crawl")
    install_transport()
    ix = RAGIndexer()
    r = site_rag.crawl_and_index("sample.test", sketch_id="sk-1", use_llm=False,
                                 indexer=ix, max_pages=4, delay_ms=0)
    check("matched", r["matched"] is True)
    check("chunks were indexed", r["chunks_indexed"] > 0, str(r["chunks_indexed"]))
    check("per-campaign collection name", r["collection"] == "company_site__sk-1", r["collection"])
    check("refused off-domain URLs are counted, not hidden",
          r["pages_refused"] >= 1, str(r["pages_refused"]))
    check("profile came from JSON-LD without the LLM",
          r["profile"].get("name") == "Sample Corp", str(r["profile"]))
    crawled_people = r.get("people") or []
    check("every crawled person carries the site_named marker",
          bool(crawled_people)
          and all(p.get("site_named") is True for p in crawled_people),
          str(crawled_people))

    hits = site_rag.ask_site("who is the chief technology officer", "sk-1",
                             n_results=3, indexer=ix)
    check("retrieval returns something", bool(hits), str(hits[:1]))
    check("every hit carries a citation URL", all(h["url"] for h in hits), str(hits[:1]))
    check("the CTO passage is retrievable",
          any("Chief Technology Officer" in h["text"] for h in hits),
          str([h["text"][:60] for h in hits]))

    # A campaign must not retrieve another campaign's corpus.
    check("another campaign's collection is empty",
          site_rag.ask_site("chief technology officer", "sk-OTHER", indexer=ix) == [])

    # Re-crawl with CHANGED content: index_documents dedups by id and can never
    # change a document, so only reset_collection makes this work.
    changed = dict(PAGES)
    changed["https://sample.test/our-team/"] = (
        "<html><head><title>Our Team | Sample</title></head><body><h1>Our Team</h1>"
        "<p>Pat Example is our Chief Technology Officer following Jane Roe's departure. "
        "She runs the platform team and the security group.</p></body></html>")
    install_transport(extra=changed)
    site_rag.crawl_and_index("sample.test", sketch_id="sk-1", use_llm=False,
                             indexer=ix, max_pages=4, delay_ms=0)
    hits2 = site_rag.ask_site("who is the chief technology officer", "sk-1",
                              n_results=5, indexer=ix)
    joined = " ".join(h["text"] for h in hits2)
    check("a re-crawl serves the NEW text", "Pat Example" in joined, joined[:120])
    check("...and no longer serves the stale text", "Jane Roe is our Chief" not in joined,
          joined[:120])


def test_collection_name_cannot_escape():
    section("collection-name safety")
    ix = RAGIndexer()
    nasty = collection_name("../../../etc/passwd")
    path = ix._collection_path(nasty)
    check("a traversal attempt stays inside the index dir",
          os.path.realpath(path).startswith(os.path.realpath(ix.index_dir)), path)
    check("the name is slugified", "/" not in nasty and ".." not in nasty, nasty)


def test_llm_names_must_be_verbatim():
    section("anti-hallucination")
    import types
    fake = types.ModuleType("llm_client")
    fake.chat_completion = lambda messages, **kw: (
        '{"description":"We make widgets.","industry":"Manufacturing",'
        '"headquarters":"Denver","offices":["Denver"],"units":[],'
        '"people":[{"name":"Jane Roe","title":"CTO"},'
        '{"name":"Wholly Invented Person","title":"CEO"}],'
        '"technologies":["Azure","Kubernetes"],"partners":["Globex"]}')
    sys.modules["llm_client"] = fake
    try:
        pages = [{"url": "https://sample.test/our-team/", "title": "Our Team",
                  "text": "Jane Roe is our Chief Technology Officer. We use Azure."}]
        got = site_rag.extract_with_llm(pages, "Sample Corp")
        names = [p["name"] for p in got.get("people") or []]
        check("a name present in the source survives", "Jane Roe" in names, str(names))
        check("a name the model invented is DROPPED",
              "Wholly Invented Person" not in names, str(names))
        check("a technology present in the source survives",
              "Azure" in (got.get("technologies") or []), str(got.get("technologies")))
        check("a technology the model invented is dropped",
              "Kubernetes" not in (got.get("technologies") or []), str(got.get("technologies")))
        check("an invented partner is dropped",
              "Globex" not in (got.get("partners") or []), str(got.get("partners")))
    finally:
        sys.modules.pop("llm_client", None)


def test_llm_failure_is_survivable():
    section("LLM failure")
    import types
    fake = types.ModuleType("llm_client")

    def boom(messages, **kw):
        raise RuntimeError("model unavailable")

    fake.chat_completion = boom
    sys.modules["llm_client"] = fake
    install_transport()
    try:
        ix = RAGIndexer()
        r = site_rag.crawl_and_index("sample.test", sketch_id="sk-llmfail",
                                     use_llm=True, indexer=ix, max_pages=3, delay_ms=0)
        check("the crawl still succeeds", r["matched"] is True)
        check("deterministic JSON-LD facts survive a dead model",
              r["profile"].get("name") == "Sample Corp", str(r["profile"]))
        check("the operator is told the model produced nothing",
              any("LLM extraction" in e for e in r["errors"]), str(r["errors"]))
    finally:
        sys.modules.pop("llm_client", None)


def test_proxy_fails_closed():
    section("proxy fail-closed")
    install_transport(fail_with=requests.exceptions.ProxyError("tunnel refused"))
    try:
        c = SiteCrawler("sample.test", proxy_url="socks5h://127.0.0.1:9050", delay_ms=0)
        try:
            c._get("https://sample.test/")
            check("a dead proxy raises instead of going direct", False, "no exception")
        except site_rag.SiteError as e:
            check("a dead proxy raises instead of going direct",
                  "refusing to fall back to direct egress" in str(e), str(e)[:90])
        # And through the never-raises wrapper.
        r = site_rag.crawl_and_index("sample.test", sketch_id="sk-proxy",
                                     use_llm=False, max_pages=2, delay_ms=0)
        check("crawl_and_index surfaces it instead of raising",
              any("proxy unreachable" in e for e in r["errors"]), str(r["errors"]))
        check("nothing is claimed as matched", r["matched"] is False)
    finally:
        site_rag.requests.get = _REAL_GET


def test_blocked_is_not_empty():
    section("blocked vs empty")
    # Some large sites answer 403 to every request from a datacenter IP, robots.txt
    # included. Reporting that as an empty site would be evidence of absence
    # drawn from absence of access.
    real = site_rag.requests.get
    site_rag.requests.get = lambda url, **kw: FakeResponse("forbidden", 403, url=url)
    try:
        r = site_rag.crawl_and_index("sample.test", sketch_id="sk-blocked",
                                     use_llm=False, max_pages=3, delay_ms=0)
        check("blocked is reported distinctly", r["blocked"] is True, str(r["blocked"]))
        check("matched stays False", r["matched"] is False)
        check("the note says BLOCKED, not empty",
              any("BLOCKED" in e and "not the same as" in e for e in r["errors"]),
              str(r["errors"])[:160])
        check("...and suggests the proxy",
              any("proxy" in e for e in r["errors"]), str(r["errors"])[:160])
    finally:
        site_rag.requests.get = real

    # A site that answers but genuinely has nothing must NOT claim it was blocked.
    install_transport({"https://sample.test/robots.txt": "User-agent: *\nAllow: /\n"})
    r2 = site_rag.crawl_and_index("sample.test", sketch_id="sk-thin",
                                  use_llm=False, max_pages=3, delay_ms=0)
    check("a reachable site is never reported as blocked", r2["blocked"] is False,
          str(r2["blocked"]))


def test_unreachable_is_not_empty():
    section("unreachable vs empty")
    # The defect this exists for: one live target answered nothing at all through a
    # Tor exit it drops. Connect succeeds, no response follows, every fetch dies
    # at the read timeout -- and the card said "no match", the status that means
    # "we reached the site and it had nothing".
    #
    # Preflight off here, so the counter under test is the one in _get(); the
    # preflight's own short-circuit is pinned by the next test.
    os.environ["SITE_PREFLIGHT_TIMEOUT"] = "0"
    install_transport(fail_with=requests.exceptions.ReadTimeout("Read timed out"))
    try:
        r = site_rag.crawl_and_index(
            "sample.test", sketch_id="sk-unreach", use_llm=False,
            max_pages=3, delay_ms=0,
            proxy_url="socks5h://operator:hunter2@127.0.0.1:9050")
        check("unreachable is reported distinctly", r["unreachable"] is True,
              str(r["unreachable"]))
        check("...and is NOT reported as blocked", r["blocked"] is False,
              str(r["blocked"]))
        check("matched stays False", r["matched"] is False)
        check("the empty is classified as a transport failure",
              r["empty_kind"] == site_rag.SITE_UNREACHABLE, str(r["empty_kind"]))
        check("the message says NOT REACHED, not empty",
              "NOT REACHED" in r["empty_message"], r["empty_message"][:120])
        check("...and names the egress an operator would have to change",
              "127.0.0.1:9050" in r["empty_message"], r["empty_message"][:160])
        # The proxy URL carries credentials from the Infrastructure envelope and
        # this string lands on the card and in the workflow response.
        check("...without leaking the proxy password",
              "hunter2" not in r["empty_message"], r["empty_message"][:160])
    finally:
        site_rag.requests.get = _REAL_GET
        os.environ.pop("SITE_PREFLIGHT_TIMEOUT", None)

    # A site that answers and simply has nothing must NOT claim it was unreachable:
    # that is the one empty state that IS a finding about the site.
    install_transport({"https://sample.test/robots.txt": "User-agent: *\nAllow: /\n"})
    thin = site_rag.crawl_and_index("sample.test", sketch_id="sk-thin2",
                                    use_llm=False, max_pages=3, delay_ms=0)
    check("a reachable site is never reported as unreachable",
          thin["unreachable"] is False, str(thin["unreachable"]))
    check("a crawl that found pages carries no empty_kind at all",
          thin["empty_kind"] == "" if thin["pages_crawled"]
          else thin["empty_kind"] == site_rag.SITE_NO_PAGES,
          "%s / %s pages" % (thin["empty_kind"], thin["pages_crawled"]))


def test_preflight_short_circuits():
    section("egress preflight")
    entered = {"crawl": 0}
    real_crawl = SiteCrawler.crawl

    def spy(self):
        entered["crawl"] += 1
        return real_crawl(self)

    site_rag.SiteCrawler.crawl = spy
    try:
        # 1. Unreachable target: one bounded request, and the 180s budget is
        #    never opened. Before this, six consecutive live runs spent the whole
        #    SITE_MAX_SECONDS timing out one page at a time and reported zero.
        seen = install_transport(fail_with=requests.exceptions.ConnectTimeout("no route"))
        r = site_rag.crawl_and_index("sample.test", sketch_id="sk-pre",
                                     use_llm=False, max_pages=60, delay_ms=0)
        check("crawl() is never entered when the egress cannot reach the site",
              entered["crawl"] == 0, str(entered["crawl"]))
        check("...at the cost of exactly one request", len(seen) == 1, str(seen))
        check("...and the page budget is untouched", r["pages_crawled"] == 0)
        check("...reported as unreachable, not as an empty site",
              r["empty_kind"] == site_rag.SITE_UNREACHABLE, str(r["empty_kind"]))
        check("the preflight says which URL it could not reach",
              any("egress preflight failed" in e for e in r["errors"]),
              str(r["errors"])[:160])

        # 2. A reachable target must still be crawled -- otherwise every
        #    assertion above would also pass on a crawler that never runs.
        entered["crawl"] = 0
        install_transport()
        good = site_rag.crawl_and_index("sample.test", sketch_id="sk-pre-ok",
                                        use_llm=False, max_pages=4, delay_ms=0)
        check("a reachable site is still crawled", entered["crawl"] == 1,
              str(entered["crawl"]))
        check("...and pages come back", good["pages_crawled"] > 0,
              str(good["pages_crawled"]))
        check("...with no empty_kind on a crawl that worked",
              good["empty_kind"] == "", str(good["empty_kind"]))

        # 3. A 403 is NOT a transport failure: the site answered. The preflight
        #    must let the crawl through so `blocked` is recorded properly.
        entered["crawl"] = 0
        site_rag.requests.get = lambda url, **kw: FakeResponse("forbidden", 403, url=url)
        waf = site_rag.crawl_and_index("sample.test", sketch_id="sk-pre-waf",
                                       use_llm=False, max_pages=3, delay_ms=0)
        check("a WAF 403 does not short-circuit the crawl", entered["crawl"] == 1,
              str(entered["crawl"]))
        check("...and is classified as blocked, not unreachable",
              waf["empty_kind"] == site_rag.SITE_BLOCKED, str(waf["empty_kind"]))

        # 4. The documented escape hatch: 0 skips the preflight entirely.
        entered["crawl"] = 0
        os.environ["SITE_PREFLIGHT_TIMEOUT"] = "0"
        try:
            seen0 = install_transport()
            site_rag.crawl_and_index("sample.test", sketch_id="sk-pre-off",
                                     use_llm=False, max_pages=2, delay_ms=0)
            check("SITE_PREFLIGHT_TIMEOUT=0 skips the preflight request",
                  seen0[0].endswith("robots.txt"), str(seen0[:2]))
            check("...and the crawl runs as before", entered["crawl"] == 1)
        finally:
            os.environ.pop("SITE_PREFLIGHT_TIMEOUT", None)
    finally:
        site_rag.SiteCrawler.crawl = real_crawl
        site_rag.requests.get = _REAL_GET


def test_disabled():
    section("SITE_ENABLED=0")
    os.environ["SITE_ENABLED"] = "0"
    try:
        r = site_rag.crawl_and_index("sample.test", sketch_id="sk-off")
        check("nothing is crawled", r["pages_crawled"] == 0)
        check("and the reason is recorded",
              any("disabled" in e for e in r["errors"]), str(r["errors"]))
    finally:
        os.environ.pop("SITE_ENABLED", None)



# ── Tavily backend ───────────────────────────────────────────────────────────

import json as _json                                                # noqa: E402
import tavily_client                                                # noqa: E402


class _TavR:
    """Stand-in for requests.Response as tavily_client uses it."""

    def __init__(self, payload, status=200):
        self._p = payload
        self.status_code = status
        self.ok = 200 <= status < 300
        self.headers = {}
        self.text = _json.dumps(payload)

    def iter_content(self, n):
        yield self.text.encode()

    def close(self):
        pass

    def json(self):
        return self._p


def _tav_stub(router, capture):
    def _post(url, **kw):
        body = kw.get("json") or {}
        capture.append({"url": url, "payload": body})
        return _TavR(router(url, body))
    return _post


def _tav_env(backend, key="fake-tavily-key"):
    prev = {k: os.environ.get(k) for k in
            ("SITE_TAVILY", "TAVILY_API_KEY", "SITE_MAX_PAGES", "TAVILY_MAX_CREDITS")}
    os.environ["SITE_TAVILY"] = str(backend)
    os.environ["TAVILY_MAX_CREDITS"] = "500"
    if key is None:
        os.environ.pop("TAVILY_API_KEY", None)
    else:
        os.environ["TAVILY_API_KEY"] = key
    return prev


def _tav_restore(prev):
    for k, v in prev.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


_MD = "# Sample Corp\n\n## Leadership\n\nJane Roe is Chief Technology Officer.\n"


def test_tavily_scope_regex():
    section("tavily scope regex mirrors in_scope()")
    import re as _re
    rx = _re.compile(site_rag.tavily_domain_regex("sample.test"))
    for host, want in (("sample.test", True), ("www.sample.test", True),
                       ("careers.sample.test", True),
                       ("sample.test.evil.example", False), ("notsample.test", False)):
        check("%s -> %s" % (host, want), bool(rx.match(host)) is want)
    pat = site_rag.tavily_domain_regex("example.co.uk")
    check("pattern is anchored at both ends",
          pat.startswith("^") and pat.endswith("$"), pat)
    check("the dot is escaped", r"example\.co\.uk" in pat, pat)


def test_tavily_payload_is_scope_locked():
    section("tavily request payload")
    prev, seen = _tav_env(2), []
    real = tavily_client.requests.post
    tavily_client.requests.post = _tav_stub(
        lambda u, b: {"base_url": "https://sample.test/", "results": [], "usage": {}}, seen)
    try:
        site_rag.crawl_and_index("sample.test", use_llm=False, max_pages=6,
                                 max_depth=9, max_seconds=900)
        p0 = seen[0]["payload"]
        check("allow_external is False", p0.get("allow_external") is False)
        check("select_domains is the in_scope regex",
              p0.get("select_domains") == [site_rag.tavily_domain_regex("sample.test")],
              str(p0.get("select_domains")))
        check("exclude_paths were sent", bool(p0.get("exclude_paths")))
        check("max_depth clamped into Tavily's 1-5",
              1 <= p0.get("max_depth", 0) <= 5, str(p0.get("max_depth")))
        check("timeout clamped into Tavily's 10-150",
              10 <= p0.get("timeout", 0) <= 150, str(p0.get("timeout")))
        check("no `instructions` is ever sent", "instructions" not in p0)
        check("no `query` is sent", "query" not in p0)
        check("no `chunks_per_source` is sent", "chunks_per_source" not in p0)
    finally:
        tavily_client.requests.post = real
        _tav_restore(prev)


def test_tavily_offdomain_result_is_dropped():
    section("the scope rail is asserted LOCALLY")
    prev, seen = _tav_env(2), []
    real = tavily_client.requests.post
    # Tavily returns an off-domain page DESPITE allow_external=false. Its
    # documentation describes that flag against the results LIST, so this is
    # the case the local re-check exists for.
    payload = {"base_url": "https://sample.test/", "results": [
        {"url": "https://sample.test/about", "raw_content": _MD},
        {"url": "https://evil.example/pwned", "raw_content": "# Evil\n\nSECRETMARKER here.\n"},
    ], "usage": {}}
    tavily_client.requests.post = _tav_stub(lambda u, b: payload, seen)
    try:
        res = site_rag.crawl_and_index("sample.test", use_llm=False, max_pages=6)
        check("the in-scope page was kept", res["pages_crawled"] == 1,
              str(res["pages_crawled"]))
        check("the off-domain page was REFUSED", res["pages_refused"] == 1,
              str(res["pages_refused"]))
        check("refusal is not counted as a fetch failure", res["pages_failed"] == 0,
              str(res["pages_failed"]))
        check("the off-domain URL is named in the sample",
              any("evil.example" in u for u in res["refused_sample"]),
              str(res["refused_sample"]))
    finally:
        tavily_client.requests.post = real
        _tav_restore(prev)


def test_tavily_unconfigured_fails_closed():
    section("Tavily selected with no key fails CLOSED")
    prev, seen = _tav_env(1, key=None), []
    real_t, real_g = tavily_client.requests.post, site_rag.requests.get
    tavily_client.requests.post = _tav_stub(lambda u, b: {}, seen)
    gets = []
    site_rag.requests.get = lambda url, **kw: (gets.append(url), FakeResponse("", 200, url=url))[1]
    try:
        res = site_rag.crawl_and_index("sample.test", use_llm=False)
        check("empty_kind is site_backend_unconfigured",
              res["empty_kind"] == site_rag.SITE_BACKEND_UNCONFIGURED, res["empty_kind"])
        check("NO request was made to Tavily", not seen, str(seen))
        check("and NO fallback request was made to the target", not gets, str(gets))
        check("the message says it did not fall back",
              "NOT crawled with the built-in" in " ".join(res["errors"]),
              str(res["errors"])[:120])
    finally:
        tavily_client.requests.post = real_t
        site_rag.requests.get = real_g
        _tav_restore(prev)


def test_tavily_provider_failure_is_not_a_finding():
    section("a Tavily failure says nothing about the target")
    prev, seen = _tav_env(2), []
    real = tavily_client.requests.post

    def boom(url, **kw):
        seen.append(url)
        return _TavR({"detail": "rate limited"}, status=429)

    tavily_client.requests.post = boom
    try:
        res = site_rag.crawl_and_index("sample.test", use_llm=False)
        check("empty_kind is site_provider_failed",
              res["empty_kind"] == site_rag.SITE_PROVIDER_FAILED, res["empty_kind"])
        check("NOT reported as blocked", res["blocked"] is False)
        check("NOT reported as unreachable", res["unreachable"] is False)
        check("the message says the target was never contacted",
              "NEVER CONTACTED" in res["empty_message"], res["empty_message"][:90])
        check("the egress is not described as the campaign proxy",
              "campaign proxy" not in res["empty_message"])
    finally:
        tavily_client.requests.post = real
        _tav_restore(prev)


def test_tavily_failed_results_classified():
    section("failed_results classification")
    prev, seen = _tav_env(2), []
    real = tavily_client.requests.post
    payload = {"base_url": "https://sample.test/", "results": [
        {"url": "https://sample.test/about", "raw_content": _MD}],
        "failed_results": [
            {"url": "https://sample.test/a", "error": "403 Forbidden"},
            {"url": "https://sample.test/b", "error": "request timed out"},
            {"url": "https://sample.test/c", "error": "something nobody has seen"},
        ], "usage": {}}
    tavily_client.requests.post = _tav_stub(lambda u, b: payload, seen)
    try:
        res = site_rag.crawl_and_index("sample.test", use_llm=False, max_pages=6)
        check("all three failures are counted", res["pages_failed"] == 3,
              str(res["pages_failed"]))
        check("per-URL detail is preserved for the operator",
              any("403" in f["error"] for f in res["failed_sample"]),
              str(res["failed_sample"]))
        check("failures did NOT inflate pages_refused", res["pages_refused"] == 0,
              str(res["pages_refused"]))
        check("a successful page keeps blocked False", res["blocked"] is False)
        check("an unrecognised error incremented neither counter",
              res["pages_failed"] == 3 and res["pages_crawled"] == 1)
    finally:
        tavily_client.requests.post = real
        _tav_restore(prev)


def test_tavily_markdown_and_jsonld_gap():
    section("markdown pages, and the JSON-LD gap is reported")
    prev, seen = _tav_env(2), []
    real = tavily_client.requests.post
    payload = {"base_url": "https://sample.test/", "results": [
        {"url": "https://sample.test/leadership", "raw_content": _MD}], "usage": {}}
    tavily_client.requests.post = _tav_stub(lambda u, b: payload, seen)
    try:
        res = site_rag.crawl_and_index("sample.test", use_llm=False, max_pages=6)
        check("the markdown page became a crawled page", res["pages_crawled"] == 1)
        check("backend is recorded on the result", res["backend"] == 2, str(res["backend"]))
        check("backend_label is human-readable",
              res["backend_label"] == "tavily-crawl", res["backend_label"])
        check("the JSON-LD gap is REPORTED, not absorbed",
              any("application/ld+json" in e for e in res["errors"]),
              str(res["errors"])[:140])
        check("no structured profile was invented with use_llm=False",
              not res["profile"], str(res["profile"]))
    finally:
        tavily_client.requests.post = real
        _tav_restore(prev)


def test_tavily_map_extract_uses_our_ranking():
    section("mode 1 ranks URLs with score_url(), not Tavily's order")
    prev, seen = _tav_env(1), []
    real = tavily_client.requests.post

    def router(url, body):
        if url.endswith("/map"):
            # Deliberately worst-first, plus one off-domain URL.
            return {"results": ["https://sample.test/blog/post-1",
                                "https://sample.test/leadership",
                                "https://evil.example/x"]}
        return {"results": [{"url": u, "raw_content": _MD} for u in body.get("urls", [])],
                "failed_results": []}

    tavily_client.requests.post = _tav_stub(router, seen)
    try:
        res = site_rag.crawl_and_index("sample.test", use_llm=False, max_pages=1)
        extract = [s for s in seen if s["url"].endswith("/extract")]
        check("an /extract call followed the /map call", bool(extract))
        picked = extract[0]["payload"]["urls"] if extract else []
        check("the highest-scoring path was chosen, not the first returned",
              picked == ["https://sample.test/leadership"], str(picked))
        check("the off-domain URL never reached /extract",
              not any("evil.example" in u for u in picked), str(picked))
        check("and was counted as refused", res["pages_refused"] >= 1,
              str(res["pages_refused"]))
    finally:
        tavily_client.requests.post = real
        _tav_restore(prev)


def test_extract_urls_offdomain_gate():
    section("extract_urls: the one path that may leave the domain")
    prev, seen = _tav_env(0), []
    real = tavily_client.requests.post
    tavily_client.requests.post = _tav_stub(
        lambda u, b: {"results": [{"url": x, "raw_content": _MD}
                                  for x in b.get("urls", [])],
                      "failed_results": []}, seen)
    try:
        # Default: off-domain is REFUSED, and in_scope() is untouched.
        res = site_rag.extract_urls(
            ["https://sample.test/about", "https://press.example/story"],
            base_domain="sample.test", indexer=_NullIndexer())
        sent = [u for s_ in seen for u in s_["payload"].get("urls", [])]
        check("the on-domain URL was read", "https://sample.test/about" in sent, str(sent))
        check("the off-domain URL was refused by default",
              not any("press.example" in u for u in sent), str(sent))
        check("and the refusal is explained",
              any("allow_off_domain" in e for e in res["errors"]),
              str(res["errors"])[:110])
        check("in_scope() itself is unchanged",
              site_rag.in_scope("https://press.example/story", "sample.test") is False)

        # Explicit opt-in, per call.
        seen.clear()
        res2 = site_rag.extract_urls(
            ["https://press.example/story"], base_domain="sample.test",
            allow_off_domain=True, indexer=_NullIndexer())
        sent2 = [u for s_ in seen for u in s_["payload"].get("urls", [])]
        check("with allow_off_domain it is read", bool(sent2), str(sent2))
        check("and counted as off-domain", res2["off_domain"] == 1, str(res2["off_domain"]))

        # LinkedIn stays refused regardless of the opt-in.
        seen.clear()
        res3 = site_rag.extract_urls(
            ["https://uk.linkedin.com/in/x"], base_domain="sample.test",
            allow_off_domain=True, indexer=_NullIndexer())
        sent3 = [u for s_ in seen for u in s_["payload"].get("urls", [])]
        check("linkedin is refused even with allow_off_domain",
              not any("linkedin" in u for u in sent3), str(sent3))
        check("and never reaches a page", res3["urls_read"] == 0, str(res3["urls_read"]))
    finally:
        tavily_client.requests.post = real
        _tav_restore(prev)


def test_extract_urls_needs_a_key():
    section("extract_urls without a key")
    prev, seen = _tav_env(0, key=None), []
    real = tavily_client.requests.post
    tavily_client.requests.post = _tav_stub(lambda u, b: {}, seen)
    try:
        res = site_rag.extract_urls(["https://sample.test/about"],
                                    base_domain="sample.test", indexer=_NullIndexer())
        check("it refuses rather than raising", res["matched"] is False)
        check("names TAVILY_API_KEY",
              any("TAVILY_API_KEY" in e for e in res["errors"]), str(res["errors"]))
        check("and issues no request", not seen, str(seen))
    finally:
        tavily_client.requests.post = real
        _tav_restore(prev)


class _NullIndexer:
    """Records what would be indexed without needing an embedder."""

    def __init__(self):
        self.docs = []

    def reset_collection(self, col):
        pass

    def index_documents(self, col, docs):
        self.docs.extend(docs)
        return len(docs)


def test_builtin_backend_is_unchanged():
    section("the default backend does not touch Tavily")
    seen = []
    real = tavily_client.requests.post
    tavily_client.requests.post = _tav_stub(lambda u, b: {}, seen)
    prev = os.environ.pop("SITE_TAVILY", None)
    try:
        res = site_rag.crawl_and_index("sample.test", use_llm=False, max_pages=2,
                                       delay_ms=0)
        check("backend reports builtin", res["backend"] == 0, str(res["backend"]))
        check("no Tavily request was made at all", not seen, str(seen))
    finally:
        tavily_client.requests.post = real
        if prev is not None:
            os.environ["SITE_TAVILY"] = prev


def main() -> int:
    for t in (
        test_scope_lock,
        test_scoring,
        test_discovery_and_crawl,
        test_extraction,
        test_chunking,
        test_index_and_retrieve,
        test_collection_name_cannot_escape,
        test_llm_names_must_be_verbatim,
        test_llm_failure_is_survivable,
        test_proxy_fails_closed,
        test_blocked_is_not_empty,
        test_unreachable_is_not_empty,
        test_preflight_short_circuits,
        test_disabled,
        test_tavily_scope_regex,
        test_tavily_payload_is_scope_locked,
        test_tavily_offdomain_result_is_dropped,
        test_tavily_unconfigured_fails_closed,
        test_tavily_provider_failure_is_not_a_finding,
        test_tavily_failed_results_classified,
        test_tavily_markdown_and_jsonld_gap,
        test_tavily_map_extract_uses_our_ranking,
        test_extract_urls_offdomain_gate,
        test_extract_urls_needs_a_key,
        test_builtin_backend_is_unchanged,
    ):
        t()
    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("all site_rag checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
