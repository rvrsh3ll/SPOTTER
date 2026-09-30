#!/usr/bin/env python3
"""
Smoke tests for the PoC-in-GitHub exploit-availability source.

Covers scripts/poc_client.py and the pieces of the enrichment chain that read it:
CPE normalisation (scripts/cve_client.py) and the match-confidence label
(scripts/tech_enricher.py).

Everything here is OFFLINE except the two tests marked `[network]`, which are
skipped automatically when the mirror has not been synced. Run:

    python3 scripts/sync_poc_mirror.py     # once, ~4s, 62 MB
    python3 scripts/smoke_poc_client.py

Exit 0 = pass, 1 = a failure, 2 = mirror missing so the corpus tests could not run.

What it deliberately asserts
----------------------------
The `unvetted` flag and warning string on EVERY record. That flag is the only
thing standing between an operator and treating a stranger's repository as
vetted tooling, and it is carried through four layers (poc_client -> engine ->
WF12/WF14 -> frontend/LLM). A regression anywhere in that chain is silent.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from cve_client import CVEClient          # noqa: E402
from poc_client import (                  # noqa: E402
    UNVETTED_WARNING, PoCClient, normalise_cve, score_repo, shape_repo,
)
from tech_enricher import _match_basis, _node_targets  # noqa: E402

FAILURES: list = []
CHECKS = 0


def ok(cond, label, extra=None):
    global CHECKS
    CHECKS += 1
    if cond:
        print(f"  ok    {label}")
        return True
    FAILURES.append(label)
    print(f"  FAIL  {label}" + (f"\n        got: {extra}" if extra is not None else ""))
    return False


def test_cve_normalisation():
    print("CVE id normalisation")
    ok(normalise_cve("CVE-2021-44228") == "CVE-2021-44228", "canonical id passes through")
    ok(normalise_cve("  cve-2021-44228 ") == "CVE-2021-44228", "lowercase + whitespace normalised")
    ok(normalise_cve("CVE-2021-1") is None, "too-short sequence rejected")
    for bad in ("", None, "not-a-cve", "CVE-21-44228", "'; DROP TABLE repos;--"):
        if normalise_cve(bad) is not None:
            ok(False, f"malformed input rejected: {bad!r}", normalise_cve(bad))
            return
    ok(True, "malformed and injection-shaped inputs all rejected")


def test_scoring():
    print("\nTrust scoring")
    strong = {"stargazers_count": 400, "forks_count": 40, "subscribers_count": 12,
              "fork": False, "description": "Working proof of concept exploit for the vulnerability, with usage notes",
              "created_at": "2021-12-11T00:00:00Z"}
    stub = {"stargazers_count": 0, "forks_count": 0, "subscribers_count": 0,
            "fork": False, "description": "", "created_at": "2024-01-01T00:00:00Z"}
    deadfork = {"stargazers_count": 0, "forks_count": 0, "subscribers_count": 0,
                "fork": True, "description": "", "created_at": "2024-01-01T00:00:00Z"}

    s_strong = score_repo(strong, "CVE-2021-44228", owner_poc_count=5)
    s_stub = score_repo(stub, "CVE-2021-44228")
    s_fork = score_repo(deadfork, "CVE-2021-44228")

    ok(s_strong["trust"] == "high", "a starred, described, timely non-fork is high trust", s_strong)
    ok(s_stub["trust"] == "low", "an empty stub is low trust", s_stub)
    ok(s_fork["score"] < s_stub["score"], "a dead fork scores below an empty stub",
       (s_fork["score"], s_stub["score"]))
    ok(s_strong["score"] > s_stub["score"], "strong outranks stub")
    ok(any("stars" in s for s in s_strong["signals"]), "signals explain the score", s_strong["signals"])

    # Timeliness must key off the CVE year, not "recent".
    late = dict(strong, created_at="2026-01-01T00:00:00Z")
    ok(score_repo(late, "CVE-2021-44228")["score"] < s_strong["score"],
       "a PoC published years after the CVE scores lower")

    # Ranking must not be perturbed by a missing/garbage timestamp.
    broken = dict(strong, created_at=None, pushed_at="not-a-date")
    try:
        score_repo(broken, "CVE-2021-44228")
        ok(True, "a malformed timestamp does not raise")
    except Exception as exc:
        ok(False, "a malformed timestamp does not raise", repr(exc))


def test_unvetted_contract():
    print("\nUnvetted contract (the flag four layers depend on)")
    rec = shape_repo({"full_name": "a/b", "html_url": "https://github.com/a/b",
                      "stargazers_count": 5, "owner": {"login": "a"}}, "CVE-2021-44228")
    ok(rec["unvetted"] is True, "every shaped record is flagged unvetted")
    ok(rec["warning"] == UNVETTED_WARNING, "every shaped record carries the warning string")
    _w = UNVETTED_WARNING.lower()
    ok("unvetted" in _w and "read the source" in _w and "never" in _w,
       "the warning states it is unvetted, what to do first, and what not to do",
       UNVETTED_WARNING)
    ok(rec["trust"] in ("high", "medium", "low"), "every record carries a trust tier", rec["trust"])


def test_degradation():
    print("\nDegradation with no mirror (must never raise)")
    client = PoCClient(cache_dir="/nonexistent", mirror_dir="/nonexistent/poc")
    ok(client.pocs_for_cve("CVE-2021-44228") == [], "lookup returns [] rather than raising")
    ok(client.search("apache") == [], "keyword search returns [] without an index")
    ok(client.has_poc("CVE-2021-44228") is False, "has_poc is False")
    st = client.mirror_status()
    ok(st["available"] is False, "status reports unavailable")
    ok(st["stale"] is True, "a missing mirror reports STALE, so absence is not read as a negative")
    summary = client.summarise_for_cves(["CVE-2021-44228"])
    ok(summary["exploit_available"] is False and summary["poc_count"] == 0,
       "summary degrades to no-exploit-found")


def test_cpe_normalisation():
    print("\nCPE normalisation (CVE match precision)")
    cases = [
        ("cpe:/a:apache:http_server", "cpe:2.3:a:apache:http_server"),
        ("cpe:/a:apache:http_server:2.4.41", "cpe:2.3:a:apache:http_server:2.4.41"),
        ("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", "cpe:2.3:a:nginx:nginx:1.18.0"),
        ("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "cpe:2.3:a:apache:http_server"),
        ("cpe:/a:apache", None),
        ("cpe:2.3:a:*:*", None),
        ("", None),
        ("garbage", None),
    ]
    bad = [(raw, exp, CVEClient.cpe23_prefix(raw))
           for raw, exp in cases if CVEClient.cpe23_prefix(raw) != exp]
    ok(not bad, "every CPE spelling normalises to the expected 2.3 prefix", bad)


def test_node_targets():
    print("\nEnrichment target selection")
    svc = {"product": "", "cpes": '["cpe:/a:apache:http_server"]',
           "vulns": '["CVE-2021-44228", "bogus", "CVE-2021-41773"]', "version": ""}
    t = _node_targets(svc, "203.0.113.25 (2 ports)")
    ok(t["known_cves"] == ["CVE-2021-41773", "CVE-2021-44228"],
       "Shodan vulns are parsed, canonicalised and de-junked", t["known_cves"])
    ok(t["name"] == "apache http server", "a CPE degrades to a usable keyword", t["name"])

    empty = {"product": "", "cpes": "[]", "vulns": "[]", "version": ""}
    t2 = _node_targets(empty, "198.51.100.27 (1 ports)")
    ok(t2["name"] is None and not t2["known_cves"],
       "an IP-labelled node with nothing usable yields no search term "
       "(so it cannot burn NVD quota)", t2)

    named = {"name": "KeePass Password Manager", "version": "2.50"}
    ok(_node_targets(named, "KeePass")["name"] == "KeePass Password Manager",
       "a real product name is used as-is")


def test_cve_proxy():
    print("\nNVD proxy routing")
    import cve_client

    calls = []
    real_get = cve_client.requests.get
    real_sleep = cve_client.time.sleep
    old_env = {k: os.environ.get(k) for k in ("NVD_PROXY_URL", "BUCKET_PROBE_PROXY")}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"vulnerabilities": []}

    def fake_get(url, **kwargs):
        calls.append({"url": url, "kwargs": kwargs})
        return FakeResponse()

    cve_client.requests.get = fake_get
    cve_client.time.sleep = lambda _seconds: None
    try:
        with tempfile.TemporaryDirectory() as td:
            client = CVEClient(cache_dir=td, proxy_url="socks5h://proxy.local:1080")
            client.search_by_keyword("Apache httpd", limit=1)
        os.environ.pop("NVD_PROXY_URL", None)
        os.environ["BUCKET_PROBE_PROXY"] = "socks5h://bucket-proxy.local:1080"
        with tempfile.TemporaryDirectory() as td:
            client = CVEClient(cache_dir=td)
            client.search_by_keyword("nginx", limit=1)
        os.environ["NVD_PROXY_URL"] = "socks5h://nvd-proxy.local:1080"
        with tempfile.TemporaryDirectory() as td:
            client = CVEClient(cache_dir=td)
            client.search_by_keyword("openssl", limit=1)
    finally:
        cve_client.requests.get = real_get
        cve_client.time.sleep = real_sleep
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    by_keyword = {
        c["kwargs"].get("params", {}).get("keywordSearch"): c["kwargs"].get("proxies")
        for c in calls
    }
    ok(by_keyword.get("Apache httpd") == {
        "http": "socks5h://proxy.local:1080",
        "https": "socks5h://proxy.local:1080",
    }, "NVD lookups pass the configured proxy to requests", calls)
    ok(by_keyword.get("nginx") == {
        "http": "socks5h://bucket-proxy.local:1080",
        "https": "socks5h://bucket-proxy.local:1080",
    }, "NVD lookups fall back to BUCKET_PROBE_PROXY", calls)
    ok(by_keyword.get("openssl") == {
        "http": "socks5h://nvd-proxy.local:1080",
        "https": "socks5h://nvd-proxy.local:1080",
    }, "NVD_PROXY_URL overrides the bucket-proxy fallback", calls)


def test_match_basis():
    print("\nMatch-confidence labelling")
    ok(_match_basis([{"discovered_by": "cpe"}] * 2) == "cpe", "uniform cpe -> cpe")
    ok(_match_basis([{"discovered_by": "shodan"}]) == "shodan", "uniform shodan -> shodan")
    ok(_match_basis([{}]) == "keyword", "unlabelled defaults to the WEAK label, not the strong one")
    ok(_match_basis([{"discovered_by": "shodan"}, {}]) == "mixed", "heterogeneous -> mixed")
    ok(_match_basis([]) == "none", "empty -> none")


def test_corpus(client: PoCClient):
    print("\n[network] Against the synced mirror")
    st = client.mirror_status()
    ok(st["available"] and (st["cve_count"] or 0) > 1000,
       f"mirror holds {st.get('cve_count')} CVEs / {st.get('repo_count')} repos")
    ok(st["stale"] is False, "a freshly synced mirror is not stale", st.get("age_days"))

    hits = client.pocs_for_cve("CVE-2021-44228")
    ok(len(hits) > 0, "Log4Shell resolves to PoC repositories", len(hits))
    ok(all(h["unvetted"] for h in hits), "every returned record is flagged unvetted")
    scores = [h["trust_score"] for h in hits]
    ok(scores == sorted(scores, reverse=True), "results are ranked best-first", scores[:5])
    ok(hits[0]["trust"] == "high", "the top Log4Shell repo is high trust", hits[0]["trust"])

    ok(client.pocs_for_cve("CVE-1999-0001") == [],
       "a CVE with no public PoC returns empty, not an error")

    cap = client.pocs_for_cve("CVE-2021-44228", limit=3)
    ok(len(cap) == 3, "limit is honoured", len(cap))
    starred = client.pocs_for_cve("CVE-2021-44228", min_stars=50)
    ok(all(h["stars"] >= 50 for h in starred), "min_stars filter is honoured")

    found = client.search("log4j", limit=5)
    ok(len(found) > 0 and all(f["unvetted"] for f in found),
       "keyword search works and preserves the unvetted flag", len(found))

    s = client.summarise_for_cves(["CVE-2021-44228", "CVE-1999-0001"])
    ok(s["exploit_available"] and s["cves_with_pocs"] == ["CVE-2021-44228"],
       "summarise reports only CVEs that actually have PoCs", s["cves_with_pocs"])


def main() -> int:
    test_cve_normalisation()
    test_scoring()
    test_unvetted_contract()
    test_degradation()
    test_cpe_normalisation()
    test_node_targets()
    test_cve_proxy()
    test_match_basis()

    client = PoCClient()
    if client.available():
        test_corpus(client)
    else:
        print("\n[network] SKIPPED — mirror not synced.")
        print("          python3 scripts/sync_poc_mirror.py")
        print(f"\n{CHECKS - len(FAILURES)}/{CHECKS} offline checks passed; corpus tests skipped")
        return 2

    print(f"\n{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
    if FAILURES:
        print("FAILED:")
        for f in FAILURES:
            print("  -", f)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
