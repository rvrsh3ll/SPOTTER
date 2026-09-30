#!/usr/bin/env python3
"""
Smoke tests for SPOTTER technology contextualization.

Validates:
  - nmap XML produces Service and Technology nodes
  - Amass text produces DNSRecord nodes
  - CVE client can format a keyword query (does not require network by default)
  - MITRE client can load or refresh the STIX bundle
  - TechContextEngine computes composite risk correctly
  - RAG indexer can build a minimal index

Usage:
  python3 scripts/smoke_tech_context.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from upload_router import _parse_nmap, _parse_amass
from tech_context_engine import TechContextEngine


def test_nmap_service_nodes() -> bool:
    xml = b'''<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="web01.lab.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41" cpe="cpe:/a:apache:http_server:2.4.41"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
    </ports>
  </host>
</nmaprun>
'''
    nodes, edges = _parse_nmap(xml)
    services = [n for n in nodes if n["entity_type"] == "Service"]
    techs = [n for n in nodes if n["entity_type"] == "Technology"]
    assert len(services) == 2, f"expected 2 services, got {len(services)}"
    assert len(techs) == 2, f"expected 2 technologies, got {len(techs)}"
    assert any(e["label"] == "EXPOSES_SERVICE" for e in edges)
    assert any(e["label"] == "IMPLEMENTED_IN" for e in edges)
    print("✓ nmap parser creates Service and Technology nodes")
    return True


def test_amass_dns_records() -> bool:
    data = b"""sub.lab.local --> 192.168.1.20
www.lab.local --> cdn.example.com
mail.lab.local --> 192.168.1.21
"""
    nodes, edges = _parse_amass(data)
    records = [n for n in nodes if n["entity_type"] == "DNSRecord"]
    assert len(records) == 3, f"expected 3 DNS records, got {len(records)}"
    assert any(r["data"]["record_type"] == "A" for r in records)
    assert any(r["data"]["record_type"] == "CNAME" for r in records)
    assert any(e["label"] == "HAS_RECORD" for e in edges)
    print("✓ Amass parser creates DNSRecord nodes")
    return True


def test_composite_risk() -> bool:
    engine = TechContextEngine()
    result = engine.compute_composite_risk(
        ad_max_score=15,
        breach_count=2,
        has_stealer_log=True,
        os_risk="critical",
        tech_stack=["KeePass Password Manager", "SAP GUI"],
        cve_exposure=3,
    )
    assert result["composite_score"] > 0
    assert result["risk_tier"] == "critical"
    assert "KeePass Password Manager" in result["high_value_tech"]
    print(f"✓ Composite risk computed: {result['composite_score']} ({result['risk_tier']})")
    return True


def test_rag_index_build() -> bool:
    # No scikit-learn guard any more: rag_indexer ships a pure-Python TF-IDF
    # fallback, because the n8n runner is Alpine/musl where scikit-learn cannot
    # be installed — and that container is the one that builds this index.
    from rag_indexer import RAGIndexer, SimpleEmbeddingFunction
    # Pin the fallback explicitly. These tests are about the persisted-model and
    # rebuild logic, not about backend selection, and RAGIndexer() with no
    # embedding_fn reads process env — so the moment anyone runs this smoke from
    # a shell that has sourced .env with VLLM_EMBEDDING_MODE=remote, they would
    # hit the network and these assertions would flip for the wrong reason.
    indexer = RAGIndexer(embedding_fn=SimpleEmbeddingFunction())

    guides = {"KeePass memory dump": "Dump master password from memory."}
    # index_guides is idempotent: it skips ids already present and returns the
    # number NEWLY added. Asserting >= 1 only held while the index was empty,
    # which it no longer is once WF14 has run. Assert the guide is RETRIEVABLE,
    # which is the property that actually matters.
    indexer.index_guides(guides)

    results = indexer.query("tech_guides", "KeePass", n_results=3)
    assert results, "tech_guides query returned nothing"

    # The query must be projected into the collection's own vector space. When it
    # was embedded standalone, a one-word query produced a 1-dimensional vector,
    # _cosine_similarity's zip() truncated to it, and the KeePass guide ranked
    # LAST at 0.0000 behind an unrelated TN3270 entry. Ranking, not mere
    # retrieval, is what regressed silently.
    top = results[0]
    assert "keepass" in top["document"].lower(), (
        f"KeePass query ranked the wrong document first: {top['document'][:80]!r} "
        f"(score {top['score']})"
    )
    assert top["score"] > 0, "top hit scored 0 — query/document vector space mismatch"
    print(f"✓ RAG index builds, queries, and RANKS correctly (top score {top['score']})")
    return True


def test_rag_query_uses_persisted_model() -> bool:
    from rag_indexer import RAGIndexer, SimpleEmbeddingFunction

    with tempfile.TemporaryDirectory() as tmp:
        # Pin the fallback explicitly. These tests are about the persisted-model and
        # rebuild logic, not about backend selection, and RAGIndexer() with no
        # embedding_fn reads process env — so the moment anyone runs this smoke from
        # a shell that has sourced .env with VLLM_EMBEDDING_MODE=remote, they would
        # hit the network and these assertions would flip for the wrong reason.
        indexer = RAGIndexer(cache_dir=tmp, embedding_fn=SimpleEmbeddingFunction())
        indexer.index_guides({
            "KeePass memory dump": "Dump KeePass master password from memory.",
            "TN3270 session handling": "Capture terminal session metadata.",
        })

        collection_path = Path(tmp) / "rag_index" / "tech_guides.json"
        collection = json.loads(collection_path.read_text())
        assert collection.get("embedding_model", {}).get("kind") == "simple_tfidf"
        assert collection.get("embedding_model", {}).get("doc_count") == 2
        assert "_embedding_dirty" not in collection

        # Same reason as above: the SECOND indexer is the one under test here, so it
        # must not pick a remote backend out of the caller's environment either.
        query_indexer = RAGIndexer(cache_dir=tmp, embedding_fn=SimpleEmbeddingFunction())

        def fail_fit(_texts):
            raise AssertionError("query refit the whole corpus instead of loading the saved model")

        query_indexer.embedding_fn.fit = fail_fit  # type: ignore[assignment]
        results = query_indexer.query("tech_guides", "KeePass", n_results=1)
        assert results and "keepass" in results[0]["document"].lower()
        print("✓ RAG query uses persisted TF-IDF model instead of refitting")
        return True


def test_openai_embedding_response_shape() -> bool:
    import rag_indexer
    from rag_indexer import OpenAIEmbeddingFunction

    real_requests = rag_indexer.requests
    calls = []

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"data": [
                {"index": 0, "embedding": [1.0, 0.0]},
                {"index": 1, "embedding": [0.0, 1.0]},
            ]}

    class FakeRequests:
        @staticmethod
        def post(url, headers, json, timeout):
            calls.append((url, headers, json, timeout))
            return FakeResponse()

    rag_indexer.requests = FakeRequests  # type: ignore[attr-defined]
    try:
        embeddings = OpenAIEmbeddingFunction(
            "http://vllm:8000/v1", "nomic-embed-text", "smoke-key"
        )(["alpha", "beta"])
    finally:
        rag_indexer.requests = real_requests  # type: ignore[attr-defined]

    assert embeddings == [[1.0, 0.0], [0.0, 1.0]]
    assert calls[0][0] == "http://vllm:8000/v1/embeddings"
    assert calls[0][1]["Authorization"] == "Bearer smoke-key"
    assert calls[0][2] == {"model": "nomic-embed-text", "input": ["alpha", "beta"]}
    print("✓ OpenAI-compatible embeddings parse vLLM response shape")
    return True


def test_rag_rebuilds_when_embedding_backend_changes() -> bool:
    from rag_indexer import RAGIndexer, SimpleEmbeddingFunction

    class FakeAltEmbedding:
        def __init__(self):
            self.calls = 0

        def export_model(self):
            return {"kind": "fake_alt", "model": "unit-test"}

        def __call__(self, texts):
            self.calls += 1
            if len(texts) == 1:
                return [[1.0, 0.0]]
            return [[1.0, 0.0] for _ in texts]

    with tempfile.TemporaryDirectory() as tmp:
        # Pin the fallback explicitly. These tests are about the persisted-model and
        # rebuild logic, not about backend selection, and RAGIndexer() with no
        # embedding_fn reads process env — so the moment anyone runs this smoke from
        # a shell that has sourced .env with VLLM_EMBEDDING_MODE=remote, they would
        # hit the network and these assertions would flip for the wrong reason.
        indexer = RAGIndexer(cache_dir=tmp, embedding_fn=SimpleEmbeddingFunction())
        indexer.index_guides({"KeePass memory dump": "Dump KeePass master password from memory."})

        collection_path = Path(tmp) / "rag_index" / "tech_guides.json"
        collection = json.loads(collection_path.read_text())
        assert collection.get("embedding_model", {}).get("kind") == "simple_tfidf"

        embedding_fn = FakeAltEmbedding()
        query_indexer = RAGIndexer(cache_dir=tmp, embedding_fn=embedding_fn)
        results = query_indexer.query("tech_guides", "KeePass", n_results=1)

        assert results and results[0]["metadata"]["title"] == "KeePass memory dump"
        collection = json.loads(collection_path.read_text())
        assert collection.get("embedding_model", {}).get("kind") == "fake_alt"
        assert embedding_fn.calls == 2
        print("✓ RAG rebuilds stale collections when embedding backend changes")
        return True


def test_nvd_lookup_status_reports_rate_limit() -> bool:
    from tech_enricher import nvd_lookup_status

    no_key = nvd_lookup_status("")
    assert no_key["provider"] == "nvd"
    assert no_key["api_key_configured"] is False
    assert no_key["min_interval_seconds"] == 6.0
    assert "NVD_API_KEY" in no_key.get("caveat", "")

    with_key = nvd_lookup_status("configured")
    assert with_key["api_key_configured"] is True
    assert with_key["min_interval_seconds"] == 0.6
    assert "caveat" not in with_key
    print("✓ WF14 summaries report NVD API-key/rate-limit status")
    return True


def test_embedding_backend_selection() -> bool:
    """The remote path is an AND gate, and getting that wrong is not theoretical.

    issues.md carried a 'fixed' claim for weeks that prescribed setting
    EMBEDDING_URL alone — which lands here, on TF-IDF, silently. Pin all four
    corners so the next person who edits __init__ finds out immediately.
    """
    import os
    import rag_indexer
    from rag_indexer import RAGIndexer, SimpleEmbeddingFunction, OpenAIEmbeddingFunction

    cases = [
        ({"VLLM_EMBEDDING_MODE": "remote", "EMBEDDING_URL": "http://e:8000/v1"}, OpenAIEmbeddingFunction),
        ({"VLLM_EMBEDDING_MODE": "tfidf",  "EMBEDDING_URL": "http://e:8000/v1"}, SimpleEmbeddingFunction),
        ({"VLLM_EMBEDDING_MODE": "remote", "EMBEDDING_URL": ""},                 SimpleEmbeddingFunction),
        ({},                                                                      SimpleEmbeddingFunction),
    ]
    saved = {k: os.environ.get(k) for k in ("VLLM_EMBEDDING_MODE", "EMBEDDING_URL", "EMBEDDING_MODEL")}
    try:
        for env, expected in cases:
            for k in saved:
                os.environ.pop(k, None)
            os.environ.update(env)
            with tempfile.TemporaryDirectory() as tmp:
                got = type(RAGIndexer(cache_dir=tmp).embedding_fn)
            assert got is expected, f"env {env} selected {got.__name__}, expected {expected.__name__}"
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    # The backend identity must not carry the URL: the runner and the host reach
    # the same server by different names, and including it would make each one
    # rebuild every collection to "correct" the other.
    ident = OpenAIEmbeddingFunction("http://vllm-embed:8000/v1", "m").export_model()
    assert "url" not in ident, f"export_model still carries the URL: {ident}"
    assert OpenAIEmbeddingFunction("http://127.0.0.1:8100/v1", "m").export_model() == ident, \
        "the same model reached by two URLs must be ONE backend identity"

    print("✓ Embedding backend selection is an AND gate; identity excludes the URL")
    return True


def test_openai_embeddings_batch_and_truncate() -> bool:
    """One request per collection is what the old code did; mitre_index is ~300k
    tokens and poc_index holds a single 64 KB document. Both are refused by any
    backend with a context limit, and the failure surfaces far from the cause."""
    import rag_indexer
    from rag_indexer import OpenAIEmbeddingFunction

    calls = []

    class _Resp:
        def __init__(self, n): self._n = n
        def raise_for_status(self): pass
        def json(self): return {"data": [{"embedding": [0.123456789, 1.0]} for _ in range(self._n)]}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(json["input"])
        return _Resp(len(json["input"]))

    orig = rag_indexer.requests.post
    rag_indexer.requests.post = fake_post
    try:
        fn = OpenAIEmbeddingFunction("http://e:8000/v1", "m")
        out = fn(["doc-%d" % i for i in range(100)])
        assert len(calls) == 4, f"100 docs at batch 32 should be 4 requests, got {len(calls)}"
        assert [len(c) for c in calls] == [32, 32, 32, 4], [len(c) for c in calls]
        assert len(out) == 100, f"results must concatenate in order, got {len(out)}"
        assert out[0] == [0.123457, 1.0], f"vectors are rounded to 6dp, got {out[0]}"

        calls.clear()
        long_doc = "x" * 100000
        fn([long_doc])
        sent = calls[0][0]
        assert len(sent) == rag_indexer._EMBED_MAX_CHARS, \
            f"oversize document not truncated client-side: {len(sent)}"
    finally:
        rag_indexer.requests.post = orig

    print("✓ OpenAI-compatible embeddings batch, truncate and round")
    return True


def main() -> int:
    tests = [
        test_nmap_service_nodes,
        test_amass_dns_records,
        test_composite_risk,
        test_rag_index_build,
        test_rag_query_uses_persisted_model,
        test_openai_embedding_response_shape,
        test_rag_rebuilds_when_embedding_backend_changes,
        test_embedding_backend_selection,
        test_openai_embeddings_batch_and_truncate,
        test_nvd_lookup_status_reports_rate_limit,
    ]
    failed = 0
    for test in tests:
        try:
            if not test():
                failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} failed: {e}")
            failed += 1

    if failed:
        print(f"\n{failed} tech-context smoke test(s) failed")
        return 1
    print("\nAll tech-context smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
