"""
company_site_tool.py — Open WebUI Tool

Answers free-form questions about the target ORGANIZATION from its own website,
with a citation back to the page each answer came from.

Install:
  Open WebUI → Admin → Tools → + New Tool → paste this file → Save
  (or run scripts/setup_openwebui.py, which installs every SPOTTER tool)

Requires:
  - scripts/rag_indexer.py
  - scripts/site_rag.py
  - a crawl already performed by WF13's `org` source, which writes the
    per-campaign collection this reads

WHERE THE CORPUS COMES FROM
---------------------------
Live Analysis → DOMAIN RECON ▾ → Enrich Organization crawls the target's own
site, chunks it and indexes it into `company_site__<sketch_id>`. Until that has
run for a campaign, this tool has nothing to answer from and says so — it does
NOT fall back to another campaign's corpus, because one client's website has
nothing to say about another's and a confident answer sourced from the wrong
company is worse than no answer.

WHY CITATIONS ARE MANDATORY
---------------------------
Every passage returned carries the URL it came from. Pass them through to the
operator verbatim. A claim about a client's leadership, offices or technology
that cannot be traced back to a page is not usable in a report, and this corpus
is scraped marketing prose — it is what the company SAYS about itself, which is
not always what is true.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

import requests

# Matches the bootstrap in the other SPOTTER tools, so the module also imports
# when run on the host rather than only in the Open WebUI container where
# scripts/ is mounted at /data/scripts.
for _scripts_dir in (
    os.environ.get("SPOTTER_SCRIPTS_DIR", "/data/scripts"),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts")),
):
    if _scripts_dir and os.path.isdir(_scripts_dir) and _scripts_dir not in sys.path:
        sys.path.insert(0, _scripts_dir)


class Tools:
    def __init__(self):
        self.sketch_id = os.environ.get("FLOWSINT_SKETCH_ID", "")

    # ── helpers ──────────────────────────────────────────────────────────────

    def _neo(self, cypher: str, params: Dict[str, Any], timeout: int = 25) -> List[Dict[str, Any]]:
        url = os.environ.get("NEO4J_HTTP_URL", "http://neo4j:7474")
        user = os.environ.get("NEO4J_USER", "neo4j")
        pw = os.environ.get("NEO4J_PASSWORD", "")
        resp = requests.post(
            f"{url.rstrip('/')}/db/neo4j/tx/commit",
            auth=(user, pw), headers={"Content-Type": "application/json"},
            json={"statements": [{"statement": cypher, "parameters": params}]},
            timeout=timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("errors"):
            raise RuntimeError(str(body["errors"])[:200])
        res = body["results"][0]
        cols = res["columns"]
        return [dict(zip(cols, row["row"])) for row in res["data"]]

    def _resolve_sketch(self, explicit: Optional[str] = None) -> str:
        """Same precedence the other tools use: explicit, env, then busiest."""
        candidate = (explicit or self.sketch_id or "").strip()
        if candidate:
            return candidate
        try:
            rows = self._neo(
                "MATCH (n) WHERE n.sketch_id IS NOT NULL "
                "RETURN n.sketch_id AS sketch_id, count(n) AS nodes "
                "ORDER BY nodes DESC LIMIT 1", {})
            if rows:
                return str(rows[0]["sketch_id"])
        except Exception:
            pass
        return ""

    def _indexer(self):
        from rag_indexer import RAGIndexer
        return RAGIndexer()

    # ── tool methods ─────────────────────────────────────────────────────────

    def ask_company_website(self, question: str, sketch_id: str = "",
                            max_results: int = 5) -> str:
        """
        Answer a question about the target organization from its own website.

        Searches the pages SPOTTER crawled for this campaign and returns the
        most relevant passages, each with the URL it came from. Use this for
        questions about who the company is, who works there, where its offices
        are, what it sells, who its partners are, or what technology it names.

        :param question: A natural-language question about the company.
        :param sketch_id: Optional campaign sketch id; defaults to the active one.
        :param max_results: How many passages to return (1-10).
        """
        q = (question or "").strip()
        if not q:
            return json.dumps({"error": "question is required"})
        sk = self._resolve_sketch(sketch_id)
        if not sk:
            return json.dumps({"error": "no campaign sketch could be resolved"})
        try:
            n = max(1, min(int(max_results or 5), 10))
        except Exception:
            n = 5

        try:
            import site_rag
            hits = site_rag.ask_site(q, sk, n_results=n, indexer=self._indexer())
        except Exception as exc:                      # noqa: BLE001
            return json.dumps({"error": f"website corpus query failed: {exc!r}"})

        if not hits:
            return json.dumps({
                "question": q, "sketch_id": sk, "passages": [],
                # Say which of the two it is. "No results" reads as "the company
                # does not mention it" when it usually means "nobody has crawled
                # the site for this campaign yet".
                "note": "No indexed website content for this campaign. Run "
                        "Live Analysis > DOMAIN RECON > Enrich Organization to "
                        "crawl and index the target's site, then ask again. This "
                        "tool never reads another campaign's corpus.",
            })

        return json.dumps({
            "question": q,
            "sketch_id": sk,
            "passages": [{
                "text": h.get("text", ""),
                "source_url": h.get("url", ""),
                "page_title": h.get("page_title", ""),
                "heading": h.get("heading", ""),
                "score": h.get("score"),
            } for h in hits],
            "citation_required": (
                "Every statement drawn from these passages must cite its "
                "source_url. This is scraped marketing copy -- it is what the "
                "company says about itself, not verified fact."
            ),
        }, ensure_ascii=False)

    def get_company_site_status(self, sketch_id: str = "") -> str:
        """
        Report whether the target organization's website has been crawled and
        indexed for this campaign, and how much of it there is.

        :param sketch_id: Optional campaign sketch id; defaults to the active one.
        """
        sk = self._resolve_sketch(sketch_id)
        if not sk:
            return json.dumps({"error": "no campaign sketch could be resolved"})
        try:
            import site_rag
            ix = self._indexer()
            col = site_rag.collection_name(sk)
            data = ix._load_collection(col)           # noqa: SLF001 - read-only
            urls = sorted({(m or {}).get("url", "") for m in (data.get("metadatas") or [])})
            urls = [u for u in urls if u]
            return json.dumps({
                "sketch_id": sk,
                "collection": col,
                "indexed_chunks": len(data.get("ids") or []),
                "pages": len(urls),
                "sample_urls": urls[:20],
                "crawled_at": next((m.get("crawled_at") for m in (data.get("metadatas") or [])
                                    if (m or {}).get("crawled_at")), ""),
            }, ensure_ascii=False)
        except Exception as exc:                      # noqa: BLE001
            return json.dumps({"error": f"could not read the website corpus: {exc!r}"})
