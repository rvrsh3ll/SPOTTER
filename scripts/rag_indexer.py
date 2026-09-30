"""
rag_indexer.py — Build and query a local RAG corpus for SPOTTER technology
contextualization.

Collections:
  - cve_index: CVE descriptions, CVSS, and references
  - mitre_index: MITRE ATT&CK technique names and descriptions
  - poc_index: Public proof-of-concept repositories, keyed to their CVE
  - tech_guides: Operator-contributed credential-extraction and attack playbooks
  - asset_inventory: Embeddings of detected Technology/Service node labels

Embeddings come from EMBEDDING_URL (an OpenAI-compatible endpoint) when it is
set and VLLM_EMBEDDING_MODE is remote, and otherwise from a pure-Python TF-IDF vectoriser. The fallback needs no
third-party packages on purpose: the n8n task runner is an Alpine/musl image
where scikit-learn cannot be installed without a source build, and requiring it
meant this whole index was never built in the one container that populates it.

Environment:
    SPOTTER_CACHE_DIR — cache directory (default: ./.spotter-cache)
    EMBEDDING_URL — optional OpenAI-compatible embedding endpoint
    EMBEDDING_MODEL — model name the CLIENT sends (default: Alibaba-NLP/gte-modernbert-base).
        Not the model vllm-embed loads: that is VLLM_EMBED_MODEL, set in
        deployment/docker-compose.llm.yml. Keep the two equal.
    VLLM_EMBEDDING_MODE — tfidf (default) or remote
"""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import os
import re
from typing import Any, Dict, List, Optional

import requests

from cve_client import CVEClient
from mitre_client import MITREClient
from poc_client import PoCClient
from spotter_cache import ensure_cache_path, ensure_cache_tree


DEFAULT_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".spotter-cache")


_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._+-]*")

# Small English stop list. Deliberately short: this corpus is CVE descriptions,
# ATT&CK techniques and repository blurbs, where "remote", "allows" and "attacker"
# appear everywhere and IDF already discounts them.
_STOPWORDS = frozenset("""
a an and are as at be been by for from has have in into is it its of on or that
the this to via was were will with which when where who whom would could should
""".split())


class SimpleEmbeddingFunction:
    """
    Pure-Python TF-IDF. This is the DEFAULT: the remote path needs BOTH
    VLLM_EMBEDDING_MODE=remote AND a non-empty EMBEDDING_URL (see
    RAGIndexer.__init__). Either one alone lands here.

    Why not scikit-learn: the n8n Python task runner is an Alpine (musl) image on
    Python 3.13, where no scipy/scikit-learn wheel exists, so pip falls through to
    a source build needing gcc, gfortran and a BLAS. Requiring it meant WF14's RAG
    step died with "scikit-learn is required for the fallback embedding function"
    and cve_index / poc_index / mitre_index were never built — the semantic half
    of the knowledge base did not exist in the one container that populates it.

    Using pure Python on BOTH sides also matters because the host and the runner
    share one cache directory: two different vectorisers writing the same
    collection would produce silently incompatible vectors.

    fit() is deterministic over a given corpus — vocabulary chosen by document
    frequency, ties alphabetical, columns then sorted — which is what lets
    RAGIndexer.query() re-derive the document space and embed a query into it.
    It is not as good as real embeddings; set EMBEDDING_URL for those.
    """

    def __init__(self, max_features: int = 1024):
        self.max_features = max_features
        self.vocabulary_: Dict[str, int] = {}
        self.idf_: Dict[str, float] = {}
        self.doc_count = 0

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return [t for t in _TOKEN_RE.findall((text or "").lower())
                if len(t) > 1 and t not in _STOPWORDS]

    def fit(self, texts: List[str]) -> "SimpleEmbeddingFunction":
        """Learn the vocabulary and IDF weights for a corpus."""
        docs = [self._tokenize(t) for t in texts]
        df: Dict[str, int] = {}
        for tokens in docs:
            for term in set(tokens):
                df[term] = df.get(term, 0) + 1

        # Most-documented terms first, ties broken alphabetically, then the kept
        # terms sorted so the column order is a pure function of the corpus. That
        # determinism is what lets query() re-derive the same space later.
        kept = sorted(df.items(), key=lambda kv: (-kv[1], kv[0]))[: self.max_features]
        self.vocabulary_ = {term: i for i, term in enumerate(sorted(t for t, _ in kept))}
        n_docs = len(docs)
        self.doc_count = n_docs
        self.idf_ = {
            term: math.log((1.0 + n_docs) / (1.0 + df[term])) + 1.0
            for term in self.vocabulary_
        }
        return self

    def export_model(self) -> Dict[str, Any]:
        return {
            "kind": "simple_tfidf",
            "max_features": self.max_features,
            "doc_count": self.doc_count,
            "vocabulary": self.vocabulary_,
            "idf": self.idf_,
        }

    def load_model(self, model: Dict[str, Any]) -> "SimpleEmbeddingFunction":
        self.max_features = int(model.get("max_features") or self.max_features)
        self.doc_count = int(model.get("doc_count") or 0)
        self.vocabulary_ = {
            str(term): int(idx)
            for term, idx in (model.get("vocabulary") or {}).items()
        }
        self.idf_ = {
            str(term): float(weight)
            for term, weight in (model.get("idf") or {}).items()
        }
        return self

    def transform(self, texts: List[str]) -> List[List[float]]:
        """Project texts into the fitted space. Unknown terms are dropped."""
        vectors: List[List[float]] = []
        width = len(self.vocabulary_)
        for text in texts:
            tokens = self._tokenize(text)
            counts: Dict[str, int] = {}
            for term in tokens:
                if term in self.vocabulary_:
                    counts[term] = counts.get(term, 0) + 1
            vec = [0.0] * width
            total = float(len(tokens)) or 1.0
            for term, count in counts.items():
                vec[self.vocabulary_[term]] = (count / total) * self.idf_[term]
            # L2 normalise so the cosine similarity in query() is a dot product.
            norm = math.sqrt(sum(v * v for v in vec))
            if norm:
                # Rounded: these are serialised to JSON on every write, and full
                # float repr triples the on-disk size of the collections.
                vec = [round(v / norm, 6) for v in vec]
            vectors.append(vec)
        return vectors

    def __call__(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        return self.fit(texts).transform(texts)


# Documents in these collections are not uniform: mitre_index p95 is ~2.7 KB but
# poc_index holds one 64 KB record. Sending a whole collection in one request
# (858 MITRE documents is ~300k tokens) is refused by any backend with a context
# limit, so batch, and truncate client-side rather than relying on a backend flag
# — truncation is then backend-agnostic and the request body stays the plain
# {"model", "input"} shape the smoke test pins.
_EMBED_BATCH = max(1, int(os.environ.get("EMBEDDING_BATCH_SIZE", "32")))
_EMBED_MAX_CHARS = max(500, int(os.environ.get("EMBEDDING_MAX_CHARS", "20000")))


class OpenAIEmbeddingFunction:
    """Embedding function for OpenAI-compatible /v1/embeddings services."""

    def __init__(self, url: str, model: str, api_key: str = ""):
        self.url = url.rstrip("/")
        self.model = model
        self.api_key = api_key

    def export_model(self) -> Dict[str, Any]:
        # The URL is deliberately NOT part of the identity. The runner reaches the
        # backend as http://vllm-embed:8000/v1 and the host reaches the SAME server
        # as http://127.0.0.1:8100/v1; including the URL would make those two look
        # like different backends to the staleness check in _query_embedding, and
        # each would rebuild the whole collection to "correct" the other.
        return {"kind": "openai_embeddings", "model": self.model}

    def __call__(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        out: List[List[float]] = []
        for i in range(0, len(texts), _EMBED_BATCH):
            chunk = [str(t or "")[:_EMBED_MAX_CHARS] for t in texts[i:i + _EMBED_BATCH]]
            response = requests.post(
                f"{self.url}/embeddings",
                headers=headers,
                json={"model": self.model, "input": chunk},
                timeout=max(60, min(600, 10 + len(chunk) * 10)),
            )
            response.raise_for_status()
            rows = response.json().get("data") or []
            embeddings = [row.get("embedding") for row in rows if isinstance(row, dict)]
            if len(embeddings) != len(chunk) or any(not isinstance(r, list) for r in embeddings):
                raise ValueError(
                    "OpenAI-compatible embedding endpoint returned an incomplete response"
                )
            # Rounded for the same reason SimpleEmbeddingFunction rounds: these are
            # serialised to JSON on every write and full float repr triples the size.
            out.extend([round(float(v), 6) for v in vec] for vec in embeddings)
        return out


class RAGIndexer:
    def __init__(self, cache_dir: Optional[str] = None, embedding_fn=None):
        self.cache_dir = cache_dir or os.environ.get("SPOTTER_CACHE_DIR") or DEFAULT_CACHE_DIR
        os.makedirs(self.cache_dir, exist_ok=True)
        ensure_cache_path(self.cache_dir, is_dir=True)
        self.index_dir = os.path.join(self.cache_dir, "rag_index")
        os.makedirs(self.index_dir, exist_ok=True)
        ensure_cache_path(self.index_dir, is_dir=True)
        ensure_cache_tree(self.index_dir)

        if embedding_fn is not None:
            self.embedding_fn = embedding_fn
        elif (os.environ.get("VLLM_EMBEDDING_MODE", "tfidf").strip().lower() == "remote"
              and os.environ.get("EMBEDDING_URL")):
            self.embedding_fn = OpenAIEmbeddingFunction(
                os.environ["EMBEDDING_URL"],
                os.environ.get("EMBEDDING_MODEL") or "Alibaba-NLP/gte-modernbert-base",
                os.environ.get("EMBEDDING_API_KEY", ""),
            )
        else:
            self.embedding_fn = SimpleEmbeddingFunction()

        self.cve_client = CVEClient(cache_dir=self.cache_dir)
        self.mitre_client = MITREClient(cache_dir=self.cache_dir)
        self.poc_client = PoCClient(cache_dir=self.cache_dir)

    @staticmethod
    def _safe_collection_name(name: str) -> str:
        """Reduce a collection name to something that cannot leave index_dir.

        The five built-in collections are hardcoded literals, so this never
        mattered. Per-campaign collections are not: `company_site__<sketch_id>`
        embeds an id that arrives in a webhook request body, and this name goes
        straight into a filesystem path. A `../` in it would write outside the
        cache directory.
        """
        slug = re.sub(r"[^A-Za-z0-9_.-]", "_", str(name or "").strip())
        slug = slug.lstrip(".")           # no leading dots -> no '..' traversal
        return slug[:120] or "unnamed"

    def _collection_path(self, name: str) -> str:
        return os.path.join(self.index_dir, f"{self._safe_collection_name(name)}.json")

    def _load_collection(self, name: str) -> Dict[str, Any]:
        path = self._collection_path(name)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"ids": [], "documents": [], "metadatas": [], "embeddings": []}

    def _save_collection(self, name: str, collection: Dict[str, Any]) -> None:
        path = self._collection_path(name)
        collection.pop("_embedding_dirty", None)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(collection, f, separators=(",", ":"))
        # The cache is shared between the host (root) and the n8n task runner
        # (uid/gid 1000) over one bind mount. A default 0644 file written by
        # whichever side got there first is then unwritable by the other, and the
        # symptom is a bare "[Errno 13] Permission denied" from deep inside WF14
        # long after the run that caused it. Group-writable keeps both writers
        # working; failure to chmod is ignored because not owning the file is
        # only a problem if we also needed to rewrite it, which this just did.
        try:
            ensure_cache_path(path, is_dir=False)
        except OSError:
            pass

    def _embed(self, documents: List[str]) -> List[List[float]]:
        if not documents:
            return []
        return self.embedding_fn(documents)

    def _is_corpus_embedding(self) -> bool:
        return hasattr(self.embedding_fn, "fit") and hasattr(self.embedding_fn, "transform")

    def _embedding_model_metadata(self) -> Dict[str, Any]:
        if hasattr(self.embedding_fn, "export_model"):
            return self.embedding_fn.export_model()
        return {"kind": "fixed_space", "class": type(self.embedding_fn).__name__}

    def _refresh_embeddings(self, collection: Dict[str, Any]) -> None:
        documents = collection.get("documents") or []
        if not documents:
            collection["embeddings"] = []
            collection.pop("embedding_model", None)
            collection["_embedding_dirty"] = True
            return
        if self._is_corpus_embedding():
            self.embedding_fn.fit(documents)
            collection["embeddings"] = self.embedding_fn.transform(documents)
            if hasattr(self.embedding_fn, "export_model"):
                collection["embedding_model"] = self.embedding_fn.export_model()
            collection["_embedding_dirty"] = True
            return
        collection["embeddings"] = self._embed(documents)
        collection["embedding_model"] = self._embedding_model_metadata()
        collection["_embedding_dirty"] = True

    def _append_embeddings(self, collection: Dict[str, Any], new_documents: List[str]) -> None:
        if self._is_corpus_embedding():
            self._refresh_embeddings(collection)
            return
        old_count = len(collection.get("documents") or []) - len(new_documents)
        if (
            collection.get("embedding_model") != self._embedding_model_metadata()
            or len(collection.get("embeddings") or []) != old_count
        ):
            self._refresh_embeddings(collection)
            return
        collection.setdefault("embeddings", []).extend(self._embed(new_documents))
        collection["embedding_model"] = self._embedding_model_metadata()
        collection["_embedding_dirty"] = True

    def _query_embedding(self, collection_name: str, collection: Dict[str, Any], query_text: str) -> List[float]:
        if self._is_corpus_embedding():
            model = collection.get("embedding_model") or {}
            embeddings = collection.get("embeddings") or []
            documents = collection.get("documents") or []
            if (
                model.get("kind") != "simple_tfidf"
                or int(model.get("doc_count") or 0) != len(documents)
                or len(embeddings) != len(documents)
            ):
                self._refresh_embeddings(collection)
                model = collection.get("embedding_model") or {}
                self._save_collection(collection_name, collection)
            if hasattr(self.embedding_fn, "load_model"):
                self.embedding_fn.load_model(model)
            return self.embedding_fn.transform([query_text])[0]

        embeddings = collection.get("embeddings") or []
        documents = collection.get("documents") or []
        if collection.get("embedding_model") != self._embedding_model_metadata() or len(embeddings) != len(documents):
            self._refresh_embeddings(collection)
            self._save_collection(collection_name, collection)
        return self._embed([query_text])[0]

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = sum(x * x for x in a) ** 0.5
        norm_b = sum(x * x for x in b) ** 0.5
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def index_cves(self, keywords: List[str], limit_per_keyword: int = 20) -> int:
        """Fetch and index CVEs for a list of technology keywords."""
        collection = self._load_collection("cve_index")
        existing_ids = set(collection["ids"])
        added = 0

        for keyword in keywords:
            cves = self.cve_client.search_by_keyword(keyword, limit=limit_per_keyword)
            for cve in cves:
                doc_id = cve["cve_id"]
                if doc_id in existing_ids:
                    continue
                existing_ids.add(doc_id)
                doc = f"{cve['cve_id']}: {cve['description']}"
                collection["ids"].append(doc_id)
                collection["documents"].append(doc)
                collection["metadatas"].append({
                    "cve_id": cve["cve_id"],
                    "base_score": cve.get("cvss", {}).get("base_score"),
                    "severity": cve.get("cvss", {}).get("severity"),
                    "keyword": keyword,
                })
                added += 1

        if added:
            self._append_embeddings(collection, collection["documents"][-added:])
            self._save_collection("cve_index", collection)
        return added

    def index_mitre(self) -> int:
        """Index all MITRE ATT&CK techniques."""
        collection = self._load_collection("mitre_index")
        if collection["ids"]:
            return 0  # Already indexed

        self.mitre_client._load()
        for obj in self.mitre_client._objects:
            if obj.get("type") != "attack-pattern":
                continue
            tid = self.mitre_client._technique_id(obj)
            if not tid:
                continue
            doc = f"{tid} {obj.get('name', '')}: {obj.get('description', '')}"
            collection["ids"].append(tid)
            collection["documents"].append(doc)
            collection["metadatas"].append({
                "technique_id": tid,
                "name": obj.get("name"),
            })

        if collection["documents"]:
            self._refresh_embeddings(collection)
            self._save_collection("mitre_index", collection)
        return len(collection["ids"])

    def index_cve_ids(self, cve_ids: List[str]) -> int:
        """
        Index specific CVEs by ID.

        Companion to index_cves(), which takes keywords and re-runs the NVD
        search. Callers that have already resolved CVEs — tech_enricher does,
        for exactly the technologies present in the graph — should use this
        instead: it indexes the CVEs that actually matched an asset rather than
        everything a keyword happened to hit, and every lookup is a cache read
        because the enrichment pass just performed it.
        """
        collection = self._load_collection("cve_index")
        existing_ids = set(collection["ids"])
        added = 0

        for cve_id in cve_ids:
            if not cve_id or cve_id in existing_ids:
                continue
            try:
                cve = self.cve_client.get_cve(cve_id)
            except Exception:
                continue
            if not cve:
                continue
            existing_ids.add(cve_id)
            collection["ids"].append(cve_id)
            collection["documents"].append(f"{cve['cve_id']}: {cve['description']}")
            collection["metadatas"].append({
                "cve_id": cve["cve_id"],
                "base_score": (cve.get("cvss") or {}).get("base_score"),
                "severity": (cve.get("cvss") or {}).get("severity"),
                "keyword": "graph-asset",
            })
            added += 1

        if added:
            self._append_embeddings(collection, collection["documents"][-added:])
            self._save_collection("cve_index", collection)
        return added

    def index_pocs(self, cve_ids: List[str], limit_per_cve: int = 5) -> int:
        """
        Index public PoC repositories for a list of CVE IDs.

        Scope is deliberately the CVEs that actually matched something in the
        graph, not the whole 22k-repo mirror: `query()` is a linear cosine scan
        and `_embed` refits the entire corpus on every write, so indexing the
        mirror wholesale would make every other collection slow too. The mirror
        itself stays the complete source — poc_client answers exact CVE lookups
        directly from it, and this collection only exists for the semantic case
        ("is there exploit code for anything like our Citrix stack").
        """
        collection = self._load_collection("poc_index")
        existing_ids = set(collection["ids"])
        added = 0

        for cve_id in cve_ids:
            for repo in self.poc_client.pocs_for_cve(cve_id, limit=limit_per_cve):
                doc_id = f"{repo['cve_id']}:{repo['full_name']}"
                if doc_id in existing_ids:
                    continue
                existing_ids.add(doc_id)
                collection["ids"].append(doc_id)
                collection["documents"].append(
                    f"{repo['cve_id']} proof of concept {repo['full_name']}: "
                    f"{repo.get('description') or ''}".strip()
                )
                collection["metadatas"].append({
                    "cve_id": repo["cve_id"],
                    "full_name": repo["full_name"],
                    "url": repo["url"],
                    "stars": repo["stars"],
                    "trust": repo["trust"],
                    # Carried into every retrieval so a RAG hit can never be
                    # presented as vetted code.
                    "unvetted": True,
                })
                added += 1

        if added:
            self._append_embeddings(collection, collection["documents"][-added:])
            self._save_collection("poc_index", collection)
        return added

    def index_guides(self, guides: Dict[str, str]) -> int:
        """Index operator playbook guides."""
        collection = self._load_collection("tech_guides")
        existing_ids = set(collection["ids"])
        added = 0
        for title, body in guides.items():
            doc_id = hashlib.sha256(title.encode()).hexdigest()[:16]
            if doc_id in existing_ids:
                continue
            existing_ids.add(doc_id)
            collection["ids"].append(doc_id)
            collection["documents"].append(f"{title}: {body}")
            collection["metadatas"].append({"title": title})
            added += 1

        if added:
            self._append_embeddings(collection, collection["documents"][-added:])
            self._save_collection("tech_guides", collection)
        return added

    def reset_collection(self, collection_name: str) -> int:
        """Empty a collection, returning how many documents were dropped.

        Every index_* method appends and dedups by id, so a document can be
        added but never CHANGED. That is fine for CVEs and ATT&CK techniques,
        which are immutable records, and wrong for a crawled web page, which is
        the whole point of re-crawling. A site re-crawl resets, then re-indexes.

        Deliberately does not delete the file: keeping an empty collection
        preserves nothing of value, but rewriting it in place keeps the cache
        permissions the runner depends on (see spotter_cache.ensure_cache_path).
        """
        collection = self._load_collection(collection_name)
        dropped = len(collection.get("ids") or [])
        self._save_collection(collection_name, {
            "ids": [], "documents": [], "metadatas": [], "embeddings": [],
        })
        return dropped

    def index_documents(self, collection_name: str,
                        documents: List[Dict[str, Any]]) -> int:
        """Generic writer: index arbitrary {id, text, metadata} records.

        The content-agnostic sibling of index_guides/index_cves/index_pocs,
        added so a caller with its own corpus (a crawled website) does not need
        a bespoke index_* method on this class. Same append-and-dedup-by-id
        contract as the others; pair it with reset_collection() when the source
        documents can change.

        `id` is optional -- a missing one is derived from the text, so a caller
        that re-indexes identical content twice does not duplicate it.
        """
        collection = self._load_collection(collection_name)
        existing_ids = set(collection["ids"])
        added = 0
        for doc in documents or []:
            text = str((doc or {}).get("text") or "").strip()
            if not text:
                continue
            doc_id = str(doc.get("id") or "").strip()
            if not doc_id:
                doc_id = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
            if doc_id in existing_ids:
                continue
            existing_ids.add(doc_id)
            collection["ids"].append(doc_id)
            collection["documents"].append(text)
            collection["metadatas"].append(dict(doc.get("metadata") or {}))
            added += 1

        if added:
            self._append_embeddings(collection, collection["documents"][-added:])
            self._save_collection(collection_name, collection)
        return added

    def index_asset_inventory(self, technologies: List[Dict[str, Any]]) -> int:
        """Index detected Technology/Service node labels for semantic search."""
        collection = self._load_collection("asset_inventory")
        existing_ids = set(collection["ids"])
        added = 0
        for tech in technologies:
            doc_id = tech.get("id") or hashlib.sha256(
                f"{tech.get('name','')}:{tech.get('version','')}".encode()
            ).hexdigest()[:16]
            if doc_id in existing_ids:
                continue
            existing_ids.add(doc_id)
            doc = f"{tech.get('name', '')} {tech.get('version', '')} {tech.get('category', '')} {tech.get('vendor', '')}".strip()
            if not doc:
                continue
            collection["ids"].append(doc_id)
            collection["documents"].append(doc)
            collection["metadatas"].append(tech)
            added += 1

        if added:
            self._append_embeddings(collection, collection["documents"][-added:])
            self._save_collection("asset_inventory", collection)
        return added

    def query(self, collection_name: str, query_text: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """
        Semantic search over a collection.

        The query MUST be projected into the same vector space as the stored
        documents. This used to call _embed([query_text]), which for a TF-IDF
        vectoriser fits a fresh vocabulary on the query alone: a one-word query
        produced a 1-dimensional vector, `zip()` in _cosine_similarity silently
        truncated to that one dimension, and the ranking was noise. Searching
        tech_guides for "KeePass" returned the KeePass playbook LAST, at 0.0000,
        behind an unrelated TN3270 guide.

        The fallback now stores the fitted TF-IDF vocabulary/IDF beside the
        collection, so each query can load that model and project the query into
        the stored vector space without fitting over the whole corpus again.
        Collections written before that metadata existed are rebuilt once on
        first query and saved back in the current format.
        """
        collection = self._load_collection(collection_name)
        if not collection["documents"]:
            return []

        query_embedding = self._query_embedding(collection_name, collection, query_text)
        scores = heapq.nlargest(
            n_results,
            (
                (i, self._cosine_similarity(query_embedding, emb))
                for i, emb in enumerate(collection["embeddings"])
            ),
            key=lambda x: x[1],
        )

        results: List[Dict[str, Any]] = []
        for idx, score in scores:
            results.append({
                "id": collection["ids"][idx],
                "document": collection["documents"][idx],
                "metadata": collection["metadatas"][idx],
                "score": round(score, 4),
            })
        return results


def build_default_index() -> Dict[str, int]:
    """Build the default RAG index with CVEs for common high-value tech."""
    indexer = RAGIndexer()
    counts = {}
    counts["mitre"] = indexer.index_mitre()
    counts["guides"] = indexer.index_guides({
        "KeePass memory dump": "Dump KeePass master password from memory during active session using KeeThief or KeeDump.",
        "SAP GUI credential store": "Extract SAPUILandscape.xml and saved connection entries from %APPDATA%\\SAP\\Common.",
        "Citrix ICA file theft": "Steal .ica files from Downloads/temp and extract saved credentials from Credential Manager.",
        "Mainframe TN3270 session hijack": "Capture TN3270 traffic on TCP/23 or inject into terminal emulator process.",
    })
    keywords = [
        "Apache httpd", "OpenSSH", "Windows Server 2019", "Windows 10",
        "SAP GUI", "Citrix Workspace", "CyberArk", "KeePass", "SQL Server",
    ]
    counts["cves"] = indexer.index_cves(keywords)
    return counts


if __name__ == "__main__":
    counts = build_default_index()
    print(json.dumps(counts, indent=2))
