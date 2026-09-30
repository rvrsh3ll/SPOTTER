"""
cve_client.py — NVD CVE retriever with local SQLite cache.

Provides keyword and CPE-based CVE lookups with rate-limit awareness.
Results are cached in SQLite to respect the NVD API rate limit and to allow
offline operation during engagements.

Environment:
    NVD_API_KEY — optional NIST NVD API key (raises rate limit)
    NVD_PROXY_URL — optional proxy URL for NVD requests
    BUCKET_PROBE_PROXY — fallback proxy URL when NVD_PROXY_URL is unset
    SPOTTER_CACHE_DIR — cache directory (default: ./.spotter-cache)
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests

from spotter_cache import ensure_cache_path


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".spotter-cache")


class CVEClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_dir: Optional[str] = None,
        proxy_url: Optional[str] = None,
    ):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.cache_dir = cache_dir or os.environ.get("SPOTTER_CACHE_DIR") or DEFAULT_CACHE_DIR
        self.proxy_url = self._resolve_proxy(proxy_url)
        self.proxies = {"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None
        os.makedirs(self.cache_dir, exist_ok=True)
        ensure_cache_path(self.cache_dir, is_dir=True)
        self.db_path = os.path.join(self.cache_dir, "cve_cache.db")
        if os.path.exists(self.db_path):
            ensure_cache_path(self.db_path, is_dir=False)
        self._init_db()
        ensure_cache_path(self.db_path, is_dir=False)
        self._last_request = 0.0
        self._min_interval = 0.6 if self.api_key else 6.0  # seconds between requests

    @staticmethod
    def _resolve_proxy(proxy_url: Optional[str] = None) -> str:
        """Proxy URL for NVD's target-specific product/version lookups.

        Prefer NVD_PROXY_URL so this path can be controlled independently. Fall
        back to BUCKET_PROBE_PROXY because operators already use that as the
        managed SOCKS egress knob for domain-recon traffic.
        """
        raw = proxy_url if proxy_url is not None else os.environ.get("NVD_PROXY_URL")
        if raw is None:
            raw = os.environ.get("BUCKET_PROBE_PROXY", "")
        raw = str(raw or "").strip()
        if raw.lower() in {"none", "direct", "off", "false", "0"}:
            return ""
        return raw

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_cache (
                    query_key TEXT PRIMARY KEY,
                    query_type TEXT NOT NULL,
                    query_value TEXT NOT NULL,
                    results TEXT NOT NULL,
                    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_cve_cache_type_value
                ON cve_cache(query_type, query_value)
                """
            )

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.time()

    def _get_cache(self, query_type: str, query_value: str) -> Optional[List[Dict[str, Any]]]:
        key = f"{query_type}:{query_value.lower()}"
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT results, fetched_at FROM cve_cache WHERE query_key = ?",
                (key,),
            ).fetchone()
        if not row:
            return None
        results, fetched_at = row
        fetched = datetime.fromisoformat(fetched_at)
        if datetime.utcnow() - fetched > timedelta(days=7):
            return None
        return json.loads(results)

    def _set_cache(self, query_type: str, query_value: str, results: List[Dict[str, Any]]) -> None:
        key = f"{query_type}:{query_value.lower()}"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO cve_cache (query_key, query_type, query_value, results)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(query_key) DO UPDATE SET
                    results = excluded.results,
                    fetched_at = CURRENT_TIMESTAMP
                """,
                (key, query_type, query_value, json.dumps(results)),
            )

    @staticmethod
    def _sort_worst_first(cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Highest CVSS first, then most recently published.

        NVD returns matches in CVE-ID order, i.e. OLDEST FIRST. Every caller here
        takes the top N, so unsorted results meant a search for "Microsoft Edge"
        answered with CVE-1999-0999 and two other 1999 entries — for a product
        that did not exist until 2015. Sorting before the slice is what makes the
        `limit` parameter select the CVEs worth an operator's attention rather
        than the alphabetically earliest ones.
        """
        def score_of(c: Dict[str, Any]) -> float:
            raw = (c.get("cvss") or {}).get("base_score")
            return float(raw) if isinstance(raw, (int, float)) else -1.0

        # Two stable passes: newest first, then worst first on top of it.
        out = sorted(cves, key=lambda c: str(c.get("published") or ""), reverse=True)
        out.sort(key=score_of, reverse=True)
        return out

    def _fetch(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        self._rate_limit()
        resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=60,
                    proxies=self.proxies)
        resp.raise_for_status()
        data = resp.json()

        cves: List[Dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            if not desc and descriptions:
                desc = descriptions[0].get("value", "")

            metrics = cve.get("metrics", {})
            cvss = {}
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metric_key in metrics and metrics[metric_key]:
                    cvss_data = metrics[metric_key][0].get("cvssData", {})
                    cvss = {
                        "version": cvss_data.get("version"),
                        "base_score": cvss_data.get("baseScore"),
                        "severity": cvss_data.get("baseSeverity") or metrics[metric_key][0].get("baseSeverity"),
                        "vector": cvss_data.get("vectorString"),
                    }
                    break

            cves.append({
                "cve_id": cve_id,
                "description": desc,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "cvss": cvss,
                "references": [r.get("url") for r in cve.get("references", []) if r.get("url")],
                "cpe_matches": self._extract_cpes(cve),
            })
        return self._sort_worst_first(cves)

    @staticmethod
    def _extract_cpes(cve: Dict[str, Any]) -> List[str]:
        cpes: List[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria")
                    if cpe and cpe not in cpes:
                        cpes.append(cpe)
        return cpes

    # Window fetched before slicing to `limit`. NVD orders by CVE ID, so a page
    # sized to `limit` would return the oldest matches and the sort in
    # _sort_worst_first would have nothing useful to reorder. 100 is a page NVD
    # serves comfortably and costs the same one rate-limited request.
    _SORT_WINDOW = 100

    def search_by_keyword(
        self, keyword: str, limit: int = 20, exact_phrase: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Search CVEs by keyword (product name, vendor, etc.).

        `exact_phrase` defaults to True because NVD's keywordSearch is otherwise
        an OR across the words: "Microsoft Edge" matched every CVE mentioning
        *either* term, which for a two-word product name is most of the database.
        Callers that genuinely want the broad match can opt out, and the two
        variants are cached separately so they cannot contaminate each other.
        """
        cache_type = "keyword_exact" if exact_phrase else "keyword"
        cached = self._get_cache(cache_type, keyword)
        if cached is not None:
            return cached[:limit]

        params: Dict[str, Any] = {
            "keywordSearch": keyword,
            "resultsPerPage": max(min(self._SORT_WINDOW, 2000), limit),
        }
        if exact_phrase:
            params["keywordExactMatch"] = ""      # valueless flag parameter
        results = self._fetch(params)

        # An exact phrase that matches nothing is common for a versioned or
        # vendor-prefixed name ("Micro Focus RUMBA Terminal Emulator"). Fall back
        # to the broad search rather than reporting the technology as clean.
        if not results and exact_phrase:
            results = self.search_by_keyword(keyword, limit=limit, exact_phrase=False)
            return results[:limit]

        self._set_cache(cache_type, keyword, results)
        return results[:limit]

    def search_by_cpe(self, cpe: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Search CVEs by an exact CPE 2.3 name.

        NVD's `cpeName` demands a complete, well-formed 2.3 URI: a CPE 2.2 URI
        (`cpe:/a:apache:http_server`) or a 2.3 name with a wildcard version both
        answer HTTP 404. Prefer search_by_cpe_prefix() unless the caller genuinely
        has a full versioned 2.3 name.
        """
        cached = self._get_cache("cpe", cpe)
        if cached is not None:
            return cached[:limit]

        params = {"cpeName": cpe, "resultsPerPage": max(min(self._SORT_WINDOW, 2000), limit)}
        results = self._fetch(params)
        self._set_cache("cpe", cpe, results)
        return results[:limit]

    def search_by_cpe_prefix(self, cpe_prefix: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Search CVEs by a PARTIAL CPE 2.3 string, e.g. 'cpe:2.3:a:apache:http_server'.

        Uses NVD's `virtualMatchString`, which accepts an incomplete CPE where
        `cpeName` does not. This is the accurate path for the CPEs SPOTTER actually
        holds: WF13's domain-recon Service nodes carry vendor/product 2.2 URIs with
        no version, and falling back to a product-name keyword search for those
        attributed Ivanti Sentry's CVE-2023-38035 to every host running Apache
        httpd — a phrase match that is technically correct and operationally
        useless. A vendor+product CPE match returns only that product's CVEs.
        """
        cached = self._get_cache("cpe_virtual", cpe_prefix)
        if cached is not None:
            return cached[:limit]

        params = {
            "virtualMatchString": cpe_prefix,
            "resultsPerPage": max(min(self._SORT_WINDOW, 2000), limit),
        }
        results = self._fetch(params)
        self._set_cache("cpe_virtual", cpe_prefix, results)
        return results[:limit]

    @staticmethod
    def cpe23_prefix(cpe: str) -> Optional[str]:
        """
        Normalise any CPE spelling to a `cpe:2.3:<part>:<vendor>:<product>[:<version>]`
        prefix suitable for search_by_cpe_prefix().

        Accepts CPE 2.2 (`cpe:/a:vendor:product:1.0`) and 2.3
        (`cpe:2.3:a:vendor:product:1.0:...`). Returns None when vendor or product
        is missing or wildcarded, because a prefix of `cpe:2.3:a` would match the
        entire database rather than nothing — a silent false positive, which is
        worse than no answer.
        """
        raw = (cpe or "").strip()
        if not raw:
            return None
        if raw.startswith("cpe:2.3:"):
            parts = raw[len("cpe:2.3:"):].split(":")
        elif raw.startswith("cpe:/"):
            parts = raw[len("cpe:/"):].split(":")
        else:
            return None

        fields = []
        for p in parts[:4]:                      # part, vendor, product, version
            if not p or p in ("*", "-"):
                break
            fields.append(p)
        if len(fields) < 3:                      # need at least part:vendor:product
            return None
        return "cpe:2.3:" + ":".join(fields)

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single CVE by ID."""
        cached = self._get_cache("id", cve_id)
        if cached is not None:
            return cached[0] if cached else None

        params = {"cveId": cve_id}
        results = self._fetch(params)
        self._set_cache("id", cve_id, results)
        return results[0] if results else None


if __name__ == "__main__":
    import json
    client = CVEClient()
    print(json.dumps(client.search_by_keyword("Apache httpd 2.4.41", limit=5), indent=2))
