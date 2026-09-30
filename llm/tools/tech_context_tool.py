"""
tech_context_tool.py — Open WebUI Tool

Provides RAG-backed technology contextualization for the SPOTTER graph:
  - CVE lookup by technology name/version or CPE
  - MITRE ATT&CK technique lookup by technology
  - Public exploit (PoC) availability for a CVE or a technology
  - Attack-surface summary for a host (IP or Device)

Install:
  Open WebUI → Admin → Tools → + New Tool → paste this file → Save

Requires:
  - scripts/cve_client.py
  - scripts/mitre_client.py
  - scripts/poc_client.py
  - scripts/rag_indexer.py
  - scripts/tech_context_engine.py

PoC data comes from a local mirror of nomi-sec/PoC-in-GitHub, refreshed on the
host by scripts/sync_poc_mirror.py. Those repositories are UNVETTED — inclusion
means a repo name or description matched a CVE ID, nothing more — so every
record carries `unvetted` and `warning`, and both must be passed through to the
operator verbatim. Never describe a PoC repository as safe, verified or
reviewed, and never suggest running one on engagement infrastructure.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

import requests

# The graph-label vocabulary is shared with WF04, WF12, tech_enricher and the
# other two chat tools — see scripts/asset_labels.py. This bootstrap matches
# attack_path_tool.py's so the module also imports when run on the host, not only
# in the Open WebUI container where scripts/ is mounted at /data/scripts.
for _scripts_dir in (
    os.environ.get("SPOTTER_SCRIPTS_DIR", "/data/scripts"),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts")),
):
    if _scripts_dir and os.path.isdir(_scripts_dir) and _scripts_dir not in sys.path:
        sys.path.insert(0, _scripts_dir)

from asset_labels import SERVICE_TYPES_LOWER, TECH_TYPES_LOWER


class Tools:
    def __init__(self):
        self.api_url   = os.environ.get("FLOWSINT_API_URL", "http://flowsint-api:5001")
        self.api_key   = os.environ.get("FLOWSINT_API_KEY", "")
        self.sketch_id = os.environ.get("FLOWSINT_SKETCH_ID", "")
        self._engine_instance = None

    def _neo(self, cypher, params, timeout=25):
        url  = os.environ.get("NEO4J_HTTP_URL", "http://neo4j:7474")
        user = os.environ.get("NEO4J_USER", "neo4j")
        pw   = os.environ.get("NEO4J_PASSWORD", "")
        resp = requests.post(
            f"{url}/db/neo4j/tx/commit",
            json={"statements": [{"statement": cypher, "parameters": params,
                                  "resultDataContents": ["row"]}]},
            auth=(user, pw), timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("errors"):
            raise RuntimeError(str(data["errors"][0]))
        results = data.get("results", [{}])
        columns = results[0].get("columns", []) if results else []
        return [dict(zip(columns, row.get("row", [])))
                for row in (results[0].get("data", []) if results else [])]

    def _resolve_sketch(self, explicit: Optional[str] = None) -> str:
        """The sketch to read. Container env is fixed at creation time, so
        FLOWSINT_SKETCH_ID goes stale whenever the engagement moves to a new sketch —
        and this tool's /graph call then 404s ("Graph not found") rather than saying
        why. Falls back to the only populated sketch, and refuses to guess when
        several are populated so campaigns cannot be mixed up. Keep in sync with the
        copies in flowsint_search_tool.py / dossier_tool.py / attack_path_tool.py.
        """
        candidate = (explicit or self.sketch_id or "").strip()
        if candidate:
            try:
                rows = self._neo("MATCH (n) WHERE n.sketch_id = $sk RETURN count(n) AS c",
                                 {"sk": candidate}, timeout=20)
                if rows and rows[0].get("c"):
                    return candidate
            except Exception:
                return candidate       # Neo4j unreachable: let the API call decide
        populated = self._neo(
            "MATCH (n) WHERE n.sketch_id IS NOT NULL "
            "RETURN n.sketch_id AS sketch_id, count(n) AS nodes ORDER BY nodes DESC LIMIT 25", {})
        if not populated:
            raise RuntimeError("no sketch in Neo4j contains any nodes — nothing has been ingested yet")
        if len(populated) > 1:
            raise RuntimeError(
                f"the configured sketch ({candidate or 'unset'}) holds 0 nodes and this database has "
                f"{len(populated)} populated sketches, so the right one cannot be guessed without risking "
                "another campaign's data — set FLOWSINT_SKETCH_ID")
        return populated[0]["sketch_id"]

    def _get_engine(self):
        if self._engine_instance is None:
            sys.path.insert(0, "/data/scripts")
            from tech_context_engine import TechContextEngine  # type: ignore[import]
            self._engine_instance = TechContextEngine()
        return self._engine_instance

    def get_cves_for_tech(self, tech: str, version: str = "") -> str:
        """
        Return CVEs relevant to a technology name and optional version.

        :param tech: Technology name, e.g. 'Apache httpd' or 'Windows Server 2019'.
        :param version: Optional version string, e.g. '2.4.41'.
        :return: JSON list of CVEs with CVSS scores and descriptions.
        """
        try:
            engine = self._get_engine()
        except Exception as e:
            return json.dumps({"error": f"Tech context engine unavailable: {e}"})

        cves = engine.map_tech_to_cves(tech, version or None, limit=10)
        return json.dumps({
            "tech": tech,
            "version": version or None,
            "cve_count": len(cves),
            "cves": cves,
        }, indent=2, default=str)

    def get_pocs_for_cve(self, cve_id: str) -> str:
        """
        Return public proof-of-concept exploit repositories for a CVE.

        :param cve_id: CVE identifier, e.g. 'CVE-2021-44228'.
        :return: JSON list of GitHub repositories ranked by a trust heuristic.
        """
        try:
            sys.path.insert(0, "/data/scripts")
            from poc_client import PoCClient  # type: ignore[import]
            client = PoCClient()
        except Exception as e:
            return json.dumps({"error": f"PoC client unavailable: {e}"})

        status = client.mirror_status()
        if not status.get("available"):
            return json.dumps({
                "error": "PoC mirror has never been synced — run "
                         "scripts/sync_poc_mirror.py on the host",
                "mirror": status,
            })

        pocs = client.pocs_for_cve(cve_id)
        return json.dumps({
            "cve_id": cve_id,
            "poc_count": len(pocs),
            "exploit_available": bool(pocs),
            "pocs": pocs,
            # A stale mirror answers "none" for every recent CVE, which reads
            # identically to a genuine negative unless the age travels with it.
            "mirror_stale": status.get("stale"),
            "mirror_age_days": status.get("age_days"),
            "caveat": (
                "These repositories are UNVETTED: inclusion means the repo name or "
                "description matched the CVE ID. Present the trust tier, never "
                "describe one as safe or verified, and do not recommend running "
                "one on engagement infrastructure."
            ),
        }, indent=2, default=str)

    def get_exploit_availability_for_tech(self, tech: str, version: str = "") -> str:
        """
        Return CVEs for a technology, each annotated with whether public exploit code exists.

        :param tech: Technology name, e.g. 'Apache httpd' or 'Citrix Workspace'.
        :param version: Optional version string, e.g. '2.4.41'.
        :return: JSON list of CVEs with exploit availability and top PoC repositories.
        """
        try:
            engine = self._get_engine()
        except Exception as e:
            return json.dumps({"error": f"Tech context engine unavailable: {e}"})

        cves = engine.map_tech_to_cves(tech, version or None, limit=10)
        exploitable = [c for c in cves if c.get("exploit_available")]
        status = engine.poc_client.mirror_status()

        return json.dumps({
            "tech": tech,
            "version": version or None,
            "cve_count": len(cves),
            "exploitable_cve_count": len(exploitable),
            "cves": [{
                "cve_id": c.get("cve_id"),
                "severity": (c.get("cvss") or {}).get("severity"),
                "base_score": (c.get("cvss") or {}).get("base_score"),
                "description": c.get("description"),
                "exploit_available": bool(c.get("exploit_available")),
                "poc_count": c.get("poc_count", 0),
                "pocs": c.get("pocs", []),
            } for c in cves],
            "mirror_stale": status.get("stale"),
            "mirror_age_days": status.get("age_days"),
            "caveat": (
                "PoC repositories are UNVETTED third-party code. Report the trust "
                "tier with each, and never characterise one as safe or reviewed."
            ),
        }, indent=2, default=str)

    def get_mitre_for_tech(self, tech: str) -> str:
        """
        Return MITRE ATT&CK techniques relevant to a technology.

        :param tech: Technology name, e.g. 'KeePass' or 'SAP GUI'.
        :return: JSON list of technique IDs, names, and descriptions.
        """
        try:
            engine = self._get_engine()
        except Exception as e:
            return json.dumps({"error": f"Tech context engine unavailable: {e}"})

        techniques = engine.map_tech_to_mitre(tech, limit=10)
        return json.dumps({
            "tech": tech,
            "technique_count": len(techniques),
            "techniques": techniques,
        }, indent=2, default=str)

    def get_attack_surface_for_host(self, host_identifier: str) -> str:
        """
        Return the attack surface for a host (IP address or hostname).

        :param host_identifier: IP address, hostname, or node label.
        :return: JSON with exposed services, technologies, and relevant CVEs.
        """
        try:
            sk = self._resolve_sketch()
            # Resolve the host, then read only its outbound service/technology edges.
            # Deterministic ordering (shortest label first) replaces the old
            # "first match in whatever order the API serialised" behaviour.
            found = self._neo(
                "MATCH (n) WHERE n.sketch_id = $sk AND n.deleted_at IS NULL AND ("
                "  toLower(coalesce(n.nodeLabel, '')) CONTAINS $q"
                "  OR toLower(coalesce(n['nodeProperties.ip'], '')) CONTAINS $q"
                "  OR toLower(coalesce(n['nodeProperties.hostname'], '')) CONTAINS $q"
                "  OR toLower(elementId(n)) = $q) "
                "WITH n, coalesce(n.nodeLabel, '') AS label "
                "RETURN elementId(n) AS host_id, label AS host "
                "ORDER BY size(label) ASC, label ASC LIMIT 1",
                {"sk": sk, "q": host_identifier.lower()})
            if not found:
                return json.dumps({"error": f"No host found matching '{host_identifier}'"})
            host_id, host_label = found[0]["host_id"], found[0]["host"]

            rows = self._neo(
                "MATCH (h)-[]->(t) WHERE elementId(h) = $id AND t.sketch_id = $sk "
                "  AND t.deleted_at IS NULL "
                "  AND toLower(coalesce(t.nodeType, '')) IN $tech_types "
                "RETURN toLower(coalesce(t.nodeType, '')) AS ntype, "
                "  t['nodeProperties.port'] AS port, t['nodeProperties.protocol'] AS protocol, "
                "  coalesce(t['nodeProperties.name'], t.nodeLabel) AS name, "
                "  t['nodeProperties.product'] AS product, t['nodeProperties.version'] AS version, "
                "  t['nodeProperties.cpe'] AS cpe, t['nodeProperties.category'] AS category, "
                "  t['nodeProperties.is_high_value'] AS is_high_value, "
                "  t['nodeProperties.name'] AS raw_name, "
                # Written by scripts/tech_enricher.py via WF14. Reading it here
                # means the common case costs no NVD calls at all and matches
                # exactly what the Tech Intel tab shows for the same node.
                "  t['nodeProperties.cve_count'] AS cve_count, "
                "  t['nodeProperties.poc_count'] AS poc_count, "
                "  t['nodeProperties.exploit_available'] AS exploit_available, "
                "  t['nodeProperties.cves'] AS cves_json, "
                "  t['nodeProperties.cve_match_basis'] AS cve_match_basis, "
                "  t['nodeProperties.top_pocs'] AS top_pocs_json, "
                "  t['nodeProperties.tech_context_enriched_at'] AS enriched_at",
                {"id": host_id, "sk": sk, "tech_types": sorted(TECH_TYPES_LOWER)})
        except Exception as e:
            return json.dumps({"error": f"Graph fetch failed: {e}"})

        def _json_prop(raw: Any) -> List[Dict[str, Any]]:
            """Enriched list properties are stored as JSON strings on the node."""
            if isinstance(raw, list):
                return raw
            if isinstance(raw, str) and raw.strip():
                try:
                    parsed = json.loads(raw)
                    return parsed if isinstance(parsed, list) else []
                except ValueError:
                    return []
            return []

        services, technologies = [], []
        enriched_cves: List[Dict[str, Any]] = []
        top_pocs: List[Dict[str, Any]] = []
        any_enriched = False
        unenriched: List[str] = []

        for r in rows:
            name = r.get("raw_name") or r.get("name")
            if r.get("enriched_at"):
                any_enriched = True
                enriched_cves.extend(_json_prop(r.get("cves_json")))
                top_pocs.extend(_json_prop(r.get("top_pocs_json")))
            elif name:
                unenriched.append(name)

            common = {
                "cve_count": r.get("cve_count"),
                "poc_count": r.get("poc_count"),
                "exploit_available": r.get("exploit_available"),
                # shodan | cpe | keyword | mixed. 'keyword' means the CVEs were
                # matched on the product NAME and may belong to other products.
                "cve_match_basis": r.get("cve_match_basis"),
            }
            if r["ntype"] in SERVICE_TYPES_LOWER:
                services.append({
                    "port": r.get("port"), "protocol": r.get("protocol"),
                    "name": r.get("raw_name"), "product": r.get("product"),
                    "version": r.get("version"), "cpe": r.get("cpe"), **common,
                })
            else:
                technologies.append({
                    "name": r.get("name"), "version": r.get("version"),
                    "category": r.get("category"),
                    "is_high_value": r.get("is_high_value"), **common,
                })

        # Prefer what WF14 already resolved onto the nodes. Fall back to live NVD
        # lookups only for a host nothing has enriched yet, so an un-enriched
        # graph still answers rather than returning an empty attack surface.
        relevant_cves: List[Dict[str, Any]] = list(
            {c.get("cve_id"): c for c in enriched_cves if c.get("cve_id")}.values()
        )[:10]
        if not any_enriched:
            try:
                engine = self._get_engine()
                fallback: List[Dict[str, Any]] = []
                for svc in services:
                    product = svc.get("product")
                    if product:
                        fallback.extend(engine.map_tech_to_cves(product, svc.get("version"), limit=3))
                relevant_cves = list({c["cve_id"]: c for c in fallback}.values())[:10]
            except Exception:
                pass

        top_pocs = sorted(
            {p.get("full_name"): p for p in top_pocs if p.get("full_name")}.values(),
            key=lambda p: -(p.get("trust_score") or 0),
        )[:5]

        return json.dumps({
            "host": host_label,
            "host_id": host_id,
            "services": services,
            "technologies": technologies,
            "relevant_cves": relevant_cves,
            "exploit_available": bool(top_pocs),
            "top_pocs": top_pocs,
            "poc_caveat": (
                "PoC repositories are UNVETTED third-party code — report the trust "
                "tier and never describe one as safe or verified."
            ) if top_pocs else None,
            # An un-enriched host is not a clean host. Saying so stops "no CVEs"
            # being read as "no exposure" when nothing has actually looked yet.
            "enrichment": {
                "enriched": any_enriched,
                "unenriched_components": unenriched[:10],
                "hint": None if any_enriched else
                        "No component here has been enriched — POST /webhook/tech-enrich "
                        "or run WF14 before treating this as a complete attack surface.",
            },
            "sketch_id": sk,
        }, indent=2, default=str)
