"""
flowsint_search_tool.py — Open WebUI Tool

Allows the LLM to search for entities in the Flowsint graph by keyword or type.

Install:
  Open WebUI → Admin → Tools → + New Tool → paste this file → Save

Queries run against Neo4j directly (the transactional HTTP endpoint, same as
ad_attack_paths_tool.py) and are filtered server-side. The previous version
downloaded the entire sketch graph on every call and filtered in Python, which
cost ~19s on a ~10k-node engagement graph to return 15 rows.

Sketch scoping: a tool has no campaign context, so the sketch is resolved at call
time — explicit sketch_id argument, else FLOWSINT_SKETCH_ID if it actually holds
data, else the only populated sketch in the database. If several sketches hold
data the tool refuses to guess and lists them, so one campaign's data can never be
silently substituted for another's.

Neo4j schema:
  Node labels are exactly the nodeType and ARE case-sensitive: AD objects are
  lower-case (individual, device, organization, gpo), enrichment/OSINT nodes are
  CamelCase (DomainBreach, Subdomain, WebAsset, SocialProfile, ...).
  Nested props are FLAT dotted keys: n['nodeProperties.sid'], etc.
  Every node carries sketch_id — ALWAYS scope by it.
"""

import json
import os
import requests
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# SKETCH RESOLUTION — keep in sync with the copy in dossier_tool.py and
# attack_path_tool.py (Open WebUI tools are standalone files, so this is
# duplicated by design, like ACE_SCORES).
# ─────────────────────────────────────────────────────────────────────────────
class _SketchMixin:
    def _neo4j(self):
        return (os.environ.get("NEO4J_HTTP_URL", "http://neo4j:7474"),
                os.environ.get("NEO4J_USER", "neo4j"),
                os.environ.get("NEO4J_PASSWORD", ""))

    def _run(self, cypher: str, params: Dict[str, Any], timeout: int = 45) -> List[Dict[str, Any]]:
        url, user, pw = self._neo4j()
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

    # Underscore-prefixed on purpose: Open WebUI turns every PUBLIC method on
    # Tools into a callable tool, and this helper is not one.
    def _resolve_sketch(self, explicit: Optional[str] = None) -> Dict[str, Any]:
        """Return {'sketch_id': str} or {'error': ..., 'sketches': [...]}.

        Container env is fixed at creation time, so FLOWSINT_SKETCH_ID goes stale
        whenever the engagement moves to a new sketch — that is the single most
        common cause of a tool truthfully reporting "nothing found" on a graph
        that is full of data.
        """
        candidate = (explicit or os.environ.get("FLOWSINT_SKETCH_ID", "") or "").strip()
        if candidate:
            try:
                rows = self._run("MATCH (n) WHERE n.sketch_id = $sk RETURN count(n) AS c",
                                 {"sk": candidate}, timeout=20)
                if rows and rows[0].get("c"):
                    return {"sketch_id": candidate}
            except Exception as e:
                return {"error": f"Neo4j unreachable: {e}"}
        try:
            populated = self._run(
                "MATCH (n) WHERE n.sketch_id IS NOT NULL "
                "RETURN n.sketch_id AS sketch_id, count(n) AS nodes ORDER BY nodes DESC LIMIT 25",
                {}, timeout=25)
        except Exception as e:
            return {"error": f"Neo4j unreachable: {e}"}
        if not populated:
            return {"error": "No sketch in this Neo4j database contains any nodes — nothing has been ingested yet."}
        if len(populated) == 1:
            return {"sketch_id": populated[0]["sketch_id"],
                    "substituted_for": candidate or None,
                    "note": (f"The configured sketch ({candidate}) holds 0 nodes, so the only populated "
                             f"sketch ({populated[0]['sketch_id']}, {populated[0]['nodes']} nodes) was used. "
                             "Update FLOWSINT_SKETCH_ID to make this permanent.") if candidate else None}
        return {"error": (f"The configured sketch ({candidate or 'unset'}) holds 0 nodes and this database has "
                          f"{len(populated)} populated sketches, so the correct one cannot be guessed without "
                          "risking another campaign's data. Pass sketch_id explicitly."),
                "sketches": populated}


class Tools(_SketchMixin):
    def __init__(self):
        self.sketch_id = os.environ.get("FLOWSINT_SKETCH_ID", "")

    def search_entities(
        self,
        query: str,
        entity_type: Optional[str] = None,
        max_results: int = 15,
        sketch_id: Optional[str] = None,
    ) -> str:
        """
        Search the SPOTTER graph for entities matching a keyword.

        :param query: Search keyword — matches nodeLabel and key string properties.
                      Pass an empty string to list all entities of a given type.
        :param entity_type: Optional filter by entity type.
                            Use 'individual' for users, 'device' for computers/hosts,
                            'organization' for groups and domains.
        :param max_results: Maximum number of results to return (default 15).
        :param sketch_id: Optional explicit sketch (campaign) to search. Defaults to the configured one.
        :return: JSON array of matching entities with their key properties.
        """
        scope = self._resolve_sketch(sketch_id)
        if "error" in scope:
            return json.dumps(scope, default=str, indent=2)
        sk = scope["sketch_id"]

        query_l = (query or "").lower().strip()
        etype_l = entity_type.lower().strip() if entity_type else None
        try:
            limit = max(1, min(200, int(max_results or 15)))
        except (TypeError, ValueError):
            limit = 15

        # Same searchable surface the Python filter used: label + sid +
        # email_addresses + full_name + name.
        searchable = (
            "toLower(coalesce(n.nodeLabel, n['nodeProperties.label'], '') + ' ' + "
            "coalesce(n['nodeProperties.sid'], '') + ' ' + "
            "coalesce(toString(n['nodeProperties.email_addresses']), '') + ' ' + "
            "coalesce(n['nodeProperties.full_name'], '') + ' ' + "
            "coalesce(n['nodeProperties.name'], ''))"
        )
        cypher = (
            "MATCH (n) WHERE n.sketch_id = $sk AND n.deleted_at IS NULL "
            + ("AND toLower(coalesce(n.nodeType, '')) = $etype " if etype_l else "")
            + ("AND " + searchable + " CONTAINS $q " if query_l else "")
            + "RETURN elementId(n) AS id, n.nodeType AS type, "
              "coalesce(n.nodeLabel, n['nodeProperties.label'], '') AS label, "
              "n['nodeProperties.sid'] AS sid, "
              "n['nodeProperties.enabled'] AS enabled, "
              "n['nodeProperties.is_admin'] AS is_admin, "
              "n['nodeProperties.active_beacon'] AS active_beacon, "
              "n['nodeProperties.priority_score'] AS priority_score, "
              "n['nodeProperties.ad_max_score'] AS ad_max_score, "
              "n['nodeProperties.alert'] AS alert, "
              "n['nodeProperties.is_high_value'] AS is_high_value, "
              "n['nodeProperties.admin_count'] AS admin_count "
            "ORDER BY coalesce(n['nodeProperties.priority_score'], n['nodeProperties.ad_max_score'], 0) DESC, label ASC "
            "LIMIT $limit"
        )
        params: Dict[str, Any] = {"sk": sk, "limit": limit}
        if etype_l:
            params["etype"] = etype_l
        if query_l:
            params["q"] = query_l

        try:
            rows = self._run(cypher, params)
        except Exception as e:
            return json.dumps({"error": f"Failed to query graph: {e}"})

        # Drop null properties so the payload matches the old "only present keys" shape.
        results = [{k: v for k, v in row.items() if v is not None} for row in rows]

        out: Dict[str, Any] = {"count": len(results), "results": results, "sketch_id": sk}
        if scope.get("note"):
            out["scope_note"] = scope["note"]
        if not results:
            out["note"] = (f"No entity in sketch {sk} matches that filter. The sketch does hold data, so this is a "
                           "genuine miss — try a shorter keyword or drop entity_type.")
        return json.dumps(out, default=str, indent=2)
