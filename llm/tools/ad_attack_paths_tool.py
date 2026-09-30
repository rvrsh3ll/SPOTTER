"""
ad_attack_paths_tool.py — Open WebUI Tool

BloodHound-style graph queries over Neo4j: shortest path to Tier-0 (Domain
Admins / Enterprise Admins / DCs) and GPO-abuse enumeration. Uses the Neo4j
transactional HTTP endpoint directly so it can run shortestPath().

Neo4j schema:
  Node labels (lowercase): individual, device, organization, gpo, certtemplate,
    enterpriseca
  Nested props are FLAT dotted keys: n['nodeProperties.is_dc'], etc.
  Every node/edge carries sketch_id — ALWAYS scope by it.
  Attack edges (relationship TYPES): GenericAll, WriteDacl, WriteOwner,
    GenericWrite, AllExtendedRights, AddAllowedToAct, ForceChangePassword,
    AddMember, Owns, ReadLAPSPassword, WriteAccountRestrictions,
    AddKeyCredentialLink, WriteSPN, ReadGMSAPassword, DCSync, GetChanges,
    GetChangesAll, AllowedToAct, AllowedToDelegate, HasSIDHistory, CoerceToTGT,
    ManageCA, ManageCertificates, WritePKIEnrollmentFlag, WritePKINameFlag,
    Enroll, WriteGPLink, SQLAdmin, ExecuteDCOM, CanPSRemote, CanRDP, MEMBER_OF,
    LOCAL_ADMIN, HAS_SESSION, GpLink, PublishedTo, TrustedBy

Install: Open WebUI → Admin → Tools → + New Tool → paste → Save
"""

import json
import os
import requests
from typing import Any, Dict, List

# Attack + navigational edge types used for path finding (keep aligned with
# TRAVERSAL_LABELS in attack_path_tool.py).
_REL_TYPES = [
    "GenericAll", "WriteDacl", "WriteOwner", "GenericWrite", "AllExtendedRights",
    "AddAllowedToAct", "ForceChangePassword", "AddMember", "Owns",
    "ReadLAPSPassword", "WriteAccountRestrictions", "AddKeyCredentialLink",
    "WriteSPN", "ReadGMSAPassword", "DCSync", "GetChanges", "GetChangesAll",
    "AllowedToAct", "AllowedToDelegate", "HasSIDHistory", "CoerceToTGT",
    "ManageCA", "ManageCertificates", "WritePKIEnrollmentFlag", "WritePKINameFlag",
    "Enroll", "WriteGPLink", "SQLAdmin", "ExecuteDCOM", "CanPSRemote", "CanRDP",
    "MEMBER_OF", "LOCAL_ADMIN", "HAS_SESSION", "GpLink", "PublishedTo", "TrustedBy",
]
_REL_PATTERN = "|".join(_REL_TYPES)


class Tools:
    def __init__(self):
        self.neo4j_url  = os.environ.get("NEO4J_HTTP_URL", "http://neo4j:7474")
        self.neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
        self.neo4j_pass = os.environ.get("NEO4J_PASSWORD", "")
        self.sketch_id  = os.environ.get("FLOWSINT_SKETCH_ID", "")

    def _run(self, cypher: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        endpoint = f"{self.neo4j_url}/db/neo4j/tx/commit"
        payload = {"statements": [{
            "statement": cypher, "parameters": params, "resultDataContents": ["row"],
        }]}
        resp = requests.post(endpoint, json=payload,
                             auth=(self.neo4j_user, self.neo4j_pass), timeout=25)
        resp.raise_for_status()
        data = resp.json()
        if data.get("errors"):
            raise RuntimeError(f"Neo4j errors: {data['errors']}")
        results = data.get("results", [{}])
        if not results:
            return []
        cols = results[0].get("columns", [])
        return [dict(zip(cols, r.get("row", []))) for r in results[0].get("data", [])]

    def get_shortest_path_to_tier0(self, identifier: str = "", max_hops: int = 8) -> str:
        """
        Find the shortest attack path(s) to Tier-0 (Domain Admins / Enterprise
        Admins groups, or any Domain Controller). This is BloodHound's signature
        query: given a foothold, how few steps to domain compromise.

        :param identifier: Username / SAM / SID of the starting (owned) principal.
               Leave empty to search from ALL compromised users (active beacon or
               stealer-log), falling back to all users if none are flagged.
        :param max_hops: Maximum path length to consider (1-10, default 8).
        :return: JSON list of shortest paths, each with source, target, hops, and
                 the ordered node + edge sequence — sorted shortest first.
        """
        try:
            max_hops = max(1, min(10, int(max_hops)))
        except Exception:
            max_hops = 8

        ident = (identifier or "").strip().lower()
        if ident:
            src_pred = ("(toLower(s.nodeLabel) CONTAINS $ident "
                        "OR toLower(coalesce(s['nodeProperties.sam_account_name'],'')) CONTAINS $ident "
                        "OR toLower(coalesce(s['nodeProperties.sid'],'')) CONTAINS $ident)")
        else:
            src_pred = ("(s['nodeProperties.active_beacon'] = true "
                        "OR s['nodeProperties.has_stealer_log'] = true)")

        cypher = f"""
MATCH (s:individual), (t)
WHERE s.sketch_id = $sk AND t.sketch_id = $sk
  AND s.deleted_at IS NULL AND t.deleted_at IS NULL AND s <> t
  AND {src_pred}
  AND (
      t['nodeProperties.is_dc'] = true
      OR t['nodeProperties.is_high_value'] = true
      OR toLower(t.nodeLabel) CONTAINS 'domain admins'
      OR toLower(t.nodeLabel) CONTAINS 'enterprise admins'
  )
MATCH p = shortestPath((s)-[:{_REL_PATTERN}*1..{max_hops}]->(t))
RETURN s.nodeLabel AS source,
       t.nodeLabel AS target,
       length(p)   AS hops,
       [n IN nodes(p) | n.nodeLabel]        AS path_nodes,
       [r IN relationships(p) | type(r)]    AS path_edges
ORDER BY hops ASC
LIMIT 15
"""
        try:
            rows = self._run(cypher, {"sk": self.sketch_id, "ident": ident})
        except Exception as e:
            return json.dumps({"error": str(e)})
        if not rows:
            return json.dumps({"paths": [], "note": "No path to Tier-0 found for the given source(s)."})
        return json.dumps({"count": len(rows), "paths": rows}, default=str, indent=2)

    def find_gpo_abuse(self) -> str:
        """
        Find principals that can edit a GPO which is linked to an OU or domain —
        i.e. can push code to every computer/user in that scope (a lateral-movement
        and Tier-0 escalation primitive; SharpGPOAbuse / pyGPOAbuse).

        :return: JSON list of {principal, right, gpo, applies_to, scope_high_value},
                 highest-value scopes first.
        """
        cypher = """
MATCH (p)-[r]->(g:gpo)-[:GpLink]->(scope)
WHERE g.sketch_id = $sk AND p.sketch_id = $sk AND g.deleted_at IS NULL
  AND type(r) IN ['WriteGPLink','WriteDacl','WriteOwner','GenericAll','GenericWrite']
RETURN p.nodeLabel AS principal,
       type(r)     AS right,
       g.nodeLabel AS gpo,
       scope.nodeLabel AS applies_to,
       coalesce(scope['nodeProperties.is_high_value'], false) AS scope_high_value
ORDER BY scope_high_value DESC
LIMIT 50
"""
        try:
            rows = self._run(cypher, {"sk": self.sketch_id})
        except Exception as e:
            return json.dumps({"error": str(e)})
        return json.dumps({"count": len(rows), "gpo_abuse": rows}, default=str, indent=2)
