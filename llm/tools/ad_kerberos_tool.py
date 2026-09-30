"""
ad_kerberos_tool.py — Open WebUI Tool

Kerberos-abuse finders for the SPOTTER graph: kerberoastable users, AS-REP
roastable users, and Kerberos delegation (unconstrained / constrained / RBCD).
These map to the highest-signal, most-covered AD tradecraft (Rubeus, kerbrute,
Impacket GetUserSPNs / getTGT).

Filtering runs inside Neo4j (transactional HTTP endpoint, same as
ad_attack_paths_tool.py). The previous version downloaded the entire sketch graph
through the Flowsint API on every call — 91.6 MB / ~18.5s on a 12k-node engagement
graph — to return a handful of rows, and failed outright with "404 Graph not found"
whenever FLOWSINT_SKETCH_ID had gone stale.

Sketch scoping: a tool has no campaign context, so the sketch is resolved at call
time — FLOWSINT_SKETCH_ID if it actually holds data, else the only populated sketch.
If several sketches hold data it refuses to guess, so one campaign's data is never
silently substituted for another's.

Neo4j schema:
  Node labels are exactly the nodeType and ARE case-sensitive: AD objects are
  lower-case (individual, device, organization, gpo), enrichment/OSINT nodes are
  CamelCase (DomainBreach, Subdomain, WebAsset, SocialProfile, ...).
  Nested props are FLAT dotted keys: n['nodeProperties.is_kerberoastable'], etc.
  Every node carries sketch_id — ALWAYS scope by it.
  Attack-surface properties set by scripts/sharphound_parser.py:
    is_kerberoastable, spn_count, spns, rc4_only, is_asrep_roastable,
    unconstrained_delegation, constrained_delegation
  Delegation edges: AllowedToDelegate (constrained), AllowedToAct (RBCD)

Install: Open WebUI → Admin → Tools → + New Tool → paste → Save
"""

import json
import os
import requests
from typing import Any, Dict, List, Optional


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return bool(v)


# _truthy() expressed in Cypher. The graph stores these flags as booleans, but the
# Python helper also accepted "true"/"1"/"yes", so accept both rather than silently
# dropping string-valued flags. Format with a dict: _TRUTHY % {"p": "<expr>"}.
_TRUTHY = "(%(p)s = true OR toLower(toString(coalesce(%(p)s, ''))) IN ['true', '1', 'yes'])"


class Tools:
    def __init__(self):
        self.sketch_id = os.environ.get("FLOWSINT_SKETCH_ID", "")

    # ── helpers ──────────────────────────────────────────────────────────────
    # Underscore-prefixed on purpose: Open WebUI turns every PUBLIC method on Tools
    # into a callable tool, and these are not tools.

    def _neo(self, cypher: str, params: Dict[str, Any], timeout: int = 45) -> List[Dict[str, Any]]:
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
        FLOWSINT_SKETCH_ID goes stale whenever the engagement moves to a new sketch.
        Keep in sync with the copies in the other SPOTTER tools.
        """
        candidate = (explicit or self.sketch_id or "").strip()
        if candidate:
            rows = self._neo("MATCH (n) WHERE n.sketch_id = $sk RETURN count(n) AS c",
                             {"sk": candidate}, timeout=20)
            if rows and rows[0].get("c"):
                return candidate
        populated = self._neo(
            "MATCH (n) WHERE n.sketch_id IS NOT NULL "
            "RETURN n.sketch_id AS sketch_id, count(n) AS nodes ORDER BY nodes DESC LIMIT 25", {})
        if not populated:
            raise RuntimeError("no sketch in Neo4j contains any nodes — nothing has been ingested yet")
        if len(populated) > 1:
            raise RuntimeError(
                f"the configured sketch ({candidate or 'unset'}) holds 0 nodes and this database has "
                f"{len(populated)} populated sketches, so the right one cannot be guessed without risking "
                "another campaign's data — set FLOWSINT_SKETCH_ID or pass sketch_id")
        return populated[0]["sketch_id"]

    # ── tools ────────────────────────────────────────────────────────────────

    def find_kerberoastable(self, sketch_id: Optional[str] = None) -> str:
        """
        List all kerberoastable users (accounts with a Service Principal Name).

        Any domain user can request a service ticket for these accounts and crack
        it offline (Rubeus kerberoast / Impacket GetUserSPNs). Accounts flagged
        rc4_only are far cheaper to crack (RC4 vs AES). Admin/high-privilege SPN
        accounts are the top targets.

        :param sketch_id: Optional explicit sketch (campaign). Defaults to the configured one.
        :return: JSON list of kerberoastable users with spn_count, rc4_only,
                 is_admin, department, sorted with admin + rc4_only first.
        """
        try:
            sk = self._resolve_sketch(sketch_id)
            rows = self._neo(
                "MATCH (n:individual) WHERE n.sketch_id = $sk AND n.deleted_at IS NULL AND "
                + (_TRUTHY % {"p": "n['nodeProperties.is_kerberoastable']"}) + " "
                "RETURN n.nodeLabel AS user, n['nodeProperties.sam_account_name'] AS sam, "
                "  n['nodeProperties.spn_count'] AS spn_count, n['nodeProperties.spns'] AS spns, "
                + (_TRUTHY % {"p": "n['nodeProperties.rc4_only']"}) + " AS rc4_only, "
                + (_TRUTHY % {"p": "n['nodeProperties.is_admin']"}) + " AS is_admin, "
                "  n['nodeProperties.department'] AS department, "
                "  n['nodeProperties.enabled'] AS enabled",
                {"sk": sk})
        except Exception as e:
            return json.dumps({"error": f"Graph fetch failed: {e}"})

        out: List[Dict[str, Any]] = list(rows)
        out.sort(key=lambda u: (u["is_admin"], u["rc4_only"], u.get("spn_count") or 0), reverse=True)
        return json.dumps({"count": len(out), "kerberoastable": out, "sketch_id": sk},
                          default=str, indent=2)

    def find_asrep_roastable(self, sketch_id: Optional[str] = None) -> str:
        """
        List users with Kerberos pre-authentication disabled (AS-REP roastable).

        Their AS-REP can be requested without credentials and cracked offline
        (Rubeus asreproast / Impacket GetNPUsers). rc4_only accounts crack faster.

        :param sketch_id: Optional explicit sketch (campaign). Defaults to the configured one.
        :return: JSON list of AS-REP roastable users with rc4_only, is_admin, department.
        """
        try:
            sk = self._resolve_sketch(sketch_id)
            rows = self._neo(
                "MATCH (n:individual) WHERE n.sketch_id = $sk AND n.deleted_at IS NULL AND "
                + (_TRUTHY % {"p": "n['nodeProperties.is_asrep_roastable']"}) + " "
                "RETURN n.nodeLabel AS user, n['nodeProperties.sam_account_name'] AS sam, "
                + (_TRUTHY % {"p": "n['nodeProperties.rc4_only']"}) + " AS rc4_only, "
                + (_TRUTHY % {"p": "n['nodeProperties.is_admin']"}) + " AS is_admin, "
                "  n['nodeProperties.department'] AS department, "
                "  n['nodeProperties.enabled'] AS enabled",
                {"sk": sk})
        except Exception as e:
            return json.dumps({"error": f"Graph fetch failed: {e}"})

        out: List[Dict[str, Any]] = list(rows)
        out.sort(key=lambda u: (u["is_admin"], u["rc4_only"]), reverse=True)
        return json.dumps({"count": len(out), "asrep_roastable": out, "sketch_id": sk},
                          default=str, indent=2)

    def find_delegation_paths(self, sketch_id: Optional[str] = None) -> str:
        """
        Enumerate Kerberos delegation abuse surface: unconstrained, constrained,
        and resource-based constrained delegation (RBCD).

        - Unconstrained: coerce the host (PetitPotam/PrinterBug) and capture a DC
          TGT (krbrelayx). DCs are always unconstrained.
        - Constrained (AllowedToDelegate): S4U2Proxy to impersonate a user to the
          target service (Rubeus).
        - RBCD (AllowedToAct): if you control the source principal, S4U2Self +
          S4U2Proxy to impersonate any user to the target host (Rubeus).

        :param sketch_id: Optional explicit sketch (campaign). Defaults to the configured one.
        :return: JSON with three lists — unconstrained[], constrained[], rbcd[].
        """
        try:
            sk = self._resolve_sketch(sketch_id)
            unconstrained = self._neo(
                "MATCH (n) WHERE n.sketch_id = $sk AND n.deleted_at IS NULL AND "
                + (_TRUTHY % {"p": "n['nodeProperties.unconstrained_delegation']"}) + " "
                "RETURN n.nodeLabel AS principal, n.nodeType AS type, "
                + (_TRUTHY % {"p": "n['nodeProperties.is_dc']"}) + " AS is_dc",
                {"sk": sk})
            # Both delegation edge types in one query. The old label() helper fell back
            # to the node id when a label was missing; elementId() is that same fallback.
            edges = self._neo(
                "MATCH (a)-[r:AllowedToDelegate|AllowedToAct]->(b) "
                "WHERE a.sketch_id = $sk AND b.sketch_id = $sk "
                "  AND a.deleted_at IS NULL AND b.deleted_at IS NULL "
                "RETURN type(r) AS rel, "
                "  coalesce(a.nodeLabel, a['nodeProperties.name'], elementId(a)) AS principal, "
                "  coalesce(b.nodeLabel, b['nodeProperties.name'], elementId(b)) AS target",
                {"sk": sk})
        except Exception as e:
            return json.dumps({"error": f"Graph fetch failed: {e}"})

        constrained = [{"principal": e["principal"], "target": e["target"]}
                       for e in edges if e["rel"] == "AllowedToDelegate"]
        rbcd        = [{"principal": e["principal"], "target": e["target"]}
                       for e in edges if e["rel"] == "AllowedToAct"]

        return json.dumps({
            "unconstrained": list(unconstrained),
            "constrained":   constrained,
            "rbcd":          rbcd,
            "sketch_id":     sk,
        }, default=str, indent=2)
