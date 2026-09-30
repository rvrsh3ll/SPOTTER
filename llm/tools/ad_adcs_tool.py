"""
ad_adcs_tool.py — Open WebUI Tool

AD Certificate Services (ADCS) and coercion+relay finders. Maps to Certipy /
Certify (ESC1/ESC8) and Coercer / PetitPotam / krbrelayx tradecraft.

Filtering runs inside Neo4j (transactional HTTP endpoint, same as
ad_attack_paths_tool.py). The previous version downloaded the entire sketch graph
through the Flowsint API on every call — 91.6 MB / ~18.5s on a 12k-node engagement
graph — and failed with "404 Graph not found" whenever FLOWSINT_SKETCH_ID went stale.
Node labels are exactly the nodeType and ARE case-sensitive; nested props are FLAT
dotted keys (n['nodeProperties.esc1']); every node carries sketch_id.

Legacy Flowsint API graph shape, for reference:
  nds — node objects: id, nodeLabel, nodeType, nodeProperties
  rls — edge objects: id, source, target, label
  ADCS node types (set by scripts/sharphound_parser.py):
    certtemplate  — props: esc1, enrollee_supplies_subject, client_auth_eku,
                    requires_manager_approval, enabled, esc_vulnerabilities
    enterpriseca  — props: esc8, web_enrollment, dns_hostname, user_specified_san
  ADCS edges: Enroll, AutoEnroll, ManageCA, ManageCertificates,
              WritePKIEnrollmentFlag, WritePKINameFlag, PublishedTo (template→CA)
  Coercion: devices with unconstrained_delegation, is_dc, and CoerceToTGT edges

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


# _truthy() expressed in Cypher: the graph stores these flags as booleans, but the
# Python helper also accepted "true"/"1"/"yes", so accept both rather than silently
# dropping string-valued flags. Format with a dict: _TRUTHY % {"p": "<expr>"}.
_TRUTHY = "(%(p)s = true OR toLower(toString(coalesce(%(p)s, ''))) IN ['true', '1', 'yes'])"


class Tools:
    def __init__(self):
        self.sketch_id = os.environ.get("FLOWSINT_SKETCH_ID", "")

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

    def find_adcs_esc(self, sketch_id: Optional[str] = None) -> str:
        """
        Find AD Certificate Services misconfigurations (ESC1 / ESC8) and who can
        abuse them.

        - ESC1: a certificate template lets the enrollee supply an arbitrary SAN,
          has a client-auth EKU, needs no manager approval — any principal with
          Enroll can request a cert authenticating as any user (Certipy req
          --upn administrator@domain).
        - ESC8: an enterprise CA exposes HTTP web enrollment — coerce a DC
          (PetitPotam) and NTLM-relay to the CA to get a DC cert (Certipy relay).

        :param sketch_id: Optional explicit sketch (campaign). Defaults to the configured one.
        :return: JSON with esc1_templates[] (incl. principals holding Enroll) and
                 esc8_cas[] (web-enrollment CAs).
        """
        try:
            sk = self._resolve_sketch(sketch_id)
            # Enrollees come back per template in one query; the old label() helper
            # fell back to the node id, which is what elementId() gives.
            esc1 = self._neo(
                "MATCH (t) WHERE t.sketch_id = $sk AND t.deleted_at IS NULL "
                "  AND toLower(coalesce(t.nodeType, '')) = 'certtemplate' AND "
                + (_TRUTHY % {"p": "t['nodeProperties.esc1']"}) + " "
                "OPTIONAL MATCH (p)-[r:Enroll|AutoEnroll]->(t) WHERE p.sketch_id = $sk "
                "RETURN t.nodeLabel AS template, "
                + (_TRUTHY % {"p": "t['nodeProperties.enabled']"}) + " AS enabled, "
                "  [x IN collect(DISTINCT coalesce(p.nodeLabel, p['nodeProperties.name'], elementId(p))) "
                "     WHERE x IS NOT NULL] AS enrollees, "
                "  t['nodeProperties.esc_vulnerabilities'] AS esc",
                {"sk": sk})
            esc8 = self._neo(
                "MATCH (c) WHERE c.sketch_id = $sk AND c.deleted_at IS NULL "
                "  AND toLower(coalesce(c.nodeType, '')) = 'enterpriseca' AND "
                + (_TRUTHY % {"p": "c['nodeProperties.esc8']"}) + " "
                "RETURN c.nodeLabel AS ca, c['nodeProperties.dns_hostname'] AS dns_hostname, "
                "  true AS web_enrollment",
                {"sk": sk})
        except Exception as e:
            return json.dumps({"error": f"Graph fetch failed: {e}"})

        return json.dumps({"esc1_templates": list(esc1), "esc8_cas": list(esc8), "sketch_id": sk},
                          default=str, indent=2)

    def find_coercion_relay_targets(self, sketch_id: Optional[str] = None) -> str:
        """
        Identify NTLM coercion + relay opportunities.

        Coercion sources (make a host authenticate to you): domain controllers and
        any host — via PetitPotam (MS-EFSR), PrinterBug (MS-RPRN), DFSCoerce
        (MS-DFSNM). Relay destinations: unconstrained-delegation hosts (capture
        TGT via krbrelayx), ESC8 web-enrollment CAs (relay to ADCS for a cert),
        and LDAP on DCs (relay to grant RBCD / DCSync).

        :param sketch_id: Optional explicit sketch (campaign). Defaults to the configured one.
        :return: JSON with coercible_dcs[], unconstrained_hosts[], esc8_cas[] —
                 the building blocks of a coerce→relay chain.
        """
        try:
            sk = self._resolve_sketch(sketch_id)
            dcs = self._neo(
                "MATCH (n) WHERE n.sketch_id = $sk AND n.deleted_at IS NULL "
                "  AND toLower(coalesce(n.nodeType, '')) = 'device' AND "
                + (_TRUTHY % {"p": "n['nodeProperties.is_dc']"}) + " "
                "RETURN n.nodeLabel AS host", {"sk": sk})
            unconstrained = self._neo(
                "MATCH (n) WHERE n.sketch_id = $sk AND n.deleted_at IS NULL AND "
                + (_TRUTHY % {"p": "n['nodeProperties.unconstrained_delegation']"}) + " "
                "RETURN n.nodeLabel AS host, n.nodeType AS type", {"sk": sk})
            esc8 = self._neo(
                "MATCH (c) WHERE c.sketch_id = $sk AND c.deleted_at IS NULL "
                "  AND toLower(coalesce(c.nodeType, '')) = 'enterpriseca' AND "
                + (_TRUTHY % {"p": "c['nodeProperties.esc8']"}) + " "
                "RETURN c.nodeLabel AS ca, c['nodeProperties.dns_hostname'] AS dns_hostname",
                {"sk": sk})
        except Exception as e:
            return json.dumps({"error": f"Graph fetch failed: {e}"})

        return json.dumps({
            "coercible_dcs":       [d["host"] for d in dcs],
            "unconstrained_hosts": list(unconstrained),
            "esc8_cas":            list(esc8),
            "note": "Chain: coerce a DC (PetitPotam) → relay to an ESC8 CA "
                    "(Certipy) or to an unconstrained host to capture its TGT.",
            "sketch_id": sk,
        }, default=str, indent=2)
