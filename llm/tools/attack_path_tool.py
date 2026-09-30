"""
attack_path_tool.py — Open WebUI Tool

Scores and returns the top attack paths reachable from a compromised Individual
node in the SPOTTER graph.

Traversal runs inside Neo4j via the transactional HTTP endpoint (same approach as
ad_attack_paths_tool.py), NOT by pulling the whole sketch graph and walking it in
Python. The previous version did the latter: one /graph fetch plus a recursive DFS
with no bounds. On a mid-sized engagement graph (~10k nodes, hundreds of
thousands of ACE edges, maximum out-degree in the thousands) that is exponential —
a Domain Admin source has millions of paths within 4 hops over the heavy ACE
edges alone, and the tool ran for many minutes without returning. It now answers in well under a second.

Three bounded searches replace the DFS:
  stage 1  shortestPath to high-value endpoints (DA/EA/SA/Administrators groups,
           is_high_value, DCs) — one path per endpoint, complete up to target_cap.
  stage 2  chains over the heaviest ACE edges to ANY endpoint, capped. Paths to
           ordinary objects can outscore high-value ones, so omitting this would
           change the ranking. Widens to medium-weight edges only when the heavy
           search did not hit its cap.
  stage 3  direct 1-hop edges, so a low-privilege source always gets its
           immediate ACEs even when it reaches nothing high-value.

Paths are node-unique (Cypher's default uniqueness is per-relationship, and this
graph contains ACE self-loops and DOMAIN ADMINS <-> ADMINISTRATORS cycles that
would otherwise inflate scores) and skip soft-deleted nodes. Every cap that is hit
is reported in the response, so a sampled ranking is never presented as complete.
Scoring is unchanged from the DFS version.

Neo4j schema:
  Node labels are exactly the nodeType and ARE case-sensitive: AD objects are
  lower-case (individual, device, organization, gpo), enrichment/OSINT nodes are
  CamelCase (DomainBreach, Subdomain, WebAsset, SocialProfile, ...).
  Nested props are FLAT dotted keys: n['nodeProperties.is_dc'], etc.
  Every node carries sketch_id — ALWAYS scope by it.
  ACE rights ARE the relationship type (GenericAll, WriteDacl, MEMBER_OF, etc.)

Scoring:
  GenericAll=10, WriteDacl=9, WriteOwner=8, GenericWrite/AllExtendedRights=7
  AddAllowedToAct=7, ForceChangePassword=6, AddMember/Owns=5
  WriteAccountRestrictions/AddKeyCredentialLink=5, ReadLAPSPassword/GetChanges=4
  WriteSPN/ReadGMSAPassword=4, DCSync/GetChangesAll=10
  HasSIDHistory/CoerceToTGT/WriteGPLink/ManageCA=8, AllowedToAct/AllowedToDelegate=7
  ManageCertificates/WritePKIEnrollmentFlag/WritePKINameFlag=7
  SQLAdmin=5, Enroll/ExecuteDCOM/CanPSRemote=4, CanRDP=3
  +5 target is a DC, +8 target is DA/EA group, -2 per hop
  +6 Enroll on an ESC1 template, +3 target kerberoastable-admin or unconstrained-deleg

Install: Open WebUI → Admin → Tools → + New Tool → paste → Save
"""

import json
import os
import sys
import requests
from typing import Any, Dict, List, Optional

for _scripts_dir in (
    os.environ.get("SPOTTER_SCRIPTS_DIR", "/data/scripts"),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts")),
):
    if _scripts_dir and os.path.isdir(_scripts_dir) and _scripts_dir not in sys.path:
        sys.path.insert(0, _scripts_dir)

from high_value_tech import HIGH_VALUE_TECH
from asset_labels import TECH_EDGES, TECH_TYPES_LOWER, rel_pattern
from individual_lookup import individual_resolve_query, normalize_identifier


# ─────────────────────────────────────────────────────────────────────────────
# EDGE SCORES — keep in sync across ALL FIVE copies (tradecraft update 2026-07):
#   llm/tools/attack_path_tool.py  (this file)   · llm/tools/dossier_tool.py
#   flowsint-custom/enrichers/ad_permission_enricher.py
#   flowsint-custom/types/ad_permission.py
#   n8n-workflows/04-attack-path-analyzer.json  ("Score Attack Paths" node)
# ─────────────────────────────────────────────────────────────────────────────
ACE_SCORES: Dict[str, int] = {
    "GenericAll": 10, "WriteDacl": 9, "WriteOwner": 8,
    "GenericWrite": 7, "AllExtendedRights": 7, "AddAllowedToAct": 7,
    "ForceChangePassword": 6, "AddMember": 5, "Owns": 5,
    "ReadLAPSPassword": 4, "GetChanges": 4,
    "DCSync": 10, "GetChangesAll": 10,
    "WriteAccountRestrictions": 5, "AddKeyCredentialLink": 5,
    "WriteSPN": 4, "ReadGMSAPassword": 4,
    # ── Kerberos delegation / SID history ──
    "AllowedToAct": 7,           # RBCD: impersonate to the target host (S4U)
    "AllowedToDelegate": 7,      # constrained delegation to target SPN/host
    "HasSIDHistory": 8,          # inherits the historical SID's privileges
    "CoerceToTGT": 8,            # coerce (PetitPotam/PrinterBug) → capture TGT
    # ── ADCS abuse (Certipy / Certify) ──
    "ManageCA": 8, "ManageCertificates": 7,
    "WritePKIEnrollmentFlag": 7, "WritePKINameFlag": 7,
    "Enroll": 4,                 # enrollment right (score amplified on vuln templates)
    # ── GPO abuse ──
    "WriteGPLink": 8,
    # ── Lateral movement (from LocalGroups / UserRights) ──
    "SQLAdmin": 5, "ExecuteDCOM": 4, "CanPSRemote": 4, "CanRDP": 3,
}

# Navigational (non-privilege) edges the traversal may chain through to extend a
# path: GpLink (GPO→OU), PublishedTo (template→CA), TrustedBy (domain→domain).
NAV_LABELS = {"GpLink", "PublishedTo", "TrustedBy"}
TRAVERSAL_LABELS = (
    set(ACE_SCORES.keys()) | NAV_LABELS | {"MEMBER_OF", "HAS_SESSION", "LOCAL_ADMIN"}
)
# Connectors carry no privilege of their own but are how privilege is inherited or
# applied, so they stay available in every tier of the chain search.
CONNECTORS = NAV_LABELS | {"MEMBER_OF"}
# Tiered chain search: high scores come from the heaviest edges, so those are
# searched first and the sample is concentrated where the top paths actually live.
HEAVY_LABELS  = sorted(CONNECTORS | {r for r, w in ACE_SCORES.items() if w >= 8})
MEDIUM_LABELS = sorted(CONNECTORS | {r for r, w in ACE_SCORES.items() if w >= 5})
ALL_LABELS    = sorted(TRAVERSAL_LABELS)
DA_PATTERN = ("domain admins", "enterprise admins", "schema admins", "administrators")
DC_BONUS   = 5
DA_BONUS   = 8
HOP_PENALTY = 2
EXPLOIT_TRUST_BONUS = {"high": 6, "medium": 4, "low": 2}
EXPLOIT_BASIS_SCALE = {"shodan": 1.0, "cpe": 1.0, "mixed": 0.75, "keyword": 0.5}
EXPLOIT_CRITICAL_BONUS = 2
EXPLOIT_CRITICAL_CVSS = 9.0
EXPLOIT_INTERNET_BONUS = 2
EXPLOIT_MAX_BONUS = max(0, min(25, int(os.environ.get("EXPLOIT_PATH_MAX_BONUS", "8") or 8)))
EXPLOIT_CAVEAT = (
    "Public exploit code is UNVETTED third-party GitHub source: read it before "
    "running it, never on engagement infrastructure."
)

TECH_BONUS = 5


# Per-hop projection returned by every Cypher stage. Order matters — _score_path
# indexes into it. Keeping it a positional list keeps the payload small on the
# thousands of rows a chain search can return.
_HOP_FIELDS = (
    "coalesce(n.nodeLabel, n['nodeProperties.label'], n['nodeProperties.name'], elementId(n))",
    "coalesce(n.nodeType, '')",
    "coalesce(n['nodeProperties.is_dc'], false)",
    "coalesce(n['nodeProperties.is_admin'], false)",
    "coalesce(n['nodeProperties.is_kerberoastable'], false)",
    "coalesce(n['nodeProperties.is_asrep_roastable'], false)",
    "coalesce(n['nodeProperties.unconstrained_delegation'], false)",
    "coalesce(n['nodeProperties.esc1'], false)",
    "elementId(n)",
)
_RETURN_HOPS = (
    "RETURN [n IN tail(nodes(p)) | [" + ", ".join(_HOP_FIELDS) + "]] AS hop_nodes, "
    "[r IN relationships(p) | type(r)] AS rels, length(p) AS hops"
)
# Campaign isolation plus soft-delete: every hop must be live and in this sketch.
_LIVE_IN_SKETCH = (
    "WHERE ALL (n IN nodes(p) WHERE n.sketch_id = $sk AND n.deleted_at IS NULL) "
)
# Node uniqueness — Cypher's default is per-relationship, so without this a path
# can revisit a node through a self-loop or cycle and inflate its score.
_NO_REVISIT = _LIVE_IN_SKETCH + "AND ALL (n IN nodes(p) WHERE single(x IN nodes(p) WHERE x = n)) "
# Endpoints that earn the DA / DC scoring bonuses.
_HIGH_VALUE = (
    "(t['nodeProperties.is_dc'] = true OR t['nodeProperties.is_high_value'] = true"
    + "".join(f" OR toLower(coalesce(t.nodeLabel, '')) CONTAINS '{p}'" for p in DA_PATTERN)
    + ")"
)


class Tools:
    def __init__(self):
        self.neo4j_url  = os.environ.get("NEO4J_HTTP_URL", "http://neo4j:7474")
        self.neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
        self.neo4j_pass = os.environ.get("NEO4J_PASSWORD", "")
        self.sketch_id  = os.environ.get("FLOWSINT_SKETCH_ID", "")

    def _run(self, cypher: str, params: Dict[str, Any], timeout: int = 60) -> List[Dict[str, Any]]:
        endpoint = f"{self.neo4j_url}/db/neo4j/tx/commit"
        resp = requests.post(
            endpoint,
            json={"statements": [{"statement": cypher, "parameters": params,
                                  "resultDataContents": ["row"]}]},
            auth=(self.neo4j_user, self.neo4j_pass), timeout=timeout,
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
        """Which sketch to read. Container env is fixed at creation time, so
        FLOWSINT_SKETCH_ID goes stale whenever the engagement moves to a new sketch.
        Falls back to the only populated sketch and refuses to guess when several
        are populated, so campaigns cannot be mixed up. Keep in sync with the copies
        in flowsint_search_tool.py and dossier_tool.py.
        """
        candidate = (explicit or self.sketch_id or "").strip()
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
                    "note": (f"The configured sketch ({candidate}) holds 0 nodes, so the only populated sketch "
                             f"({populated[0]['sketch_id']}, {populated[0]['nodes']} nodes) was used. Update "
                             "FLOWSINT_SKETCH_ID to make this permanent.") if candidate else None}
        return {"error": (f"The configured sketch ({candidate or 'unset'}) holds 0 nodes and this database has "
                          f"{len(populated)} populated sketches, so the correct one cannot be guessed without "
                          "risking another campaign's data. Pass sketch_id explicitly."),
                "sketches": populated}

    def _truthy(self, v: Any) -> bool:
        if isinstance(v, bool):
            return v
        return str(v).strip().lower() in ("true", "1", "yes")

    def _ival(self, v: Any, default: int = 0) -> int:
        try:
            return int(float(str(v).strip()))
        except (TypeError, ValueError):
            return default

    def _jlist(self, v: Any) -> list:
        if isinstance(v, list):
            return v
        if isinstance(v, str) and v.strip():
            try:
                parsed = json.loads(v)
            except (TypeError, ValueError):
                return []
            return parsed if isinstance(parsed, list) else []
        return []

    def _exploit_bonus(self, fact: Dict[str, Any]) -> int:
        base = EXPLOIT_TRUST_BONUS.get(fact.get("trust"), EXPLOIT_TRUST_BONUS["low"])
        if fact.get("critical"):
            base += EXPLOIT_CRITICAL_BONUS
        if fact.get("internet_facing"):
            base += EXPLOIT_INTERNET_BONUS
        scaled = base * EXPLOIT_BASIS_SCALE.get(fact.get("match"), EXPLOIT_BASIS_SCALE["keyword"])
        return max(0, min(EXPLOIT_MAX_BONUS, int(round(scaled))))

    def _exploit_fact(self, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self._truthy(row.get("exploit_available")):
            return None
        trust = ""
        for repo in self._jlist(row.get("top_pocs")):
            if isinstance(repo, dict) and repo.get("trust"):
                trust = str(repo["trust"]).strip().lower()
                break
        critical = False
        cve_ids = []
        for cve in self._jlist(row.get("cves")):
            if not isinstance(cve, dict) or not self._truthy(cve.get("exploit_available")):
                continue
            cve_id = cve.get("cve_id") or cve.get("id")
            if cve_id:
                cve_ids.append(str(cve_id))
            try:
                critical = critical or float(cve.get("base_score") or 0) >= EXPLOIT_CRITICAL_CVSS
            except (TypeError, ValueError):
                pass
        asset = (str(row.get("name") or row.get("product") or row.get("label") or "(unnamed component)").strip()
                 + " " + str(row.get("version") or "").strip()).strip()
        fact = {
            "asset": asset,
            "trust": trust or "low",
            "poc_count": self._ival(row.get("poc_count")),
            "match": str(row.get("cve_match_basis") or "keyword").strip().lower(),
            "cves": cve_ids[:5],
            "critical": critical,
            "internet_facing": str(row.get("source") or "").strip().lower() == "domain-recon",
        }
        fact["bonus"] = self._exploit_bonus(fact)
        return fact if fact["bonus"] else None

    def _fetch_exploit_index(self, node_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        node_ids = sorted({str(n) for n in node_ids if n})[:2000]
        if not node_ids:
            return {}
        # The carrier pattern and the tech-layer label set both come from
        # scripts/asset_labels.py, so this tool and WF04 walk the same graph.
        #
        # The label test is toLower()'d and parameterized. It used to be
        # `IN ['Technology', 'Service']`, matched case-SENSITIVELY: which spelling
        # a node carries is decided by its writer (fc.add_node preserves case,
        # batch_import lowercases), so on a graph holding 141 lowercase
        # `technology` nodes and 38 PascalCase `Service` ones this saw 3 of the 65
        # exploit-bearing nodes and reported success. That is the WF04-vs-chat-tool
        # score disagreement in issues.md, "Confirmed limitations" item 3.
        #
        # Node types CAN be parameterized; relationship types cannot, which is why
        # rel_pattern() validates the shape before interpolating.
        _carrier = "-[:" + rel_pattern(TECH_EDGES) + "]-"
        cypher = (
            "MATCH (a) WHERE elementId(a) IN $ids AND a.sketch_id = $sk AND a.deleted_at IS NULL "
            "MATCH (a)" + _carrier + "(x) "
            "WHERE x.sketch_id = $sk AND x.deleted_at IS NULL "
            "  AND toLower(coalesce(x.nodeType, '')) IN $tech_types "
            "OPTIONAL MATCH (x)" + _carrier + "(y) "
            "WHERE y.sketch_id = $sk AND y.deleted_at IS NULL "
            "  AND toLower(coalesce(y.nodeType, '')) IN $tech_types "
            "WITH a, collect(DISTINCT x) + collect(DISTINCT y) AS candidates "
            "UNWIND candidates AS t "
            "WITH a, t WHERE t IS NOT NULL AND (t['nodeProperties.exploit_available'] = true "
            "  OR toLower(toString(t['nodeProperties.exploit_available'])) IN ['true', '1', 'yes']) "
            "RETURN elementId(a) AS asset_id, collect({"
            "label: coalesce(t.nodeLabel, ''), "
            "name: t['nodeProperties.name'], product: t['nodeProperties.product'], "
            "version: t['nodeProperties.version'], source: t['nodeProperties.source'], "
            "exploit_available: t['nodeProperties.exploit_available'], poc_count: t['nodeProperties.poc_count'], "
            "top_pocs: t['nodeProperties.top_pocs'], cves: t['nodeProperties.cves'], "
            "cve_match_basis: t['nodeProperties.cve_match_basis']}) AS facts"
        )
        try:
            rows = self._run(
                cypher,
                {"sk": self.sketch_id, "ids": node_ids,
                 "tech_types": sorted(TECH_TYPES_LOWER)},
                timeout=30,
            )
        except Exception:
            return {}
        index: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            best = None
            for raw in row.get("facts") or []:
                fact = self._exploit_fact(raw or {})
                if fact and (best is None or fact["bonus"] > best["bonus"]):
                    best = fact
            if best:
                index[row["asset_id"]] = best
        return index

    def _step_exploit(self, fact: Dict[str, Any]) -> Dict[str, Any]:
        return {k: fact[k] for k in ("bonus", "asset", "trust", "poc_count", "match", "cves")}

    def _score_path(self, hop_nodes: list, rels: list, hv_tech: int,
                    exploit_index: Optional[Dict[str, Dict[str, Any]]] = None) -> Optional[dict]:
        """Score one path with the same formula the previous DFS used."""
        if not rels or len(hop_nodes) < len(rels):
            return None
        exploit_index = exploit_index or {}
        steps = []
        for i, right in enumerate(rels):
            hop      = hop_nodes[i]
            tgt_lbl  = hop[0] or ""
            tgt_type = hop[1] or ""
            tgt_id   = hop[8] if len(hop) > 8 else ""
            ace_score = ACE_SCORES.get(right, 1)
            bonus = 0
            if hop[2]:                                       # is_dc
                bonus += DC_BONUS
            if any(p in str(tgt_lbl).lower() for p in DA_PATTERN):
                bonus += DA_BONUS
            # Amplify paths when the source user has high-value tech correlated with AD rights
            if hv_tech and right in ACE_SCORES:
                bonus += TECH_BONUS * hv_tech
            # Kerberos-abuse amplifiers: taking over a roastable/delegating target
            # yields a crackable/impersonatable credential.
            if hop[4] and (hop[3] or bonus):                 # is_kerberoastable, is_admin
                bonus += 3
            if hop[5]:                                       # is_asrep_roastable
                bonus += 2
            if hop[6]:                                       # unconstrained_delegation
                bonus += 3
            # Enrolling in a template already flagged ESC1 is a direct DA path.
            if right == "Enroll" and hop[7]:
                bonus += 6
            ex = exploit_index.get(tgt_id)
            if ex:
                bonus += ex["bonus"]
            step = {"node": tgt_lbl, "type": tgt_type, "edge": right,
                    "hop_score": ace_score + bonus - (i * HOP_PENALTY)}
            if ex:
                step["exploit"] = self._step_exploit(ex)
            steps.append(step)
        last = steps[-1]
        return {
            "path":              steps,
            "final_target":      last["node"],
            "final_target_type": last["type"],
            "hops":              len(steps),
            "score":             max(0, sum(s["hop_score"] for s in steps)),
            "tech_bonus_applied": bool(hv_tech and any(r in ACE_SCORES for r in rels)),
            "exploit_bonus":      sum(s.get("exploit", {}).get("bonus", 0) for s in steps),
        }

    def get_attack_paths(self, identifier: str, top_n: int = 5,
                         max_hops: int = 4, chain_cap: int = 4000,
                         sketch_id: Optional[str] = None) -> str:
        """
        Return the top scored attack paths reachable from a compromised Individual.

        :param identifier: Label, display name, SID, username, email, or node id. Matching is scripts/individual_lookup.py.
        :param top_n: Number of top paths to return (default 5).
        :param max_hops: Maximum path length, 1-5 (default 4).
        :param chain_cap: Row cap for the ACE-chain search (default 4000). Raise it for a wider search when the response reports that the cap was hit.
        :param sketch_id: Optional explicit sketch (campaign) to read. Defaults to the configured one.
        :return: JSON with the scored paths, the per-stage search diagnostics, and any cap that was hit.
        """
        import time
        t0 = time.monotonic()
        scope = self._resolve_sketch(sketch_id)
        if "error" in scope:
            return json.dumps(scope, default=str, indent=2)
        self.sketch_id = scope["sketch_id"]
        top_n     = max(1, min(50, int(top_n or 5)))
        max_hops  = max(1, min(5, int(max_hops or 4)))
        chain_cap = max(1, min(20000, int(chain_cap or 4000)))
        budget_s  = 45.0

        # ── resolve the source Individual (one indexed query, no graph fetch) ──
        ident_l = normalize_identifier(identifier)
        resolve = individual_resolve_query(
            sketch_param="$sk",
            label_expr="coalesce(u.nodeLabel, u['nodeProperties.label'], elementId(u))",
            return_clause="RETURN elementId(u) AS id, label, u['nodeProperties.tech_stack'] AS tech_stack",
        )
        try:
            found = self._run(resolve, {"sk": self.sketch_id, "q": ident_l}, timeout=30)
        except Exception as e:
            return json.dumps({"error": f"Source lookup failed: {e}"})

        if not found:
            out = {"error": f"No Individual found matching '{identifier}'"}
            # Distinguish "not in the data" from "pointed at the wrong sketch" — an
            # empty sketch is the most common cause of surprise zeros.
            try:
                cnt = self._run("MATCH (n) WHERE n.sketch_id = $sk RETURN count(n) AS c",
                                {"sk": self.sketch_id}, timeout=30)
                nodes_in_scope = cnt[0]["c"] if cnt else 0
                out["sketch_id"] = self.sketch_id
                out["nodes_in_sketch"] = nodes_in_scope
                if nodes_in_scope == 0:
                    out["scope_warning"] = (
                        f"The configured sketch ({self.sketch_id}) contains 0 nodes, so no user can be "
                        "found in it. Do NOT report this as 'user not found' — FLOWSINT_SKETCH_ID points "
                        "at an empty sketch and must be re-pointed at the ingested one."
                    )
            except Exception:
                pass
            return json.dumps(out, indent=2)

        source_id    = found[0]["id"]
        source_label = found[0]["label"]

        raw_ts = found[0].get("tech_stack")
        hv_tech = 0
        if raw_ts:
            try:
                ts = json.loads(raw_ts) if isinstance(raw_ts, str) else (raw_ts if isinstance(raw_ts, list) else [])
            except Exception:
                ts = []
            hv_tech = len(set(ts) & HIGH_VALUE_TECH)

        rows: List[Dict[str, Any]] = []
        stages: List[Dict[str, Any]] = []

        def stage(name: str, cypher: str, params: Dict[str, Any], cap: int):
            started = time.monotonic()
            try:
                got = self._run(cypher, params)
            except Exception as e:
                stages.append({"stage": name, "error": str(e)[:300]})
                return []
            stages.append({"stage": name, "returned": len(got), "cap": cap,
                           "cap_hit": len(got) >= cap,
                           "ms": int((time.monotonic() - started) * 1000)})
            return got

        # ── stage 1: shortestPath to every high-value endpoint ────────────────
        target_cap = 750
        rows += stage(
            "high_value_shortest_paths",
            "MATCH (s) WHERE elementId(s) = $src "
            "MATCH (t) WHERE t.sketch_id = $sk AND t.deleted_at IS NULL "
            "  AND elementId(t) <> $src AND " + _HIGH_VALUE + " "
            "WITH s, t, CASE WHEN t['nodeProperties.is_dc'] = true THEN 0 "
            "  WHEN t['nodeProperties.is_high_value'] = true THEN 1 ELSE 2 END AS prio "
            "ORDER BY prio ASC LIMIT $target_cap "
            "MATCH p = shortestPath((s)-[:" + "|".join(ALL_LABELS) + f"*1..{max_hops}]->(t)) "
            + _LIVE_IN_SKETCH + _RETURN_HOPS,
            {"sk": self.sketch_id, "src": source_id, "target_cap": target_cap}, target_cap)

        # ── stage 2: heaviest-ACE chains to any endpoint (capped sample) ───────
        if max_hops >= 2 and (budget_s - (time.monotonic() - t0)) > 5:
            chain = ("MATCH (s) WHERE elementId(s) = $src "
                     "MATCH p = (s)-[:{rels}*2..{hops}]->(t) " + _NO_REVISIT + _RETURN_HOPS + " LIMIT $cap")
            heavy = stage("heavy_ace_chains",
                          chain.format(rels="|".join(HEAVY_LABELS), hops=max_hops),
                          {"sk": self.sketch_id, "src": source_id, "cap": chain_cap}, chain_cap)
            rows += heavy
            # Only widen when the heavy edge space was exhausted, otherwise the
            # heavy sample is already the richest source of high scores.
            if len(heavy) < chain_cap and (budget_s - (time.monotonic() - t0)) > 5:
                rows += stage("medium_ace_chains",
                              chain.format(rels="|".join(MEDIUM_LABELS), hops=max_hops),
                              {"sk": self.sketch_id, "src": source_id, "cap": chain_cap}, chain_cap)

        # ── stage 3: direct 1-hop edges ───────────────────────────────────────
        if (budget_s - (time.monotonic() - t0)) > 3:
            rows += stage("direct_edges",
                          "MATCH (s) WHERE elementId(s) = $src "
                          "MATCH p = (s)-[:" + "|".join(ALL_LABELS) + "*1..1]->(t) "
                          + _NO_REVISIT + _RETURN_HOPS + " LIMIT $cap",
                          {"sk": self.sketch_id, "src": source_id, "cap": 500}, 500)

        exploit_index = self._fetch_exploit_index(
            [hop[8] for row in rows for hop in (row.get("hop_nodes") or []) if len(hop) > 8]
        )

        paths: List[dict] = []
        seen: set = set()
        for row in rows:
            hop_nodes = row.get("hop_nodes") or []
            rels      = row.get("rels") or []
            key = (tuple(str(h[0]) for h in hop_nodes), tuple(rels))
            if key in seen:
                continue
            seen.add(key)
            p = self._score_path(hop_nodes, rels, hv_tech, exploit_index)
            if p:
                paths.append(p)

        scored = sorted(paths, key=lambda p: (-p["score"], p["hops"], str(p["final_target"])))[:top_n]

        def recommend(p: dict) -> str:
            if not p.get("path"):
                return ""
            last  = p["path"][-1]["edge"]
            tgt   = p.get("final_target", "")
            ttype = p.get("final_target_type", "")
            if last in ("GenericAll", "WriteDacl", "WriteOwner"):
                return f"Abuse {last} on '{tgt}' — reset password, add to group, or grant DA rights."
            if last == "ForceChangePassword":
                return f"Force password reset for '{tgt}'."
            if last == "AddMember":
                return f"Add controlled user to '{tgt}' to inherit its rights."
            if last in ("AllowedToAct", "AddAllowedToAct"):
                return (f"RBCD on '{tgt}': write msDS-AllowedToActOnBehalfOfOtherIdentity, "
                        f"then S4U2Self/S4U2Proxy to impersonate any user to it (Rubeus).")
            if last == "AllowedToDelegate":
                return f"Constrained delegation to '{tgt}': S4U2Proxy to impersonate a privileged user (Rubeus)."
            if last == "HasSIDHistory":
                return f"Path inherits '{tgt}' privileges via SID history — no further action needed."
            if last == "CoerceToTGT":
                return (f"Coerce '{tgt}' (PetitPotam/PrinterBug/DFSCoerce) to auth to your host "
                        f"and capture/relay its TGT (krbrelayx) — unconstrained delegation.")
            if last == "Enroll":
                return (f"Enroll in vulnerable template '{tgt}' with an arbitrary SAN to obtain a "
                        f"cert authenticating as a privileged user (ESC1 — Certipy).")
            if last in ("ManageCA", "ManageCertificates", "WritePKIEnrollmentFlag", "WritePKINameFlag"):
                return f"Abuse {last} on CA/template '{tgt}' to issue a privileged cert (ESC7/ESC4 — Certipy)."
            if last == "WriteGPLink":
                return f"Link a malicious GPO to '{tgt}' to run code on every object in that scope."
            if last == "SQLAdmin":
                return f"SQLAdmin on '{tgt}': xp_cmdshell / relay to run code as the SQL service (mssqlclient)."
            if last in ("CanRDP", "CanPSRemote", "ExecuteDCOM"):
                return f"Use {last} to log on to '{tgt}' and harvest credentials / pivot."
            if ttype == "device" and last == "HAS_SESSION":
                return f"Harvest credentials from active sessions on '{tgt}'."
            if last == "LOCAL_ADMIN":
                return f"Use local admin on '{tgt}' to dump LSASS/SAM."
            return f"Exploit {last} on '{tgt}' for privilege escalation."

        for p in scored:
            p["recommended_action"] = recommend(p)

        out: Dict[str, Any] = {
            "source": {"identifier": identifier, "resolved_to": source_label},
            "count": len(scored),
            "paths": scored,
            "search": {"max_hops": max_hops, "unique_paths_scored": len(paths),
                       "stages": stages, "elapsed_ms": int((time.monotonic() - t0) * 1000)},
            "sketch_id": self.sketch_id,
        }
        if scope.get("note"):
            out["scope_note"] = scope["note"]
        if any(p.get("exploit_bonus") for p in scored):
            out["exploit_note"] = EXPLOIT_CAVEAT
        capped = [s["stage"] for s in stages if s.get("cap_hit")]
        if capped:
            out["notes"] = [
                "These searches hit their row cap and were sampled, so the ranking is best-effort "
                f"within those bounds rather than a proven global top-{top_n}: {', '.join(capped)}. "
                "Reachability to high-value endpoints is complete up to target_cap. Re-call with a "
                "larger chain_cap for a wider search."
            ]
        if not scored:
            out["note"] = (
                f"'{source_label}' has no outbound attack path within {max_hops} hops over the scored "
                "ACE / navigational / session edges. That is a real finding about this account, not a "
                "tool failure — report it as 'no escalation path found from this user'."
            )
        return json.dumps(out, default=str, indent=2)
