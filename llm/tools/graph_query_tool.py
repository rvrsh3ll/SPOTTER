"""
graph_query_tool.py — Open WebUI Tool

Allows the LLM to execute read-only Cypher queries against the Neo4j graph
database backing Flowsint.

Neo4j schema (verified against live data):
  Node labels (lowercase): individual, organization, device, certtemplate,
    enterpriseca, gpo, adrisk
    (organization also covers domains [is_domain] and OUs [is_ou];
     adrisk is one PingCastle health-check finding, see below)
  Top-level properties: nodeLabel, nodeType, id
  Nested properties accessed as: n['nodeProperties.sid'], n['nodeProperties.is_admin'], etc.

  Identity properties (present on every SharpHound-ingested node):
    individual : nodeProperties.sam_account_name, nodeProperties.sid,
                 nodeProperties.username, nodeProperties.email,
                 nodeProperties.full_name, nodeProperties.department, nodeProperties.enabled
    device     : nodeProperties.sam_account_name, nodeProperties.sid,
                 nodeProperties.hostname, nodeProperties.domain,
                 nodeProperties.operating_system, nodeProperties.is_dc
    organization (AD group): nodeProperties.sid, nodeProperties.name,
                 nodeProperties.is_high_value
  The SAM account name lives under the SAME key on every node type
  (nodeProperties.sam_account_name), so one query covers all SIDs — no
  node-type special-casing needed.

  Relationship types: MEMBER_OF, HAS_SESSION, LOCAL_ADMIN, GenericAll, WriteDacl,
    WriteOwner, GenericWrite, AllExtendedRights, ForceChangePassword, AddMember,
    Owns, ReadLAPSPassword, WriteAccountRestrictions, AddKeyCredentialLink,
    WriteSPN, ReadGMSAPassword, AddAllowedToAct, DCSync, GetChanges, GetChangesAll,
    AllowedToAct, AllowedToDelegate, HasSIDHistory, CoerceToTGT, Enroll, ManageCA,
    ManageCertificates, WritePKIEnrollmentFlag, WritePKINameFlag, PublishedTo,
    WriteGPLink, GpLink, SQLAdmin, ExecuteDCOM, CanPSRemote, CanRDP, TrustedBy,
    HAS_PERMISSION, DC_OF, HAS_RISK, AFFECTS
  AD attack-surface props (individual/device): is_kerberoastable, rc4_only,
    is_asrep_roastable, unconstrained_delegation, constrained_delegation;
    (certtemplate) esc1; (enterpriseca) esc8.

  PingCastle health-check data (source = 'pingcastle'):
    adrisk : nodeProperties.risk_id (e.g. P-Delegated), nodeProperties.points (int),
             nodeProperties.severity (low|medium|high|critical),
             nodeProperties.category, nodeProperties.rationale,
             nodeProperties.is_high_risk, nodeProperties.details (list)
             Edges: (domain:organization)-[:HAS_RISK]->(:adrisk)-[:AFFECTS]->(object)
    organization (the domain): nodeProperties.pingcastle_global_score and the
             per-area pingcastle_*_score / pingcastle_maturity_level, plus
             account-hygiene counters (pingcastle_users_no_preauth,
             pingcastle_users_pwd_not_required, pingcastle_machine_account_quota,
             pingcastle_krbtgt_last_change, pingcastle_gpp_password_accounts)
    device (domain controllers): nodeProperties.is_dc = true and coercion/relay
             surface — pingcastle_smb1_enabled, pingcastle_null_session,
             pingcastle_remote_spooler, pingcastle_ldap_channel_binding_disabled,
             pingcastle_ldap_signing_not_required, pingcastle_webclient_enabled;
             linked to the domain by (:device)-[:DC_OF]->(:organization)
    Every PingCastle-sourced node carries nodeProperties.pingcastle_report = true.

Example queries:
  Members of Domain Admins:
    MATCH (u:individual)-[:MEMBER_OF]->(g:organization)
    WHERE toLower(g.nodeLabel) CONTAINS 'domain admins'
    RETURN u.nodeLabel AS user, u['nodeProperties.sid'] AS sid

  Users with GenericAll on any node:
    MATCH (u:individual)-[:GenericAll]->(t)
    RETURN u.nodeLabel AS attacker, t.nodeLabel AS target, t.nodeType AS target_type
    LIMIT 20

  Users with active sessions on DCs:
    MATCH (c:device)-[:HAS_SESSION]->(u:individual)
    WHERE c['nodeProperties.is_dc'] = true
    RETURN u.nodeLabel AS user, c.nodeLabel AS dc

  SamAccountName for every SID (one key covers individuals and devices):
    MATCH (n)
    WHERE n['nodeProperties.sid'] IS NOT NULL
    RETURN n['nodeProperties.sid'] AS sid,
           n['nodeProperties.sam_account_name'] AS sam,
           n.nodeType AS type

  Highest-scoring PingCastle findings and what they hit:
    MATCH (d:organization)-[:HAS_RISK]->(r:adrisk)
    OPTIONAL MATCH (r)-[:AFFECTS]->(o)
    RETURN r['nodeProperties.risk_id'] AS rule, r['nodeProperties.points'] AS points,
           r['nodeProperties.severity'] AS severity, d.nodeLabel AS domain,
           collect(o.nodeLabel) AS affected
    ORDER BY points DESC LIMIT 20

  Domain controllers exposing coercion / relay surface:
    MATCH (c:device)-[:DC_OF]->(d:organization)
    WHERE c['nodeProperties.pingcastle_remote_spooler'] = true
       OR c['nodeProperties.pingcastle_smb1_enabled'] = true
       OR c['nodeProperties.pingcastle_ldap_signing_not_required'] = true
    RETURN c.nodeLabel AS dc, d.nodeLabel AS domain,
           c['nodeProperties.pingcastle_remote_spooler'] AS spooler,
           c['nodeProperties.pingcastle_smb1_enabled'] AS smb1

  Computer SID → hostname (which systems a SID maps to):
    MATCH (c:device)
    WHERE c['nodeProperties.sid'] IS NOT NULL
    RETURN c['nodeProperties.sid'] AS sid,
           c['nodeProperties.hostname'] AS hostname,
           c['nodeProperties.sam_account_name'] AS sam

Install: Open WebUI → Admin → Tools → + New Tool → paste → Save
"""

import json
import os
import re
import requests
from typing import Any, List


_DISALLOWED_PATTERN = re.compile(
    r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|FOREACH|CALL|LOAD\s+CSV|"
    r"START\s+TRANSACTION|COMMIT|ROLLBACK|USE|DROP|ALTER|RENAME)\b",
    re.IGNORECASE,
)
_ALLOWED_START_PATTERN = re.compile(r"^\s*(MATCH|OPTIONAL\s+MATCH|UNWIND|WITH|RETURN)\b", re.IGNORECASE)


def _validate_cypher(query: str) -> str:
    if not isinstance(query, str):
        return "Cypher query must be a string."

    q = query.strip()
    if not q:
        return "Cypher query is empty."

    if len(q) > 5000:
        return "Cypher query exceeds 5000 characters."

    # One statement only; semicolon chaining is blocked.
    if ";" in q:
        return "Multiple statements are not allowed."

    # Disallow inline comments to avoid prompt-injection style query smuggling.
    if "--" in q or "/*" in q or "*/" in q:
        return "Comments are not allowed in Cypher queries."

    if _DISALLOWED_PATTERN.search(q):
        return "Query contains blocked Cypher clauses."

    if not _ALLOWED_START_PATTERN.search(q):
        return "Query must start with MATCH, OPTIONAL MATCH, UNWIND, WITH, or RETURN."

    return ""


class Tools:
    def __init__(self):
        self.neo4j_url    = os.environ.get("NEO4J_HTTP_URL", "http://neo4j:7474")
        self.neo4j_user   = os.environ.get("NEO4J_USER", "neo4j")
        self.neo4j_pass   = os.environ.get("NEO4J_PASSWORD", "")
        # NOTE: currently unused. Nothing in this file reads self.cypher_model — the tool
        # takes Cypher it is given rather than generating any, so this is not the live model
        # setting for anything. Kept (and kept in step with SECURITY_LLM_MODEL) only so it
        # does not become a stale value someone later trusts.
        self.cypher_model = os.environ.get(
            "SPOTTER_CYPHER_MODEL",
            "qwen3.8:27b",
        )

    def _run_cypher(self, cypher: str) -> List[Any]:
        endpoint = f"{self.neo4j_url}/db/neo4j/tx/commit"
        payload  = {"statements": [{"statement": cypher, "resultDataContents": ["row"]}]}
        resp = requests.post(
            endpoint, json=payload,
            auth=(self.neo4j_user, self.neo4j_pass),
            timeout=15,
        )
        resp.raise_for_status()
        data   = resp.json()
        errors = data.get("errors", [])
        if errors:
            raise RuntimeError(f"Neo4j errors: {errors}")
        results = data.get("results", [{}])
        if not results:
            return []
        columns = results[0].get("columns", [])
        rows = []
        for row in results[0].get("data", []):
            rows.append(dict(zip(columns, row.get("row", []))))
        return rows

    def run_cypher(self, cypher: str) -> str:
        """
        Execute a read-only Cypher query against the Neo4j graph database.

        :param cypher: A read-only Cypher MATCH query. Use only MATCH, RETURN,
               WHERE, WITH, ORDER BY, LIMIT. Do NOT use CREATE, MERGE, DELETE,
               SET, or REMOVE — those are blocked.

        Neo4j schema:
          Labels (lowercase): individual, organization, device
          Key properties (top-level): nodeLabel, nodeType, id
          Nested properties: n['nodeProperties.sid'], n['nodeProperties.is_admin'],
            n['nodeProperties.enabled'], n['nodeProperties.is_dc'],
            n['nodeProperties.priority_score'], n['nodeProperties.is_high_value']
          Identity properties (SharpHound-ingested):
            individual: n['nodeProperties.sam_account_name'],
              n['nodeProperties.username'], n['nodeProperties.email'],
              n['nodeProperties.full_name'], n['nodeProperties.department']
            device: n['nodeProperties.sam_account_name'],
              n['nodeProperties.hostname'], n['nodeProperties.domain'],
              n['nodeProperties.operating_system']
          The SAM account name uses the SAME key on every node type
          (n['nodeProperties.sam_account_name']) — one query covers all SIDs.
          Relationship types: MEMBER_OF, HAS_SESSION, LOCAL_ADMIN, GenericAll,
            WriteDacl, WriteOwner, GenericWrite, AllExtendedRights,
            ForceChangePassword, AddMember, Owns, ReadLAPSPassword,
            WriteAccountRestrictions, AddKeyCredentialLink, WriteSPN,
            ReadGMSAPassword, AddAllowedToAct, DCSync, GetChanges, GetChangesAll,
            AllowedToAct, AllowedToDelegate, HasSIDHistory, CoerceToTGT, Enroll,
            ManageCA, ManageCertificates, WritePKIEnrollmentFlag, WritePKINameFlag,
            PublishedTo, WriteGPLink, GpLink, SQLAdmin, ExecuteDCOM, CanPSRemote,
            CanRDP, TrustedBy, DC_OF, HAS_RISK, AFFECTS
          Node labels: individual, organization, device, certtemplate,
            enterpriseca, gpo, adrisk
          PingCastle health-check findings are :adrisk nodes —
            n['nodeProperties.risk_id'], n['nodeProperties.points'] (int),
            n['nodeProperties.severity'], n['nodeProperties.rationale'] —
            reached via (domain:organization)-[:HAS_RISK]->(:adrisk)-[:AFFECTS]->(object).
            Domain scores live on the domain node as
            n['nodeProperties.pingcastle_global_score']; DC hardening gaps on the
            DC device nodes as n['nodeProperties.pingcastle_smb1_enabled'],
            n['nodeProperties.pingcastle_remote_spooler'], etc.

        :return: JSON with the cypher used, row count, and up to 50 result rows.
        """
        validation_error = _validate_cypher(cypher)
        if validation_error:
            return json.dumps({
                "error": validation_error,
                "cypher": cypher,
            })

        try:
            rows = self._run_cypher(cypher)
        except Exception as e:
            return json.dumps({"error": str(e), "cypher": cypher})

        return json.dumps({
            "cypher": cypher,
            "row_count": len(rows),
            "results": rows[:50],
        }, default=str, indent=2)
