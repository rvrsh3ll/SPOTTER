"""
dossier_tool.py — Open WebUI Tool

Fetches a complete operator dossier for an Individual entity from the SPOTTER
graph, including all linked nodes: beacons, AD permissions, sessions, social
profiles, Flare breach data, and attack path summary.

Install:
  Open WebUI → Admin → Tools → + New Tool → paste this file → Save

Flowsint graph format (verified against live API):
  nds — list of node objects with: id, nodeLabel, nodeType, nodeProperties
  rls — list of edge objects with: id, source, target, label
  nodeType values (lowercase): individual, device, organization,
                               c2session, flarebreach, socialprofile
                               (cobaltbeacon is the pre-migration name for
                                c2session — see scripts/migrate_c2session.py)
  ACE rights ARE the edge label (GenericAll, WriteDacl, MEMBER_OF, etc.)

Sensitivity rules applied to output:
  - password hashes: always [REDACTED]
  - phone numbers: masked to last 4 digits (***-***-XXXX)
  - all other personal/breach fields: shown as-is (operators need the intel)
"""

import hashlib
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

from individual_lookup import identifier_matches, individual_resolve_query, normalize_identifier


def _mask_phone(phone: str) -> Optional[str]:
    if not phone:
        return None
    digits = "".join(c for c in str(phone) if c.isdigit())
    if len(digits) >= 4:
        return f"***-***-{digits[-4:]}"
    return "[REDACTED]"


def _gravatar_url(email: Optional[str]) -> Optional[str]:
    if not email or "@" not in email:
        return None
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    return f"https://www.gravatar.com/avatar/{h}?d=404"


def _derive_specialty(job_title: Optional[str]) -> Optional[str]:
    if not job_title:
        return None
    t = job_title.lower()
    rules = [
        (["database", "dba", "sql server", "oracle dba", "mysql admin"], "Database Engineer"),
        (["ciso", "penetration test", "pentest", "red team", "soc analyst", "infosec", "cybersecurity"], "Security Professional"),
        (["devops", "site reliability", "sre ", "platform engineer", "cloud engineer", "devsecops"], "DevOps / Cloud"),
        (["data scientist", "data analyst", "machine learning", "ml engineer", " ai ", "data engineer"], "Data / ML"),
        (["software engineer", "software developer", "swe", "programmer", "full stack", "frontend", "backend"], "Software Engineer"),
        (["network engineer", "network admin", "infrastructure", "systems admin", "sysadmin", "it admin"], "Infrastructure / IT"),
        (["finance", "financial analyst", "accounting", "accountant", "controller", "cfo", "treasurer"], "Finance"),
        (["human resources", " hr ", "talent acquisition", "recruiting", "recruiter", "people ops"], "Human Resources"),
        (["marketing", "growth", "brand manager", "content strategist", "digital marketing", "seo"], "Marketing"),
        (["sales", "account executive", "business development", "bdr", "sdr"], "Sales"),
        (["ceo", "chief executive", "cto", "coo", "president", "vice president", " vp ", "head of"], "Executive"),
        (["director", "senior director", "managing director"], "Director"),
        (["manager", "team lead", "principal ", "staff ", "engineering manager"], "Manager"),
        (["analyst"], "Analyst"),
        (["engineer", "developer", "architect"], "Engineer"),
    ]
    for keywords, specialty in rules:
        if any(k in t for k in keywords):
            return specialty
    return job_title.title()


class Tools:
    def __init__(self):
        self.api_url   = os.environ.get("FLOWSINT_API_URL", "http://flowsint-api:5001")
        self.api_key   = os.environ.get("FLOWSINT_API_KEY", "")
        self.sketch_id = os.environ.get("FLOWSINT_SKETCH_ID", "")

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    # ── Neo4j access ─────────────────────────────────────────────────────────
    # Queries go straight to Neo4j (same as ad_attack_paths_tool.py). The previous
    # version pulled every node and edge in the sketch through the Flowsint API —
    # ~19s on a 12k-node engagement graph — to describe one person.

    def _run(self, cypher: str, params: Dict[str, Any], timeout: int = 45) -> List[Dict[str, Any]]:
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

    # Underscore-prefixed on purpose: Open WebUI turns every PUBLIC method on
    # Tools into a callable tool, and this helper is not one.
    def _resolve_sketch(self, explicit: Optional[str] = None) -> Dict[str, Any]:
        """Which sketch to read. Container env is fixed at creation time, so
        FLOWSINT_SKETCH_ID goes stale whenever the engagement moves to a new
        sketch — the usual cause of a tool truthfully reporting "not found" on a
        graph full of data. Falls back to the only populated sketch, and refuses
        to guess when several are populated so campaigns cannot be mixed up.
        Keep in sync with the copy in flowsint_search_tool.py.
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
                    "note": (f"The configured sketch ({candidate}) holds 0 nodes, so the only populated sketch "
                             f"({populated[0]['sketch_id']}, {populated[0]['nodes']} nodes) was used. Update "
                             "FLOWSINT_SKETCH_ID to make this permanent.") if candidate else None}
        return {"error": (f"The configured sketch ({candidate or 'unset'}) holds 0 nodes and this database has "
                          f"{len(populated)} populated sketches, so the correct one cannot be guessed without "
                          "risking another campaign's data. Pass sketch_id explicitly."),
                "sketches": populated}

    @staticmethod
    def _node_shape(node_id: str, props: dict) -> dict:
        """Rebuild the Flowsint API node shape from Neo4j's flat dotted keys, so the
        dossier logic below is unchanged."""
        nested, top = {}, {}
        for k, v in (props or {}).items():
            if k.startswith("nodeProperties."):
                nested[k[len("nodeProperties."):]] = v
            elif not k.startswith("nodeMetadata."):
                top[k] = v
        return {"id": node_id, "nodeLabel": top.get("nodeLabel", "") or "",
                "nodeType": top.get("nodeType", "") or "", "nodeProperties": nested}

    def _subject_and_neighbourhood(self, sk: str, identifier: str):
        """Resolve the subject, then read only its 1-hop neighbourhood.

        Returns ({'nds': [...], 'rls': [...]}, subject_id) — the same shape the old
        whole-graph payload had, scoped to what a dossier actually reads.
        """
        ident_l = normalize_identifier(identifier)
        # Identifier surface is individual_lookup. The neighbourhood scan below
        # uses the same predicate so a subject matched on display_name or
        # email_addresses is still the subject once the rows come back.
        found = self._run(
            individual_resolve_query(
                sketch_param="$sk",
                return_clause="RETURN elementId(u) AS id, properties(u) AS props",
            ),
            {"sk": sk, "q": ident_l}, timeout=30)
        if not found:
            return None, None

        subj_id = found[0]["id"]
        nds = [self._node_shape(subj_id, found[0]["props"])]
        rls: List[dict] = []

        rows = self._run(
            "MATCH (u) WHERE elementId(u) = $id "
            "MATCH (u)-[r]-(o) WHERE o.sketch_id = $sk AND o.deleted_at IS NULL "
            "RETURN elementId(o) AS oid, properties(o) AS oprops, type(r) AS rel, "
            "  elementId(startNode(r)) AS src, elementId(endNode(r)) AS dst LIMIT 4000",
            {"id": subj_id, "sk": sk})
        seen_nodes = {subj_id}
        seen_edges = set()
        for row in rows:
            oid = row["oid"]
            if oid not in seen_nodes:
                seen_nodes.add(oid)
                nds.append(self._node_shape(oid, row["oprops"]))
            ekey = (row["src"], row["dst"], row["rel"])
            if ekey not in seen_edges:
                seen_edges.add(ekey)
                rls.append({"source": row["src"], "target": row["dst"], "label": row["rel"]})
        return {"nds": nds, "rls": rls}, subj_id

    def _reuse_count(self, sk: str, subj_id: str, hashes) -> int:
        """How many OTHER individuals share a credential hash with the subject.
        Needs the whole graph, so it is a count in Neo4j rather than a Python scan."""
        hs = [h for h in hashes if h]
        if not hs:
            return 0
        rows = self._run(
            "MATCH (o:individual)-->(c) WHERE o.sketch_id = $sk AND o.deleted_at IS NULL "
            "  AND elementId(o) <> $id AND toLower(coalesce(c.nodeType, '')) = 'credential' "
            "  AND c['nodeProperties.value_hash'] IN $hashes "
            "RETURN count(DISTINCT o) AS n",
            {"sk": sk, "id": subj_id, "hashes": hs})
        return rows[0]["n"] if rows else 0

    def get_dossier(self, identifier: str, sketch_id: Optional[str] = None) -> str:
        """
        Return a complete SPOTTER dossier for an Individual.

        :param identifier: Username, email, SID, display name, or Flowsint node ID.
        :param sketch_id: Optional explicit sketch (campaign) to read. Defaults to the configured one.
        :return: Structured JSON dossier with all correlated intelligence.

        The dossier includes:
          - Core identity (name, SID, enabled status, admin flag)
          - Personal info (emails, phones [masked], location, address)
          - Professional profile (specialty, job title, employer, office)
          - Social media links (LinkedIn, Twitter, GitHub, others)
          - Flare.io breach data (credential leaks, stealer logs, paste exposure)
          - Active Directory permissions (ACE rights, scored targets)
          - Group memberships
          - Active sessions (computers this user has sessions on)
          - Cobalt Strike beacons (hostname, IP, last checkin, admin status)
          - Attack path summary and priority score
          - Operator alerts
        """
        scope = self._resolve_sketch(sketch_id)
        if "error" in scope:
            return json.dumps(scope, default=str, indent=2)
        sk = scope["sketch_id"]

        try:
            graph, _subj_id = self._subject_and_neighbourhood(sk, identifier)
        except Exception as e:
            return json.dumps({"error": f"Graph fetch failed: {e}"})

        if graph is None:
            out = {"error": f"No Individual found matching '{identifier}'", "sketch_id": sk}
            if scope.get("note"):
                out["scope_note"] = scope["note"]
            return json.dumps(out, default=str, indent=2)

        nds   = graph.get("nds", [])
        rls   = graph.get("rls", [])
        nodes = {n["id"]: n for n in nds}

        # First hit, not shortest-label: the Cypher resolve already applied the
        # tie-break and put that subject first. A shorter-label neighbour must
        # not steal the dossier.
        individual = None
        for node in nds:
            if (node.get("nodeType") or "").lower() != "individual":
                continue
            props = node.get("nodeProperties", {}) or {}
            if identifier_matches(node.get("nodeLabel", ""), props, node.get("id", ""), identifier):
                individual = node
                break

        if individual is None:
            return json.dumps({"error": f"No Individual found matching '{identifier}'"})

        ind_id    = individual["id"]
        ind_props = individual.get("nodeProperties", {}) or {}
        ind_label = individual.get("nodeLabel") or ind_props.get("label", "")

        outbound = [e for e in rls if e.get("source") == ind_id]
        inbound  = [e for e in rls if e.get("target") == ind_id]

        # Keep in sync with attack_path_tool.py ACE_SCORES (tradecraft update 2026-07).
        ACE_SCORES = {
            "GenericAll": 10, "WriteDacl": 9, "WriteOwner": 8,
            "GenericWrite": 7, "AllExtendedRights": 7, "AddAllowedToAct": 7,
            "ForceChangePassword": 6, "AddMember": 5, "Owns": 5,
            "ReadLAPSPassword": 4, "GetChanges": 4, "ReadGMSAPassword": 4,
            "WriteAccountRestrictions": 5, "AddKeyCredentialLink": 5, "WriteSPN": 4,
            "DCSync": 10, "GetChangesAll": 10,
            # Kerberos delegation / SID history / coercion
            "AllowedToAct": 7, "AllowedToDelegate": 7, "HasSIDHistory": 8, "CoerceToTGT": 8,
            # ADCS abuse
            "ManageCA": 8, "ManageCertificates": 7,
            "WritePKIEnrollmentFlag": 7, "WritePKINameFlag": 7, "Enroll": 4,
            # GPO + lateral movement
            "WriteGPLink": 8, "SQLAdmin": 5, "ExecuteDCOM": 4, "CanPSRemote": 4, "CanRDP": 3,
        }

        beacons, permissions, groups, sessions = [], [], [], []
        breaches, social_profiles, credentials = [], [], []

        for e in outbound:
            tgt    = nodes.get(e.get("target", ""), {})
            tprops = tgt.get("nodeProperties", {}) or {}
            ttype  = (tgt.get("nodeType") or "").lower()
            tlabel = tgt.get("nodeLabel") or tprops.get("label") or tprops.get("name") or ""
            elabel = e.get("label", "")

            # HAS_BEACON is written individual → session by BOTH ingestors (WF01
            # Cobalt Strike, WF21 Brute Ratel), so beacons arrive on the OUTBOUND
            # side. Matching only the pre-migration `cobaltbeacon` type dropped
            # every C2Session silently — which is every Brute Ratel badger ever
            # ingested, plus every Cobalt Strike beacon after migrate_c2session.py.
            # The edge label is checked too, so a session node whose type is
            # spelled some third way still lands.
            if ttype in ("c2session", "cobaltbeacon") or elabel == "HAS_BEACON":
                beacons.append({
                    "hostname":     tprops.get("hostname"),
                    "internal_ip":  tprops.get("internal_ip") or tprops.get("last_external_ip"),
                    "last_checkin": tprops.get("last_checkin"),
                    "is_admin":     tprops.get("is_admin"),
                    "process_name": tprops.get("process_name"),
                    # Nodes predating the CobaltBeacon → C2Session rename carry no
                    # c2_framework, and back then Cobalt Strike was the only one.
                    "c2_framework": tprops.get("c2_framework") or "cobalt_strike",
                    "session_id":   tprops.get("session_id") or tprops.get("beacon_id"),
                })

            elif ttype == "flarebreach" or elabel == "HAS_BREACH":
                entry = {
                    "source":           tprops.get("source"),
                    "event_type":       tprops.get("event_type"),
                    "identity_name":    tprops.get("identity_name"),
                    "domain":           tprops.get("domain"),
                    "hash_type":        tprops.get("hash_type"),
                    "hash":             "[REDACTED]",
                    "password_exposed": tprops.get("password_exposed"),
                    "imported_at":      tprops.get("imported_at"),
                }
                if tprops.get("event_type") == "stealer_log":
                    entry["malware_family"]    = tprops.get("malware_family")
                    entry["infection_country"] = tprops.get("infection_country")
                breaches.append(entry)

            elif ttype == "credential" or elabel == "HAS_CREDENTIAL":
                credentials.append({
                    "cred_type":    tprops.get("cred_type"),
                    "value_masked": tprops.get("value_masked"),
                    "severity":     tprops.get("severity"),
                    "validated":    tprops.get("validated"),
                    "service":      tprops.get("service"),
                    "source_file":  tprops.get("source_file"),
                })

            elif ttype == "socialprofile" or elabel == "HAS_PROFILE":
                social_profiles.append({
                    "platform":     tprops.get("platform"),
                    "username":     tprops.get("username"),
                    "url":          tprops.get("url"),
                    "display_name": tprops.get("display_name"),
                    "job_title":    tprops.get("job_title"),
                    "employer":     tprops.get("employer"),
                    "location":     tprops.get("location"),
                    "specialty":    tprops.get("specialty"),
                    "bio":          tprops.get("bio"),
                })

            elif elabel in ACE_SCORES:
                permissions.append({
                    "target":      tlabel,
                    "target_type": tgt.get("nodeType"),
                    "right":       elabel,
                    "score":       ACE_SCORES[elabel],
                })

            elif elabel == "MEMBER_OF" or ttype == "organization":
                if tlabel:
                    groups.append(tlabel)

        for e in inbound:
            src    = nodes.get(e.get("source", ""), {})
            sprops = src.get("nodeProperties", {}) or {}
            if e.get("label") == "HAS_SESSION":
                sessions.append({
                    "computer": src.get("nodeLabel") or sprops.get("hostname"),
                    "is_dc":    sprops.get("is_dc"),
                })
            elif e.get("label") == "HAS_BEACON":
                # Defensive only: both ingestors write this edge individual →
                # session, so it is handled in the OUTBOUND loop above and this
                # branch fires only for a reversed legacy edge. An edge is either
                # inbound or outbound, never both, so there is no double count.
                beacons.append({
                    "hostname":     sprops.get("hostname"),
                    "internal_ip":  sprops.get("internal_ip"),
                    "last_checkin": sprops.get("last_checkin"),
                    "is_admin":     sprops.get("is_admin"),
                    "c2_framework": sprops.get("c2_framework") or "cobalt_strike",
                    "session_id":   sprops.get("session_id") or sprops.get("beacon_id"),
                })

        permissions.sort(key=lambda p: p.get("score") or 0, reverse=True)

        # ── Personal section ──────────────────────────────────────────────────
        # personal_phones / personal_emails are set by OSINT enrichers.
        # Fallback to the AD fields (phone, mobile, email) written by SharpHound.
        raw_phones = ind_props.get("personal_phones") or []
        if isinstance(raw_phones, str):
            try:
                raw_phones = json.loads(raw_phones)
            except Exception:
                raw_phones = [raw_phones] if raw_phones else []
        for key in ("phone", "mobile", "telephonenumber", "othertelephone"):
            v = ind_props.get(key)
            if v and v not in raw_phones:
                raw_phones.append(v)

        raw_emails = ind_props.get("personal_emails") or []
        if isinstance(raw_emails, str):
            try:
                raw_emails = json.loads(raw_emails)
            except Exception:
                raw_emails = [raw_emails] if raw_emails else []
        # AD stores email as a plain string under "email"
        ad_email = ind_props.get("email")
        if ad_email and ad_email not in raw_emails:
            raw_emails.append(ad_email)

        # pull emails/phones from social profile pages too
        for sp in social_profiles:
            for em in (sp.get("profile_emails") or []):
                if em and em not in raw_emails:
                    raw_emails.append(em)
            for ph in (sp.get("profile_phones") or []):
                if ph and ph not in raw_phones:
                    raw_phones.append(ph)

        # aggregate all locations lived (individual props + social profiles)
        locations_lived = list(ind_props.get("locations_lived") or [])
        for sp in social_profiles:
            for loc in (sp.get("locations_lived") or []):
                if loc and loc not in locations_lived:
                    locations_lived.append(loc)
            if sp.get("location") and sp["location"] not in locations_lived:
                locations_lived.append(sp["location"])

        # addresses: SharpHound writes a list; personal_address is an OSINT field
        addresses = ind_props.get("addresses") or []
        if isinstance(addresses, str):
            try:
                addresses = json.loads(addresses)
            except Exception:
                addresses = [addresses] if addresses else []
        personal_address = ind_props.get("personal_address")
        if personal_address and personal_address not in addresses:
            addresses.insert(0, personal_address)

        # Resolve names: explicit fields → full_name parse → identity label
        first_name = ind_props.get("first_name") or ind_props.get("givenname")
        last_name  = ind_props.get("last_name") or ind_props.get("sn") or ind_props.get("surname")
        if not first_name and not last_name:
            full = ind_props.get("full_name") or ind_label or ""
            if "," in full:
                last_name, _, first_name = full.partition(",")
                last_name  = last_name.strip()
                first_name = first_name.strip()
            elif " " in full and not full.endswith(("@" + full.split("@")[-1] if "@" in full else "")):
                parts = full.split()
                first_name = parts[0]
                last_name  = " ".join(parts[1:])

        # email_addresses is the Flowsint schema field; email is the extra field written by SharpHound
        schema_emails = ind_props.get("email_addresses") or []
        if isinstance(schema_emails, list):
            for em in schema_emails:
                val = em if isinstance(em, str) else (em or {}).get("address") or (em or {}).get("email")
                if val and val not in raw_emails:
                    raw_emails.append(val)

        personal = {
            "first_name":      first_name,
            "middle_name":     ind_props.get("middle_name"),
            "last_name":       last_name,
            "username":        ind_props.get("username") or ind_props.get("sam_account_name"),
            "department":      ind_props.get("department"),
            "emails":          [e for e in raw_emails if e],
            "phones":          [_mask_phone(p) for p in raw_phones if p],
            "location":        ind_props.get("personal_location") or ind_props.get("location"),
            "addresses":       addresses,
            "locations_lived": locations_lived,
        }

        # ── Professional section ──────────────────────────────────────────────
        job_title = ind_props.get("job_title")
        specialty = ind_props.get("specialty") or _derive_specialty(job_title)

        # Prefer LinkedIn-sourced specialty/job if the Individual property is empty
        if not specialty and social_profiles:
            for sp in social_profiles:
                if sp.get("platform") == "linkedin" and sp.get("specialty"):
                    specialty = sp["specialty"]
                    job_title = job_title or sp.get("job_title")
                    break

        work_history = ind_props.get("work_history") or []
        if not work_history:
            for sp in social_profiles:
                if sp.get("platform") == "linkedin" and sp.get("work_history"):
                    work_history = sp["work_history"]
                    break

        professional = {
            "specialty":      specialty,
            "job_title":      job_title,
            "employer":       ind_props.get("employer"),
            "office_address": ind_props.get("office_address"),
            "work_history":   work_history,
        }

        # ── Social section ────────────────────────────────────────────────────
        linked_in = ind_props.get("social_linkedin")
        twitter   = ind_props.get("social_twitter")
        github    = ind_props.get("social_github")

        # Also surface from HAS_PROFILE nodes
        other_profiles = []
        for sp in social_profiles:
            plat = (sp.get("platform") or "").lower()
            if plat == "linkedin" and not linked_in:
                linked_in = sp.get("url")
            elif plat in ("twitter", "x") and not twitter:
                twitter = sp.get("url")
            elif plat == "github" and not github:
                github = sp.get("url")
            else:
                other_profiles.append({
                    "platform":    plat,
                    "username":    sp.get("username"),
                    "url":         sp.get("url"),
                    "display_name": sp.get("display_name"),
                    "followers":   sp.get("followers"),
                })

        social = {
            "linkedin": linked_in,
            "twitter":  twitter,
            "github":   github,
            "other":    other_profiles,
        }

        # ── Credential section ────────────────────────────────────────────────
        # Detect password re-use: count other individuals sharing any value_hash
        # from this individual's credentials.  Uses the graph already in memory.
        my_hashes = set()
        for e in outbound:
            tgt   = nodes.get(e.get("target", ""), {})
            tprops_c = tgt.get("nodeProperties", {}) or {}
            if (tgt.get("nodeType") or "").lower() == "credential":
                h = tprops_c.get("value_hash")
                if h:
                    my_hashes.add(h)

        # Password reuse is the one figure that needs more than the subject's
        # neighbourhood, so it is counted in Neo4j instead of scanned in Python.
        try:
            reuse_count = self._reuse_count(sk, ind_id, my_hashes)
        except Exception:
            reuse_count = 0

        # Sort credentials by severity for operator readability.
        _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        credentials.sort(key=lambda c: _sev_rank.get(c.get("severity") or "info", 0), reverse=True)

        cred_section = {
            "count":          len(credentials),
            "findings":       credentials[:30],
            "password_reuse": reuse_count > 0,
            "reuse_count":    reuse_count,
            "cred_score":     ind_props.get("cred_score", 0),
            "cred_severity":  ind_props.get("cred_severity"),
        }

        # ── Breach section ────────────────────────────────────────────────────
        breach_count = ind_props.get("breach_count", len(breaches))
        stealer_logs = [b for b in breaches if b.get("event_type") == "stealer_log"]
        pastes       = [b for b in breaches if b.get("event_type") == "paste"]
        credentials  = [b for b in breaches if b.get("event_type") not in ("stealer_log", "paste")]

        breach = {
            "total":                breach_count,
            "stealer_logs":         stealer_logs,
            "paste_exposures":      pastes,
            "leaked_credentials":   credentials[:20],
            "has_stealer_log":      bool(stealer_logs) or ind_props.get("has_stealer_log"),
            "last_seen":            ind_props.get("breach_last_seen"),
            "summary":              ind_props.get("breach_summary"),
        }

        # ── Technology section ────────────────────────────────────────────────
        raw_tech_stack = ind_props.get("tech_stack") or []
        if isinstance(raw_tech_stack, str):
            try:
                tech_stack = json.loads(raw_tech_stack)
            except Exception:
                tech_stack = [raw_tech_stack] if raw_tech_stack else []
        elif isinstance(raw_tech_stack, list):
            tech_stack = raw_tech_stack
        else:
            tech_stack = []

        technology = {
            "tech_stack":          tech_stack,
            "tech_stack_enriched": ind_props.get("tech_stack_enriched", False),
            "process_list":        ind_props.get("process_list"),
        }

        # ── Photo sources ─────────────────────────────────────────────────────
        # AD/O365 photo from SharpHound thumbnailPhoto
        ad_photo = ind_props.get("photo_url")
        # LinkedIn photo from enrichment
        linkedin_photo = ind_props.get("linkedin_photo")
        # Gravatar fallback from primary email
        gravatar_url = _gravatar_url(ind_props.get("email"))

        # Operator-verified / false-positive photo management
        raw_verified = ind_props.get("photo_verified_url") or ""
        raw_fp = ind_props.get("photo_false_positives") or "[]"
        try:
            photo_false_positives = json.loads(raw_fp) if isinstance(raw_fp, str) else (raw_fp if isinstance(raw_fp, list) else [])
        except Exception:
            photo_false_positives = []

        # ── Assemble dossier ──────────────────────────────────────────────────
        dossier = {
            "identity": {
                "id":        ind_id,
                "name":      ind_label,
                "full_name": ind_props.get("full_name"),
                "sid":       ind_props.get("sid"),
                "enabled":   ind_props.get("enabled"),
                "is_admin":  ind_props.get("is_admin"),
                "email":     ind_props.get("email"),
                "photo_url": ad_photo,
                "gravatar_url": gravatar_url,
                "linkedin_photo": linkedin_photo,
                "photo_verified_url": raw_verified or None,
                "photo_false_positives": photo_false_positives,
            },
            "personal":     personal,
            "professional": professional,
            "technology":   technology,
            "social":       social,
            "breach":       breach,
            "ad": {
                "permissions": permissions[:20],
                "groups":      [g for g in groups if g],
                "sessions":    sessions,
                "summary":     ind_props.get("ad_summary"),
            },
            "beacons":        beacons,
            "active_beacon":  ind_props.get("active_beacon"),
            "credentials":    cred_section,
            "priority_score": ind_props.get("priority_score") or ind_props.get("ad_max_score"),
            "cred_score":     ind_props.get("cred_score", 0),
            "total_score": (
                (ind_props.get("priority_score") or ind_props.get("ad_max_score") or 0)
                + (ind_props.get("cred_score") or 0)
            ),
            "alert":          ind_props.get("alert"),
        }

        dossier["sketch_id"] = sk
        if scope.get("note"):
            dossier["scope_note"] = scope["note"]
        return json.dumps(dossier, default=str, indent=2)
