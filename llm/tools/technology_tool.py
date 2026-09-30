"""
technology_tool.py — Open WebUI Tool

Provides technology intelligence for the SPOTTER graph: OS inventory per
device, per-user tech stack (inferred from Cobalt Strike process lists),
user-to-device-to-system relationships, and targeted 'Jane scenario' attack
narratives for users whose tech stack includes high-value credential stores
or legacy remote-access clients.

Install:
  Open WebUI → Admin → Tools → + New Tool → paste this file → Save

Requires the Flowsint graph to have been enriched by:
  - C2SessionEnricher     (sets process_list on Individual)
  - ProcessTechStackEnricher (sets tech_stack on Individual)
  - DeviceTechEnricher    (sets os_name / os_risk on Device)
"""

import json
import os
import re
# sys is used by the optional tech_context_engine enrichment below
# (sys.path.insert("/data/scripts")). It was never imported, so that block
# raised NameError and the bare "except Exception: pass" swallowed it — CVE,
# MITRE and composite-risk enrichment silently never ran.
import sys
from typing import Any, Dict, List, Optional
import requests

for _scripts_dir in (
    os.environ.get("SPOTTER_SCRIPTS_DIR", "/data/scripts"),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts")),
):
    if _scripts_dir and os.path.isdir(_scripts_dir) and _scripts_dir not in sys.path:
        sys.path.insert(0, _scripts_dir)

from high_value_tech import HIGH_VALUE_TECH
from asset_labels import (SERVICE_TYPE, SERVICE_TYPES_LOWER, TECHNOLOGY_TYPE,
                          TECHNOLOGY_TYPES_LOWER)
from individual_lookup import identifier_matches, individual_resolve_query, normalize_identifier

OS_EOL_DB = [
    ("windows xp",             "Windows XP",             "2014-04-08"),
    ("windows vista",          "Windows Vista",          "2017-04-11"),
    ("windows 7",              "Windows 7",              "2020-01-14"),
    ("windows 8.1",            "Windows 8.1",            "2023-01-10"),
    ("windows 8",              "Windows 8",              "2016-01-12"),
    ("windows 10",             "Windows 10",             "2025-10-14"),
    ("windows server 2003 r2", "Windows Server 2003 R2", "2015-07-14"),
    ("windows server 2003",    "Windows Server 2003",    "2015-07-14"),
    ("windows server 2008 r2", "Windows Server 2008 R2", "2020-01-14"),
    ("windows server 2008",    "Windows Server 2008",    "2020-01-14"),
    ("windows server 2012 r2", "Windows Server 2012 R2", "2023-10-10"),
    ("windows server 2012",    "Windows Server 2012",    "2023-10-10"),
    ("windows server 2016",    "Windows Server 2016",    "2027-01-12"),
    ("windows server 2019",    "Windows Server 2019",    "2029-01-09"),
    ("windows server 2022",    "Windows Server 2022",    "2031-10-13"),
]

CRED_EXTRACTION_GUIDE: Dict[str, List[str]] = {
    "IBM iSeries Access for Windows (AS/400)": [
        "Dump iSeries Access credential store: %APPDATA%\\IBM\\Client Access\\Profiles\\*.ini",
        "Extract saved passwords from IBM iSeries Access connection profiles (DES-encrypted or cleartext in older versions)",
        "Hook cwbunpack.exe / pcsws.exe with a keylogger targeting the AS/400 signon window",
        "Monitor network traffic on TCP/23 (TN5250) or TCP/449 (iSeries Access) for session data",
        "Check HKCU\\Software\\IBM\\Client Access\\Connections for stored host/user config",
    ],
    "IBM Personal Communications (Mainframe)": [
        "Dump PCOMM session profiles: %APPDATA%\\IBM\\Personal Communications\\*.WS",
        "Extract credentials from PCOMM autologon scripts (plaintext or XOR-obfuscated)",
        "Keylog the 3270/5250 terminal window using EHLLAPI DLL injection",
        "Monitor TCP/23 (TN3270) or TCP/992 (TN3270S/TLS) traffic",
        "Check HKCU\\Software\\IBM\\Personal Communications for host profiles",
    ],
    "TN3270 Mainframe Terminal Emulator": [
        "Capture TN3270 session data from TCP/23 stream (cleartext if no TLS)",
        "Inject into terminal emulator process to read screen buffers",
        "Steal session profiles from %APPDATA% or install directory",
        "Keylog terminal window title matching mainframe host address",
    ],
    "TN5250 AS/400 Terminal Emulator": [
        "Capture TN5250 session on TCP/23 (legacy cleartext) or TCP/992 (TLS)",
        "Steal connection profiles from emulator's config directory",
        "Keylog AS/400 username/password field during signon",
        "Check for autologon scripts with embedded credentials",
    ],
    "SAP Logon (SAP GUI)": [
        "Dump SAP GUI credential store: %APPDATA%\\SAP\\Common\\SAPUILandscape.xml",
        "Read saved SAP passwords from SNC config (often base64 or obfuscated)",
        "Hook saplogon.exe with keylogger targeting the SAP Logon dialog",
        "Monitor SAP RFC/DIAG protocol on TCP/3200-3299 or HTTPS (sapgui for HTML)",
        "Check HKCU\\Software\\SAP\\SAPLogon for connection entries",
        "Use SAP credential extraction tool on harvested config files",
    ],
    "Citrix Workspace / ICA Client": [
        "Steal Citrix ICA files from Downloads / temp (contain server, credentials)",
        "Monitor ICA protocol (TCP/1494 or TCP/2598) for session tokens",
        "Extract Citrix saved credentials from Credential Manager (Windows DPAPI)",
        "Inject into wfica32.exe to capture launched application sessions",
        "Check %LOCALAPPDATA%\\Citrix\\SelfService for cached app config",
    ],
    "CyberArk PAM": [
        "Monitor PSM/PVWA session: CyberArk records sessions — avoid direct web console",
        "Target CyberArk Central Policy Manager (CPM) host for credential rotation scripts",
        "Dump CyberArk agent cache from disk if endpoint agent is present",
        "Phish CyberArk PVWA credentials — CyberArk web portal is often Internet-accessible",
        "Pivot via legitimate CyberArk 'transparent auth' to target systems without knowing passwords",
    ],
    "KeePass Password Manager": [
        "Locate KeePass database: *.kdbx in Documents, Desktop, or profile",
        "Dump KeePass master password from memory during active session (KeeThief / KeeDump)",
        "Monitor for KeePass auto-type triggers (CTRL+ALT+A) to intercept cleartext credentials",
        "Use KeeFarce or similar to export all passwords from running KeePass process",
        "Brute-force offline .kdbx with hashcat mode 13400 if you can exfiltrate the file",
    ],
    "1Password": [
        "Extract 1Password browser extension data from browser profile (encrypted vault)",
        "Monitor 1Password desktop agent process for memory-resident master password",
        "Target 1Password.com web portal credentials if cloud-sync is enabled",
        "Check %LOCALAPPDATA%\\1Password for local vault cache",
    ],
    "SQL Server Management Studio": [
        "Dump SSMS saved connections: %APPDATA%\\Microsoft SQL Server Management Studio\\*.ssms",
        "Extract SQL Server credentials from Windows Credential Manager (DPAPI)",
        "Monitor SQL connections on TCP/1433 for authentication packets",
        "Keylog SSMS login dialog for SQL auth connections",
    ],
    "Bloomberg Terminal": [
        "Steal Bloomberg session token from %LOCALAPPDATA%\\Bloomberg\\Bterm\\session",
        "Keylog Bloomberg Terminal login (BUID/password)",
        "Monitor Bloomberg B-PIPE API traffic on TCP/8195 for session data",
        "Extract Bloomberg credentials from Windows Credential Manager",
    ],
}


class Tools:
    def __init__(self):
        self.api_url   = os.environ.get("FLOWSINT_API_URL", "http://flowsint-api:5001")
        self.api_key   = os.environ.get("FLOWSINT_API_KEY", "")
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

    # The Python classification below (_classify_os / _os_risk / HIGH_VALUE_TECH /
    # CRED_EXTRACTION_GUIDE) is unchanged; only the data source shrank. The old
    # _graph() pulled every node and edge in the sketch through the Flowsint API —
    # 91.6 MB / ~18.5s on a 12k-node engagement graph — when these methods read a
    # handful of properties. _graph_subset() returns the same {nds, rls} shape from
    # Neo4j with only the node types and properties the callers actually touch.

    _DEVICE_KEYS = ("os_name", "operating_system", "hostname", "is_dc")
    _INDIVIDUAL_KEYS = ("tech_stack", "department", "job_title", "sam_account_name")
    _SERVICE_KEYS = ("port", "protocol", "name", "product", "version", "cpe")
    _TECHNOLOGY_KEYS = ("name", "version", "category", "vendor", "cve_count",
                        "is_high_value", "mitre_techniques", "composite_risk")

    def _projection(self, keys) -> str:
        """Cypher map projection of nodeProperties.<key> under its bare key name."""
        return "{" + ", ".join(f"`{k}`: n['nodeProperties.{k}']" for k in keys) + "}"

    def _nodes_of_type(self, sk: str, ntype: str, keys) -> List[Dict[str, Any]]:
        rows = self._neo(
            "MATCH (n) WHERE n.sketch_id = $sk AND n.deleted_at IS NULL "
            "  AND toLower(coalesce(n.nodeType, '')) = $ntype "
            "RETURN elementId(n) AS id, n.nodeType AS nodeType, "
            "  coalesce(n.nodeLabel, '') AS nodeLabel, " + self._projection(keys) + " AS nodeProperties",
            {"sk": sk, "ntype": ntype}, timeout=60)
        # The Flowsint API omitted empty-string properties, so the callers below have
        # always seen None for them. Neo4j returns "" — normalise so the shape matches.
        for r in rows:
            props = r.get("nodeProperties") or {}
            r["nodeProperties"] = {k: (None if v == "" else v) for k, v in props.items()}
        return rows

    @staticmethod
    def _unflatten(node_id: str, props: dict) -> dict:
        nested, top = {}, {}
        for k, v in (props or {}).items():
            if k.startswith("nodeProperties."):
                nested[k[len("nodeProperties."):]] = v
            elif not k.startswith("nodeMetadata."):
                top[k] = v
        return {"id": node_id, "nodeLabel": top.get("nodeLabel", "") or "",
                "nodeType": top.get("nodeType", "") or "", "nodeProperties": nested}

    def _graph_subset(self, scope: str, identifier: Optional[str] = None) -> dict:
        """Minimal {nds, rls} for one caller. scope='inventory' returns the four node
        types the inventory aggregates (projected properties only); scope='user'
        returns one individual plus its 1-hop neighbourhood (full properties)."""
        sk = self._resolve_sketch()

        if scope == "inventory":
            nds: List[Dict[str, Any]] = []
            for ntype, keys in (("device", self._DEVICE_KEYS),
                                ("individual", self._INDIVIDUAL_KEYS),
                                (SERVICE_TYPE, self._SERVICE_KEYS),
                                (TECHNOLOGY_TYPE, self._TECHNOLOGY_KEYS)):
                nds.extend(self._nodes_of_type(sk, ntype, keys))
            # Only edges incident to a technology node are read (affected users/hosts).
            rls = self._neo(
                "MATCH (a)-[r]-(t) WHERE t.sketch_id = $sk AND a.sketch_id = $sk "
                "  AND toLower(coalesce(t.nodeType, '')) = $ntype "
                "RETURN DISTINCT elementId(startNode(r)) AS source, "
                "  elementId(endNode(r)) AS target, type(r) AS label",
                {"sk": sk, "ntype": TECHNOLOGY_TYPE}, timeout=60)
            return {"nds": nds, "rls": rls, "sketch_id": sk}

        # scope == 'user'. Identifier surface is individual_lookup — label,
        # display_name, sid, username, and email_addresses included, not only
        # the four fields this query used to list.
        q = normalize_identifier(identifier)
        found = self._neo(
            individual_resolve_query(
                sketch_param="$sk",
                return_clause="RETURN elementId(u) AS id, properties(u) AS props",
            ),
            {"sk": sk, "q": q}, timeout=30)
        if not found:
            return {"nds": [], "rls": [], "sketch_id": sk}

        subj_id = found[0]["id"]
        nds = [self._unflatten(subj_id, found[0]["props"])]
        rls: List[Dict[str, Any]] = []
        rows = self._neo(
            "MATCH (u) WHERE elementId(u) = $id "
            "MATCH (u)-[r]-(o) WHERE o.sketch_id = $sk AND o.deleted_at IS NULL "
            "RETURN elementId(o) AS oid, properties(o) AS oprops, type(r) AS rel, "
            "  elementId(startNode(r)) AS src, elementId(endNode(r)) AS dst LIMIT 4000",
            {"id": subj_id, "sk": sk}, timeout=45)
        seen = {subj_id}
        for row in rows:
            if row["oid"] not in seen:
                seen.add(row["oid"])
                nds.append(self._unflatten(row["oid"], row["oprops"]))
            rls.append({"source": row["src"], "target": row["dst"], "label": row["rel"]})
        return {"nds": nds, "rls": rls, "sketch_id": sk}

    def _classify_os(self, os_str: str):
        raw = (os_str or "").lower()
        for key, name, eol in OS_EOL_DB:
            if key in raw:
                return name, eol
        return os_str or "Unknown", None

    def _os_risk(self, eol_str: Optional[str]) -> str:
        if not eol_str:
            return "supported"
        from datetime import date, datetime
        eol = datetime.strptime(eol_str, "%Y-%m-%d").date()
        today = date.today()
        if eol >= today:
            return "low" if (eol - today).days <= 180 else "supported"
        days = (today - eol).days
        if days > 3 * 365: return "critical"
        if days > 365:     return "high"
        return "medium"

    def get_tech_inventory(self) -> str:
        """
        Return a full technology inventory: OS version breakdown across all devices,
        software catalog (all detected tech and how many users have it), EOL device
        count, and users with high-value technology (mainframe clients, PAM tools,
        password managers, trading terminals, SAP).

        :return: JSON with os_inventory, tech_catalog, hv_users, legacy_devices.
        """
        try:
            graph = self._graph_subset("inventory")
        except Exception as e:
            return json.dumps({"error": f"Graph fetch failed: {e}"})

        nds = graph.get("nds", [])
        rls = graph.get("rls", [])
        nodes_by_id = {n["id"]: n for n in nds}

        os_counter: Dict[str, Dict] = {}
        tech_catalog: Dict[str, int] = {}
        hv_users: List[Dict] = []
        legacy_devices: List[Dict] = []

        for node in nds:
            ntype = (node.get("nodeType") or "").lower()
            props = node.get("nodeProperties") or {}

            if ntype == "device":
                raw_os = props.get("os_name") or props.get("operating_system") or ""
                os_name, eol = self._classify_os(raw_os)
                risk = self._os_risk(eol)
                key = os_name
                if key not in os_counter:
                    os_counter[key] = {"os": os_name, "count": 0, "eol_date": eol, "risk": risk}
                os_counter[key]["count"] += 1
                if eol and risk in ("critical", "high"):
                    legacy_devices.append({
                        "hostname": node.get("nodeLabel") or props.get("hostname", ""),
                        "os":       os_name,
                        "risk":     risk,
                        "is_dc":    props.get("is_dc"),
                    })

            elif ntype == "individual":
                raw_ts = props.get("tech_stack")
                if not raw_ts:
                    continue
                try:
                    ts = json.loads(raw_ts) if isinstance(raw_ts, str) else (raw_ts if isinstance(raw_ts, list) else [])
                except Exception:
                    ts = []
                for tech in ts:
                    tech_catalog[tech] = tech_catalog.get(tech, 0) + 1
                hv = sorted(set(ts) & HIGH_VALUE_TECH)
                if hv:
                    hv_users.append({
                        "user":       node.get("nodeLabel", ""),
                        "department": props.get("department"),
                        "job_title":  props.get("job_title"),
                        "hv_tech":    hv,
                    })

        os_inventory = sorted(os_counter.values(), key=lambda x: -x["count"])
        tech_catalog_sorted = dict(sorted(tech_catalog.items(), key=lambda x: -x[1]))
        hv_users.sort(key=lambda u: -len(u["hv_tech"]))

        # Aggregate first-class Service / Technology nodes if present
        service_nodes = [n for n in nds
                         if (n.get("nodeType") or "").lower() in SERVICE_TYPES_LOWER]
        technology_nodes = [n for n in nds
                            if (n.get("nodeType") or "").lower() in TECHNOLOGY_TYPES_LOWER]
        exposed_services = []
        for svc in service_nodes[:50]:
            sp = svc.get("nodeProperties") or {}
            exposed_services.append({
                "label": svc.get("nodeLabel"),
                "port": sp.get("port"),
                "protocol": sp.get("protocol"),
                "product": sp.get("product"),
                "version": sp.get("version"),
                "cpe": sp.get("cpe"),
            })

        vulnerable_tech = []
        for tech in technology_nodes:
            tp = tech.get("nodeProperties") or {}
            if tp.get("cve_count") or tp.get("is_high_value"):
                vulnerable_tech.append({
                    "name": tp.get("name") or tech.get("nodeLabel"),
                    "version": tp.get("version"),
                    "category": tp.get("category"),
                    "vendor": tp.get("vendor"),
                    "cve_count": tp.get("cve_count"),
                    "is_high_value": tp.get("is_high_value"),
                    "mitre_techniques": tp.get("mitre_techniques") or [],
                    "composite_risk": tp.get("composite_risk"),
                })

        # Enrich vulnerable_tech with CVE details and affected users via TechContextEngine
        try:
            sys.path.insert(0, "/data/scripts")
            from tech_context_engine import TechContextEngine  # type: ignore[import]
            engine = TechContextEngine()
            for v in vulnerable_tech:
                v.setdefault("relevant_cves", engine.map_tech_to_cves(v["name"], limit=3))
                v.setdefault("mitre_techniques", engine.map_tech_to_mitre(v["name"], limit=3))
                v["composite_risk"] = v.get("composite_risk") or engine.compute_composite_risk(
                    ad_max_score=0, breach_count=0, has_stealer_log=False,
                    os_risk="supported", tech_stack=[v["name"]],
                    cve_exposure=v.get("cve_count", 0),
                ).get("score", 0)
        except Exception:
            pass

        # Map affected users/hosts per vulnerable tech
        tech_name_to_id = {n.get("nodeLabel"): n["id"] for n in technology_nodes}
        tech_name_to_id.update({(n.get("nodeProperties") or {}).get("name"): n["id"] for n in technology_nodes})
        for v in vulnerable_tech:
            tech_id = tech_name_to_id.get(v["name"])
            if not tech_id:
                continue
            affected_users, affected_hosts = set(), set()
            for edge in rls:
                if edge.get("source") != tech_id and edge.get("target") != tech_id:
                    continue
                other_id = edge.get("target") if edge.get("source") == tech_id else edge.get("source")
                other = nodes_by_id.get(other_id)
                if not other:
                    continue
                otype = (other.get("nodeType") or "").lower()
                if otype == "individual":
                    affected_users.add(other.get("nodeLabel") or (other.get("nodeProperties") or {}).get("sam_account_name") or other_id)
                elif otype == "device":
                    affected_hosts.add(other.get("nodeLabel") or (other.get("nodeProperties") or {}).get("hostname") or other_id)
            v["affected_users"] = sorted(affected_users)[:10]
            v["affected_hosts"] = sorted(affected_hosts)[:10]

        return json.dumps({
            "os_inventory":    os_inventory,
            "tech_catalog":    tech_catalog_sorted,
            "hv_users":        hv_users,
            "legacy_devices":  legacy_devices[:20],
            "eol_count":       len(legacy_devices),
            "hv_user_count":   len(hv_users),
            "service_count":   len(service_nodes),
            "technology_count": len(technology_nodes),
            "exposed_services": exposed_services,
            "vulnerable_tech": vulnerable_tech[:20],
        }, indent=2, default=str)

    def get_user_tech_profile(self, identifier: str) -> str:
        """
        Return a user's complete technology profile: their workstation (hostname,
        OS, risk), detected tech stack, high-value tech, and which systems they
        have direct access to via their software.

        :param identifier: Label, display name, SID, username, email, or node id. Matching is scripts/individual_lookup.py.
        :return: JSON with computer, OS, tech_stack, hv_tech, credential_attack_surface.
        """
        try:
            graph = self._graph_subset("user", identifier)
        except Exception as e:
            return json.dumps({"error": f"Graph fetch failed: {e}"})

        nds = graph.get("nds", [])
        rls = graph.get("rls", [])
        nodes_by_id = {n["id"]: n for n in nds}

        # First hit, not shortest-label: _graph_subset already applied the
        # tie-break and put that subject first.
        individual = None
        for node in nds:
            if (node.get("nodeType") or "").lower() != "individual":
                continue
            props = node.get("nodeProperties") or {}
            if identifier_matches(node.get("nodeLabel", ""), props, node.get("id", ""), identifier):
                individual = node
                break

        if individual is None:
            return json.dumps({"error": f"No Individual found matching '{identifier}'"})

        ind_id    = individual["id"]
        ind_props = individual.get("nodeProperties") or {}

        raw_ts = ind_props.get("tech_stack")
        try:
            tech_stack = json.loads(raw_ts) if isinstance(raw_ts, str) else (raw_ts if isinstance(raw_ts, list) else [])
        except Exception:
            tech_stack = []

        hv_tech = sorted(set(tech_stack) & HIGH_VALUE_TECH)

        # Find sessions (device nodes this user has sessions on)
        devices = []
        for edge in rls:
            src, tgt, label = edge.get("source"), edge.get("target"), edge.get("label")
            if label != "HAS_SESSION":
                continue
            dev_node = None
            if src == ind_id:
                dev_node = nodes_by_id.get(tgt)
            elif tgt == ind_id:
                dev_node = nodes_by_id.get(src)
            if dev_node and (dev_node.get("nodeType") or "").lower() == "device":
                dp = dev_node.get("nodeProperties") or {}
                raw_os = dp.get("os_name") or dp.get("operating_system") or ""
                os_name, eol = self._classify_os(raw_os)
                devices.append({
                    "hostname": dev_node.get("nodeLabel") or dp.get("hostname", ""),
                    "os":       os_name,
                    "os_risk":  self._os_risk(eol),
                    "is_dc":    dp.get("is_dc"),
                })

        # Build credential attack surface guide for each HV tech detected
        attack_surface = {}
        for tech in hv_tech:
            if tech in CRED_EXTRACTION_GUIDE:
                attack_surface[tech] = CRED_EXTRACTION_GUIDE[tech]

        # Optional contextualization via tech_context_engine
        relevant_cves: List[Dict[str, Any]] = []
        mitre_techniques: List[Dict[str, Any]] = []
        composite_risk: Optional[Dict[str, Any]] = None
        # Assigned inside the try below, but referenced unconditionally in the
        # response — initialise it or a missing tech_context_engine raises
        # UnboundLocalError instead of degrading gracefully.
        primary_device: Optional[Dict[str, Any]] = next((d for d in devices if not d.get("is_dc")),
                                                        devices[0] if devices else None)
        try:
            sys.path.insert(0, "/data/scripts")
            from tech_context_engine import TechContextEngine  # type: ignore[import]
            engine = TechContextEngine()
            for tech in hv_tech[:3]:
                relevant_cves.extend(engine.map_tech_to_cves(tech, limit=3))
                mitre_techniques.extend(engine.map_tech_to_mitre(tech, limit=3))
            relevant_cves = list({c["cve_id"]: c for c in relevant_cves}.values())[:5]
            mitre_techniques = list({m["technique_id"]: m for m in mitre_techniques}.values())[:5]
            primary_device = next((d for d in devices if not d.get("is_dc")), devices[0] if devices else None)
            composite_risk = engine.compute_composite_risk(
                ad_max_score=ind_props.get("ad_max_score", 0),
                breach_count=ind_props.get("breach_count", 0),
                has_stealer_log=ind_props.get("has_stealer_log", False),
                os_risk=primary_device.get("os_risk", "supported") if primary_device else "supported",
                tech_stack=tech_stack,
                cve_exposure=len(relevant_cves),
            )
        except Exception:
            pass

        return json.dumps({
            "user":              individual.get("nodeLabel", ""),
            "full_name":         ind_props.get("full_name"),
            "department":        ind_props.get("department"),
            "job_title":         ind_props.get("job_title"),
            "tech_stack":        tech_stack,
            "hv_tech":           hv_tech,
            "devices":           devices,
            "primary_device":    primary_device,
            "breach_count":      ind_props.get("breach_count", 0),
            "has_stealer_log":   ind_props.get("has_stealer_log", False),
            "credential_attack_surface": attack_surface,
            "relevant_cves":     relevant_cves,
            "mitre_techniques":  mitre_techniques,
            "composite_risk":    composite_risk,
        }, indent=2, default=str)

    def generate_attack_narrative(self, identifier: str) -> str:
        """
        Generate a targeted 'Jane scenario' attack narrative for a specific user.

        Combines their department/role, workstation details, OS vulnerability, tech
        stack, and high-value credential stores into a step-by-step red team plan:
        initial access → persistence → credential extraction (browser, OS, app-specific)
        → pivot to the target system they connect to.

        :param identifier: Label, display name, SID, username, email, or node id. Matching is scripts/individual_lookup.py.
        :return: Markdown-formatted attack narrative.
        """
        profile_json = self.get_user_tech_profile(identifier)
        try:
            profile = json.loads(profile_json)
        except Exception:
            return f"Error parsing profile for '{identifier}'"

        if "error" in profile:
            return profile["error"]

        user        = profile.get("user", identifier)
        full_name   = profile.get("full_name") or user.split("@")[0]
        dept        = profile.get("department") or ""
        job         = profile.get("job_title") or ""
        role_str    = f"{dept} — {job}" if dept and job else (dept or job or "unknown role")
        pd          = profile.get("primary_device") or {}
        hostname    = pd.get("hostname", "unknown workstation")
        os_name     = pd.get("os", "unknown OS")
        os_risk     = pd.get("os_risk", "unknown")
        hv_tech     = profile.get("hv_tech") or []
        all_tech    = profile.get("tech_stack") or []
        breach_count = profile.get("breach_count", 0)
        has_stealer = profile.get("has_stealer_log", False)
        attack_surf = profile.get("credential_attack_surface") or {}

        lines = [f"## Attack Narrative: {full_name} ({user})", ""]
        lines += [
            f"**Role:** {role_str}",
            f"**Workstation:** `{hostname}`",
            f"**OS:** {os_name}  |  **Risk tier:** `{os_risk.upper()}`",
        ]
        if hv_tech:
            lines.append(f"**High-value tech:** {', '.join(hv_tech)}")
        if breach_count or has_stealer:
            breach_note = []
            if breach_count:
                breach_note.append(f"{breach_count} breach records")
            if has_stealer:
                breach_note.append("stealer log hit — credential reuse likely")
            lines.append(f"**Flare intel:** {', '.join(breach_note)}")
        lines.append("")

        lines.append("### Phase 1 — Initial Access")
        browsers = [t for t in all_tech if t in ("Google Chrome", "Mozilla Firefox", "Microsoft Edge", "Internet Explorer")]
        office   = [t for t in all_tech if "Microsoft" in t and t not in ("Microsoft Outlook",)]
        if dept.lower() in ("accounting", "finance", "payroll"):
            lines.append(f"- Craft a spearphishing email to {user} themed around financial reports or invoice processing")
            if "Microsoft Excel" in all_tech:
                lines.append("- Attach a macro-enabled Excel file (XLM/VBA) — accountants routinely open Excel attachments (T1566.001, T1204.002)")
        elif "Microsoft Outlook" in all_tech:
            lines.append(f"- Spearphishing email to {user} with a weaponised Office document (T1566.001)")
        else:
            lines.append(f"- Spearphishing email to {user} with a malicious link or attachment (T1566.001)")
        if os_risk in ("critical", "high"):
            lines.append(f"- Alternatively: exploit unpatched {os_name} vulnerability directly if host is reachable (T1190 / T1203)")
        if has_stealer:
            lines.append(f"- Credential stuffing using Flare stealer log credentials — attempt VPN/Citrix/OWA login first (T1078)")
        lines.append("")

        lines.append("### Phase 2 — Persistence on Workstation")
        lines += [
            f"- Deploy implant on `{hostname}` — establish C2 beacon (T1059)",
            "- Scheduled task or registry run key for persistence (T1053.005 / T1547.001)",
            "- Ensure persistence survives reboots before extracting credentials",
        ]
        lines.append("")

        lines.append("### Phase 3 — Credential Extraction")

        if browsers:
            lines.append(f"**Browser credentials** ({', '.join(browsers)}):")
            lines += [
                "- Dump saved credentials via DPAPI decryption of browser login database (T1555.003)",
                "- Extract cookies/session tokens for web applications they're logged into",
                "- Harvest autofill data for additional account credentials",
            ]
            lines.append("")

        lines.append("**OS credential extraction:**")
        lines += [
            "- LSASS memory dump via Mimikatz / ProcDump → extract NTLM hashes and Kerberos tickets (T1003.001)",
            "- SAM database dump from registry: `reg save HKLM\\SAM` (T1003.002)",
            "- Credential Manager extraction (Windows Vault) for saved network credentials (T1555.004)",
            f"- Check `%APPDATA%` and `%LOCALAPPDATA%` for stored credential files",
        ]
        lines.append("")

        if attack_surf:
            for tech, steps in attack_surf.items():
                lines.append(f"**{tech}:**")
                for step in steps:
                    lines.append(f"- {step}")
                lines.append("")

        if hv_tech:
            lines.append("### Phase 4 — Pivot to Target System")
            for tech in hv_tech:
                if "AS/400" in tech or "iSeries" in tech or "TN5250" in tech:
                    lines += [
                        "- Use extracted AS/400 / iSeries credentials to authenticate to IBM i system via TN5250 (TCP/23 or TCP/449)",
                        "- AS/400 profiles often lack password complexity requirements and MFA — high credential reuse probability",
                        "- Once authenticated: explore IBM i file system (IFS), job queues, and data queues for sensitive data",
                        "- IBM i authority levels (QSECOFR = root equivalent) — check for profile with *ALLOBJ authority",
                        "- ATT&CK: T1078 (Valid Accounts), T1021 (Remote Services — non-standard protocol)",
                    ]
                elif "Mainframe" in tech or "TN3270" in tech:
                    lines += [
                        "- Replay extracted mainframe credentials via TN3270 session to target host (TCP/23 or TCP/992)",
                        "- Mainframe RACF/ACF2/TopSecret — enumerate user authority with extracted session",
                        "- Pivot to batch job submission or ISPF to access sensitive data",
                        "- ATT&CK: T1078, T1021",
                    ]
                elif "SAP" in tech:
                    lines += [
                        "- Authenticate to SAP system using extracted credentials (RFC/DIAG port TCP/3200-3299 or HTTPS)",
                        "- Use SAP transaction SE38 / SE80 to execute ABAP code if authorized (T1059)",
                        "- Enumerate sensitive data in FI/HR modules (vendor bank accounts, salary data, PII)",
                        "- ATT&CK: T1078, T1213 (Data from Information Repositories)",
                    ]
                elif "PAM" in tech or tech in ("CyberArk PAM", "BeyondTrust PAM", "Thycotic Secret Server", "Delinea PAM"):
                    lines += [
                        "- PAM access = keys to the kingdom: extract all managed account passwords from vault",
                        "- Target the PAM web portal (PVWA/BeyondInsight) with extracted user credentials",
                        "- If CyberArk: use 'transparent auth' to access managed systems without seeing raw passwords",
                        "- Escalate: PAM admin accounts can export the full credential vault",
                        "- ATT&CK: T1078, T1555 (Credentials from Password Stores)",
                    ]
                elif "Password Manager" in tech or tech in ("KeePass Password Manager", "1Password", "LastPass", "Bitwarden"):
                    lines += [
                        f"- Exfiltrate {tech} database file (.kdbx / vault) from disk",
                        "- If KeePass is running: dump master password from memory (KeeThief) or auto-type intercept",
                        "- Offline crack: hashcat mode 13400 against .kdbx with rockyou + target-specific wordlist",
                        "- ATT&CK: T1555.001 (Keychain), T1555 (Credentials from Password Stores)",
                    ]
                elif "Bloomberg" in tech or "Eikon" in tech:
                    lines += [
                        "- Access Bloomberg/Reuters with stolen credentials for market data and proprietary research",
                        "- Bloomberg session token may be reusable across terminals",
                        "- ATT&CK: T1078, T1213",
                    ]

        lines.append("")
        lines.append("### ATT&CK Coverage")
        attck = set()
        if "Microsoft Excel" in all_tech or "Microsoft Word" in all_tech:
            attck |= {"T1566.001 Spearphishing Attachment", "T1204.002 Malicious File"}
        if os_risk in ("critical", "high"):
            attck.add("T1190 Exploit Public-Facing Application")
        if has_stealer:
            attck.add("T1078 Valid Accounts (credential stuffing)")
        attck |= {"T1059 Command and Scripting Interpreter", "T1053.005 Scheduled Task",
                  "T1003.001 LSASS Memory Dump", "T1555.003 Credentials from Web Browsers",
                  "T1555.004 Windows Credential Manager"}
        if hv_tech:
            attck |= {"T1078 Valid Accounts (pivot)", "T1021 Remote Services"}
        for t in sorted(attck):
            lines.append(f"- {t}")

        return "\n".join(lines)
