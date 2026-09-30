"""
tech_context_engine.py — Contextualize detected technologies into actionable
intelligence for SPOTTER operators.

Responsibilities:
  - Map a technology name/version to relevant CVEs (via NVD) and MITRE
    ATT&CK techniques (via local STIX + RAG).
  - Annotate those CVEs with public exploit availability (via the local
    PoC-in-GitHub mirror, scripts/poc_client.py).
  - Compute a composite risk score per Individual or Device that combines
    AD rights, breach exposure, OS EOL risk, and high-value technology presence.
  - Generate markdown attack narratives that cite specific CVEs and MITRE
    technique IDs where available.

This module is called by:
  - llm/tools/technology_tool.py
  - llm/tools/tech_context_tool.py
  - scripts/tech_enricher.py          (writes the results onto Technology nodes)
  - n8n-workflows/12-tech-inventory.json
  - n8n-workflows/10-security-llm-analysis.json
  - n8n-workflows/14-tech-context-indexer.json

A CVE with public exploit code is a materially different proposition from one
without, so `map_tech_to_cves` attaches `poc_count` / `exploit_available` /
`pocs` to every CVE it returns, and `compute_composite_risk` weights exploitable
exposure above theoretical exposure. PoC repositories are UNVETTED — see
scripts/poc_client.py — and every record carries that flag through unchanged.
"""

from __future__ import annotations

import json
import os
from datetime import date
from typing import Any, Dict, List, Optional

from cve_client import CVEClient
from high_value_tech import HIGH_VALUE_TECH
from mitre_client import MITREClient
from poc_client import PoCClient
from rag_indexer import RAGIndexer

# Hardcoded credential-extraction playbooks (fallback when RAG is offline)
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


class TechContextEngine:
    def __init__(self, cache_dir: Optional[str] = None):
        self.cve_client = CVEClient(cache_dir=cache_dir)
        self.mitre_client = MITREClient(cache_dir=cache_dir)
        self.poc_client = PoCClient(cache_dir=cache_dir)
        self.rag_indexer = RAGIndexer(cache_dir=cache_dir)

    def annotate_cves_with_pocs(
        self, cves: List[Dict[str, Any]], pocs_per_cve: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Attach public-exploit availability to each CVE, in place.

        Adds `poc_count`, `exploit_available` and `pocs` (the top few ranked
        repositories). A missing or unsynced mirror yields poc_count 0 rather
        than an error — but callers that care about the difference between "no
        exploit exists" and "we have no data" should check
        `poc_client.mirror_status()['stale']`, which is exactly why
        map_tech_to_cves does not swallow that distinction silently.
        """
        for cve in cves:
            cve_id = cve.get("cve_id") or ""
            try:
                hits = self.poc_client.pocs_for_cve(cve_id, limit=pocs_per_cve)
            except Exception:
                hits = []
            cve["pocs"] = hits
            cve["poc_count"] = len(hits)
            cve["exploit_available"] = bool(hits)
        return cves

    def map_tech_to_cves(
        self,
        tech_name: str,
        version: Optional[str] = None,
        limit: int = 5,
        with_pocs: bool = True,
    ) -> List[Dict[str, Any]]:
        """Return CVEs relevant to a technology name and optional version."""
        query = f"{tech_name} {version}".strip() if version else tech_name
        cves = self.cve_client.search_by_keyword(query, limit=limit)
        if not cves and version:
            # Fallback to product-only search if versioned search returns nothing
            cves = self.cve_client.search_by_keyword(tech_name, limit=limit)
        if with_pocs and cves:
            self.annotate_cves_with_pocs(cves)
        return cves

    def map_cpe_to_cves(
        self, cpe: str, limit: int = 5, with_pocs: bool = True
    ) -> List[Dict[str, Any]]:
        """
        CVEs for a CPE, in whichever spelling the graph holds.

        Always preferred over the keyword path when a CPE exists: a keyword search
        for "Apache httpd" phrase-matches CVEs belonging to *other* products that
        merely run Apache, which attributes someone else's vulnerability to your
        host. A CPE match cannot do that.

        Tries the partial (virtualMatchString) form first because it accepts CPE
        2.2 and version-less CPEs, which is what WF13's Service nodes actually
        carry; falls back to the exact cpeName lookup for a full 2.3 name.
        """
        prefix = self.cve_client.cpe23_prefix(cpe)
        cves: List[Dict[str, Any]] = []
        if prefix:
            try:
                cves = self.cve_client.search_by_cpe_prefix(prefix, limit=limit)
            except Exception:
                cves = []
        if not cves and cpe.startswith("cpe:2.3:"):
            try:
                cves = self.cve_client.search_by_cpe(cpe, limit=limit)
            except Exception:
                cves = []
        if with_pocs and cves:
            self.annotate_cves_with_pocs(cves)
        return cves

    def map_tech_to_mitre(self, tech_name: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Return MITRE ATT&CK techniques relevant to a technology."""
        # Try direct software mapping first
        techniques = self.mitre_client.techniques_for_software(tech_name)
        if techniques:
            return techniques[:limit]

        # Fall back to RAG search over indexed techniques
        try:
            rag_results = self.rag_indexer.query("mitre_index", tech_name, n_results=limit)
            techniques = []
            for r in rag_results:
                meta = r.get("metadata", {})
                tid = meta.get("technique_id")
                if tid:
                    detail = self.mitre_client.get_technique(tid)
                    if detail:
                        techniques.append(detail)
            return techniques
        except Exception:
            return []

    def credential_extraction_steps(self, tech_name: str) -> List[str]:
        """Return operator playbook steps for a high-value technology."""
        if tech_name in CRED_EXTRACTION_GUIDE:
            return CRED_EXTRACTION_GUIDE[tech_name]
        # Try RAG guides
        try:
            rag_results = self.rag_indexer.query("tech_guides", tech_name, n_results=1)
            if rag_results:
                return [rag_results[0]["document"]]
        except Exception:
            pass
        return []

    def compute_composite_risk(
        self,
        ad_max_score: int = 0,
        breach_count: int = 0,
        has_stealer_log: bool = False,
        os_risk: str = "supported",
        tech_stack: Optional[List[str]] = None,
        cve_exposure: int = 0,
        exploitable_cve_count: int = 0,
    ) -> Dict[str, Any]:
        """
        Compute a composite risk score from multiple intelligence sources.

        `exploitable_cve_count` is the subset of `cve_exposure` with public PoC
        code. It is scored ON TOP of the CVE term rather than replacing it: a
        vulnerability someone has already written a working exploit for is
        cheaper to use than one that would need original development, and that
        difference should move a target up the list. Defaults to 0, so callers
        predating the PoC source score exactly as they did before.
        """
        tech_stack = tech_stack or []
        score = ad_max_score

        # Breach exposure
        score += min(breach_count * 2, 10)
        if has_stealer_log:
            score += 5

        # OS EOL risk
        os_risk_bonus = {"supported": 0, "low": 1, "medium": 3, "high": 5, "critical": 8}
        score += os_risk_bonus.get(os_risk, 0)

        # High-value technology presence
        hv_tech = [t for t in tech_stack if t in HIGH_VALUE_TECH]
        score += len(hv_tech) * 3

        # CVE exposure
        score += min(cve_exposure, 10)

        # Exploit availability. Capped at 6 so a CVE with 400 public PoCs
        # (Log4Shell) cannot outweigh the AD rights that actually decide whether
        # a path exists.
        score += min(exploitable_cve_count * 2, 6)

        return {
            "composite_score": score,
            "ad_max_score": ad_max_score,
            "breach_count": breach_count,
            "has_stealer_log": has_stealer_log,
            "os_risk": os_risk,
            "high_value_tech": hv_tech,
            "cve_exposure": cve_exposure,
            "exploitable_cve_count": exploitable_cve_count,
            "risk_tier": self._risk_tier(score),
        }

    @staticmethod
    def _risk_tier(score: int) -> str:
        if score >= 30:
            return "critical"
        if score >= 20:
            return "high"
        if score >= 10:
            return "medium"
        if score > 0:
            return "low"
        return "minimal"

    def generate_attack_narrative(
        self,
        user_label: str,
        tech_stack: List[str],
        workstation: Optional[Dict[str, Any]] = None,
        ad_rights: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate a phase-by-phase attack narrative grounded in tech context."""
        hv_tech = [t for t in tech_stack if t in HIGH_VALUE_TECH]
        cves: List[Dict[str, Any]] = []
        mitre: List[Dict[str, Any]] = []
        for tech in hv_tech[:3]:
            cves.extend(self.map_tech_to_cves(tech, limit=3))
            mitre.extend(self.map_tech_to_mitre(tech, limit=3))

        # Deduplicate
        cves = list({c["cve_id"]: c for c in cves}.values())[:5]
        mitre = list({m["technique_id"]: m for m in mitre}.values())[:5]

        steps: List[str] = []
        for tech in hv_tech:
            steps.extend(self.credential_extraction_steps(tech))

        # Exploit availability across this target's CVEs. Surfaced as its own
        # block rather than left buried per-CVE, because "one of these already
        # has working public code" is the single fact most likely to change
        # which target an operator picks up first.
        exploit_summary = self.poc_client.summarise_for_cves(
            [c.get("cve_id") for c in cves if c.get("cve_id")], top_n=3
        )
        mirror = self.poc_client.mirror_status()
        if mirror.get("stale"):
            # Never let an unsynced mirror read as "no exploits exist".
            exploit_summary["caveat"] = (
                f"PoC mirror is stale (age {mirror.get('age_days')}d, "
                f"limit {mirror.get('max_age_days')}d) — absence of exploit code "
                "here is not evidence that none exists."
            )

        narrative = {
            "target": user_label,
            "high_value_tech": hv_tech,
            "workstation": workstation,
            "initial_access": (
                "Phish or leverage existing beacon on the user's workstation; "
                "prioritize credentials stored in high-value applications."
            ),
            "credential_extraction": steps[:8] or ["No specific playbook available for detected tech stack."],
            "pivot_method": (
                "Use credentials or sessions from high-value tech to move laterally "
                "to systems reachable by the user's AD rights."
            ),
            "relevant_cves": cves,
            "mitre_techniques": mitre,
            "attack_techniques": [m["technique_id"] for m in mitre],
            "exploit_availability": exploit_summary,
        }
        return narrative


if __name__ == "__main__":
    engine = TechContextEngine()
    print(json.dumps(engine.map_tech_to_cves("Apache httpd", "2.4.41", limit=3), indent=2))
    print(json.dumps(engine.map_tech_to_mitre("KeePass"), indent=2))
    print(json.dumps(engine.compute_composite_risk(
        ad_max_score=15, breach_count=2, has_stealer_log=True,
        os_risk="critical", tech_stack=["KeePass Password Manager", "SAP GUI"], cve_exposure=3
    ), indent=2))
