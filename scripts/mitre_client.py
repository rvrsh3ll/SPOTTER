"""
mitre_client.py — MITRE ATT&CK STIX downloader and technique mapper.

Downloads the latest enterprise ATT&CK STIX bundle and provides lookups:
  - techniques_for_tactic(tactic)
  - techniques_for_software(software_name)
  - techniques_for_cve(cve_id)
  - get_technique(technique_id)

Results are cached locally in JSON for offline use.

Environment:
    SPOTTER_CACHE_DIR — cache directory (default: ./.spotter-cache)
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

import requests

from spotter_cache import ensure_cache_path


ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DEFAULT_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".spotter-cache")


class MITREClient:
    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = cache_dir or os.environ.get("SPOTTER_CACHE_DIR") or DEFAULT_CACHE_DIR
        os.makedirs(self.cache_dir, exist_ok=True)
        ensure_cache_path(self.cache_dir, is_dir=True)
        self.bundle_path = os.path.join(self.cache_dir, "enterprise-attack.json")
        if os.path.exists(self.bundle_path):
            ensure_cache_path(self.bundle_path, is_dir=False)
        self._objects: List[Dict[str, Any]] = []
        self._by_id: Dict[str, Dict[str, Any]] = {}
        self._by_name: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        if not os.path.exists(self.bundle_path):
            self.refresh()
        with open(self.bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        self._objects = bundle.get("objects", [])
        for obj in self._objects:
            obj_id = obj.get("id")
            if obj_id:
                self._by_id[obj_id] = obj
            name = obj.get("name", "")
            if name:
                self._by_name[name.lower()] = obj
        self._loaded = True

    def refresh(self) -> None:
        """Download the latest ATT&CK STIX bundle."""
        resp = requests.get(ATTACK_STIX_URL, timeout=120)
        resp.raise_for_status()
        with open(self.bundle_path, "w", encoding="utf-8") as f:
            json.dump(resp.json(), f)
        ensure_cache_path(self.bundle_path, is_dir=False)
        self._loaded = False
        self._load()

    def _technique_id(self, obj: Dict[str, Any]) -> Optional[str]:
        for ext in obj.get("external_references", []):
            if ext.get("source_name") == "mitre-attack":
                return ext.get("external_id")
        return None

    def _technique_ids_from_relationships(self, source_id: str, relationship_type: str) -> List[str]:
        self._load()
        technique_ids: List[str] = []
        for obj in self._objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("relationship_type") != relationship_type:
                continue
            if obj.get("source_ref") == source_id:
                target = self._by_id.get(obj.get("target_ref", ""))
                if target and target.get("type") == "attack-pattern":
                    tid = self._technique_id(target)
                    if tid and tid not in technique_ids:
                        technique_ids.append(tid)
        return technique_ids

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Return technique details by MITRE technique ID (e.g. T1566.001)."""
        self._load()
        for obj in self._objects:
            if obj.get("type") != "attack-pattern":
                continue
            for ext in obj.get("external_references", []):
                if ext.get("external_id") == technique_id:
                    return {
                        "technique_id": technique_id,
                        "name": obj.get("name"),
                        "description": obj.get("description", ""),
                        "tactics": [
                            phase.get("phase_name")
                            for phase in obj.get("kill_chain_phases", [])
                        ],
                        "platforms": obj.get("x_mitre_platforms", []),
                        "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                    }
        return None

    def techniques_for_tactic(self, tactic: str) -> List[Dict[str, Any]]:
        """Return techniques mapped to a tactic (e.g. 'initial-access')."""
        self._load()
        tactic_lower = tactic.lower().replace(" ", "-")
        results: List[Dict[str, Any]] = []
        seen: set = set()
        for obj in self._objects:
            if obj.get("type") != "attack-pattern":
                continue
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("phase_name", "").lower() == tactic_lower:
                    tid = self._technique_id(obj)
                    if tid and tid not in seen:
                        seen.add(tid)
                        results.append({
                            "technique_id": tid,
                            "name": obj.get("name"),
                            "description": obj.get("description", ""),
                        })
        return results

    def techniques_for_software(self, software_name: str) -> List[Dict[str, Any]]:
        """Return techniques used by a named software/tool."""
        self._load()
        key = software_name.lower()
        software = self._by_name.get(key)
        if not software:
            # Fuzzy match on aliases
            for obj in self._objects:
                if obj.get("type") not in ("malware", "tool"):
                    continue
                aliases = [a.lower() for a in obj.get("x_mitre_aliases", [])]
                if key in aliases or key in obj.get("name", "").lower():
                    software = obj
                    break
        if not software:
            return []

        technique_ids = self._technique_ids_from_relationships(
            software.get("id"), "uses"
        )
        return [t for t in (self.get_technique(tid) for tid in technique_ids) if t]

    def techniques_for_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Return techniques associated with a CVE via CAPEC mappings if present."""
        self._load()
        # Direct CVE→technique relationships are rare in ATT&CK; return empty by default.
        # Future enhancement: map CVE→CAPEC→technique.
        return []

    def search_techniques(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search technique names and descriptions by keyword."""
        self._load()
        q = query.lower()
        results: List[Dict[str, Any]] = []
        for obj in self._objects:
            if obj.get("type") != "attack-pattern":
                continue
            name = obj.get("name", "").lower()
            desc = obj.get("description", "").lower()
            if q in name or q in desc:
                tid = self._technique_id(obj)
                if tid:
                    results.append({
                        "technique_id": tid,
                        "name": obj.get("name"),
                        "description": obj.get("description", ""),
                    })
            if len(results) >= limit:
                break
        return results[:limit]


if __name__ == "__main__":
    client = MITREClient()
    print(json.dumps(client.get_technique("T1566.001"), indent=2))
