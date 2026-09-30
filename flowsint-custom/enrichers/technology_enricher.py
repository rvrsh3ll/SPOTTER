"""
TechnologyEnricher — Flowsint plugin enricher for technology nodes.

Reads technology-relevant properties on Individual and Device nodes and
creates first-class Technology nodes plus relationships:

  Individual -[USES_TECHNOLOGY]-> Technology
  Device     -[RUNS_TECHNOLOGY]-> Technology

Also marks technologies as high-value when they match the SPOTTER high-value
tech set (PAM tools, password managers, mainframe emulators, SAP, etc.).

Installation: copy this file into the Flowsint container at
  /app/flowsint-enrichers/src/flowsint_enrichers/spotter/
and restart flowsint-api-prod and flowsint-celery-prod.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Set, Tuple

for _scripts_dir in (
    os.environ.get("SPOTTER_SCRIPTS_DIR", "/data/scripts"),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts")),
):
    if _scripts_dir and os.path.isdir(_scripts_dir) and _scripts_dir not in sys.path:
        sys.path.insert(0, _scripts_dir)

from high_value_tech import HIGH_VALUE_TECH

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.individual import Individual

try:
    from flowsint_types.device import Device as DeviceType  # type: ignore[import]
except ImportError:
    from flowsint_types.individual import Individual as DeviceType  # type: ignore[import]

# ── Cypher templates ──────────────────────────────────────────────────────────

_CYPHER_READ_INDIVIDUAL = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
RETURN n.`nodeProperties.tech_stack` AS tech_stack,
       n.`nodeProperties.process_list` AS process_list
"""

_CYPHER_READ_DEVICE = """
MATCH (n:device {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
RETURN n.`nodeProperties.operating_system` AS operating_system,
       n.`nodeProperties.os_name` AS os_name
"""

_CYPHER_MERGE_TECH = """
MERGE (t:technology {nodeLabel: $label, sketch_id: $sketch_id})
ON CREATE SET t.entity_type = 'Technology',
              t.`nodeProperties.name` = $name,
              t.`nodeProperties.vendor` = $vendor,
              t.`nodeProperties.version` = $version,
              t.`nodeProperties.category` = $category,
              t.`nodeProperties.source` = $source,
              t.`nodeProperties.confidence` = $confidence,
              t.`nodeProperties.is_high_value` = $is_high_value,
              t.`nodeProperties.cpe` = $cpe,
              t.include = true
ON MATCH SET t.`nodeProperties.source` = coalesce(t.`nodeProperties.source`, $source),
             t.`nodeProperties.is_high_value` = coalesce(t.`nodeProperties.is_high_value`, false) OR $is_high_value
RETURN id(t) AS node_id
"""

_CYPHER_LINK_INDIVIDUAL = """
MATCH (u:individual {nodeLabel: $label, sketch_id: $sketch_id})
      ,(t:technology {nodeLabel: $tech_label, sketch_id: $sketch_id})
WHERE u.deleted_at IS NULL AND t.deleted_at IS NULL
MERGE (u)-[r:USES_TECHNOLOGY]->(t)
ON CREATE SET r.source = $source
"""

_CYPHER_LINK_DEVICE = """
MATCH (d:device {nodeLabel: $label, sketch_id: $sketch_id})
      ,(t:technology {nodeLabel: $tech_label, sketch_id: $sketch_id})
WHERE d.deleted_at IS NULL AND t.deleted_at IS NULL
MERGE (d)-[r:RUNS_TECHNOLOGY]->(t)
ON CREATE SET r.source = $source
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_tech_stack(raw: Any) -> List[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return [raw]
    if isinstance(raw, list):
        return raw
    return []


def _derive_category(tech_name: str) -> str:
    t = tech_name.lower()
    if any(k in t for k in ("mainframe", "tn3270", "tn5250", "as/400", "iseries", "ibm personal communications")):
        return "Legacy/Mainframe"
    if "sap" in t:
        return "ERP"
    if any(k in t for k in ("sql", "oracle", "mysql", "postgresql", "mongodb", "dbeaver")):
        return "Database"
    if any(k in t for k in ("password", "pam", "cyberark", "beyondtrust", "thycotic", "delinea", "keepass", "1password", "lastpass", "bitwarden")):
        return "Credential Store / PAM"
    if any(k in t for k in ("bloomberg", "eikon", "refinitiv", "reuters")):
        return "Financial/Trading"
    if any(k in t for k in ("citrix", "rdp", "putty", "winscp", "ssh", "anyconnect", "globalprotect", "pulse secure")):
        return "Remote Access"
    if any(k in t for k in ("python", "java", "visual studio", "git", "docker", "kubernetes", "terraform")):
        return "Development"
    if any(k in t for k in ("outlook", "teams", "slack", "zoom")):
        return "Office/Productivity"
    if any(k in t for k in ("crowdstrike", "carbon black", "defender", "nessus", "qualys")):
        return "Security"
    if "windows" in t or "linux" in t or "macos" in t:
        return "Operating System"
    return "Other"


def _vendor_from_name(tech_name: str) -> Optional[str]:
    t = tech_name.lower()
    if "microsoft" in t or t.startswith("windows") or "sql server" in t or "visual studio" in t:
        return "Microsoft"
    if "ibm" in t:
        return "IBM"
    if "sap" in t:
        return "SAP"
    if "oracle" in t:
        return "Oracle"
    if "apache" in t:
        return "Apache"
    if "nginx" in t:
        return "Nginx"
    if "citrix" in t:
        return "Citrix"
    if "cyberark" in t:
        return "CyberArk"
    if "beyondtrust" in t:
        return "BeyondTrust"
    if "thycotic" in t:
        return "Thycotic"
    if "delinea" in t:
        return "Delinea"
    if "bloomberg" in t:
        return "Bloomberg"
    if "refinitiv" in t or "eikon" in t:
        return "Refinitiv"
    return None


# ── Enricher ──────────────────────────────────────────────────────────────────

@flowsint_enricher
class TechnologyEnricher(Enricher):
    """Create Technology nodes from Individual.tech_stack and Device OS data."""

    InputType = Individual
    OutputType = Individual

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tech_to_create: List[Dict[str, Any]] = []
        self._links: List[Tuple[str, str, str, str]] = []  # (node_type, label, tech_label, source)

    @classmethod
    def name(cls) -> str:
        return "technology_enricher"

    @classmethod
    def category(cls) -> str:
        return "SPOTTER"

    @classmethod
    def key(cls) -> str:
        return "nodeLabel"

    @classmethod
    def documentation(cls) -> str:
        return (
            "Creates first-class Technology nodes from Individual.tech_stack "
            "and Device operating_system properties, links them via "
            "USES_TECHNOLOGY / RUNS_TECHNOLOGY relationships, and flags "
            "high-value technologies."
        )

    async def scan(self, data: List[Individual]) -> List[Individual]:  # type: ignore[override]
        self._tech_to_create = []
        self._links = []

        for node in data:
            label = getattr(node, "nodeLabel", None)
            ntype = (getattr(node, "nodeType", "") or "").lower()
            if not label:
                continue

            if ntype == "individual":
                self._process_individual(label)
            elif ntype == "device":
                self._process_device(label)

        return data

    def _process_individual(self, label: str) -> None:
        rows = self._graph_service.query(_CYPHER_READ_INDIVIDUAL, {
            "label": label,
            "sketch_id": self.sketch_id,
        })
        if not rows:
            return

        tech_stack = _parse_tech_stack(rows[0].get("tech_stack"))
        for tech_name in tech_stack:
            if not tech_name:
                continue
            tech_label = tech_name
            category = _derive_category(tech_name)
            vendor = _vendor_from_name(tech_name)
            is_hv = tech_name in HIGH_VALUE_TECH

            self._tech_to_create.append({
                "label": tech_label,
                "name": tech_name,
                "vendor": vendor,
                "version": None,
                "category": category,
                "source": "cobalt_strike",
                "confidence": "medium",
                "is_high_value": is_hv,
                "cpe": None,
            })
            self._links.append(("individual", label, tech_label, "cobalt_strike"))

    def _process_device(self, label: str) -> None:
        rows = self._graph_service.query(_CYPHER_READ_DEVICE, {
            "label": label,
            "sketch_id": self.sketch_id,
        })
        if not rows:
            return

        os_name = rows[0].get("os_name") or rows[0].get("operating_system")
        if not os_name:
            return

        tech_label = os_name
        category = "Operating System"
        vendor = _vendor_from_name(os_name)

        self._tech_to_create.append({
            "label": tech_label,
            "name": os_name,
            "vendor": vendor,
            "version": None,
            "category": category,
            "source": "sharphound",
            "confidence": "high",
            "is_high_value": False,
            "cpe": None,
        })
        self._links.append(("device", label, tech_label, "sharphound"))

    def postprocess(
        self,
        results: List[Individual],
        original_input: List[Individual],
    ) -> List[Individual]:
        # Deduplicate technology nodes by label within this batch
        seen: Set[str] = set()
        for tech in self._tech_to_create:
            key = tech["label"].lower()
            if key in seen:
                continue
            seen.add(key)

            self._graph_service.query(_CYPHER_MERGE_TECH, {
                "label": tech["label"],
                "sketch_id": self.sketch_id,
                "name": tech["name"],
                "vendor": tech["vendor"],
                "version": tech["version"],
                "category": tech["category"],
                "source": tech["source"],
                "confidence": tech["confidence"],
                "is_high_value": tech["is_high_value"],
                "cpe": tech["cpe"],
            })

        for node_type, label, tech_label, source in self._links:
            cypher = _CYPHER_LINK_INDIVIDUAL if node_type == "individual" else _CYPHER_LINK_DEVICE
            self._graph_service.query(cypher, {
                "label": label,
                "tech_label": tech_label,
                "sketch_id": self.sketch_id,
                "source": source,
            })

        if self._tech_to_create:
            self.log_graph_message(
                f"Technology enrichment: created/updated {len(seen)} technology nodes "
                f"and {len(self._links)} relationships."
            )

        return results


InputType = TechnologyEnricher.InputType
OutputType = TechnologyEnricher.OutputType
