"""
ADPermissionEnricher — Flowsint plugin enricher for Individual nodes.

Traverses ACE-typed relationships (GenericAll, WriteDacl, etc.) outbound from
an Individual in the current sketch, computes an ad_summary, and writes the
result back to the Individual node's properties.

ACE right names are stored as the relationship TYPE in Neo4j (not as an edge
property) because the Flowsint import Edge schema has no data/properties field.
The sharphound_parser creates edges with label=<RightName> rather than
label="HAS_PERMISSION".

Installation: copy this file into the Flowsint container at
  /app/flowsint-enrichers/src/flowsint_enrichers/spotter/
then restart flowsint-api-prod and flowsint-celery-prod.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.individual import Individual

# Keep in sync with llm/tools/attack_path_tool.py ACE_SCORES (tradecraft update 2026-07).
ACE_SCORES: Dict[str, int] = {
    "GenericAll":         10,
    "WriteDacl":           9,
    "WriteOwner":          8,
    "GenericWrite":        7,
    "AllExtendedRights":   7,
    "AddAllowedToAct":     7,
    "ForceChangePassword": 6,
    "AddMember":           5,
    "Owns":                5,
    "WriteAccountRestrictions": 5,
    "AddKeyCredentialLink": 5,
    "ReadLAPSPassword":    4,
    "WriteSPN":            4,
    "ReadGMSAPassword":    4,
    "DCSync":             10,
    "GetChangesAll":      10,
    "GetChanges":          4,
    # Kerberos delegation / SID history / coercion
    "AllowedToAct":        7,
    "AllowedToDelegate":   7,
    "HasSIDHistory":       8,
    "CoerceToTGT":         8,
    # ADCS abuse (Certipy / Certify)
    "ManageCA":            8,
    "ManageCertificates":  7,
    "WritePKIEnrollmentFlag": 7,
    "WritePKINameFlag":    7,
    "Enroll":              4,
    # GPO + lateral movement
    "WriteGPLink":         8,
    "SQLAdmin":            5,
    "ExecuteDCOM":         4,
    "CanPSRemote":         4,
    "CanRDP":              3,
}

ACE_TYPES: List[str] = list(ACE_SCORES.keys())

# Traverse all outbound ACE edges from this Individual within the same sketch.
# ACE right names are the Neo4j relationship TYPE (not a property).
_CYPHER_FIND_ACES = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
WITH n
MATCH (n)-[r]->(target)
WHERE type(r) IN $ace_types
  AND target.sketch_id = $sketch_id
  AND target.deleted_at IS NULL
RETURN type(r)                              AS permission_type,
       target.nodeLabel                    AS target_label,
       target.`nodeProperties.is_dc`       AS is_dc,
       target.`nodeProperties.is_high_value` AS is_high_value
"""

_CYPHER_UPDATE = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
SET n.`nodeProperties.ad_summary`  = $ad_summary,
    n.`nodeProperties.ad_enriched` = true,
    n.`nodeProperties.ad_max_score` = $max_score
"""

_CYPHER_SET_ALERT = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
SET n.`nodeProperties.alert` = CASE
    WHEN n.`nodeProperties.alert` IS NULL OR n.`nodeProperties.alert` = ''
        THEN $new_alert
    WHEN NOT $new_alert IN split(coalesce(n.`nodeProperties.alert`, ''), ',')
        THEN n.`nodeProperties.alert` + ',' + $new_alert
    ELSE n.`nodeProperties.alert`
    END
"""


@flowsint_enricher
class ADPermissionEnricher(Enricher):
    """Summarise Active Directory ACEs for an Individual and flag high-privilege rights."""

    InputType = Individual
    OutputType = Individual

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._updates: List[Dict[str, Any]] = []

    @classmethod
    def name(cls) -> str:
        return "individual_to_ad_permissions"

    @classmethod
    def category(cls) -> str:
        return "Individual"

    @classmethod
    def key(cls) -> str:
        return "nodeLabel"

    @classmethod
    def documentation(cls) -> str:
        return (
            "Traverses ACE-typed relationships from an Individual node and writes "
            "ad_summary + ad_max_score + alert back to the node."
        )

    async def scan(self, data: List[Individual]) -> List[Individual]:  # type: ignore[override]
        self._updates = []

        for ind in data:
            if not ind.nodeLabel:
                continue

            rows = self._graph_service.query(_CYPHER_FIND_ACES, {
                "label":     ind.nodeLabel,
                "sketch_id": self.sketch_id,
                "ace_types": ACE_TYPES,
            })

            max_score = 0
            highest_right: Optional[str] = None
            sensitive_targets: List[str] = []

            for row in rows:
                perm      = row.get("permission_type", "")
                score     = ACE_SCORES.get(perm, 2)
                target    = row.get("target_label", "")
                is_dc     = row.get("is_dc") or False
                is_hv     = row.get("is_high_value") or False

                if score > max_score:
                    max_score     = score
                    highest_right = perm

                if score >= 7 or is_dc or is_hv:
                    sensitive_targets.append(f"{perm} → {target}")

            summary: Dict[str, Any] = {
                "highest_right":     highest_right,
                "max_ace_score":     max_score,
                "sensitive_targets": sensitive_targets[:10],
                "total_permissions": len(rows),
            }

            self._updates.append({
                "label":     ind.nodeLabel,
                "summary":   summary,
                "max_score": max_score,
                "alert":     "CRITICAL_AD_RIGHTS" if max_score >= 8 else None,
            })

        return data

    def postprocess(
        self,
        results: List[Individual],
        original_input: List[Individual],
    ) -> List[Individual]:
        for upd in self._updates:
            params: Dict[str, Any] = {
                "label":      upd["label"],
                "sketch_id":  self.sketch_id,
                "ad_summary": json.dumps(upd["summary"]),
                "max_score":  upd["max_score"],
            }
            self._graph_service.query(_CYPHER_UPDATE, params)

            if upd["alert"]:
                self._graph_service.query(_CYPHER_SET_ALERT, {
                    "label":     upd["label"],
                    "sketch_id": self.sketch_id,
                    "new_alert": upd["alert"],
                })

            self.log_graph_message(
                f"AD permissions enriched for {upd['label']} "
                f"(max_score={upd['max_score']})"
            )

        return results


InputType  = ADPermissionEnricher.InputType
OutputType = ADPermissionEnricher.OutputType
