"""
ShareAclEnricher — Flowsint plugin enricher for FileShare nodes.

Traverses HAS_PERMISSION edges from principals to FileShare nodes and computes:
  - acl_summary  : list of trustees and their effective access
  - highest_access: FULL | WRITE | READ | EXECUTE | DENY | UNKNOWN
  - acl_count     : number of ACEs observed
  - alert         : flag when a hidden share grants broad write/full access

The BOF output is normalized by scripts/shareacl_normalizer.py and imported as
FileShare nodes with HAS_PERMISSION edges.

Installation: copy this file into the Flowsint container at
  /app/flowsint-enrichers/src/flowsint_enrichers/spotter/
then restart flowsint-api-prod and flowsint-celery-prod.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.file_share import FileShare

_ACCESS_RANK = {
    "FULL": 4,
    "WRITE": 3,
    "READ": 2,
    "EXECUTE": 1,
    "DENY": 0,
    "CUSTOM": -1,
    "UNKNOWN": -2,
}

_BROAD_PRINCIPALS = {
    "everyone",
    "authenticated users",
    "domain users",
    "users",
    "domain computers",
}

_CYPHER_FIND_ACLS = """
MATCH (s:fileshare {nodeLabel: $label, sketch_id: $sketch_id})
WHERE s.deleted_at IS NULL
WITH s
MATCH (p)-[r]->(s)
WHERE type(r) STARTS WITH 'SHARE_'
  AND p.sketch_id = $sketch_id
  AND p.deleted_at IS NULL
  AND r.deleted_at IS NULL
RETURN p.nodeLabel                    AS principal_label,
       p.nodeType                     AS principal_type,
       type(r)                        AS permission_type,
       r.`data.effective_access`      AS effective_access,
       r.`data.ace_type`              AS ace_type,
       r.`data.rights`                AS rights
"""

_CYPHER_UPDATE = """
MATCH (s:fileshare {nodeLabel: $label, sketch_id: $sketch_id})
WHERE s.deleted_at IS NULL
SET s.`nodeProperties.acl_summary`   = $acl_summary,
    s.`nodeProperties.highest_access` = $highest_access,
    s.`nodeProperties.acl_count`     = $acl_count,
    s.`nodeProperties.share_acl_enriched` = true
"""

_CYPHER_SET_ALERT = """
MATCH (s:fileshare {nodeLabel: $label, sketch_id: $sketch_id})
WHERE s.deleted_at IS NULL
SET s.`nodeProperties.alert` = CASE
    WHEN s.`nodeProperties.alert` IS NULL OR s.`nodeProperties.alert` = ''
        THEN $new_alert
    WHEN NOT $new_alert IN split(coalesce(s.`nodeProperties.alert`, ''), ',')
        THEN s.`nodeProperties.alert` + ',' + $new_alert
    ELSE s.`nodeProperties.alert`
    END
"""


def _rank(access: Optional[str]) -> int:
    return _ACCESS_RANK.get((access or "UNKNOWN").upper(), -99)


@flowsint_enricher
class ShareAclEnricher(Enricher):
    """Summarise SMB share ACLs on a FileShare node and flag over-permissive hidden shares."""

    InputType = FileShare
    OutputType = FileShare

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._updates: List[Dict[str, Any]] = []

    @classmethod
    def name(cls) -> str:
        return "fileshare_to_acl_summary"

    @classmethod
    def category(cls) -> str:
        return "FileShare"

    @classmethod
    def key(cls) -> str:
        return "nodeLabel"

    @classmethod
    def documentation(cls) -> str:
        return (
            "Traverses HAS_PERMISSION edges to a FileShare and writes "
            "acl_summary, highest_access, acl_count and alert flags back to the node."
        )

    async def scan(self, data: List[FileShare]) -> List[FileShare]:  # type: ignore[override]
        self._updates = []

        for share in data:
            if not share.nodeLabel:
                continue

            rows = self._graph_service.query(_CYPHER_FIND_ACLS, {
                "label": share.nodeLabel,
                "sketch_id": self.sketch_id,
            })

            summary: List[Dict[str, Any]] = []
            highest = "UNKNOWN"
            highest_rank = _rank(highest)
            over_permissive = False

            for row in rows:
                perm = (row.get("permission_type") or "SHARE_UNKNOWN").upper()
                eff = perm.replace("SHARE_", "") if perm.startswith("SHARE_") else (row.get("effective_access") or "UNKNOWN").upper()
                ace_type = row.get("ace_type") or "ACCESS_ALLOWED"
                principal = row.get("principal_label") or "unknown"
                ptype = (row.get("principal_type") or "").lower()
                rights = row.get("rights") or []

                rank = _rank(eff)
                if ace_type == "ACCESS_ALLOWED" and rank > highest_rank:
                    highest_rank = rank
                    highest = eff

                principal_lower = principal.lower()
                is_broad = any(b in principal_lower for b in _BROAD_PRINCIPALS)
                if (
                    share.is_hidden
                    and ace_type == "ACCESS_ALLOWED"
                    and is_broad
                    and eff in {"FULL", "WRITE"}
                ):
                    over_permissive = True

                summary.append({
                    "principal": principal,
                    "principal_type": ptype,
                    "effective_access": eff,
                    "ace_type": ace_type,
                    "rights": rights,
                })

            self._updates.append({
                "label": share.nodeLabel,
                "summary": summary,
                "highest_access": highest,
                "acl_count": len(rows),
                "alert": "OVERPERMISSIVE_HIDDEN_SHARE" if over_permissive else None,
            })

        return data

    def postprocess(
        self,
        results: List[FileShare],
        original_input: List[FileShare],
    ) -> List[FileShare]:
        for upd in self._updates:
            self._graph_service.query(_CYPHER_UPDATE, {
                "label": upd["label"],
                "sketch_id": self.sketch_id,
                "acl_summary": json.dumps(upd["summary"]),
                "highest_access": upd["highest_access"],
                "acl_count": upd["acl_count"],
            })

            if upd["alert"]:
                self._graph_service.query(_CYPHER_SET_ALERT, {
                    "label": share.nodeLabel,
                    "sketch_id": self.sketch_id,
                    "new_alert": upd["alert"],
                })

            self.log_graph_message(
                f"Share ACL enriched for {upd['label']} "
                f"(highest={upd['highest_access']}, aces={upd['acl_count']})"
            )

        return results


InputType = ShareAclEnricher.InputType
OutputType = ShareAclEnricher.OutputType
