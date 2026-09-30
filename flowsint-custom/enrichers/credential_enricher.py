"""
Credential Enricher — Flowsint plugin enricher for Individual nodes.

For each Individual, queries all Credential nodes linked via HAS_CREDENTIAL
and computes a cred_score (highest-severity finding), fires alerts, and
detects password re-use across individuals.

Cross-references with Flare breach data: if an Individual has both a validated
credential AND a Flare breach record, fires CORP_BREACH_CRED_MATCH.

Credentials are created by n8n workflow 11 (11-credential-scanner.json).
Individual ↔ Credential edges (HAS_CREDENTIAL) are created by workflow 11
using username_context / email matching; this enricher validates and scores them.

Installation: copy this file into the Flowsint container at
  /app/flowsint-enrichers/src/flowsint_enrichers/spotter/
then restart flowsint-api-prod and flowsint-celery-prod.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.individual import Individual

# Score contribution: (severity, validated) → cred_score delta.
# Only the single highest-contributing credential counts as the base.
_CRED_SCORE: Dict[str, Dict[bool, int]] = {
    "critical": {True: 15, False: 10},
    "high":     {True: 10, False: 7},
    "medium":   {True: 4,  False: 4},
    "low":      {True: 2,  False: 2},
    "info":     {True: 1,  False: 1},
}
_REUSE_BONUS       = 3
_BREACH_CRED_BONUS = 5

_ALERT_SEP = ","

# ── Cypher queries ─────────────────────────────────────────────────────────────

_CYPHER_FIND_CREDS = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
MATCH (n)-[:HAS_CREDENTIAL]->(c)
WHERE c.sketch_id = $sketch_id
  AND c.deleted_at IS NULL
RETURN c.`nodeProperties.cred_type`       AS cred_type,
       c.`nodeProperties.value_hash`       AS value_hash,
       c.`nodeProperties.severity`         AS severity,
       c.`nodeProperties.severity_score`   AS severity_score,
       c.`nodeProperties.validated`        AS validated,
       c.`nodeProperties.source_file`      AS source_file,
       c.`nodeProperties.service`          AS service
"""

_CYPHER_CHECK_BREACH = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
MATCH (n)-[:HAS_BREACH]->(b)
WHERE b.sketch_id = $sketch_id
  AND b.deleted_at IS NULL
RETURN count(b) AS breach_count
"""

_CYPHER_UPDATE_IND = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
SET n.`nodeProperties.cred_score`      = $cred_score,
    n.`nodeProperties.cred_count`      = $cred_count,
    n.`nodeProperties.cred_severity`   = $cred_severity,
    n.`nodeProperties.cred_enriched`   = true
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

# Fired once per sketch after all individuals are processed.
_CYPHER_REUSE_DETECT = """
MATCH (c:credential {sketch_id: $sketch_id})
WHERE c.deleted_at IS NULL
  AND c.`nodeProperties.value_hash` IS NOT NULL
WITH c.`nodeProperties.value_hash` AS h, collect(c) AS creds
WHERE size(creds) > 1
MATCH (i:individual {sketch_id: $sketch_id})-[:HAS_CREDENTIAL]->(rc:credential {sketch_id: $sketch_id})
WHERE rc.`nodeProperties.value_hash` = h
  AND rc.deleted_at IS NULL
  AND i.deleted_at IS NULL
WITH i
SET i.`nodeProperties.alert` = CASE
  WHEN i.`nodeProperties.alert` IS NULL OR i.`nodeProperties.alert` = ''
    THEN 'PASSWORD_REUSE'
  WHEN NOT 'PASSWORD_REUSE' IN split(coalesce(i.`nodeProperties.alert`, ''), ',')
    THEN i.`nodeProperties.alert` + ',PASSWORD_REUSE'
  ELSE i.`nodeProperties.alert`
  END,
  i.`nodeProperties.cred_score` = coalesce(i.`nodeProperties.cred_score`, 0) + $reuse_bonus
RETURN count(i) AS affected
"""

_CYPHER_BREACH_CRED_MATCH = """
MATCH (i:individual {sketch_id: $sketch_id})-[:HAS_CREDENTIAL]->(c:credential {sketch_id: $sketch_id})
WHERE c.`nodeProperties.validated` = true
  AND c.deleted_at IS NULL
  AND i.deleted_at IS NULL
MATCH (i)-[:HAS_BREACH]->(b)
WHERE b.sketch_id = $sketch_id
  AND b.deleted_at IS NULL
WITH i, count(DISTINCT c) AS vc, count(DISTINCT b) AS bc
WHERE vc > 0 AND bc > 0
SET i.`nodeProperties.alert` = CASE
  WHEN i.`nodeProperties.alert` IS NULL OR i.`nodeProperties.alert` = ''
    THEN 'CORP_BREACH_CRED_MATCH'
  WHEN NOT 'CORP_BREACH_CRED_MATCH' IN split(coalesce(i.`nodeProperties.alert`, ''), ',')
    THEN i.`nodeProperties.alert` + ',CORP_BREACH_CRED_MATCH'
  ELSE i.`nodeProperties.alert`
  END,
  i.`nodeProperties.cred_score` = coalesce(i.`nodeProperties.cred_score`, 0) + $breach_cred_bonus
RETURN count(i) AS flagged
"""


def _severity_rank(sev: Optional[str]) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
        (sev or "").lower(), 0
    )


def _score(sev: Optional[str], validated: bool) -> int:
    tier = _CRED_SCORE.get((sev or "info").lower(), {})
    return tier.get(bool(validated), 0)


@flowsint_enricher
class CredentialEnricher(Enricher):
    """
    Link Credential nodes to Individual nodes, score credential findings,
    and detect password re-use across individuals in the same sketch.
    """

    InputType  = Individual
    OutputType = Individual

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._updates: List[Dict[str, Any]] = []

    @classmethod
    def name(cls) -> str:
        return "individual_credential_summary"

    @classmethod
    def category(cls) -> str:
        return "Individual"

    @classmethod
    def key(cls) -> str:
        return "nodeLabel"

    @classmethod
    def documentation(cls) -> str:
        return (
            "Queries Credential nodes linked via HAS_CREDENTIAL and writes "
            "cred_score, cred_count, cred_severity, and alert flags to each "
            "Individual node.  Runs sketch-wide re-use detection and "
            "Flare breach × validated credential correlation after per-node scan."
        )

    async def scan(self, data: List[Individual]) -> List[Individual]:  # type: ignore[override]
        self._updates = []

        for ind in data:
            if not ind.nodeLabel:
                continue

            cred_rows = self._graph_service.query(_CYPHER_FIND_CREDS, {
                "label":     ind.nodeLabel,
                "sketch_id": self.sketch_id,
            })

            if not cred_rows:
                self._updates.append({
                    "label":        ind.nodeLabel,
                    "cred_score":   0,
                    "cred_count":   0,
                    "cred_severity": None,
                    "alerts":       [],
                })
                continue

            # Find the single highest-contributing credential for the base score.
            best_row   = max(cred_rows, key=lambda r: (
                _severity_rank(r.get("severity")),
                int(r.get("severity_score") or 0),
                bool(r.get("validated")),
            ))
            base_score = _score(best_row.get("severity"), bool(best_row.get("validated")))

            # Additional score for each validated credential beyond the first.
            validated_count = sum(1 for r in cred_rows if r.get("validated"))
            if validated_count > 1:
                base_score += (validated_count - 1) * 2

            alerts: List[str] = []
            if cred_rows:
                alerts.append("CREDENTIAL_FOUND")
            if any(r.get("validated") for r in cred_rows):
                alerts.append("VALIDATED_CREDENTIAL")

            self._updates.append({
                "label":         ind.nodeLabel,
                "cred_score":    base_score,
                "cred_count":    len(cred_rows),
                "cred_severity": best_row.get("severity") or "info",
                "alerts":        alerts,
            })

        return data

    def postprocess(
        self,
        results: List[Individual],
        original_input: List[Individual],
    ) -> List[Individual]:
        # Per-individual: write score + alerts
        for upd in self._updates:
            self._graph_service.query(_CYPHER_UPDATE_IND, {
                "label":         upd["label"],
                "sketch_id":     self.sketch_id,
                "cred_score":    upd["cred_score"],
                "cred_count":    upd["cred_count"],
                "cred_severity": upd["cred_severity"],
            })

            for alert in upd["alerts"]:
                self._graph_service.query(_CYPHER_SET_ALERT, {
                    "label":     upd["label"],
                    "sketch_id": self.sketch_id,
                    "new_alert": alert,
                })

            if upd["cred_count"] > 0:
                self.log_graph_message(
                    f"Credential enrichment: {upd['label']} — "
                    f"count={upd['cred_count']}, score={upd['cred_score']}, "
                    f"severity={upd['cred_severity']}"
                )

        # Sketch-wide: password re-use detection
        try:
            reuse_result = self._graph_service.query(_CYPHER_REUSE_DETECT, {
                "sketch_id":   self.sketch_id,
                "reuse_bonus": _REUSE_BONUS,
            })
            affected = (reuse_result[0].get("affected") or 0) if reuse_result else 0
            if affected:
                self.log_graph_message(
                    f"PASSWORD_REUSE detected — {affected} individual(s) share credential hashes"
                )
        except Exception as exc:
            self.log_graph_message(f"Re-use detection query failed: {exc}")

        # Sketch-wide: Flare breach × validated credential correlation
        try:
            bcm_result = self._graph_service.query(_CYPHER_BREACH_CRED_MATCH, {
                "sketch_id":        self.sketch_id,
                "breach_cred_bonus": _BREACH_CRED_BONUS,
            })
            flagged = (bcm_result[0].get("flagged") or 0) if bcm_result else 0
            if flagged:
                self.log_graph_message(
                    f"CORP_BREACH_CRED_MATCH — {flagged} individual(s) have validated creds + Flare breaches"
                )
        except Exception as exc:
            self.log_graph_message(f"Breach-credential correlation query failed: {exc}")

        return results


InputType  = CredentialEnricher.InputType
OutputType = CredentialEnricher.OutputType
