"""
FlareBreach Enricher — Flowsint plugin enricher for Individual nodes.

Queries all FlareBreach nodes linked to an Individual via HAS_BREACH, then
aggregates breach statistics (count, event_type breakdown, last_seen, stealer
presence) back into the Individual's node properties.

FlareBreach nodes are created by the Flare ingestor workflow
(09-flare-ingestor.json) using batch_import with type='FlareBreach'.

Installation: copy this file into the Flowsint container at
  /app/flowsint-enrichers/src/flowsint_enrichers/spotter/
then restart flowsint-api-prod and flowsint-celery-prod.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.individual import Individual

_CYPHER_FIND_BREACHES = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
WITH n
MATCH (n)-[:HAS_BREACH]->(b)
WHERE b.sketch_id = $sketch_id
  AND b.deleted_at IS NULL
RETURN b.`nodeProperties.breach_id`        AS breach_id,
       b.`nodeProperties.event_type`        AS event_type,
       b.`nodeProperties.source`            AS source,
       b.`nodeProperties.identity_name`     AS identity_name,
       b.`nodeProperties.domain`            AS domain,
       b.`nodeProperties.hash_type`         AS hash_type,
       b.`nodeProperties.password_exposed`  AS password_exposed,
       b.`nodeProperties.malware_family`    AS malware_family,
       b.`nodeProperties.infection_country` AS infection_country,
       b.`nodeProperties.imported_at`       AS imported_at
"""

_CYPHER_UPDATE = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
SET n.`nodeProperties.breach_count`      = $breach_count,
    n.`nodeProperties.breach_summary`    = $breach_summary,
    n.`nodeProperties.breach_last_seen`  = $breach_last_seen,
    n.`nodeProperties.has_stealer_log`   = $has_stealer_log,
    n.`nodeProperties.breach_enriched`   = true
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
class FlareBreachEnricher(Enricher):
    """Aggregate Flare.io breach data from linked FlareBreach nodes into Individual."""

    InputType = Individual
    OutputType = Individual

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._updates: List[Dict[str, Any]] = []

    @classmethod
    def name(cls) -> str:
        return "individual_flare_breach_summary"

    @classmethod
    def category(cls) -> str:
        return "Individual"

    @classmethod
    def key(cls) -> str:
        return "nodeLabel"

    @classmethod
    def documentation(cls) -> str:
        return (
            "Aggregates FlareBreach nodes linked via HAS_BREACH and writes "
            "breach_count, breach_summary, breach_last_seen, and alert flags "
            "to the Individual node."
        )

    async def scan(self, data: List[Individual]) -> List[Individual]:  # type: ignore[override]
        self._updates = []

        for ind in data:
            if not ind.nodeLabel:
                continue

            rows = self._graph_service.query(_CYPHER_FIND_BREACHES, {
                "label":     ind.nodeLabel,
                "sketch_id": self.sketch_id,
            })

            if not rows:
                self._updates.append({
                    "label":          ind.nodeLabel,
                    "breach_count":   0,
                    "breach_summary": "{}",
                    "breach_last_seen": None,
                    "has_stealer_log": False,
                    "alert":          None,
                })
                continue

            type_counts: Counter = Counter()
            has_stealer = False
            latest_dt:  Optional[datetime] = None
            latest_str: Optional[str] = None

            for row in rows:
                etype = row.get("event_type") or "unknown"
                type_counts[etype] += 1

                if etype == "stealer_log":
                    has_stealer = True

                imported = row.get("imported_at")
                if imported:
                    try:
                        dt = datetime.fromisoformat(str(imported).rstrip("Z"))
                        dt = dt.replace(tzinfo=timezone.utc)
                        if latest_dt is None or dt > latest_dt:
                            latest_dt = dt
                            latest_str = str(imported)
                    except (ValueError, TypeError):
                        pass

            alert: Optional[str] = None
            if has_stealer:
                alert = "STEALER_LOG_DETECTED"
            elif len(rows) >= 5:
                alert = "MULTIPLE_BREACHES"

            self._updates.append({
                "label":           ind.nodeLabel,
                "breach_count":    len(rows),
                "breach_summary":  json.dumps(dict(type_counts)),
                "breach_last_seen": latest_str,
                "has_stealer_log": has_stealer,
                "alert":           alert,
            })

        return data

    def postprocess(
        self,
        results: List[Individual],
        original_input: List[Individual],
    ) -> List[Individual]:
        for upd in self._updates:
            self._graph_service.query(_CYPHER_UPDATE, {
                "label":           upd["label"],
                "sketch_id":       self.sketch_id,
                "breach_count":    upd["breach_count"],
                "breach_summary":  upd["breach_summary"],
                "breach_last_seen": upd["breach_last_seen"],
                "has_stealer_log": upd["has_stealer_log"],
            })

            if upd["alert"]:
                self._graph_service.query(_CYPHER_SET_ALERT, {
                    "label":     upd["label"],
                    "sketch_id": self.sketch_id,
                    "new_alert": upd["alert"],
                })

            self.log_graph_message(
                f"Flare breach enrichment complete for {upd['label']} "
                f"(count={upd['breach_count']}, stealer={upd['has_stealer_log']})"
            )

        return results


InputType  = FlareBreachEnricher.InputType
OutputType = FlareBreachEnricher.OutputType
