"""
C2SessionEnricher — Flowsint plugin enricher for Individual nodes.

Queries all C2Session nodes linked to an Individual via HAS_BEACON, then surfaces
session metadata (last_seen, active_beacon, process_list, etc.) back into the
Individual's node properties.

C2Session nodes are stored in Neo4j with nodeType='c2session'. They are created by
the C2 ingestors — 01-cobalt-strike-ingestor.json (beacons) and
21-brute-ratel-receiver.json (badgers) — using
fc.add_node(node_type='C2Session', ...).

Reads tolerate BOTH schemas: nodes created before the CobaltBeacon → C2Session
generalisation carry nodeProperties.beacon_id and no c2_framework, so session_id is
COALESCEd across both names and a missing framework is read as cobalt_strike (the
only framework that existed then). That keeps this enricher correct on a graph where
scripts/migrate_c2session.py has not run yet.

The Individual-side property names are deliberately unchanged (beacon_count,
active_beacon, is_admin_beacon, beacon_enriched): active_beacon in particular is
read by the LLM system prompt, WF10, flowsint_search_tool, ad_attack_paths_tool and
dossier_tool. c2_frameworks is added alongside them.

Installation: copy this file into the Flowsint container at
  /app/flowsint-enrichers/src/flowsint_enrichers/spotter/
then restart flowsint-api-prod and flowsint-celery-prod.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.individual import Individual

_CYPHER_FIND_SESSIONS = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
WITH n
MATCH (n)-[:HAS_BEACON]->(s)
WHERE s.sketch_id = $sketch_id
  AND s.deleted_at IS NULL
RETURN COALESCE(s.`nodeProperties.session_id`,
                s.`nodeProperties.beacon_id`)      AS session_id,
       COALESCE(s.`nodeProperties.c2_framework`,
                'cobalt_strike')                   AS c2_framework,
       s.`nodeProperties.is_admin`                 AS is_admin,
       s.`nodeProperties.last_checkin`             AS last_checkin,
       s.`nodeProperties.process_list`             AS process_list,
       s.`nodeProperties.priority_score`           AS priority_score,
       s.`nodeProperties.hostname`                 AS hostname,
       s.`nodeProperties.is_dead`                  AS is_dead
"""

_CYPHER_UPDATE = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
SET n.`nodeProperties.beacon_count`    = $beacon_count,
    n.`nodeProperties.active_beacon`   = $active_beacon,
    n.`nodeProperties.last_seen`       = $last_seen,
    n.`nodeProperties.process_list`    = $process_list,
    n.`nodeProperties.priority_score`  = $priority_score,
    n.`nodeProperties.is_admin_beacon` = $is_admin_beacon,
    n.`nodeProperties.c2_frameworks`   = $c2_frameworks,
    n.`nodeProperties.beacon_enriched` = true
"""

_CYPHER_SET_ALERT = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
SET n.`nodeProperties.alert` = $alert
"""

_ACTIVE_THRESHOLD_MINUTES = 30


def _as_process_list(value: Any) -> List[str]:
    """process_list may arrive as a list or as a JSON-encoded string."""
    if isinstance(value, list):
        return [str(v) for v in value if v]
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except ValueError:
            return []
        if isinstance(parsed, list):
            return [str(v) for v in parsed if v]
    return []


@flowsint_enricher
class C2SessionEnricher(Enricher):
    """Surface active C2 session metadata into an Individual dossier."""

    InputType = Individual
    OutputType = Individual

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._updates: List[Dict[str, Any]] = []

    @classmethod
    def name(cls) -> str:
        return "individual_to_c2_sessions"

    @classmethod
    def category(cls) -> str:
        return "Individual"

    @classmethod
    def key(cls) -> str:
        return "nodeLabel"

    @classmethod
    def documentation(cls) -> str:
        return (
            "Aggregates C2Session nodes (Cobalt Strike beacons, Brute Ratel badgers) "
            "linked via HAS_BEACON and writes session metadata (count, active, "
            "process_list, frameworks, alert) to Individual."
        )

    async def scan(self, data: List[Individual]) -> List[Individual]:  # type: ignore[override]
        self._updates = []

        for ind in data:
            if not ind.nodeLabel:
                continue

            rows = self._graph_service.query(_CYPHER_FIND_SESSIONS, {
                "label":     ind.nodeLabel,
                "sketch_id": self.sketch_id,
            })

            if not rows:
                self._updates.append({
                    "label":         ind.nodeLabel,
                    "beacon_count":  0,
                    "active_beacon": False,
                    "last_seen":     None,
                    "process_list":  [],
                    "priority_score": 0,
                    "is_admin_beacon": False,
                    "c2_frameworks": [],
                    "alert":         None,
                })
                continue

            all_procs:   List[str] = []
            frameworks:  set = set()
            highest_score = 0
            any_admin     = False
            last_seen_str: Optional[str] = None
            last_seen_dt:  Optional[datetime] = None

            for row in rows:
                all_procs.extend(_as_process_list(row.get("process_list")))

                fw = (row.get("c2_framework") or "").strip().lower()
                if fw:
                    frameworks.add(fw)

                score = row.get("priority_score") or 0
                if score > highest_score:
                    highest_score = score

                if row.get("is_admin"):
                    any_admin = True

                # A session the C2 has declared dead must not keep an Individual
                # flagged as actively beaconing.
                if row.get("is_dead"):
                    continue

                checkin = row.get("last_checkin")
                if checkin:
                    try:
                        dt = datetime.fromisoformat(str(checkin))
                        if last_seen_dt is None or dt > last_seen_dt:
                            last_seen_dt = dt
                            last_seen_str = str(checkin)
                    except (ValueError, TypeError):
                        pass

            active = False
            if last_seen_dt:
                now = datetime.now(timezone.utc)
                aware_dt = last_seen_dt.replace(tzinfo=timezone.utc) \
                    if last_seen_dt.tzinfo is None else last_seen_dt
                age_minutes = (now - aware_dt).total_seconds() / 60
                active = 0 <= age_minutes < _ACTIVE_THRESHOLD_MINUTES

            unique_procs = sorted(set(all_procs))

            self._updates.append({
                "label":          ind.nodeLabel,
                "beacon_count":   len(rows),
                "active_beacon":  active,
                "last_seen":      last_seen_str,
                "process_list":   unique_procs,
                "priority_score": highest_score,
                "is_admin_beacon": any_admin,
                "c2_frameworks":  sorted(frameworks),
                "alert": "HIGH_VALUE_BEACON" if (any_admin or highest_score >= 15) else None,
            })

        return data

    def postprocess(
        self,
        results: List[Individual],
        original_input: List[Individual],
    ) -> List[Individual]:
        for upd in self._updates:
            self._graph_service.query(_CYPHER_UPDATE, {
                "label":          upd["label"],
                "sketch_id":      self.sketch_id,
                "beacon_count":   upd["beacon_count"],
                "active_beacon":  upd["active_beacon"],
                "last_seen":      upd["last_seen"],
                "process_list":   json.dumps(upd["process_list"]),
                "priority_score": upd["priority_score"],
                "is_admin_beacon": upd["is_admin_beacon"],
                "c2_frameworks":  upd["c2_frameworks"],
            })

            if upd["alert"]:
                self._graph_service.query(_CYPHER_SET_ALERT, {
                    "label":     upd["label"],
                    "sketch_id": self.sketch_id,
                    "alert":     upd["alert"],
                })

            frameworks = ", ".join(upd["c2_frameworks"]) or "none"
            self.log_graph_message(
                f"C2 session enrichment complete for {upd['label']} "
                f"(count={upd['beacon_count']}, active={upd['active_beacon']}, "
                f"frameworks={frameworks})"
            )

        return results


InputType  = C2SessionEnricher.InputType
OutputType = C2SessionEnricher.OutputType
