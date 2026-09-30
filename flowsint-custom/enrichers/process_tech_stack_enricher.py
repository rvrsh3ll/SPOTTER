"""
ProcessTechStackEnricher — Flowsint plugin enricher for Individual nodes.

Reads the process_list property set by the C2SessionEnricher (or imported
directly from Cobalt Strike), maps each process name to a technology label via
cobalt_normalizer.infer_tech_stack(), and writes the result back to the
Individual as nodeProperties.tech_stack.

Note: Technology nodes are NOT created here because 'Technology' is not a
registered Flowsint type.  The tech_stack property on the Individual is a
JSON-serialised list and is sufficient for dossier display and LLM analysis.
A separate type-registration step would unlock full node creation.

Installation: copy this file into the Flowsint container at
  /app/flowsint-enrichers/src/flowsint_enrichers/spotter/
then restart flowsint-api-prod and flowsint-celery-prod.
Note also that cobalt_normalizer.py must be on sys.path inside the container
(mount /data/scripts or install the module).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.individual import Individual

_CYPHER_READ_PROCS = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
RETURN n.`nodeProperties.process_list` AS process_list
"""

_CYPHER_UPDATE = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
SET n.`nodeProperties.tech_stack`          = $tech_stack,
    n.`nodeProperties.tech_stack_enriched` = true
"""


@flowsint_enricher
class ProcessTechStackEnricher(Enricher):
    """Infer technology stack from a beacon process list and annotate the Individual."""

    InputType = Individual
    OutputType = Individual

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._updates: List[Dict[str, Any]] = []

    @classmethod
    def name(cls) -> str:
        return "individual_to_tech_stack"

    @classmethod
    def category(cls) -> str:
        return "Individual"

    @classmethod
    def key(cls) -> str:
        return "nodeLabel"

    @classmethod
    def documentation(cls) -> str:
        return (
            "Maps running process names to technology labels via the SPOTTER "
            "cobalt_normalizer and writes tech_stack to the Individual node."
        )

    async def scan(self, data: List[Individual]) -> List[Individual]:  # type: ignore[override]
        self._updates = []

        try:
            sys.path.insert(0, "/data/scripts")
            from cobalt_normalizer import infer_tech_stack  # type: ignore[import]
        except ImportError:
            for ind in data:
                self.log_graph_message(
                    f"cobalt_normalizer not importable — skipping {ind.nodeLabel}"
                )
            return data

        for ind in data:
            if not ind.nodeLabel:
                continue

            rows = self._graph_service.query(_CYPHER_READ_PROCS, {
                "label":     ind.nodeLabel,
                "sketch_id": self.sketch_id,
            })

            if not rows:
                continue

            raw = rows[0].get("process_list")
            if not raw:
                continue

            # process_list is stored as a JSON string by C2SessionEnricher
            if isinstance(raw, str):
                try:
                    process_list: List[str] = json.loads(raw)
                except (ValueError, TypeError):
                    process_list = [raw]
            elif isinstance(raw, list):
                process_list = raw
            else:
                continue

            if not process_list:
                continue

            tech_labels = infer_tech_stack(process_list)

            self._updates.append({
                "label":      ind.nodeLabel,
                "tech_stack": tech_labels,
            })

        return data

    def postprocess(
        self,
        results: List[Individual],
        original_input: List[Individual],
    ) -> List[Individual]:
        for upd in self._updates:
            self._graph_service.query(_CYPHER_UPDATE, {
                "label":      upd["label"],
                "sketch_id":  self.sketch_id,
                "tech_stack": json.dumps(upd["tech_stack"]),
            })
            self.log_graph_message(
                f"Tech stack enriched for {upd['label']}: "
                f"{', '.join(upd['tech_stack']) or 'none identified'}"
            )

        return results


InputType  = ProcessTechStackEnricher.InputType
OutputType = ProcessTechStackEnricher.OutputType
