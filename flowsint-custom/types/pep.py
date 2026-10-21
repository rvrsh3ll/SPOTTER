"""
PEP — Flowsint custom node type for Politically Exposed Persons.

Created by WF30 (Russian Corporate Intelligence) via rupep.org and similar
PEP databases. Connected to Company nodes via POSITION_AT / ASSOCIATED_WITH
edges, and to Individual nodes when a match is found.

Flowsint node label : PEP
Dedup key           : name + country  (the node's nodeLabel)

DECLARED PROPERTIES ARE STRINGS ONLY
------------------------------------
Same rule as Company: a DB-registered custom type rebuilds every *declared*
property as Optional[str], so ints, bools and lists stay UNDECLARED to
preserve their native Neo4j type.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class PEP(BaseModel):
    # ── Identity ──────────────────────────────────────────────────────────────
    name: str = Field(description="Person's full name (used as dedup key part)")
    country: str = Field(
        default="RU",
        description="Country code (ISO 3166-1 alpha-2): RU, BY, KZ",
    )
    position: Optional[str] = Field(
        default=None,
        description="Current or most recent political/public position",
    )
    organization: Optional[str] = Field(
        default=None,
        description="Government body, agency, or state-owned enterprise",
    )

    # ── PEP classification ───────────────────────────────────────────────────
    pep_category: Optional[str] = Field(
        default=None,
        description="PEP category: head_of_state | minister | parliament | "
                    "judiciary | military | diplomat | state_enterprise | other",
    )
    pep_level: Optional[str] = Field(
        default=None,
        description="Seniority: national | regional | local",
    )

    # ── Provenance ────────────────────────────────────────────────────────────
    source: Optional[str] = Field(
        default=None,
        description="Source database: rupep.org | opi_corruption | custom",
    )
    source_url: Optional[str] = Field(
        default=None,
        description="Direct link to the person's record on the source",
    )
    discovered_at: Optional[datetime] = Field(
        default=None,
        description="When this record was first written to the graph",
    )

    # ── Undeclared on purpose (see module docstring) ─────────────────────────
    # assets_summary: str        connections_count: int
    # birth_date: str            birth_place: str
    # positions_history: list    sanctions: list

    class Config:
        extra = "allow"

    def to_flowsint_node(self) -> dict:
        label = f"{self.name} ({self.country})" if self.country else self.name
        return {
            "label": label,
            "type": "PEP",
            **self.model_dump(exclude_none=True),
        }
