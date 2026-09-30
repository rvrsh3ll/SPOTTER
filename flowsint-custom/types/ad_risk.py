"""
ADRisk — Flowsint custom node type (Active Directory configuration risk).

One node per triggered assessment rule, currently sourced from a PingCastle
health check (`scripts/pingcastle_parser.py`). A PingCastle rule is a finding
about the *domain*, not about one object: "the krbtgt password has not been
changed in 4 years", "unconstrained delegation is enabled on N accounts". Each
carries a risk-point weight, a category, a rationale and a list of the objects
that triggered it.

Flowsint node label : ADRisk  (nodeType: adrisk)
Dedup key           : nodeLabel = "<RiskId>@<DOMAIN.FQDN>", e.g. "P-Delegated@CORP.LOCAL"
                      (the domain suffix keeps two domains' reports from
                      colliding on the same rule id in one sketch)

Edges (created by scripts/pingcastle_parser.py):
  Organization (domain) -[HAS_RISK]-> ADRisk
  ADRisk -[AFFECTS]-> Individual | Device | Organization   (when a rule's detail
                      lines name an object that was also ingested)

Registration
────────────
This is a **custom** type: it lives in Flowsint's Postgres type registry, not in
flowsint-types. Register it once per install before ingesting:

    python3 scripts/register_pingcastle_type.py --apply

Skipping that is not a soft failure. Flowsint's graph serializer raises on a
nodeType it cannot resolve and has no per-node try/except, so a single ADRisk
node in an unregistered install makes GET /api/sketches/{id}/graph return HTTP
500 for the **whole sketch** — the campaign goes dark, not just the node.
`upload_router` therefore checks the registry and drops risk nodes (keeping the
rest of the report) rather than poisoning the graph.

Type-coercion footgun
─────────────────────
A DB-registered custom type is rebuilt with `_build_pydantic_model_from_schema`,
which types **every declared property as Optional[str]** regardless of what the
JSON schema says. Pydantic v2 will not coerce int/bool into str, and
`GraphSerializer.parse_flowsint_type` silently drops fields that fail validation
— so a declared `points` would arrive as an int and vanish.

Undeclared keys pass through untouched (FlowsintType sets extra="allow") and keep
their native type in Neo4j. So the numeric/boolean fields below are deliberately
**not** in REGISTERED_SCHEMA: that is what keeps `WHERE r.points > 20` working in
Cypher. Keep the split in this file and the registration script in sync.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from pydantic import BaseModel, Field


# Bands applied to PingCastle risk points (higher points = worse).
SEVERITY_BANDS = ((30, "critical"), (15, "high"), (5, "medium"))


class ADRisk(BaseModel):
    # ── Declared in REGISTERED_SCHEMA: must be sent as strings ───────────────
    risk_id: str = Field(
        description="Assessment rule id, e.g. P-Delegated, A-Krbtgt, S-PwdNotRequired"
    )
    category: Optional[str] = Field(
        default=None,
        description="PingCastle category: Anomalies | PrivilegedAccounts | "
        "StaleObjects | Trusts",
    )
    model: Optional[str] = Field(
        default=None,
        description="PingCastle risk model, e.g. CredentialTheft, Reconnaissance, "
        "PrivilegeControl",
    )
    severity: Optional[str] = Field(
        default=None, description="low | medium | high | critical, derived from points"
    )
    rationale: Optional[str] = Field(
        default=None, description="One-line explanation of why the rule triggered"
    )
    domain: Optional[str] = Field(
        default=None, description="FQDN of the assessed domain (uppercase)"
    )
    source: Optional[str] = Field(default=None, description="Producing tool, e.g. pingcastle")
    generated_at: Optional[str] = Field(
        default=None, description="Report generation timestamp (ISO 8601)"
    )
    reference: Optional[str] = Field(
        default=None, description="URL documenting the rule catalogue"
    )

    # ── NOT declared in REGISTERED_SCHEMA: pass through as native types ──────
    points: Optional[int] = Field(
        default=None, description="Risk points the rule contributes to the domain score"
    )
    details_count: Optional[int] = Field(
        default=None, description="Number of objects that triggered the rule"
    )
    details: Optional[List[str]] = Field(
        default=None,
        description="Object names/lines the rule reported, capped by "
        "SPOTTER_PINGCASTLE_MAX_DETAILS",
    )
    details_truncated: Optional[bool] = Field(
        default=None, description="True when details was capped"
    )
    is_high_risk: Optional[bool] = Field(
        default=None, description="severity is high or critical"
    )

    # JSON schema POSTed to /api/custom-types. String-typed fields only, by design
    # — see the module docstring.
    REGISTERED_SCHEMA: ClassVar[Dict[str, Any]] = {
        "type": "object",
        "properties": {
            "risk_id":      {"type": "string"},
            "category":     {"type": "string"},
            "model":        {"type": "string"},
            "severity":     {"type": "string"},
            "rationale":    {"type": "string"},
            "domain":       {"type": "string"},
            "source":       {"type": "string"},
            "generated_at": {"type": "string"},
            "reference":    {"type": "string"},
        },
    }

    class Config:
        extra = "allow"

    @staticmethod
    def severity_for(points: int) -> str:
        for threshold, label in SEVERITY_BANDS:
            if points >= threshold:
                return label
        return "low"

    def to_flowsint_node(self) -> dict:
        """Return the dict expected by POST /api/sketches/{id}/nodes/add."""
        return {
            "label": f"{self.risk_id}@{self.domain}" if self.domain else self.risk_id,
            "type": "ADRisk",
            **self.model_dump(exclude_none=True),
        }
