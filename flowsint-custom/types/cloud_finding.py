"""
CloudFinding — Flowsint custom node type (cloud posture / misconfiguration finding).

One node per CloudSchism finding: "S3 bucket allows public read", "Entra user has
a permanent Global Administrator assignment", "Cloud SQL instance is reachable from
0.0.0.0/0". Sourced from `scripts/cloudschism_parser.py` (WF06 route `cloudschism`).

A cloud finding is about a *resource*, unlike an ADRisk which is about a domain, so
the edges point the other way round from the account: the account owns the finding,
the finding affects the asset.

Flowsint node label : CloudFinding  (nodeType: cloudfinding)
Dedup key           : nodeLabel = "<control_id>@<scope>", e.g.
                      "s3_bucket_public_read@123456789012" (the scope suffix keeps
                      two accounts' instances of one control apart in a sketch that
                      holds both)

Edges (created by scripts/cloudschism_parser.py):
  Organization (account) -[HAS_RISK]->  CloudFinding
  CloudFinding           -[AFFECTS]->  CloudAsset

  HAS_RISK / AFFECTS are deliberately the labels ADRisk already uses, so "what is
  wrong with this thing" is one traversal across both AD and cloud findings rather
  than two dialects.

Registration
────────────
This is a **custom** type: it lives in Flowsint's Postgres type registry, not in
flowsint-types. Register it once per install before ingesting:

    python3 scripts/register_cloudschism_type.py --apply

Skipping that is not a soft failure. Flowsint's graph serializer raises on a
nodeType it cannot resolve and has no per-node try/except, so a single CloudFinding
node in an unregistered install makes GET /api/sketches/{id}/graph return HTTP 500
for the **whole sketch** — the campaign goes dark in the UI, not just the node.
`upload_router` therefore checks the registry first and drops finding nodes (keeping
the endpoints, assets and identities) rather than poisoning the graph.

Type-coercion footgun
─────────────────────
A DB-registered custom type is rebuilt with `_build_pydantic_model_from_schema`,
which types **every declared property as Optional[str]** regardless of what the JSON
schema says. Pydantic v2 will not coerce bool/int into str and
`GraphSerializer.parse_flowsint_type` silently drops the fields that fail validation.

Undeclared keys pass through untouched (FlowsintType sets extra="allow") and keep
their native type in Neo4j. So `attack_path_relevance` and `suppressed` are
deliberately **not** in REGISTERED_SCHEMA below: that is what keeps
`WHERE f.attack_path_relevance` working in Cypher instead of matching the string
"False". Keep the split in this file and the registration script in sync.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from pydantic import BaseModel, Field


# CloudSchism severities, worst first. Used for ordering in the dossier / UI.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")

# Finding classes that describe something an operator can actually act through,
# as opposed to hygiene. Mirrors CloudSchism's own `finding_class` vocabulary.
ACTIONABLE_CLASSES = ("exploitable", "high_risk_configuration", "exposure_indicator")


class CloudFinding(BaseModel):
    """A cloud posture finding as stored in Flowsint."""

    # ── Declared on the registered type (stored as strings) ──────────────────
    finding_id: Optional[str] = Field(None, description="CloudSchism finding_instance_id")
    control_id: Optional[str] = Field(None, description="Stable control identifier")
    title: Optional[str] = None
    severity: Optional[str] = None
    provider: Optional[str] = Field(None, description="aws | azure | m365 | gcp")
    service: Optional[str] = None
    resource_id: Optional[str] = Field(None, description="Affected cloud resource id")
    region: Optional[str] = None
    account_id: Optional[str] = Field(None, description="Account / subscription / project")
    finding_class: Optional[str] = None
    exploitability: Optional[str] = Field(None, description="direct | chainable | defensive | contextual")
    evidence_state: Optional[str] = None
    confidence: Optional[str] = Field(None, description="low | medium | high")
    flagged_reason: Optional[str] = None
    remediation: Optional[str] = None
    source: Optional[str] = "cloudschism"

    # ── Deliberately NOT declared — see the footgun note above ───────────────
    attack_path_relevance: bool = False
    suppressed: bool = False
    related_techniques: List[str] = Field(default_factory=list)

    # The schema actually POSTed to /api/custom-types. String-typed properties
    # only; every field below the divider above is omitted on purpose.
    REGISTERED_SCHEMA: ClassVar[Dict[str, Any]] = {
        "type": "object",
        "properties": {
            "finding_id":     {"type": "string"},
            "control_id":     {"type": "string"},
            "title":          {"type": "string"},
            "severity":       {"type": "string"},
            "provider":       {"type": "string"},
            "service":        {"type": "string"},
            "resource_id":    {"type": "string"},
            "region":         {"type": "string"},
            "account_id":     {"type": "string"},
            "finding_class":  {"type": "string"},
            "exploitability": {"type": "string"},
            "evidence_state": {"type": "string"},
            "confidence":     {"type": "string"},
            "flagged_reason": {"type": "string"},
            "remediation":    {"type": "string"},
            "source":         {"type": "string"},
        },
    }

    def is_actionable(self) -> bool:
        """True when this finding is exploitable rather than hygiene."""
        return (self.finding_class or "") in ACTIONABLE_CLASSES

    def severity_rank(self) -> int:
        """Sort key: 0 is worst, len(SEVERITY_ORDER) for anything unrecognised."""
        sev = (self.severity or "").strip().lower()
        return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)
