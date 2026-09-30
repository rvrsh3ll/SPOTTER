"""
CloudAttackPath — Flowsint custom node type (deterministic cloud attack path).

One node per CloudSchism attack path: a rule-backed chain that takes a set of
findings and an entry point and states how they compose into a route — "anonymous
S3 read on a bucket holding CI credentials, which grant a role that can start EC2
instances". Sourced from `scripts/cloudschism_parser.py` (WF06 route `cloudschism`).

A path is only worth a node because of what it connects, so it is never imported
alone: it links out to the resources it reaches, the findings it chains and the
public endpoint it enters through.

Flowsint node label : CloudAttackPath  (nodeType: cloudattackpath)
Dedup key           : nodeLabel = "<path_id>@<scope>", e.g.
                      "ap-s3-cred-exfil@123456789012". `scope` is the account /
                      subscription / project parsed out of the path's first
                      affected resource id, falling back to the provider — an
                      AttackPathRecord carries no account field of its own, and
                      without the suffix the same rule firing in two accounts
                      would MERGE into one node.

Edges (created by scripts/cloudschism_parser.py):
  Organization (account) -[HAS_RISK]->      CloudAttackPath
  CloudAttackPath        -[AFFECTS]->       CloudAsset      (affected_resource_ids)
  CloudAttackPath        -[USES_FINDING]->  CloudFinding    (finding_ids)
  CloudAttackPath        -[ENTRY_POINT]->   Domain | Ip     (entry_points)

  HAS_RISK / AFFECTS are the labels ADRisk and CloudFinding already use, so "what
  is wrong with this thing" stays one traversal. USES_FINDING and ENTRY_POINT are
  new because nothing in SPOTTER expressed either relationship before — WF04
  computes AD attack paths on the fly from MEMBER_OF / HAS_SESSION and creates no
  path nodes at all.

Two on-disk shapes
──────────────────
`attack-paths.json` is written through CloudSchism's `attack_path_export_record()`,
which adds derived fields the raw model does not have: `path_type`, `trust_state`,
`entry_points`, `target_impacts`. The copy inside `CloudSchism-report.json` is a
plain `AttackPathRecord` dump without them. The parser reads whichever keys are
present rather than assuming one shape, so both profiles produce the same node.

Registration
────────────
This is a **custom** type: it lives in Flowsint's Postgres type registry, not in
flowsint-types. Register it once per install before ingesting:

    python3 scripts/register_cloudschism_type.py --apply

Skipping that is not a soft failure. Flowsint's graph serializer raises on a
nodeType it cannot resolve and has no per-node try/except, so a single
CloudAttackPath node in an unregistered install makes GET /api/sketches/{id}/graph
return HTTP 500 for the **whole sketch** — the campaign goes dark in the UI, not
just the node. `upload_router` therefore checks the registry first and drops path
nodes (keeping the endpoints, assets, identities and findings) rather than
poisoning the graph.

Type-coercion footgun
─────────────────────
A DB-registered custom type is rebuilt with `_build_pydantic_model_from_schema`,
which types **every declared property as Optional[str]** regardless of what the JSON
schema says. Pydantic v2 will not coerce int/bool into str and
`GraphSerializer.parse_flowsint_type` silently drops the fields that fail validation.

Undeclared keys pass through untouched (FlowsintType sets extra="allow") and keep
their native type in Neo4j. So `confidence_score`, `severity_ceiling_applied`,
`has_contradictions`, `affected_resource_count` and `finding_count` are deliberately
**not** in REGISTERED_SCHEMA below — that is what keeps `WHERE p.confidence_score > 70`
working instead of comparing strings. Keep the split in this file and the
registration script in sync.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from pydantic import BaseModel, Field


# CloudSchism severities, worst first (shared with CloudFinding).
SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")

# CloudSchism's AttackPathCompleteness literal, ordered weakest → strongest.
# "potential" is a hypothesis the scan could not fully substantiate; "confirmed"
# means every prerequisite was observed. Verified against
# cloudschism/models/core.py — do not extend without checking that Literal.
COMPLETENESS_ORDER = ("unknown", "incomplete", "potential", "confirmed")

# Paths CloudSchism derived from an explicit rule, as opposed to ones assembled for
# manual review. Only the former carry a rule_id.
RULE_BACKED_TYPE = "deterministic_rule_backed"


class CloudAttackPath(BaseModel):
    """A deterministic cloud attack path as stored in Flowsint."""

    # ── Declared on the registered type (stored as strings) ──────────────────
    path_id: Optional[str] = Field(None, description="CloudSchism attack path id")
    title: Optional[str] = None
    severity: Optional[str] = None
    provider: Optional[str] = Field(None, description="aws | azure | m365 | gcp")
    rule_id: Optional[str] = Field(None, description="Set only for rule-backed paths")
    path_type: Optional[str] = Field(None, description=RULE_BACKED_TYPE + " | manual_review_required")
    trust_state: Optional[str] = None
    evidence_state: Optional[str] = None
    evidence_confidence: Optional[str] = Field(None, description="low | medium | high")
    completeness: Optional[str] = Field(None, description="See COMPLETENESS_ORDER")
    rule_confidence: Optional[str] = None
    account_id: Optional[str] = Field(None, description="Account / subscription / project")
    reasoning: Optional[str] = None
    remediation: Optional[str] = None
    # JSON-encoded lists, matching how WF12/WF13 store list properties.
    tactic_chain: Optional[str] = None
    entry_points: Optional[str] = None
    missing_prerequisites: Optional[str] = None
    source: Optional[str] = "cloudschism"

    # ── Deliberately NOT declared — see the footgun note above ───────────────
    confidence_score: Optional[int] = None
    severity_ceiling_applied: bool = False
    has_contradictions: bool = False
    affected_resource_count: int = 0
    finding_count: int = 0

    # The schema actually POSTed to /api/custom-types. String-typed properties
    # only; every field below the divider above is omitted on purpose.
    REGISTERED_SCHEMA: ClassVar[Dict[str, Any]] = {
        "type": "object",
        "properties": {
            "path_id":               {"type": "string"},
            "title":                 {"type": "string"},
            "severity":              {"type": "string"},
            "provider":              {"type": "string"},
            "rule_id":               {"type": "string"},
            "path_type":             {"type": "string"},
            "trust_state":           {"type": "string"},
            "evidence_state":        {"type": "string"},
            "evidence_confidence":   {"type": "string"},
            "completeness":          {"type": "string"},
            "rule_confidence":       {"type": "string"},
            "account_id":            {"type": "string"},
            "reasoning":             {"type": "string"},
            "remediation":           {"type": "string"},
            "tactic_chain":          {"type": "string"},
            "entry_points":          {"type": "string"},
            "missing_prerequisites": {"type": "string"},
            "source":                {"type": "string"},
        },
    }

    def is_rule_backed(self) -> bool:
        """True when CloudSchism derived this path from an explicit rule."""
        return bool(self.rule_id) or self.path_type == RULE_BACKED_TYPE

    def is_confirmed(self) -> bool:
        """True only when every prerequisite was actually observed."""
        return (self.completeness or "").strip().lower() == "confirmed"

    def completeness_rank(self) -> int:
        """Sort key over COMPLETENESS_ORDER; -1 for anything unrecognised."""
        value = (self.completeness or "").strip().lower()
        return COMPLETENESS_ORDER.index(value) if value in COMPLETENESS_ORDER else -1

    def severity_rank(self) -> int:
        """Sort key: 0 is worst, len(SEVERITY_ORDER) for anything unrecognised."""
        sev = (self.severity or "").strip().lower()
        return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)
