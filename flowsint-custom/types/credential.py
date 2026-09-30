"""
Credential — Flowsint node type for secrets and credentials found by Titus.

A Credential node represents a single unique secret (API key, password hash,
token, NTLM hash, etc.) found during file scanning.  Plaintext values are
never stored — only a salted SHA-256 hash (for re-use detection) and a
4-char masked preview (for display).

Node type  : credential
Edges      : HAS_CREDENTIAL  Individual  → Credential
             FOUND_IN        Credential  → FileShare | Device

Created by : n8n workflow 11 (11-credential-scanner.json) via batch import.
Enriched by: credential_enricher.py (links to Individuals, detects re-use).
"""

from __future__ import annotations

from typing import ClassVar, Dict, Literal, Optional

from pydantic import BaseModel, Field

# Score contribution per (severity, validated) — mirrors credential_enricher.py
CRED_SCORES: Dict[str, Dict[bool, int]] = {
    "critical": {True: 15, False: 10},
    "high":     {True: 10, False: 7},
    "medium":   {True: 4,  False: 4},
    "low":      {True: 2,  False: 2},
    "info":     {True: 1,  False: 1},
}

REUSE_BONUS = 3
BREACH_CRED_BONUS = 5

SeverityLiteral = Literal["critical", "high", "medium", "low", "info"]


class Credential(BaseModel):
    """
    Represents a scanned credential in the SPOTTER graph.

    Titus JSON field mapping
    ────────────────────────
    rule_name / detector_name  → cred_type
    score / severity_score     → severity_score
    severity                   → severity
    validated / is_active      → validated
    file / filename            → source_file
    line_content / context     → source_context (truncated to 120 chars)
    service / source           → service

    SHA-256(sketch_id:secret)  → value_hash   (computed by titus-sidecar)
    secret[:4] + "***"         → value_masked  (computed by titus-sidecar)
    """

    # ── Core identity ──────────────────────────────────────────────────────────
    cred_type: str = Field(
        description="Titus rule / detector name (e.g. aws_access_key, ntlm_nt_hash, github_pat)"
    )
    value_hash: str = Field(
        description=(
            "SHA-256(sketch_id:raw_value).  For NTLM NT hashes, stored as the "
            "NT hash itself (it is already a one-way hash).  Never plaintext."
        )
    )
    value_masked: str = Field(
        description="First 4 chars of the raw value + '***' — for UI display only"
    )

    # ── Risk ───────────────────────────────────────────────────────────────────
    severity: SeverityLiteral = Field(default="info")
    severity_score: int = Field(
        default=0, ge=0, le=100,
        description="Titus 0–100 risk score"
    )
    validated: bool = Field(
        default=False,
        description="True if Titus confirmed the credential is still active"
    )

    # ── Source provenance ──────────────────────────────────────────────────────
    source_file: Optional[str] = Field(
        default=None,
        description="Filename / UNC path where the credential was found"
    )
    source_context: Optional[str] = Field(
        default=None,
        description="Surrounding source line, truncated to 120 chars"
    )
    service: Optional[str] = Field(
        default=None,
        description="Target service identified by Titus (AWS, GitHub, generic, etc.)"
    )
    username_context: Optional[str] = Field(
        default=None,
        description=(
            "Username or email extracted from surrounding context by titus-sidecar. "
            "Used by credential_enricher to link this node to an Individual."
        )
    )

    # ── Enricher metadata ──────────────────────────────────────────────────────
    reuse_group: Optional[str] = Field(
        default=None,
        description=(
            "Set by credential_enricher when the same value_hash appears on "
            "multiple Individuals — holds the shared hash prefix for grouping"
        )
    )

    SCORE_MAP: ClassVar[Dict[str, Dict[bool, int]]] = CRED_SCORES

    class Config:
        extra = "allow"

    # ── Helpers ────────────────────────────────────────────────────────────────

    @property
    def score_contribution(self) -> int:
        """Score delta this credential adds to a linked Individual's cred_score."""
        tier = self.SCORE_MAP.get(self.severity, {})
        return tier.get(self.validated, 0)

    def to_flowsint_node(self, node_id: str, sketch_id: str) -> dict:
        """
        Return the dict expected by Flowsint's batch_import endpoint.

        {
          "id": "<deterministic-uuid>",
          "nodeLabel": "<cred_type>:<value_hash[:8]>",
          "nodeType": "credential",
          "sketch_id": "<sketch_id>",
          "nodeProperties": { ...all fields... }
        }
        """
        label = f"{self.cred_type}:{self.value_hash[:8]}"
        return {
            "id":         node_id,
            "nodeLabel":  label,
            "nodeType":   "credential",
            "sketch_id":  sketch_id,
            "nodeProperties": self.model_dump(exclude_none=True),
        }
