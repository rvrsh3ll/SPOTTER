"""
Technology — Flowsint custom node type.

Represents a hardware or software technology identified during reconnaissance
or endpoint enrichment. A Technology node is linked to Individuals via
USES_TECHNOLOGY, to Devices via RUNS_TECHNOLOGY, and to Services via
IMPLEMENTED_IN.

Flowsint node label : Technology
Dedup key           : normalized (name, vendor, version, source)
"""

from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel, Field


class Technology(BaseModel):
    # ── Identity ──────────────────────────────────────────────────────────────
    name: str = Field(
        description="Human-readable technology name, e.g. 'Apache httpd', 'Windows Server 2019'"
    )
    category: Optional[str] = Field(
        default=None,
        description=(
            "High-level category: Development, Database, Office, Security, "
            "Legacy/Mainframe, Password Manager, PAM, VPN, Web Server, OS, etc."
        ),
    )
    vendor: Optional[str] = Field(
        default=None, description="Vendor or project name, e.g. 'Microsoft', 'Apache'"
    )

    # ── Versioning & fingerprinting ───────────────────────────────────────────
    version: Optional[str] = Field(
        default=None, description="Detected version string, if available"
    )
    cpe: Optional[str] = Field(
        default=None, description="Common Platform Enumeration URI, if known"
    )
    confidence: str = Field(
        default="medium",
        description="Fingerprint confidence: high | medium | low"
    )

    # ── Source & enrichment ───────────────────────────────────────────────────
    source: str = Field(
        description="Origin of the detection: cobalt_strike, nmap, sharphound, manual, etc."
    )
    is_high_value: Optional[bool] = Field(
        default=False,
        description=(
            "True if this technology is a high-value attack surface "
            "(PAM, password manager, mainframe emulator, SAP, trading terminal, etc.)"
        ),
    )
    aliases: List[str] = Field(
        default_factory=list,
        description="Alternative names or labels for this technology"
    )

    # ── Contextual intelligence (populated by enrichment) ──────────────────────
    eol_date: Optional[str] = Field(
        default=None, description="ISO date when this version/product reaches end-of-life"
    )
    cve_count: Optional[int] = Field(
        default=None, description="Number of known CVEs affecting this technology"
    )
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs relevant to this technology"
    )

    class Config:
        extra = "allow"

    # ── Flowsint helpers ──────────────────────────────────────────────────────

    def to_flowsint_node(self) -> dict:
        """Return the dict expected by POST /api/sketches/{id}/nodes/add."""
        label = self.name
        if self.version:
            label = f"{label} {self.version}"
        return {
            "label": label,
            "type": "Technology",
            **self.model_dump(exclude_none=True),
        }

    @property
    def dedup_key(self) -> str:
        """Stable key for deduplication within a sketch."""
        parts = [self.name.lower(), (self.vendor or "").lower(), (self.version or "").lower()]
        return "|".join(parts)
