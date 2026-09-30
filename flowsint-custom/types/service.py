"""
Service — Flowsint custom node type.

Represents a network service discovered by active scanning (nmap, masscan,
Shodan, FOFA) or manual upload. A Service node is linked to its host Device
or IP node via EXPOSES_SERVICE and to a Technology node via
IMPLEMENTED_IN when the product is identified.

Flowsint node label : Service
Dedup key           : service:{host_id}:{port}:{protocol}
"""

from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel, Field


class Service(BaseModel):
    # ── Network location ──────────────────────────────────────────────────────
    host_id: str = Field(
        description="Stable ID of the host node (IP or Device) that exposes this service"
    )
    port: int = Field(description="TCP/UDP port number")
    protocol: str = Field(
        default="tcp",
        description="Transport protocol: tcp | udp | sctp"
    )
    state: str = Field(
        default="open",
        description="Port state: open | filtered | closed | unknown"
    )

    # ── Service fingerprint ───────────────────────────────────────────────────
    name: Optional[str] = Field(
        default=None, description="Service name from nmap service detection, e.g. 'http'"
    )
    product: Optional[str] = Field(
        default=None, description="Product name, e.g. 'Apache httpd'"
    )
    version: Optional[str] = Field(
        default=None, description="Product version, e.g. '2.4.41'"
    )
    extrainfo: Optional[str] = Field(
        default=None, description="Extra information from the service probe"
    )
    banner: Optional[str] = Field(
        default=None, description="Raw service banner or NSE script output"
    )
    cpe: Optional[str] = Field(
        default=None, description="Common Platform Enumeration URI"
    )
    confidence: str = Field(
        default="medium",
        description="Fingerprint confidence: high | medium | low"
    )

    # ── Source & enrichment ───────────────────────────────────────────────────
    source: str = Field(
        description="Origin of the detection: nmap, shodan, fofa, manual, etc."
    )
    is_internet_exposed: Optional[bool] = Field(
        default=None, description="True if this service is reachable from the public internet"
    )

    # ── Contextual intelligence (populated by enrichment) ──────────────────────
    cve_count: Optional[int] = Field(
        default=None, description="Number of known CVEs affecting this service/product/version"
    )
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs relevant to this service"
    )

    class Config:
        extra = "allow"

    # ── Flowsint helpers ──────────────────────────────────────────────────────

    @property
    def node_id(self) -> str:
        """Stable node ID for this service within a sketch."""
        return f"service:{self.host_id}:{self.port}:{self.protocol}"

    @property
    def node_label(self) -> str:
        """Display label shown in the graph."""
        label = f"{self.port}/{self.protocol}"
        if self.product:
            label = f"{label} {self.product}"
            if self.version:
                label = f"{label} {self.version}"
        elif self.name:
            label = f"{label} {self.name}"
        return label

    def to_flowsint_node(self) -> dict:
        """Return the dict expected by POST /api/sketches/{id}/nodes/add."""
        return {
            "id": self.node_id,
            "label": self.node_label,
            "type": "Service",
            **self.model_dump(exclude_none=True),
        }
