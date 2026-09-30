"""
EnterpriseCA — Flowsint custom node type (AD Certificate Services enterprise CA).

Represents an enterprise Certificate Authority collected by SharpHound-CE. A CA
that exposes HTTP/HTTPS web enrollment is the ESC8 target: coerce a privileged
machine account (PetitPotam / PrinterBug / DFSCoerce) and NTLM-relay the
authentication to the CA's web enrollment endpoint to obtain a certificate as
that machine (see Certipy, krbrelayx).

Flowsint node label : EnterpriseCA  (nodeType: enterpriseca)
Dedup key           : sid  (CA ObjectIdentifier)

Edges (created by scripts/sharphound_parser.py):
  principal -[ManageCA|ManageCertificates|Enroll|GenericAll|WriteDacl]-> EnterpriseCA
  CertTemplate -[PublishedTo]-> EnterpriseCA
"""

from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field


class EnterpriseCA(BaseModel):
    sid: str = Field(description="CA ObjectIdentifier (dedup key)")
    name: str = Field(description="CA display name")
    dns_hostname: Optional[str] = Field(
        default=None, description="DNS host name of the CA server"
    )
    web_enrollment: Optional[bool] = Field(
        default=None,
        description="True if the CA exposes HTTP(S) web enrollment (ESC8 target)",
    )
    esc8: Optional[bool] = Field(
        default=None,
        description="True if the CA is vulnerable to ESC8 (web enrollment + no "
        "channel binding / EPA) — coerce + NTLM relay to enroll",
    )
    user_specified_san: Optional[bool] = Field(
        default=None,
        description="True if EDITF_ATTRIBUTESUBJECTALTNAME2 is set (ESC6)",
    )

    class Config:
        extra = "allow"

    def to_flowsint_node(self) -> dict:
        """Return the dict expected by POST /api/sketches/{id}/nodes/add."""
        return {
            "label": self.name,
            "type": "EnterpriseCA",
            **self.model_dump(exclude_none=True),
        }
