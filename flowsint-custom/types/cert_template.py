"""
CertTemplate — Flowsint custom node type (AD Certificate Services template).

Represents an AD CS certificate template collected by SharpHound-CE. Certificate
templates are the pivot for the ESC1–ESC16 escalation family (Certipy / Certify):
a low-privileged principal that can Enroll in a misconfigured template can obtain
a certificate that authenticates as a privileged account.

Flowsint node label : CertTemplate  (nodeType: certtemplate)
Dedup key           : sid  (template ObjectIdentifier)

Edges (created by scripts/sharphound_parser.py):
  principal -[Enroll|AutoEnroll|WritePKIEnrollmentFlag|WritePKINameFlag|
              GenericAll|WriteDacl|WriteOwner]-> CertTemplate
  CertTemplate -[PublishedTo]-> EnterpriseCA
"""

from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel, Field


class CertTemplate(BaseModel):
    sid: str = Field(description="Template ObjectIdentifier (dedup key)")
    name: str = Field(description="Template display name")
    enabled: Optional[bool] = Field(
        default=None, description="True if the template is published/enabled"
    )
    client_auth_eku: Optional[bool] = Field(
        default=None,
        description="True if the template grants a client-authentication EKU "
        "(Client Authentication, Smart Card Logon, PKINIT, or Any Purpose)",
    )
    enrollee_supplies_subject: Optional[bool] = Field(
        default=None,
        description="ENROLLEE_SUPPLIES_SUBJECT flag — requester can specify an "
        "arbitrary SAN. Core ESC1 precondition.",
    )
    requires_manager_approval: Optional[bool] = Field(
        default=None,
        description="True if issuance requires CA manager approval (blocks ESC1)",
    )
    esc1: Optional[bool] = Field(
        default=None,
        description="True if template meets ESC1 conditions (enrollee-supplies-"
        "subject + client-auth EKU + no manager approval + enabled)",
    )
    esc_vulnerabilities: List[str] = Field(
        default_factory=list,
        description="List of detected ESC misconfigurations, e.g. ['ESC1']",
    )

    class Config:
        extra = "allow"

    def to_flowsint_node(self) -> dict:
        """Return the dict expected by POST /api/sketches/{id}/nodes/add."""
        return {
            "label": self.name,
            "type": "CertTemplate",
            **self.model_dump(exclude_none=True),
        }
