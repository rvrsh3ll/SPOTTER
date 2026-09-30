"""
GPO — Flowsint custom node type (Group Policy Object).

Represents a Group Policy Object collected by SharpHound-CE. A principal that can
edit a GPO (WriteDacl / WriteOwner / GenericAll / WriteGPLink on the GPO, or
write access to its gpcpath share) can push code / scheduled tasks / immediate
tasks to every computer or user in the OUs the GPO is linked to — a powerful
lateral-movement and Tier-0 escalation primitive when the GPO is linked to a
sensitive OU or the domain root.

Flowsint node label : GPO  (nodeType: gpo)
Dedup key           : sid  (GPO ObjectIdentifier)

Edges (created by scripts/sharphound_parser.py):
  principal -[WriteGPLink|WriteDacl|WriteOwner|GenericAll|GenericWrite]-> GPO
  GPO -[GpLink]-> Organization (OU / domain the GPO applies to)
"""

from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field


class GPO(BaseModel):
    sid: str = Field(description="GPO ObjectIdentifier (dedup key)")
    name: str = Field(description="GPO display name")
    gpcpath: Optional[str] = Field(
        default=None,
        description="UNC path to the GPO's SYSVOL folder (gPCFileSysPath). "
        "Write access here allows GPO content tampering without an AD ACE.",
    )

    class Config:
        extra = "allow"

    def to_flowsint_node(self) -> dict:
        """Return the dict expected by POST /api/sketches/{id}/nodes/add."""
        return {
            "label": self.name,
            "type": "GPO",
            **self.model_dump(exclude_none=True),
        }
