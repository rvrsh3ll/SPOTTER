"""
ADPermission — Flowsint relationship wrapper for Active Directory ACEs.

In Flowsint's graph model this is stored as a relationship property bag rather
than a standalone node.  This class provides:
  - A typed schema for the relationship data dict
  - Scoring helpers used by workflow 04 (attack path analyser)
  - A mapping from BloodHound / SharpHound ACE right names to SPOTTER labels

Relationship type : HAS_PERMISSION
Direction         : Individual -[HAS_PERMISSION]-> target_object_node
"""

from __future__ import annotations
from typing import Optional, ClassVar, Dict
from pydantic import BaseModel, Field


# Risk score per ACE / attack-path edge type.
# Keep in sync with llm/tools/attack_path_tool.py ACE_SCORES (tradecraft update 2026-07).
ACE_SCORES: Dict[str, int] = {
    "GenericAll":        10,
    "WriteDacl":          9,
    "WriteOwner":         8,
    "GenericWrite":       7,
    "AllExtendedRights":  7,
    "AddAllowedToAct":    7,
    "ForceChangePassword": 6,
    "AddMember":          5,
    "Owns":               5,
    "WriteAccountRestrictions": 5,
    "AddKeyCredentialLink": 5,
    "ReadLAPSPassword":   4,
    "WriteSPN":           4,
    "ReadGMSAPassword":   4,
    "DCSync":            10,
    "GetChangesAll":     10,
    "GetChanges":         4,
    # Kerberos delegation / SID history / coercion
    "AllowedToAct":       7,
    "AllowedToDelegate":  7,
    "HasSIDHistory":      8,
    "CoerceToTGT":        8,
    # ADCS abuse (Certipy / Certify)
    "ManageCA":           8,
    "ManageCertificates": 7,
    "WritePKIEnrollmentFlag": 7,
    "WritePKINameFlag":   7,
    "Enroll":             4,
    # GPO + lateral movement
    "WriteGPLink":        8,
    "SQLAdmin":           5,
    "ExecuteDCOM":        4,
    "CanPSRemote":        4,
    "CanRDP":             3,
}


class ADPermission(BaseModel):
    """
    Represents a single Active Directory ACE edge in the graph.

    SharpHound JSON field mapping
    ─────────────────────────────
    ObjectIdentifier (source)  → source_sid
    ObjectType (source)        → source_type
    RightName                  → permission_type
    AceType                    → ace_type
    IsInherited                → is_inherited
    ObjectIdentifier (target)  → target_sid
    ObjectType (target)        → target_type
    """

    # ── Principals ────────────────────────────────────────────────────────────
    source_sid: str = Field(description="SID of the principal that holds this ACE")
    source_sam: Optional[str] = Field(
        default=None, description="SAMAccountName of the source principal"
    )
    source_type: Optional[str] = Field(
        default=None,
        description="AD object type of source: User | Group | Computer | GPO",
    )
    source_dn: Optional[str] = Field(
        default=None, description="Distinguished Name of the source principal"
    )

    target_sid: Optional[str] = Field(
        default=None, description="SID of the target object (if known)"
    )
    target_name: Optional[str] = Field(
        default=None, description="Display / SAM name of the target object"
    )
    target_type: Optional[str] = Field(
        default=None,
        description="AD object type of target: User | Group | Computer | Domain | GPO | OU",
    )
    target_dn: Optional[str] = Field(
        default=None, description="Distinguished Name of the target object"
    )

    # ── ACE details ───────────────────────────────────────────────────────────
    permission_type: str = Field(
        description=(
            "BloodHound right name, e.g. GenericAll, WriteDacl, GenericWrite, "
            "AddMember, ForceChangePassword, ReadLAPSPassword, DCSync, etc."
        )
    )
    ace_type: Optional[str] = Field(
        default=None,
        description="BloodHound AceType: AccessAllowed | AccessAllowedObject | ...",
    )
    is_inherited: Optional[bool] = Field(
        default=None, description="True if this ACE is inherited rather than explicit"
    )

    # ── Engagement context ────────────────────────────────────────────────────
    is_sensitive_target: Optional[bool] = Field(
        default=None,
        description=(
            "True if target is a Tier-0 / high-value object "
            "(Domain Controller, Domain Admins group, AdminSDHolder, etc.)"
        ),
    )

    SCORE_MAP: ClassVar[Dict[str, int]] = ACE_SCORES

    class Config:
        extra = "allow"

    # ── Helpers ───────────────────────────────────────────────────────────────

    @property
    def score(self) -> int:
        """Risk score for this ACE (used in attack path scoring)."""
        base = self.SCORE_MAP.get(self.permission_type, 2)
        bonus = 5 if self.is_sensitive_target else 0
        return base + bonus

    def to_flowsint_edge(
        self,
        source_node_id: str,
        target_node_id: str,
    ) -> dict:
        """
        Return the dict expected by Flowsint's import/execute edges list.

        {
          "source": "<node_id>",
          "target": "<node_id>",
          "label": "HAS_PERMISSION",
          "data": { ...ace fields... }
        }
        """
        return {
            "source": source_node_id,
            "target": target_node_id,
            "label": "HAS_PERMISSION",
            "data": {
                "permission_type": self.permission_type,
                "ace_type": self.ace_type,
                "is_inherited": self.is_inherited,
                "score": self.score,
                "is_sensitive_target": self.is_sensitive_target,
            },
        }

    @classmethod
    def from_sharphound_ace(
        cls, ace: dict, source_sid: str, target_sid: str, target_type: str
    ) -> "ADPermission":
        """Build from a BloodHound/SharpHound ACE dict."""
        return cls(
            source_sid=source_sid,
            target_sid=target_sid,
            target_type=target_type,
            permission_type=ace.get("RightName", ace.get("right_name", "Unknown")),
            ace_type=ace.get("AceType", ace.get("ace_type")),
            is_inherited=ace.get("IsInherited", ace.get("is_inherited")),
        )
