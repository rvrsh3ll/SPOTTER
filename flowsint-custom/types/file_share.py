"""
FileShare — Flowsint custom node type.

Represents a UNC file share path discovered during an authorized engagement
(e.g. from a beacon process listing, SharpHound, or Maigret / manual input).

Flowsint node label : FileShare
Dedup key           : unc_path  (normalised to lowercase)
Relationship        : Individual -[HAS_SHARE]-> FileShare
"""

from __future__ import annotations
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator


class FileShare(BaseModel):
    # ── Identity ──────────────────────────────────────────────────────────────
    nodeLabel: Optional[str] = Field(
        default=None,
        description="Flowsint graph label (defaults to unc_path)",
    )
    unc_path: str = Field(
        description=r"Full UNC path, e.g. \\fileserver01\Finance$"
    )
    share_name: str = Field(
        description="Share name portion only, e.g. Finance$"
    )
    host: str = Field(
        description="Hostname or IP of the file server"
    )

    # ── Access details ────────────────────────────────────────────────────────
    access_type: Optional[str] = Field(
        default=None,
        description="Access level observed: READ | WRITE | FULL | UNKNOWN",
    )
    is_hidden: Optional[bool] = Field(
        default=None,
        description="True if the share name ends with $ (administrative share)",
    )
    observed_by_sid: Optional[str] = Field(
        default=None,
        description="SID of the AD principal observed accessing this share",
    )

    # ── Contents hints ────────────────────────────────────────────────────────
    interesting_files: List[str] = Field(
        default_factory=list,
        description=(
            "File names / patterns of interest found on the share "
            "(e.g. passwords.xlsx, *.kdbx)"
        ),
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Operator-assigned tags, e.g. ['sensitive', 'backup', 'finance']",
    )

    # ── Source ────────────────────────────────────────────────────────────────
    discovered_via: Optional[str] = Field(
        default=None,
        description="How this share was discovered: sharphound | beacon | manual | nmap",
    )
    note: Optional[str] = Field(
        default=None, description="Free-text operator note"
    )

    @field_validator("unc_path", mode="before")
    @classmethod
    def normalise_unc(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("is_hidden", mode="before")
    @classmethod
    def infer_hidden(cls, v, info):
        if v is None and "share_name" in (info.data or {}):
            return info.data["share_name"].endswith("$")
        return v

    class Config:
        extra = "allow"

    def to_flowsint_node(self) -> dict:
        return {
            "label": self.unc_path,
            "type": "FileShare",
            **self.model_dump(exclude_none=True),
        }

    @classmethod
    def from_unc(
        cls,
        unc: str,
        access_type: str = "UNKNOWN",
        discovered_via: str = "manual",
    ) -> "FileShare":
        """Quick constructor from a raw UNC string."""
        unc = unc.strip()
        parts = unc.lstrip("\\").split("\\")
        host = parts[0] if parts else "unknown"
        share = parts[1] if len(parts) > 1 else unc
        return cls(
            unc_path=unc,
            share_name=share,
            host=host,
            access_type=access_type,
            discovered_via=discovered_via,
        )
