"""
FlareBreach — Flowsint custom node type.

Represents a single Flare.io breach/exposure event linked to an Individual.
Created by the Flare ingestor workflow (09-flare-ingestor.json) and connected
via a HAS_BREACH relationship.

Flowsint node label : FlareBreach
Dedup key           : breach_id  (Flare credential hash or event UID)
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class FlareBreach(BaseModel):
    # ── Identity ──────────────────────────────────────────────────────────────
    breach_id: str = Field(
        description="Flare credential hash or event UID used for deduplication"
    )
    event_type: str = Field(
        description=(
            "Flare event category: leaked_credentials | stealer_log | paste | "
            "ransomleak | forum_post | chat_message | blog_post | cc"
        )
    )

    # ── Exposure details ──────────────────────────────────────────────────────
    source: Optional[str] = Field(
        default=None,
        description="Breach or dark-web source name (e.g. 'Collection#1', 'RaidForums')"
    )
    identity_name: Optional[str] = Field(
        default=None,
        description="Email address or username that was exposed"
    )
    domain: Optional[str] = Field(
        default=None,
        description="Email domain of the exposed credential (e.g. 'example.com')"
    )

    # ── Credential fields ─────────────────────────────────────────────────────
    hash_type: Optional[str] = Field(
        default=None,
        description="Password hash format: MD5, SHA1, SHA256, bcrypt, plaintext, unknown"
    )
    password_exposed: Optional[bool] = Field(
        default=None,
        description="True if a cleartext password was present in the source dump"
    )

    # ── Stealer-log specific ──────────────────────────────────────────────────
    malware_family: Optional[str] = Field(
        default=None,
        description="Infostealer malware family (e.g. Redline, Raccoon, Vidar) — stealer_log only"
    )
    infection_country: Optional[str] = Field(
        default=None,
        description="ISO-3166 country code where the stealer infection occurred"
    )

    # ── Dark-web context ──────────────────────────────────────────────────────
    url: Optional[str] = Field(
        default=None,
        description="Dark-web or paste URL where the data was found (if available)"
    )

    # ── Timing ────────────────────────────────────────────────────────────────
    breach_date: Optional[datetime] = Field(
        default=None,
        description="Original breach date if known; otherwise None"
    )
    imported_at: Optional[str] = Field(
        default=None,
        description="ISO-8601 date when Flare indexed this event"
    )

    class Config:
        extra = "allow"

    def to_flowsint_node(self) -> dict:
        label_parts = filter(None, [self.identity_name, self.source, self.event_type])
        return {
            "label": f"Breach:{':'.join(label_parts)}",
            "type": "FlareBreach",
            **self.model_dump(exclude_none=True),
        }

    @classmethod
    def from_flare_credential(cls, raw: dict) -> "FlareBreach":
        """
        Construct from a Flare /astp/v2/credentials/_search result item.

        Flare field mapping:
          id              → breach_id
          source          → source
          identity_name   → identity_name
          domain          → domain
          hash_type       → hash_type
          imported_at     → imported_at
        """
        return cls(
            breach_id=str(raw.get("id") or raw.get("credential_hash", "")),
            event_type="leaked_credentials",
            source=raw.get("source"),
            identity_name=raw.get("identity_name"),
            domain=raw.get("domain"),
            hash_type=raw.get("hash_type"),
            password_exposed=raw.get("hash_type", "").lower() in ("plain", "plaintext", ""),
            imported_at=raw.get("imported_at"),
        )

    @classmethod
    def from_flare_event(cls, raw: dict) -> "FlareBreach":
        """
        Construct from a Flare GET /firework/v4/events/ response.

        The event_type discriminator maps to the FlareBreach event_type field.
        Stealer-log extras (malware_family, infection_country) are extracted
        from the nested stealer metadata when present.
        """
        etype = raw.get("event_type", "unknown")
        metadata = raw.get("metadata", {}) or {}
        return cls(
            breach_id=str(raw.get("uid") or raw.get("id", "")),
            event_type=etype,
            source=raw.get("source") or metadata.get("source"),
            identity_name=raw.get("identity_name") or metadata.get("username"),
            domain=raw.get("domain") or metadata.get("domain"),
            hash_type=raw.get("hash_type"),
            password_exposed=raw.get("has_password"),
            malware_family=metadata.get("malware_family") if etype == "stealer_log" else None,
            infection_country=metadata.get("country") if etype == "stealer_log" else None,
            url=raw.get("url"),
            imported_at=raw.get("imported_at") or raw.get("created_at"),
        )
