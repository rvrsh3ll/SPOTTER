"""
SocialProfile — Flowsint custom node type.

Represents a social media or professional profile discovered for an Individual.
Created by Maigret enrichment or manual operator input and connected to an
Individual via a HAS_PROFILE relationship.

Flowsint node label : SocialProfile
Dedup key           : url  (canonical profile URL)

Specialty derivation:
  The 'specialty' field is a normalized job function category derived from the
  raw 'job_title'.  It lets operators filter by role without string-matching
  free-text titles across sources.

  _SPECIALTY_RULES below is MIRRORED in scripts/job_titles.py, because the n8n
  Python runner cannot import this package -- only scripts/ is mounted there,
  and only allowlisted module names may be imported at all.  WF13's organization
  block compares specialties derived on both sides, so the two tables must agree:
  edit one, edit the other.  check_job_title_rules() in
  scripts/check_workflow_regressions.py fails the build when they diverge.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, model_validator


_SPECIALTY_RULES: list[tuple[list[str], str]] = [
    (["database", "dba", "sql server", "oracle dba", "mysql admin", "postgres dba"], "Database Engineer"),
    (["ciso", "penetration test", "pentest", "red team", "soc analyst", "threat hunt", "infosec", "cybersecurity", "information security"], "Security Professional"),
    (["devops", "site reliability", "sre ", " sre", "platform engineer", "cloud engineer", "devsecops"], "DevOps / Cloud"),
    (["data scientist", "data analyst", "machine learning", "ml engineer", " ai ", "artificial intel", "data engineer", "analytics engineer"], "Data / ML"),
    (["software engineer", "software developer", "swe", "programmer", "full stack", "frontend", "backend", "web developer", "mobile developer"], "Software Engineer"),
    (["network engineer", "network admin", "infrastructure", "systems admin", "sysadmin", "it admin", "it manager", "systems engineer"], "Infrastructure / IT"),
    (["finance", "financial analyst", "accounting", "accountant", "controller", "cfo", "treasurer", "bookkeeper", "payroll"], "Finance"),
    (["human resources", " hr ", "talent acquisition", "recruiting", "recruiter", "people ops", "people partner"], "Human Resources"),
    (["marketing", "growth hacker", "brand manager", "content strategist", "digital marketing", "seo specialist", "demand gen"], "Marketing"),
    (["sales", "account executive", "business development", "bdr", "sdr", "account manager", "revenue"], "Sales"),
    (["ceo", "chief executive", "cto", "chief technology", "coo", "chief operating", "president", "vice president", " vp ", "head of"], "Executive"),
    (["director", "senior director", "managing director"], "Director"),
    (["manager", "team lead", "principal ", "staff ", "engineering manager"], "Manager"),
    (["analyst"], "Analyst"),
    (["engineer", "developer", "architect"], "Engineer"),
]


def derive_specialty(job_title: Optional[str]) -> Optional[str]:
    """Map a free-text job title to a normalized specialty category."""
    if not job_title:
        return None
    t = job_title.lower()
    for keywords, specialty in _SPECIALTY_RULES:
        if any(k in t for k in keywords):
            return specialty
    return job_title.title()


class SocialProfile(BaseModel):
    # ── Platform identity ─────────────────────────────────────────────────────
    platform: str = Field(
        description=(
            "Social platform slug: linkedin | twitter | github | facebook | "
            "instagram | youtube | telegram | reddit | tiktok | mastodon | other"
        )
    )
    username: Optional[str] = Field(
        default=None, description="Handle / username on the platform"
    )
    url: str = Field(description="Canonical profile URL (used as dedup key)")

    # ── Identity fields ───────────────────────────────────────────────────────
    display_name: Optional[str] = Field(
        default=None, description="Full name as displayed on the platform"
    )
    bio: Optional[str] = Field(
        default=None, description="Profile bio or summary text"
    )

    # ── Professional metadata (mainly LinkedIn) ───────────────────────────────
    job_title: Optional[str] = Field(
        default=None, description="Current or most recent job title"
    )
    employer: Optional[str] = Field(
        default=None, description="Current or most recent employer / company"
    )
    specialty: Optional[str] = Field(
        default=None,
        description="Normalized job function derived from job_title (auto-populated if absent)"
    )

    # ── Location ──────────────────────────────────────────────────────────────
    location: Optional[str] = Field(
        default=None, description="City, State/Province, Country from profile"
    )

    # ── Engagement metrics ────────────────────────────────────────────────────
    connections: Optional[int] = Field(
        default=None, description="LinkedIn connection count or similar"
    )
    followers: Optional[int] = Field(
        default=None, description="Follower count on the platform"
    )

    # ── Contact info on profile ───────────────────────────────────────────────
    profile_emails: List[str] = Field(
        default_factory=list,
        description="Email addresses found on the public profile page"
    )
    profile_phones: List[str] = Field(
        default_factory=list,
        description="Phone numbers found on the public profile page"
    )

    # ── LinkedIn extended data ────────────────────────────────────────────────
    work_history: List[dict] = Field(
        default_factory=list,
        description="Past and current positions: [{title, employer, start_date, end_date, description}]"
    )
    locations_lived: List[str] = Field(
        default_factory=list,
        description="Historical locations from profile (cities/regions lived or worked in)"
    )
    office_address: Optional[str] = Field(
        default=None,
        description="Physical office or company address from profile"
    )

    # ── Visual identity ───────────────────────────────────────────────────────
    photo_url: Optional[str] = Field(
        default=None, description="URL to a profile photo/avatar (LinkedIn, Gravatar, etc.)"
    )
    photo_source: Optional[str] = Field(
        default=None, description="Source of the photo: linkedin | gravatar | ad | manual"
    )

    # ── Provenance ────────────────────────────────────────────────────────────
    source: Optional[str] = Field(
        default=None,
        description="How this profile was discovered: maigret | manual | linkedin-scrape | osint"
    )
    last_crawled: Optional[datetime] = Field(
        default=None, description="Timestamp of the most recent data pull from this profile"
    )

    @model_validator(mode="after")
    def _fill_specialty(self) -> "SocialProfile":
        if not self.specialty and self.job_title:
            self.specialty = derive_specialty(self.job_title)
        return self

    class Config:
        extra = "allow"

    def to_flowsint_node(self) -> dict:
        label = f"{self.platform.title()}:{self.username or self.display_name or self.url}"
        return {
            "label": label,
            "type": "SocialProfile",
            **self.model_dump(exclude_none=True),
        }
