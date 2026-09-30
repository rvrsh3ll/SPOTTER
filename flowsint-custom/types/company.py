"""
Company — Flowsint custom node type.

A real-world commercial entity: the target organization itself, its subsidiary
and sibling brands, and the third-party vendors its infrastructure depends on.
Created by WF13's `org` source (hh.ru, plus DNS/WHOIS-derived vendors) and
connected to other companies via SUBSIDIARY_OF / RELATED_TO / VENDOR_OF, and to
people via RECRUITS_FOR / WORKS_FOR.

Flowsint node label : Company
Dedup key           : name  (the node's nodeLabel)

WHY NOT THE BUILT-IN `organization` TYPE
----------------------------------------
Because in a SPOTTER graph `organization` does not mean "company". SharpHound
ingests three different Active Directory constructs under that label:

    scripts/sharphound_parser.py:581   AD groups      -> Organization
    scripts/sharphound_parser.py:621   AD domains     -> Organization {is_domain}
    scripts/sharphound_parser.py:679   OUs/containers -> Organization {is_ou}

and every downstream reader was written against that meaning. WF05's dossier
compiler treats *any* `organization` neighbour of an Individual as an AD group
membership, so a company written there would appear in operators' dossiers as a
security group the person belongs to -- wrong, and wrong without erroring.
Flowsint's own built-in organization model is a French SIRENE/INSEE company
record (siren, siege_*, dirigeants), which does not fit either.

A separate label keeps both meanings intact and lets a reader ask for one
without filtering the other out by hand.

CASING
------
Written with fc.add_node, which preserves the PascalCase spelling. Do NOT route
these through batch_import: it lowercases custom type names, so the nodes land
as `company` and any PascalCase read finds zero and reports success. Readers
should still fold case (toLower(labels(n)[0]) = 'company') to survive a graph
that was populated either way.

DECLARED PROPERTIES ARE STRINGS ONLY
------------------------------------
A DB-registered custom type is rebuilt with every *declared* property typed
Optional[str]; Pydantic v2 refuses to coerce ints, floats, bools and lists into
str, and the serializer then drops them silently. So open_vacancies, rating,
employee_count, the boolean flags and every list stay UNDECLARED here and in
scripts/register_company_type.py, which lets them through as extras and keeps
their native Neo4j type. That is what makes `WHERE c.open_vacancies > 100` and
`WHERE 'DevOps / Cloud' IN c.hiring_specialties` work.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


# How a Company node relates to the campaign's target organization. Stored as a
# property rather than inferred from edges so a single-node read can answer
# "is this the target or a vendor?" without walking the graph.
RELATIONSHIPS = ("target", "subsidiary", "related", "vendor")


class Company(BaseModel):
    # ── Identity ──────────────────────────────────────────────────────────────
    name: str = Field(description="Company name (used as the dedup key / nodeLabel)")
    relationship: str = Field(
        default="target",
        description="How this company relates to the campaign target: "
                    "target | subsidiary | related | vendor",
    )
    source: Optional[str] = Field(
        default=None,
        description="Where this record came from: hh.ru | linkedin | whois | dns",
    )
    external_id: Optional[str] = Field(
        default=None, description="Identifier on the source platform (e.g. hh.ru employer id)"
    )
    profile_url: Optional[str] = Field(
        default=None, description="Canonical page for this company on the source platform"
    )

    # ── Corporate facts ───────────────────────────────────────────────────────
    industry: Optional[str] = Field(
        default=None, description="Primary industry, as named by the source"
    )
    description: Optional[str] = Field(
        default=None, description="Self-described business, flattened to text"
    )
    site_url: Optional[str] = Field(default=None, description="Corporate website")
    country: Optional[str] = Field(default=None, description="Country code or name")
    hq_address: Optional[str] = Field(default=None, description="Headquarters address")
    size_category: Optional[str] = Field(
        default=None, description="Employee-count band as reported by the source"
    )

    # ── Provenance ────────────────────────────────────────────────────────────
    discovered_at: Optional[datetime] = Field(
        default=None, description="When this record was first written"
    )

    # ── Undeclared on purpose (see the module docstring) ──────────────────────
    # open_vacancies: int        employee_count: int       rating: float
    # it_accredited: bool        trusted: bool             has_divisions: bool
    # industries: List[str]      departments: List[str]    offices: List[str]
    # hiring_roles: List[str]    hiring_specialties: List[str]
    # tech_keywords: List[str]

    class Config:
        extra = "allow"

    def to_flowsint_node(self) -> dict:
        return {
            "label": self.name,
            "type": "Company",
            **self.model_dump(exclude_none=True),
        }


def vendor_from_hostname(hostname: str) -> Optional[str]:
    """Best-effort vendor name from an SPF include / MX / NS / CNAME target.

    `spf.protection.outlook.com` -> `outlook.com`, `aspmx.l.google.com` ->
    `google.com`. This is a naming convenience only; it deliberately does not
    try to resolve a legal entity, because guessing one wrong is worse than
    showing the operator the hostname the guess came from -- so callers keep the
    source hostname alongside the name.
    """
    h = (hostname or "").strip().lower().rstrip(".")
    if not h or "." not in h:
        return None
    parts = h.split(".")
    # Two-level public suffixes we actually meet in mail/DNS records.
    two_level = {"co.uk", "com.au", "co.jp", "com.br", "co.nz", "com.tr", "co.za"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
