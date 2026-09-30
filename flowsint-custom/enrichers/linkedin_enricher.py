"""
LinkedIn OSINT Enricher — Flowsint plugin enricher for Individual nodes.

For each Individual this enricher:
  1. Checks for a LinkedIn SocialProfile already linked (from Maigret) — if
     found, uses that URL as a confirmed hint for the lookup service.
  2. Calls the SPOTTER LinkedIn Lookup API sidecar (linkedin-api:7051/lookup)
     with full_name, email, company, and location to search for the profile.
  3. If a match meets the confidence threshold, MERGEs a SocialProfile node
     (platform=linkedin) and creates/confirms a HAS_PROFILE edge.
  4. Writes linkedin_enriched, linkedin_url, and linkedin_confidence back to
     the Individual.

Configuration (environment variables on Flowsint API / Celery containers):
  LINKEDIN_API_URL              URL of the LinkedIn Lookup sidecar
                                (default: http://linkedin-api:7051)
  LINKEDIN_CONFIDENCE_THRESHOLD Minimum confidence (0–1) to accept a match
                                (default: 0.40)

Parameters (operator-configurable per enricher run):
  force   Set to 'true' to re-enrich individuals already processed.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests as _requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.individual import Individual

# ── Configuration ─────────────────────────────────────────────────────────────
_LINKEDIN_API_URL  = os.environ.get("LINKEDIN_API_URL", "http://linkedin-api:7051").rstrip("/")
_CONF_THRESHOLD    = float(os.environ.get("LINKEDIN_CONFIDENCE_THRESHOLD", "0.40"))

# ── Cypher ────────────────────────────────────────────────────────────────────

_CYPHER_GET_INDIVIDUAL = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
RETURN
  n.`nodeProperties.full_name`         AS full_name,
  n.`nodeProperties.sam_account_name`  AS sam,
  n.`nodeProperties.email`             AS email,
  n.`nodeProperties.department`        AS department,
  n.`nodeProperties.title`             AS ad_title,
  n.`nodeProperties.company`           AS company,
  n.`nodeProperties.linkedin_enriched` AS already_enriched
LIMIT 1
"""

# Find any existing LinkedIn SocialProfile linked via HAS_PROFILE
_CYPHER_EXISTING_LINKEDIN = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})-[:HAS_PROFILE]->(sp:socialprofile)
WHERE sp.`nodeProperties.platform` = 'linkedin'
  AND sp.deleted_at IS NULL
  AND n.deleted_at IS NULL
RETURN sp.`nodeProperties.url` AS url
LIMIT 1
"""

_CYPHER_MERGE_PROFILE = """
MERGE (sp:socialprofile {nodeLabel: $sp_label, sketch_id: $sketch_id})
ON CREATE SET
    sp.id                                = $node_id,
    sp.nodeType                          = 'socialprofile',
    sp.created_at                        = datetime(),
    sp.`nodeProperties.platform`         = 'linkedin',
    sp.`nodeProperties.url`              = $url,
    sp.`nodeProperties.source`           = 'linkedin-osint'
ON MATCH SET
    sp.deleted_at                        = null,
    sp.`nodeProperties.url`              = $url,
    sp.`nodeProperties.source`           = 'linkedin-osint'
"""

_CYPHER_UPDATE_PROFILE_META = """
MATCH (sp:socialprofile {nodeLabel: $sp_label, sketch_id: $sketch_id})
WHERE sp.deleted_at IS NULL
SET sp.`nodeProperties.display_name`    = $display_name,
    sp.`nodeProperties.job_title`        = $job_title,
    sp.`nodeProperties.employer`         = $employer,
    sp.`nodeProperties.photo_url`        = $photo_url,
    sp.`nodeProperties.photo_source`     = $photo_source,
    sp.`nodeProperties.linkedin_confidence` = $confidence
"""

_CYPHER_LINK_PROFILE = """
MATCH (n:individual {nodeLabel: $ind_label, sketch_id: $sketch_id})
  WHERE n.deleted_at IS NULL
MATCH (sp:socialprofile {nodeLabel: $sp_label, sketch_id: $sketch_id})
  WHERE sp.deleted_at IS NULL
MERGE (n)-[:HAS_PROFILE]->(sp)
"""

_CYPHER_UPDATE_INDIVIDUAL = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
SET n.`nodeProperties.linkedin_enriched`   = true,
    n.`nodeProperties.linkedin_enriched_at` = $enriched_at,
    n.`nodeProperties.linkedin_url`         = $linkedin_url,
    n.`nodeProperties.linkedin_confidence`  = $confidence,
    n.`nodeProperties.linkedin_photo`       = $linkedin_photo
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_company_hint(email: Optional[str], company: Optional[str]) -> Optional[str]:
    """
    Return the best company string we have.  If only an email is available,
    strip the domain and use the company-name part (e.g. 'example' from example.com).
    """
    if company and company.strip():
        return company.strip()
    if email and "@" in email:
        domain = email.split("@")[-1].lower()
        # Strip common TLDs and return the leftmost domain label
        parts = domain.split(".")
        if len(parts) >= 2:
            return parts[-2]  # e.g. "example" from "example.com" or "examplecorp" from "mail.examplecorp.test"
    return None


def _sp_node_id(sketch_id: str, sp_label: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{sketch_id}/{sp_label}"))


# ── Enricher ──────────────────────────────────────────────────────────────────

@flowsint_enricher
class LinkedInEnricher(Enricher):
    """
    Search for and enrich LinkedIn profiles for Individual nodes via the
    SPOTTER LinkedIn Lookup API sidecar.
    """

    InputType  = Individual
    OutputType = Individual

    def __init__(
        self,
        sketch_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        params_schema: Optional[List[Dict[str, Any]]] = None,
        vault: Any = None,
        params: Optional[Dict[str, Any]] = None,
        graph_service: Any = None,
    ) -> None:
        super().__init__(
            sketch_id=sketch_id,
            scan_id=scan_id,
            params_schema=self.get_params_schema(),
            vault=vault,
            params=params,
            graph_service=graph_service,
        )
        self._updates: List[Dict[str, Any]] = []

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "force",
                "type": "string",
                "required": False,
                "default": "false",
                "description": "Set to 'true' to re-enrich individuals already processed.",
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "individual_linkedin_osint"

    @classmethod
    def category(cls) -> str:
        return "Individual"

    @classmethod
    def key(cls) -> str:
        return "nodeLabel"

    @classmethod
    def documentation(cls) -> str:
        return (
            "Searches for a LinkedIn profile matching each Individual using the "
            "SPOTTER LinkedIn Lookup API (DuckDuckGo/SerpAPI), then creates a "
            "SocialProfile node (platform=linkedin) and updates the Individual "
            "with linkedin_url and linkedin_confidence."
        )

    # ── scan (async) ──────────────────────────────────────────────────────────

    async def scan(self, data: List[Individual]) -> List[Individual]:
        self._updates = []
        force = str(self.params.get("force") or "").strip().lower() in (
            "true", "1", "yes", "on"
        )

        for ind in data:
            if not ind.nodeLabel:
                continue

            rows = self._graph_service.query(_CYPHER_GET_INDIVIDUAL, {
                "label":     ind.nodeLabel,
                "sketch_id": self.sketch_id,
            })
            if not rows:
                continue
            row = rows[0]

            if row.get("already_enriched") and not force:
                self.log_graph_message(
                    f"LinkedIn: {ind.nodeLabel} already enriched — skipping "
                    "(set force=true to re-run)"
                )
                continue

            full_name = (row.get("full_name") or ind.nodeLabel or "").strip()
            if not full_name:
                continue

            email   = (row.get("email") or "").strip() or None
            company = _extract_company_hint(email, row.get("company"))

            # Check for an existing LinkedIn SocialProfile (e.g. from Maigret)
            existing_rows = self._graph_service.query(_CYPHER_EXISTING_LINKEDIN, {
                "label":     ind.nodeLabel,
                "sketch_id": self.sketch_id,
            })
            hint_url = existing_rows[0].get("url") if existing_rows else None

            result = self._call_lookup(
                full_name=full_name,
                email=email,
                company=company,
                linkedin_url=hint_url,
            )

            if result is None or not result.get("found"):
                self.log_graph_message(
                    f"LinkedIn: no match found for {ind.nodeLabel} "
                    f"(full_name={full_name!r}, company={company!r})"
                )
                # Still mark as enriched (attempted) to avoid re-scanning on
                # every daily sweep.  Force=true will override this.
                self._updates.append({
                    "ind_label":  ind.nodeLabel,
                    "found":      False,
                    "url":        None,
                    "confidence": 0.0,
                })
                continue

            self.log_graph_message(
                f"LinkedIn: match for {ind.nodeLabel} → {result['url']} "
                f"(confidence={result['confidence']:.2f})"
            )
            self._updates.append({
                "ind_label":    ind.nodeLabel,
                "found":        True,
                "url":          result["url"],
                "confidence":   result["confidence"],
                "display_name": result.get("display_name") or full_name,
                "job_title":    result.get("job_title"),
                "employer":     result.get("employer"),
                "photo_url":    result.get("photo_url"),
            })

        return data

    # ── postprocess (sync) ────────────────────────────────────────────────────

    def postprocess(
        self,
        results: List[Individual],
        original_input: List[Individual],
    ) -> List[Individual]:
        now = datetime.now(timezone.utc).isoformat()

        for upd in self._updates:
            ind_label = upd["ind_label"]
            found     = upd["found"]
            url       = upd.get("url") or ""
            confidence = upd.get("confidence", 0.0)

            # Always update Individual metadata (marks as enriched even if not found)
            self._graph_service.query(_CYPHER_UPDATE_INDIVIDUAL, {
                "label":         ind_label,
                "sketch_id":     self.sketch_id,
                "enriched_at":   now,
                "linkedin_url":  url,
                "confidence":    confidence,
                "linkedin_photo": upd.get("photo_url") or "",
            })

            if not found or not url:
                continue

            # LinkedIn slug as SocialProfile nodeLabel
            slug_m = url.rstrip("/").split("/in/")
            slug   = slug_m[-1] if len(slug_m) > 1 else url
            sp_label = f"Linkedin:{slug}"
            node_id  = _sp_node_id(self.sketch_id, sp_label)

            self._graph_service.query(_CYPHER_MERGE_PROFILE, {
                "sketch_id": self.sketch_id,
                "sp_label":  sp_label,
                "node_id":   node_id,
                "url":       url,
            })

            # Update profile metadata fields only if we have values
            if any(upd.get(k) for k in ("display_name", "job_title", "employer")):
                self._graph_service.query(_CYPHER_UPDATE_PROFILE_META, {
                    "sketch_id":    self.sketch_id,
                    "sp_label":     sp_label,
                    "display_name": upd.get("display_name"),
                    "job_title":    upd.get("job_title"),
                    "employer":     upd.get("employer"),
                    "photo_url":    upd.get("photo_url"),
                    "photo_source": "linkedin" if upd.get("photo_url") else None,
                    "confidence":   confidence,
                })

            self._graph_service.query(_CYPHER_LINK_PROFILE, {
                "sketch_id": self.sketch_id,
                "ind_label": ind_label,
                "sp_label":  sp_label,
            })

            self.log_graph_message(
                f"LinkedIn: linked {sp_label} → {ind_label} "
                f"(job_title={upd.get('job_title')!r}, employer={upd.get('employer')!r})"
            )

        return results

    # ── Internal: call lookup API ─────────────────────────────────────────────

    def _call_lookup(
        self,
        full_name: str,
        email: Optional[str],
        company: Optional[str],
        linkedin_url: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        try:
            resp = _requests.post(
                f"{_LINKEDIN_API_URL}/lookup",
                json={
                    "full_name":    full_name,
                    "email":        email,
                    "company":      company,
                    "linkedin_url": linkedin_url,
                },
                timeout=LI_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            self.log_graph_message(
                f"LinkedIn API error for {full_name!r}: {exc}"
            )
            return None


# Cap request timeout at API sidecar level
LI_TIMEOUT = int(os.environ.get("LINKEDIN_LOOKUP_TIMEOUT", "60"))

InputType  = LinkedInEnricher.InputType
OutputType = LinkedInEnricher.OutputType
