"""
Maigret Social-Profile Enricher — Flowsint plugin enricher for Individual nodes.

Calls the SPOTTER Maigret API sidecar (maigret-api:7050) to search for social
media profiles by username.  For each claimed profile it:

  1. MERGEs a SocialProfile node in Neo4j (idempotent; keyed on platform:username
     within the sketch).
  2. Creates a HAS_PROFILE edge from the Individual to the SocialProfile.
  3. Writes social_profile_count / maigret_enriched back to the Individual.

Already-enriched individuals are skipped unless the **force** run parameter is
set to "true" (type it into the Force field in the enricher dialog).

Configuration (environment variables on the Flowsint API / Celery containers):
  MAIGRET_API_URL   URL of the Maigret API service  (default: http://maigret-api:7050)
  MAIGRET_TIMEOUT   Per-site request timeout in s    (default: 30)
  MAIGRET_TOP_SITES Limit scan to this many sites    (default: 150)

Installation: volume-mounted via docker-compose.flowsint.yml; restart
flowsint-api-prod and flowsint-celery-prod after adding this file.
"""

from __future__ import annotations

import json as _json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests as _requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.individual import Individual

# ── Configuration ─────────────────────────────────────────────────────────────
_MAIGRET_API_URL = os.environ.get("MAIGRET_API_URL", "http://maigret-api:7050").rstrip("/")
_MAIGRET_TIMEOUT = int(os.environ.get("MAIGRET_TIMEOUT", "30"))
_MAIGRET_TOP_SITES = int(os.environ.get("MAIGRET_TOP_SITES", "150"))

# ── Cypher ────────────────────────────────────────────────────────────────────

_CYPHER_GET_PROPS = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
RETURN n.`nodeProperties.sam_account_name` AS sam,
       n.`nodeProperties.full_name`         AS full_name,
       n.`nodeProperties.email`             AS email,
       n.`nodeProperties.personal_emails`   AS personal_emails,
       n.`nodeProperties.maigret_enriched`  AS already_enriched
LIMIT 1
"""

# MERGE on (nodeLabel, sketch_id) — deterministic UUID in ON CREATE so
# re-running never creates duplicates.
_CYPHER_MERGE_PROFILE = """
MERGE (sp:socialprofile {nodeLabel: $sp_label, sketch_id: $sketch_id})
ON CREATE SET
    sp.id                          = $node_id,
    sp.nodeType                    = 'socialprofile',
    sp.created_at                  = datetime(),
    sp.`nodeProperties.platform`   = $platform,
    sp.`nodeProperties.username`   = $username,
    sp.`nodeProperties.url`        = $url,
    sp.`nodeProperties.source`     = 'maigret'
ON MATCH SET
    sp.deleted_at                  = null,
    sp.`nodeProperties.url`        = $url,
    sp.`nodeProperties.platform`   = $platform
"""

_CYPHER_LINK_PROFILE = """
MATCH (ind:individual {nodeLabel: $ind_label, sketch_id: $sketch_id})
  WHERE ind.deleted_at IS NULL
MATCH (sp:socialprofile {nodeLabel: $sp_label, sketch_id: $sketch_id})
  WHERE sp.deleted_at IS NULL
MERGE (ind)-[:HAS_PROFILE]->(sp)
"""

_CYPHER_UPDATE_IND = """
MATCH (n:individual {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
SET n.`nodeProperties.social_profile_count` = $count,
    n.`nodeProperties.maigret_enriched`     = true,
    n.`nodeProperties.maigret_enriched_at`  = $enriched_at
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clean_username(sam: Optional[str], label: str) -> Optional[str]:
    """Return a clean username: strip DOMAIN\\ prefix, reject empty strings."""
    raw = (sam or label or "").strip()
    if not raw:
        return None
    # Strip 'DOMAIN\\user' → 'user'
    if "\\" in raw:
        raw = raw.split("\\")[-1].strip()
    # Strip '@domain.tld' suffix (email-style)
    if "@" in raw:
        raw = raw.split("@")[0].strip()
    return raw or None


def _sp_node_id(sketch_id: str, sp_label: str) -> str:
    """Deterministic UUID5 so re-running never changes node IDs."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{sketch_id}/{sp_label}"))


def _extract_usernames(emails: List[str]) -> List[str]:
    """Return unique username parts (before @) from a list of email strings."""
    seen: set = set()
    result = []
    for em in emails:
        if not em or "@" not in em:
            continue
        uname = em.split("@")[0].strip().lower()
        if uname and uname not in seen:
            seen.add(uname)
            result.append(uname)
    return result


# ── Enricher ──────────────────────────────────────────────────────────────────

@flowsint_enricher
class MaigretEnricher(Enricher):
    """
    Search for social media profiles by username via the Maigret API sidecar
    and write SocialProfile nodes linked to the Individual via HAS_PROFILE.
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
            params_schema=self.get_params_schema(),  # always use class-defined schema
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
                "description": (
                    "Set to 'true' to re-search individuals that were already "
                    "enriched (ignores the maigret_enriched flag)."
                ),
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "individual_maigret_social_profiles"

    @classmethod
    def category(cls) -> str:
        return "Individual"

    @classmethod
    def key(cls) -> str:
        return "nodeLabel"

    @classmethod
    def documentation(cls) -> str:
        return (
            "Calls the Maigret API sidecar to discover social media profiles "
            "by username, then creates SocialProfile nodes and HAS_PROFILE "
            "edges in the graph."
        )

    # ── scan (async) — do Maigret API calls, build update list ────────────────

    async def scan(self, data: List[Individual]) -> List[Individual]:  # type: ignore[override]
        self._updates = []
        force = str(self.params.get("force") or "").strip().lower() in (
            "true", "1", "yes", "on"
        )

        for ind in data:
            if not ind.nodeLabel:
                continue

            rows = self._graph_service.query(_CYPHER_GET_PROPS, {
                "label":     ind.nodeLabel,
                "sketch_id": self.sketch_id,
            })

            if not rows:
                continue

            row = rows[0]

            # Skip if already enriched — unless force=true
            if row.get("already_enriched") and not force:
                self.log_graph_message(
                    f"Maigret: {ind.nodeLabel} already enriched — skipping "
                    f"(set force=true to re-run)"
                )
                continue

            # Build a deduplicated username list to search:
            # 1. Primary: stripped sam_account_name
            # 2. Corporate email username (e.g. "jdoe" from "jdoe@example.com")
            # 3. Personal email usernames from Flare breach data
            usernames_to_search: List[str] = []
            seen_unames: set = set()

            def _add(u: Optional[str]) -> None:
                if u and u not in seen_unames:
                    seen_unames.add(u)
                    usernames_to_search.append(u)

            _add(_clean_username(row.get("sam"), ind.nodeLabel))
            _add(_clean_username(row.get("email"), ""))  # corp email → username part

            raw_pe = row.get("personal_emails") or "[]"
            try:
                pe_list: List[str] = _json.loads(raw_pe) if isinstance(raw_pe, str) else (raw_pe if isinstance(raw_pe, list) else [])
            except Exception:
                pe_list = []
            for pu in _extract_usernames(pe_list):
                _add(pu)

            # Cap at 5 username variants to avoid excessive API calls
            usernames_to_search = usernames_to_search[:5]
            if not usernames_to_search:
                continue

            # Search Maigret for each username, aggregate and dedup by platform+username
            all_profiles: List[Dict[str, Any]] = []
            seen_profiles: set = set()
            for uname in usernames_to_search:
                found = self._call_maigret(uname)
                for p in found:
                    key = f"{p.get('platform','').lower()}:{p.get('username','').lower()}"
                    if key not in seen_profiles:
                        seen_profiles.add(key)
                        all_profiles.append(p)

            self.log_graph_message(
                f"Maigret: {ind.nodeLabel} → searched {len(usernames_to_search)} username(s), "
                f"found {len(all_profiles)} unique profiles"
            )

            self._updates.append({
                "ind_label": ind.nodeLabel,
                "profiles":  all_profiles,
            })

        return data

    # ── postprocess (sync) — write nodes and edges ────────────────────────────

    def postprocess(
        self,
        results: List[Individual],
        original_input: List[Individual],
    ) -> List[Individual]:
        now = datetime.now(timezone.utc).isoformat()

        for upd in self._updates:
            ind_label = upd["ind_label"]
            profiles  = upd["profiles"]

            for p in profiles:
                platform = p["platform"]
                username = p["username"]
                url      = p["url"]

                # nodeLabel matches the to_flowsint_node() convention
                sp_label = f"{platform.title()}:{username}"
                node_id  = _sp_node_id(self.sketch_id, sp_label)

                self._graph_service.query(_CYPHER_MERGE_PROFILE, {
                    "sketch_id": self.sketch_id,
                    "sp_label":  sp_label,
                    "node_id":   node_id,
                    "platform":  platform,
                    "username":  username,
                    "url":       url,
                })

                self._graph_service.query(_CYPHER_LINK_PROFILE, {
                    "ind_label": ind_label,
                    "sp_label":  sp_label,
                    "sketch_id": self.sketch_id,
                })

            self._graph_service.query(_CYPHER_UPDATE_IND, {
                "label":       ind_label,
                "sketch_id":   self.sketch_id,
                "count":       len(profiles),
                "enriched_at": now,
            })

            self.log_graph_message(
                f"Maigret enrichment done for {ind_label}: "
                f"{len(profiles)} social profiles linked"
            )

        return results

    # ── Internal: call Maigret API ────────────────────────────────────────────

    def _call_maigret(self, username: str) -> List[Dict[str, Any]]:
        try:
            resp = _requests.post(
                f"{_MAIGRET_API_URL}/search",
                json={
                    "username":  username,
                    "timeout":   _MAIGRET_TIMEOUT,
                    "top_sites": _MAIGRET_TOP_SITES,
                },
                timeout=_MAIGRET_TIMEOUT * 4 + 90,
            )
            resp.raise_for_status()
            return resp.json().get("profiles") or []
        except Exception as exc:
            self.log_graph_message(
                f"Maigret API error for username={username!r}: {exc}"
            )
            return []


InputType  = MaigretEnricher.InputType
OutputType = MaigretEnricher.OutputType
