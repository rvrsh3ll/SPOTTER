"""
flare_client.py — Flare.io REST API client for SPOTTER.

Handles authentication (API key → 1-hour JWT), credential searches by domain
and email, and event retrieval.

NOT CURRENTLY WIRED IN. This module has no importers. WF09 (Flare ingestor) and
WF13 (domain recon) both call the Flare API with inline `requests` in their Code
nodes, and flare_breach_enricher.py does not import this either -- so the JWT
rotation implemented here is duplicated, less carefully, in those nodes. It stays
on the runners' N8N_RUNNERS_EXTERNAL_ALLOW list, so a Code node can adopt it with
no config change; doing that and deleting the inline copies is the intended
direction. Verified unreferenced 2026-09-06 -- do not trust this note over a
fresh grep if you are relying on it.

Environment variables:
  FLARE_API_KEY   — Flare API key from https://app.flare.io/#/profile → API Keys
  FLARE_TENANT_ID — (optional) Flare tenant ID when using multi-tenant access
"""

from __future__ import annotations

import os
import time
from typing import Iterator, List, Optional

import requests

FLARE_BASE = "https://api.flare.io"
_TOKEN_TTL = 3500  # seconds; Flare tokens expire at 3600, refresh 100s early


class FlareClient:
    def __init__(self, api_key: Optional[str] = None, tenant_id: Optional[str] = None):
        self.api_key = api_key or os.environ.get("FLARE_API_KEY", "")
        self.tenant_id = tenant_id or os.environ.get("FLARE_TENANT_ID", "")
        self._token: Optional[str] = None
        self._token_expires: float = 0.0

    # ── Authentication ────────────────────────────────────────────────────────

    def _refresh_token(self) -> None:
        """Exchange the API key for a short-lived Bearer JWT."""
        resp = requests.post(
            f"{FLARE_BASE}/tokens/generate",
            headers={"Authorization": self.api_key},
            timeout=15,
        )
        resp.raise_for_status()
        self._token = resp.json()["token"]
        self._token_expires = time.time() + _TOKEN_TTL

    def _token_valid(self) -> bool:
        return bool(self._token) and time.time() < self._token_expires

    def _headers(self) -> dict:
        if not self._token_valid():
            self._refresh_token()
        h = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        if self.tenant_id:
            h["X-Tenant-ID"] = self.tenant_id
        return h

    def test_auth(self) -> bool:
        """Return True if the current credentials successfully authenticate."""
        try:
            resp = requests.get(
                f"{FLARE_BASE}/tokens/test",
                headers=self._headers(),
                timeout=10,
            )
            return resp.status_code == 200
        except Exception:
            return False

    # ── Credential search (ASTP) ──────────────────────────────────────────────

    def _search_credentials(self, query: dict, size: int = 200) -> Iterator[dict]:
        """
        POST /astp/v2/credentials/_search with pagination.

        Yields individual credential dicts from all pages.
        Fields per credential: id, identity_name, domain, hash, hash_type,
        source, imported_at, auth_domains (if included).
        """
        cursor: Optional[str] = None
        fetched = 0

        while True:
            body: dict = {"size": min(size, 10000), "query": query}
            if cursor:
                body["from"] = cursor

            resp = requests.post(
                f"{FLARE_BASE}/astp/v2/credentials/_search",
                headers=self._headers(),
                json=body,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

            items = data.get("items") or data.get("hits") or []
            for item in items:
                yield item
                fetched += 1

            cursor = data.get("next")
            if not cursor or not items:
                break

    def search_by_domain(self, domain: str, size: int = 200) -> List[dict]:
        """Return all exposed credentials for an email domain (e.g. 'example.com')."""
        query = {"type": "domain", "fqdn": domain}
        return list(self._search_credentials(query, size=size))

    def search_by_email(self, email: str, size: int = 100) -> List[dict]:
        """Return all exposed credentials for an exact email address."""
        # ASTP v2 query is a discriminated union keyed by `type`; the value field
        # is named after the type (email→email, keyword→keyword, domain→fqdn).
        query = {"type": "email", "email": email}
        return list(self._search_credentials(query, size=size))

    def search_by_username(self, username: str, size: int = 100) -> List[dict]:
        """
        Return credentials where the username portion before '@' matches.
        Useful when the operator's email domain is unknown.
        """
        query = {"type": "keyword", "keyword": username}
        return list(self._search_credentials(query, size=size))

    # ── Event retrieval ───────────────────────────────────────────────────────

    def get_event(self, uid: str) -> Optional[dict]:
        """
        GET /firework/v4/events/?uid=<uid>

        Returns the full event object for any event type (stealer_log, paste,
        ransomleak, forum_post, etc.).  Returns None on 404.
        """
        resp = requests.get(
            f"{FLARE_BASE}/firework/v4/events/",
            headers=self._headers(),
            params={"uid": uid},
            timeout=20,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    # ── Convenience helpers ───────────────────────────────────────────────────

    def search_individual(
        self,
        email: Optional[str] = None,
        username: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> List[dict]:
        """
        Aggregate all breach hits for one individual.

        Priority:
          1. Exact email search (most specific, least noise)
          2. Domain search (catches variations, higher volume)
          3. Username keyword search (cross-domain username reuse)

        Deduplicates by credential `id` field.
        """
        seen: set[str] = set()
        results: List[dict] = []

        def _add(items: List[dict]) -> None:
            for item in items:
                key = str(item.get("id") or item.get("credential_hash") or id(item))
                if key not in seen:
                    seen.add(key)
                    results.append(item)

        if email:
            _add(self.search_by_email(email))

        if domain:
            _add(self.search_by_domain(domain))
        elif email and "@" in email:
            _add(self.search_by_domain(email.split("@")[1]))

        if username:
            _add(self.search_by_username(username))

        return results
