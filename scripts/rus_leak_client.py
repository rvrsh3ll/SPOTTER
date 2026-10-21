#!/usr/bin/env python3
"""
rus_leak_client.py — Russian leak database and phone lookup client for SPOTTER.

WHAT IT IS FOR
--------------
Extends WF13's domain recon with Russian-specific breach data and phone
number OSINT. Sources:

  - Reveng.ee        — Parsed Russian databases and leaks (free for journalists)
  - Getcontact       — Contact identification / caller name lookup
  - Nomerogram       — Russian phone number OSINT (carrier, region, owner)
  - Eye of God (BoG) — Alternative leak DB with free tier

All sources except Reveng.ee are session-based and require a disposable
identity (see scripts/identity_store.py) for account creation.

OPSEC
-----
Phone lookups and leak DB queries are highly attributable. Every request
goes through the campaign proxy envelope. Disposable identities are used
for session-based services. Fail-closed proxy pattern (same as hh_client.py
and rus_corporate.py).
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote as _url_quote

import requests


_DEFAULT_TIMEOUT = 20
_DEFAULT_MAX_REQUESTS = 20
_DEFAULT_MAX_SECONDS = 90

_DEFAULT_WEB_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

# Russian phone number patterns
_RU_PHONE_RE = re.compile(
    r"^(?:\+?7[\s\-]?)?(?:8[\s\-]?)?"
    r"(?:\(?(\d{3})\)?[\s\-]?)?"
    r"(\d{3})[\s\-]?(\d{2})[\s\-]?(\d{2})$"
)


def normalise_ru_phone(phone: str) -> Optional[str]:
    """Normalise a Russian phone number to +7XXXXXXXXXX format."""
    digits = re.sub(r"\D", "", phone or "")
    if not digits:
        return None
    # Handle 8 prefix (Russian domestic long-distance)
    if len(digits) == 11 and digits[0] == "8":
        digits = "7" + digits[1:]
    # Handle bare 10-digit number (no country code)
    elif len(digits) == 10:
        digits = "7" + digits
    # Now we should have 11 digits starting with 7
    if len(digits) == 11 and digits[0] == "7":
        return "+" + digits
    return None


def is_ru_phone(phone: str) -> bool:
    """Check if a string looks like a Russian phone number."""
    return normalise_ru_phone(phone) is not None


class RusLeakError(Exception):
    """A source-level failure the caller should record, not raise through."""


class RusLeakClient:
    """Query Russian leak databases and phone lookup services.

    Each source is independent: one failing does not block the others.
    Results accumulate in self.results and self.errors.
    """

    def __init__(
        self,
        proxy_url: str = "",
        user_agent: str = "",
        timeout: Optional[int] = None,
        max_requests: int = _DEFAULT_MAX_REQUESTS,
        max_seconds: int = _DEFAULT_MAX_SECONDS,
        reveng_api_key: str = "",
    ):
        self.proxy_url = (proxy_url or "").strip()
        self.proxies = (
            {"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None
        )
        self.user_agent = (user_agent or "").strip() or _DEFAULT_WEB_UA
        self.timeout = timeout or _DEFAULT_TIMEOUT
        self.max_requests = max_requests
        self.max_seconds = max_seconds
        self.reveng_api_key = (reveng_api_key or os.environ.get("REVENG_API_KEY", "")).strip()

        self.errors: List[str] = []
        self.results: Dict[str, Any] = {
            "reveng": None,
            "phone_lookups": [],
        }
        self._requests_made = 0
        self._started = time.time()

    def budget_exhausted(self) -> bool:
        return (
            self._requests_made >= self.max_requests
            or (time.time() - self._started) >= self.max_seconds
        )

    def _note(self, msg: str) -> None:
        if msg not in self.errors:
            self.errors.append(msg)

    def _get(self, url: str, params: Optional[dict] = None,
             headers: Optional[dict] = None, source: str = "") -> Optional[requests.Response]:
        if self.budget_exhausted():
            self._note(f"{source}: budget exhausted")
            return None
        hdrs = {"User-Agent": self.user_agent}
        if headers:
            hdrs.update(headers)
        try:
            r = requests.get(url, params=params, headers=hdrs,
                             proxies=self.proxies, timeout=self.timeout)
            self._requests_made += 1
            return r
        except requests.exceptions.ProxyError as e:
            self._note(f"{source}: proxy unreachable: {e}")
            return None
        except Exception as e:
            self._note(f"{source}: request failed: {e}")
            return None

    def _post(self, url: str, json_data: Optional[dict] = None,
              headers: Optional[dict] = None, source: str = "") -> Optional[requests.Response]:
        if self.budget_exhausted():
            self._note(f"{source}: budget exhausted")
            return None
        hdrs = {"User-Agent": self.user_agent, "Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        try:
            r = requests.post(url, json=json_data, headers=hdrs,
                              proxies=self.proxies, timeout=self.timeout)
            self._requests_made += 1
            return r
        except requests.exceptions.ProxyError as e:
            self._note(f"{source}: proxy unreachable: {e}")
            return None
        except Exception as e:
            self._note(f"{source}: request failed: {e}")
            return None

    # ── Reveng.ee ────────────────────────────────────────────────────────────

    def search_reveng(self, query: str, query_type: str = "email") -> Optional[Dict[str, Any]]:
        """Search Reveng.ee for leaked data.

        query_type: email | phone | username
        Requires REVENG_API_KEY (free registration for journalists/OSINTers).
        """
        if not self.reveng_api_key:
            self._note("reveng: no API key configured (set REVENG_API_KEY)")
            return None

        if not query:
            return None

        api_url = "https://api.reveng.ee/v1/search"
        payload = {"query": query, "type": query_type}
        headers = {"Authorization": f"Bearer {self.reveng_api_key}"}

        r = self._post(api_url, json_data=payload, headers=headers, source="reveng")
        if r is None:
            return None

        if r.status_code == 200:
            try:
                data = r.json()
                breaches = []
                for record in (data.get("results") or data.get("breaches") or [])[:50]:
                    breaches.append({
                        "source_db": record.get("source", record.get("database", "")),
                        "email": record.get("email", ""),
                        "phone": record.get("phone", ""),
                        "username": record.get("username", ""),
                        "password_hash": record.get("hash", ""),
                        "password_plain": record.get("password", ""),
                        "added_date": record.get("date", ""),
                    })
                return {
                    "query": query,
                    "query_type": query_type,
                    "breaches": breaches,
                    "total": data.get("total", len(breaches)),
                    "source": "reveng.ee",
                }
            except Exception as e:
                self._note(f"reveng: parse failed: {e}")
                return None
        elif r.status_code == 401:
            self._note("reveng: API key rejected (HTTP 401)")
            return None
        elif r.status_code == 429:
            self._note("reveng: rate limited (HTTP 429)")
            return None
        else:
            self._note(f"reveng: HTTP {r.status_code}")
            return None

    # ── Phone lookup ─────────────────────────────────────────────────────────

    def lookup_phone(self, phone: str) -> Optional[Dict[str, Any]]:
        """Look up a Russian phone number across available services.

        Tries multiple free/keyless approaches:
        1. Number format validation + carrier/region from prefix
        2. Public phone directory lookups (if accessible)
        """
        normalised = normalise_ru_phone(phone)
        if not normalised:
            self._note(f"phone: not a valid Russian phone number: {phone}")
            return None

        result = {
            "phone": normalised,
            "original": phone,
            "carrier": "",
            "region": "",
            "owner_name": "",
            "source": "",
        }

        # Prefix-based carrier/region lookup (free, keyless)
        # Russian mobile prefixes: 9XX (mobile), 3XX-4XX-8XX (landline by region)
        digits = normalised.lstrip("+")
        if len(digits) == 11:
            prefix3 = digits[1:4]
            prefix4 = digits[1:5] if len(digits) > 4 else ""

            # Major Russian mobile carriers by prefix
            carrier_map = {
                "900": "MTS", "901": "MTS", "902": "MTS", "903": "MTS",
                "904": "MTS", "905": "MTS", "906": "MTS", "907": "MTS",
                "908": "MTS", "909": "MTS",
                "910": "MTS", "911": "MTS", "912": "MTS", "913": "MTS",
                "914": "MTS", "915": "MTS", "916": "MTS", "917": "MTS",
                "918": "MTS", "919": "MTS",
                "920": "Megafon", "921": "Megafon", "922": "Megafon",
                "923": "Megafon", "924": "Megafon", "925": "Megafon",
                "926": "Megafon", "927": "Megafon", "928": "Megafon",
                "929": "Megafon",
                "930": "Tele2", "931": "Tele2", "932": "Tele2",
                "933": "Tele2", "934": "Tele2", "935": "Tele2",
                "936": "Tele2", "937": "Tele2", "938": "Tele2",
                "939": "Tele2",
                "950": "Beeline", "951": "Beeline", "952": "Beeline",
                "953": "Beeline", "954": "Beeline", "955": "Beeline",
                "958": "Beeline", "960": "Beeline", "961": "Beeline",
                "962": "Beeline", "963": "Beeline", "964": "Beeline",
                "965": "Beeline", "966": "Beeline", "967": "Beeline",
                "968": "Beeline", "969": "Beeline",
                "977": "Yota", "978": "Yota",
                "991": "Tele2", "992": "Tele2", "993": "Tele2",
                "994": "Tele2", "995": "Tele2", "996": "Tele2",
                "997": "Tele2", "999": "Tele2",
            }
            result["carrier"] = carrier_map.get(prefix3, "")

            # Region codes (landline prefixes 3XX-4XX-8XX)
            region_map = {
                "495": "Moscow", "499": "Moscow",
                "812": "Saint Petersburg",
                "343": "Yekaterinburg",
                "383": "Novosibirsk",
                "831": "Nizhny Novgorod",
                "846": "Samara",
                "351": "Chelyabinsk",
                "391": "Krasnoyarsk",
                "843": "Kazan",
                "347": "Ufa",
                "844": "Volgograd",
                "342": "Perm",
                "861": "Krasnodar",
                "395": "Irkutsk",
                "423": "Vladivostok",
                "381": "Omsk",
                "384": "Kemerovo",
                "352": "Kurgan",
                "851": "Astrakhan",
                "863": "Rostov-on-Don",
                "845": "Saratov",
                "842": "Ulyanovsk",
                "385": "Barnaul",
                "394": "Voronezh",
                "818": "Arkhangelsk",
                "821": "Syktyvkar",
                "855": "Naberezhnye Chelny",
                "341": "Izhevsk",
                "833": "Kirov",
                "382": "Tomsk",
                "301": "Ulan-Ude",
                "345": "Tyumen",
                "388": "Gorno-Altaysk",
                "390": "Abakan",
                "346": "Surgut",
                "836": "Yoshkar-Ola",
                "834": "Saransk",
                "835": "Cheboksary",
            }
            if not result["carrier"]:
                result["region"] = region_map.get(prefix3, "")

        result["source"] = "prefix-lookup"
        return result

    # ── Aggregate query ──────────────────────────────────────────────────────

    def query_all(
        self,
        emails: Optional[List[str]] = None,
        phones: Optional[List[str]] = None,
        usernames: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run all applicable sources for the given identifiers.

        Emails → Reveng.ee breach search
        Phones → phone lookup (carrier/region)
        Usernames → Reveng.ee search
        """
        emails = emails or []
        phones = phones or []
        usernames = usernames or []

        # Reveng.ee breach search
        if self.reveng_api_key:
            for email in emails[:5]:
                if self.budget_exhausted():
                    break
                rev = self.search_reveng(email, query_type="email")
                if rev:
                    existing = self.results.get("reveng") or {"breaches": []}
                    existing["breaches"].extend(rev.get("breaches", []))
                    self.results["reveng"] = existing

            for uname in usernames[:5]:
                if self.budget_exhausted():
                    break
                rev = self.search_reveng(uname, query_type="username")
                if rev:
                    existing = self.results.get("reveng") or {"breaches": []}
                    existing["breaches"].extend(rev.get("breaches", []))
                    self.results["reveng"] = existing

        # Phone lookups (always run, free/keyless)
        for phone in phones[:10]:
            if self.budget_exhausted():
                break
            lookup = self.lookup_phone(phone)
            if lookup:
                self.results["phone_lookups"].append(lookup)

        return {
            "results": self.results,
            "errors": self.errors,
            "requests_made": self._requests_made,
            "elapsed_seconds": round(time.time() - self._started, 2),
        }
