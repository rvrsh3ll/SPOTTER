#!/usr/bin/env python3
"""
rus_corporate.py — Russian corporate registry client for SPOTTER.

WHAT IT IS FOR
--------------
WF30 (Russian Corporate Intelligence) queries free/keyless Russian government
and open-data sources to build a corporate profile of a target entity:

  - EGRUL (egrul.nalog.ru)     — Federal Tax Service legal entity registry
  - rupep.org                  — PEP database (Russia/Belarus/Kazakhstan)
  - zakupki.gov.ru             — Public procurement portal
  - kad.arbitr.ru              — Arbitration court case filings
  - fssp.gov.ru                — Federal Bailiff Service (enforcement proceedings)

All sources are free and keyless. Some require CAPTCHA solving (EGRUL) or
have rate limits. The client follows the same fail-closed proxy pattern as
hh_client.py: if a proxy is configured and unreachable, the request fails
rather than leaking the operator's real IP.

SANDBOX CONSTRAINTS
-------------------
Runs inside the n8n Python task runner. Only stdlib + requests available.
No bs4/lxml. Parsing is re + json + html (same as hh_client.py).

OPSEC
-----
Every request here tells a Russian government portal which entity we are
interested in. The caller MUST pass proxy_url and user_agent from the
campaign's Infrastructure envelope. Fail-closed: proxy unreachable → error,
never silent fallback to direct egress.
"""

from __future__ import annotations

import html as _html
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote as _url_quote, urlencode

import requests


# ── Source base URLs ──────────────────────────────────────────────────────────
EGRUL_BASE = "https://egrul.nalog.ru"
RUPEP_BASE = "https://rupep.org"
ZAKUPKI_BASE = "https://zakupki.gov.ru"
KAD_BASE = "https://kad.arbitr.ru"
FSSP_BASE = "https://fssp.gov.ru"

_DEFAULT_TIMEOUT = 20
_DEFAULT_MAX_REQUESTS = 30
_DEFAULT_MAX_SECONDS = 120

_DEFAULT_WEB_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


class RusCorporateError(Exception):
    """A source-level failure the caller should record, not raise through."""


def _as_int(v: Any) -> Optional[int]:
    try:
        return int(str(v).strip())
    except Exception:
        return None


def _strip_html(s: Any, limit: int = 2000) -> str:
    """Flatten HTML to text for storage."""
    if not s:
        return ""
    txt = re.sub(r"<br\s*/?>|</p>|</li>|</div>", "\n", str(s), flags=re.I)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = _html.unescape(txt)
    txt = re.sub(r"[ \t\u00a0]+", " ", txt)
    txt = re.sub(r"\n\s*\n+", "\n", txt).strip()
    return txt[:limit]


class RusCorporateClient:
    """Query Russian corporate registries for a target entity.

    The client supports lookup by:
      - INN (taxpayer identification number, 10 or 12 digits)
      - OGRN (state registration number, 13 digits)
      - Company name (fuzzy search)
      - Person name (for PEP lookup)

    Each source is independent: one failing does not block the others.
    Results are accumulated in self.results and self.errors.
    """

    def __init__(
        self,
        proxy_url: str = "",
        user_agent: str = "",
        timeout: Optional[int] = None,
        max_requests: int = _DEFAULT_MAX_REQUESTS,
        max_seconds: int = _DEFAULT_MAX_SECONDS,
    ):
        self.proxy_url = (proxy_url or "").strip()
        self.proxies = (
            {"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None
        )
        self.user_agent = (user_agent or "").strip() or _DEFAULT_WEB_UA
        self.timeout = timeout or _DEFAULT_TIMEOUT
        self.max_requests = max_requests
        self.max_seconds = max_seconds

        self.errors: List[str] = []
        self.results: Dict[str, Any] = {
            "egrul": None,
            "rupep": None,
            "procurement": None,
            "courts": None,
            "bailiffs": None,
        }
        self._requests_made = 0
        self._started = time.time()

    # ── Budget + transport ────────────────────────────────────────────────────

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
        """GET with proxy fail-closed and budget tracking."""
        if self.budget_exhausted():
            self._note(f"{source}: budget exhausted before request")
            return None
        hdrs = {"User-Agent": self.user_agent}
        if headers:
            hdrs.update(headers)
        try:
            r = requests.get(url, params=params, headers=hdrs,
                             proxies=self.proxies, timeout=self.timeout)
            self._requests_made += 1
            if self.proxies and r.status_code >= 500:
                self._note(f"{source}: proxy returned HTTP {r.status_code} for {url}")
            return r
        except requests.exceptions.ProxyError as e:
            self._note(f"{source}: proxy unreachable; refusing to fall back to direct: {e}")
            return None
        except Exception as e:
            self._note(f"{source}: request failed ({url}): {e}")
            return None

    def _post(self, url: str, data: Optional[dict] = None,
              json_data: Optional[dict] = None, headers: Optional[dict] = None,
              source: str = "") -> Optional[requests.Response]:
        """POST with proxy fail-closed and budget tracking."""
        if self.budget_exhausted():
            self._note(f"{source}: budget exhausted before request")
            return None
        hdrs = {"User-Agent": self.user_agent}
        if headers:
            hdrs.update(headers)
        try:
            r = requests.post(url, data=data, json=json_data, headers=hdrs,
                              proxies=self.proxies, timeout=self.timeout)
            self._requests_made += 1
            return r
        except requests.exceptions.ProxyError as e:
            self._note(f"{source}: proxy unreachable; refusing to fall back to direct: {e}")
            return None
        except Exception as e:
            self._note(f"{source}: request failed ({url}): {e}")
            return None

    # ── INN / OGRN validation ────────────────────────────────────────────────

    @staticmethod
    def validate_inn(inn: str) -> bool:
        """Validate a Russian INN (10 or 12 digits with checksum)."""
        inn = (inn or "").strip()
        if not re.match(r"^\d{10}$|^\d{12}$", inn):
            return False
        digits = [int(d) for d in inn]
        if len(inn) == 10:
            coeffs = [2, 4, 10, 3, 5, 9, 4, 6, 8]
            check = sum(c * d for c, d in zip(coeffs, digits[:9])) % 11 % 10
            return check == digits[9]
        else:
            coeffs1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
            coeffs2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
            c1 = sum(c * d for c, d in zip(coeffs1, digits[:10])) % 11 % 10
            c2 = sum(c * d for c, d in zip(coeffs2, digits[:11])) % 11 % 10
            return c1 == digits[10] and c2 == digits[11]

    @staticmethod
    def validate_ogrn(ogrn: str) -> bool:
        """Validate a Russian OGRN (13 digits with checksum)."""
        ogrn = (ogrn or "").strip()
        if not re.match(r"^\d{13}$", ogrn):
            return False
        check = int(ogrn[:12]) % 11 % 10
        return check == int(ogrn[12])

    # ── EGRUL (Federal Tax Service) ──────────────────────────────────────────

    def search_egrul(self, query: str) -> Optional[Dict[str, Any]]:
        """Search EGRUL by INN, OGRN, or company name.

        EGRUL requires a CAPTCHA for search. This method performs the initial
        search request and returns the result structure. If a CAPTCHA is
        required, the result includes captcha_required=True and the caller
        must solve it externally and retry with the solution.

        In automated mode (no CAPTCHA solver), this returns the search form
        structure and notes that manual CAPTCHA solving is needed.
        """
        if not query:
            return None

        is_inn = bool(re.match(r"^\d{10}$|^\d{12}$", query.strip()))
        is_ogrn = bool(re.match(r"^\d{13}$", query.strip()))

        # EGRUL search endpoint
        search_url = f"{EGRUL_BASE}/search"
        payload = {"query": query}

        r = self._post(search_url, data=payload, source="egrul")
        if r is None:
            return None

        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, dict) and data.get("captcha_required"):
                    self._note("egrul: CAPTCHA required — manual solving needed")
                    return {
                        "captcha_required": True,
                        "query": query,
                        "query_type": "inn" if is_inn else ("ogrn" if is_ogrn else "name"),
                        "source": "egrul.nalog.ru",
                    }
                return {
                    "captcha_required": False,
                    "query": query,
                    "query_type": "inn" if is_inn else ("ogrn" if is_ogrn else "name"),
                    "results": data if isinstance(data, list) else [],
                    "source": "egrul.nalog.ru",
                    "url": f"{EGRUL_BASE}/search?query={_url_quote(query)}",
                }
            except Exception as e:
                self._note(f"egrul: response parse failed: {e}")
                return None
        elif r.status_code in (403, 429):
            self._note(f"egrul: rate limited or blocked (HTTP {r.status_code})")
            return None
        else:
            self._note(f"egrul: unexpected HTTP {r.status_code}")
            return None

    def get_egrul_by_inn(self, inn: str) -> Optional[Dict[str, Any]]:
        """Look up a legal entity by INN on EGRUL."""
        if not self.validate_inn(inn):
            self._note(f"egrul: invalid INN format: {inn}")
            return None
        return self.search_egrul(inn)

    # ── rupep.org (PEP database) ─────────────────────────────────────────────

    def search_rupep(self, name: str, country: str = "RU") -> Optional[Dict[str, Any]]:
        """Search rupep.org for a politically exposed person.

        rupep.org covers Russia, Belarus, and Kazakhstan. The search is
        name-based; results include position, organization, and asset data.
        """
        if not name or len(name.strip()) < 3:
            return None

        search_url = f"{RUPEP_BASE}/en/person"
        params = {"search": name.strip()}

        r = self._get(search_url, params=params, source="rupep")
        if r is None:
            return None

        if r.status_code == 200:
            try:
                text = r.text
                # rupep.org returns HTML; extract person records via regex
                # Look for person cards in the search results
                persons = []
                # Pattern: person name + position + organization blocks
                person_blocks = re.findall(
                    r'class="person-name"[^>]*>([^<]+)</.*?'
                    r'class="person-position"[^>]*>([^<]*)</.*?'
                    r'class="person-org"[^>]*>([^<]*)',
                    text, re.S,
                )
                for pname, position, org in person_blocks[:10]:
                    persons.append({
                        "name": _strip_html(pname, 200),
                        "position": _strip_html(position, 200),
                        "organization": _strip_html(org, 200),
                        "country": country,
                    })

                return {
                    "query": name,
                    "country": country,
                    "persons": persons,
                    "source": "rupep.org",
                    "url": f"{RUPEP_BASE}/en/person?search={_url_quote(name)}",
                }
            except Exception as e:
                self._note(f"rupep: response parse failed: {e}")
                return None
        else:
            self._note(f"rupep: HTTP {r.status_code}")
            return None

    # ── Public Procurement (zakupki.gov.ru) ──────────────────────────────────

    def search_procurement(self, inn: str) -> Optional[Dict[str, Any]]:
        """Search public procurement portal by supplier INN.

        Returns contracts where the entity participated as a supplier.
        """
        if not inn:
            return None

        # zakupki.gov.ru has a REST API for contract search
        search_url = f"{ZAKUPKI_BASE}/rest/api/contract/search"
        payload = {
            "supplierINN": inn,
            "pageNumber": 1,
            "pageSize": 20,
            "sortDirection": "DESC",
            "orderBy": "PUBLISH_DATE",
        }

        r = self._post(search_url, json_data=payload,
                        headers={"Content-Type": "application/json"},
                        source="procurement")
        if r is None:
            return None

        if r.status_code == 200:
            try:
                data = r.json()
                contracts = []
                for c in (data.get("contracts") or data.get("data") or [])[:20]:
                    contracts.append({
                        "contract_number": c.get("contractNumber", ""),
                        "publish_date": c.get("publishDate", ""),
                        "initial_price": c.get("initialPrice", ""),
                        "price": c.get("price", ""),
                        "subject": _strip_html(c.get("subject", ""), 300),
                        "customer_name": c.get("customerName", ""),
                        "status": c.get("status", ""),
                    })
                return {
                    "inn": inn,
                    "contracts": contracts,
                    "total": data.get("total", len(contracts)),
                    "source": "zakupki.gov.ru",
                }
            except Exception as e:
                self._note(f"procurement: response parse failed: {e}")
                return None
        else:
            self._note(f"procurement: HTTP {r.status_code}")
            return None

    # ── Arbitration Courts (kad.arbitr.ru) ───────────────────────────────────

    def search_courts(self, name: str) -> Optional[Dict[str, Any]]:
        """Search arbitration court cases by party name.

        Returns case filings where the entity is a plaintiff or defendant.
        """
        if not name or len(name.strip()) < 3:
            return None

        search_url = f"{KAD_BASE}/api/search"
        params = {"q": name.strip(), "page": 1, "count": 20}

        r = self._get(search_url, params=params, source="courts")
        if r is None:
            return None

        if r.status_code == 200:
            try:
                data = r.json()
                cases = []
                for case in (data.get("results") or data.get("items") or [])[:20]:
                    cases.append({
                        "case_number": case.get("caseNumber", case.get("number", "")),
                        "date": case.get("date", ""),
                        "court": case.get("court", ""),
                        "plaintiff": case.get("plaintiff", ""),
                        "defendant": case.get("defendant", ""),
                        "subject": _strip_html(case.get("subject", ""), 300),
                        "status": case.get("status", ""),
                    })
                return {
                    "query": name,
                    "cases": cases,
                    "total": data.get("total", len(cases)),
                    "source": "kad.arbitr.ru",
                }
            except Exception as e:
                self._note(f"courts: response parse failed: {e}")
                return None
        else:
            self._note(f"courts: HTTP {r.status_code}")
            return None

    # ── Bailiff Service (fssp.gov.ru) ────────────────────────────────────────

    def search_bailiffs(self, name: str) -> Optional[Dict[str, Any]]:
        """Search Federal Bailiff Service for enforcement proceedings.

        Returns outstanding debts and legal enforcement actions.
        """
        if not name or len(name.strip()) < 3:
            return None

        # fssp.gov.ru has a public search interface
        search_url = f"{FSSP_BASE}/search"
        params = {"term": name.strip(), "type": "person"}

        r = self._get(search_url, params=params, source="bailiffs")
        if r is None:
            return None

        if r.status_code == 200:
            try:
                text = r.text
                proceedings = []
                # Parse enforcement proceeding records from HTML
                proc_blocks = re.findall(
                    r'class="proceeding"[^>]*>.*?'
                    r'class="proc-number"[^>]*>([^<]+).*?'
                    r'class="proc-amount"[^>]*>([^<]+).*?'
                    r'class="proc-reason"[^>]*>([^<]+)',
                    text, re.S,
                )
                for num, amount, reason in proc_blocks[:20]:
                    proceedings.append({
                        "number": _strip_html(num, 100),
                        "amount": _strip_html(amount, 100),
                        "reason": _strip_html(reason, 300),
                    })
                return {
                    "query": name,
                    "proceedings": proceedings,
                    "source": "fssp.gov.ru",
                }
            except Exception as e:
                self._note(f"bailiffs: response parse failed: {e}")
                return None
        else:
            self._note(f"bailiffs: HTTP {r.status_code}")
            return None

    # ── Aggregate query ──────────────────────────────────────────────────────

    def query_all(
        self,
        inn: str = "",
        ogrn: str = "",
        company_name: str = "",
        person_name: str = "",
    ) -> Dict[str, Any]:
        """Run all applicable sources for the given identifiers.

        INN/OGRN → EGRUL + procurement
        Company name → EGRUL + courts
        Person name → rupep + bailiffs + courts

        Returns a dict with per-source results.
        """
        if inn and self.validate_inn(inn):
            self.results["egrul"] = self.get_egrul_by_inn(inn)
            if not self.budget_exhausted():
                self.results["procurement"] = self.search_procurement(inn)

        if ogrn and self.validate_ogrn(ogrn) and not self.results.get("egrul"):
            self.results["egrul"] = self.search_egrul(ogrn)

        if company_name and not self.results.get("egrul"):
            self.results["egrul"] = self.search_egrul(company_name)
            if not self.budget_exhausted():
                self.results["courts"] = self.search_courts(company_name)

        if person_name:
            self.results["rupep"] = self.search_rupep(person_name)
            if not self.budget_exhausted():
                self.results["bailiffs"] = self.search_bailiffs(person_name)
            if not self.budget_exhausted():
                self.results["courts"] = self.search_courts(person_name)

        return {
            "results": self.results,
            "errors": self.errors,
            "requests_made": self._requests_made,
            "elapsed_seconds": round(time.time() - self._started, 2),
        }
