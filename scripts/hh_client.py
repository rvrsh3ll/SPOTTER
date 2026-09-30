#!/usr/bin/env python3
"""
hh_client.py — HeadHunter (hh.ru) employer / vacancy retriever for SPOTTER.

WHAT IT IS FOR
--------------
hh.ru is Russia's dominant job board. For an RU-region engagement it is the
richest single public source of *organizational* intelligence about a target
company: legal name, industries, described business, registered site, HQ and
branch addresses, subsidiary and sibling brands, internal department names, the
shape of the org chart implied by what it is hiring for, the tech stack named in
its own vacancy text, and -- when the employer chooses to publish them --
recruiter names and phone numbers.

WF13's `org` source drives this. Nothing else imports it yet.

TWO TRANSPORTS, ONE SHAPE
-------------------------
The documented REST API at api.hh.ru is NOT anonymous for anything useful.
Verified 2026-09-19 from this host:

    GET /areas          200      GET /employers        403 {"type":"forbidden"}
    GET /industries     200      GET /employers/{id}   403 {"type":"forbidden"}
    GET /dictionaries   200      GET /vacancies        403 {"type":"forbidden"}

The 403 is not an IP block and not a malformed User-Agent -- it persists with a
correctly formed `HH-User-Agent: <app> (<email>)`. Those endpoints carry the "client"
badge in hh.ru's own docs, meaning they require an *application* token minted
from a client_id/client_secret registered at https://dev.hh.ru/admin.

The public web pages, meanwhile, answer 200 and embed their entire server-side
state as JSON in a hidden template element:

    <template style="display:none" id="HH-Lux-InitialState"> {...} </template>

That blob carries strictly more than the API does for our purposes (the API's
employer record has no department names and no address list at all), so scraping
is the default rather than the fallback-of-shame. When an app credential IS
configured we prefer the API: it is stable, it is rate-limit-documented, and it
does not depend on an undocumented template id that hh.ru can rename without
notice. `mode='auto'` picks; both paths return the SAME normalized dicts so no
caller ever branches on transport.

OPSEC
-----
Every request here tells a Russian job board which company we are interested in.
The caller is expected to pass `proxy_url` and `user_agent` from the campaign's
Infrastructure envelope. If a proxy is configured and unreachable this client
FAILS CLOSED -- it never silently retries direct. See `_get`.

BUDGET
------
Employer and vacancy pages are 0.85-3.2 MB each. A naive "fetch every vacancy"
walk on a large employer is hundreds of megabytes and several minutes inside an
n8n code node that has a task timeout. Every public method is capped, and the
client also enforces a whole-session request count and wall-clock ceiling.

SANDBOX CONSTRAINTS
-------------------
This module runs inside the n8n Python task runner, which scans imports
statically against N8N_RUNNERS_EXTERNAL_ALLOW. `requests` is allowed; bs4,
lxml and html5lib are not, and a try/except around the import does not help --
the node is killed before line 1. Parsing is therefore stdlib `re` + `json` +
`html`, which is sufficient because the payload is JSON, not markup.

Environment:
    HH_MODE                  auto | api | scrape          (default: auto)
    HH_APP_TOKEN             pre-minted application token, skips /token
    HH_CLIENT_ID             from https://dev.hh.ru/admin
    HH_CLIENT_SECRET         from https://dev.hh.ru/admin
    HH_USER_AGENT            value for the API's mandatory HH-User-Agent header
    HH_TIMEOUT               per-request seconds           (default: 20)
    HH_MAX_EMPLOYERS         employer-search results kept  (default: 25)
    HH_MAX_VACANCIES         vacancies listed per employer (default: 100)
    HH_MAX_VACANCY_DETAILS   vacancy detail pages fetched  (default: 15)
"""

from __future__ import annotations

import html as _html
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

# The shared, Cyrillic-aware company matcher. hh.ru is the provider that needs
# it most: its employer search matches DESCRIPTION text as well as names, so a
# query about a target's industry returns organisations that merely write about
# that industry. Deciding which of them IS the target is not this module's
# judgement to make alone -- employment_evidence owns that comparison, the same
# way it owns the employer-claim comparison serp_client delegates to it.
import employment_evidence

API_BASE = "https://api.hh.ru"
WEB_BASE = "https://hh.ru"

# The state blob's element id. hh.ru has renamed this before (it was
# "HH-Lego-InitialState"), so both spellings are accepted and a miss is reported
# as a named error rather than an empty result -- "no data" and "they renamed the
# template again" must not look the same to an operator.
_STATE_RE = re.compile(
    r'<template[^>]*id="(?:HH-Lux-InitialState|HH-Lego-InitialState)"[^>]*>(.*?)</template>',
    re.S,
)

# A browser UA. hh.ru serves the state blob only to something that looks like a
# browser; a bare python-requests UA gets a different, blob-less page.
_DEFAULT_WEB_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
# The API's HH-User-Agent is NOT a normal User-Agent string and hh.ru validates
# its shape: it must be "<application name> (<developer contact email>)", e.g.
#   HH-User-Agent: SPOTTER (recon@example.org)
# Anything else -- including a browser UA, or an app name with no parenthesised
# email -- is rejected with HTTP 400 before the Bearer token is even considered,
# so a malformed value looks like a broken integration rather than a config typo.
#
# There is deliberately NO default. A fabricated contact address would be a lie
# told to a third party on the operator's behalf, and hardcoding the operator's
# real address would leak it to a Russian job board on every run without anyone
# choosing that. API mode therefore refuses to start until HH_USER_AGENT is set;
# the scrape path does not use it and is unaffected.
_HH_UA_RE = re.compile(r"^\S.*\(\s*[^@\s()]+@[^@\s()]+\.[^@\s()]+\s*\)\s*$")

_DEFAULT_TIMEOUT = 20
_DEFAULT_MAX_BYTES = 6 * 1024 * 1024      # one page; the largest seen was 3.2 MB
_DEFAULT_MAX_REQUESTS = 40
_DEFAULT_MAX_SECONDS = 120


class HHError(Exception):
    """A request-level failure the caller should record, not raise through."""


def _as_int(v: Any) -> Optional[int]:
    try:
        return int(str(v).strip())
    except Exception:
        return None


def _strip_html(s: Any, limit: int = 1200) -> str:
    """hh.ru descriptions are HTML. Flatten to text for storage and display."""
    if not s:
        return ""
    txt = re.sub(r"<br\s*/?>|</p>|</li>", "\n", str(s), flags=re.I)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = _html.unescape(txt)
    txt = re.sub(r"[ \t\u00a0]+", " ", txt)   # \u00a0 spelled out: a literal nbsp here is invisible
    txt = re.sub(r"\n\s*\n+", "\n", txt).strip()
    return txt[:limit]


def _first(d: Any, *keys: str) -> Any:
    """hh.ru's blob mixes bare and @-prefixed keys for the same field."""
    if not isinstance(d, dict):
        return None
    for k in keys:
        if d.get(k) not in (None, "", [], {}):
            return d[k]
        at = "@" + k
        if d.get(at) not in (None, "", [], {}):
            return d[at]
    return None


class HHClient:
    def __init__(
        self,
        mode: Optional[str] = None,
        proxy_url: str = "",
        user_agent: str = "",
        timeout: Optional[int] = None,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        max_requests: int = _DEFAULT_MAX_REQUESTS,
        max_seconds: int = _DEFAULT_MAX_SECONDS,
        app_token: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        api_user_agent: Optional[str] = None,
        max_employers: Optional[int] = None,
    ):
        self.app_token = (app_token if app_token is not None
                          else os.environ.get("HH_APP_TOKEN", "")).strip()
        self.client_id = (client_id if client_id is not None
                          else os.environ.get("HH_CLIENT_ID", "")).strip()
        self.client_secret = (client_secret if client_secret is not None
                              else os.environ.get("HH_CLIENT_SECRET", "")).strip()

        requested = (mode or os.environ.get("HH_MODE", "auto") or "auto").strip().lower()
        if requested not in ("auto", "api", "scrape"):
            requested = "auto"
        self.requested_mode = requested
        self.mode = self._resolve_mode(requested)

        self.proxy_url = (proxy_url or "").strip()
        self.proxies = (
            {"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None
        )
        # The operator's opsec UA wins on the scrape path only if they set one;
        # the API path has its own mandatory header with a different format.
        self.user_agent = (user_agent or "").strip()
        self.api_user_agent = (api_user_agent if api_user_agent is not None
                               else os.environ.get("HH_USER_AGENT", "")).strip()

        self.timeout = timeout or _as_int(os.environ.get("HH_TIMEOUT")) or _DEFAULT_TIMEOUT
        self.max_employers = (max_employers
                              or _as_int(os.environ.get("HH_MAX_EMPLOYERS")) or 25)
        self.max_bytes = max_bytes
        self.max_requests = max_requests
        self.max_seconds = max_seconds

        self.errors: List[str] = []
        self._requests_made = 0
        self._started = time.time()
        self._token: str = ""

    # ── mode ──────────────────────────────────────────────────────────────────

    def _has_credential(self) -> bool:
        return bool(self.app_token or (self.client_id and self.client_secret))

    def _resolve_mode(self, requested: str) -> str:
        if requested == "api":
            return "api"
        if requested == "scrape":
            return "scrape"
        return "api" if self._has_credential() else "scrape"

    @property
    def source_label(self) -> str:
        """What the UI should say this run's data came from."""
        return "hh.ru-api" if self.mode == "api" else "hh.ru-scrape"

    # ── budget + transport ────────────────────────────────────────────────────

    def budget_exhausted(self) -> bool:
        return (
            self._requests_made >= self.max_requests
            or (time.time() - self._started) >= self.max_seconds
        )

    def _note(self, msg: str) -> None:
        if msg not in self.errors:
            self.errors.append(msg)

    def _get(self, url: str, headers: Dict[str, str], params: Optional[dict] = None) -> requests.Response:
        """One HTTP GET, budgeted, proxied, and fail-closed on proxy failure."""
        if self.budget_exhausted():
            raise HHError("hh.ru budget exhausted (request or time cap reached)")
        self._requests_made += 1
        try:
            r = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=self.timeout,
                proxies=self.proxies,
                allow_redirects=True,
                stream=True,
            )
        except requests.exceptions.ProxyError as e:
            # Deliberately not retried without the proxy. A campaign that asked
            # for proxied egress must not leak a direct request to a Russian job
            # board because the proxy happened to be down.
            raise HHError("hh.ru proxy unreachable; refusing to fall back to direct egress: %s" % e)
        except Exception as e:
            raise HHError("hh.ru request failed (%s): %s" % (url, e))

        # Pages are megabytes. Read a bounded prefix rather than the whole body.
        body = b""
        try:
            for chunk in r.iter_content(64 * 1024):
                body += chunk
                if len(body) >= self.max_bytes:
                    # Slice, not just break: breaking at chunk granularity means
                    # a 64 KB chunk can overshoot the cap by almost its whole
                    # size, so the cap would be advisory rather than a bound.
                    body = body[: self.max_bytes]
                    break
        finally:
            r.close()
        r._content = body          # noqa: SLF001 - make .text/.json() see the prefix
        r._content_consumed = True  # noqa: SLF001
        return r

    # ── API transport ─────────────────────────────────────────────────────────

    def _api_ua(self) -> str:
        """The mandatory HH-User-Agent, validated before it can cause a 400.

        hh.ru answers 400 for a malformed value regardless of the Bearer token,
        so checking the shape here turns "the integration is broken" into one
        sentence naming the variable and the format.
        """
        ua = self.api_user_agent
        if not ua:
            raise HHError(
                "hh.ru API mode requires HH_USER_AGENT in the form "
                "'AppName (contact@email)' — hh.ru rejects the request with "
                "HTTP 400 without it. Unset HH_CLIENT_ID/HH_APP_TOKEN, or set "
                "HH_MODE=scrape, to use the public pages instead."
            )
        if not _HH_UA_RE.match(ua):
            raise HHError(
                "HH_USER_AGENT=%r is not in hh.ru's required form "
                "'AppName (contact@email)' — the API answers HTTP 400 for "
                "anything else, including a browser User-Agent." % ua[:120]
            )
        return ua

    def _ensure_token(self) -> str:
        if self._token:
            return self._token
        if self.app_token:
            self._token = self.app_token
            return self._token
        if not (self.client_id and self.client_secret):
            raise HHError("hh.ru API mode requires HH_APP_TOKEN or HH_CLIENT_ID+HH_CLIENT_SECRET")
        self._requests_made += 1
        try:
            r = requests.post(
                "%s/token" % API_BASE,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                headers={"HH-User-Agent": self._api_ua()},
                timeout=self.timeout,
                proxies=self.proxies,
            )
        except requests.exceptions.ProxyError as e:
            raise HHError("hh.ru proxy unreachable during token mint: %s" % e)
        except Exception as e:
            raise HHError("hh.ru token request failed: %s" % e)
        if not r.ok:
            raise HHError("hh.ru token request rejected (HTTP %s)" % r.status_code)
        tok = (r.json() or {}).get("access_token")
        if not tok:
            raise HHError("hh.ru token response carried no access_token")
        self._token = str(tok)
        return self._token

    def _api(self, path: str, params: Optional[dict] = None) -> dict:
        headers = {
            "Authorization": "Bearer %s" % self._ensure_token(),
            # Mandatory on every employer/vacancy call; the request is rejected
            # without it even when the Bearer token is valid.
            "HH-User-Agent": self._api_ua(),
            "Accept": "application/json",
        }
        r = self._get("%s%s" % (API_BASE, path), headers, params)
        if r.status_code == 403:
            raise HHError(
                "hh.ru API returned 403 for %s — the application token is missing, "
                "revoked, or lacks this scope" % path
            )
        if not r.ok:
            raise HHError("hh.ru API %s returned HTTP %s" % (path, r.status_code))
        try:
            return r.json() or {}
        except Exception as e:
            raise HHError("hh.ru API %s returned unparseable JSON: %s" % (path, e))

    # ── scrape transport ──────────────────────────────────────────────────────

    def _page_state(self, path: str, params: Optional[dict] = None) -> dict:
        headers = {
            "User-Agent": self.user_agent or _DEFAULT_WEB_UA,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
        }
        r = self._get("%s%s" % (WEB_BASE, path), headers, params)
        if not r.ok:
            raise HHError("hh.ru page %s returned HTTP %s" % (path, r.status_code))
        m = _STATE_RE.search(r.text or "")
        if not m:
            raise HHError(
                "hh.ru page %s carried no HH-Lux-InitialState blob — the page layout "
                "changed, or the request was served a captcha/interstitial" % path
            )
        try:
            return json.loads(_html.unescape(m.group(1))) or {}
        except Exception as e:
            raise HHError("hh.ru state blob on %s did not parse: %s" % (path, e))

    # ── public: employer search ───────────────────────────────────────────────

    def search_employers(self, name: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Employers whose name or description matches `name`.

        The result doubles as the subsidiary/sibling-brand list: a query for a
        holding company returns its per-brand legal entities as separate
        employers (e.g. "Ромашка", "Ромашка.Доставка", "Ромашка.Еда"), which is
        exactly the partner-company signal the Organization card wants.
        """
        cap = limit or self.max_employers
        name = (name or "").strip()
        if not name:
            return []
        if self.mode == "api":
            data = self._api("/employers", {"text": name, "per_page": min(cap, 100)})
            rows = data.get("items") or []
            out = []
            for it in rows[:cap]:
                out.append({
                    "id": str(_first(it, "id") or ""),
                    "name": str(_first(it, "name") or ""),
                    "vacancies_open": _as_int(_first(it, "open_vacancies")),
                    "url": str(_first(it, "alternate_url") or ""),
                })
            return [r for r in out if r["name"]]

        # /search/employer and /employers are both 404 on the web site;
        # /employers_list?query= is the real one.
        state = self._page_state("/employers_list", {"query": name})
        bucket = state.get("employersList") or {}
        grouped = bucket.get("employers") or {}
        flat: List[dict] = []
        if isinstance(grouped, dict):
            # Keyed by first letter of the name.
            for _letter, rows in grouped.items():
                if isinstance(rows, list):
                    flat.extend(rows)
        elif isinstance(grouped, list):
            flat = grouped
        out = []
        for it in flat[:cap]:
            eid = _as_int(_first(it, "id"))
            nm = str(_first(it, "name") or "")
            if not (eid and nm):
                continue
            out.append({
                "id": str(eid),
                "name": nm,
                "vacancies_open": _as_int(_first(it, "vacanciesOpen")),
                "url": "%s/employer/%s" % (WEB_BASE, eid),
            })
        return out

    # ── public: employer profile ──────────────────────────────────────────────

    def get_employer(self, employer_id: Any) -> Dict[str, Any]:
        eid = str(employer_id or "").strip()
        if not eid:
            return {}
        if self.mode == "api":
            d = self._api("/employers/%s" % eid)
            area = d.get("area") or {}
            return {
                "id": str(d.get("id") or eid),
                "name": str(d.get("name") or ""),
                "industries": [str(i.get("name") or "") for i in (d.get("industries") or []) if isinstance(i, dict)],
                "description": _strip_html(d.get("description")),
                "site": str(d.get("site_url") or ""),
                "area": str(area.get("name") or "") if isinstance(area, dict) else "",
                "address": "",
                "country": str(d.get("country_code") or ""),
                "size_category": "",
                "it_accredited": bool(d.get("accredited_it_employer")),
                "trusted": bool(d.get("trusted")),
                "has_divisions": False,
                "rating": None,
                "logo_url": str((d.get("logo_urls") or {}).get("original") or "") if isinstance(d.get("logo_urls"), dict) else "",
                "open_vacancies": _as_int(d.get("open_vacancies")),
                "profile_url": str(d.get("alternate_url") or "%s/employer/%s" % (WEB_BASE, eid)),
            }

        state = self._page_state("/employer/%s" % eid)
        info = state.get("employerInfo") or {}
        schema = state.get("employerOrganizationSchema") or {}
        area = info.get("area") or {}
        rating = None
        agg = schema.get("aggregateRating") or {}
        if isinstance(agg, dict):
            try:
                rating = float(agg.get("ratingValue"))
            except Exception:
                rating = None
        industries = []
        for i in (info.get("industries") or []):
            if isinstance(i, dict):
                nm = _first(i, "trl", "name")
                if nm:
                    industries.append(str(nm))
        return {
            "id": str(_first(info, "id") or eid),
            "name": str(_first(info, "name") or ""),
            "industries": industries,
            "description": _strip_html(info.get("description")),
            "site": str(_first(info, "site") or schema.get("siteUrl") or ""),
            "area": str(_first(area, "name") or "") if isinstance(area, dict) else "",
            "address": _strip_html(info.get("address"), 300) if not isinstance(info.get("address"), dict)
                       else str(_first(info.get("address"), "rawAddress", "raw") or ""),
            "country": str(_first(info, "employerCountryCode") or ""),
            "size_category": str(_first(info, "sizeCategory") or ""),
            "it_accredited": bool(_first(info, "accreditedITEmployer")),
            "trusted": bool(_first(info, "isTrusted")),
            # The signal that this employer is a holding with sub-entities --
            # the cue to trust the sibling list from search_employers().
            "has_divisions": bool(_first(info, "hasDivisions")
                                  or state.get("employerHasHoldingOrDepartments")),
            "rating": rating,
            "logo_url": str(schema.get("logoUrl") or ""),
            "open_vacancies": _as_int(state.get("activeEmployerVacancyCount")),
            "profile_url": "%s/employer/%s" % (WEB_BASE, eid),
        }

    # ── public: vacancy list ──────────────────────────────────────────────────

    def list_vacancies(self, employer_id: Any, cap: Optional[int] = None) -> List[Dict[str, Any]]:
        eid = str(employer_id or "").strip()
        if not eid:
            return []
        cap = cap or _as_int(os.environ.get("HH_MAX_VACANCIES")) or 100
        out: List[Dict[str, Any]] = []

        if self.mode == "api":
            page, per = 0, min(cap, 100)
            while len(out) < cap and not self.budget_exhausted():
                d = self._api("/vacancies", {"employer_id": eid, "per_page": per, "page": page})
                items = d.get("items") or []
                if not items:
                    break
                for it in items:
                    out.append(self._norm_vacancy_api(it))
                    if len(out) >= cap:
                        break
                if page + 1 >= (_as_int(d.get("pages")) or 1):
                    break
                page += 1
            return out

        page = 0
        while len(out) < cap and not self.budget_exhausted():
            state = self._page_state(
                "/search/vacancy",
                {"employer_id": eid, "page": page, "items_on_page": 100},
            )
            res = state.get("vacancySearchResult") or {}
            items = res.get("vacancies") or []
            if not items:
                break
            for it in items:
                out.append(self._norm_vacancy_web(it))
                if len(out) >= cap:
                    break
            paging = res.get("paging") or {}
            if not (isinstance(paging, dict) and paging.get("next")):
                break
            page += 1
        return out

    @staticmethod
    def _norm_vacancy_api(it: dict) -> Dict[str, Any]:
        dept = it.get("department") or {}
        addr = it.get("address") or {}
        area = it.get("area") or {}
        return {
            "id": str(it.get("id") or ""),
            "title": str(it.get("name") or ""),
            "department": str(dept.get("name") or "") if isinstance(dept, dict) else "",
            "division": "",
            "area": str(area.get("name") or "") if isinstance(area, dict) else "",
            "address": HHClient._norm_address(addr),
            "roles": [str(r.get("name") or "") for r in (it.get("professional_roles") or []) if isinstance(r, dict)],
            "experience": str((it.get("experience") or {}).get("name") or "") if isinstance(it.get("experience"), dict) else "",
            "url": str(it.get("alternate_url") or ""),
        }

    @staticmethod
    def _norm_vacancy_web(it: dict) -> Dict[str, Any]:
        # The department is nested under `company`, NOT at the vacancy top level.
        # The top-level `department` key exists but is null on every row; reading
        # it yields a card with an empty org-structure block and no error, which
        # is exactly the kind of quiet nothing that reads as "this company has no
        # divisions". The real value looks like
        # {"@name": "Финтех", "@code": "romashka-100001-finteh"}.
        company = it.get("company") or {}
        dept = it.get("department") or (company.get("department") if isinstance(company, dict) else None) or {}
        area = it.get("area") or {}
        links = it.get("links") or {}
        vid = _first(it, "vacancyId", "id")
        role_ids: List[str] = []
        for blk in (it.get("professionalRoleIds") or []):
            if isinstance(blk, dict):
                role_ids += [str(x) for x in (blk.get("professionalRoleId") or [])]
            else:
                role_ids.append(str(blk))
        div = it.get("division") or {}
        return {
            "id": str(vid or ""),
            "title": str(_first(it, "name") or ""),
            "department": str(_first(dept, "name") or "") if isinstance(dept, dict) else "",
            "division": str(_first(div, "id") or "") if isinstance(div, dict) else str(div or ""),
            "area": str(_first(area, "name") or "") if isinstance(area, dict) else "",
            "address": HHClient._norm_address(it.get("address") or {}),
            # Web search returns role IDs, not names; the names come off the
            # detail page or the /professional_roles dictionary. The title is the
            # useful signal either way, so this stays as ids rather than pretending.
            "roles": role_ids,
            "experience": str(_first(it, "workExperience") or ""),
            "url": str(links.get("desktop") or ("%s/vacancy/%s" % (WEB_BASE, vid) if vid else "")),
        }

    # ── public: search facets (scrape only) ───────────────────────────────────

    def vacancy_facets(self, employer_id: Any) -> Dict[str, List[Dict[str, Any]]]:
        """Role / area / industry histograms across ALL of an employer's vacancies.

        hh.ru's search page ships the facet counts for the *whole* result set in
        `searchClusters`, so one request describes an employer with 1000 openings
        as accurately as one with 10 -- where aggregating the vacancy rows we
        actually fetched would describe only the first page and silently
        under-report everything after the cap.

        Scrape-only: the API exposes clusters too, but behind the same 403 as
        everything else, and the caller already has the vacancy rows in API mode.
        """
        eid = str(employer_id or "").strip()
        if not eid or self.mode == "api":
            return {}
        state = self._page_state(
            "/search/vacancy", {"employer_id": eid, "items_on_page": 20}
        )
        clusters = state.get("searchClusters") or {}
        out: Dict[str, List[Dict[str, Any]]] = {}
        for key, name in (("professional_role", "roles"),
                          ("area", "areas"),
                          ("industry", "industries"),
                          ("experience", "experience")):
            groups = (clusters.get(key) or {}).get("groups") or {}
            rows = []
            for g in groups.values():
                if not isinstance(g, dict):
                    continue
                title = str(g.get("title") or "")
                if not title:
                    continue
                rows.append({"name": title, "count": _as_int(g.get("count")) or 0})
            rows.sort(key=lambda r: (-r["count"], r["name"]))
            if rows:
                out[name] = rows
        return out

    @staticmethod
    def _norm_address(addr: Any) -> Dict[str, Any]:
        if not isinstance(addr, dict) or not addr:
            return {}
        city = _first(addr, "city")
        street = _first(addr, "street")
        building = _first(addr, "building")
        raw = _first(addr, "raw", "rawAddress", "displayName")
        metro = ""
        ms = addr.get("metroStations") or {}
        if isinstance(ms, dict):
            mlist = ms.get("metro") or []
            if isinstance(mlist, list) and mlist:
                metro = str(_first(mlist[0], "name") or "")
        label = raw or ", ".join([str(x) for x in (city, street, building) if x])
        out = {
            "city": str(city or ""),
            "street": str(street or ""),
            "building": str(building or ""),
            "metro": metro,
            "label": str(label or ""),
        }
        lat, lng = _first(addr, "lat"), _first(addr, "lng")
        if lat is not None and lng is not None:
            out["lat"], out["lng"] = lat, lng
        return out if out.get("label") or out.get("city") else {}

    # ── public: vacancy detail ────────────────────────────────────────────────

    def get_vacancy(self, vacancy_id: Any) -> Dict[str, Any]:
        """Detail page: description text, key skills, and contacts if published.

        Contacts are usually NOT published. hh.ru answers anonymous views with
        `contactInfo: {contactsHidden: true, phones: {phones: []}}` on most
        vacancies, so an empty contact list here means "withheld", not "the
        employer has no recruiters". The caller must present it that way.
        """
        vid = str(vacancy_id or "").strip()
        if not vid:
            return {}
        if self.mode == "api":
            d = self._api("/vacancies/%s" % vid)
            c = d.get("contacts") or {}
            return {
                "id": vid,
                "description": _strip_html(d.get("description"), 4000),
                "key_skills": [str(s.get("name") or "") for s in (d.get("key_skills") or []) if isinstance(s, dict)],
                "department": str((d.get("department") or {}).get("name") or "") if isinstance(d.get("department"), dict) else "",
                "contacts": self._norm_contacts(c),
            }
        state = self._page_state("/vacancy/%s" % vid)
        vv = state.get("vacancyView") or {}
        ks = vv.get("keySkills") or {}
        skills: List[str] = []
        if isinstance(ks, dict):
            skills = [str(_first(s, "name") or s) if isinstance(s, dict) else str(s)
                      for s in (ks.get("keySkill") or ks.get("keySkills") or [])]
        elif isinstance(ks, list):
            skills = [str(_first(s, "name") or s) if isinstance(s, dict) else str(s) for s in ks]
        dept = vv.get("department") or {}
        return {
            "id": vid,
            "description": _strip_html(vv.get("description"), 4000),
            "key_skills": [s for s in skills if s],
            "department": str(_first(dept, "name") or "") if isinstance(dept, dict) else "",
            "contacts": self._norm_contacts(vv.get("contactInfo") or {}),
        }

    @staticmethod
    def _norm_contacts(c: Any) -> Dict[str, Any]:
        if not isinstance(c, dict) or not c:
            return {"hidden": True, "name": "", "email": "", "phones": []}
        hidden = bool(c.get("contactsHidden"))
        phones: List[str] = []
        ph = c.get("phones") or {}
        raw_list = ph.get("phones") if isinstance(ph, dict) else ph
        for p in (raw_list or []):
            if isinstance(p, dict):
                # `number` alone is the subscriber part only ("1234567"); the
                # country and city codes are siblings. Prefer a pre-joined form,
                # and otherwise reassemble rather than storing a fragment that
                # nobody can dial and that will not match anything else.
                num = _first(p, "raw", "formatted")
                if not num:
                    parts = [_first(p, "country"), _first(p, "city"), _first(p, "number")]
                    num = "".join(str(x) for x in parts if x)
                if num:
                    phones.append(str(num))
            elif p:
                phones.append(str(p))
        name = _first(c, "fio", "name") or ""
        email = _first(c, "email") or ""
        return {
            "hidden": hidden or not (phones or name or email),
            "name": str(name),
            "email": str(email),
            "phones": phones,
        }

    # ── public: the whole profile in one call ─────────────────────────────────

    def organization_profile(
        self,
        company_name: str,
        max_vacancies: Optional[int] = None,
        max_details: Optional[int] = None,
        identity: Optional[Dict[str, Any]] = None,
        match_min: Optional[int] = None,
        max_probes: int = 2,
    ) -> Dict[str, Any]:
        """Search → EVIDENCED best match → profile → vacancies → capped details.

        Never raises: every leg records into `errors` and the partially-filled
        result is returned, so a card renders whatever was reached. Returns
        `matched: False` when the company could not be identified at all.

        `identity` is employment_evidence.build_identity() — every name and
        domain the operator gave for the target. Two things change when it is
        supplied, and both were real failures before it existed:

          * EVERY identifier is searched, not just the display name. A Russian
            company's employer record is filed under its legal entity ("ООО
            ОБРАЗЕЦ"), which no amount of matching on the trading name will find,
            but which the operator already typed into Additional Identifiers.
          * Nothing is adopted without evidence. A search that returns only
            thematically-related employers now returns `matched: False` and says
            which near miss it refused, instead of handing back whichever of
            them had the most open vacancies.

        Without it the call still works and falls back to the old name-only
        ordering, so an existing caller is not silently changed.
        """
        max_details = (max_details if max_details is not None
                       else _as_int(os.environ.get("HH_MAX_VACANCY_DETAILS")) or 15)
        ident = identity or employment_evidence.identity_from_aliases([company_name])
        terms = [t for t in (ident.get("search_terms") or ()) if t] or (
            [company_name] if (company_name or "").strip() else [])

        out: Dict[str, Any] = {
            "matched": False,
            "source": self.source_label,
            "query": company_name,
            "queries": [],
            "profile": {},
            "related": [],
            "mentions": [],
            "rejected": [],
            "match_reason": "",
            "match_evidence": [],
            "match_score": 0,
            "vacancies": [],
            "facets": {},
            "details": [],
            "errors": self.errors,
        }
        if not terms:
            self._note("hh.ru needs a company name; none was resolved")
            return out

        # ── search every identifier, keep every row ─────────────────────────
        # Pooled rather than first-hit-wins: the legal entity and the trading
        # name return overlapping but different employer sets, and the best
        # evidence can come from either.
        pool: List[Dict[str, Any]] = []
        seen_ids = set()
        for term in terms:
            if self.budget_exhausted():
                self._note("hh.ru budget exhausted before every identifier was "
                           "searched; %r and after were not tried"
                           % term)
                break
            out["queries"].append(term)
            try:
                rows = self.search_employers(term)
            except HHError as e:
                self._note(str(e))
                continue
            for row in rows:
                if row.get("id") in seen_ids:
                    continue
                seen_ids.add(row.get("id"))
                pool.append(row)

        if not pool:
            if not out["queries"]:
                # Critically different from a real miss: we never got to look.
                self._note("hh.ru budget was exhausted before any identifier was "
                           "searched, so nothing was actually looked up. This is "
                           "NOT evidence that the company is absent from hh.ru.")
            else:
                self._note("hh.ru found no employer matching %s"
                           % " / ".join(repr(t) for t in out["queries"]))
            return out

        picked = employment_evidence.pick_company(
            pool, ident, match_min=match_min,
            tie_break=lambda c: c.get("vacancies_open"))

        # ── the domain probe ────────────────────────────────────────────────
        # An employer-search row carries no website, so a candidate whose only
        # tie to the target is that it SERVES the target's domain cannot be
        # recognised from the search result alone. Rather than give that up, the
        # strongest few near misses have their profile fetched and are re-checked
        # with the site URL present. Capped, and only on the path that would
        # otherwise return nothing, so the common case costs no extra request.
        if picked["best"] is None and ident.get("domains"):
            for near in (picked.get("rejected") or [])[:max_probes]:
                if self.budget_exhausted():
                    break
                cand = next((c for c in pool if c.get("name") == near.get("name")), None)
                if not cand:
                    continue
                try:
                    prof = self.get_employer(cand["id"])
                except HHError as e:
                    self._note(str(e))
                    continue
                probe = dict(cand)
                probe["site"] = prof.get("site") or ""
                probe["description"] = prof.get("description") or ""
                verdict = employment_evidence.company_verdict(
                    probe, ident, match_min=match_min)
                if verdict["accept"]:
                    picked = {"best": probe, "verdict": verdict,
                              "units": picked["units"], "mentions": picked["mentions"],
                              "rejected": [], "reason": ""}
                    out["profile"] = prof
                    break

        out["related"] = picked["units"]
        out["mentions"] = picked["mentions"]

        if picked["best"] is None:
            out["rejected"] = picked["rejected"]
            out["match_reason"] = picked["reason"]
            self._note(
                "hh.ru returned %d employer(s) for %s but none is evidently the "
                "target — %s. Not adopted: a job board's employer search matches "
                "description text, so an unmatched top row is usually a different "
                "company in the same field."
                % (len(pool), " / ".join(repr(t) for t in terms), picked["reason"]))
            return out

        best = picked["best"]
        out["match_score"] = int((picked["verdict"] or {}).get("score") or 0)
        out["match_evidence"] = list((picked["verdict"] or {}).get("evidence") or [])

        if not out["profile"]:
            try:
                out["profile"] = self.get_employer(best["id"])
                out["matched"] = bool(out["profile"].get("name"))
            except HHError as e:
                self._note(str(e))
                out["profile"] = {
                    "id": best["id"], "name": best["name"],
                    "profile_url": best.get("url", ""),
                    "open_vacancies": best.get("vacancies_open"),
                }
                out["matched"] = True
        else:
            out["matched"] = bool(out["profile"].get("name"))

        try:
            out["vacancies"] = self.list_vacancies(best["id"], max_vacancies)
        except HHError as e:
            self._note(str(e))

        try:
            out["facets"] = self.vacancy_facets(best["id"])
        except HHError as e:
            self._note(str(e))

        for v in out["vacancies"][:max_details]:
            if self.budget_exhausted():
                self._note("hh.ru budget exhausted before all vacancy details were fetched")
                break
            try:
                d = self.get_vacancy(v["id"])
                if d:
                    d["title"] = v.get("title", "")
                    d["url"] = v.get("url", "")
                    out["details"].append(d)
            except HHError as e:
                self._note(str(e))
        return out

    @staticmethod
    def _pick_best(query: str, candidates: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Exact name wins, then prefix, then most open vacancies.

        RETAINED FOR CALLERS THAT HAVE NOTHING BUT A NAME, and deliberately no
        longer used by organization_profile(). Read its last branch before
        reusing it: when no candidate relates to the query at all, `score` is 3
        for every row and the tie-break -- most open vacancies -- decides. That
        is how a campaign against an aviation manufacturer produced a profile
        for a military-history journal: hh.ru matches description text, the
        journal wrote about drones, and it was the busiest recruiter in the set.
        A ranking is not a match test. Use employment_evidence.pick_company(),
        which refuses rather than ranks.
        """
        q = (query or "").strip().lower()

        def rank(c: Dict[str, Any]) -> Tuple[int, int]:
            nm = (c.get("name") or "").strip().lower()
            if nm == q:
                score = 0
            elif nm.startswith(q) or q.startswith(nm):
                score = 1
            elif q in nm:
                score = 2
            else:
                score = 3
            return (score, -(c.get("vacancies_open") or 0))

        ordered = sorted(candidates, key=rank)
        return ordered[0], ordered[1:]
