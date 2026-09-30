"""
adaptix_normalizer.py — Fetch and normalise Adaptix C2 agent data.

Connects to the Adaptix teamserver Web API, retrieves the agent roster, and returns
the canonical C2Session dict documented in c2_common.py, ready for ingestion into
Flowsint via flowsint_client.

Framework-agnostic pieces (process→technology inference, scoring, dedup keys) live
in c2_common.py and are shared with cobalt_normalizer.py and brc4_normalizer.py.
They are re-exported here so importers behave the same across all three.

All agent data processed here originates from an authorized red team engagement
running under documented Rules of Engagement.

Adaptix Web API reference:
  https://adaptix-framework.gitbook.io/adaptix-framework/development/teamserver-interface/web-api

Key endpoints used:
  POST /login        — {username, password} → {access_token, refresh_token, version}
  GET  /agent/list   — the full agent roster with metadata

Why this is a POLL and not a push (the opposite of Brute Ratel / workflow 21):
  Adaptix does have an outbound webhook -- EventCallback in profile.json -- but it
  fires on NEW AGENT REGISTRATION ONLY and sends a rendered message template
  ("%type% %id% %user% %computer% %internalip% %elevated% %externalip% %domain%"),
  not a check-in. A push-only integration would therefore stamp last_checkin once
  and never again, and WF23 derives live/stale/dead from last_checkin against a
  30-minute threshold -- so every agent would read `stale` half an hour after it
  landed and never recover. /agent/list returns a_last_tick on every call, which is
  the field the roster actually needs.

Two things that will waste your time if you do not know them:

  1. A FAILED LOGIN ANSWERS 404, not 401. The teamserver serves a 404 page for
     unauthenticated requests by default, so a wrong password and a wrong URL are
     indistinguishable by status code alone. Both are reported as such below.

  2. THE ENDPOINT PREFIX IS PART OF THE URL. Adaptix's profile.json sets a URI
     prefix (commonly "/endpoint") that every API route hangs off, and it is
     operator-chosen per teamserver. ADAPTIX_API_URL must include it, e.g.
     https://10.0.0.5:4321/endpoint -- not just scheme://host:port.

Environment variables:
  ADAPTIX_API_URL   — teamserver API base INCLUDING the endpoint prefix
  ADAPTIX_USERNAME  — operator account used for the poll
  ADAPTIX_PASSWORD  — that account's password (Adaptix has no static API token)
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

from c2_common import (
    DC_PATTERNS,
    HIGH_VALUE_TECH,
    PROCESS_TECH_MAP,
    TECH_CATEGORIES,
    categorize_tech_stack,
    finalize_session,
    get_high_value_tech,
    infer_tech_stack,
    is_high_value_tech,
    score_session,
    session_key,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ─────────────────────────────────────────────────────────────

ADAPTIX_API_URL  = os.environ.get("ADAPTIX_API_URL", "")
ADAPTIX_USERNAME = os.environ.get("ADAPTIX_USERNAME", "")
ADAPTIX_PASSWORD = os.environ.get("ADAPTIX_PASSWORD", "")

C2_FRAMEWORK = "adaptix"

# a_os is an enum, not a string. An unknown value maps to "" rather than a guess:
# os_version feeds the Technology inference and the operator-facing roster, and a
# wrong OS there is worse than a blank one.
_OS_NAMES = {0: "", 1: "Windows", 2: "Linux", 3: "macOS"}

# Adaptix agents reached over an SMB named pipe or a raw TCP channel are pivots
# routed through another agent. /agent/list does not document a parent-agent field,
# so the CHANNEL is inferable from the listener name but the PARENT is not -- see
# normalise_agent() for why pivot_parent is deliberately left empty.
_PIVOT_LISTENERS = ("smb", "pipe", "tcp")

# Kept as an alias for symmetry with cobalt_normalizer.score_beacon.
score_agent = score_session


# ── Adaptix Web API client ────────────────────────────────────────────────────

def _adaptix_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def login(
    base_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> str:
    """
    Authenticate against the teamserver and return an access token.

    POST /login  →  {"access_token": ..., "refresh_token": ..., "version": ...}

    No token cache: every n8n run is a fresh process with nowhere to persist one,
    and at a 5-minute poll cadence a login per run is cheaper than the /refresh
    bookkeeping would be.

    A 404 here means the credentials were rejected, NOT that the path is wrong --
    the teamserver serves its 404 page for unauthenticated requests. The message
    says so, because the two failures are otherwise indistinguishable.
    """
    url  = (base_url or ADAPTIX_API_URL).rstrip("/")
    user = username or ADAPTIX_USERNAME
    pw   = password if password is not None else ADAPTIX_PASSWORD
    if not url or not user:
        raise ValueError("ADAPTIX_API_URL and ADAPTIX_USERNAME must be set")

    s = _adaptix_session()
    resp = s.post(
        f"{url}/login",
        json={"username": user, "password": pw},
        verify=False,
        timeout=15,
    )
    if resp.status_code == 404:
        raise ValueError(
            "Adaptix login returned 404 — the teamserver answers a REJECTED LOGIN "
            "with its 404 page, so this is most likely bad credentials. If the "
            "credentials are known good, check that ADAPTIX_API_URL includes the "
            "endpoint prefix from the teamserver's profile.json (e.g. /endpoint)."
        )
    resp.raise_for_status()

    token = (resp.json() or {}).get("access_token", "")
    if not token:
        raise ValueError("Adaptix login succeeded but returned no access_token")
    return token


def fetch_agents(base_url: Optional[str] = None, token: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Fetch the full agent roster.

    GET /agent/list  (Authorization: Bearer <access_token>)

    Returns a list of raw agent dicts as returned by the API.
    """
    url = (base_url or ADAPTIX_API_URL).rstrip("/")
    if not url:
        raise ValueError("ADAPTIX_API_URL must be set")

    tok = token or login(url)

    s = _adaptix_session()
    s.headers.update({"Authorization": f"Bearer {tok}"})
    resp = s.get(f"{url}/agent/list", verify=False, timeout=15)
    if resp.status_code == 404:
        raise ValueError(
            "Adaptix /agent/list returned 404 — the access token was rejected "
            "(the teamserver 404s unauthenticated requests rather than 401ing)"
        )
    resp.raise_for_status()

    data = resp.json()
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("agents", "data", "items"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


# ── Normalisation ─────────────────────────────────────────────────────────────

def _int_or_none(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _os_version(raw: Dict[str, Any]) -> str:
    """
    Prefer the teamserver's free-text OS description; fall back to the a_os enum.

    a_os_desc carries the build ("Windows Server 2019 Build 17763"), which is what
    makes a host recognisable in the roster. a_os alone is a bare family name.
    """
    desc = str(raw.get("a_os_desc") or "").strip()
    if desc:
        return desc
    return _OS_NAMES.get(_int_or_none(raw.get("a_os")), "")


def _username(raw: Dict[str, Any]) -> str:
    """
    Build DOMAIN\\user when Adaptix reports a domain, bare username otherwise.

    finalize_session() derives sam_account_name by splitting on the backslash, and
    that sam is what the ingest workflow dedups against SharpHound-ingested
    identities. Emitting a bare "jdoe" where the AD graph holds "CORP\\jdoe" would
    still dedup correctly, but emitting "CORP\\jdoe" keeps the operator-facing
    username consistent with what every other framework reports.
    """
    user   = str(raw.get("a_username") or "").strip()
    domain = str(raw.get("a_domain") or "").strip()
    if user and domain and "\\" not in user:
        return f"{domain}\\{user}"
    return user


def _note(raw: Dict[str, Any]) -> str:
    """Fold Adaptix's operator-facing labels into the single `note` field."""
    parts: List[str] = []

    tags = raw.get("a_tags")
    if isinstance(tags, (list, tuple)):
        parts.extend(str(t).strip() for t in tags if str(t).strip())
    elif str(tags or "").strip():
        parts.append(str(tags).strip())

    mark = str(raw.get("a_mark") or "").strip()
    if mark:
        parts.append(mark)

    imp = str(raw.get("a_impersonated") or "").strip()
    if imp:
        parts.append(f"impersonating {imp}")

    return " · ".join(parts)


def normalise_agent(raw: Dict[str, Any], ts_server: str = "") -> Dict[str, Any]:
    """
    Normalise one raw Adaptix agent dict into SPOTTER's canonical C2Session format.

    Adaptix field mapping (every key is a_-prefixed; the API is stable enough not to
    need cobalt_normalizer's paired .get() fallbacks):
      a_id                     → session_id
      a_computer               → hostname
      a_domain + a_username    → username  (DOMAIN\\user)
      a_internal_ip            → internal_ip
      a_external_ip            → external_ip
      a_os / a_os_desc         → os_version
      a_arch                   → arch
      a_pid / a_tid            → pid / thread_id
      a_process                → process_name
      a_elevated               → is_admin   (tri-state, see below)
      a_last_tick              → last_checkin  (unix epoch seconds)
      a_sleep / a_jitter       → sleep_seconds / jitter_pct
      a_listener               → listener
      a_tags/a_mark/a_impersonated → note
    """
    # a_last_tick is a unix epoch, so Adaptix has none of Brute Ratel's timezone
    # ambiguity -- there is no ADAPTIX_*_TZ_OFFSET knob and none is needed.
    last_checkin_dt: Optional[datetime] = None
    last_ts = _int_or_none(raw.get("a_last_tick"))
    if last_ts:
        try:
            last_checkin_dt = datetime.fromtimestamp(last_ts, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            pass

    # Tri-state, and the absence of the key is the third state. WF23's _tri() and
    # the AGENTS tab treat None as UNKNOWN, which is a different claim from a
    # confirmed non-admin -- never coerce a missing a_elevated to False.
    is_admin: Optional[bool] = None
    if raw.get("a_elevated") is not None:
        is_admin = bool(raw["a_elevated"])

    # Pivot channel is inferable from the listener; the PARENT is not. /agent/list
    # carries no documented parent-agent field, and guessing one would create a
    # PIVOTS_TO edge between two agents that may have no relationship at all. So
    # the channel is recorded, pivot_parent is left empty, and WF28 skips the edge
    # rather than inventing it. Revisit if a live teamserver turns out to expose a
    # parent id -- this heuristic is unconfirmed against one.
    listener = str(raw.get("a_listener") or "").strip()
    lowered  = listener.lower()
    channel  = next((c for c in _PIVOT_LISTENERS if c in lowered), "")

    normalised = {
        "c2_framework":    C2_FRAMEWORK,
        "session_id":      str(raw.get("a_id", "")),
        "c2_server":       ts_server or ADAPTIX_API_URL,
        "hostname":        str(raw.get("a_computer") or "").strip(),
        "username":        _username(raw),
        "internal_ip":     str(raw.get("a_internal_ip") or "").strip(),
        "external_ip":     str(raw.get("a_external_ip") or "").strip(),
        "os_version":      _os_version(raw),
        "arch":            str(raw.get("a_arch") or "").strip(),
        "pid":             _int_or_none(raw.get("a_pid")),
        "thread_id":       _int_or_none(raw.get("a_tid")),
        "process_name":    str(raw.get("a_process") or "").strip(),
        "is_admin":        is_admin,
        "last_checkin":    last_checkin_dt.isoformat() if last_checkin_dt else None,
        "last_checkin_dt": last_checkin_dt,
        "sleep_seconds":   _int_or_none(raw.get("a_sleep")),
        "jitter_pct":      _int_or_none(raw.get("a_jitter")),
        "listener":        listener,
        "note":            _note(raw),
        # /agent/list carries no process list -- that only arrives from a `ps`
        # task, exactly as with Cobalt Strike's /beacons. tech_stack is therefore
        # empty until one runs, and the upsert must not patch this empty list over
        # enrichment that a later task produced.
        "process_list":    [],
        "is_dead":         False,
        "is_pivot":        bool(channel),
        "pivot_parent":    "",
        "pivot_channel":   channel,
        # Retained for consumers that predate the C2Session generalisation.
        "source":          C2_FRAMEWORK,
    }
    # sam_account_name, tech_stack, session_key and priority_score are derived.
    return finalize_session(normalised)


def fetch_and_normalise(
    base_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Convenience wrapper: log in, fetch every agent and return normalised dicts,
    sorted by priority_score descending.
    """
    url   = (base_url or ADAPTIX_API_URL).rstrip("/")
    token = login(url, username, password)
    raw_agents = fetch_agents(url, token)
    normalised = [normalise_agent(a, url) for a in raw_agents if isinstance(a, dict)]
    return sorted(normalised, key=lambda a: a["priority_score"], reverse=True)


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json as _json
    sessions = fetch_and_normalise()
    print(f"Fetched {len(sessions)} agent(s)")
    for s in sessions[:5]:
        print(
            f"  [{s['priority_score']:>3}] {s['hostname']:30} "
            f"{s['username']:30} {s['internal_ip']:15} tech={s['tech_stack']}"
        )
    print(_json.dumps(sessions[:2], indent=2, default=str))
