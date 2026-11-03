"""
tuoni_normalizer.py — Fetch and normalise Tuoni C2 agent data.

Connects to the Tuoni teamserver REST API, retrieves the agent roster, and returns
the canonical C2Session dict documented in c2_common.py, ready for ingestion into
Flowsint via flowsint_client.

Framework-agnostic pieces (process→technology inference, scoring, dedup keys) live
in c2_common.py and are shared with cobalt_normalizer.py, brc4_normalizer.py and
adaptix_normalizer.py. They are re-exported here so importers behave the same
across every framework.

All agent data processed here originates from an authorized red team engagement
running under documented Rules of Engagement.

Tuoni REST API reference:
  https://docs.tuoni.io   (OpenAPI live at https://<host>:8443/docs/api)

Key endpoints used:
  POST /api/v2/auth/login   — HTTP Basic → {accessToken, refreshToken, ...}
  GET  /api/v2/agents       — paged agent roster (page/pageSize/hasMorePages)
  GET  /api/v1/agents       — fallback roster (bare array OR dict-of-agents)
  GET  /api/v1/listeners    — id → name map, to resolve recentListenerId

Why this is a POLL and not a push (same shape as Adaptix / workflow 28):
  Tuoni exposes a STOMP/SockJS event bus (/events) whose heartbeat topic carries
  little more than an agent GUID, and the access JWT that authorises the socket
  expires in ~15 minutes without the open socket being renewed. A correct
  live/stale/dead roster only needs lastCallbackTime, which every /agents poll
  refreshes, so WebSocket ingestion is deliberately DEFERRED to a later iteration
  and this normaliser polls REST every 5 minutes exactly as WF28 does.

Two things that differ from Adaptix and will waste your time otherwise:

  1. THE BASE URL HAS NO PATH PREFIX. Adaptix hangs every route off an
     operator-chosen prefix (commonly "/endpoint"); Tuoni does not. TUONI_API_URL
     is just scheme://host:port, e.g. https://10.0.0.5:8443 (default port 8443),
     and the API paths (/api/v2/auth/login, /api/v2/agents) are fixed.

  2. AUTH IS HTTP BASIC → BEARER. The login endpoint takes an
     `Authorization: Basic base64(user:pass)` header (NOT a JSON body) and
     answers with a short-lived accessToken; every subsequent call carries
     `Authorization: Bearer <accessToken>`. A rejected login is a plain 401,
     unlike Adaptix's 404 trap.

Environment variables:
  TUONI_API_URL    — teamserver base URL, scheme://host:port, NO path prefix
  TUONI_USERNAME   — operator account used for the poll
  TUONI_PASSWORD   — that account's password (Tuoni has no static API token)
"""

from __future__ import annotations

import base64
import os
import re
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

TUONI_API_URL  = os.environ.get("TUONI_API_URL", "")
TUONI_USERNAME = os.environ.get("TUONI_USERNAME", "")
TUONI_PASSWORD = os.environ.get("TUONI_PASSWORD", "")

C2_FRAMEWORK = "tuoni"

# Tuoni's metadata.osArch / .processArch come upper-cased ("X64"). Normalise the
# common ones to the lower-case spellings the rest of SPOTTER and the AGENTS tab
# use; anything unrecognised is passed through untouched rather than guessed at.
_ARCH_NORMALISE = {"X64": "x64", "X86": "x86", "AMD64": "x64",
                   "ARM64": "arm64", "AARCH64": "aarch64"}

# metadata.integrity is a label, not a flag. System/High are elevated, Medium/Low
# are not, and a MISSING value is UNKNOWN (None) -- never coerced to False, which
# would claim the agent is confirmed unprivileged. WF23's _tri() and the AGENTS
# tab render None differently from a hard False.
_INTEGRITY_ADMIN = {"system": True, "high": True, "medium": False, "low": False}

# A BLOCKED agent is one the operator has cut off; mark it dead. ACTIVE/INACTIVE
# are left to WF23's stale logic (last_checkin vs active_minutes) so an agent that
# simply has not called back recently is not prematurely flagged dead.
_DEAD_STATUSES = {"BLOCKED"}

# Kept as an alias for symmetry with cobalt_normalizer.score_beacon.
score_agent = score_session


# ── Tuoni REST API client ─────────────────────────────────────────────────────

def _tuoni_session() -> requests.Session:
    s = requests.Session()
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

    POST /api/v2/auth/login with `Authorization: Basic base64(user:pass)`
      →  {"accessToken": ..., "refreshToken": ..., "tokenType": "Bearer", ...}

    No token cache: every n8n run is a fresh process with nowhere to persist one,
    and at a 5-minute poll cadence a login per run is well under the ~15-minute
    access-token TTL, cheaper than the /refresh bookkeeping would be.

    Prefer the v2 endpoint (structured JSON). A deployment that still answers the
    deprecated v1 endpoint returns the raw JWT string as the whole body; that is
    tolerated as a fallback so a mixed-version teamserver still authenticates.
    """
    url  = (base_url or TUONI_API_URL).rstrip("/")
    user = username or TUONI_USERNAME
    pw   = password if password is not None else TUONI_PASSWORD
    if not url or not user:
        raise ValueError("TUONI_API_URL and TUONI_USERNAME must be set")

    basic = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")

    s = _tuoni_session()
    resp = s.post(
        f"{url}/api/v2/auth/login",
        headers={"Authorization": f"Basic {basic}"},
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()

    # v2 returns JSON {accessToken: ...}; the deprecated v1 path returns the raw
    # JWT as the body. Accept either so a mixed-version teamserver still works.
    token = ""
    try:
        token = (resp.json() or {}).get("accessToken", "")
    except ValueError:
        token = (resp.text or "").strip()
    if not token:
        body = (resp.text or "").strip()
        if body and "{" not in body:
            token = body
    if not token:
        raise ValueError("Tuoni login succeeded but returned no accessToken")
    return token


def fetch_listeners(
    base_url: Optional[str] = None, token: Optional[str] = None
) -> Dict[Any, str]:
    """
    Fetch listeners and return an {id: name} map used to resolve recentListenerId
    into a human listener name for the AGENTS tab.

    GET /api/v1/listeners  (Authorization: Bearer <accessToken>)

    Best-effort: any failure returns an empty map rather than raising, because a
    missing listener name only blanks one column -- it must not fail the poll.
    """
    url = (base_url or TUONI_API_URL).rstrip("/")
    if not url:
        return {}
    tok = token or login(url)

    s = _tuoni_session()
    s.headers.update({"Authorization": f"Bearer {tok}"})
    try:
        resp = s.get(f"{url}/api/v1/listeners", verify=False, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return {}

    if isinstance(data, dict):
        # Either a dict-of-listeners keyed by id, or a wrapper {items:[...]}.
        for key in ("items", "listeners", "data"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            out: Dict[Any, str] = {}
            for lid, l in data.items():
                name = (l or {}).get("name") if isinstance(l, dict) else None
                out[lid] = str(name or lid)
            return out
    if isinstance(data, list):
        out = {}
        for l in data:
            if isinstance(l, dict) and l.get("id") is not None:
                out[l["id"]] = str(l.get("name") or l["id"])
        return out
    return {}


def fetch_agents(base_url: Optional[str] = None, token: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Fetch the full agent roster, ACTIVE and INACTIVE alike.

    Prefers the v2 paged endpoint and walks every page:
      GET /api/v2/agents?page={n}&pageSize=200   (Authorization: Bearer <token>)
    looping until `hasMorePages` is false. No `status` filter is sent, so both
    ACTIVE and INACTIVE agents come back and WF23 can mark stale/dead from
    lastCallbackTime rather than this normaliser deciding it.

    Falls back to the v1 endpoint (GET /api/v1/agents), which may answer with a
    bare JSON array OR a dict of agents, if v2 is unavailable.

    Returns a list of raw agent dicts as returned by the API.
    """
    url = (base_url or TUONI_API_URL).rstrip("/")
    if not url:
        raise ValueError("TUONI_API_URL must be set")

    tok = token or login(url)

    s = _tuoni_session()
    s.headers.update({"Authorization": f"Bearer {tok}"})

    # ── Preferred: v2 pagination ──────────────────────────────────────────────
    try:
        agents: List[Dict[str, Any]] = []
        page = 0
        for _ in range(1000):  # hard cap; a real roster never reaches it
            resp = s.get(
                f"{url}/api/v2/agents",
                params={"page": page, "pageSize": 200},
                verify=False,
                timeout=15,
            )
            resp.raise_for_status()
            payload = resp.json()

            if isinstance(payload, list):
                # A v2 that ignores paging and returns a bare list: take it once.
                return payload
            if not isinstance(payload, dict):
                break

            batch = None
            for key in ("items", "content", "agents", "data"):
                if isinstance(payload.get(key), list):
                    batch = payload[key]
                    break
            if batch is None:
                break
            agents.extend(batch)

            if not payload.get("hasMorePages"):
                break
            page += 1
        return agents
    except requests.HTTPError:
        pass  # fall through to v1

    # ── Fallback: v1 ──────────────────────────────────────────────────────────
    resp = s.get(f"{url}/api/v1/agents", verify=False, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Either a wrapper {items|agents|data:[...]} or a bare dict-of-agents
        # keyed by guid; both appear in the wild.
        for key in ("items", "agents", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        return [v for v in data.values() if isinstance(v, dict)]
    return []


# ── Normalisation ─────────────────────────────────────────────────────────────

def _int_or_none(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _first_ipv4(ips: Any) -> str:
    """
    Pick the first usable IPv4 out of metadata.ips.

    Tuoni reports `ips` as a single comma-separated string that mixes IPv4 and
    IPv6 ("10.10.4.21,fe80::1"). SPOTTER's internal_ip is a single IPv4, so the
    first token that parses as a dotted quad wins and the rest (IPv6, extra NICs)
    are ignored for v1. A list is accepted too, in case a future payload sends one.
    """
    if isinstance(ips, (list, tuple)):
        tokens = [str(x) for x in ips]
    else:
        tokens = str(ips or "").split(",")
    for tok in tokens:
        tok = tok.strip()
        if _IPV4_RE.match(tok):
            octets = tok.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                return tok
    return ""


def _os_version(meta: Dict[str, Any]) -> str:
    """
    Build an OS string from `os` plus the major/minor build numbers.

    metadata.os is a bare family ("WINDOWS"); osMajor/osMinor carry the version
    ("10"/"0"), so the operator-facing string becomes "WINDOWS 10.0". With no
    build numbers the family alone is returned, and with no family at all, "".
    """
    os_name = str(meta.get("os") or "").strip()
    major = meta.get("osMajor")
    minor = meta.get("osMinor")
    if os_name and major is not None:
        if minor is not None:
            return f"{os_name} {major}.{minor}"
        return f"{os_name} {major}"
    return os_name


def _arch(meta: Dict[str, Any]) -> str:
    """Prefer osArch, fall back to processArch; normalise the common spellings."""
    raw = str(meta.get("osArch") or meta.get("processArch") or "").strip()
    if not raw:
        return ""
    return _ARCH_NORMALISE.get(raw.upper(), raw)


def _is_admin(meta: Dict[str, Any]) -> Optional[bool]:
    integ = meta.get("integrity")
    if integ is None or str(integ).strip() == "":
        return None
    return _INTEGRITY_ADMIN.get(str(integ).strip().lower(), None)


def _parse_iso(value: Any) -> Optional[datetime]:
    """
    Parse an ISO-8601 timestamp (lastCallbackTime) into an aware UTC datetime.

    Tuoni stamps a trailing 'Z'; datetime.fromisoformat only learned to accept it
    in 3.11, so it is swapped for +00:00 first. A naive result is assumed UTC. A
    value that will not parse yields None rather than raising -- a bad timestamp
    on one agent must not fail the whole poll.
    """
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _note(raw: Dict[str, Any], meta: Dict[str, Any]) -> str:
    """Fold Tuoni's agentType and any customProperties into the single note field."""
    parts: List[str] = []
    atype = str(meta.get("agentType") or "").strip()
    if atype:
        parts.append(atype)
    cp = meta.get("customProperties")
    if isinstance(cp, dict):
        for k, v in cp.items():
            if v not in (None, "", {}, []):
                parts.append(f"{k}={v}")
    return " · ".join(parts)


def normalise_agent(
    raw: Dict[str, Any],
    ts_server: str = "",
    listeners: Optional[Dict[Any, str]] = None,
) -> Dict[str, Any]:
    """
    Normalise one raw Tuoni agent dict into SPOTTER's canonical C2Session format.

    Tuoni field mapping (top-level + nested `metadata`):
      guid                         → session_id
      metadata.hostname            → hostname
      metadata.username            → username (finalize derives sam_account_name)
      first IPv4 in metadata.ips   → internal_ip   (external_ip is always "")
      metadata.os + osMajor/osMinor→ os_version
      metadata.osArch/processArch  → arch
      metadata.proc / pid          → process_name / pid
      metadata.integrity           → is_admin (tri-state; see _is_admin)
      lastCallbackTime (ISO)       → last_checkin / last_checkin_dt
      metadata.sleep / sleepRandom → sleep_seconds / jitter_pct
      recentListenerId + listeners → listener (resolved to a name when possible)
      status BLOCKED               → is_dead
    """
    meta = raw.get("metadata") or {}
    if not isinstance(meta, dict):
        meta = {}

    last_checkin_dt = _parse_iso(raw.get("lastCallbackTime") or meta.get("lastCallbackTime"))

    # recentListenerId → human name via the listeners map; fall back to the bare
    # id as a string so the column is never empty when an id is present.
    listener = ""
    lid = raw.get("recentListenerId")
    if lid is not None:
        listener = (listeners or {}).get(lid) or (listeners or {}).get(str(lid)) or str(lid)

    status = str(raw.get("status") or "").strip().upper()

    normalised = {
        "c2_framework":    C2_FRAMEWORK,
        "session_id":      str(raw.get("guid", "")),
        "c2_server":       ts_server or TUONI_API_URL,
        "hostname":        str(meta.get("hostname") or "").strip(),
        "username":        str(meta.get("username") or "").strip(),
        "internal_ip":     _first_ipv4(meta.get("ips")),
        # Tuoni's agent record has no victim-side public IP field.
        "external_ip":     "",
        "os_version":      _os_version(meta),
        "arch":            _arch(meta),
        "pid":             _int_or_none(meta.get("pid")),
        "process_name":    str(meta.get("proc") or "").strip(),
        "is_admin":        _is_admin(meta),
        "last_checkin":    last_checkin_dt.isoformat() if last_checkin_dt else None,
        "last_checkin_dt": last_checkin_dt,
        "sleep_seconds":   _int_or_none(meta.get("sleep")),
        "jitter_pct":      _int_or_none(meta.get("sleepRandom")),
        "listener":        listener,
        "note":            _note(raw, meta),
        # The agent roster carries no process list -- that only arrives from a
        # dedicated task, exactly as with Adaptix /agent/list and CS /beacons.
        # tech_stack is therefore empty until one runs, and the upsert must not
        # patch this empty list over enrichment a later task produced.
        "process_list":    [],
        "is_dead":         status in _DEAD_STATUSES,
        # No documented parent-agent field on the roster, so no pivot topology is
        # inferred -- guessing one would fabricate a PIVOTS_TO edge.
        "is_pivot":        False,
        "pivot_parent":    "",
        "pivot_channel":   "",
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
    Convenience wrapper: log in, fetch every agent (plus the listener map) and
    return normalised dicts, sorted by priority_score descending.
    """
    url   = (base_url or TUONI_API_URL).rstrip("/")
    token = login(url, username, password)
    listeners = fetch_listeners(url, token)
    raw_agents = fetch_agents(url, token)
    normalised = [normalise_agent(a, url, listeners) for a in raw_agents if isinstance(a, dict)]
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
