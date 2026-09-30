"""
cobalt_normalizer.py — Fetch and normalise Cobalt Strike 4.x beacon data.

Connects to the CS Team Server REST API, retrieves active beacons, and returns
the canonical C2Session dict documented in c2_common.py, ready for ingestion
into Flowsint via flowsint_client.

Framework-agnostic pieces (process→technology inference, scoring, dedup keys)
live in c2_common.py and are shared with brc4_normalizer.py. They are re-exported
here so existing importers keep working.

All beacon data processed here originates from an authorized red team engagement
running under documented Rules of Engagement.

CS REST API reference:
  https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/api/index.htm

Key endpoints used:
  GET /beacons           — list all beacons
  GET /beacon/<id>       — single beacon detail

Environment variables:
  CS_API_URL    — e.g. https://192.168.1.10:50050
  CS_API_TOKEN  — REST API bearer token
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

CS_API_URL   = os.environ.get("CS_API_URL", "")
CS_API_TOKEN = os.environ.get("CS_API_TOKEN", "")

C2_FRAMEWORK = "cobalt_strike"

# Kept as an alias: score_beacon() was this module's public scoring entry point
# before scoring moved to c2_common for reuse across frameworks.
score_beacon = score_session

# ── CS REST API client ────────────────────────────────────────────────────────

def _cs_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Token {CS_API_TOKEN}",
        "Content-Type": "application/json",
    })
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def fetch_beacons(cs_url: Optional[str] = None, cs_token: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Fetch all beacons from the CS Team Server REST API.

    GET /beacons

    Returns a list of raw beacon dicts as returned by the API.
    """
    url   = cs_url or CS_API_URL
    token = cs_token or CS_API_TOKEN
    if not url or not token:
        raise ValueError("CS_API_URL and CS_API_TOKEN must be set")

    s = _cs_session()
    if token != CS_API_TOKEN:
        s.headers.update({"Authorization": f"Token {token}"})

    resp = s.get(f"{url}/beacons", verify=False, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    # CS API may return {"beacons": [...]} or a bare list
    if isinstance(data, list):
        return data
    return data.get("beacons", [])


def normalise_beacon(raw: Dict[str, Any], cs_server: str = "") -> Dict[str, Any]:
    """
    Normalise a single raw CS beacon dict into SPOTTER's canonical C2Session format.

    CS field mapping (the API is inconsistent across 4.x point releases, hence the
    paired .get() fallbacks):
      id / bid            → session_id
      computer / hostname → hostname
      user                → username
      internal            → internal_ip
      external            → external_ip
      last / lastcheckin  → last_checkin (epoch seconds)
      process             → process_name
    """
    last_ts = raw.get("last") or raw.get("lastcheckin")
    last_checkin_dt: Optional[datetime] = None
    if last_ts:
        try:
            last_checkin_dt = datetime.fromtimestamp(int(last_ts), tz=timezone.utc)
        except (ValueError, OSError):
            pass

    # Process list — CS may give a raw newline-delimited string or a list
    raw_procs = raw.get("processes") or raw.get("process_list") or []
    if isinstance(raw_procs, str):
        raw_procs = [p.strip() for p in raw_procs.splitlines() if p.strip()]
    process_list: List[str] = raw_procs

    normalised = {
        "c2_framework":    C2_FRAMEWORK,
        "session_id":      str(raw.get("id", raw.get("bid", ""))),
        "c2_server":       cs_server or CS_API_URL,
        "hostname":        raw.get("computer", raw.get("hostname", "unknown")),
        "username":        raw.get("user", ""),
        "internal_ip":     raw.get("internal", raw.get("internalip", "")),
        "external_ip":     raw.get("external", raw.get("externalip", "")),
        "os_version":      raw.get("os", raw.get("osname", "")),
        "arch":            raw.get("arch", ""),
        "pid":             raw.get("pid"),
        "process_name":    raw.get("process", ""),
        "is_admin":        bool(raw.get("admin", raw.get("elevated", False))),
        "last_checkin":    last_checkin_dt.isoformat() if last_checkin_dt else None,
        "last_checkin_dt": last_checkin_dt,
        "sleep_seconds":   raw.get("sleep"),
        "jitter_pct":      raw.get("jitter"),
        "listener":        raw.get("listener", ""),
        "note":            raw.get("note", ""),
        "process_list":    process_list,
        "is_dead":         False,
        "is_pivot":        bool(raw.get("parent") or raw.get("pivot")),
        "pivot_parent":    str(raw.get("parent") or ""),
        "pivot_channel":   raw.get("pivot") or "",
        # Retained for consumers that predate the C2Session generalisation.
        "source":          C2_FRAMEWORK,
    }
    # sam_account_name, tech_stack, session_key and priority_score are derived.
    return finalize_session(normalised)


def fetch_and_normalise(
    cs_url: Optional[str] = None,
    cs_token: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Convenience wrapper: fetch all beacons and return normalised dicts,
    sorted by priority_score descending.
    """
    raw_beacons = fetch_beacons(cs_url, cs_token)
    normalised  = [normalise_beacon(b, cs_url or CS_API_URL) for b in raw_beacons]
    return sorted(normalised, key=lambda b: b["priority_score"], reverse=True)


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json as _json
    sessions = fetch_and_normalise()
    print(f"Fetched {len(sessions)} session(s)")
    for s in sessions[:5]:
        print(
            f"  [{s['priority_score']:>3}] {s['hostname']:30} "
            f"{s['username']:30} {s['internal_ip']:15} tech={s['tech_stack']}"
        )
    print(_json.dumps(sessions[:2], indent=2, default=str))
