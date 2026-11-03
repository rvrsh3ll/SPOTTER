#!/usr/bin/env python3
"""
smoke_tuoni.py — Offline checks for scripts/tuoni_normalizer.py.

Runs entirely on fixtures: no teamserver, no n8n, no Neo4j. Every assertion here
pins an operator-visible behaviour of the Tuoni ingest (workflow 31), so a
failure means a session would land wrong in the graph, not merely that a unit
test drifted. Mirrors smoke_adaptix.py.

    python3 scripts/smoke_tuoni.py
    python3 scripts/smoke_tuoni.py --only canonical_shape
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tuoni_normalizer import C2_FRAMEWORK, normalise_agent  # noqa: E402


TS = "https://10.0.0.5:8443"
LISTENERS = {1: "http-443", 2: "smb-pipe"}


def _agent(metadata=None, **over):
    """A complete, plausible /api/v2/agents record; override what a case is about.

    `metadata=` replaces the whole metadata block; keyword `meta_*` args patch a
    single metadata field so a case can speak to just one of them.
    """
    base = {
        "guid":                  "3a698332-53cd-4059-a479-f130c7b1ff13",
        "status":                "ACTIVE",
        "firstRegistrationTime": "2026-11-01T10:00:00Z",
        "lastCallbackTime":      "2026-11-03T13:40:00Z",
        "recentListenerId":      1,
        "metadata": {
            "username":     "CORP\\jdoe",
            "proc":         "explorer.exe",
            "pid":          4812,
            "os":           "WINDOWS",
            "osMajor":      10,
            "osMinor":      0,
            "ips":          "10.10.4.21,fe80::1",
            "hostname":     "WS-014",
            "processArch":  "X64",
            "osArch":       "X64",
            "integrity":    "High",
            "sleep":        60,
            "sleepRandom":  15,
            "agentType":    "shelldot.agent.windows-exe",
        },
    }
    meta_over = {k[5:]: v for k, v in over.items() if k.startswith("meta_")}
    over = {k: v for k, v in over.items() if not k.startswith("meta_")}
    if metadata is not None:
        base["metadata"] = metadata
    base["metadata"].update(meta_over)
    base.update(over)
    return base


# ── Cases ─────────────────────────────────────────────────────────────────────

def case_canonical_shape():
    """Every canonical key the upsert node writes must be present."""
    s = normalise_agent(_agent(), TS, LISTENERS)

    assert s["c2_framework"] == C2_FRAMEWORK == "tuoni", s["c2_framework"]
    assert s["session_id"] == "3a698332-53cd-4059-a479-f130c7b1ff13", s["session_id"]
    assert s["session_key"] == "tuoni:3a698332-53cd-4059-a479-f130c7b1ff13", s["session_key"]
    assert s["c2_server"] == TS, s["c2_server"]
    assert s["hostname"] == "WS-014", s["hostname"]
    assert s["username"] == "CORP\\jdoe", s["username"]
    assert s["sam_account_name"] == "jdoe", s["sam_account_name"]
    assert s["internal_ip"] == "10.10.4.21", s["internal_ip"]
    assert s["external_ip"] == "", s["external_ip"]
    assert s["os_version"] == "WINDOWS 10.0", s["os_version"]
    assert s["arch"] == "x64", s["arch"]
    assert s["pid"] == 4812 and isinstance(s["pid"], int), s["pid"]
    assert s["process_name"] == "explorer.exe", s["process_name"]
    assert s["sleep_seconds"] == 60, s["sleep_seconds"]
    assert s["jitter_pct"] == 15, s["jitter_pct"]
    assert s["listener"] == "http-443", s["listener"]
    assert s["source"] == "tuoni", s["source"]

    # WF31's upsert reads all of these by name; a missing key writes a None.
    for key in ("os_version", "username", "sam_account_name", "is_admin",
                "last_checkin", "note", "process_list", "tech_stack",
                "priority_score", "is_dead", "is_pivot", "pivot_parent",
                "pivot_channel"):
        assert key in s, f"canonical key missing: {key}"


def case_integrity_admin_tri_state():
    """
    integrity → is_admin is True / False / None=UNKNOWN.

    System/High are elevated, Medium/Low are not, and an absent integrity must
    stay None -- collapsing it to False would claim the agent is confirmed
    unprivileged, a different statement from "the teamserver did not say".
    """
    assert normalise_agent(_agent(meta_integrity="System"), TS)["is_admin"] is True
    assert normalise_agent(_agent(meta_integrity="High"), TS)["is_admin"] is True
    assert normalise_agent(_agent(meta_integrity="Medium"), TS)["is_admin"] is False
    assert normalise_agent(_agent(meta_integrity="Low"), TS)["is_admin"] is False

    missing = _agent()
    del missing["metadata"]["integrity"]
    assert normalise_agent(missing, TS)["is_admin"] is None, "absent integrity must be None"
    assert normalise_agent(_agent(meta_integrity=""), TS)["is_admin"] is None
    # An unknown label is UNKNOWN, not a guess.
    assert normalise_agent(_agent(meta_integrity="Weird"), TS)["is_admin"] is None


def case_ips_picks_first_ipv4():
    """metadata.ips is a comma-joined string; the first IPv4 wins, IPv6 skipped."""
    assert normalise_agent(_agent(meta_ips="10.10.4.21,fe80::1"), TS)["internal_ip"] == "10.10.4.21"
    # IPv6 first, IPv4 second → still picks the IPv4.
    assert normalise_agent(_agent(meta_ips="fe80::1,192.168.1.5"), TS)["internal_ip"] == "192.168.1.5"
    # No IPv4 at all → empty, never an IPv6.
    assert normalise_agent(_agent(meta_ips="fe80::1"), TS)["internal_ip"] == ""
    assert normalise_agent(_agent(meta_ips=""), TS)["internal_ip"] == ""
    # A not-really-an-IP token (octet > 255) is rejected.
    assert normalise_agent(_agent(meta_ips="999.1.1.1,10.0.0.9"), TS)["internal_ip"] == "10.0.0.9"
    # A list form is tolerated too.
    assert normalise_agent(_agent(meta_ips=["fe80::1", "10.1.2.3"]), TS)["internal_ip"] == "10.1.2.3"


def case_last_checkin_iso_parse():
    """lastCallbackTime (ISO, trailing Z) → aware UTC; bad/absent → None."""
    s = normalise_agent(_agent(lastCallbackTime="2026-11-03T13:40:00Z"), TS)
    assert s["last_checkin"] == "2026-11-03T13:40:00+00:00", s["last_checkin"]
    assert s["last_checkin_dt"].tzinfo is not None, "last_checkin_dt must be aware"

    # An explicit offset is honoured and converted to UTC.
    s2 = normalise_agent(_agent(lastCallbackTime="2026-11-03T15:40:00+02:00"), TS)
    assert s2["last_checkin"] == "2026-11-03T13:40:00+00:00", s2["last_checkin"]

    for bad in (None, "", "not-a-time"):
        s = normalise_agent(_agent(lastCallbackTime=bad), TS)
        assert s["last_checkin"] is None, f"lastCallbackTime={bad!r} → {s['last_checkin']!r}"
        assert s["last_checkin_dt"] is None, f"lastCallbackTime={bad!r} left a datetime"


def case_listener_resolved_from_map():
    """recentListenerId resolves to a name via the listeners map."""
    assert normalise_agent(_agent(recentListenerId=1), TS, LISTENERS)["listener"] == "http-443"
    assert normalise_agent(_agent(recentListenerId=2), TS, LISTENERS)["listener"] == "smb-pipe"
    # An id absent from the map falls back to the bare id as a string.
    assert normalise_agent(_agent(recentListenerId=9), TS, LISTENERS)["listener"] == "9"
    # No map supplied → still the bare id, never empty when an id is present.
    assert normalise_agent(_agent(recentListenerId=1), TS)["listener"] == "1"
    # No listener id at all → empty.
    no_lid = _agent()
    del no_lid["recentListenerId"]
    assert normalise_agent(no_lid, TS, LISTENERS)["listener"] == ""


def case_missing_guid_yields_empty_session_id():
    """
    An agent with no guid must produce an empty session_id (WF31 drops it later).

    session_key would collapse to 'tuoni:' for every such record, and the upsert
    MERGEs on the label, so they would fold onto one node reporting success.
    """
    no_guid = _agent()
    del no_guid["guid"]
    s = normalise_agent(no_guid, TS)
    assert s["session_id"] == "", s["session_id"]
    assert s["session_key"] == "tuoni:", s["session_key"]

    assert normalise_agent(_agent(guid=""), TS)["session_id"] == ""


def case_blocked_status_is_dead():
    """status BLOCKED marks the agent dead; ACTIVE/INACTIVE do not."""
    assert normalise_agent(_agent(status="BLOCKED"), TS)["is_dead"] is True
    assert normalise_agent(_agent(status="ACTIVE"), TS)["is_dead"] is False
    assert normalise_agent(_agent(status="INACTIVE"), TS)["is_dead"] is False


def case_arch_normalised():
    """osArch wins over processArch; X64 → x64, unknown values pass through."""
    assert normalise_agent(_agent(meta_osArch="X64"), TS)["arch"] == "x64"
    assert normalise_agent(_agent(meta_osArch="X86"), TS)["arch"] == "x86"
    assert normalise_agent(_agent(meta_osArch="riscv"), TS)["arch"] == "riscv"
    # osArch preferred over processArch.
    a = _agent()
    a["metadata"]["osArch"] = "ARM64"
    a["metadata"]["processArch"] = "X86"
    assert normalise_agent(a, TS)["arch"] == "arm64"


def case_scoring_wired():
    """
    finalize_session() must actually run: admin + DC hostname + fresh check-in.

    10 (admin) + 8 (DC name pattern) + 5 (checked in <10 min ago) = 23.
    """
    fresh = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    s = normalise_agent(
        _agent(lastCallbackTime=fresh, meta_hostname="DC01", meta_integrity="System"), TS
    )
    assert s["priority_score"] == 23, f"expected 23, got {s['priority_score']}"


def case_empty_process_list():
    """The roster carries no process list, so tech_stack must come back empty."""
    s = normalise_agent(_agent(), TS)
    assert s["process_list"] == [], s["process_list"]
    assert s["tech_stack"] == [], s["tech_stack"]


def case_sparse_record():
    """A near-empty agent must normalise without raising."""
    s = normalise_agent({"guid": "deadbeef"}, TS)
    assert s["session_key"] == "tuoni:deadbeef", s["session_key"]
    assert s["hostname"] == "" and s["username"] == ""
    assert s["is_admin"] is None
    assert s["last_checkin"] is None
    assert s["pid"] is None
    assert s["internal_ip"] == ""
    assert isinstance(s["priority_score"], int)


CASES = {
    name[5:]: fn
    for name, fn in sorted(globals().items())
    if name.startswith("case_") and callable(fn)
}


def main() -> int:
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1]

    failures = []
    for name, fn in CASES.items():
        if only and name != only:
            continue
        try:
            fn()
            print(f"  ok    {name}")
        except AssertionError as e:
            failures.append((name, str(e)))
            print(f"  FAIL  {name}: {e}")
        except Exception as e:
            failures.append((name, repr(e)))
            print(f"  ERROR {name}: {e!r}")

    total = len(CASES) if not only else 1
    if failures:
        print(f"\n{len(failures)} of {total} tuoni checks failed")
        return 1
    print(f"\nall {total} tuoni checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
