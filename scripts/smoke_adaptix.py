#!/usr/bin/env python3
"""
smoke_adaptix.py — Offline checks for scripts/adaptix_normalizer.py.

Runs entirely on fixtures: no teamserver, no n8n, no Neo4j. Every assertion here
pins an operator-visible behaviour of the Adaptix ingest (workflow 28), so a
failure means a session would land wrong in the graph, not merely that a unit
test drifted.

    python3 scripts/smoke_adaptix.py
    python3 scripts/smoke_adaptix.py --only tri_state_admin

No equivalent exists for cobalt_normalizer or brc4_normalizer yet; this is the
pattern to copy when one is written.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from adaptix_normalizer import C2_FRAMEWORK, normalise_agent  # noqa: E402


TS = "https://ts.example:4321/endpoint"


def _agent(**over):
    """A complete, plausible /agent/list record; override what a case is about."""
    base = {
        "a_id":          "a1b2c3d4",
        "a_computer":    "WS-014",
        "a_domain":      "CORP",
        "a_username":    "jdoe",
        "a_internal_ip": "10.10.4.21",
        "a_external_ip": "203.0.113.9",
        "a_os":          1,
        "a_arch":        "x64",
        "a_pid":         4812,
        "a_tid":         9120,
        "a_process":     "explorer.exe",
        "a_elevated":    False,
        "a_last_tick":   1757000000,
        "a_sleep":       60,
        "a_jitter":      15,
        "a_listener":    "http-443",
    }
    base.update(over)
    return base


# ── Cases ─────────────────────────────────────────────────────────────────────

def case_canonical_shape():
    """Every canonical key the upsert node writes must be present."""
    s = normalise_agent(_agent(), TS)

    assert s["c2_framework"] == C2_FRAMEWORK == "adaptix", s["c2_framework"]
    assert s["session_id"] == "a1b2c3d4", s["session_id"]
    assert s["session_key"] == "adaptix:a1b2c3d4", s["session_key"]
    assert s["c2_server"] == TS, s["c2_server"]
    assert s["hostname"] == "WS-014", s["hostname"]
    assert s["internal_ip"] == "10.10.4.21", s["internal_ip"]
    assert s["external_ip"] == "203.0.113.9", s["external_ip"]
    assert s["arch"] == "x64", s["arch"]
    assert s["pid"] == 4812 and isinstance(s["pid"], int), s["pid"]
    assert s["thread_id"] == 9120, s["thread_id"]
    assert s["process_name"] == "explorer.exe", s["process_name"]
    assert s["sleep_seconds"] == 60, s["sleep_seconds"]
    assert s["jitter_pct"] == 15, s["jitter_pct"]
    assert s["listener"] == "http-443", s["listener"]
    assert s["source"] == "adaptix", s["source"]

    # WF28's upsert reads all of these by name; a missing key writes a None.
    for key in ("os_version", "username", "sam_account_name", "is_admin",
                "last_checkin", "note", "process_list", "tech_stack",
                "priority_score", "is_dead", "is_pivot", "pivot_parent",
                "pivot_channel"):
        assert key in s, f"canonical key missing: {key}"


def case_domain_qualified_username():
    """a_domain + a_username must fold to DOMAIN\\user with the sam split out."""
    s = normalise_agent(_agent(), TS)
    assert s["username"] == "CORP\\jdoe", s["username"]
    # sam_account_name is what dedups against a SharpHound-ingested identity.
    assert s["sam_account_name"] == "jdoe", s["sam_account_name"]


def case_bare_username():
    """No domain (a workgroup or Linux host) → bare username, sam equal to it."""
    s = normalise_agent(_agent(a_domain=""), TS)
    assert s["username"] == "jdoe", s["username"]
    assert s["sam_account_name"] == "jdoe", s["sam_account_name"]

    # An already-qualified username must not be double-prefixed.
    s2 = normalise_agent(_agent(a_username="OTHER\\svc_sql"), TS)
    assert s2["username"] == "OTHER\\svc_sql", s2["username"]
    assert s2["sam_account_name"] == "svc_sql", s2["sam_account_name"]


def case_tri_state_admin():
    """
    is_admin is True / False / None=UNKNOWN. An absent a_elevated must stay None.

    Collapsing it to False would claim the agent is confirmed unprivileged, which
    is a different statement from "the teamserver did not say", and it is the
    claim the AGENTS tab renders.
    """
    assert normalise_agent(_agent(a_elevated=True), TS)["is_admin"] is True
    assert normalise_agent(_agent(a_elevated=False), TS)["is_admin"] is False

    missing = _agent()
    del missing["a_elevated"]
    assert normalise_agent(missing, TS)["is_admin"] is None, "absent a_elevated must be None"
    assert normalise_agent(_agent(a_elevated=None), TS)["is_admin"] is None


def case_last_tick_epoch():
    """a_last_tick is a unix epoch → aware UTC; absent/zero → None, not epoch 0."""
    s = normalise_agent(_agent(a_last_tick=1757000000), TS)
    assert s["last_checkin"] == "2025-09-04T15:33:20+00:00", s["last_checkin"]
    assert s["last_checkin_dt"].tzinfo is not None, "last_checkin_dt must be aware"

    for bad in (0, None, "", "not-a-number"):
        s = normalise_agent(_agent(a_last_tick=bad), TS)
        assert s["last_checkin"] is None, f"a_last_tick={bad!r} → {s['last_checkin']!r}"
        assert s["last_checkin_dt"] is None, f"a_last_tick={bad!r} left a datetime"


def case_os_mapping():
    """a_os is an enum; a_os_desc wins when the teamserver supplies one."""
    for code, want in ((0, ""), (1, "Windows"), (2, "Linux"), (3, "macOS")):
        s = normalise_agent(_agent(a_os=code), TS)
        assert s["os_version"] == want, f"a_os={code} → {s['os_version']!r}"

    # An unmapped enum must not guess a family.
    assert normalise_agent(_agent(a_os=99), TS)["os_version"] == ""

    s = normalise_agent(_agent(a_os=1, a_os_desc="Windows Server 2019 Build 17763"), TS)
    assert s["os_version"] == "Windows Server 2019 Build 17763", s["os_version"]


def case_scoring_wired():
    """
    finalize_session() must actually run: admin + DC hostname + fresh check-in.

    10 (admin) + 8 (DC name pattern) + 5 (checked in <10 min ago) = 23. If this
    reads 0 or 18 the normaliser is returning its own dict without scoring it.
    """
    fresh = int((datetime.now(timezone.utc) - timedelta(minutes=2)).timestamp())
    s = normalise_agent(
        _agent(a_computer="DC01", a_elevated=True, a_last_tick=fresh), TS
    )
    assert s["priority_score"] == 23, f"expected 23, got {s['priority_score']}"

    # Same agent, stale: loses only the +5 recency.
    old = int((datetime.now(timezone.utc) - timedelta(hours=6)).timestamp())
    s2 = normalise_agent(
        _agent(a_computer="DC01", a_elevated=True, a_last_tick=old), TS
    )
    assert s2["priority_score"] == 18, f"expected 18, got {s2['priority_score']}"


def case_pivot_channel_without_parent():
    """
    An SMB/TCP listener marks a pivot, but pivot_parent stays empty on purpose.

    /agent/list documents no parent-agent field, and WF28 skips the PIVOTS_TO edge
    when pivot_parent is empty rather than inventing a relationship.
    """
    for listener, want in (("smb-pipe-01", "smb"), ("tcp-4444", "tcp"),
                           ("pipe_internal", "pipe")):
        s = normalise_agent(_agent(a_listener=listener), TS)
        assert s["is_pivot"] is True, f"{listener} should read as a pivot"
        assert s["pivot_channel"] == want, f"{listener} → {s['pivot_channel']!r}"
        assert s["pivot_parent"] == "", "pivot_parent must stay empty (unguessable)"

    s = normalise_agent(_agent(a_listener="https-443"), TS)
    assert s["is_pivot"] is False, "an HTTPS listener is not a pivot"
    assert s["pivot_channel"] == ""


def case_note_folding():
    """Tags, mark and impersonation context fold into the single note field."""
    s = normalise_agent(
        _agent(a_tags=["finance", "priority"], a_mark="verified",
               a_impersonated="CORP\\svc_backup"),
        TS,
    )
    assert s["note"] == "finance · priority · verified · impersonating CORP\\svc_backup", s["note"]

    # A string a_tags is accepted as readily as a list, and empties drop out.
    assert normalise_agent(_agent(a_tags="lab"), TS)["note"] == "lab"
    assert normalise_agent(_agent(), TS)["note"] == ""


def case_empty_process_list():
    """
    /agent/list never carries a process list, so tech_stack must come back empty.

    This is what makes the upsert node's empty-value patch guard load-bearing: if
    an empty process_list were written over an existing session on every poll, any
    enrichment from a `ps` task would be wiped within five minutes.
    """
    s = normalise_agent(_agent(), TS)
    assert s["process_list"] == [], s["process_list"]
    assert s["tech_stack"] == [], s["tech_stack"]


def case_sparse_record():
    """A near-empty agent must normalise without raising."""
    s = normalise_agent({"a_id": "deadbeef"}, TS)
    assert s["session_key"] == "adaptix:deadbeef", s["session_key"]
    assert s["hostname"] == "" and s["username"] == ""
    assert s["is_admin"] is None
    assert s["last_checkin"] is None
    assert s["pid"] is None and s["thread_id"] is None
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
        print(f"\n{len(failures)} of {total} adaptix checks failed")
        return 1
    print(f"\nall {total} adaptix checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
