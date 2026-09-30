#!/usr/bin/env python3
"""
smoke_notify_agents.py — Offline checks for spotter_notify._sweep_agents().

Covers the C2 liveness source behind the header ticker (workflow 24). Runs on
fixtures: no Neo4j, no n8n. `_q` is swapped for a stub that records the Cypher it
was handed and replays canned rows.

Why this file exists
--------------------
_sweep_agents selected `nodeProperties.framework`, a key NOTHING has ever
written -- every writer (WF01/WF21/WF28, upload_router, migrate_c2session) stores
`c2_framework`. Neo4j returns null for an unresolvable property rather than
erroring, so the column came back empty for every row, the framework silently
dropped out of each notification's detail line, and the feed looked perfectly
healthy. The identical misspelling sat in README's "did the ingest land"
verification query, which therefore always answered 0.

That is a bug class this repo keeps meeting: a read that is WRONG rather than
INVALID, so every layer reports success. The static assertion below is the cheap
guard that would have caught it.

    python3 scripts/smoke_notify_agents.py
    python3 scripts/smoke_notify_agents.py --only detail_carries_framework_label
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import spotter_notify as sn  # noqa: E402


def _iso(minutes_ago: float) -> str:
    """A check-in `minutes_ago` in the past, relative to now.

    Timestamps must be relative: a hard-coded future date reads as a clock fault
    and a hard-coded past one goes stale as the file ages.
    """
    return (sn._now() - timedelta(minutes=minutes_ago)).isoformat()


def run_sweep(rows: List[list], prev: Dict[str, str] = None):
    """Drive _sweep_agents with canned rows; return (staged, cypher, state)."""
    captured: Dict[str, str] = {}

    def fake_q(sid, stmt, cap):
        captured["cypher"] = stmt
        return rows

    staged: List[Dict[str, Any]] = []

    def stage(**kw):
        staged.append(kw)

    state: Dict[str, Any] = {"agents": dict(prev or {})}
    real_q = sn._q
    sn._q = fake_q
    try:
        sn._sweep_agents("sketch-1", "camp-1", state, stage, {})
    finally:
        sn._q = real_q
    return staged, captured.get("cypher", ""), state


# Column order matches the RETURN clause:
# label, session_id, last_checkin, is_dead, hostname, username, c2_framework
def _row(session_id, framework, hostname="WS-01", username="CORP\\jdoe",
         last_checkin=None, is_dead=False, label=None):
    return [label or f"Agent:{session_id}@{hostname}", session_id,
            last_checkin if last_checkin is not None else _iso(1),
            is_dead, hostname, username, framework]


# ── Cases ─────────────────────────────────────────────────────────────────────

def case_cypher_reads_c2_framework():
    """
    The query must select `c2_framework`, backticked, and never a bare `framework`.

    This is the assertion that would have caught the original bug. Both halves of
    the UNION must carry it, or the legacy CobaltBeacon branch regresses alone.
    """
    _, cypher, _ = run_sweep([])
    assert "nodeProperties.c2_framework" in cypher, cypher
    assert cypher.count("`nodeProperties.c2_framework`") == 2, (
        "both UNION branches must select the backticked c2_framework: " + cypher)
    # The bare key never existed. Guard the exact string, not a substring of the
    # correct one -- 'nodeProperties.framework' is not a suffix of the right key.
    assert "`nodeProperties.framework`" not in cypher, (
        "nothing writes a bare `framework` key; it silently reads null: " + cypher)


def case_detail_carries_framework_label():
    """
    Each notification's detail line must name the framework, in operator language.

    The ticker is user-facing, so it shows "Adaptix C2", not "adaptix" -- the same
    label WF23 renders in the AGENTS tab, from the same c2_common registry.
    """
    staged, _, _ = run_sweep([
        _row("s1", "cobalt_strike", hostname="WS-01"),
        _row("s2", "brute_ratel",   hostname="SRV-DB"),
        _row("s3", "adaptix",       hostname="LAP-09"),
    ])
    details = {s["target_id"]: s["detail"] for s in staged}
    assert "Cobalt Strike" in details["s1"], details["s1"]
    assert "Brute Ratel"   in details["s2"], details["s2"]
    assert "Adaptix C2"    in details["s3"], details["s3"]
    # ...and the raw discriminator must not leak into operator-facing text.
    assert "cobalt_strike" not in details["s1"], details["s1"]
    assert "adaptix" not in details["s3"].replace("Adaptix C2", ""), details["s3"]
    # The host and user still lead the line.
    assert details["s1"].startswith("WS-01 · CORP\\jdoe · "), details["s1"]


def case_legacy_null_framework():
    """
    A pre-migration CobaltBeacon node carries no discriminator.

    WF01/WF21/WF23 all COALESCE a missing c2_framework to cobalt_strike; the
    ticker must agree, or the same session reads as two different frameworks
    depending on which surface you look at.

    A whitespace-only value is deliberately NOT coalesced: `(v or 'cobalt_strike')`
    keeps it, the strip empties it, and framework_display('') answers "Unknown".
    That is WF23's behaviour too, and matching it exactly is the point of this
    fix -- it is also the more honest answer, since a blank discriminator is a
    data fault rather than evidence of Cobalt Strike. Pinned so the two surfaces
    stay in step if either is ever changed.
    """
    for missing in (None, ""):
        staged, _, _ = run_sweep([_row("legacy1", missing)])
        assert len(staged) == 1, staged
        assert "Cobalt Strike" in staged[0]["detail"], (missing, staged[0]["detail"])

    staged, _, _ = run_sweep([_row("legacy1", "   ")])
    assert "Unknown" in staged[0]["detail"], staged[0]["detail"]


def case_unknown_framework_not_mislabelled():
    """
    A framework with no registry entry must look unfamiliar, never mislabelled.

    framework_display() title-cases the discriminator rather than defaulting to
    Cobalt Strike, so a C2 added to the ingest but not to the registry is visibly
    odd instead of quietly wrong.
    """
    staged, _, _ = run_sweep([_row("s9", "mythic")])
    assert "Mythic" in staged[0]["detail"], staged[0]["detail"]
    assert "Cobalt Strike" not in staged[0]["detail"], staged[0]["detail"]


def case_status_transitions_still_fire():
    """The framework fix must not disturb the transition logic around it."""
    # First sighting.
    staged, _, state = run_sweep([_row("s1", "adaptix", last_checkin=_iso(1))])
    assert staged[0]["title"].startswith("New agent"), staged[0]
    assert state["agents"]["s1"] == "live"

    # Unchanged status is silent.
    staged, _, _ = run_sweep([_row("s1", "adaptix", last_checkin=_iso(1))],
                             prev={"s1": "live"})
    assert staged == [], staged

    # live -> stale, and live -> dead.
    staged, _, _ = run_sweep([_row("s1", "adaptix", last_checkin=_iso(600))],
                             prev={"s1": "live"})
    assert "went stale" in staged[0]["title"], staged[0]
    staged, _, _ = run_sweep([_row("s1", "adaptix", is_dead=True)],
                             prev={"s1": "live"})
    assert "died" in staged[0]["title"], staged[0]

    # Back from the dead.
    staged, _, _ = run_sweep([_row("s1", "adaptix", last_checkin=_iso(1))],
                             prev={"s1": "stale"})
    assert "returned" in staged[0]["title"], staged[0]


def case_no_checkin_is_unknown():
    """A session with no parseable timestamp is 'unknown', not silently stale."""
    _, _, state = run_sweep([_row("s1", "adaptix", last_checkin=None)])
    # _row substitutes a live stamp for None, so pass an unparseable one directly.
    rows = [["Agent:s2@H", "s2", "not-a-date", False, "H", "u", "adaptix"]]
    _, _, state = run_sweep(rows)
    assert state["agents"]["s2"] == "unknown", state


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
            failures.append(name)
            print(f"  FAIL  {name}: {e}")
        except Exception as e:
            failures.append(name)
            print(f"  ERROR {name}: {e!r}")

    total = len(CASES) if not only else 1
    if failures:
        print(f"\n{len(failures)} of {total} notify-agent checks failed")
        return 1
    print(f"\nall {total} notify-agent checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
