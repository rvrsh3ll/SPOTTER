#!/usr/bin/env python3
"""
Smoke scenarios for workflow 23 (C2 Agent Roster), which backs the AGENTS tab.

Runs WF23's embedded Python code node on the host, skipping the n8n
import-and-restart cycle entirely (same approach as smoke_workflow12.py).

Two modes, because the interesting cases cannot be reached from the live graph:

  --live      Runs against the real Flowsint graph for the resolved campaign
              sketch. Today that graph holds zero C2Session nodes, so this
              proves the empty path returns a well-formed payload rather than
              throwing -- which is exactly what the tab renders on day one.

  (default)   Runs against synthetic fixtures covering what the graph will look
              like once a teamserver is wired up, and specifically the coercion
              traps that make this endpoint non-trivial:

                fixture              what it pins down
                -------------------  ---------------------------------------
                mixed_frameworks     a beacon and a badger are labelled apart
                string_false         is_dead='False' (a STRING) is not truthy
                tri_state_admin      is_admin None stays None, never False
                json_string_arrays   process_list stored as a JSON string
                reversed_edge        HAS_BEACON read in either orientation
                pivot_chain          PIVOTS_TO becomes parent/child topology
                legacy_props         beacon_id / cs_server COALESCE forward
                no_checkin           a timestamp-less session reads 'unknown'
                stale_vs_live        is_dead beats a fresh stamp; live sorts up
                clock_skew           a host 3 min fast is live, 10 h is a fault

Two things this harness must do or it silently "verifies" a no-op:

  1. WF23 line 4 is `sys.path.insert(0, '/data/scripts')`, which does not exist
     on the host, so `from c2_common import framework_display` would fail. We
     prepend the real scripts/ directory first.
  2. flowsint_client talks to `flowsint-neo4j-prod`, a name that only resolves
     inside the compose network. --live needs NEO4J_HTTP_URL pointed at the
     published port (http://127.0.0.1:7474).

Usage:
    python3 scripts/smoke_workflow23.py
    NEO4J_HTTP_URL=http://127.0.0.1:7474 python3 scripts/smoke_workflow23.py --live
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / "n8n-workflows" / "23-c2-agents.json"
CODE_NODE = "Build Agent Roster"

# Must come before the code node runs -- see docstring note 1.
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def load_code_node(path: Path, name: str) -> str:
    obj = json.loads(path.read_text())
    for node in obj.get("nodes", []):
        if node.get("name") == name:
            return node["parameters"]["pythonCode"]
    raise SystemExit(f"code node {name!r} not found in {path}")


def run_code_node(code: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Execute the node body the way n8n does: `_items` in scope, `return` at the
    end. n8n wraps the code in a function; exec() will not accept a bare return,
    so wrap it the same way before compiling."""
    wrapper = "def __node(_items):\n" + "".join(
        "    " + line + "\n" for line in code.splitlines()
    )
    ns: Dict[str, Any] = {}
    exec(compile(wrapper, "<wf23>", "exec"), ns)
    return ns["__node"](items)[0]["json"]


# ── Synthetic graph ──────────────────────────────────────────────────────────

def _node(nid: str, ntype: str, label: str, props: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": nid, "nodeType": ntype, "nodeLabel": label, "nodeProperties": props}


def _ago(minutes: float) -> str:
    """ISO check-in `minutes` in the past. Timestamps must be relative to now, not
    hard-coded: a fixed far-future date reads as a clock fault, and a fixed past
    one goes stale the moment the file ages."""
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


FRESH = _ago(1)          # inside the 30-minute live window
STALE = _ago(60 * 24)    # a day old
SKEWED = _ago(-3)        # host clock 3 minutes fast: still live
IMPOSSIBLE = _ago(-600)  # 10 hours in the future: a data fault, not a session


FIXTURES: Dict[str, Dict[str, Any]] = {
    "mixed_frameworks": {
        "nodes": [
            _node("s1", "C2Session", "Beacon:1234@WKS-01", {
                "c2_framework": "cobalt_strike", "session_id": "1234",
                "hostname": "WKS-01", "internal_ip": "10.0.0.5", "listener": "http-80",
                "pid": 4820, "is_admin": True, "priority_score": 70,
                "last_checkin": FRESH,
            }),
            _node("s2", "C2Session", "Badger:b-7@SRV-DB", {
                "c2_framework": "brute_ratel", "session_id": "b-7",
                "hostname": "SRV-DB", "internal_ip": "10.0.0.9", "listener": "https-443",
                "pid": 991, "thread_id": 12, "is_admin": False, "priority_score": 40,
                "last_checkin": FRESH,
            }),
            # Adaptix (WF28). The roster reads framework names from
            # c2_common.framework_display(), so a missing registry entry shows up
            # here as "Adaptix"/"Session" rather than "Adaptix C2"/"Agent".
            _node("s3", "C2Session", "Agent:a1b2c3d4@LAP-09", {
                "c2_framework": "adaptix", "session_id": "a1b2c3d4",
                "hostname": "LAP-09", "internal_ip": "10.0.0.31", "listener": "http-443",
                "pid": 4812, "thread_id": 9120, "is_admin": True, "priority_score": 55,
                "last_checkin": FRESH,
            }),
        ],
        "has_beacon": [
            {"source": "i1", "target": "s1", "source_label": "jsmith", "target_label": "Beacon:1234@WKS-01"},
        ],
        "pivots_to": [],
        "expect": lambda r: (
            {a["framework_label"] for a in r["agents"]}
                == {"Cobalt Strike", "Brute Ratel", "Adaptix C2"}
            and {a["agent_noun"] for a in r["agents"]} == {"Beacon", "Badger", "Agent"}
            and r["stats"]["by_framework"] == {"cobalt_strike": 1, "brute_ratel": 1, "adaptix": 1}
            and r["stats"]["live"] == 3
            and r["stats"]["admin"] == 2
        ),
    },
    "string_false": {
        # The trap: Flowsint can hand a declared boolean back as the STRING
        # 'False', which is truthy. bool('False') is True -> the session would be
        # reported dead while it is happily checking in.
        "nodes": [_node("s1", "C2Session", "Beacon:1@H", {
            "c2_framework": "cobalt_strike", "is_dead": "False", "is_pivot": "False",
            "hostname": "H", "last_checkin": FRESH,
        })],
        "has_beacon": [], "pivots_to": [],
        "expect": lambda r: (
            r["agents"][0]["is_dead"] is False
            and r["agents"][0]["is_pivot"] is False
            and r["agents"][0]["status"] == "live"
            and r["stats"]["dead"] == 0
        ),
    },
    "tri_state_admin": {
        "nodes": [
            _node("s1", "C2Session", "A", {"c2_framework": "cobalt_strike", "is_admin": None,
                                           "last_checkin": FRESH}),
            _node("s2", "C2Session", "B", {"c2_framework": "cobalt_strike", "is_admin": "False",
                                           "last_checkin": FRESH}),
            _node("s3", "C2Session", "C", {"c2_framework": "cobalt_strike", "is_admin": True,
                                           "last_checkin": FRESH}),
        ],
        "has_beacon": [], "pivots_to": [],
        "expect": lambda r: (
            # Identity, not equality: `False == 0` and `None`-vs-`False` are exactly
            # the distinction under test, so compare per node id.
            {a["id"]: a["is_admin"] for a in r["agents"]}
            == {"s1": None, "s2": False, "s3": True}
            and r["stats"]["admin"] == 1
        ),
    },
    "json_string_arrays": {
        "nodes": [_node("s1", "C2Session", "A", {
            "c2_framework": "brute_ratel",
            "process_list": '["explorer.exe", "chrome.exe"]',
            "tech_stack": '["Google Chrome"]',
            "last_checkin": FRESH,
        })],
        "has_beacon": [], "pivots_to": [],
        "expect": lambda r: (
            r["agents"][0]["process_list"] == ["explorer.exe", "chrome.exe"]
            and r["agents"][0]["tech_stack"] == ["Google Chrome"]
        ),
    },
    "reversed_edge": {
        # HAS_BEACON is written individual -> session, but nothing enforces it.
        "nodes": [_node("s1", "C2Session", "A", {"c2_framework": "cobalt_strike",
                                                 "last_checkin": FRESH})],
        "has_beacon": [{"source": "s1", "target": "i9", "source_label": "A", "target_label": "adoe"}],
        "pivots_to": [],
        "expect": lambda r: r["agents"][0]["owner_label"] == "adoe" and r["agents"][0]["owner_id"] == "i9",
    },
    "pivot_chain": {
        "nodes": [
            _node("s1", "C2Session", "Badger:b-1@EDGE", {"c2_framework": "brute_ratel",
                                                         "session_id": "b-1",
                                                         "last_checkin": FRESH}),
            _node("s2", "C2Session", "Badger:b-2@INNER", {"c2_framework": "brute_ratel",
                                                          "session_id": "b-2", "is_pivot": True,
                                                          "pivot_parent": "b-1", "pivot_channel": "smb",
                                                          "last_checkin": FRESH}),
        ],
        "has_beacon": [],
        "pivots_to": [{"source": "s1", "target": "s2", "source_label": "Badger:b-1@EDGE",
                       "target_label": "Badger:b-2@INNER"}],
        "expect": lambda r: (
            r["stats"]["pivots"] == 1
            and r["pivot_chains"][0]["parent_session_id"] == "b-1"
            and r["pivot_chains"][0]["child_session_id"] == "b-2"
            and r["pivot_chains"][0]["channel"] == "smb"
            and next(a for a in r["agents"] if a["id"] == "s1")["pivot_child_ids"] == ["s2"]
        ),
    },
    "legacy_props": {
        # Pre-migration nodes carry beacon_id / cs_server and the CobaltBeacon label.
        "nodes": [_node("s1", "CobaltBeacon", "Beacon:77@OLD", {
            "c2_framework": "cobalt_strike", "beacon_id": "77", "cs_server": "https://ts:50050",
            "last_checkin": FRESH,
        })],
        "has_beacon": [], "pivots_to": [],
        "expect": lambda r: (
            len(r["agents"]) == 1
            and r["agents"][0]["session_id"] == "77"
            and r["agents"][0]["c2_server"] == "https://ts:50050"
        ),
    },
    "no_checkin": {
        "nodes": [_node("s1", "C2Session", "A", {"c2_framework": "cobalt_strike"})],
        "has_beacon": [], "pivots_to": [],
        "expect": lambda r: (
            r["agents"][0]["status"] == "unknown"
            and r["agents"][0]["age_minutes"] is None
            and r["stats"]["unknown"] == 1
            and r["stats"]["live"] == 0
        ),
    },
    "stale_vs_live": {
        "nodes": [
            _node("s1", "C2Session", "fresh", {"c2_framework": "cobalt_strike",
                                               "last_checkin": FRESH}),
            _node("s2", "C2Session", "old", {"c2_framework": "cobalt_strike",
                                             "last_checkin": STALE}),
            _node("s3", "C2Session", "gone", {"c2_framework": "cobalt_strike", "is_dead": True,
                                              "last_checkin": FRESH}),
        ],
        "has_beacon": [], "pivots_to": [],
        "expect": lambda r: (
            r["stats"]["live"] == 1 and r["stats"]["stale"] == 1 and r["stats"]["dead"] == 1
            # is_dead wins over a fresh timestamp
            and next(a for a in r["agents"] if a["id"] == "s3")["status"] == "dead"
            # live sorts ahead of stale/dead
            and r["agents"][0]["status"] == "live"
        ),
    },
    "clock_skew": {
        # A target host whose clock runs a few minutes fast stamps a check-in in
        # SPOTTER's future. The enricher's bare `0 <= age` test calls that stale
        # while the beacon is actively calling home; WF23 tolerates the drift but
        # refuses to guess about a timestamp hours ahead.
        "nodes": [
            _node("s1", "C2Session", "skewed", {"c2_framework": "cobalt_strike",
                                                "last_checkin": SKEWED}),
            _node("s2", "C2Session", "impossible", {"c2_framework": "cobalt_strike",
                                                    "last_checkin": IMPOSSIBLE}),
        ],
        "has_beacon": [], "pivots_to": [],
        "expect": lambda r: (
            next(a for a in r["agents"] if a["id"] == "s1")["status"] == "live"
            and next(a for a in r["agents"] if a["id"] == "s2")["status"] == "unknown"
            and r["stats"]["stale"] == 0
        ),
    },
}


class _FakeClient:
    """Stands in for flowsint_client so a fixture graph can be served without
    touching Neo4j. Only the three readers WF23 calls are implemented."""

    def __init__(self, fx: Dict[str, Any]):
        self.fx = fx

    def get_nodes_by_type(self, labels, sketch_id=None, properties=None, timeout=60):
        want = {str(x).lower() for x in (labels if isinstance(labels, list) else [labels])}
        return [n for n in self.fx["nodes"] if str(n["nodeType"]).lower() in want]

    def get_edges_by_type(self, rel_types, sketch_id=None, resolve_endpoints=False, timeout=60, **kw):
        rts = rel_types if isinstance(rel_types, list) else [rel_types]
        out: List[Dict[str, Any]] = []
        for rt in rts:
            out += self.fx["has_beacon"] if rt == "HAS_BEACON" else self.fx["pivots_to"] if rt == "PIVOTS_TO" else []
        return out


def run_fixtures(code: str, only: str | None) -> int:
    failures = 0
    for name, fx in FIXTURES.items():
        if only and only != name:
            continue
        real = sys.modules.get("flowsint_client")
        sys.modules["flowsint_client"] = _FakeClient(fx)  # type: ignore[assignment]
        try:
            result = run_code_node(code, [{"json": {"body": {"sketch_id": "fixture"}}}])
        except Exception as exc:  # noqa: BLE001 - report, keep going
            print(f"  FAIL {name}: raised {type(exc).__name__}: {exc}")
            failures += 1
            continue
        finally:
            if real is not None:
                sys.modules["flowsint_client"] = real
            else:
                sys.modules.pop("flowsint_client", None)

        if result.get("errors"):
            print(f"  FAIL {name}: endpoint reported errors {result['errors']}")
            failures += 1
        elif fx["expect"](result):
            print(f"  ok   {name}")
        else:
            print(f"  FAIL {name}")
            print("       " + json.dumps(result["stats"], sort_keys=True))
            for a in result["agents"]:
                print("       " + json.dumps(
                    {k: a[k] for k in ("id", "framework_label", "agent_noun", "status",
                                       "is_admin", "is_dead", "owner_label", "session_id")}))
            failures += 1
    return failures


def run_live(code: str) -> int:
    import flowsint_client as fc

    sketch = fc.resolve_campaign_sketch()
    print(f"  sketch {sketch}")
    result = run_code_node(code, [{"json": {"body": {"sketch_id": sketch}}}])
    if result.get("errors"):
        print(f"  FAIL live: {result['errors']}")
        return 1
    stats = result["stats"]
    print(f"  ok   live: {stats['total']} agents "
          f"(live={stats['live']} stale={stats['stale']} dead={stats['dead']} "
          f"unknown={stats['unknown']} pivots={stats['pivots']}) "
          f"by_framework={stats['by_framework']}")
    # The payload must be JSON-serialisable or respondToWebhook returns a 500.
    json.dumps(result)
    print("  ok   live: payload is JSON-serialisable")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true",
                    help="also run against the live graph (needs NEO4J_HTTP_URL reachable)")
    ap.add_argument("--only", help="run a single fixture by name")
    args = ap.parse_args()

    code = load_code_node(WORKFLOW_PATH, CODE_NODE)
    print(f"WF23 {CODE_NODE}: {len(code.splitlines())} lines")

    print("fixtures:")
    failures = run_fixtures(code, args.only)

    if args.live:
        print("live graph:")
        failures += run_live(code)

    print("FAILED" if failures else "PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
