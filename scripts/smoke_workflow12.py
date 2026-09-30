#!/usr/bin/env python3
"""
Smoke scenarios for workflow 12 (Tech Inventory) against the LIVE Flowsint graph.

Runs WF12's embedded Python code node on the host, skipping the n8n
import-and-restart cycle entirely. The graph is fetched once and reused across
scenarios, so the 130k-node pull only happens on the first run.

Scenarios:
  no_filter    active_only=false  → every device, filter reported as not applied
  strict       default            → only hosts seen within --activity-days
  no_timestamp props stripped     → filter must DISABLE itself, not empty the tab
  paste        pasted_processes   → process names resolve to technologies

Three things this harness must do or it silently "verifies" a no-op:

  1. WF12 line 2 is `sys.path.insert(0, '/data/scripts')`, which does not exist on
     the host. Python ignores a missing path, so `from cobalt_normalizer import
     infer_tech_stack` falls through to WF12's own no-op stub and every tech list
     comes back empty. We prepend the real scripts/ directory first.
  2. It must intercept WF12's graph reads at flowsint_client, not at requests.get.
     WF12 reads Neo4j directly now (fc.get_nodes_by_type / get_edges_by_type); the
     old requests.get stub caught nothing, so scenarios re-read the live database and
     the graph-mutation scenarios asserted against unmodified data. See ReaderCache.
  3. NEO4J_HTTP_URL must point at loopback, and be set BEFORE flowsint_client is
     imported (it reads the value into a module constant at import time). The
     in-cluster hostname does not resolve from the host. Defaulted below.

It loads the repo env itself -- no `set -a; . ./.env` needed. (That never really
worked: .env is not shell-sourceable, because EDGAR_USER_AGENT carries unquoted
parens. It works even less now that FLOWSINT_API_KEY lives encrypted in
secrets/machine.sops.env rather than in .env.)

    python3 scripts/smoke_workflow12.py --sketch-id <uuid>

Usage:
    python3 scripts/smoke_workflow12.py --sketch-id <uuid>

Environment (same names WF12 reads):
    FLOWSINT_API_URL, FLOWSINT_API_KEY, OLLAMA_URL
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / "n8n-workflows" / "12-tech-inventory.json"
CODE_NODE = "Build Tech Inventory + Narratives"

# Must come before the code node runs — see docstring note 1.
sys.path.insert(0, str(REPO_ROOT / "scripts"))

# flowsint_client reads NEO4J_* into module-level constants AT IMPORT TIME, so this
# has to happen before the import below or it has no effect.
#
# A plain setdefault is not enough: the documented way to run this is
# `set -a; . ./.env; set +a`, and .env carries the in-cluster hostnames
# (flowsint-neo4j-prod, ollama) which do not resolve on the host. So rewrite any
# service URL whose host cannot be resolved to the loopback port it is published on.
# Populate os.environ from .env + the decrypted secret tiers. Must run before the
# flowsint_client import below, which reads API_URL/API_KEY/NEO4J_* into
# module-level constants at import time.
try:
    import spotter_env as _se
    _se.export_into_environ()
except Exception as _exc:                       # not split yet, or no age key
    print(f"note: could not load the repo env ({_exc}); relying on the ambient environment")

_LOOPBACK_FALLBACK = {
    "NEO4J_HTTP_URL": "http://127.0.0.1:7474",
    "OLLAMA_URL":     "http://127.0.0.1:8001",
}


def _host_resolves(url: str) -> bool:
    import socket
    from urllib.parse import urlparse
    host = urlparse(url).hostname
    if not host:
        return False
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


for _var, _fallback in _LOOPBACK_FALLBACK.items():
    _cur = os.environ.get(_var, "")
    if not _cur:
        os.environ[_var] = _fallback
    elif not _host_resolves(_cur):
        print(f"note: {_var}={_cur} does not resolve from the host; using {_fallback}")
        os.environ[_var] = _fallback

import flowsint_client as fc  # noqa: E402  (must follow the env defaults above)

# Bound before any scenario patches them, so the cache calls the real readers.
_real_get_nodes_by_type = fc.get_nodes_by_type
_real_get_edges_by_type = fc.get_edges_by_type

# Properties the activity filter depends on. The no_timestamp scenario strips
# these to simulate a graph that was never backfilled.
ACTIVITY_PROPS = (
    "last_activity_ts", "last_logon_timestamp", "last_logon",
    "pwd_last_set", "when_created", "activity_source",
)


def load_workflow_code_nodes(path: Path) -> Dict[str, str]:
    obj = json.loads(path.read_text())
    return {
        node.get("name", ""): node.get("parameters", {}).get("pythonCode", "")
        for node in obj.get("nodes", [])
        if node.get("type") == "n8n-nodes-base.code"
    }


def run_n8n_python_code(code: str, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    fn_name = "__n8n_exec"
    wrapped = f"def {fn_name}(_items):\n" + textwrap.indent(code, "    ")
    ns: Dict[str, Any] = {}
    exec(compile(wrapped, "<n8n_code>", "exec"), ns, ns)
    return ns[fn_name](items)


class ReaderCache:
    """
    Memoize flowsint_client's Neo4j readers, keyed by call signature.

    WF12 reads the graph through fc.get_nodes_by_type / fc.get_edges_by_type (six
    calls). This calls each one for real the first time and replays the result on
    every later scenario, so the expensive reads happen once per run.

    Why this replaced a requests.get stub: WF12 used to fetch GET /graph, so pinning
    requests.get was enough. It now reads Neo4j directly with requests.POST, which
    the old stub never intercepted -- so every scenario silently re-read the live
    database, strip_activity mutated an object nothing looked at, and the three
    scenarios built on a mutated graph asserted against unmodified data. They
    reported failures that said nothing about WF12.

    Interposing here rather than on requests also drops the 100k-node truncation in
    GET /graph: a large live sketch has well over 100k nodes, so the old harness
    was testing WF12 against a silently truncated graph.
    """

    def __init__(self) -> None:
        self._nodes: Dict[Any, List[Dict[str, Any]]] = {}
        self._edges: Dict[Any, Any] = {}
        self.primed = False

    @staticmethod
    def _key(first: Any, kwargs: Dict[str, Any]) -> Any:
        # timeout does not change the result, so calls that differ only by it share
        # a cache entry.
        return (repr(first), tuple(sorted(
            (k, repr(v)) for k, v in kwargs.items() if k != "timeout"
        )))

    def nodes_by_type(self, labels: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        key = self._key(labels, kwargs)
        if key not in self._nodes:
            self._nodes[key] = _real_get_nodes_by_type(labels, **kwargs)
        return self._nodes[key]

    def edges_by_type(self, rel_types: Any, **kwargs: Any) -> Any:
        key = self._key(rel_types, kwargs)
        if key not in self._edges:
            self._edges[key] = _real_get_edges_by_type(rel_types, **kwargs)
        return self._edges[key]

    def report(self) -> None:
        n = sum(len(v) for v in self._nodes.values())
        print(f"  cached {n} nodes across {len(self._nodes)} node read(s), "
              f"{len(self._edges)} edge read(s)\n", flush=True)


def strip_activity(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Return a deep copy of a node list with every device activity property removed.

    Deep-copied because the caller hands out cached lists: mutating in place would
    leak the stripped graph into every later scenario.
    """
    out = copy.deepcopy(nodes)
    for node in out:
        if (node.get("nodeType") or "").lower() != "device":
            continue
        props = node.get("nodeProperties") or node.get("data") or {}
        for key in ACTIVITY_PROPS:
            props.pop(key, None)
    return out


def run_scenario(
    code: str,
    cache: "ReaderCache",
    body: Dict[str, Any],
    node_filter: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Execute the code node with WF12's Neo4j readers served from `cache`.

    node_filter, when given, transforms the node list the code node sees -- that is
    how the no_timestamp scenario simulates a graph that was never backfilled.
    """
    def nodes_by_type(labels: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        out = cache.nodes_by_type(labels, **kwargs)
        return node_filter(out) if node_filter else out

    real_nodes = fc.get_nodes_by_type
    real_edges = fc.get_edges_by_type
    fc.get_nodes_by_type = nodes_by_type       # type: ignore[assignment]
    fc.get_edges_by_type = cache.edges_by_type  # type: ignore[assignment]
    try:
        result = run_n8n_python_code(code, [{"json": body}])
    finally:
        fc.get_nodes_by_type = real_nodes       # type: ignore[assignment]
        fc.get_edges_by_type = real_edges       # type: ignore[assignment]
    return result[0]["json"]


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' — ' + detail) if detail else ''}")
    return ok


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sketch-id", default=os.environ.get("FLOWSINT_SKETCH_ID", ""))
    ap.add_argument("--api-url", default=os.environ.get("FLOWSINT_API_URL", "http://127.0.0.1:5001"))
    ap.add_argument("--api-key", default=os.environ.get("FLOWSINT_API_KEY", ""))
    ap.add_argument("--activity-days", type=int, default=90)
    args = ap.parse_args(argv)

    if not args.sketch_id:
        print("error: --sketch-id is required", file=sys.stderr)
        return 2

    os.environ["FLOWSINT_API_URL"] = args.api_url
    os.environ["FLOWSINT_API_KEY"] = args.api_key
    if not os.environ.get("NEO4J_PASSWORD"):
        print("error: NEO4J_PASSWORD is not set — the graph reads will all 401.\n"
              "       run with:  set -a; . ./.env; set +a", file=sys.stderr)
        return 2

    code = load_workflow_code_nodes(WORKFLOW_PATH).get(CODE_NODE, "")
    if not code:
        print(f"error: code node {CODE_NODE!r} not found", file=sys.stderr)
        return 2

    print(f"reading graph for {args.sketch_id} via {os.environ['NEO4J_HTTP_URL']} ...", flush=True)
    cache = ReaderCache()
    base = {"sketch_id": args.sketch_id, "activity_days": args.activity_days}
    passed = True

    # ── no_filter ─────────────────────────────────────────────────────────────
    print("scenario: no_filter (active_only=false)")
    d = run_scenario(code, cache, {**base, "active_only": False})
    if d.get("error"):
        print(f"  FATAL: code node returned an error: {d['error']}", file=sys.stderr)
        return 2
    cache.report()
    total_all = d.get("total_devices_all")
    passed &= check("filter not applied", d.get("activity_filter_applied") is False)
    passed &= check("all devices returned", d.get("total_devices") == total_all,
                    f"{d.get('total_devices')} == {total_all}")
    passed &= check("mode is off", d.get("activity_mode") == "off", str(d.get("activity_mode")))

    # ── strict ────────────────────────────────────────────────────────────────
    print("\nscenario: strict (default)")
    s = run_scenario(code, cache, {**base, "active_only": True})
    passed &= check("filter applied", s.get("activity_filter_applied") is True)
    passed &= check("mode is strict", s.get("activity_mode") == "strict", str(s.get("activity_mode")))
    passed &= check("coverage is 100%", s.get("activity_coverage_pct") == 100.0,
                    f"{s.get('activity_coverage_pct')}%")
    passed &= check("active + stale == all",
                    (s.get("total_devices") or 0) + (s.get("stale_device_count") or 0) == total_all,
                    f"{s.get('total_devices')} + {s.get('stale_device_count')} == {total_all}")
    passed &= check("fewer devices than unfiltered", (s.get("total_devices") or 0) < (total_all or 0),
                    f"{s.get('total_devices')} < {total_all}")
    for key in ("os_device_map", "device_dossier_map", "os_inventory"):
        passed &= check(f"{key} non-empty", bool(s.get(key)), f"{len(s.get(key) or [])} entries")
    # legacy_systems lists only EOL hosts that SURVIVED the activity filter, so empty
    # is a legitimate result: nothing end-of-life has logged on inside --activity-days.
    # Asserting non-empty unconditionally failed on exactly that (6,583 EOL devices in
    # the sketch, none of them active). Tie it to the filtered population instead.
    if s.get("eol_device_count"):
        passed &= check("legacy_systems non-empty when EOL hosts are active",
                        bool(s.get("legacy_systems")),
                        f"{len(s.get('legacy_systems') or [])} entries")
    else:
        print(f"  [SKIP] legacy_systems - no EOL host active within "
              f"{args.activity_days}d (unfiltered EOL count {d.get('eol_device_count')})")
    passed &= check("stale_devices capped at 200", len(s.get("stale_devices") or []) <= 200)
    passed &= check("stale entries carry day counts",
                    any(x.get("days_since_seen") for x in (s.get("stale_devices") or [])[:20]))

    print(f"\n  devices {total_all} -> {s.get('total_devices')} "
          f"(stale {s.get('stale_device_count')}, unknown {s.get('unknown_activity_count')})")
    print(f"  eol_device_count {d.get('eol_device_count')} -> {s.get('eol_device_count')}")

    # ── no_timestamp ──────────────────────────────────────────────────────────
    # The regression that matters: a graph with no freshness data must render in
    # full with the filter off, not come back empty.
    print("\nscenario: no_timestamp (never backfilled)")
    n = run_scenario(code, cache, {**base, "active_only": True}, node_filter=strip_activity)
    passed &= check("filter disabled itself", n.get("activity_filter_applied") is False)
    passed &= check("reason is no_timestamp_data", n.get("activity_filter_reason") == "no_timestamp_data",
                    str(n.get("activity_filter_reason")))
    passed &= check("all devices still returned", n.get("total_devices") == total_all,
                    f"{n.get('total_devices')} == {total_all}")
    passed &= check("os_inventory still populated", bool(n.get("os_inventory")))

    # ── paste ─────────────────────────────────────────────────────────────────
    # WF12 no longer treats the body as the only source of pasted processes. Extraction
    # moved server-side to ingest (upload_router._parse_process_list), which writes a
    # Device carrying process_list plus Technology nodes, and WF12 merges those graph
    # hosts with anything still posted on the body. So the body's 5 processes / 1 host
    # are a SUBSET of what comes back -- the old `== 5` and `== 1` assertions described
    # the body-only design and failed against the real 104 / 2. Assert inclusion, and
    # keep a unique marker process so the body's contribution is identifiable.
    print("\nscenario: paste (pasted process listing)")
    # Prefix sorts before any real process name. WF12 caps `unmatched` at 50 entries
    # AFTER sorting across all hosts, so a marker sorting late ('zzz-') gets truncated
    # away by real graph data and the assertion below degrades to a permanent skip.
    MARKER = "000-smoke-marker-not-real.exe"
    BODY_PROCS = ["ssms.exe", "pcomm.exe", "KeePass.exe", "chrome.exe", MARKER]
    p = run_scenario(code, cache, {
        **base, "active_only": True,
        "analyst_context": "Observed on the finance workstation during the 06 Aug session.",
        "pasted_processes": [{"host": "WS01", "processes": BODY_PROCS}],
    })
    pp = p.get("pasted_processes") or {}
    catalog = p.get("tech_catalog") or {}
    passed &= check("body processes counted", (pp.get("process_count") or 0) >= len(BODY_PROCS),
                    f"{pp.get('process_count')} >= {len(BODY_PROCS)}")
    passed &= check("body host present", "WS01" in (pp.get("hosts") or []),
                    f"hosts={(pp.get('hosts') or [])[:4]}")
    passed &= check("graph hosts merged in too", (pp.get("host_count") or 0) >= 1,
                    f"host_count={pp.get('host_count')}")
    passed &= check("tech resolved from process names", len(pp.get("tech") or []) >= 3,
                    ", ".join((pp.get("tech") or [])[:6]))
    passed &= check("tech landed in catalog", all(t in catalog for t in (pp.get("tech") or [])))
    # `unmatched` is sorted then capped at 50 across ALL hosts, so a marker that sorts
    # late can be truncated away by real graph data. Sorting it last ('zzz-') is not a
    # guarantee, so treat truncation as a skip rather than a failure.
    unmatched = pp.get("unmatched") or []
    if MARKER in unmatched:
        passed &= check("unmatched name reported", True, f"{len(unmatched)} unmatched")
    elif len(unmatched) >= 50:
        # Absent AND capped: truncation is a sufficient explanation, so this is not
        # evidence of a bug. Only skip in that order -- checking the cap first would
        # skip even when the marker is sitting in the list.
        print(f"  [SKIP] unmatched marker - absent but list hit its 50-entry cap")
    else:
        passed &= check("unmatched name reported", False,
                        f"absent from {len(unmatched)} uncapped entries")
    # Provenance label is '(process listing)'; it was '(analyst paste)' when extraction
    # ran in the browser.
    passed &= check("provenance in tech_user_map", any(
        e.get("user") == "(process listing)"
        for t in (pp.get("tech") or [])
        for e in (p.get("tech_user_map") or {}).get(t, [])
    ))
    passed &= check("analyst context length echoed", (p.get("analyst_context_chars") or 0) > 0)

    print("\n" + ("ALL SCENARIOS PASSED" if passed else "FAILURES PRESENT"))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
