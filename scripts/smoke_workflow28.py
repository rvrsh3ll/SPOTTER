#!/usr/bin/env python3
"""
Smoke scenarios for workflow 28 (Adaptix C2 Ingestor).

Runs WF28's embedded Python code nodes on the host, skipping the n8n
import-and-restart cycle entirely (same approach as smoke_workflow23.py).
Everything is offline: no teamserver, no n8n, no Neo4j.

`scripts/smoke_adaptix.py` covers the normalizer's field mapping. This file
covers the *node code* around it -- the parts that only exist inside the JSON and
that no unit test of the module would reach:

    fixture                    what it pins down
    -------------------------  ------------------------------------------------
    unconfigured_noop          a REPLACE_WITH_* .env never opens a connection
    partial_config             one missing var still no-ops, and says which
    fetch_failure_emits_none   a failed poll returns ZERO items, not a sentinel
    roster_unwrapping          {"agents":[...]}, bare list and {"data":[...]}
    idless_agent_dropped       an agent with no a_id can never reach the graph
    upsert_namespace           edit_node patches are nodeProperties.-prefixed
    upsert_empty_guard         an empty process_list never overwrites enrichment
    create_path_keeps_lists    ...but the CREATE path keeps them, typed
    tech_node_has_name         Technology always carries the required `name`
    no_pivot_edge_without_parent   PIVOTS_TO is not invented from a channel

Two things this harness must do or it silently "verifies" a no-op:

  1. WF28's nodes begin `sys.path.insert(0, '/data/scripts')`, which does not
     exist on the host, so `from adaptix_normalizer import ...` would fail. We
     prepend the real scripts/ directory first.
  2. flowsint_client would talk to the compose network. A fake is swapped into
     sys.modules so the upsert/relationship nodes record calls instead.

Usage:
    python3 scripts/smoke_workflow28.py
    python3 scripts/smoke_workflow28.py --only upsert_namespace
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / "n8n-workflows" / "28-adaptix-ingestor.json"

# Must come before any node runs -- see docstring note 1.
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def load_code_node(name: str) -> str:
    obj = json.loads(WORKFLOW_PATH.read_text())
    for node in obj.get("nodes", []):
        if node.get("name") == name:
            return node["parameters"]["pythonCode"]
    raise SystemExit(f"code node {name!r} not found in {WORKFLOW_PATH}")


def run_code_node(code: str, items: List[Dict[str, Any]], env: Dict[str, str] = None):
    """Execute the node body the way n8n does: `_items` in scope, `return` at the
    end. n8n wraps the code in a function; exec() will not accept a bare return,
    so wrap it the same way before compiling."""
    import os
    saved = {}
    for k, v in (env or {}).items():
        saved[k] = os.environ.get(k)
        os.environ[k] = v
    try:
        wrapper = "def __node(_items):\n" + "".join(
            "    " + line + "\n" for line in code.splitlines()
        )
        ns: Dict[str, Any] = {}
        exec(compile(wrapper, "<wf28>", "exec"), ns)
        return ns["__node"](items)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ── Fake flowsint_client ──────────────────────────────────────────────────────

class FakeClient:
    """Records every graph write so a node's behaviour can be asserted on."""

    def __init__(self, existing_nodes=None):
        self.existing_nodes = existing_nodes or []
        self.added: List[Dict[str, Any]] = []
        self.edited: List[Dict[str, Any]] = []
        self.edges: List[tuple] = []
        self._next = 0

    def resolve_campaign_sketch(self, *a, **k):
        return "sketch-under-test"

    def get_nodes_by_type(self, types_, sketch_id=None, **k):
        want = {t.lower() for t in types_}
        return [n for n in self.existing_nodes
                if (n.get("nodeType") or "").lower() in want]

    def get_edges_by_type(self, *a, **k):
        return []

    def search_nodes(self, *a, **k):
        return []

    def add_node(self, label, node_type, properties, sketch_id=None, **k):
        self._next += 1
        nid = f"new-{self._next}"
        self.added.append({"id": nid, "label": label, "node_type": node_type,
                           "properties": properties})
        return {"id": nid}

    def edit_node(self, node_id, updates, sketch_id=None, **k):
        self.edited.append({"id": node_id, "updates": updates})
        return {"id": node_id}

    def create_edge(self, src, dst, kind, sketch_id=None, **k):
        self.edges.append((src, dst, kind))
        return {"ok": True}


def install_fake(fc: FakeClient):
    mod = types.ModuleType("flowsint_client")
    for name in ("resolve_campaign_sketch", "get_nodes_by_type", "get_edges_by_type",
                 "search_nodes", "add_node", "edit_node", "create_edge"):
        setattr(mod, name, getattr(fc, name))
    sys.modules["flowsint_client"] = mod
    return fc


PLACEHOLDER_ENV = {
    "ADAPTIX_API_URL": "REPLACE_WITH_ADAPTIX_API_URL",
    "ADAPTIX_USERNAME": "REPLACE_WITH_ADAPTIX_USERNAME",
    "ADAPTIX_PASSWORD": "REPLACE_WITH_ADAPTIX_PASSWORD",
}

FETCH     = load_code_node("Fetch Adaptix Agents")
NORMALISE = load_code_node("Normalise Agents")
DEDUP     = load_code_node("Dedup Check")
UPSERT    = load_code_node("Upsert Individual + Session")
RELS      = load_code_node("Create Relationships")


def _agent_item(**over):
    """A normalised agent as it leaves the Normalise node."""
    base = {
        "c2_framework": "adaptix", "session_id": "a1b2c3d4",
        "session_key": "adaptix:a1b2c3d4", "c2_server": "https://ts:4321/endpoint",
        "hostname": "WS-014", "username": "CORP\\jdoe", "sam_account_name": "jdoe",
        "internal_ip": "10.0.0.5", "external_ip": "203.0.113.9",
        "os_version": "Windows", "arch": "x64", "pid": 4812, "thread_id": 9120,
        "process_name": "explorer.exe", "is_admin": True,
        "last_checkin": "2026-09-07T10:00:00+00:00", "sleep_seconds": 60,
        "jitter_pct": 15, "listener": "http-443", "note": "",
        "priority_score": 15, "process_list": [], "tech_stack": [],
        "is_dead": False, "is_pivot": False, "pivot_parent": "", "pivot_channel": "",
        "source": "adaptix",
    }
    base.update(over)
    return {"json": base}


# ── Cases ─────────────────────────────────────────────────────────────────────

def case_unconfigured_noop():
    """
    A stock .env must never open a socket.

    Every REPLACE_WITH_* value is 'not configured', and the fetch reports that
    rather than spending a connection attempt on every 5-minute tick forever.
    """
    out = run_code_node(FETCH, [], PLACEHOLDER_ENV)
    j = out[0]["json"]
    assert j["fetch_ok"] is False, j
    assert j["configured"] is False, j
    assert j["agents"] == [], j
    assert "ADAPTIX_API_URL" in j["error"], j["error"]


def case_partial_config():
    """A half-filled .env must name the var that is still a placeholder."""
    env = dict(PLACEHOLDER_ENV, ADAPTIX_API_URL="https://ts:4321/endpoint")
    j = run_code_node(FETCH, [], env)[0]["json"]
    assert j["configured"] is False and "ADAPTIX_USERNAME" in j["error"], j

    env["ADAPTIX_USERNAME"] = "operator"
    j = run_code_node(FETCH, [], env)[0]["json"]
    assert j["configured"] is False and "ADAPTIX_PASSWORD" in j["error"], j

    # An empty URL is as unconfigured as a placeholder one.
    j = run_code_node(FETCH, [], dict(env, ADAPTIX_API_URL=""))[0]["json"]
    assert j["configured"] is False, j


def case_fetch_failure_emits_none():
    """
    A failed poll must emit ZERO items, never a sentinel.

    Everything downstream reads the graph and writes to it. Passing a sentinel
    through would make every failed poll pay that cost, and on a 5-minute
    schedule the runs then overlap and pile up until the execution timeout --
    the bug WF01 shipped with.
    """
    items = [{"json": {"fetch_ok": False, "error": "boom", "agents": []}}]
    assert run_code_node(NORMALISE, items) == [], "a failed fetch must yield no items"


def case_roster_unwrapping():
    """
    The Normalise node accepts the roster however the fetch node hands it over.

    The fetch node already unwraps {"agents"|"data"|"items": [...]} into a bare
    list, so what arrives here is that list -- but a pinned item or a manual run
    can present the raw dict, and neither must crash the node.
    """
    raw = {"a_id": "x1", "a_computer": "H1", "a_username": "u"}
    env = {"ADAPTIX_API_URL": "https://ts/endpoint"}

    for agents in ([raw], raw):
        items = [{"json": {"fetch_ok": True, "error": "", "agents": agents}}]
        out = run_code_node(NORMALISE, items, env)
        assert len(out) == 1, f"{agents} → {out}"
        assert out[0]["json"]["session_key"] == "adaptix:x1", out

    # An empty roster is a normal quiet teamserver, not an error.
    assert run_code_node(
        NORMALISE, [{"json": {"fetch_ok": True, "error": "", "agents": []}}], env) == []


def case_idless_agent_dropped():
    """
    An agent with no a_id must never reach the graph.

    session_key would collapse to 'adaptix:' for every such record, and add_node
    MERGEs on the label -- so they would all fold onto a single node, and the
    write would report success each time.
    """
    items = [{"json": {"fetch_ok": True, "error": "", "agents": [
        {"a_id": "good", "a_computer": "H1"},
        {"a_computer": "H2"},            # no a_id
        {"a_id": "", "a_computer": "H3"},  # empty a_id
    ]}}]
    out = run_code_node(NORMALISE, items, {"ADAPTIX_API_URL": "https://ts/endpoint"})
    assert len(out) == 1, [o["json"].get("session_key") for o in out]
    assert out[0]["json"]["session_id"] == "good"


def case_upsert_namespace():
    """
    Patches to an EXISTING node must be nodeProperties.-prefixed.

    edit_node passes `updates` through verbatim, so a bare key lands at the
    node's top level -- a second namespace get_nodes_by_type, the dossier query
    and the AGENTS roster all read straight past. The write reports success and
    the value really is in Neo4j, just nowhere anything looks, which is why a
    re-checked-in agent kept its first-contact last_checkin forever.
    """
    fc = install_fake(FakeClient(existing_nodes=[
        {"id": "s-old", "nodeType": "C2Session", "nodeLabel": "Agent:a1b2c3d4@WS-014",
         "nodeProperties": {"session_key": "adaptix:a1b2c3d4"}},
        {"id": "i-old", "nodeType": "individual", "nodeLabel": "jdoe",
         "nodeProperties": {"sam_account_name": "jdoe"}},
    ]))
    deduped = run_code_node(DEDUP, [_agent_item()])
    assert deduped[0]["json"]["_existing_session_id"] == "s-old", deduped[0]["json"]
    assert deduped[0]["json"]["_existing_individual_id"] == "i-old"

    run_code_node(UPSERT, deduped)
    assert fc.edited, "an existing session must be patched, not re-created"
    assert not fc.added, f"nothing should be created: {fc.added}"
    for patch in fc.edited:
        for key in patch["updates"]:
            assert key.startswith("nodeProperties."), f"unprefixed patch key: {key}"
    session_patch = next(p for p in fc.edited if p["id"] == "s-old")["updates"]
    assert session_patch["nodeProperties.last_checkin"] == "2026-09-07T10:00:00+00:00"


def case_upsert_empty_guard():
    """
    An empty process_list must never overwrite enrichment on an existing node.

    /agent/list carries no process list -- that only arrives from a `ps` task --
    so an unguarded patch would wipe tech_stack every 5 minutes. False and 0 are
    real values and must survive the same filter.
    """
    fc = install_fake(FakeClient(existing_nodes=[
        {"id": "s-old", "nodeType": "C2Session", "nodeLabel": "x",
         "nodeProperties": {"session_key": "adaptix:a1b2c3d4"}},
    ]))
    deduped = run_code_node(DEDUP, [_agent_item(is_dead=False, priority_score=0)])
    run_code_node(UPSERT, deduped)

    patch = next(p for p in fc.edited if p["id"] == "s-old")["updates"]
    assert "nodeProperties.process_list" not in patch, "empty list must be dropped"
    assert "nodeProperties.tech_stack" not in patch, "empty list must be dropped"
    # ...but falsey-yet-real values are NOT empties.
    assert patch["nodeProperties.is_dead"] is False, patch
    assert patch["nodeProperties.priority_score"] == 0, patch


def case_create_path_keeps_lists():
    """
    The CREATE path keeps the empty lists so the property exists, correctly typed.

    Dropping them here would leave process_list absent rather than [], and the
    readers that coerce it (WF23's _list) would then be guessing.
    """
    fc = install_fake(FakeClient())
    deduped = run_code_node(DEDUP, [_agent_item()])
    run_code_node(UPSERT, deduped)

    session = next(a for a in fc.added if a["node_type"] == "C2Session")
    assert session["properties"]["process_list"] == [], session["properties"]
    assert session["properties"]["tech_stack"] == [], session["properties"]
    assert session["properties"]["c2_framework"] == "adaptix"
    assert session["label"] == "Agent:a1b2c3d4@WS-014", session["label"]

    # 'individual' must be lowercase: Neo4j labels are case-sensitive and a
    # capitalised one is invisible to this workflow's own dedup.
    ind = next(a for a in fc.added if a["node_type"] == "individual")
    assert ind["node_type"] == "individual", ind


def case_tech_node_has_name():
    """
    Technology nodes must always carry `name`.

    It is REQUIRED on the built-in type, and a single name-less Technology node
    makes GET /graph return 500 for the ENTIRE sketch.
    """
    fc = install_fake(FakeClient())
    deduped = run_code_node(DEDUP, [_agent_item(tech_stack=["Microsoft SQL Server"])])
    upserted = run_code_node(UPSERT, deduped)
    run_code_node(RELS, upserted)

    tech = [a for a in fc.added if a["node_type"] == "Technology"]
    assert tech, "a tech_stack entry must create a Technology node"
    assert tech[0]["properties"]["name"] == "Microsoft SQL Server", tech[0]
    assert any(k == "USES_TECH" for _, _, k in fc.edges), fc.edges
    assert any(k == "HAS_BEACON" for _, _, k in fc.edges), fc.edges


def case_no_pivot_edge_without_parent():
    """
    A pivot channel alone must not produce a PIVOTS_TO edge.

    /agent/list reports no parent-agent id, so the channel is all we know.
    Inventing a parent would fabricate a relayed-through relationship between
    agents that share nothing but a listener type.
    """
    fc = install_fake(FakeClient())
    deduped = run_code_node(DEDUP, [_agent_item(is_pivot=True, pivot_channel="smb",
                                                pivot_parent="")])
    upserted = run_code_node(UPSERT, deduped)
    out = run_code_node(RELS, upserted)

    assert not any(k == "PIVOTS_TO" for _, _, k in fc.edges), fc.edges
    assert out[0]["json"]["rel_status"] == "ok", out[0]["json"]
    # The channel itself is still recorded on the node.
    session = next(a for a in fc.added if a["node_type"] == "C2Session")
    assert session["properties"]["pivot_channel"] == "smb"
    assert session["properties"]["is_pivot"] is True


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
        print(f"\n{len(failures)} of {total} WF28 node checks failed")
        return 1
    print(f"\nall {total} WF28 node checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
