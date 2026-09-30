#!/usr/bin/env python3
"""
Smoke scenarios for workflow 10 (Security LLM Analysis), specifically the
evidence-weighted ownership contribution to a person's score.

Runs WF10's embedded `Fetch Graph + Run Analysis LLM` node on the host with fake
Neo4j and LLM transports, skipping the n8n import-and-restart cycle (same
approach as smoke_workflow04.py / _13.py / _23.py).

WHY THIS EXISTS
---------------
WF10's `asset_bump` used to add a flat +8 for every asset a person "owned", +6
more for a CloudAsset and +6 more if it carried vulns, with no evidence
discrimination and no ceiling -- over a label set that included plain MANAGES.

MANAGES is the apex WHOIS registrant. WF13 computes it ONCE, from the domain's
own WHOIS and TXT records, and attaches it to the apex, to every subdomain and to
every bucket in the sweep alike. It is a fact about the DOMAIN, not about any one
asset. So a registrant on a 40-subdomain estate accumulated +320 and pegged the
100 cap -- and that is the mechanism by which WF13's retired name-token false
positives actually moved Targets-tab scores. `issues.md` recorded it as
"Confirmed limitations" item 5: an unpinned, cruder version of WF04's owner
credit, with no evidence discrimination and no read of exposure_score.

Every part of the replacement is silent when it breaks. A weight that reverts to
flat produces HIGHER scores, which reads as the feature working harder, and the
label that carries the evidence tier is the only durable channel there is --
Flowsint drops edge `data` before it reaches Neo4j, so the relationship type is
all the scorer has to read.

    fixture              what it pins down
    -------------------  ----------------------------------------------------
    registrant_free      40 MANAGES assets contribute 0, not +320
    control_scores       an OWNS_ASSET asset does contribute
    access_discounted    HAS_ACCESS contributes strictly less than OWNS_ASSET
    bump_capped          many owned assets hit the ceiling, not the sum
    tier_travels         the edge LABEL reaches the scorer, not just the asset
    registrant_rendered  a 0-weight row still appears in the ownership section

Usage:
    python3 scripts/smoke_workflow10.py
    python3 scripts/smoke_workflow10.py --only registrant_free
"""

from __future__ import annotations

import argparse
import json
import sys
import types
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / "n8n-workflows" / "10-security-llm-analysis.json"
CODE_NODE = "Fetch Graph + Run Analysis LLM"

# The node does sys.path.insert(0, '/data/scripts'), which only exists inside the
# runner container, so the real scripts/ directory has to be ahead of it for
# `from asset_ownership import ...` to resolve.
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import asset_ownership as ao  # noqa: E402  (after the path insert, deliberately)


def load_code_node() -> str:
    obj = json.loads(WORKFLOW_PATH.read_text())
    for node in obj.get("nodes", []):
        if node.get("name") == CODE_NODE:
            return node["parameters"]["pythonCode"]
    raise SystemExit(f"code node {CODE_NODE!r} not found")


def run_code_node(code: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the node body the way n8n does: `_items` in scope, top-level
    `return`. exec() rejects a bare return, so wrap it in a function first --
    which also makes this a real syntax check, unlike ast.parse()."""
    wrapper = "def __node(_items):\n" + "".join(
        "    " + line + "\n" for line in code.splitlines()
    )
    ns: Dict[str, Any] = {}
    exec(compile(wrapper, "<wf10>", "exec"), ns)
    out = ns["__node"]([{"json": {"body": payload}}])
    assert len(out) == 1, out
    return out[0]["json"]


# ── Synthetic graph ──────────────────────────────────────────────────────────

def _node(eid: str, ntype: str, label: str, **props: Any) -> Dict[str, Any]:
    """One Neo4j row shape: properties() returns the flattened `nodeProperties.x`
    keys the node's _props_to_nd() unpacks."""
    row = {"nodeType": ntype, "nodeLabel": label}
    row.update({f"nodeProperties.{k}": v for k, v in props.items()})
    return {"eid": eid, "p": row}


def build_graph(relationship: str, asset_count: int,
                asset_type: str = "Subdomain") -> Dict[str, Any]:
    """One individual owning `asset_count` assets through `relationship`.

    The person carries no other scoring signal at all -- no admin flag, no
    beacon, no breach, no ACE -- so whatever score comes back is the ownership
    contribution and nothing else. That is what makes "contributes 0" testable
    rather than assumed.
    """
    nodes = [_node("i-1", "individual", "OWNER@EXAMPLE.COM",
                   full_name="Pat Owner", email="pat@example.com",
                   source="sharphound")]
    edges = []
    for i in range(asset_count):
        aid = f"a-{i}"
        nodes.append(_node(aid, asset_type, f"sub{i}.example.com",
                           fqdn=f"sub{i}.example.com"))
        edges.append({"s": "i-1", "t": aid, "l": relationship})
    return {"nodes": nodes, "edges": edges}


def build_fake_requests(graph: Dict[str, Any]) -> types.ModuleType:
    """Fake Neo4j + LLM transports.

    The Cypher fake filters by the label the statement names, because the node
    fetches label by label; returning every node for every label would multiply
    the graph by len(_LABELS) and quietly inflate every count under test.
    """
    fake = types.ModuleType("requests")

    class FakeResponse:
        def __init__(self, payload: Any) -> None:
            self._payload = payload
            self.status_code = 200
            self.text = json.dumps(payload)

        def json(self) -> Any:
            return self._payload

        def raise_for_status(self) -> None:
            return None

    def post(url: str, **kwargs: Any) -> FakeResponse:
        if "/tx/commit" in url:
            stmt = kwargs["json"]["statements"][0]["statement"]
            label = stmt.split("`")[1]
            by_id = {n["eid"]: n for n in graph["nodes"]}
            if "RETURN elementId(n)" in stmt:
                rows = [{"row": [n["eid"], n["p"]]}
                        for n in graph["nodes"] if n["p"]["nodeType"] == label]
                cols = ["eid", "p"]
            else:
                rows = [{"row": [e["s"], e["t"], e["l"]]} for e in graph["edges"]
                        if by_id.get(e["s"], {}).get("p", {}).get("nodeType") == label]
                cols = ["s", "t", "l"]
            return FakeResponse({"errors": [], "results": [{"columns": cols, "data": rows}]})
        # The LLM leg. Its narrative is not under test here, but it must return
        # SOMETHING usable: the node sets result['error'] when the summary, the
        # scenarios and the objective alignment are all empty, and an errored
        # result would make every score assertion below vacuous. The shape is
        # Ollama's /api/chat -- message.content, not choices[].
        return FakeResponse({"message": {"content": json.dumps({
            "objective_alignment": "smoke",
            "summary": "smoke",
            "scenarios": [],
        })}})

    fake.post = post  # type: ignore[attr-defined]
    fake.get = lambda *a, **k: FakeResponse({})  # type: ignore[attr-defined]

    class RequestException(Exception):
        pass

    fake.RequestException = RequestException  # type: ignore[attr-defined]
    fake.exceptions = types.SimpleNamespace(RequestException=RequestException)  # type: ignore[attr-defined]
    return fake


@contextmanager
def patched(modules: Dict[str, types.ModuleType], env: Dict[str, str]):
    import os
    saved_mod = {k: sys.modules.get(k) for k in modules}
    saved_env = {k: os.environ.get(k) for k in env}
    sys.modules.update(modules)
    os.environ.update(env)
    try:
        yield
    finally:
        for k, v in saved_mod.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


PAYLOAD = {
    "campaign_id": "smoke-campaign",
    "campaign_name": "Smoke",
    "sketch_id": "smoke-sketch",
    "target_type": "individual",
    "mission_statement": "",
}


def score_for(code: str, relationship: str, count: int,
              asset_type: str = "Subdomain") -> int:
    graph = build_graph(relationship, count, asset_type)
    with patched({"requests": build_fake_requests(graph)},
                 {"NEO4J_HTTP_URL": "http://neo4j.invalid:7474",
                  "NEO4J_PASSWORD": "x", "FLOWSINT_SKETCH_ID": "smoke-sketch"}):
        result = run_code_node(code, PAYLOAD)
    assert not result.get("error"), result.get("error")
    for row in result.get("targets", []):
        if row.get("name") == "OWNER@EXAMPLE.COM" or row.get("label") == "OWNER@EXAMPLE.COM":
            return int(row.get("score") or 0)
    return 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    args = ap.parse_args()
    only = args.only
    code = load_code_node()
    failures = 0

    def check(name: str, ok: bool, detail: Any = None) -> None:
        nonlocal failures
        if only and only != name:
            return
        print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f"  {detail!r}"))
        failures += 0 if ok else 1

    base = score_for(code, "NONE", 0)          # no ownership edge at all
    reg40 = score_for(code, ao.MANAGES, 40)    # the shape seen on a real campaign
    own1 = score_for(code, ao.OWNS_ASSET, 1)
    acc1 = score_for(code, ao.HAS_ACCESS, 1)
    own9 = score_for(code, ao.OWNS_ASSET, 9)

    print("ownership scoring fixtures:")
    # THE LOAD-BEARING ONE. 40 registrant assets is exactly what a WHOIS match on
    # a 40-subdomain estate produced, and it used to be +320 -> capped at 100.
    check("registrant_free", reg40 == base, (reg40, base))
    check("control_scores", own1 > base, (own1, base))
    check("access_discounted", base < acc1 < own1, (base, acc1, own1))
    # Nine owned assets is not nine findings. Without the cap this would be 72.
    check("bump_capped", own9 - base <= ao.ASSET_BUMP_CAP, (own9, base, ao.ASSET_BUMP_CAP))
    # The tier must reach the scorer through the EDGE LABEL. If the node dropped
    # `relationship` when building its asset dicts, every tier would weigh the
    # same and this equality would hold.
    check("tier_travels", own1 != acc1, (own1, acc1))

    # A 0-weight row still has to RENDER: the operator wants to see that the
    # registrant relationship exists, it just must not move the score.
    graph = build_graph(ao.MANAGES, 3)
    with patched({"requests": build_fake_requests(graph)},
                 {"NEO4J_HTTP_URL": "http://neo4j.invalid:7474",
                  "NEO4J_PASSWORD": "x", "FLOWSINT_SKETCH_ID": "smoke-sketch"}):
        rendered = run_code_node(code, PAYLOAD)
    blob = json.dumps(rendered)
    check("registrant_rendered", "sub0.example.com" in blob, blob[:200])

    if failures:
        print(f"FAILED ({failures})")
        raise SystemExit(1)
    print("PASSED")


if __name__ == "__main__":
    main()
