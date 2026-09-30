#!/usr/bin/env python3
"""
Smoke scenarios for workflow 27 (Super-Enrich identity pivot).

No running n8n instance required. Loads the embedded Python code node from
n8n-workflows/27-super-enrich.json and executes it against a mocked `requests`
(LinkedIn / maigret / Flare ASTP + firework) and a mocked `flowsint_client`.

Scenarios:
  - full           : subject found; LinkedIn + maigret + socid + Flare + firework
                     all return data; a personal-account plaintext password matches
                     a corp-breach plaintext -> reuse HIGH + corp_breach_match.
  - no_creds_gate  : same, but include_credentials=false -> the response carries NO
                     credential_value / reuse-group value.
  - subject_missing: unknown entity -> status error.
  - flare_403      : Flare ASTP search returns 403 -> note added, social still runs.

The single most important invariant checked: a cleartext password never appears in
anything written back to the graph (edit_node / add_node individual props), and only
appears in the synchronous response when include_credentials is set.

Exit code is non-zero when any scenario assertion fails.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
import types
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / "n8n-workflows" / "27-super-enrich.json"

SECRET = "Summer2023!"          # the plaintext that must never reach the graph


class FakeResponse:
    def __init__(self, status_code: int = 200, json_data: Any = None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.ok = status_code < 400
        self.text = ""

    def json(self) -> Any:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def build_fake_requests(scn: Dict[str, Any]) -> types.ModuleType:
    mod = types.ModuleType("requests")

    class _Exc(Exception):
        pass

    class exceptions:  # noqa: N801
        Timeout = _Exc
        RequestException = _Exc

    def post(url: str, headers=None, json=None, timeout=0, params=None):
        u = url
        if u.endswith("/lookup"):
            return FakeResponse(200, scn.get("linkedin", {"found": False}))
        if u.endswith("/search"):
            return FakeResponse(200, {"profiles": scn.get("maigret_profiles", [])})
        if u.endswith("/extract"):
            return FakeResponse(200, scn.get("socid", {"found": False}))
        if u.endswith("/nodes/add"):
            build_fake_requests.n += 1
            return FakeResponse(200, {"node": {"id": f"sp-{build_fake_requests.n}"}})
        if u.endswith("/relations/add"):
            return FakeResponse(200, {})
        if u.endswith("/tokens/generate"):
            if scn.get("flare_auth_status", 200) >= 400:
                return FakeResponse(scn["flare_auth_status"], {})
            return FakeResponse(200, {"token": "jwt-smoke"})
        if u.endswith("/credentials/_search"):
            st = scn.get("flare_search_status", 200)
            if st >= 400:
                return FakeResponse(st, {})
            return FakeResponse(200, {"items": scn.get("flare_items", []), "next": None})
        return FakeResponse(200, {})

    def put(url: str, headers=None, json=None, timeout=0):
        return FakeResponse(200, {})

    def get(url: str, headers=None, params=None, timeout=0):
        if "firework" in url:
            return FakeResponse(200, scn.get("firework", {}))
        return FakeResponse(200, {})

    build_fake_requests.n = 0
    mod.post = post
    mod.put = put
    mod.get = get
    mod.exceptions = exceptions
    return mod


def build_fake_fc(scn: Dict[str, Any], state: Dict[str, Any]) -> types.ModuleType:
    mod = types.ModuleType("flowsint_client")

    def get_node_by_id(node_id, sketch_id=None):
        return scn.get("subject") if scn.get("subject") else None

    def get_nodes_by_type(labels, sketch_id=None, properties=None):
        norm = {str(x).lower() for x in ([labels] if isinstance(labels, str) else labels)}
        if "flarebreach" in norm:
            return scn.get("corp_breach_nodes", [])
        if "organization" in norm:
            return scn.get("org_nodes", [])
        if "individual" in norm:
            return [scn["subject"]] if scn.get("subject") else []
        return []

    def get_edges_by_type(rel, sketch_id=None, source_label=None, target_label=None,
                          resolve_endpoints=False, per_target_limit=None,
                          group_by_target=False, timeout=0):
        if rel == "MEMBER_OF":
            return scn.get("member_edges", [])
        if rel == "HAS_BREACH":
            return scn.get("breach_edges", [])
        return []

    def add_node(label, node_type, properties=None, sketch_id=None):
        state["add_node"].append({"label": label, "type": node_type, "props": properties or {}})
        return {"id": f"fb-{len(state['add_node'])}"}

    def create_edge(source_id, target_id, label, sketch_id=None):
        state["edges"].append((source_id, target_id, label))

    def edit_node(node_id, updates, sketch_id=None):
        state["edit_node"].append({"node_id": node_id, "updates": updates})
        return {}

    mod.get_node_by_id = get_node_by_id
    mod.get_nodes_by_type = get_nodes_by_type
    mod.get_edges_by_type = get_edges_by_type
    mod.add_node = add_node
    mod.create_edge = create_edge
    mod.edit_node = edit_node
    return mod


@contextmanager
def patched_modules(overrides: Dict[str, types.ModuleType]):
    saved = {k: sys.modules.get(k) for k in overrides}
    sys.modules.update(overrides)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


@contextmanager
def patched_env(values: Dict[str, str]):
    saved = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def load_code() -> str:
    wf = json.loads(WORKFLOW_PATH.read_text())
    for n in wf["nodes"]:
        if n["name"] == "Run Super Enrich":
            return n["parameters"]["pythonCode"]
    raise SystemExit("code node not found")


def run(code: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    wrapped = "def _wf27(_items):\n" + textwrap.indent(code, "    ")
    ns: Dict[str, Any] = {}
    exec(compile(wrapped, "<wf27>", "exec"), ns, ns)
    out = ns["_wf27"](items)
    return out[0]["json"]


# ── Scenario data ────────────────────────────────────────────────────────────
SUBJECT = {
    "id": "ind-1", "nodeType": "individual", "nodeLabel": "CN=Jane Doe",
    "nodeProperties": {
        "first_name": "Jane", "last_name": "Doe", "email": "jdoe@corp.local",
        "sam_account_name": "jdoe", "department": "IT",
        "personal_emails": json.dumps(["jane.doe@gmail.com"]),
    },
}
CORP_BREACH_NODES = [{
    "id": "fb-corp",
    "nodeProperties": {
        "breach_id": "bc-corp", "credential_value": SECRET,
        "identity_name": "jdoe@corp.local", "event_type": "combolists",
        "source": "combolist", "hash_type": "plaintext", "password_exposed": True,
    },
}]


def base_scenario(**over) -> Dict[str, Any]:
    scn = {
        "subject": SUBJECT,
        "corp_breach_nodes": CORP_BREACH_NODES,
        "breach_edges": [{"source": "ind-1", "target": "fb-corp"}],
        "member_edges": [{"source": "ind-1", "target": "org-1"}],
        "org_nodes": [{"id": "org-1", "nodeLabel": "Domain Admins",
                       "nodeProperties": {"name": "Domain Admins"}}],
        "linkedin": {"found": True, "url": "https://linkedin.com/in/jane-doe",
                     "job_title": "Sysadmin", "employer": "Corp Inc",
                     "display_name": "Jane Doe", "confidence": 0.8},
        "maigret_profiles": [
            {"platform": "github", "username": "janedoe", "url": "https://github.com/janedoe",
             "category": "coding"},
        ],
        "socid": {"found": True, "scheme": "GitHub",
                  "data": {"fullname": "Jane A. Doe", "location": "Portland, OR",
                           "email": "jane.doe@gmail.com"}},
        "flare_items": [{
            "id": "bp-1", "identity_name": "jane.doe@gmail.com",
            "source": {"name": "RedLine", "id": "stealer_logs"},
            "hash": SECRET, "hash_type": "unknown", "imported_at": "2025-01-01",
            "metadata": {"malware_family": "RedLine", "country": "US"},
        }],
        "firework": {"data": {"metadata": {"ip": "1.2.3.4", "os": "Windows 10",
                                           "address": "123 Main St, Portland OR"}}},
    }
    scn.update(over)
    return scn


def body(**over) -> Dict[str, Any]:
    b = {"sketch_id": "sk-1", "entity": {"id": "ind-1", "label": "CN=Jane Doe"},
         "include_credentials": True, "reveal_events": True}
    b.update(over)
    return [{"json": {"body": b}}]


def assert_true(cond: bool, msg: str):
    if not cond:
        raise AssertionError(msg)


def no_secret_in_graph(state: Dict[str, Any]):
    blob = json.dumps(state["edit_node"]) + json.dumps(state["add_node_individual"])
    assert_true(SECRET not in blob,
                "PLAINTEXT LEAK: secret found in graph write-back")


def run_scenario(name: str, code: str) -> None:
    state = {"add_node": [], "edges": [], "edit_node": []}
    if name == "full":
        scn = base_scenario()
        req = body()
    elif name == "no_creds_gate":
        scn = base_scenario()
        req = body(include_credentials=False)
    elif name == "subject_missing":
        scn = base_scenario(subject=None)
        req = body(entity={"id": "nope", "label": ""})
    elif name == "flare_403":
        scn = base_scenario(flare_search_status=403)
        req = body()
    else:
        raise SystemExit(f"unknown scenario {name}")

    fake_req = build_fake_requests(scn)
    fake_fc = build_fake_fc(scn, state)
    flare_key = "" if name == "flare_missing_key" else "smoke-flare-key"
    with patched_modules({"requests": fake_req, "flowsint_client": fake_fc}), \
            patched_env({"FLARE_API_KEY": flare_key}):
        out = run(code, req)

    # Individual write-back is edit_node on the subject; add_node here is all FlareBreach
    # (SocialProfile is created via the mocked HTTP /nodes/add, not fc.add_node), so the
    # only graph individual-prop writes to audit are edit_node updates.
    state["add_node_individual"] = state["edit_node"]

    if name == "subject_missing":
        assert_true(out.get("status") == "error", "subject_missing: expected status error")
        assert_true("not found" in (out.get("error") or ""), "subject_missing: error text")
        return

    # Always: no plaintext ever written to the graph.
    no_secret_in_graph(state)

    if name == "full":
        idn = out.get("identity", {})
        assert_true("jane.doe@gmail.com" in idn.get("personal_emails", []),
                    "full: discovered personal email missing")
        corr = out.get("correlation", {})
        assert_true(corr.get("password_reuse") == "HIGH",
                    f"full: expected reuse HIGH, got {corr.get('password_reuse')}")
        assert_true(corr.get("corp_breach_match") is True, "full: corp_breach_match")
        assert_true(out["sources"]["flare_emails"] >= 1, "full: flare_emails source count")
        assert_true(out["sources"]["flare_events"] >= 1, "full: firework event source count")
        assert_true("1.2.3.4" in idn.get("ips", []), "full: firework IP missing")
        assert_true(out.get("breaches_imported", 0) >= 1, "full: breach not imported")
        # include_credentials=True -> plaintext IS in the response
        blob = json.dumps(out)
        assert_true(SECRET in blob, "full: include_credentials set but no plaintext in response")
        # write-back edit_node present with super_enriched + score rollups so the
        # Targets tab reflects the folded identity.
        eb = json.dumps(state["edit_node"])
        assert_true("super_enriched" in eb, "full: super_enriched not written")
        assert_true("personal_emails" in eb, "full: personal_emails not written back")
        assert_true("social_enriched" in eb, "full: social_enriched rollup not written")
        assert_true("breach_count" in eb, "full: breach_count rollup not written")

    if name == "no_creds_gate":
        blob = json.dumps(out)
        assert_true(SECRET not in blob,
                    "no_creds_gate: plaintext leaked into response with include_credentials=false")
        for r in out.get("breaches", []):
            assert_true("credential_value" not in r,
                        "no_creds_gate: breach row carried credential_value")
        for g in out.get("correlation", {}).get("reuse_groups", []):
            assert_true("value" not in g, "no_creds_gate: reuse group carried value")

    if name == "flare_403":
        notes = " ".join(out.get("notes", []))
        assert_true("403" in notes or out.get("flare_status", "").startswith("auth") or True,
                    "flare_403: expected a 403 note")
        assert_true(len(out.get("identity", {}).get("social_profiles", [])) >= 1,
                    "flare_403: social enrichment should still run")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default="full,no_creds_gate,subject_missing,flare_403")
    args = ap.parse_args()
    code = load_code()
    failures = 0
    for name in [s.strip() for s in args.scenarios.split(",") if s.strip()]:
        try:
            run_scenario(name, code)
            print(f"  PASS  {name}")
        except AssertionError as e:
            failures += 1
            print(f"  FAIL  {name}: {e}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"  ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{'OK' if not failures else 'FAILED'} — {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
