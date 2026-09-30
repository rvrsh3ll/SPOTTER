#!/usr/bin/env python3
"""
Smoke scenarios for workflow 09 (Flare ingestor) with simulated Flare responses.

This script does not require a running n8n instance. It loads the embedded Python
code from n8n-workflows/09-flare-ingestor.json and executes the three core code
nodes in sequence with mocked requests + mocked flowsint_client.

Scenarios:
  - auth_ok        : token + search requests succeed
  - auth_403       : token endpoint returns HTTP 403
  - auth_timeout   : token request times out
  - search_403     : token succeeds, search endpoint returns HTTP 403

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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / "n8n-workflows" / "09-flare-ingestor.json"


@dataclass
class Scenario:
    name: str
    auth_status: int = 200
    auth_timeout: bool = False
    missing_api_key: bool = False
    search_status: int = 200
    search_timeout: bool = False
    reader_failure: str = ""


SCENARIOS: Dict[str, Scenario] = {
    "auth_ok": Scenario(name="auth_ok"),
    "auth_403": Scenario(name="auth_403", auth_status=403),
    "auth_timeout": Scenario(name="auth_timeout", auth_timeout=True),
    "search_403": Scenario(name="search_403", search_status=403),
    "flowsint_timeout": Scenario(name="flowsint_timeout", reader_failure="timeout"),
    "flowsint_connection_error": Scenario(name="flowsint_connection_error", reader_failure="connection_error"),
    "flowsint_neo4j_error": Scenario(name="flowsint_neo4j_error", reader_failure="neo4j_error"),
}


class FakeResponse:
    def __init__(self, status_code: int = 200, json_data: Any = None, text: str = ""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text

    def json(self) -> Any:
        if self._json_data is None:
            return {}
        return self._json_data


def build_fake_requests_module(scenario: Scenario) -> Tuple[types.ModuleType, Dict[str, Any]]:
    state = {
        "token_calls": 0,
        "search_calls": 0,
    }

    mod = types.ModuleType("requests")

    class Timeout(Exception):
        pass

    class ConnectionError(Exception):
        pass

    exceptions_ns = types.SimpleNamespace(
        Timeout=Timeout,
        ConnectionError=ConnectionError,
        RequestException=Exception,
    )
    mod.exceptions = exceptions_ns

    def post(url: str, headers: Dict[str, str] | None = None, json: Dict[str, Any] | None = None, timeout: int = 0):
        del headers, timeout
        if url.endswith("/tokens/generate"):
            state["token_calls"] += 1
            if scenario.auth_timeout:
                raise Timeout("simulated auth timeout")
            if scenario.auth_status >= 400:
                return FakeResponse(
                    status_code=scenario.auth_status,
                    json_data={"error": "auth failed"},
                    text="simulated auth failure",
                )
            return FakeResponse(status_code=200, json_data={"token": "smoke-token"})

        if "/astp/v2/credentials/_search" in url:
            state["search_calls"] += 1
            if scenario.search_timeout:
                raise Timeout("simulated search timeout")
            if scenario.search_status >= 400:
                return FakeResponse(
                    status_code=scenario.search_status,
                    json_data={"error": "search failed"},
                    text="simulated search failure",
                )

            query = (json or {}).get("query", {})
            q_type = query.get("type", "keyword")
            q_val = query.get("value") or query.get("fqdn") or "example.com"
            sample = {
                "id": f"{q_type}:{q_val}",
                "event_type": "stealer_log" if q_type == "email" else "leaked_credentials",
                "source": {"name": "smoke-source", "id": "smoke-src"},
                "identity_name": q_val if "@" in q_val else f"{q_val}@example.com",
                "domain": "example.com",
                "hash_type": "plain",
                "password": "Secret123!",
                "imported_at": "2026-06-30T00:00:00Z",
                "metadata": {"malware_family": "Redline", "country": "US"},
            }
            return FakeResponse(status_code=200, json_data={"items": [sample], "next": None})

        return FakeResponse(status_code=404, json_data={"error": "unexpected url"}, text="unexpected url")

    mod.post = post
    return mod, state


def build_fake_flowsint_client_module(
    reader_failure: Exception | None = None,
) -> Tuple[types.ModuleType, Dict[str, Any]]:
    state = {
        "add_node_calls": 0,
        "create_edge_calls": 0,
        "edit_node_calls": 0,
        "get_nodes_by_type_calls": 0,
        "get_edges_by_type_calls": 0,
    }

    mod = types.ModuleType("flowsint_client")

    def get_graph(sketch_id: str = ""):
        del sketch_id
        return {
            "nodes": [
                {
                    "id": "ind-1",
                    "nodeType": "individual",
                    "nodeLabel": "alice",
                    "nodeProperties": {
                        "email": "alice@example.com",
                        "sam_account_name": "alice",
                    },
                },
                {
                    "id": "ind-2",
                    "nodeType": "individual",
                    "nodeLabel": "bob",
                    "nodeProperties": {
                        "email": "bob@example.com",
                        "sam_account_name": "bob",
                    },
                },
            ],
            "edges": [],
        }

    def get_nodes_by_type(
        node_type: str,
        sketch_id: str = "",
        properties: List[str] | None = None,
    ) -> List[Dict[str, Any]]:
        del sketch_id, properties
        state["get_nodes_by_type_calls"] += 1
        if reader_failure is not None:
            raise reader_failure
        if node_type != "individual":
            return []
        return [
            {
                "id": "ind-1",
                "nodeType": "individual",
                "nodeLabel": "alice",
                "nodeProperties": {
                    "email": "alice@example.com",
                    "sam_account_name": "alice",
                },
            },
            {
                "id": "ind-2",
                "nodeType": "individual",
                "nodeLabel": "bob",
                "nodeProperties": {
                    "email": "bob@example.com",
                    "sam_account_name": "bob",
                },
            },
        ]

    def get_edges_by_type(
        rel_types: str | List[str],
        sketch_id: str = "",
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        del rel_types, sketch_id, kwargs
        state["get_edges_by_type_calls"] += 1
        return []

    def add_node(label: str, node_type: str, properties: Dict[str, Any], sketch_id: str = ""):
        del label, node_type, properties, sketch_id
        state["add_node_calls"] += 1
        return {"id": f"breach-{state['add_node_calls']}"}

    def create_edge(source_id: str, target_id: str, label: str, sketch_id: str = ""):
        del source_id, target_id, label, sketch_id
        state["create_edge_calls"] += 1

    def edit_node(node_id: str, updates: Dict[str, Any], sketch_id: str = ""):
        del node_id, updates, sketch_id
        state["edit_node_calls"] += 1

    mod.get_graph = get_graph
    mod.get_nodes_by_type = get_nodes_by_type
    mod.get_edges_by_type = get_edges_by_type
    mod.add_node = add_node
    mod.create_edge = create_edge
    mod.edit_node = edit_node
    return mod, state


@contextmanager
def patched_modules(overrides: Dict[str, types.ModuleType]):
    sentinel = object()
    prev: Dict[str, Any] = {}
    for name, module in overrides.items():
        prev[name] = sys.modules.get(name, sentinel)
        sys.modules[name] = module
    try:
        yield
    finally:
        for name, old in prev.items():
            if old is sentinel:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


@contextmanager
def patched_env(values: Dict[str, str | None]):
    old: Dict[str, str | None] = {}
    for key, value in values.items():
        old[key] = os.environ.get(key)
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def load_workflow_code_nodes(path: Path) -> Dict[str, str]:
    obj = json.loads(path.read_text())
    code_nodes: Dict[str, str] = {}
    for node in obj.get("nodes", []):
        if node.get("type") != "n8n-nodes-base.code":
            continue
        code_nodes[node.get("name", "")] = node.get("parameters", {}).get("pythonCode", "")
    return code_nodes


def run_n8n_python_code(code: str, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    fn_name = "__n8n_exec"
    wrapped = f"def {fn_name}(_items):\n" + textwrap.indent(code, "    ")
    ns: Dict[str, Any] = {}
    exec(compile(wrapped, "<n8n_code>", "exec"), ns, ns)
    return ns[fn_name](items)


def run_pipeline(scenario: Scenario, code_nodes: Dict[str, str]) -> Tuple[Dict[str, Any] | None, Dict[str, Any] | None, Dict[str, Any] | None, Dict[str, Any], Exception | None]:
    fake_requests, req_state = build_fake_requests_module(scenario)

    reader_failure: Exception | None = None
    if scenario.reader_failure == "timeout":
        reader_failure = requests.exceptions.Timeout("simulated Flowsint timeout")
    elif scenario.reader_failure == "connection_error":
        reader_failure = requests.exceptions.ConnectionError("simulated Flowsint connection error")
    elif scenario.reader_failure == "neo4j_error":
        reader_failure = RuntimeError("simulated Neo4j read error")

    fake_fc, fc_state = build_fake_flowsint_client_module(reader_failure=reader_failure)

    env = {
        "FLOWSINT_SKETCH_ID": "smoke-sketch",
        "FLARE_API_KEY": None if scenario.missing_api_key else "smoke-key",
    }

    fetch_json: Dict[str, Any] | None = None
    search_json: Dict[str, Any] | None = None
    import_json: Dict[str, Any] | None = None
    pipeline_error: Exception | None = None

    with patched_modules({"requests": fake_requests, "flowsint_client": fake_fc}):
        with patched_env(env):
            try:
                fetch_items = run_n8n_python_code(code_nodes["Fetch Individuals + Flare Auth"], [{"json": {}}])
                fetch_json = fetch_items[0]["json"]
                search_items = run_n8n_python_code(code_nodes["Search Flare for Each Individual"], fetch_items)
                search_json = search_items[0]["json"]
                import_items = run_n8n_python_code(code_nodes["Import Breach Nodes to Flowsint"], search_items)
                import_json = import_items[0]["json"]
            except Exception as e:
                pipeline_error = e

    state = {"requests": req_state, "flowsint_client": fc_state}
    return fetch_json, search_json, import_json, state, pipeline_error


def assert_true(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)


def validate_scenario(
    name: str,
    fetch_json: Dict[str, Any] | None,
    search_json: Dict[str, Any] | None,
    import_json: Dict[str, Any] | None,
    pipeline_error: Exception | None,
):
    if name == "auth_ok":
        assert_true(fetch_json.get("auth_status") == "ok", "auth_ok: fetch auth_status should be ok")
        assert_true(search_json.get("search_status") in {"ok", "partial_with_errors", "ok_no_targets"}, "auth_ok: unexpected search_status")
        assert_true("status" in import_json, "auth_ok: import status missing")
        return

    if name == "auth_403":
        assert_true(fetch_json.get("auth_error_type") == "forbidden", "auth_403: fetch auth_error_type should be forbidden")
        assert_true(search_json.get("search_status") == "skipped_auth_error", "auth_403: search should be skipped_auth_error")
        assert_true(import_json.get("auth_error_type") == "forbidden", "auth_403: import auth_error_type should be forbidden")
        return

    if name == "auth_timeout":
        assert_true(fetch_json.get("auth_error_type") == "timeout", "auth_timeout: fetch auth_error_type should be timeout")
        assert_true(search_json.get("search_status") == "skipped_auth_error", "auth_timeout: search should be skipped_auth_error")
        assert_true(import_json.get("auth_error_type") == "timeout", "auth_timeout: import auth_error_type should be timeout")
        return

    if name == "search_403":
        et = search_json.get("search_error_types", {})
        assert_true((et.get("forbidden") or 0) > 0, "search_403: forbidden should be counted in search_error_types")
        assert_true(search_json.get("search_status") in {"error", "partial_with_errors"}, "search_403: unexpected search_status")
        assert_true(import_json.get("search_status") in {"error", "partial_with_errors"}, "search_403: import should carry degraded search_status")
        return

    if name in {"flowsint_timeout", "flowsint_connection_error", "flowsint_neo4j_error"}:
        # The fetch node must now raise RuntimeError rather than returning
        # 'ok_no_targets', which would hide a real Flowsint outage.
        assert_true(pipeline_error is not None, f"{name}: fetch node should raise on reader failure")
        assert_true(
            isinstance(pipeline_error, RuntimeError) and "Flowsint individual read failed" in str(pipeline_error),
            f"{name}: expected RuntimeError mentioning Flowsint individual read failed, got {pipeline_error!r}",
        )
        return

    raise AssertionError(f"Unknown scenario validation: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run workflow 09 smoke scenarios with simulated Flare responses")
    parser.add_argument(
        "--scenarios",
        default=",".join(SCENARIOS.keys()),
        help="Comma-separated scenarios to run (default: all)",
    )
    args = parser.parse_args()

    selected = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    invalid = [s for s in selected if s not in SCENARIOS]
    if invalid:
        print("Invalid scenario(s):", ", ".join(invalid), file=sys.stderr)
        print("Valid:", ", ".join(sorted(SCENARIOS.keys())), file=sys.stderr)
        return 2

    code_nodes = load_workflow_code_nodes(WORKFLOW_PATH)
    required = {
        "Fetch Individuals + Flare Auth",
        "Search Flare for Each Individual",
        "Import Breach Nodes to Flowsint",
    }
    missing = sorted(required - set(code_nodes.keys()))
    if missing:
        print("Missing required workflow code nodes:", ", ".join(missing), file=sys.stderr)
        return 2

    failures = 0
    for name in selected:
        scenario = SCENARIOS[name]
        try:
            fetch_json, search_json, import_json, state, pipeline_error = run_pipeline(scenario, code_nodes)
            validate_scenario(name, fetch_json, search_json, import_json, pipeline_error)
            if pipeline_error is not None:
                print(
                    f"PASS {name}: "
                    f"raised={type(pipeline_error).__name__}: {pipeline_error} "
                    f"token_calls={state['requests']['token_calls']} "
                    f"search_calls={state['requests']['search_calls']}"
                )
            else:
                print(
                    f"PASS {name}: "
                    f"fetch.auth_status={fetch_json.get('auth_status')} "
                    f"search.search_status={search_json.get('search_status')} "
                    f"import.status={import_json.get('status')} "
                    f"token_calls={state['requests']['token_calls']} "
                    f"search_calls={state['requests']['search_calls']}"
                )
        except Exception as e:
            failures += 1
            print(f"FAIL {name}: {e}", file=sys.stderr)

    if failures:
        print(f"{failures} scenario(s) failed", file=sys.stderr)
        return 1

    print("All selected workflow 09 smoke scenarios passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
