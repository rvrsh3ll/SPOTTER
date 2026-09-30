#!/usr/bin/env python3
"""
Focused regression checks for hardened workflows:
    - 03-enrichment-orchestrator.json
  - 01-cobalt-strike-ingestor.json
    - 05-dossier-exporter.json
  - 06-manual-upload-handler.json
  - 09-flare-ingestor.json
  - 11-credential-scanner.json
  - 13-domain-recon.json
    - 14-tech-context-indexer.json
  - 19-export-campaign.json
  - 20-import-campaign.json

Checks include:
  - JSON parse validity
  - Embedded Python code-node AST parse validity
  - Guardrail assertions tied to recent hardening work

Usage:
  python3 scripts/check_workflow_regressions.py
"""

from __future__ import annotations

import ast
import json
import io
import re
import tokenize
import sys
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / "n8n-workflows"

TARGETS = {
    "03": WORKFLOW_DIR / "03-enrichment-orchestrator.json",
    "01": WORKFLOW_DIR / "01-cobalt-strike-ingestor.json",
    "04": WORKFLOW_DIR / "04-attack-path-analyzer.json",
    "05": WORKFLOW_DIR / "05-dossier-exporter.json",
    "06": WORKFLOW_DIR / "06-manual-upload-handler.json",
    "09": WORKFLOW_DIR / "09-flare-ingestor.json",
    # Added 2026-09-03: WF10 was absent, so its top-level except handler shipped a
    # type() call that the sandbox has no builtin for. Every workflow with a Python
    # code node belongs here.
    "10": WORKFLOW_DIR / "10-security-llm-analysis.json",
    "11": WORKFLOW_DIR / "11-credential-scanner.json",
    "12": WORKFLOW_DIR / "12-tech-inventory.json",
    "13": WORKFLOW_DIR / "13-domain-recon.json",
    "14": WORKFLOW_DIR / "14-tech-context-indexer.json",
    "19": WORKFLOW_DIR / "19-export-campaign.json",
    "20": WORKFLOW_DIR / "20-import-campaign.json",
    "21": WORKFLOW_DIR / "21-brute-ratel-receiver.json",
    "23": WORKFLOW_DIR / "23-c2-agents.json",
    "24": WORKFLOW_DIR / "24-notifications.json",
    "25": WORKFLOW_DIR / "25-vulnerability-context.json",
    "28": WORKFLOW_DIR / "28-adaptix-ingestor.json",
    "29": WORKFLOW_DIR / "29-analysis-correction.json",
}

# Flowsint's built-in node types. Neo4j labels are case-sensitive and
# create_node interpolates nodeType straight into `MERGE (n:{node_type} …)` with
# no normalisation, so a capitalised spelling silently creates a *second*,
# unregistered label that queries for the built-in never match.
BUILTIN_NODE_TYPES = {"individual", "device", "organization", "gpo", "credential"}

# Built-in types resolve from flowsint_types.TYPE_REGISTRY *before* the custom-type
# table, and some carry required fields. GraphSerializer.parse_flowsint_type retries
# once with invalid fields stripped, but a **missing required** field cannot be
# recovered that way — so one node written without it makes GET /graph return 500
# for the whole sketch. Custom types are built with every field Optional, so only
# these built-ins can fail this way.
REQUIRED_BUILTIN_PROPS = {
    "Technology":   "name",
    "device":       "device_id",
    "organization": "name",
    "credential":   "username",
}

# Env vars a Python code node reads that are deliberately allowed to be
# unreachable from the runner, with the reason. Every entry is a spot where
# check_code_node_env_reachable is blind, so keep the list short and justified.
ENV_REACHABILITY_WAIVERS = {
    "WEBHOOK_URL": (
        "secondary fallback only — the read is "
        "`N8N_WEBHOOK_BASE_URL or WEBHOOK_URL or 'http://n8n:5678'`, and the primary "
        "is both set and allowlisted. n8n injects WEBHOOK_URL into its own container, "
        "never into the runner, so wiring it through would be cargo cult."
    ),
}


def load_json(path: Path) -> Dict:
    return json.loads(path.read_text())


def code_nodes(workflow_obj: Dict) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for node in workflow_obj.get("nodes", []):
        if node.get("type") != "n8n-nodes-base.code":
            continue
        out[node.get("name", "")] = node.get("parameters", {}).get("pythonCode", "")
    return out


def check_ast_parse(wf_id: str, node_map: Dict[str, str], failures: List[str]):
    for node_name, code in node_map.items():
        try:
            ast.parse(code)
        except Exception as e:
            failures.append(f"{wf_id}/{node_name}: embedded Python parse failed: {e}")


def require_contains(wf_id: str, node_name: str, code: str, needle: str, failures: List[str]):
    if needle not in code:
        failures.append(f"{wf_id}/{node_name}: missing expected pattern: {needle}")


def check_builtin_type_casing(wf_id: str, node_map: Dict[str, str], failures: List[str]):
    """A built-in type passed with any capitalisation forks the Neo4j label.

    WF01 wrote node_type='Individual' while its own dedup read 'individual', so
    every C2 session created an orphan identity the rest of SPOTTER could not see —
    and 'Individual' is not a registered custom type either, which puts the whole
    sketch one GET /graph away from a 500.
    """
    import re as _re
    for node_name, code in node_map.items():
        for written in _re.findall(r"node_type\s*=\s*['\"]([A-Za-z0-9_]+)['\"]", code):
            if written not in BUILTIN_NODE_TYPES and written.lower() in BUILTIN_NODE_TYPES:
                failures.append(
                    f"{wf_id}/{node_name}: node_type='{written}' must be "
                    f"'{written.lower()}' — built-in types are lowercase and Neo4j "
                    f"labels are case-sensitive"
                )


def check_required_builtin_props(wf_id: str, node_map: Dict[str, str], failures: List[str]):
    """Every add_node for a built-in type with a required field must set it.

    WF01 created Technology nodes carrying only `source`. Technology is built-in
    and requires `name`, so the first C2 session with a tech_stack took the whole
    sketch's GET /graph down with a 500.
    """
    import re as _re
    for node_name, code in node_map.items():
        for m in _re.finditer(r"fc\.add_node\((.*?)\n\s*\)", code, _re.S):
            call = m.group(1)
            written = _re.search(r"node_type\s*=\s*['\"]([A-Za-z0-9_]+)['\"]", call)
            if not written:
                continue
            prop = REQUIRED_BUILTIN_PROPS.get(written.group(1))
            if prop and f"'{prop}'" not in call and f'"{prop}"' not in call:
                failures.append(
                    f"{wf_id}/{node_name}: add_node(node_type='{written.group(1)}') "
                    f"does not set required property '{prop}' — a node missing it "
                    f"makes GET /graph 500 for the entire sketch"
                )


# The n8n Python task runner sandbox is not plain CPython. It removes builtins and
# blocks introspection attributes; touching either fails the node *at run time*, long
# after every host-side test has passed, because the code-node harness (see
# spotter-workflow-node-harness) runs under real CPython where they all work.
#
# These two sets are transcribed from the runner itself, not guessed --
#   /opt/runners/task-runner-python/build/lib/src/constants.py
#     BUILTINS_DENY_DEFAULT   (overridable via N8N_RUNNERS_BUILTINS_DENY)
#     BLOCKED_ATTRIBUTES
# so re-read that file after a runner image bump rather than trusting this copy.
#
# The trap this check exists for: f'{type(err).__name__}: {err}' is the natural way
# to format an exception, and it lives almost exclusively inside `except` blocks. So
# the handler itself raises while handling the original exception, the real error is
# destroyed, and the node returns nothing at all -- which reaches the operator as
# "n8n returned an empty response (HTTP 200)". WF10 shipped exactly that.
# `err.__class__.__name__` is NOT the fix; __class__ is a blocked attribute. Use
# repr(err), which is not denied and carries both the class name and the message.
SANDBOX_DENIED_BUILTINS = {
    "eval", "exec", "compile", "open", "input", "breakpoint", "getattr", "object",
    "type", "vars", "setattr", "delattr", "hasattr", "dir", "memoryview",
    "__build_class__", "globals", "locals", "license", "help", "credits", "copyright",
}

# Subset of the runner's BLOCKED_ATTRIBUTES worth flagging in workflow code: the ones
# a normal-looking line might reach for. The runner blocks many more (frame walking,
# __reduce__, metaclass hooks) that no workflow would write by accident.
SANDBOX_BLOCKED_ATTRIBUTES = {
    "__class__", "__dict__", "__bases__", "__base__", "__mro__", "__subclasses__",
    "__globals__", "__builtins__", "__code__", "__closure__", "__module__",
    "__qualname__", "__traceback__", "__func__", "__self__", "__wrapped__",
    "__getattribute__", "__setattr__", "__delattr__", "__annotations__",
}

REMEDY = {
    "getattr": "use try/except AttributeError",
    "hasattr": "use try/except AttributeError",
    "type": "use repr(x)",
    "__class__": "use repr(x)",
}


def check_sandbox_builtins(wf_id: str, node_map: Dict[str, str], failures: List[str]):
    """Flag denied builtins and blocked attributes in Python code nodes.

    Matched over the AST rather than by regex, because `type(` legitimately appears
    inside Cypher query strings -- WF10 has `RETURN ..., type(r) AS l` -- and a
    textual search cannot tell that from a Python call.
    """
    for node_name, code in node_map.items():
        try:
            tree = ast.parse(code)
        except SyntaxError:
            continue  # check_ast_parse already reports this
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in SANDBOX_DENIED_BUILTINS):
                name = node.func.id
                hint = REMEDY.get(name, "rewrite without it")
                failures.append(
                    f"{wf_id}/{node_name}: line {node.lineno} calls {name}() — the "
                    f"task runner's Python sandbox denies this builtin and the node "
                    f"dies at run time; {hint}"
                )
            elif (isinstance(node, ast.Attribute)
                    and node.attr in SANDBOX_BLOCKED_ATTRIBUTES):
                hint = REMEDY.get(node.attr, "rewrite without it")
                failures.append(
                    f"{wf_id}/{node_name}: line {node.lineno} accesses .{node.attr} — "
                    f"the task runner's Python sandbox blocks this attribute as an "
                    f"introspection escape and the node dies at run time; {hint}"
                )


def require_absent(wf_id: str, node_name: str, code: str, needle: str, failures: List[str],
                   why: str = ""):
    """Pin a pattern that must NOT come back. Some hardening removes a call rather
    than adding one, and a contains-only check cannot express that."""
    if needle in code:
        suffix = f" ({why})" if why else ""
        failures.append(f"{wf_id}/{node_name}: forbidden pattern present: {needle}{suffix}")


def run_checks() -> List[str]:
    failures: List[str] = []

    wf = {k: load_json(v) for k, v in TARGETS.items()}
    nodes = {k: code_nodes(v) for k, v in wf.items()}

    for wf_id, node_map in nodes.items():
        check_ast_parse(wf_id, node_map, failures)
        check_sandbox_builtins(wf_id, node_map, failures)
        check_builtin_type_casing(wf_id, node_map, failures)
        check_required_builtin_props(wf_id, node_map, failures)

    # Cross-cutting: LLM tools must be registered and expose tech_stack
    setup_openwebui = REPO_ROOT / "scripts" / "setup_openwebui.py"
    dossier_tool    = REPO_ROOT / "llm" / "tools" / "dossier_tool.py"

    setup_text = setup_openwebui.read_text()
    if '"spotter_technology"' not in setup_text:
        failures.append("setup_openwebui.py: spotter_technology tool is not registered")
    if '"file": "technology_tool.py"' not in setup_text:
        failures.append("setup_openwebui.py: technology_tool.py is not listed in TOOL_DEFS")
    if '"spotter_tech_context"' not in setup_text:
        failures.append("setup_openwebui.py: spotter_tech_context tool is not registered")
    if '"file": "tech_context_tool.py"' not in setup_text:
        failures.append("setup_openwebui.py: tech_context_tool.py is not listed in TOOL_DEFS")

    dossier_text = dossier_tool.read_text()
    if '"technology"' not in dossier_text:
        failures.append("dossier_tool.py: technology section missing from dossier output")
    if '"tech_stack"' not in dossier_text:
        failures.append("dossier_tool.py: tech_stack not exposed in dossier output")

    # Workflow 01 checks
    n01_fetch = nodes["01"].get("Fetch CS Beacons", "")
    n01_dedup = nodes["01"].get("Dedup Check", "")
    n01_rel = nodes["01"].get("Create Relationships", "")
    require_contains("01", "Fetch CS Beacons", n01_fetch, "fetch_ok", failures)
    require_contains("01", "Fetch CS Beacons", n01_fetch, "CS API HTTP", failures)
    # Dedup Check used to parse a full-graph response, and this assertion pinned the
    # defensive `graph_raw.get('nodes') or graph_raw.get('nds')` key handling. That
    # whole read has since been replaced by the indexed per-label reader, so the old
    # needle guarded code that no longer exists. Pin the current invariant instead:
    # the node fetches the graph itself (not via an upstream HTTP node, which used to
    # overwrite each beacon item) and never goes back to the unpaginated full-graph
    # endpoint, which truncates at 100k nodes and would silently drop existing
    # sessions from the dedup map and re-create them.
    require_contains("01", "Dedup Check", n01_dedup, "fc.get_nodes_by_type(", failures)
    require_absent("01", "Dedup Check", n01_dedup, "fc.get_graph(", failures,
                   why="full-graph read truncates at 100k nodes and breaks dedup")

    # The C2 ingestors have no request body to read a sketch_id from, so they must
    # resolve the campaign from the shared registry. Reverting to the bare env var
    # sends every beacon to the throwaway default sketch, and because writing to an
    # empty sketch succeeds, nothing surfaces the loss.
    for wf_id, node_names in (
        ("01", ("Dedup Check", "Upsert Individual + Beacon", "Create Relationships")),
        ("21", ("Dedup Check", "Upsert Individual + Session", "Create Relationships")),
        ("28", ("Dedup Check", "Upsert Individual + Session", "Create Relationships")),
    ):
        for node_name in node_names:
            code = nodes[wf_id].get(node_name, "")
            require_contains(wf_id, node_name, code, "fc.resolve_campaign_sketch(", failures)
            require_absent(wf_id, node_name, code,
                           "os.environ.get('FLOWSINT_SKETCH_ID'", failures,
                           why="resolve_campaign_sketch() already falls back to it")
    require_contains("01", "Create Relationships", n01_rel, "fc.create_edge(", failures)
    # WF01 wrote is_pivot/pivot_parent onto the node but never the edge, so a linked
    # beacon chain existed as properties nobody could traverse. WF21 has always
    # written PIVOTS_TO; this keeps the two ingestors at parity.
    require_contains("01", "Create Relationships", n01_rel, "'PIVOTS_TO'", failures)
    # Ten normalised fields used to be dropped between normalise_beacon() and the
    # write, so Cobalt Strike sessions showed blanks in the AGENTS tab exactly where
    # Brute Ratel showed data. Pin the ones that are CS-only signal.
    n01_upsert = nodes["01"].get("Upsert Individual + Beacon", "")
    for key in ("'listener'", "'pid'", "'os_version'", "'arch'", "'sleep_seconds'", "'jitter_pct'"):
        require_contains("01", "Upsert Individual + Beacon", n01_upsert, key + ":", failures)

    # Workflow 28 checks — the Adaptix poll must hold the same invariants as the
    # other two C2 ingestors. It is a poll like WF01, not a push like WF21.
    n28_dedup  = nodes["28"].get("Dedup Check", "")
    n28_upsert = nodes["28"].get("Upsert Individual + Session", "")
    n28_rel    = nodes["28"].get("Create Relationships", "")

    require_contains("28", "Dedup Check", n28_dedup, "fc.get_nodes_by_type(", failures)
    require_absent("28", "Dedup Check", n28_dedup, "fc.get_graph(", failures,
                   why="full-graph read truncates at 100k nodes and breaks dedup")

    # edit_node passes `updates` through verbatim, so a bare key lands at the node's
    # top level where no reader looks. Without _np() a re-checked-in agent keeps its
    # first-contact last_checkin forever and the AGENTS tab calls it stale -- the
    # exact bug that froze WF01 and WF21 until 2026-08-13.
    for node_name, code in (("Upsert Individual + Session", n28_upsert),):
        require_contains("28", node_name, code, "'nodeProperties.' + k", failures)

    # 'individual' must stay lowercase: Neo4j labels are case-sensitive and
    # create_node does not normalise, so 'Individual' builds a second label that
    # this workflow's own dedup can never see.
    require_contains("28", "Upsert Individual + Session", n28_upsert,
                     "node_type='individual'", failures)
    require_absent("28", "Upsert Individual + Session", n28_upsert,
                   "node_type='Individual'", failures,
                   why="capitalised label is invisible to the dedup that reads 'individual'")

    # Adaptix reports elevation, sleep and jitter that Brute Ratel does not; losing
    # any of them blanks a column the AGENTS tab exists to serve.
    for key in ("'listener'", "'pid'", "'thread_id'", "'os_version'", "'arch'",
                "'sleep_seconds'", "'jitter_pct'", "'is_admin'", "'last_checkin'"):
        require_contains("28", "Upsert Individual + Session", n28_upsert, key + ":", failures)

    # /agent/list carries no process list, so an unguarded patch would write the
    # empty list over enrichment from a `ps` task on every 5-minute poll.
    require_contains("28", "Upsert Individual + Session", n28_upsert,
                     "if v is not None and v != []", failures)

    require_contains("28", "Create Relationships", n28_rel, "'HAS_BEACON'", failures)
    # A name-less Technology node makes GET /graph return 500 for the WHOLE sketch.
    require_contains("28", "Create Relationships", n28_rel, "'name': tech", failures)

    # Workflow 04 checks — attack-path scoring must stay exploit-aware.
    # WF04 used to score AD ACEs and nothing else, so a host with working public
    # exploit code for an internet-facing service ranked identically to one
    # without (issues.md, PoC section item 8). Three parts of that wiring are
    # easy to drop by accident and silent when dropped.
    n04_fetch = nodes["04"].get("Fetch Full Graph", "")
    n04_score = nodes["04"].get("Score Attack Paths", "")
    # The AD graph and exploit layer are read with indexed readers and handed
    # downstream. Filtering a full-graph payload instead loses data on any sketch
    # over 100k nodes, which is where GET /graph truncates.
    require_contains("04", "Fetch Full Graph", n04_fetch, "fc.resolve_campaign_sketch(", failures)
    require_contains("04", "Fetch Full Graph", n04_fetch, "fc.get_nodes_by_type(", failures)
    require_contains("04", "Fetch Full Graph", n04_fetch, "fc.get_edges_by_type(", failures)
    require_contains("04", "Fetch Full Graph", n04_fetch, "AD_LABELS", failures)
    require_contains("04", "Fetch Full Graph", n04_fetch, "AD_EDGES", failures)
    require_contains("04", "Fetch Full Graph", n04_fetch, "'tech_rls'", failures)
    require_absent("04", "Fetch Full Graph", n04_fetch, "fc.get_graph(", failures,
                   why="full-graph read truncates at 100k nodes and drops identities before scoring")
    # Ownership is not hosting. WF13 links an apex WebAsset to whoever's whois
    # email or name matches it, and every CDN edge node answering for that domain
    # hangs off the same asset — so carrying exploit facts across MANAGES would
    # charge a person with Akamai's CVEs.
    require_absent("04", "Fetch Full Graph", n04_fetch, "'MANAGES'", failures,
                   why="MANAGES is ownership, not hosting: it would inherit a CDN's CVEs")
    require_contains("04", "Score Attack Paths", n04_score, "exploit_index", failures)
    # The discount on keyword-matched CVE sets. NVD's keywordSearch is a phrase
    # match against CVE descriptions, so Ivanti Sentry's CVE-2023-38035 attaches
    # to every Apache host; without this scale those score like a real finding.
    require_contains("04", "Score Attack Paths", n04_score, "EXPLOIT_BASIS_SCALE", failures)
    require_contains("04", "Score Attack Paths", n04_score, "'keyword': 0.5", failures)

    # ── Cloud exposure ───────────────────────────────────────────────────────
    # Its own bounded term, deliberately NOT routed through the exploit-carrier
    # machinery. Both halves of that are easy to undo by accident.
    n04_update = nodes["04"].get("Update Dossier Notes", "")
    require_contains("04", "Fetch Full Graph", n04_fetch, "CLOUD_LABELS", failures)
    require_contains("04", "Fetch Full Graph", n04_fetch, "'cloud_rls'", failures)
    require_contains("04", "Score Attack Paths", n04_score, "CLOUD_ATTRIB_SCALE", failures)
    # The weakest attribution tier is a name query against a third-party index --
    # the same class of error as an NVD keyword match, so it takes the same 0.5.
    require_contains("04", "Score Attack Paths", n04_score, "'grayhatwarfare': 0.5", failures)
    require_contains("04", "Score Attack Paths", n04_score, "CLOUD_MAX_BONUS", failures)
    require_absent("04", "Score Attack Paths", n04_score, "'HAS_CLOUD_ASSET'", failures,
                   why="a public bucket is not a CVE; scoring it through the carrier "
                       "graph would spend NVD quota keyword-matching bucket names")
    # A stored string 'False' is truthy in Python and JS alike, and this node type
    # carries several spellings of "anyone can read it".
    require_contains("04", "Score Attack Paths", n04_score, "def _cloud_public(p):", failures)
    require_contains("04", "Score Attack Paths", n04_score, "if _truthy(p.get(key)):", failures)
    # sensitive_categories arrives from WF13 as a JSON string; a raw membership
    # test against it matches single characters.
    require_contains("04", "Score Attack Paths", n04_score, "def _jlist(raw):", failures)
    # The write-back item carries no ind_id, and the dossier loop's
    # `if not ind_id: continue` DROPS such an item silently -- which is how a whole
    # feature ships computing a number nothing persists.
    require_contains("04", "Update Dossier Notes", n04_update,
                     "d.get('kind') == 'cloud_exposure'", failures)
    require_contains("04", "Update Dossier Notes", n04_update,
                     "'nodeProperties.cloud_attack_bonus'", failures)
    # The caveat has to travel with the number: nothing here moves an attack_score.
    require_contains("04", "Score Attack Paths", n04_score, "CLOUD_CAVEAT", failures)
    require_contains("04", "Score Attack Paths", n04_score, "'unattributed': True", failures)
    # The opt-in owner credit must ship INERT. Crediting a person for a bucket
    # reverses the standing "ownership is not hosting" decision, so the built-in
    # fallback -- what a task runner holding a stale spotter_settings would use --
    # has to be 0 as well as the spec default. No offline fixture can catch this:
    # with a current spec the constant is never read.
    require_contains("04", "Score Attack Paths", n04_score,
                     "CLOUD_OWNER_MAX_BONUS_DEFAULT = 0", failures)
    # And the edge it reads must stay the asset-SCOPED one. The bare ownership
    # label is already pinned absent from Fetch Full Graph above.
    #
    # The literal moved from MANAGES_NAMED to OWNS_ASSET when WF13's name-token
    # match was removed: that branch attributed every asset on a domain to every
    # identity WF13 had promoted from a breach email on it, because such an
    # identity's nodeLabel IS an address on the domain. The DECISION this pin
    # protects -- asset-scoped evidence only, never the domain-wide registrant --
    # is unchanged, and now lives in scripts/asset_ownership.py, so the pin is on
    # the derivation rather than on a hard-coded list. HAS_ACCESS must not appear
    # here: WF04 scores control, not reach.
    require_contains("04", "Fetch Full Graph", n04_fetch,
                     "OWNER_EDGES = list(SCORING_OWNER_EDGES)", failures)
    require_absent("04", "Fetch Full Graph", n04_fetch, "'HAS_ACCESS'", failures,
                   why="WF04 scores control (OWNS_ASSET), never mere reach")

    # Workflow 05 checks — dossier output must carry WF04's exploit-aware score
    # provenance in both the target list and the single-person dossier payload.
    n05_compile = nodes["05"].get("Compile Dossier", "")
    require_contains("05", "Compile Dossier", n05_compile,
                     "'attack_summary': _json_obj(props.get('attack_summary'))", failures)
    require_contains("05", "Compile Dossier", n05_compile,
                     "'attack_summary': _json_obj(ind_props.get('attack_summary'))", failures)

    # Workflow 23 checks
    n23 = nodes["23"].get("Build Agent Roster", "")
    # The REST graph path nulls every *declared* boolean and integer, which would
    # blank is_admin, is_dead, is_pivot, pid, thread_id, sleep_seconds, jitter_pct
    # and priority_score -- eight of the fields this endpoint exists to serve. The
    # per-label Neo4j reader returns properties(n) untouched.
    require_contains("23", "Build Agent Roster", n23, "fc.get_nodes_by_type(", failures)
    require_absent("23", "Build Agent Roster", n23, "fc.get_graph(", failures,
                   why="the REST graph path nulls declared booleans and integers")
    # Both labels or the roster silently halves: CobaltBeacon is the legacy type and
    # is still registered alongside C2Session.
    require_contains("23", "Build Agent Roster", n23, "'CobaltBeacon'", failures)
    # A UI webhook carries a body, so it must honour the campaign the operator has
    # open. resolve_campaign_sketch() is for the body-less triggers (01/02/21) and
    # would pin this endpoint to the most recent campaign instead.
    require_contains("23", "Build Agent Roster", n23, "_sb.get('sketch_id')", failures)
    require_absent("23", "Build Agent Roster", n23, "fc.resolve_campaign_sketch(", failures,
                   why="a UI webhook must read sketch_id from its request body")
    # Framework naming has one home. A local fallback map here would relabel every
    # badger as a beacon and look like it worked.
    require_contains("23", "Build Agent Roster", n23, "from c2_common import framework_display", failures)

    # Workflow 24 checks — the notification feed. All logic lives in
    # scripts/spotter_notify.py (see check_notification_invariants); the code
    # node itself only has to import it and refuse the two sketch shortcuts.
    n24 = nodes["24"].get("Sweep And List", "")
    require_contains("24", "Sweep And List", n24, "import spotter_notify as notify", failures)
    # This endpoint authorises the caller against the campaign and then takes the
    # sketch FROM THE REGISTRY. Either shortcut below would let one operator
    # sweep another operator's graph into their own ticker.
    require_absent("24", "Sweep And List", n24, "resolve_campaign_sketch(", failures,
                   why="the notification sweep derives its sketch from the campaign registry")
    require_absent("24", "Sweep And List", n24, "FLOWSINT_SKETCH_ID", failures,
                   why="the env fallback sketch does not exist and would sweep nothing")

    # Workflow 14 checks — technology/CVE/MITRE/PoC context enrichment. This
    # workflow is long-running and deliberately degrades in several places, so a
    # syntax error or dropped invariant otherwise surfaces only when the operator
    # notices an empty Vulnerable Technology panel.
    n14 = nodes["14"].get("Enrich + Index Tech Context", "")
    require_contains("14", "Enrich + Index Tech Context", n14,
                     "fc.resolve_campaign_sketch(str(_sb.get('sketch_id') or ''))", failures)
    require_absent("14", "Enrich + Index Tech Context", n14,
                   "os.environ.get('FLOWSINT_SKETCH_ID'", failures,
                   why="scheduled enrichment must resolve the active campaign registry")
    require_contains("14", "Enrich + Index Tech Context", n14, "_st.resolve_many([", failures)
    for key in ("'TECH_ENRICH_MAX_NODES'", "'CVE_MAX_PER_TECH'", "'POC_MAX_PER_CVE'",
                "'POC_MIN_STARS'", "'POC_MIRROR_MAX_AGE_DAYS'"):
        require_contains("14", "Enrich + Index Tech Context", n14, key, failures)
    require_contains("14", "Enrich + Index Tech Context", n14, "PoCClient()", failures)
    require_contains("14", "Enrich + Index Tech Context", n14, "mirror_status()", failures)
    require_contains("14", "Enrich + Index Tech Context", n14,
                     "tech_enricher.enrich_technology_nodes(", failures)
    require_contains("14", "Enrich + Index Tech Context", n14,
                     "_ix.index_cve_ids(cve_ids) if cve_ids else 0", failures)
    require_contains("14", "Enrich + Index Tech Context", n14,
                     "_ix.index_pocs(cve_ids) if cve_ids else 0", failures)
    require_contains("14", "Enrich + Index Tech Context", n14,
                     "_ix.index_asset_inventory(techs)", failures)

    # Workflow 03 checks
    n03_social = nodes["03"].get("Social Enrichment", "")
    require_contains("03", "Social Enrichment", n03_social, "single_label = (entity.get('label') or body.get('entity_label') or '').strip().lower()", failures)
    require_contains("03", "Social Enrichment", n03_social, "enabled_plugin_flows = [name for name, fid in plugin_flow_ids.items() if fid]", failures)
    require_contains("03", "Social Enrichment", n03_social, "if 'maigret' in enabled_plugin_flows and not p.get('maigret_enriched')", failures)
    require_contains("03", "Social Enrichment", n03_social, "if 'linkedin' in enabled_plugin_flows and not p.get('linkedin_enriched')", failures)
    require_contains("03", "Social Enrichment", n03_social, "'mode': 'single' if (single_id or single_label) else 'sweep'", failures)
    # The regional social sweeps are ADDITIVE by design. Maigret tags only 61 sites
    # 'us' and 32 'cn', and GitHub/Instagram/Twitter/LinkedIn/Facebook carry no
    # country tag at all, so turning the Objectives-tab checkboxes into a filter
    # would silently drop every major platform. The global pass must stay
    # unconditional and the region codes must be validated against a fixed list.
    require_contains("03", "Social Enrichment", n03_social, "VALID_REGIONS = ('us', 'ru', 'cn')", failures)
    require_contains("03", "Social Enrichment", n03_social, "sweep(u, '', MG_TOP)", failures)
    # Reads the proxy/opsec envelope the frontend has always sent. Without it the
    # VK/Odnoklassniki/Yandex/Weibo probes leave from the operator's real IP.
    require_contains("03", "Social Enrichment", n03_social, "_proxy_url_from_envelope(", failures)
    require_contains("03", "Social Enrichment", n03_social, "payload['proxy_url'] = SOCIAL_PROXY_URL", failures)
    # The socid second stage opens one page per profile, so it has to stay bounded.
    require_contains("03", "Social Enrichment", n03_social, "discovered[:SOCID_MAX_URLS]", failures)
    # Direct mode has never returned a `status` key, and _assertSocialEnrichAccepted
    # treats a missing status as success. Adding one makes every enrich path that
    # passes allowNoTargets:false throw on runs that previously passed quietly.
    require_absent("03", "Social Enrichment", n03_social, "'status': 'ok' if cand", failures,
                   why="direct mode must not emit a status key — the frontend reads its absence as success")

    # Workflow 06 checks
    n06_detect = nodes["06"].get("Detect Format", "")
    n06_parse_sh = nodes["06"].get("Parse SharpHound", "")
    require_contains("06", "Detect Format", n06_detect, "SPOTTER_UPLOAD_MAX_BYTES", failures)
    require_contains("06", "Detect Format", n06_detect, "glob.glob(f'{DROP_DIR}/_ingest_*')", failures)
    require_contains("06", "Parse SharpHound", n06_parse_sh, "if k not in ('nodes', 'edges')", failures)
    # The webhook runs with rawBody: true, so item.binary is populated on EVERY
    # request and holds the JSON envelope for a plain POST. Resolving binary before
    # the explicit body fields silently ingested that envelope instead of the
    # csv_text / text payload, so the branch order is the guardrail here.
    require_contains("06", "Detect Format", n06_detect, "_payload_field", failures)
    require_contains("06", "Detect Format", n06_detect,
                     "was present but carried no data", failures)
    # A chunked upload is a staged id, not a body. The id is confined to the
    # staging root; a path that is not a uuid is rejected before any read.
    require_contains("06", "Detect Format", n06_detect, "staged_id", failures)
    require_contains("06", "Detect Format", n06_detect, "resolve_staged", failures)
    require_contains("06", "Parse SharpHound", n06_parse_sh, "item.get('staged')", failures)
    if "if binary and not body.get('zip_b64')" in n06_detect:
        failures.append(
            "[06] Detect Format: binary is resolved before the explicit body fields "
            "again — csv_text/text uploads will ingest the JSON envelope"
        )
    n06_text = nodes["06"].get("Parse Text (LLM)", "")
    require_contains("06", "Parse Text (LLM)", n06_text, "upload carried no bytes", failures)
    # The Titus branch must scope to the campaign the operator uploaded under.
    # Reading only FLOWSINT_SKETCH_ID wrote every recovered credential into the env
    # fallback sketch — findings for one engagement landing in another graph.
    n06_titus = nodes["06"].get("Scan Credentials (Titus)", "")
    require_contains("06", "Scan Credentials (Titus)", n06_titus,
                     "item.get('sketch_id') or _sb.get('sketch_id') or sketch_id", failures)

    # Route by Format must stay on the Switch V3 parameter shape. With V1 params
    # (dataPropertyName + rules.values[].value + top-level fallbackOutput) on a
    # typeVersion 3 node, SwitchV3 finds no `conditions` and no
    # `options.fallbackOutput`, so no rule can ever match.
    wf06 = load_json(TARGETS["06"])
    switch = next((n for n in wf06["nodes"] if n.get("name") == "Route by Format"), {})
    sp = switch.get("parameters", {})
    if "dataPropertyName" in sp or "fallbackOutput" in sp:
        failures.append("[06] Route by Format: Switch V1 parameters on a V3 node — no rule can match")
    rule_values = sp.get("rules", {}).get("values", [])
    if not rule_values or not all(r.get("conditions", {}).get("conditions") for r in rule_values):
        failures.append("[06] Route by Format: rules are missing V3 `conditions` filters")
    if sp.get("options", {}).get("fallbackOutput") != "extra":
        failures.append("[06] Route by Format: options.fallbackOutput must be 'extra'")
    n_outputs = len(rule_values) + 1  # rules + the extra fallback output
    n_conns = len(wf06.get("connections", {}).get("Route by Format", {}).get("main", []))
    if n_conns != n_outputs:
        failures.append(
            f"[06] Route by Format: {n_conns} wired outputs but {n_outputs} exist "
            f"({len(rule_values)} rules + fallback) — a format is unrouted"
        )

    # The Nessus route must stay wired all the way through. Two ways it silently
    # is not: the parse node stops trimming its output (a 100k-row report then
    # ships tens of thousands of nodes between code nodes and destabilises the
    # execution), or the guard that keeps unregistered Vulnerability nodes out of
    # the graph is removed — one such node 500s GET /graph for the whole sketch.
    n06_nessus = nodes["06"].get("Parse Nessus", "")
    require_contains("06", "Parse Nessus", n06_nessus, "if k not in ('nodes', 'edges')", failures)
    require_contains("06", "Parse Nessus", n06_nessus, "vuln_nodes_ingested", failures)

    # The EyeWitness route must trim its node/edge arrays like the other parse
    # nodes — a large web sweep produces one Website node per URL, and shipping
    # them between code nodes destabilises the execution. It must also route to a
    # real parser, not the LLM fallback (Website is a built-in type; unlike the
    # custom-type routes there is no registration guard to assert here).
    n06_ew = nodes["06"].get("Parse EyeWitness", "")
    require_contains("06", "Parse EyeWitness", n06_ew, "if k not in ('nodes', 'edges')", failures)
    # Titus must skip EyeWitness output: its "Default Creds" column and HTML source
    # would otherwise register as recovered credentials.
    require_contains("06", "Scan Credentials (Titus)", n06_titus, "eyewitness", failures)
    # Titus base64-encodes the file into another webhook. A staged report over
    # the credential-scan cap must be skipped before that read.
    require_contains("06", "Scan Credentials (Titus)", n06_titus, "SPOTTER_CRED_SCAN_MAX_BYTES", failures)
    # Ingest is not finished until the findings are joined to something: WF25 is
    # what writes exploit availability and the per-host rollup the rest of SPOTTER
    # reads. Firing it must stay fire-and-forget, and must not gate ingest_ok.
    require_contains("06", "Parse Nessus", n06_nessus, "/webhook/vuln-context", failures)

    # Workflow 25 checks. The rollup is the half that makes scan data reachable —
    # without it the findings sit in the graph connected to nothing.
    n25_ctx = nodes["25"].get("Contextualize Findings", "")
    n25_sum = nodes["25"].get("Read Vulnerability Summary", "")
    require_contains("25", "Contextualize Findings", n25_ctx, "nessus_context.run", failures)
    require_contains("25", "Contextualize Findings", n25_ctx, "NESSUS_CONTEXT_MAX_NODES", failures)
    # An empty summary has two causes needing different operator actions ("nothing
    # ingested" vs "custom type not registered, findings dropped"). Collapsing them
    # into "no vulnerabilities found" is the failure this pins.
    require_contains("25", "Read Vulnerability Summary", n25_sum, "empty_reason", failures)
    # The detailed empty-state diagnosis now lives in nessus_context.summarise(),
    # so the workflow and the LLM tool report the same reason. Keep the installer
    # hint pinned at the owner instead of forcing a duplicate string into WF25.
    nessus_context_text = (REPO_ROOT / "scripts" / "nessus_context.py").read_text()
    if "register_nessus_type.py --apply" not in nessus_context_text:
        failures.append(
            "nessus_context.py: empty vulnerability summary no longer tells the "
            "operator to run scripts/register_nessus_type.py --apply"
        )

    wf25 = load_json(TARGETS["25"])
    _w25 = {n.get("name"): n for n in wf25["nodes"]}
    _ctx_hook = _w25.get("Vuln Context Webhook", {}).get("parameters", {})
    _sum_hook = _w25.get("Vuln Summary Webhook", {}).get("parameters", {})
    if _ctx_hook.get("responseMode") != "onReceived":
        failures.append(
            "[25] Vuln Context Webhook: responseMode must be 'onReceived' — a full "
            "contextualization pass outlives the proxy timeout and would report a "
            "failure for a run that is proceeding correctly")
    if _sum_hook.get("responseMode") != "responseNode":
        failures.append(
            "[25] Vuln Summary Webhook: responseMode must be 'responseNode' or the "
            "panel receives no body")

    # Workflow 10 — the operator_tags contract with the browser.
    #
    # These marks exist ONLY in the operator's localStorage; WF10 is their sole
    # backend consumer and there is no graph trace of them. So if a refactor drops
    # the parse or one of the three drop sites, WF10 silently scores entities the
    # operator excluded from the engagement or judged a false positive, the analysis
    # quietly widens, and nothing anywhere fails. Pin both exclusion marks, all
    # three drop sites, and both echo keys.
    n10 = nodes["10"].get("Fetch Graph + Run Analysis LLM", "")
    for _needle in (
        "_op_tags.get('out_of_scope')", "_op_tags.get('false_positive')",
        "_op_dev.get('out_of_scope')",  "_op_dev.get('false_positive')",
        "_hit_oos or _hit_fp",     # individuals drop site
        "_dhit_oos or _dhit_fp",   # devices drop site
        "_ahit_oos or _ahit_fp",   # external-asset drop site
        "'out_of_scope': {", "'false_positive': {",
        "_op_fp_matched", "_opd_fp_matched",
        # The asset alias set the browser needs to make a mark made on the analysis
        # card match the Web tab's url key and the bucket list's endpoint key.
        "'keys':       sorted(_acand)",
    ):
        require_contains("10", "Fetch Graph + Run Analysis LLM", n10, _needle, failures)

    # ...and the reciprocal half, so the two cannot drift apart. The browser is the
    # only sender; a WF10 that parses false_positive nobody ships is dead code.
    _index_html = (REPO_ROOT / "frontend" / "index.html").read_text()
    for _needle in ("false_positive: Object.keys(getFPTargets())",
                    "false_positive: Object.keys(getDevFPTargets())"):
        if _needle not in _index_html:
            failures.append(
                f"frontend/index.html: runAnalysis no longer ships `{_needle}` to WF10 — "
                "false-positive marks would stop excluding anything server-side")

    # Workflow 09 checks
    n09_fetch = nodes["09"].get("Fetch Individuals + Flare Auth", "")
    n09_search = nodes["09"].get("Search Flare for Each Individual", "")
    n09_import = nodes["09"].get("Import Breach Nodes to Flowsint", "")
    require_contains("09", "Fetch Individuals + Flare Auth", n09_fetch, "auth_error_type", failures)
    require_contains("09", "Search Flare for Each Individual", n09_search, "search_error_types", failures)
    require_contains("09", "Search Flare for Each Individual", n09_search, "failed_individuals_count", failures)
    require_contains("09", "Import Breach Nodes to Flowsint", n09_import, "import_failed", failures)
    require_contains("09", "Import Breach Nodes to Flowsint", n09_import, "edge_failed", failures)
    require_contains("09", "Import Breach Nodes to Flowsint", n09_import, "search_status", failures)

    # Workflow 11 checks
    n11_scan = nodes["11"].get("Scan with Titus", "")
    require_contains("11", "Scan with Titus", n11_scan, "SPOTTER_CRED_SCAN_MAX_BYTES", failures)
    require_contains("11", "Scan with Titus", n11_scan, "base64 payload too large", failures)
    require_contains("11", "Scan with Titus", n11_scan, "file too large", failures)

    # Workflow 12 checks - "hosts in use" filter must not be silently reverted.
    # The coverage gate is the safety property: without it a graph that was never
    # backfilled would filter every device out and the Tech Intel tab would go dark.
    n12_build = nodes["12"].get("Build Tech Inventory + Narratives", "")
    require_contains("12", "Build Tech Inventory + Narratives", n12_build, "ACTIVITY_COVERAGE_STRICT", failures)
    require_contains("12", "Build Tech Inventory + Narratives", n12_build, "activity_filter_applied", failures)
    require_contains("12", "Build Tech Inventory + Narratives", n12_build, "no_timestamp_data", failures)
    # The prune must cover `devices` too, or the edge loop re-admits stale hosts.
    require_contains("12", "Build Tech Inventory + Narratives", n12_build,
                     "devices = {k: v for k, v in devices.items() if k in device_profiles}", failures)
    require_contains("12", "Build Tech Inventory + Narratives", n12_build, "'total_devices_all'", failures)
    require_contains("12", "Build Tech Inventory + Narratives", n12_build, "pasted_processes", failures)
    # vulnerable_tech's affected-host loop is SINGLE-HOP: it scans edges touching
    # the component and requires the far end to be an individual or a device. So
    # EXPOSES_SERVICE (device -> Service) is the only edge that can ever name the
    # host of an external Service, and without it every perimeter service row
    # reports no affected host. Verified offline: with EXPOSES_SERVICE the row
    # names the device, with IMPLEMENTED_IN alone it names nothing, because that
    # edge's far end is another component rather than a host.
    require_contains("12", "Build Tech Inventory + Narratives", n12_build,
                     "['USES_TECH', 'EXPOSES_SERVICE']", failures)

    # Workflow 13 checks - open cloud storage discovery
    n13 = nodes["13"].get("Run Domain OSINT + Breach Correlation", "")
    # The buckets source must stay gated, or every domain-recon run probes the cloud.
    require_contains("13", "buckets gate", n13, "if 'buckets' in sources_set:", failures)
    # Partial re-runs must not wipe previously gathered bucket data.
    require_contains("13", "source pruning", n13, "'buckets': ['open_buckets'", failures)
    # The probe must stay bounded or it hangs the synchronous webhook.
    require_contains("13", "probe budget", n13, "BUCKET_MAX_SECONDS", failures)
    require_contains("13", "probe budget", n13, "_bucket_deadline", failures)
    # AWS throttling makes a blocked probe look identical to a clean sweep. Losing
    # the canary turns "we were blocked" into a confident, wrong zero.
    require_contains("13", "throttle canary", n13, "BUCKET_S3_CANARY", failures)
    require_contains("13", "throttle canary", n13, "bucket_probe_throttled", failures)
    require_contains("13", "throttle canary", n13, "s3_trustworthy", failures)
    # Azure account names are 3-24 lowercase alphanumerics; unsanitised candidates
    # waste every request in the container fan-out.
    require_contains("13", "azure naming", n13, "re.sub(r'[^a-z0-9]', '', c)[:24]", failures)
    # Exposure findings must land on the existing CloudAsset label. A new node label
    # would make GET /graph 500 for the whole sketch until the type is registered.
    require_contains("13", "CloudAsset reuse", n13, "upsert('CloudAsset'", failures)
    if "add_node(label=label, node_type='Bucket'" in n13 or "'CloudBucket'" in n13:
        failures.append("13: introduced a new bucket node label; extend CloudAsset instead "
                        "(unregistered nodeType makes GET /graph 500 for the sketch)")
    # DNS resolution honours the opsec.dns_resolvers envelope (Infrastructure ->
    # OPSEC). WF13 resolves over DoH, so the resolver list selects which endpoint
    # answers; losing this wiring silently reverts every lookup to hardcoded
    # Google DoH from the real IP.
    require_contains("13", "dns resolver opsec", n13, "_doh_endpoints_from_opsec(opsec_cfg)", failures)
    require_contains("13", "dns resolver opsec", n13, "DOH_ACTIVE = DOH_ENDPOINTS or [DOH_DEFAULT]", failures)
    require_contains("13", "dns resolver opsec", n13, "for _ep in DOH_ACTIVE:", failures)
    # The DNS loop must go through the endpoint builder (not a hardcoded URL) and
    # ride the configured proxy like the THC calls do.
    require_contains("13", "dns resolver opsec", n13, "_doh_query_url(_ep, domain, qtype)", failures)
    require_contains("13", "dns resolver opsec", n13, "headers=_doh_headers, proxies=THC_PROXIES", failures)
    # THC reverse-DNS returns country names, while ipinfo returns ISO-2 codes.
    # Keep the top-level hosting field normalized so UI/export/LLM consumers do
    # not have to handle both `US` and `United States` for the same property.
    require_contains("13", "THC country normalization", n13, "'country':   _to_iso2_country(_meta.get('country', ''))", failures)
    require_contains("13", "THC incomplete reason", n13, "'thc_incomplete_reason': ''", failures)
    require_contains("13", "THC incomplete reason", n13, "'budget_guard_stop'", failures)
    require_contains("13", "THC incomplete reason", n13, "'service_429'", failures)
    # THC-only subdomains must be safe to persist even when CertKit found no
    # certificate for them: the graph import may not depend on cert-derived data.
    require_contains("13", "THC subdomain import", n13, "subprops = {", failures)
    require_contains("13", "THC subdomain import", n13, "'fqdn': sub, 'parent_domain': domain", failures)
    require_contains("13", "THC subdomain import", n13, "upsert('Subdomain', sub, sub, subprops)", failures)
    # External recon services should join back to AD devices when there is a
    # strong hostname/IP match. WF04 already treats EXPOSES_SERVICE as an exploit
    # carrier, so this is the data-model bridge that makes domain recon affect
    # identity scoring without using MANAGES ownership edges.
    require_contains("13", "service-device correlation", n13, "'device', 'ip', 'Ip', 'IP'", failures)
    require_contains("13", "service-device correlation", n13, "['RESOLVES_TO']", failures)
    require_contains("13", "service-device correlation", n13, "def devices_for_service(sr):", failures)
    require_contains("13", "service-device correlation", n13, "link(_dev['id'], sid_n, 'EXPOSES_SERVICE')", failures)
    require_contains("13", "service-device correlation", n13, "'service_device_links'", failures)
    # WF14 prefers Shodan scanner CVEs, then CPEs, then weak product keywords.
    # Dropping Service CPEs pushes exact Shodan matches back into noisy NVD phrase
    # search, which is the root cause of false positives like Apache hosts picking
    # up unrelated Ivanti CVEs.
    require_contains("13", "Service CPE propagation", n13, "match.get('cpes') or match.get('cpe')", failures)
    require_contains("13", "Service CPE propagation", n13, "'cpe': (_cpes[0] if _cpes else '')", failures)
    require_contains("13", "Service CPE propagation", n13, "'cpes': json.dumps(_cpes)", failures)
    # CT, THC, and FOFA feed one capped subdomain list; quotas plus round-robin
    # remainder filling stop a noisy source from silently crowding out the rest.
    require_contains("13", "subdomain source mix", n13, "SUBDOMAIN_QUOTAS = {'ct': 50, 'thc': 35, 'fofa': 15}", failures)
    require_contains("13", "subdomain source mix", n13, "def _build_subdomain_mix(thc_set, ct_set, fofa_set, cap):", failures)
    require_contains("13", "subdomain source mix", n13, "result['subdomain_mix'] = mix", failures)
    # FOFA rejects the WHOLE query, HTTP 200 + error + zero rows, when any single
    # requested field is above the account tier. WF13 asked for product,
    # as_organization and lastupdatetime -- all forbidden here -- so FOFA returned
    # nothing on every run ever made, and the card rendered itself away. The
    # ladder retries with narrower field sets; fofa_status carries the reason.
    require_contains("13", "FOFA field entitlements", n13, "FOFA_FIELD_TIERS = [", failures)
    require_contains("13", "FOFA field entitlements", n13,
                     "'host,ip,port,protocol,title,server,os,country,region,city,link,domain,icp',", failures)
    require_contains("13", "FOFA field entitlements", n13, "result['fofa_status']", failures)
    require_contains("13", "FOFA field entitlements", n13,
                     "'fofa':   ['fofa_results', 'fofa_total', 'fofa_ports', 'fofa_products', 'fofa_status'],",
                     failures)
    # shodan_api_status travels with the shodan_* keys. A present-but-empty key
    # beats a previous good value in the frontend's shallow merge, so a non-Shodan
    # re-run must prune it, and a Shodan run must be able to set it.
    require_contains("13", "Shodan status", n13,
                     "'shodan': ['shodan_results', 'shodan_open_ports', 'shodan_vulns', 'shodan_api_status'],",
                     failures)
    require_contains("13", "Shodan status", n13, "proxies=THC_PROXIES", failures)
    require_contains("13", "Shodan status", n13, "headers=_shodan_headers", failures)

    # ── Perimeter technologies ───────────────────────────────────────────────
    # WF13 must create first-class Technology nodes from perimeter recon. Before
    # this, every product string and CPE that Shodan and FOFA returned died inside
    # a Service node's JSON blob and never reached Tech Intel (WF12), CVE/MITRE/PoC
    # enrichment (WF14) or attack-path scoring (WF04) -- all three key on Technology.
    require_contains("13", "perimeter technology", n13, "upsert('Technology'", failures)
    require_contains("13", "perimeter technology", n13, "'Technology': 'name'", failures)
    # `name` is REQUIRED on the built-in Technology type, and the graph serializer
    # strips '' BEFORE validating, so an empty name is as fatal as a missing one:
    # one such node makes GET /graph 500 for the whole sketch (WF01 shipped it).
    #
    # check_required_builtin_props CANNOT catch this here. Its regex needs a string
    # literal `node_type='X'`, and every WF13 write goes through
    # upsert() -> fc.add_node(node_type=node_type, properties=props), so the
    # extraction returns None and the call is skipped. These pins plus the
    # smoke_workflow13 junk-product fixture are the whole guard.
    require_contains("13", "perimeter technology", n13, "'name': _name", failures)
    require_contains("13", "perimeter technology", n13, "if not _name:", failures)
    require_contains("13", "perimeter technology", n13, "if not clean.get('name'):", failures)
    # WF04's EXPLOIT_INTERNET_BONUS is derived from source == 'domain-recon'
    # (Score Attack Paths). The string is a join, not a label.
    require_contains("13", "perimeter technology", n13, "'source': 'domain-recon'", failures)
    # Both carrier edges. IMPLEMENTED_IN matches upload_router._parse_nmap so the
    # two writers produce one shape; USES_TECH is the only tech edge WF12's
    # single-hop affected-host loop can resolve.
    require_contains("13", "perimeter technology", n13, "'IMPLEMENTED_IN')", failures)
    require_contains("13", "perimeter technology", n13, "'USES_TECH')", failures)
    # Dedup must see BOTH spellings: fc.add_node preserves PascalCase
    # (WF01/13/21/28), batch_import lowercases (nmap / Nessus / process-list), and
    # get_nodes_by_type interpolates the label into a case-sensitive MATCH.
    require_contains("13", "perimeter technology", n13, "'Technology', 'technology'", failures)
    require_contains("13", "perimeter technology", n13, "nt.lower() == 'technology'", failures)
    # The nodeLabel is the server-side MERGE key (add_node MERGEs on
    # label+nodeLabel+sketch_id), so it must be version-free or the node forks on
    # every new banner string.
    require_contains("13", "perimeter technology", n13, "def _tech_key(raw):", failures)
    # Caps: each new Technology costs WF14 one NVD keyword search (6 s minimum with
    # no NVD_API_KEY) plus up to CVE_MAX_PER_TECH detail lookups.
    require_contains("13", "perimeter technology", n13, "TECH_PRODUCT_CAP", failures)
    require_contains("13", "perimeter technology", n13, "TECH_PLATFORM_CAP", failures)
    require_contains("13", "perimeter technology", n13, "tech_truncated", failures)
    # High-value labels have ONE home; see check_high_value_tech_catalog.
    require_contains("13", "perimeter technology", n13,
                     "from high_value_tech import HIGH_VALUE_TECH", failures)
    # Ownership is not hosting -- here as in WF04. A MANAGES edge onto a Technology
    # would reintroduce "charge a person with Akamai's CVEs" by another route.
    require_absent("13", "perimeter technology", n13, "_tid, 'MANAGES'", failures,
                   why="MANAGES on a Technology inherits a vendor's CVEs to a person")
    require_absent("13", "perimeter technology", n13, "_pid, 'MANAGES'", failures,
                   why="MANAGES on a Technology inherits a vendor's CVEs to a person")
    # A DNS-inferred platform must hang off the apex WebAsset, never a Service:
    # Technology -> Service -> device is exactly two carrier hops, so a CDN's CVEs
    # would land on every AD device matched to that IP.
    require_contains("13", "perimeter technology", n13,
                     "_tech_link(apex_id, _pid, 'USES_TECH')", failures)
    # 'technologies' prunes with services; 'platform_tech' is base recon and must
    # never be pruned, or a shodan-only re-run deletes the DNS half from the
    # frontend's shallow-merged record.
    require_contains("13", "source pruning", n13, "result.pop('technologies', None)", failures)
    _g13 = n13.split("_GROUPS = {", 1)[-1].split("}", 1)[0] if "_GROUPS = {" in n13 else ""
    for _k in ("platform_tech", "technologies"):
        if _k in _g13:
            failures.append(
                f"13: '{_k}' must not be listed in the source-pruning _GROUPS table "
                f"-- that table prunes per-source, so it would be deleted on a run "
                f"that used the other source")

    # The code node must still reach the respond node, or the webhook hangs.
    _c13 = wf["13"].get("connections", {})
    _code_targets = {t.get("node") for grp in
                     _c13.get("Run Domain OSINT + Breach Correlation", {}).get("main", [[]])
                     for t in grp}
    if "Return Domain Recon" not in _code_targets:
        failures.append("13: code node no longer reaches 'Return Domain Recon' - "
                        "the webhook would hang with responseMode:responseNode")

    # Workflows 19/20 - campaign export / import
    for wf_id in ("19", "20"):
        # The env fallback every OTHER workflow uses is a data-loss hazard here:
        # FLOWSINT_SKETCH_ID points at a real campaign, so a request carrying
        # sketch_id:null would export the wrong graph, or write an imported one
        # into a live engagement.
        # Matched on the read itself, not the name, so the comments explaining WHY
        # the fallback is absent do not trip the check.
        for node_name, code in nodes[wf_id].items():
            if "environ.get('FLOWSINT_SKETCH_ID'" in code or "environ['FLOWSINT_SKETCH_ID']" in code:
                failures.append(
                    f"{wf_id}/{node_name}: must NOT fall back to FLOWSINT_SKETCH_ID"
                )
            if "sketch_id required" not in code:
                failures.append(f"{wf_id}/{node_name}: missing the empty-sketch_id guard")
        # A campaign transfer is ~30 multi-MB page requests each way; n8n's default
        # of persisting every execution would put all of it in the SQLite DB.
        settings = wf[wf_id].get("settings", {})
        if settings.get("saveDataSuccessExecution") != "none":
            failures.append(f"{wf_id}: settings.saveDataSuccessExecution must be 'none'")
        if settings.get("saveDataErrorExecution") != "all":
            failures.append(f"{wf_id}: settings.saveDataErrorExecution must be 'all'")

    n19 = nodes["19"].get("Read Sketch Page", "")
    # Keyset paging, not SKIP: offsets shift when a scheduled ingestor writes
    # between pages, silently dropping rows from the bundle.
    require_contains("19", "Read Sketch Page", n19, "id(n) > $cur", failures)
    require_contains("19", "Read Sketch Page", n19, "id(r) > $cur", failures)
    if "SKIP $" in n19:
        failures.append("19/Read Sketch Page: SKIP paging is not snapshot-safe - use the id() cursor")
    require_contains("19", "Read Sketch Page", n19, "n.deleted_at IS NULL", failures)
    require_contains("19", "Read Sketch Page", n19, "custom_types", failures)

    n20 = nodes["20"].get("Write Sketch Page", "")
    require_contains("20", "Write Sketch Page", n20, "apoc.create.node(row.labels, row.props)", failures)
    require_contains("20", "Write Sketch Page", n20, "apoc.create.relationship(a, row.ty, row.p, b)", failures)
    # JSON collapses 100.0 to 100; without toFloat the layout coordinates come
    # back as Neo4j INTEGERs.
    require_contains("20", "Write Sketch Page", n20, "toFloat(node.x)", failures)
    # WF07's scoped purge matches relationships on sketch_id.
    require_contains("20", "Write Sketch Page", n20, "props['sketch_id'] = sketch_id", failures)
    # A row with a missing endpoint yields no output row, so shortfalls must be
    # reported explicitly rather than passing as success.
    require_contains("20", "Write Sketch Page", n20, "page incomplete", failures)
    require_contains("20", "Write Sketch Page", n20, "'unresolved': unresolved", failures)

    # Workflow 11 checks — the credential scanner reads a v2 webhook body, so the
    # payload and the sketch_id live under item.json.body. Reading the top level
    # meant raw_b64 was always empty (every scan reported "no credentials found"
    # without ever calling Titus) and findings were filed under the env fallback
    # sketch instead of the caller's campaign.
    n11_scan = nodes["11"].get("Scan with Titus", "")
    require_contains("11", "Scan with Titus", n11_scan,
                     "body = item.get('body', item)", failures)
    require_contains("11", "Scan with Titus", n11_scan,
                     "body.get('sketch_id') or item.get('sketch_id')", failures)
    # flowsint_types.Credential REQUIRES username. A credential node without it
    # cannot be reconstructed on read, and the graph serializer has no per-node
    # guard — one such node makes GET /graph 500 for the whole campaign.
    n11_import = nodes["11"].get("Import Credential Nodes", "")
    require_contains("11", "Import Credential Nodes", n11_import,
                     "'username':         f.get('username_context') or label", failures)

    check_upload_router_labels(failures)
    check_task_runner_env(failures)
    check_runner_config_mount_is_pinned(failures)
    check_no_private_key_material(failures)
    check_secret_tiers_are_local(failures)
    check_no_plaintext_secrets_in_env(failures)
    check_env_dirs_are_absolute(failures)
    check_guard_var_lists_agree(failures)
    check_code_node_env_reachable(failures)
    check_notification_invariants(failures)
    check_high_value_tech_catalog(failures)
    check_individual_lookup(failures)
    check_asset_label_catalog(failures)
    check_asset_ownership_catalog(failures)
    check_employment_evidence_catalog(failures)
    check_job_title_rules(failures)
    check_target_contact_is_proxied(failures)
    check_title_match_ordering(nodes, failures)

    return failures


def check_title_match_ordering(nodes: Dict[str, Dict[str, str]],
                               failures: List[str]) -> None:
    """WF13's Job Title Match must be computed LAST, over real open roles.

    Two bugs lived in this block for as long as it existed, and neither of them
    raised -- they produced a plausible-looking card:

      * It ran BEFORE the employment gate, over the ungated candidate roster, so
        the card offered a dossier link for people the gate had already rejected
        and the graph had never been given. Clicking one answered "No Individual
        matching: <name>".
      * It fed the roster's OWN job titles in as the roles being offered. Every
        specialty then matched by construction, "N open roles" counted people,
        and -- because derive_specialty() Title-Cases whatever it cannot
        classify rather than returning None -- an unparseable LinkedIn headline,
        usually a person's name, was printed as an open role.

    Both are ordering/plumbing facts about one code node, so assert them here
    rather than waiting for an operator to notice a name where a vacancy should
    be.
    """
    node_name = "Run Domain OSINT + Breach Correlation"
    code = nodes.get("13", {}).get(node_name, "")
    if not code:
        failures.append(f"13/{node_name}: node not found")
        return

    where = code.find("match_titles(")
    if where < 0:
        failures.append(f"13/{node_name}: the job title match is gone entirely")
        return
    if code.count("match_titles(") != 1:
        failures.append(
            f"13/{node_name}: match_titles() is called "
            f"{code.count('match_titles(')} times; there must be exactly one "
            "computation, after the graph writes")

    for marker, why in (
        ("partition(_ee_rows)",
         "the employment gate, so held candidates would reach the card"),
        # Anchored on the counter, not on add_node: WF13 writes individuals in
        # three places (Flare promotion, recruiters, org people) and only the
        # last one is the loop this block has to follow.
        ("_people_written += 1",
         "the people write loop, so the rows would carry no graph_id"),
    ):
        at = code.find(marker)
        if at < 0:
            failures.append(f"13/{node_name}: expected marker missing: {marker}")
        elif at > where:
            failures.append(
                f"13/{node_name}: match_titles() runs BEFORE {why}")

    # The offered side is vacancies and nothing else.
    for bad in ("_offered2 += [p.get('job_title'",
                "_offered += [p.get('job_title'",
                "_offered_roles += [p.get('job_title'"):
        if bad in code:
            failures.append(
                f"13/{node_name}: the roster's own job titles are being offered "
                "as open roles -- every specialty then matches itself and "
                "open_role_count stops meaning anything")

    require_contains("13", node_name, code, "result['org_title_empty_kind']", failures)
    require_contains("13", node_name, code, "_p['graph_id'] = _pid", failures)

    # The open-roles leg is the only thing that makes this card work on a
    # campaign without the RU objective -- hh.ru is the sole other vacancy
    # source and it is region-gated. If it stops feeding _offered_roles the
    # card silently goes back to being permanently empty.
    require_contains("13", node_name, code,
                     "_offered_roles += [(_j.get('title') or '') for _j in result['org_jobs']]",
                     failures)
    if "result['org_jobs_refused']" in code:
        at_ref = code.find("_offered_roles += [(_j.get('title') or '') for _j in result['org_jobs_refused']")
        if at_ref >= 0:
            failures.append(
                f"13/{node_name}: postings refused as another employer's are being "
                "offered as open roles -- google_jobs aggregates boards, so that "
                "feeds a competitor's vacancies into the Job Title Match card")
    # Postings are card data. A JobPosting nodeType would have to be registered
    # the way Company is, and an unresolvable one makes GET /graph return 500
    # for the WHOLE sketch.
    for bad in ("node_type='JobPosting'", "node_type='jobposting'", "node_type='Job'"):
        if bad in code:
            failures.append(
                f"13/{node_name}: {bad} -- open roles must stay card data; an "
                "unregistered nodeType 500s the entire sketch")


def check_job_title_rules(failures: List[str]) -> None:
    """Keep the two specialty tables from drifting apart.

    derive_specialty() exists twice on purpose: once in
    flowsint-custom/types/social_profile.py, where it runs as a pydantic
    validator inside the Flowsint container, and once in scripts/job_titles.py,
    where the n8n runner can reach it (the runner mounts only scripts/, and only
    allowlisted module names may be imported at all).

    WF13's org source compares a specialty derived from an hh.ru vacancy title
    against one derived from a SocialProfile job title. If the tables drift, the
    comparison does not error -- it just stops matching, and the Job Title Match
    block quietly empties out. So compare them here.
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        from job_titles import _SPECIALTY_RULES as runner_rules
    except Exception as exc:                                   # noqa: BLE001
        failures.append(f"scripts/job_titles.py is not importable: {exc}")
        return

    types_path = REPO_ROOT / "flowsint-custom" / "types" / "social_profile.py"
    if not types_path.exists():
        failures.append("flowsint-custom/types/social_profile.py is missing")
        return
    ns: Dict[str, Any] = {}
    try:
        # Executed rather than imported: the module pulls in pydantic, which the
        # checker should not need installed to compare two literal lists.
        tree = ast.parse(types_path.read_text())
        for stmt in tree.body:
            if isinstance(stmt, ast.AnnAssign) and getattr(stmt.target, "id", "") == "_SPECIALTY_RULES":
                ns["_SPECIALTY_RULES"] = ast.literal_eval(stmt.value)
            elif isinstance(stmt, ast.Assign) and any(
                    getattr(t, "id", "") == "_SPECIALTY_RULES" for t in stmt.targets):
                ns["_SPECIALTY_RULES"] = ast.literal_eval(stmt.value)
    except Exception as exc:                                   # noqa: BLE001
        failures.append(f"could not read _SPECIALTY_RULES from social_profile.py: {exc}")
        return

    types_rules = ns.get("_SPECIALTY_RULES")
    if types_rules is None:
        failures.append("social_profile.py no longer defines _SPECIALTY_RULES")
        return

    # Order is semantic here -- first keyword hit wins, so 'Security Engineer'
    # must reach 'Security Professional' before the catch-all 'engineer' rule.
    # Compare the lists as sequences, not as sets.
    if [(list(k), v) for k, v in types_rules] != [(list(k), v) for k, v in runner_rules]:
        failures.append(
            "scripts/job_titles.py::_SPECIALTY_RULES has drifted from "
            "flowsint-custom/types/social_profile.py::_SPECIALTY_RULES — WF13's "
            "Job Title Match compares specialties derived from both, so a "
            "mismatch silently stops matching instead of failing"
        )


def check_high_value_tech_catalog(failures: List[str]) -> None:
    """Keep high-value technology labels centralized instead of copy-pasted."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        from high_value_tech import HIGH_VALUE_TECH_LABELS
    except Exception as exc:
        failures.append(f"scripts/high_value_tech.py failed to import: {exc}")
        return

    labels = list(HIGH_VALUE_TECH_LABELS)
    frontend_path = REPO_ROOT / "frontend" / "high-value-tech.js"
    index_path = REPO_ROOT / "frontend" / "index.html"
    if not frontend_path.exists():
        failures.append("frontend/high-value-tech.js is missing")
    else:
        frontend_labels = re.findall(r"'([^']+)'", frontend_path.read_text())
        if frontend_labels != labels:
            failures.append("frontend/high-value-tech.js has drifted from scripts/high_value_tech.py")
    if not index_path.exists():
        failures.append("frontend/index.html is missing")
    else:
        index_text = index_path.read_text()
        if 'src="high-value-tech.js"' not in index_text:
            failures.append("frontend/index.html does not load high-value-tech.js")
        if "new Set(window.SPOTTER_HIGH_VALUE_TECH || [])" not in index_text:
            failures.append("frontend/index.html does not build HIGH_VALUE_TECH_SET from high-value-tech.js")

    files_that_must_import = {
        "scripts/c2_common.py": "from high_value_tech import HIGH_VALUE_TECH",
        "scripts/tech_context_engine.py": "from high_value_tech import HIGH_VALUE_TECH",
        "llm/tools/technology_tool.py": "from high_value_tech import HIGH_VALUE_TECH",
        "llm/tools/attack_path_tool.py": "from high_value_tech import HIGH_VALUE_TECH",
        "flowsint-custom/enrichers/technology_enricher.py": "from high_value_tech import HIGH_VALUE_TECH",
    }
    for rel, needle in files_that_must_import.items():
        text = (REPO_ROOT / rel).read_text()
        if needle not in text:
            failures.append(f"{rel}: must import HIGH_VALUE_TECH from high_value_tech")
        if re.search(r"HIGH_VALUE_TECH\s*(:[^=]+)?=\s*[{[]", text):
            failures.append(f"{rel}: contains an inline high-value technology list")

    n12_code = code_nodes(json.loads(TARGETS["12"].read_text())).get("Build Tech Inventory + Narratives", "")
    if "from high_value_tech import HIGH_VALUE_TECH" not in n12_code:
        failures.append("WF12 Build Tech Inventory + Narratives must import HIGH_VALUE_TECH from high_value_tech")
    if re.search(r"HIGH_VALUE_TECH\s*=\s*[{[]", n12_code):
        failures.append("WF12 Build Tech Inventory + Narratives contains an inline high-value technology list")


def check_individual_lookup(failures: List[str]) -> None:
    """One identifier contract. A private CONTAINS chain is how the five
    resolvers drifted apart (label vs display name vs email list vs node id)."""
    module = (REPO_ROOT / "scripts" / "individual_lookup.py").read_text()
    for field in (
        "nodeLabel", "label", "display_name", "full_name", "sid",
        "sam_account_name", "username", "email", "email_addresses",
    ):
        if field not in module:
            failures.append(f"individual_lookup.py: missing identifier field {field}")
    if "toLower(coalesce(toString(" not in module:
        failures.append("individual_lookup.py: email_addresses must be toString()'d before toLower()")
    if "toLower(elementId({var})) = {param}" not in module:
        failures.append("individual_lookup.py: node id match must be case-insensitive equality")
    if "ORDER BY size(label) ASC, label ASC LIMIT 1" not in module:
        failures.append("individual_lookup.py: tie-break must be shortest label, then label")
    # Comments and the docstring may name casefold() to say why it is wrong.
    # A NAME token is an actual call.
    try:
        for tok in tokenize.generate_tokens(io.StringIO(module).readline):
            if tok.type == tokenize.NAME and tok.string == "casefold":
                failures.append("individual_lookup.py: must not casefold(); Cypher only has toLower()")
                break
    except tokenize.TokenError as exc:
        failures.append(f"individual_lookup.py: could not tokenize: {exc}")

    consumers = {
        "05/Fetch Full Graph": code_nodes(load_json(TARGETS["05"])).get("Fetch Full Graph", ""),
        "05/Compile Dossier": code_nodes(load_json(TARGETS["05"])).get("Compile Dossier", ""),
        "08/Execute Query": code_nodes(load_json(WORKFLOW_DIR / "08-llm-query-gateway.json")).get("Execute Query", ""),
        "llm/tools/dossier_tool.py": (REPO_ROOT / "llm" / "tools" / "dossier_tool.py").read_text(),
        "llm/tools/attack_path_tool.py": (REPO_ROOT / "llm" / "tools" / "attack_path_tool.py").read_text(),
        "llm/tools/technology_tool.py": (REPO_ROOT / "llm" / "tools" / "technology_tool.py").read_text(),
    }
    for name, code in consumers.items():
        if "from individual_lookup import" not in code:
            failures.append(f"{name}: must import individual_lookup")
        try:
            tokens = tokenize.generate_tokens(io.StringIO(code).readline)
        except Exception as exc:
            failures.append(f"{name}: could not tokenize for the private-resolver ban: {exc}")
            continue
        for tok in tokens:
            if tok.type != tokenize.STRING:
                continue
            if "CONTAINS" in tok.string and "nodeProperties." in tok.string:
                failures.append(
                    f"{name}: private identifier CONTAINS chain in a string literal"
                )
                break


def _executable_source(code: str) -> str:
    """`code` with comments and string literals removed.

    A naive substring pin over a whole node fails the way issues.md already
    records: a COMMENT quoting the forbidden literal trips it, so the honest
    explanation of why something must not come back is what breaks the build.
    Docstrings have the same problem and `line.startswith('#')` does not see
    them. Tokenising drops both, so a pin can say "this name must not be
    EXECUTED" and mean it, while the reasoning stays in the file where the next
    reader needs it.
    """
    try:
        out, last = [], (1, 0)
        for tok in tokenize.generate_tokens(io.StringIO(code).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            if tok.start[0] != last[0]:
                out.append("\n")
            out.append(tok.string)
            last = tok.end
        return " ".join(out)
    except Exception:
        # An untokenisable node is a different failure; fall back to the raw text
        # rather than letting the pin silently pass.
        return code


def check_asset_ownership_catalog(failures: List[str]) -> None:
    """Keep the ownership evidence vocabulary centralized, and pin its decisions.

    WHY THIS EXISTS
    ---------------
    WF13 used to infer asset ownership by matching the individual's own name
    TOKENS against the asset's label. On a past engagement that attributed
    `https://primer-avia.test` and `autoconfig.primer-avia.test` to the identity
    `jd@primer-avia.test`. It was structurally broken rather than merely imprecise:
    WF13's own Flare promotion creates individuals whose nodeLabel IS an email
    address on the target domain, so tokenising the label yields the domain's own
    tokens and the match is guaranteed for every promoted identity against every
    asset on the domain.

    Three decisions replaced it, and all three are silent when lost -- an
    over-permissive ownership rule produces MORE rows, which reads as the feature
    working better. So they are asserted on the module's VALUES, the way
    check_asset_label_catalog learned to: once a literal lives in a module, a text
    pin against a workflow keeps passing while guarding nothing.
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        import asset_ownership as ao
    except Exception as exc:
        failures.append(f"scripts/asset_ownership.py failed to import: {exc}")
        return

    # 1. DECISION: only asset-scoped evidence scores. The domain registrant is
    #    computed once and attached to the apex, every subdomain and every bucket
    #    in a sweep alike, so weighting it per-asset let one person accumulate
    #    +8 x 40 and peg the cap.
    if ao.OWNERSHIP_WEIGHTS.get(ao.MANAGES) != 0:
        failures.append(
            "asset_ownership: MANAGES must weigh 0. It is the apex WHOIS registrant, "
            "attached uniformly to every asset in a sweep including CDN endpoints, so "
            "any positive weight scales with estate size rather than with evidence")
    if ao.OWNERSHIP_WEIGHTS.get(ao.LIKELY_MANAGES) != 0:
        failures.append(
            "asset_ownership: LIKELY_MANAGES must weigh 0. It is reserved for "
            "role/job-title inference, which WF13 stores as a manager_candidates "
            "node property and never as an edge -- a job title says what someone "
            "probably looks after, not that they hold rights on this asset")
    if not (0 < ao.OWNERSHIP_WEIGHTS.get(ao.HAS_ACCESS, 0) < ao.OWNERSHIP_WEIGHTS.get(ao.OWNS_ASSET, 0)):
        failures.append(
            "asset_ownership: HAS_ACCESS must weigh strictly less than OWNS_ASSET "
            "and more than 0 -- reach without control is real evidence, but weaker")

    # 2. DECISION: the contribution is capped. Owning ten assets is not ten
    #    findings; WF04's cloud_owner_credit already takes a MAX for this reason.
    if not 0 < ao.ASSET_BUMP_CAP <= 25:
        failures.append("asset_ownership: ASSET_BUMP_CAP must be a real ceiling (0 < cap <= 25)")
    many = [{"relationship": ao.OWNS_ASSET, "type": "CloudAsset", "has_vulns": True}] * 40
    if ao.asset_bump(many) > ao.ASSET_BUMP_CAP:
        failures.append("asset_ownership.asset_bump must not exceed ASSET_BUMP_CAP")
    if ao.asset_bump([{"relationship": ao.MANAGES, "type": "Subdomain"}] * 40) != 0:
        failures.append(
            "asset_ownership.asset_bump: 40 registrant rows must contribute 0. This is "
            "the exact shape that pegged a person's score to 100 on a 40-subdomain estate")

    # 3. DECISION: an email-shaped nodeLabel is NOT evidence of a provisional
    #    identity. sharphound_parser labels every AD principal from
    #    Properties.name, which BloodHound populates as SAM@DOMAIN.LOCAL, so a
    #    label-shape test excludes every genuine AD rights-holder and silently
    #    returns an empty ownership layer on real data while fixtures built on
    #    "Firstname Lastname" labels keep passing.
    if ao.is_provisional_identity("COPS@CORP.LOCAL", {"source": "sharphound"}):
        failures.append(
            "asset_ownership.is_provisional_identity must not treat an email-shaped "
            "label as provisional: EVERY SharpHound individual is SAM@DOMAIN.LOCAL, so "
            "that test zeroes the whole AD ownership layer and reports success")
    if not ao.is_provisional_identity("jd@example.com", {"provisional": True}):
        failures.append("asset_ownership.is_provisional_identity must honour the provisional flag")
    if not ao.is_provisional_identity("jd@example.com", {"source": "flare_domain"}):
        failures.append("asset_ownership.is_provisional_identity must honour source=flare_domain")

    # 4. DECISION: a built-in high-privilege group's rights are never inherited.
    #    Domain Admins holds LOCAL_ADMIN on every host in a real estate, so
    #    expanding it would attribute the whole estate to every DA -- a wider false
    #    positive than the one this work removed, wearing BloodHound's authority.
    for grp in ("Domain Admins", "Enterprise Admins", "Authenticated Users", "Domain Users"):
        if not ao.is_excluded_group(grp):
            failures.append(
                f"asset_ownership.is_excluded_group must exclude {grp!r}: its rights "
                "span the estate and say nothing about any one asset")
    if not ao.is_excluded_group("Widgets Team", {"is_high_value": True}):
        failures.append("asset_ownership.is_excluded_group must honour the is_high_value flag")
    if ao.is_excluded_group("Web Team"):
        failures.append("asset_ownership.is_excluded_group must not exclude an ordinary team")

    # 5. The retired label must have no writer. It cannot be applied
    #    retroactively either -- Flowsint drops edge properties, so nothing records
    #    which branch produced an existing edge; scripts/prune_named_ownership.py
    #    is how the legacy ones get cleared.
    for retired in ao.RETIRED_LABELS:
        if retired in ao.OWNERSHIP_LABELS or retired in ao.SCORING_OWNER_EDGES:
            failures.append(f"asset_ownership: {retired} is retired and must not be an active label")
        for wf, node in (("13", "Run Domain OSINT + Breach Correlation"),
                         ("10", "Fetch Graph + Run Analysis LLM")):
            code = code_nodes(json.loads(TARGETS[wf].read_text())).get(node, "")
            if retired in _executable_source(code):
                failures.append(
                    f"WF{wf} {node}: {retired} appears in executable code -- the "
                    "name-token branch it labelled must not come back")

    # 6. The vocabulary must not be re-declared inline by its consumers.
    for wf, node, needle in (
        ("13", "Run Domain OSINT + Breach Correlation", "from asset_ownership import"),
        ("10", "Fetch Graph + Run Analysis LLM", "from asset_ownership import"),
        ("04", "Fetch Full Graph", "from asset_ownership import SCORING_OWNER_EDGES"),
    ):
        code = code_nodes(json.loads(TARGETS[wf].read_text())).get(node, "")
        if needle not in code:
            failures.append(f"WF{wf} {node}: must import the vocabulary from asset_ownership")
        if re.search(r"OWN_LABELS\s*=\s*\{\s*'", code):
            failures.append(f"WF{wf} {node}: contains an inline ownership label set")


def check_employment_evidence_catalog(failures: List[str]) -> None:
    """Keep the employment evidence vocabulary centralized, and pin its decisions.

    WHY THIS EXISTS
    ---------------
    WF13's "People & Positions" card had no attribution test at all. Its SERP
    provider runs `'"<company>" <role> site:linkedin.com/in'`, so the ONLY thing
    tying a result to the target was that a search engine returned it for a query
    containing the company name -- and every row was then written to the graph as
    Individual -[WORKS_FOR]-> Company. A live target produced dozens of people,
    mostly profiles that merely mentioned the company.

    Every decision that fixed it is SILENT WHEN LOST, and silent in the dangerous
    direction: a looser gate produces MORE people, which reads as the feature
    working better. So they are asserted on the module's VALUES, the way
    check_asset_ownership_catalog does -- once a literal lives in a module, a text
    pin against a workflow keeps passing while guarding nothing.
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        import employment_evidence as ee
    except Exception as exc:
        failures.append(f"scripts/employment_evidence.py failed to import: {exc}")
        return

    # 1. DECISION: inference never becomes an edge. LIKELY_WORKS_FOR is the slot
    #    reserved for role-keyword / co-occurrence guesses, and it stays unwritten
    #    for the same reason LIKELY_MANAGES does -- that class of guess is exactly
    #    what produced the 34.
    if ee.EMPLOYMENT_WEIGHTS.get(ee.LIKELY_WORKS_FOR) != 0:
        failures.append(
            "employment_evidence: LIKELY_WORKS_FOR must weigh 0. It is reserved for "
            "inference from role keywords and search co-occurrence, which belongs in "
            "the held bucket and never on an edge")
    if ee.LIKELY_WORKS_FOR in ee.WRITABLE_LABELS:
        failures.append(
            "employment_evidence: LIKELY_WORKS_FOR must not be writable -- a guess "
            "about employment is indistinguishable from a fact once it is an edge")

    # 2. DECISION: a person's own claim ranks below the organisation's records.
    if not (0 < ee.EMPLOYMENT_WEIGHTS.get(ee.CLAIMS_WORKS_FOR, 0)
            < ee.EMPLOYMENT_WEIGHTS.get(ee.WORKS_FOR, 0)):
        failures.append(
            "employment_evidence: CLAIMS_WORKS_FOR must weigh strictly less than "
            "WORKS_FOR and more than 0 -- a LinkedIn headline is evidence, but it is "
            "the person's claim and it may be years out of date")

    # 3. DECISION: the employer comparison reuses EDGAR's floor. 72 sits in
    #    name_score's own 64 <-> 82 gap, so "Example Harbor Corp" cannot match
    #    "Example Harbor Information Security" -- the measured failure that set it.
    if ee.EMPLOYER_MATCH_MIN < 72:
        failures.append(
            "employment_evidence: EMPLOYER_MATCH_MIN must stay >= 72, EDGAR_MIN_SCORE's "
            "default. Below the 64<->82 gap in name_score, a half-word containment like "
            "'Example Harbor Corp' vs 'Example Harbor Information Security' becomes a match")
    if ee.employer_verdict("Example Harbor Corp",
                           ("Example Harbor Information Security",))[0] == ee.VERDICT_MATCH:
        failures.append(
            "employment_evidence.employer_verdict must not match 'Example Harbor Corp' to "
            "'Example Harbor Information Security'")

    # 4. THE STRUCTURAL DECISION, asserted arithmetically: nothing profile-only can
    #    ever reach `confirmed`. A search engine cannot confirm employment, however
    #    many profile-side signals stack. If someone raises EV_EMPLOYER_MATCH this
    #    fails loudly instead of quietly re-admitting the 34.
    profile_ceiling = (ee.EVIDENCE_WEIGHTS.get(ee.EV_EMPLOYER_MATCH, 0)
                       + ee.EVIDENCE_WEIGHTS.get(ee.EV_ROLE_TITLE, 0))
    if profile_ceiling >= ee.TIER_CONFIRMED_MIN:
        failures.append(
            f"employment_evidence: profile-only evidence tops out at {profile_ceiling}, "
            f"which now reaches TIER_CONFIRMED_MIN ({ee.TIER_CONFIRMED_MIN}). A LinkedIn "
            "profile must never be able to CONFIRM employment on its own")

    # 5. The mirror of 4: any single org-side signal confirms, by construction
    #    rather than by a special case in assess().
    weakest_org_side = min(ee.EVIDENCE_WEIGHTS.get(e, 0) for e in ee.ORG_SIDE_EVIDENCE)
    if weakest_org_side < ee.TIER_CONFIRMED_MIN:
        failures.append(
            "employment_evidence: every ORG_SIDE_EVIDENCE weight must be >= "
            "TIER_CONFIRMED_MIN, so 'the organisation's own records confirm employment' "
            "falls out of the table instead of being special-cased")

    # 6. DECISION: a held row gets no edge. Both held tiers, not just one.
    for tier in ee.HELD_TIERS:
        if ee.LABEL_FOR_TIER.get(tier) != "":
            failures.append(
                f"employment_evidence: tier {tier!r} is held and must map to no edge "
                "label -- the held bucket exists so these stay OUT of the graph")

    # 7. DECISION: geography must stay disarmed on a single attestation. A WHOIS
    #    registrant country is frequently the privacy proxy's and a ccTLD is cheap,
    #    so arming on one would start suppressing real staff.
    if ee.GEO_MIN_CORROBORATION < 2:
        failures.append(
            "employment_evidence: GEO_MIN_CORROBORATION must stay >= 2. One WHOIS "
            "registrant country is often the privacy proxy's, so a single attestation "
            "would arm the location rule against a company's actual employees")
    if ee.build_context(aliases=("x",), org_iso2="RU", org_corroboration=1)["geo_armed"]:
        failures.append("employment_evidence: the geo rule must not arm on one attestation")

    # 8. DECISION: an unresolvable location never contradicts. Guessing a country
    #    from a city or metro name silently hides a real employee, and a hidden
    #    true positive is invisible in a way a shown false positive is not.
    for vague in ("Greater Boston Area", "Remote", "EMEA", ""):
        if ee.country_from_location(vague) != "":
            failures.append(
                f"employment_evidence.country_from_location({vague!r}) must return '' -- "
                "an unresolved location has to leave the row's score untouched")

    # 8b. DECISION: a Cyrillic company name is romanised before comparison, on
    #     BOTH sides. Without it normalise_company() empties the string, name_score
    #     returns 0, and 0 means "not one word in common" -- so a genuine Russian
    #     employee whose profile names their employer in Cyrillic is classified
    #     `other` and marked contradicted. That false negative is invisible on the
    #     card and it lands hardest on exactly the targets the geography rule is
    #     written for. Asserted end to end rather than on the table, because the
    #     failure is in the COMPOSITION of transliteration, form-stripping and the
    #     matcher, not in any one of them.
    cyrillic_primer = "\u041e\u041e\u041e \u041f\u0420\u0418\u041c\u0415\u0420 \u0410\u0412\u0418\u0410"
    if ee.employer_verdict(cyrillic_primer, ("Primer Avia",))[0] != ee.VERDICT_MATCH:
        failures.append(
            "employment_evidence: a Cyrillic employer must match the company's Latin "
            "branding. Without transliteration it scores 0, reads as 'a different "
            "company', and marks genuine Russian staff contradicted")
    if ee.employer_verdict("Primer Avia", (cyrillic_primer,))[0] != ee.VERDICT_MATCH:
        failures.append(
            "employment_evidence: transliteration must apply to the ALIAS side too, "
            "or a Cyrillic company name matches nobody")
    # The corollary: precision must survive it.
    if ee.employer_verdict("\u0410\u041e \u0420\u043e\u043c\u0430\u0448\u043a\u0430",
                           ("Primer Avia",))[0] == ee.VERDICT_MATCH:
        failures.append(
            "employment_evidence: transliteration must not make unrelated Russian "
            "companies match each other")
    # And a script that CANNOT be romanised must still stay silent rather than
    # contradict — CN/JP targets are live cases.
    if ee.employer_verdict("\u682a\u5f0f\u4f1a\u793e", ("Primer Avia",))[0] == ee.VERDICT_OTHER:
        failures.append(
            "employment_evidence: an unromanisable employer must be 'unclear', never "
            "'other' -- scoring 0 on a script we cannot read is not evidence of a "
            "different employer")

    # 9. The word-alignment fix. The previous raw-substring test blanked the
    #    genuine job title "Information Security" because it is a word-run inside
    #    the employer's own name -- the same class of bug name_score documents.
    if ee.is_company_headline("Information Security",
                              ("Example Harbor Information Security",)):
        failures.append(
            "employment_evidence.is_company_headline must be word-aligned: a real job "
            "title that happens to sit inside the employer's name is still a job title")

    # 10. The vocabulary must not be re-declared inline, and the bare edge literal
    #     must be gone from the writer -- it has to come from the module now.
    node = "Run Domain OSINT + Breach Correlation"
    code = code_nodes(json.loads(TARGETS["13"].read_text())).get(node, "")
    if "from employment_evidence import" not in code:
        failures.append(f"WF13 {node}: must import the vocabulary from employment_evidence")
    # NOT _executable_source here: it strips STRING tokens as well as comments, so
    # a quoted edge label is exactly what it cannot see and the pin would pass
    # while guarding nothing. Match the call shape instead -- narrow enough that
    # prose about the old behaviour still reads fine in a comment.
    if re.search(r"""create_edge\([^)]*['"](?:WORKS_FOR|CLAIMS_WORKS_FOR)['"]""", code):
        failures.append(
            f"WF13 {node}: an employment edge label is passed to create_edge as a bare "
            "string literal. It must come from LABEL_FOR_TIER, or the gate is bypassed "
            "by the one line that writes the edge unconditionally -- which is what the "
            "ungated branch did for every person")
    if re.search(r"LABEL_FOR_TIER\s*=\s*\{", code):
        failures.append(f"WF13 {node}: contains an inline tier->label map")


def check_asset_label_catalog(failures: List[str]) -> None:
    """Keep the asset-layer label vocabulary centralized instead of copy-pasted.

    Mirrors check_high_value_tech_catalog, plus one thing that check does not need:
    two of these constants encode PINNED DECISIONS (MANAGES is not a carrier edge;
    HAS_CLOUD_ASSET is not a carrier edge). Those used to be pinned by a
    require_absent() against WF04's own source. Centralizing moved the literal out
    of that file, so the text pin would keep passing while guarding nothing -- the
    assertions below are on the module's VALUES instead, which is strictly stronger.

    The six hand-copies this replaces had already drifted twice, and neither
    failure raised: WF12's fetch list omitted PascalCase 'Technology', and
    attack_path_tool.py compared nodeType case-sensitively. Both returned clean
    zeros, which reads as "no exploits exist".
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        import asset_labels as al
    except Exception as exc:
        failures.append(f"scripts/asset_labels.py failed to import: {exc}")
        return

    # 1. The vocabulary itself, by value.
    if tuple(al.TECH_LABELS) != ("technology", "Technology", "service", "Service"):
        failures.append(
            "asset_labels.TECH_LABELS changed. Both casings must stay: which spelling "
            "a node carries is decided by its writer (fc.add_node preserves case, "
            "batch_import lowercases), and Neo4j labels are case-sensitive -- dropping "
            "one halves coverage and reports success")
    if tuple(al.TECH_EDGES) != ("USES_TECH", "EXPOSES_SERVICE", "EXPOSES", "IMPLEMENTED_IN"):
        failures.append("asset_labels.TECH_EDGES changed -- see the two pins below")
    if al.CARRIER_LABELS != frozenset(al.TECH_EDGES):
        failures.append("asset_labels.CARRIER_LABELS must equal frozenset(TECH_EDGES)")

    # 2. The two pinned decisions, asserted where they now live.
    for edge, why in (
        ("MANAGES",
         "MANAGES must never be a carrier edge: WF13 links an apex WebAsset to "
         "whoever's whois email or name matches it, and every CDN edge node "
         "answering for that domain hangs off that same asset, so inheriting "
         "exploit facts across it would charge a person with Akamai's CVEs "
         "(issues.md, Confirmed limitations item 2)"),
        ("HAS_CLOUD_ASSET",
         "HAS_CLOUD_ASSET must never be a carrier edge: a public bucket is not a "
         "CVE, and the carrier path would spend NVD quota keyword-matching bucket "
         "names. Cloud exposure is its own bounded term in WF04"),
    ):
        if edge in al.CARRIER_LABELS or edge in al.TECH_EDGES:
            failures.append(why)

    # 3. The two projections must stay distinct. Swapping them is silent: WF04
    #    would read the CPE keys, find no exploit_available, and score every bonus
    #    0 -- indistinguishable from "no exploits exist".
    if "exploit_available" in al.TECH_READ_PROPS:
        failures.append("asset_labels.TECH_READ_PROPS is the enrichment projection; "
                        "it must not carry scoring keys")
    for key in ("exploit_available", "cves", "cve_match_basis", "top_pocs"):
        if key not in al.TECH_SCORING_PROPS:
            failures.append(f"asset_labels.TECH_SCORING_PROPS is missing {key} -- "
                            f"WF04's exploit bonus would be 0 with no error")
    for key in ("cpe", "cpes"):
        if key not in al.TECH_READ_PROPS:
            failures.append(f"asset_labels.TECH_READ_PROPS is missing {key} -- "
                            f"upload_router and WF13 spell the same idea two ways "
                            f"and both are read")

    # 4. Every consumer must import, and none may re-declare inline. Matches list,
    #    tuple AND set forms -- a tuple is the natural shape to copy from a module
    #    that exports tuples, and the high-value-tech guard only catches [ and {.
    inline = re.compile(
        r"^(?!\s*#)\s*(TECH_LABELS|TECH_EDGES|CARRIER_LABELS|TECH_PROPS|READ_PROPS"
        r"|TECH_READ_PROPS|TECH_SCORING_PROPS|CLOUD_LABELS|CLOUD_EDGES|CLOUD_PROPS)"
        r"\s*(:[^=]+)?=\s*[\[({]",
        re.M)
    for rel in ("scripts/tech_enricher.py", "scripts/smoke_workflow04.py",
                "llm/tools/technology_tool.py", "llm/tools/tech_context_tool.py",
                "llm/tools/attack_path_tool.py"):
        text = (REPO_ROOT / rel).read_text()
        if "from asset_labels import" not in text:
            failures.append(f"{rel}: must import the label vocabulary from asset_labels")
        hit = inline.search(text)
        if hit:
            failures.append(f"{rel}: re-declares {hit.group(1)} inline")

    # 5. The workflow code nodes that must import it.
    for wf_id, node_name in (("04", "Fetch Full Graph"),
                             ("04", "Score Attack Paths"),
                             ("12", "Build Tech Inventory + Narratives")):
        code = code_nodes(json.loads(TARGETS[wf_id].read_text())).get(node_name, "")
        if "from asset_labels import" not in code:
            failures.append(f"{wf_id}/{node_name}: must import from asset_labels")
        hit = inline.search(code)
        if hit:
            failures.append(f"{wf_id}/{node_name}: re-declares {hit.group(1)} inline")

    # 6. WF12's fetch must cover every spelling. Its old hand-written list omitted
    #    'Technology', which left the CVE-count and vulnerable-tech blocks dead on
    #    any graph written by the fc.add_node writers.
    n12 = code_nodes(json.loads(TARGETS["12"].read_text())).get(
        "Build Tech Inventory + Narratives", "")
    if "list(TECH_LABELS)" not in n12:
        failures.append("12/Build Tech Inventory + Narratives: the node fetch must "
                        "expand list(TECH_LABELS), not a hand-written subset")

    # 7. The chat tool must compare nodeType case-INSENSITIVELY. It used to use a
    #    bare `IN ['Technology','Service']`, which on the live graph matched 38 of
    #    179 tech-layer nodes and 3 of 65 exploit-bearing ones -- the WF04-vs-chat
    #    score disagreement in issues.md, Confirmed limitations item 3.
    apt = (REPO_ROOT / "llm/tools/attack_path_tool.py").read_text()
    if "toLower(coalesce(x.nodeType, '')) IN $tech_types" not in apt:
        failures.append("llm/tools/attack_path_tool.py: the exploit-index Cypher must "
                        "match nodeType through toLower() against a parameter, or it "
                        "silently sees only one casing")
    # Skip comment lines: the fix's own comment quotes the old predicate verbatim
    # to explain what it did, and that is documentation, not a regression.
    if any(re.search(r"IN \['Technology', ?'Service'\]", line)
           for line in apt.splitlines() if not line.lstrip().startswith("#")):
        failures.append("llm/tools/attack_path_tool.py: case-sensitive nodeType filter "
                        "is back -- it misses every batch_import-written node")


def check_notification_invariants(failures: List[str]) -> None:
    """Four properties of scripts/spotter_notify.py that fail SILENTLY if lost.

    None of these produce an error when broken -- the feed keeps answering 200
    while quietly losing data -- so they are asserted on the source text rather
    than left to a code review that will not happen twice.
    """
    path = REPO_ROOT / "scripts" / "spotter_notify.py"
    if not path.exists():
        failures.append("scripts/spotter_notify.py is missing")
        return
    src = path.read_text()

    def require(needle: str, why: str) -> None:
        if needle not in src:
            failures.append(f"spotter_notify.py: missing {needle!r} — {why}")

    # 1. The dual label. WF07's orphan sweep deletes anything with no live
    #    sketch_id unless it is :SpotterMeta, so dropping that label from the
    #    MERGE means every campaign delete silently wipes the whole feed.
    require("MERGE (n:SpotterMeta:SpotterNotification {dedup_key:$dedup})",
            "WF07's orphan sweep would delete the feed without the :SpotterMeta label")

    # 2. No sketch_id on notification nodes. A node inside a sketch whose
    #    nodeType Flowsint cannot resolve makes reads of the WHOLE sketch 500.
    #
    #    Scoped to the emit statement, NOT the whole file. A bare "n.sketch_id"
    #    substring search over the module is wrong twice over: the docstring
    #    quotes WF07's orphan sweep verbatim (`coalesce(n.sketch_id, "")`), and
    #    every sweep source legitimately filters the nodes it READS by
    #    sketch_id. Neither is a notification node being written.
    start = src.find("MERGE (n:SpotterMeta:SpotterNotification")
    end = src.find("RETURN created", start) if start >= 0 else -1
    emit_stmt = src[start:end] if (start >= 0 and end > start) else ""
    if not emit_stmt:
        failures.append("spotter_notify.py: could not locate the emit statement to check")
    elif "sketch_id" in emit_stmt:
        failures.append(
            "spotter_notify.py: the notification MERGE sets sketch_id — these nodes "
            "must stay outside every sketch or an unresolvable nodeType 500s the "
            "whole graph"
        )
    if "SET n.sketch_id" in src:
        failures.append(
            "spotter_notify.py: writes sketch_id onto a notification node after "
            "creation — same 500-the-whole-sketch risk as setting it at MERGE time"
        )

    # 2b. No `key` property on notification nodes. Neo4j holds a UNIQUENESS
    #     constraint on :SpotterMeta(key) (spotter_meta_key_unique) that guards
    #     the singleton blobs, and notification nodes are dual-labelled
    #     :SpotterMeta -- so any constant written to n.key means the first
    #     notification ever created claims it and every later emit dies with
    #     ConstraintValidationFailed. The feed then holds exactly one row, for
    #     the whole install, forever. Uniqueness is not enforced against a
    #     missing property, so the fix is to write no key at all.
    if emit_stmt and "n.key" in emit_stmt:
        failures.append(
            "spotter_notify.py: the notification MERGE sets n.key — :SpotterMeta(key) "
            "is UNIQUE, so only the first notification would ever be created and "
            "every later emit would fail with ConstraintValidationFailed"
        )
    if "SET n.key" in src:
        failures.append(
            "spotter_notify.py: writes n.key onto a notification node — collides "
            "with the UNIQUE :SpotterMeta(key) constraint"
        )

    # 2c. Baseline markers are the dedup ledger, not feed rows, so retention
    #     must not trim them against the visible feed's bound — that deletes
    #     the oldest markers first and re-reports their findings as new.
    require("coalesce(n.baseline, false) = $baseline",
            "prune must trim baseline dedup markers separately from visible rows, "
            "or trimming re-notifies findings the first sweep already baselined")

    # 3. The bucket source honours the configured exposure threshold. WF13's own
    #    (removed) Slack alert gated on BUCKET_ALERT_MIN_SCORE; _sweep_buckets is
    #    now its only consumer, so reverting to an unconditional score>0 gate
    #    silently re-floods the ticker with every low-score open bucket.
    require("if score_i < min_score:",
            "_sweep_buckets must gate open buckets on the configured minimum "
            "exposure score (BUCKET_ALERT_MIN_SCORE)")

    # 2d. The per-sweep cap and the rollup must count NEW findings, not staged
    #     ones. The sweep sources re-stage the campaign's whole history every
    #     run, so capping the raw staged list makes the rollup announce
    #     "+N more findings" once a minute forever and starves genuinely new
    #     findings of the budget.
    require("fresh = [p for p in pending if str(p.get(\"dedup_key\") or \"\") not in known]",
            "the per-sweep budget and the rollup must be applied to NEW findings, "
            "or a mature campaign emits a bogus rollup on every sweep")
    if "pending[:budget]" in src:
        failures.append(
            "spotter_notify.py: applies the per-sweep budget to the raw staged list — "
            "it must be applied to the deduped `fresh` list"
        )

    # 3. The lock line that makes the sweep lease a real compare-and-set. It
    #    reads as dead code and is the only thing serialising concurrent polls.
    require("SET m._lock = timestamp()",
            "without it two simultaneous polls both read a free lease and both sweep")

    # 4. The uniqueness constraint — the backstop that makes a double-create
    #    impossible rather than merely unlikely.
    require("REQUIRE n.dedup_key IS UNIQUE",
            "MERGE alone can race; the constraint is what prevents duplicates")

    # 5. Sketch comes from the registry, never the request body.
    require("_acl.read_campaigns()",
            "the sketch must be derived from the campaign registry")
    if "body.get(\"sketch_id\")" in src or "body.get('sketch_id')" in src:
        failures.append(
            "spotter_notify.py: reads sketch_id from the request body — one operator "
            "could then sweep another operator's graph into their own ticker"
        )


def check_no_private_key_material(failures: List[str]) -> None:
    """
    No file git would publish may contain a private key.

    .gitignore cannot enforce this. Every key rule it carries is NAME-based
    (*.pem, id_rsa*, id_ed25519*, ...) and an engagement key called something
    like "extravm" -- no extension, no convention -- matches none of them. One
    such key sat untracked AND unignored in the repo root, a single `git add -A`
    from publication.

    So check CONTENT, and check both the tracked set and the untracked-but-not-
    ignored set: the second is the pre-commit window, which is where a stray key
    actually lives before it becomes a commit.
    """
    import subprocess as _sp

    marker = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")

    def _git(*args: str) -> List[str]:
        try:
            out = _sp.run(["git", "-C", str(REPO_ROOT), *args],
                          capture_output=True, text=True, timeout=60)
        except (OSError, _sp.SubprocessError):
            return []
        if out.returncode != 0:
            return []
        return [ln for ln in (out.stdout or "").splitlines() if ln.strip()]

    candidates = set(_git("ls-files")) | set(_git("ls-files", "--others", "--exclude-standard"))
    if not candidates:
        return                      # not a git checkout; nothing to protect

    for rel in sorted(candidates):
        path = REPO_ROOT / rel
        try:
            if not path.is_file() or path.is_symlink():
                continue
            with open(path, "rb") as fh:
                head = fh.read(200)
        except OSError:
            continue
        if marker.search(head):
            failures.append(
                f"{rel}: contains a PRIVATE KEY header and is tracked or "
                "untracked-but-not-ignored, i.e. one `git add -A` from being "
                "published. Move it under tunnel-keys/ (gitignored) or add a rule"
            )


def check_secret_tiers_are_local(failures: List[str]) -> None:
    """Reject tracked secret tiers and SOPS recipient configuration."""
    import subprocess as _sp

    def _git(*args: str) -> List[str]:
        try:
            out = _sp.run(["git", "-C", str(REPO_ROOT), *args],
                          capture_output=True, text=True, timeout=60)
        except (OSError, _sp.SubprocessError):
            return []
        if out.returncode != 0:
            return []
        return [ln for ln in (out.stdout or "").splitlines() if ln.strip()]

    tracked = _git("ls-files", "--", "secrets/")
    tracked += _git("ls-files", "--", ".sops.yaml")
    for rel in tracked:
        failures.append(
            f"{rel}: secret tiers and SOPS recipient configuration are local-only "
            "and must not be tracked. Keep them gitignored."
        )


def check_no_plaintext_secrets_in_env(failures: List[str]) -> None:
    """No credential may sit in .env as a plaintext value.

    .env is gitignored, so check_no_private_key_material() and
    check_secret_tiers_are_encrypted() both structurally cannot see it: the first
    walks git's file lists, and the second filters to secrets/. That left the most
    likely way to introduce a credential completely unguarded --- an operator
    following .env.example's per-key comments, which still say "paste it here".

    Classification comes from scripts/spotter_env.py so this cannot drift from
    what the splitter and the admin CLI consider a secret. It is default-deny:
    a credential-shaped name nobody has classified counts, which is what catches
    a brand-new vendor key.
    """
    env_path = REPO_ROOT / ".env"
    if not env_path.exists():
        return                      # a fresh clone has none yet; not a failure

    try:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import spotter_env
    except Exception as exc:
        failures.append(f"could not import spotter_env to check .env: {exc}")
        return

    try:
        lines = env_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, sep, value = stripped.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if not spotter_env.is_secret(key):
            continue
        # An empty value or an untouched template placeholder is not a leak --
        # .env is seeded from .env.example, which ships REPLACE_WITH_* lines.
        if not value or value.startswith("REPLACE_WITH_"):
            continue
        kind = spotter_env.classify(key)
        where = ("a tier you choose" if kind == spotter_env.UNKNOWN_SECRET
                 else f"secrets/{kind}.sops.env")
        failures.append(
            f".env: {key} is a credential stored in PLAINTEXT. It belongs in "
            f"{where}. Move it with `scripts/spotter_secret.py set {key}` "
            f"(or all at once with `scripts/split_env_to_sops.py --merge`)."
        )


# The persistent-state bind sources. Unset means the pre-folder layout, where each
# compose entry falls back to the named volume it has always used; set means a bind
# mount inside the checkout. Kept here so check_guard_var_lists_agree() can compare
# this list against the launcher's own copy.
STATE_MOUNT_VARS = (
    "SPOTTER_NEO4J_DATA", "SPOTTER_NEO4J_LOGS", "SPOTTER_NEO4J_IMPORT",
    "SPOTTER_NEO4J_PLUGINS", "SPOTTER_PG_DATA", "SPOTTER_REDIS_DATA",
    "SPOTTER_N8N_DATA", "SPOTTER_OPEN_WEBUI_DATA", "SPOTTER_TOR_DATA",
    "SPOTTER_CADDY_DATA_DIR",
)

# Every .env key that names a host path a bind mount will use. Module level so
# check_guard_var_lists_agree() can read it without depending on whether
# check_env_dirs_are_absolute() got far enough to define it -- on a fresh clone
# that one returns early, before any local would exist.
ENV_PATH_VARS = (
    "SPOTTER_SCRIPTS_DIR", "SPOTTER_ENRICHERS_DIR", "SPOTTER_RUNNERS_CONFIG",
    "SPOTTER_CACHE_HOST_DIR", "SPOTTER_SCREENSHOTS_DIR", "SPOTTER_INGEST_STAGING_DIR",
    "SHARPHOUND_DROP_DIR",
    "SSH_KEY_DIR", "SPOTTER_TUNNEL_KEYS_DIR", "SPOTTER_HOME", "FLOWSINT_HOME",
) + STATE_MOUNT_VARS


def check_guard_var_lists_agree(failures: List[str]) -> None:
    """
    The launcher's relative-path guard and check_env_dirs_are_absolute() are two
    hand-maintained copies of one list, and they had already drifted before this
    check existed: the launcher watched 8 names, this file watched 10. The
    launcher is the copy that runs on every `up`, so anything only this file
    knows about is caught offline and waved through at launch.

    Not factored into a shared sourced file on purpose. spotter_compose.sh is
    built on "derived from this script's own location, so it is right even when
    .env is wrong" (see its header); a file it has to source is a new way for it
    to be wrong, for three consumers. Comparing the two lists costs less.

    SPOTTER_HOME and FLOWSINT_HOME are allowed to be missing from the launcher:
    it derives both rather than reading them.
    """
    launcher = REPO_ROOT / "scripts" / "spotter_compose.sh"
    if not launcher.exists():
        return
    try:
        text = launcher.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    # The loop header, with line continuations, plus the $SPOTTER_STATE_VARS the
    # launcher expands into it.
    m = re.search(r"for _k in ((?:[^\n;]|\\\n)*?); do", text)
    if not m:
        failures.append(
            "scripts/spotter_compose.sh: could not find the 'for _k in ...' guard "
            "loop. If it was renamed, update check_guard_var_lists_agree()."
        )
        return
    names = set(m.group(1).replace("\\\n", " ").split())

    if "$SPOTTER_STATE_VARS" in names:
        names.discard("$SPOTTER_STATE_VARS")
        sv = re.search(r'SPOTTER_STATE_VARS="((?:[^"\\]|\\\n)*)"', text)
        if sv:
            names |= set(sv.group(1).replace("\\\n", " ").split())

    expected = set(ENV_PATH_VARS)
    derived = {"SPOTTER_HOME", "FLOWSINT_HOME"}

    missing_in_launcher = (expected - derived) - names
    extra_in_launcher = names - expected
    if missing_in_launcher:
        failures.append(
            "scripts/spotter_compose.sh guard loop is missing "
            + ", ".join(sorted(missing_in_launcher))
            + " — the launcher runs on every `up`, so anything only "
            "check_env_dirs_are_absolute() watches is refused offline and waved "
            "through at launch."
        )
    if extra_in_launcher:
        failures.append(
            "scripts/spotter_compose.sh guards "
            + ", ".join(sorted(extra_in_launcher))
            + " but check_env_dirs_are_absolute() does not. Add them to `watched`."
        )


def check_env_dirs_are_absolute(failures: List[str]) -> None:
    """
    Every *_DIR in .env must be absolute. The static twin of the guard in
    scripts/spotter_compose.sh.

    Compose resolves a relative bind source against the PROJECT directory, which
    is the Flowsint checkout (vendor/flowsint), not this repo -- and Docker
    CREATES a missing bind source rather than erroring. That is how the enrichers
    sat behind an empty mount for three weeks. Worse since vendoring: upstream
    ships its own sharphound-drops/, so a relative value now lands somewhere real
    and wrong instead of merely empty.
    """
    env_path = REPO_ROOT / ".env"
    if not env_path.exists():
        return                      # a fresh clone has none yet; not a failure

    watched = ENV_PATH_VARS
    try:
        lines = env_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key not in watched or not value:
            continue
        # SPOTTER_REDIS_DATA carries "<source>:/data" -- upstream gives redis no
        # volumes: key, so the target has to come from the variable. Judge the
        # source half; every other watched value is a bare source already.
        value = value.split(":", 1)[0]
        # ${...} and ~ are expanded later by compose or the shell.
        if value.startswith(("/", "${", "~", "$")):
            continue
        failures.append(
            f".env: {key}={value} is relative. Compose resolves it against the "
            "project directory (vendor/flowsint), not this repo, and Docker "
            "silently creates the missing directory. Use an absolute path or "
            "${SPOTTER_HOME}/..."
        )


def check_runner_config_mount_is_pinned(failures: List[str]) -> None:
    """
    The runner config must be bind-mounted from an ENV-PINNED absolute path.

    A bare `./n8n-task-runners.json` resolves against the compose PROJECT
    directory, which under the documented multi-file invocation is
    /root/flowsint — and a stale copy of this very file lives there. Compose
    silently mounts that one, the launcher applies ITS `env-overrides`, and the
    Python runner enforces an older import allowlist than this repo ships.

    Nothing errors. A code node dies at run time with ModuleNotFoundError on a
    module the repo has allowlisted, and the obvious diagnostic lies: `docker
    exec <runner> printenv` reports the LAUNCHER's correct value while the
    runner process disagrees. Read /proc/<python-runner-pid>/environ instead.
    """
    compose_path = REPO_ROOT / "deployment" / "docker-compose.n8n.yml"
    if not compose_path.exists():
        return  # reported by the checks below
    for line in compose_path.read_text().splitlines():
        stripped = line.strip()
        if not stripped.startswith("-") or "/etc/n8n-task-runners.json" not in stripped:
            continue
        if "${" not in stripped:
            failures.append(
                "docker-compose.n8n.yml: the /etc/n8n-task-runners.json mount uses "
                "a bare relative path. It must be ${SPOTTER_RUNNERS_CONFIG:-...} "
                "and pinned to an absolute path in .env, or compose mounts the "
                "stale /root/flowsint copy and the runner enforces the wrong "
                "import allowlist"
            )
        return
    failures.append(
        "docker-compose.n8n.yml: no /etc/n8n-task-runners.json mount found — the "
        "runner would fall back to the image's built-in allowlist"
    )


# Names that identify the ENGAGEMENT TARGET inside a code node. A URL whose HOST
# is built from one of these is a request to the client's own infrastructure.
TARGET_URL_NAMES = {"domain", "hostname", "host", "fqdn", "apex",
                    "subdomain", "sub", "base_domain"}

_URL_NETLOC = re.compile(r"^[A-Za-z][\w+.-]*://([^/]*)")


def _url_template(node: Any) -> str:
    """A URL expression rendered as a template: literal text kept, every
    interpolation replaced by `{name}` (or `{a|b}`). '' for anything else.

    Handles the two idioms WF13 actually uses -- an f-string and `BASE + path`
    -- because a pin that only understood f-strings would wave through the
    concatenated spelling of the same leak.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            elif isinstance(v, ast.FormattedValue):
                names = sorted({n.id for n in ast.walk(v.value)
                                if isinstance(n, ast.Name)})
                parts.append("{%s}" % "|".join(names))
            else:
                return ""
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _url_template(node.left), _url_template(node.right)
        return left + right if (left and right) else ""
    if isinstance(node, ast.Name):
        return "{%s}" % node.id
    return ""


def check_target_contact_is_proxied(failures: List[str]) -> None:
    """Nothing in WF13 may contact the TARGET off the campaign proxy.

    WF13's website-title probe called `req.get(f'https://{domain}')` with no
    `proxies=` from the day it was written. On a Russian defence-sector target,
    on a campaign whose Tor egress was configured precisely to prevent it, every
    single run therefore touched the target from this host's real IP -- and the
    leak was invisible because the proxied site_rag crawl beside it returned
    nothing while the title arrived anyway.

    The pin is deliberately the RULE and not that one line: a check for
    `proxies=` near the old line number would not stop the next such call site
    being added. It is scoped to the URL's NETLOC because that is what "we
    contacted the target" means -- a domain in a query string is a third-party
    lookup ABOUT the target (Shodan, CertKit, Flare), which is a different
    decision and correctly unproxied today.
    """
    try:
        wf = load_json(TARGETS["13"])
    except Exception as exc:                        # noqa: BLE001
        failures.append(f"WF13: unreadable ({exc})")
        return

    seen = 0
    for node_name, code in code_nodes(wf).items():
        try:
            tree = ast.parse(code)
        except SyntaxError:
            continue                    # check_ast_parse reports this already
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            url = call.args[0] if call.args else next(
                (k.value for k in call.keywords if k.arg == "url"), None)
            if url is None:
                continue
            tmpl = _url_template(url)
            m = _URL_NETLOC.match(tmpl)
            if not m:
                continue
            names = {n for group in re.findall(r"\{([^}]*)\}", m.group(1))
                     for n in group.split("|")}
            if not names & TARGET_URL_NAMES:
                continue
            seen += 1
            if not any(k.arg == "proxies" for k in call.keywords):
                failures.append(
                    f"WF13 {node_name} line {call.lineno}: {tmpl[:60]!r} builds its "
                    f"HOST from the target and passes no proxies= — that request "
                    f"leaves from this host's real IP. Pass proxies=THC_PROXIES "
                    f"(and headers with THC_USER_AGENT), or route it through "
                    f"site_rag, which is already proxied."
                )
    if not seen:
        # A guard that matches nothing passes forever. If the target variable is
        # ever renamed, this says so instead of going quietly blind.
        failures.append(
            "WF13: no request whose host is built from the target was found at "
            "all — check_target_contact_is_proxied has gone blind (renamed "
            "variable? add it to TARGET_URL_NAMES)"
        )


def check_task_runner_env(failures: List[str]) -> None:
    """
    The Python task runner only sees the env vars in its `allowed-env` list.

    Anything missing silently falls back to the code node's hard-coded default.
    N8N_WEBHOOK_BASE_URL defaulted to http://localhost:5678, which is
    connection-refused from inside the runner container, so every workflow-to-
    workflow webhook call made from Python (WF02/WF06 -> the Titus credential
    scan, WF06 -> WF03 enrichment and WF04 attack paths) failed inside a
    try/except and did nothing at all. WF04 had never executed once.
    """
    cfg_path = REPO_ROOT / "deployment" / "n8n-task-runners.json"
    if not cfg_path.exists():
        failures.append("deployment/n8n-task-runners.json is missing")
        return
    cfg = json.loads(cfg_path.read_text())
    runners = {r.get("runner-type"): r for r in cfg.get("task-runners", [])}
    py = runners.get("python")
    if not py:
        failures.append("n8n-task-runners.json: no python runner defined")
        return

    allowed = set(py.get("allowed-env", []))
    for var in ("N8N_WEBHOOK_BASE_URL", "FLOWSINT_API_URL", "FLOWSINT_API_KEY",
                "FLOWSINT_SKETCH_ID", "TITUS_API_URL", "NEO4J_HTTP_URL",
                "NVD_PROXY_URL", "SPOTTER_RUNNER_GID", "EMBEDDING_MODEL",
                "EXPLOIT_PATH_MAX_BONUS",
                "CLOUD_EXPOSURE_MAX_BONUS", "CLOUD_OWNER_MAX_BONUS",
                # WF28's fetch node reads all three; a missing one does not error,
                # os.environ.get() just returns '' and the poll reports itself as
                # "not configured" forever. BRC4_SERVER_TZ_OFFSET_HOURS is the
                # standing proof that an unlisted var stays silently inert.
                "ADAPTIX_API_URL", "ADAPTIX_USERNAME", "ADAPTIX_PASSWORD",
                # WF13's org source. HH_USER_AGENT unlisted is the nastiest of
                # these: hh_client refuses API mode without it, so the block
                # silently drops back to scraping and an operator who configured
                # an app credential never learns why it is unused.
                "HH_MODE", "HH_APP_TOKEN", "HH_CLIENT_ID", "HH_CLIENT_SECRET",
                "HH_USER_AGENT", "HH_TIMEOUT", "HH_MAX_EMPLOYERS",
                "HH_MAX_VACANCIES", "HH_MAX_VACANCY_DETAILS",
                # SERP_API_KEY was wired ONLY to the linkedin-api sidecar, so a
                # code node read it as '' and the provider reported itself
                # unconfigured forever while .env plainly had a key in it.
                "SERP_MODE", "SERP_API_KEY", "SERP_MAX_SEARCHES",
                "SERP_ROLE_KEYWORDS", "SERP_TIMEOUT",
                # The Tavily peer provider. TAVILY_API_KEY has no keyless
                # fallback behind it, so an unlisted key is not a degraded
                # provider the way an unlisted SERP_API_KEY was -- it is a
                # provider that reports "skipped" on every run while .env
                # plainly has a key in it.
                "TAVILY_API_KEY", "TAVILY_MAX_SEARCHES", "TAVILY_MAX_RESULTS",
                "TAVILY_TIMEOUT", "TAVILY_SEARCH_DEPTH_ADVANCED",
                "TAVILY_MAX_CREDITS", "TAVILY_ROLE_KEYWORDS", "TAVILY_BASE_URL",
                # The website-crawl backend switch. Unlisted, SITE_TAVILY reads
                # as 0 and an operator who selected Tavily silently keeps
                # crawling the client from this deployment's own egress -- the
                # opposite of what they asked for.
                "SITE_TAVILY", "SITE_TAVILY_BREADTH", "SITE_TAVILY_ADVANCED",
                "SITE_ENABLED", "SITE_MAX_PAGES", "SITE_MAX_DEPTH",
                "SITE_DELAY_MS", "SITE_MAX_BYTES_PER_PAGE", "SITE_MAX_SECONDS",
                "SITE_TIMEOUT", "SITE_CHUNK_CHARS", "SITE_CHUNK_OVERLAP",
                # Unlisted, the egress preflight falls back to its module
                # default and an operator who set it to 0 to skip it would
                # never see that take effect.
                "SITE_PREFLIGHT_TIMEOUT",
                "EDGAR_ENABLED", "EDGAR_USER_AGENT", "EDGAR_TIMEOUT",
                "EDGAR_MAX_REQUESTS", "EDGAR_MIN_SCORE",
                # The employment gate. Unlisted, these fall back to the module's
                # defaults -- which happen to be the safe values, so the failure
                # is invisible: the Configuration panel would show a knob that
                # changes nothing, and an operator who widened the gate for a
                # distributed target would never see it take effect.
                "ORG_PEOPLE_EMPLOYER_MIN", "ORG_PEOPLE_MIN_SCORE",
                "ORG_PEOPLE_GEO_GATE", "ORG_PEOPLE_MAX_WRITES",
                # The company-identification floor, one level above. Unlisted it
                # falls back to the module default too -- also the safe value,
                # and also invisibly.
                "ORG_COMPANY_MATCH_MIN"):
        if var not in allowed:
            failures.append(
                f"n8n-task-runners.json: {var} missing from the python runner's "
                f"allowed-env — code nodes will silently use their hard-coded default"
            )

    # Local modules under scripts/ are imported by an allowlisted module at
    # runtime; keep them listed so a code node can also import them directly.
    external = py.get("env-overrides", {}).get("N8N_RUNNERS_EXTERNAL_ALLOW", "")
    # cobalt_normalizer and brc4_normalizer both import c2_common, so a code node
    # that only touches them works with c2_common absent -- which is exactly how
    # WF21's direct `from c2_common import infer_tech_stack` shipped blocked.
    # nessus_context is imported DIRECTLY by WF25's code nodes, so unlike
    # nessus_parser (which upload_router reaches internally) its absence here is a
    # run-time death, not a theoretical one.
    for mod in ("upload_router", "flowsint_client", "sharphound_parser", "pingcastle_parser",
                "nessus_parser", "nessus_context",
                "spotter_campaign_acl", "spotter_settings", "spotter_notify",
                "spotter_cache", "analysis_history", "cobalt_normalizer", "brc4_normalizer",
                "adaptix_normalizer",
                "c2_common", "high_value_tech", "asset_labels", "cve_client",
                # Both are imported DIRECTLY by WF13's org block, so their
                # absence kills the node before line 1 with "Security violations
                # detected" -- the import scan is static, and a try/except
                # around the import does not save it.
                "hh_client", "job_titles",
                # Imported directly by WF13's org block. site_rag additionally
                # imports rag_indexer and llm_client at call time, both of which
                # are already listed.
                "serp_client", "site_rag", "edgar_client",
                # Imported directly by WF13's org block, and transitively by
                # serp_client for its headline comparison.
                "employment_evidence",
                # The Tavily provider. Imported directly by WF13's org block,
                # and by site_rag at call time when SITE_TAVILY is non-zero. It
                # additionally imports serp_client for the LinkedIn parsers --
                # ONE WAY ONLY; serp_client importing it back would take the
                # node out on a circular import before line 1.
                "tavily_client",
                # Imported directly by WF13's CT block as a second, independent
                # certificate-transparency source alongside the inline CertKit
                # call. Its absence kills the node the same way as the others.
                "certcreep",
                # Imported directly by WF05 and WF08. A missing entry is a
                # security violation before line 1; try/except does not save it.
                "individual_lookup"):
        if mod not in external:
            failures.append(f"n8n-task-runners.json: {mod} missing from N8N_RUNNERS_EXTERNAL_ALLOW")
    _check_certcreep_ru_source(failures)


def _check_certcreep_ru_source(failures: List[str]) -> None:
    """A .ru TLD must select precert only. Other TLDs stay on both sources."""
    code = code_nodes(load_json(TARGETS["13"])).get("Run Domain OSINT + Breach Correlation", "")
    if "certcreep.source_for_domain(domain, 'both')" not in code:
        failures.append(
            "WF13: CertCreep must choose its source with source_for_domain(domain, 'both') "
            "so a .ru TLD is queried as --source precert and every other TLD stays on both"
        )
    if "source=_cc_source" not in code:
        failures.append("WF13: CertCreep collect() must be called with the selected source")
    helper = (REPO_ROOT / "scripts" / "certcreep.py").read_text(encoding="utf-8")
    if 'if tld == "ru":' not in helper or 'return "precert"' not in helper:
        failures.append("scripts/certcreep.py: a .ru TLD must force source precert")


def _env_names_read(code: str) -> set:
    """Env var names a code node reads, as string literals.

    Covers `os.environ.get('X', d)`, `os.getenv('X')`, `os.environ['X']`, and
    local `_env*('X', default, lo, hi)` helpers (WF13 wraps every bucket knob in
    `_env_int`, so a plain grep for `os.environ` misses all of them).
    """
    names: set = set()
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return names  # check_ast_parse already reports this

    def _is_environ(node) -> bool:
        return isinstance(node, ast.Attribute) and node.attr == "environ"

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                func = node.func
                if isinstance(func, ast.Attribute):
                    if func.attr == "get" and _is_environ(func.value):
                        names.add(first.value)
                    elif func.attr == "getenv":
                        names.add(first.value)
                elif isinstance(func, ast.Name) and func.id.startswith("_env"):
                    names.add(first.value)
        elif isinstance(node, ast.Subscript) and _is_environ(node.value):
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                names.add(node.slice.value)
    return names


def _compose_service_env(compose_path: Path) -> Dict[str, set]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "PyYAML is required for the env-reachability check (pip install -r requirements.txt)"
        ) from exc
    doc = yaml.safe_load(compose_path.read_text()) or {}
    services = doc.get("services") or {}
    out: Dict[str, set] = {}
    for name, spec in services.items():
        env = (spec or {}).get("environment") or {}
        # compose accepts both a mapping and a `- KEY=value` list
        if isinstance(env, list):
            keys = {str(e).split("=", 1)[0] for e in env}
        else:
            keys = set(env.keys())
        out[name] = keys
    return out


def check_code_node_env_reachable(failures: List[str]) -> None:
    """
    Every env var a Python code node reads must actually be able to reach it.

    Two distinct ways it silently cannot, both of which have shipped:

      1. Set on the `task-runners` service but absent from `allowed-env`. The
         launcher filters the environment before spawning the runner, so the
         code node falls back to its hard-coded default with no error anywhere.
         This is what made SPOTTER_UPLOAD_MAX_BYTES enforce 32 MB instead of the
         configured 90 MB, and what made WF13's GRAYHATWARFARE_API_KEY and every
         BUCKET_PROBE_* knob inert no matter what .env said.

      2. Set on the `n8n` service only. Code nodes execute in the *runner*
         container, not in n8n, so an var that never appears in the
         task-runners block cannot reach them however it is allowlisted.

    A var that is set nowhere is fine: the code-node default is then the
    intended value. This check only fires when configuration exists and is
    being thrown away, which is the case that looks like it works.
    """
    compose_path = REPO_ROOT / "deployment" / "docker-compose.n8n.yml"
    cfg_path = REPO_ROOT / "deployment" / "n8n-task-runners.json"
    if not compose_path.exists() or not cfg_path.exists():
        failures.append("deployment/: docker-compose.n8n.yml or n8n-task-runners.json is missing")
        return

    cfg = json.loads(cfg_path.read_text())
    runners = {r.get("runner-type"): r for r in cfg.get("task-runners", [])}
    if "python" not in runners:
        return  # check_task_runner_env already reports this
    allowed = set(runners["python"].get("allowed-env", []))

    svc_env = _compose_service_env(compose_path)
    runner_env = svc_env.get("task-runners", set())
    n8n_env = svc_env.get("n8n", set())

    reads: Dict[str, List[str]] = {}

    # Settings resolved through spotter_settings read os.environ by *variable*
    # name, so the AST scan above cannot see them — the literal lives in
    # SETTINGS_SPEC instead. Without this, moving a knob onto the Configuration
    # panel would silently remove it from this guard's coverage, which is the
    # exact failure the guard exists to prevent.
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import spotter_settings  # noqa: E402
        for var in spotter_settings.SETTINGS_SPEC:
            reads.setdefault(var, []).append("spotter_settings/SETTINGS_SPEC")
    except Exception as exc:
        failures.append(f"spotter_settings: import failed, settings knobs unchecked: {exc}")

    for wf_path in sorted(WORKFLOW_DIR.glob("*.json")):
        try:
            wf = load_json(wf_path)
        except Exception:
            continue  # parse failures are reported elsewhere
        wf_id = wf_path.name.split("-", 1)[0]
        for node_name, code in code_nodes(wf).items():
            if not code:
                continue
            for var in _env_names_read(code):
                reads.setdefault(var, []).append(f"{wf_id}/{node_name}")

    for var, sites in sorted(reads.items()):
        if var in ENV_REACHABILITY_WAIVERS:
            continue
        where = ", ".join(sorted(set(sites))[:3])
        if "spotter_settings/SETTINGS_SPEC" in sites and var not in runner_env:
            failures.append(
                f"{var}: listed in spotter_settings.SETTINGS_SPEC but missing from "
                f"the task-runners service env — .env deployment defaults are inert"
            )
        elif var in runner_env and var not in allowed:
            failures.append(
                f"{var}: set on the task-runners service but missing from the python "
                f"runner's allowed-env — {where} silently uses its hard-coded default"
            )
        elif var in n8n_env and var not in runner_env:
            failures.append(
                f"{var}: set on the n8n service only, never on task-runners — {where} "
                f"runs in the runner container and cannot see it"
            )


def check_upload_router_labels(failures: List[str]) -> None:
    """
    Every node upload_router emits must carry data['nodeLabel'].

    Flowsint MERGEs on the Pydantic model's nodeLabel, which is populated from
    `data` — the top-level key only feeds import error messages. Nodes that set
    `label` but not `nodeLabel` import with an empty MERGE key, so all of them
    collapse into a single blank-labelled node (a two-row CSV upload landed as
    one empty `individual` before this was fixed). Types that derive nodeLabel
    from a primary field (Domain, Ip) hide the bug, so this checks a type that
    does not: Individual.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from upload_router import route_bytes
    except Exception as exc:                        # noqa: BLE001
        failures.append(f"upload_router: import failed: {exc}")
        return

    samples = {
        "csv": (b"username,email\nrjones,rjones@example.test\nkpatel,kpatel@example.test\n",
                "users.csv"),
        "amass": (b"a.example.test --> 10.0.0.1\nb.example.test --> 10.0.0.2\n", "amass.txt"),
        "json": (b'[{"username":"rjones","email":"rjones@example.test"},'
                 b'{"domain":"a.example.test"},"10.0.0.1"]', "entities.json"),
        # A Nessus header contains "ip" inside "description", so it satisfies the
        # generic CSV branch's substring test. If the nessus check ever stops
        # running first, this sample lands in _parse_csv and every finding is read
        # as a person — which the label/primary-field assertions below would not
        # catch on their own, so the format is asserted too.
        "nessus": (b"Plugin ID,CVE,Risk,Host,Protocol,Port,Name,Synopsis,Solution\n"
                   b"12345,CVE-2021-44228,Critical,10.0.0.1,tcp,8080,"
                   b"Log4j RCE,Remote code execution,Upgrade\n",
                   "scan.csv"),
    }
    for fmt, (payload, name) in samples.items():
        try:
            result = route_bytes(payload, filename=name, ingest=False)
        except Exception as exc:                    # noqa: BLE001
            failures.append(f"upload_router/{fmt}: route_bytes raised: {exc}")
            continue
        if result["format"] != fmt:
            failures.append(
                f"upload_router/{fmt}: sample detected as {result['format']!r} — "
                f"it is being routed to the wrong parser"
            )
        if not result["nodes"]:
            failures.append(f"upload_router/{fmt}: parsed 0 nodes from the sample")
            continue
        missing = [n.get("nodeLabel", "?") for n in result["nodes"]
                   if not (n.get("data") or {}).get("nodeLabel")]
        if missing:
            failures.append(
                f"upload_router/{fmt}: {len(missing)} node(s) have no data['nodeLabel'] "
                f"({missing[:3]}) — they would MERGE into one blank node"
            )
        labels = {(n.get("data") or {}).get("nodeLabel") for n in result["nodes"]}
        if len(labels) != len(result["nodes"]):
            failures.append(
                f"upload_router/{fmt}: duplicate nodeLabels across {len(result['nodes'])} nodes"
            )

        # An entity_type Flowsint cannot resolve, or a built-in one missing its
        # required primary field, is dropped by the importer with no node created
        # and nothing surfaced to the caller. Raw JSON uploads used to emit
        # "Unknown" for every item, so 100% of them vanished; nmap/amass/csv IP and
        # Domain nodes vanished for want of `address` / `domain`.
        # Only ENTITY_PRIMARY_FIELD (the built-ins) is checked: a DB-registered
        # custom type is rebuilt with every property Optional[str], so it has no
        # required field and imports fine without one.
        from upload_router import ENTITY_PRIMARY_FIELD, canonical_entity_type
        for node in result["nodes"]:
            declared = node.get("entity_type", "")
            canonical = canonical_entity_type(declared)
            if not canonical:
                failures.append(
                    f"upload_router/{fmt}: entity_type {declared!r} resolves to no "
                    f"Flowsint type — the node would be silently dropped"
                )
                continue
            primary = ENTITY_PRIMARY_FIELD.get(canonical, "")
            if primary and not (node.get("data") or {}).get(primary):
                failures.append(
                    f"upload_router/{fmt}: {canonical} node {node.get('nodeLabel')!r} "
                    f"is missing its required field {primary!r}"
                )


def main() -> int:
    failures = run_checks()
    if failures:
        print("Regression check FAILED")
        for f in failures:
            print(" -", f)
        return 1
    # Derived from TARGETS so adding a workflow cannot leave this claiming less
    # (or more) coverage than the run actually had.
    print(f"Regression check passed for workflows {'/'.join(sorted(TARGETS))} "
          f"+ LLM tool registration")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
