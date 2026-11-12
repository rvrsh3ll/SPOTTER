#!/usr/bin/env python3
"""Smoke tests for n8n webhook inventory and doctor comparison logic.

  python3 scripts/smoke_n8n_webhooks.py
"""
from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_n8n_webhooks as chk  # noqa: E402
import json  # noqa: E402

fails = 0
checks = 0


def ok(cond: bool, label: str, extra=None) -> None:
    global checks, fails
    checks += 1
    if cond:
        print("  ok    %s" % label)
        return
    fails += 1
    suffix = "" if extra is None else "\n        got: %r" % (extra,)
    print("  FAIL  %s%s" % (label, suffix))


def main() -> int:
    rows = chk.expected_workflows(ROOT)
    ok(len(rows) >= 32, "repo inventory includes at least 32 workflow files", len(rows))
    files = {r["file"] for r in rows}
    ok("32-site-clone.json" in files, "inventory includes 32-site-clone.json")
    ok("16-create-sketch.json" in files, "inventory includes 16-create-sketch.json")

    sc = chk.site_clone_expected(rows)
    ok(sc["id"] == chk.SITE_CLONE_ID, "WF32 id is spotter-workflow-32", sc["id"])
    ok(sc["want_active"] is True, "WF32 ships active:true")
    hooks = {(h["method"], h["path"]) for h in sc["webhooks"]}
    ok(("POST", "site-clone") in hooks, "WF32 registers POST /webhook/site-clone", sc["webhooks"])
    ok(chk.site_clone_deploy_hint() == chk.DEPLOY_SITE_CLONE,
       "deploy hint is the supported deploy_workflow.sh command")

    wf = json.loads((ROOT / "n8n-workflows" / "32-site-clone.json").read_text())
    code = ""
    for node in wf["nodes"]:
        if node.get("name") == "Run Site Clone":
            code = node["parameters"]["pythonCode"]
    ok("site-clone-api unreachable at" in code,
       "WF32 returns an error that names the site-clone-api URL")
    ok("if not isinstance(options, dict)" in code,
       "WF32 does not treat an empty options object as missing")
    ok("site-clone workflow failed" in code and "return _run()" in code,
       "WF32 wraps the node in a top-level try/except that still returns JSON")
    ok('code == 0 or (not data.get("status") and data.get("error"))' in code
       or "site-clone-api unreachable at %s" in code,
       "status action does not report ok on an unreachable API")

    live = {
        "spotter-workflow-16": {"id": "spotter-workflow-16", "name": "16", "active": 1},
    }
    problems = chk.compare_inventory(rows, live)
    missing_ids = {p["id"] for p in problems if p["kind"] == "missing"}
    ok(chk.SITE_CLONE_ID in missing_ids,
       "compare flags WF32 as missing when it is absent from the live DB")
    problems_inactive = chk.compare_inventory(rows, {
        chk.SITE_CLONE_ID: {"id": chk.SITE_CLONE_ID, "name": "32 - Site Clone", "active": 0},
        **live,
    })
    kinds = {p["id"]: p["kind"] for p in problems_inactive}
    ok(kinds.get(chk.SITE_CLONE_ID) == "inactive",
       "compare flags WF32 as inactive when active=0", kinds.get(chk.SITE_CLONE_ID))
    ok(not chk.compare_inventory(rows, {
        r["id"]: {"id": r["id"], "name": r["name"], "active": 1} for r in rows if r["want_active"]
    }), "compare is clean when every active workflow is present")

    ok(chk.classify_site_clone_probe(
        404, 'The requested webhook "POST site-clone" is not registered.') == "unregistered",
       "404 + not registered is unregistered")
    ok(chk.classify_site_clone_probe(
        500, 'The requested webhook "POST site-clone" is not registered.') == "unregistered",
       "500 + not registered is unregistered")
    ok(chk.classify_site_clone_probe(200, '{"ok":false,"error":"unknown job"}') == "registered",
       "200 JSON from a status probe means the webhook is registered")
    ok(chk.classify_site_clone_probe(0, "fetch failed") == "unknown",
       "status 0 is unknown")

    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "database.sqlite"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE workflow_entity (id TEXT PRIMARY KEY, name TEXT, active INTEGER)")
        con.execute("INSERT INTO workflow_entity VALUES (?,?,?)",
                    (chk.SITE_CLONE_ID, "32 - Site Clone", 1))
        con.commit()
        con.close()
        live_db = chk.live_workflows(db)
        ok(chk.SITE_CLONE_ID in live_db and chk.is_active(live_db[chk.SITE_CLONE_ID]),
           "live_workflows reads an active WF32 row from sqlite")

    rows_ok = chk.check_clone_containers(None)
    ok(rows_ok == [], "clone-container check is skipped without docker")

    orig = chk.container_running
    try:
        chk.container_running = lambda docker, name: name in set(docker)
        missing = chk.check_clone_containers(["docker"])
        names = [r["msg"] for r in missing]
        ok(all(r["ok"] is False for r in missing) and len(missing) == 2,
           "both Site Clone containers are flagged when they are down", names)
        ok(any(chk.START_CLONE_SERVICES in (r.get("hints") or []) for r in missing),
           "missing API hints the compose build command")
        ok(any(chk.START_DEOBF_WORKER in (r.get("hints") or []) for r in missing),
           "missing deobf worker hints the worker compose command")
        present = chk.check_clone_containers(
            [chk.SITE_CLONE_API_CONTAINER, chk.SITE_CLONE_DEOBF_CONTAINER]
        )
        ok(all(r["ok"] is True for r in present) and len(present) == 2,
           "both Site Clone containers pass when running")
    finally:
        chk.container_running = orig

    print("\n%s: %d/%d checks" % ("FAILED" if fails else "PASSED", checks - fails, checks))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
