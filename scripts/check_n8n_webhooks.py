#!/usr/bin/env python3
"""Check that repo workflows (especially WF32 Site Clone) are imported and active.

Used by ``./spotter doctor``. Compares n8n-workflows/*.json against the live
n8n database when it is readable, and probes POST /webhook/site-clone from
inside the n8n container (a status request for a fake job_id, never a clone).

Never prints secrets. Exit 0 when the checks that could run all passed and
Site Clone is registered and the clone/deobf containers are running when
Docker is reachable; exit 1 otherwise.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SITE_CLONE_FILE = "32-site-clone.json"
SITE_CLONE_ID = "spotter-workflow-32"
SITE_CLONE_PATH = "site-clone"
DEPLOY_SITE_CLONE = (
    "sudo ./scripts/deploy_workflow.sh n8n-workflows/32-site-clone.json"
)
DEPLOY_ALL = "sudo ./scripts/deploy_workflow.sh --all"
SITE_CLONE_API_CONTAINER = "spotter-site-clone"
SITE_CLONE_DEOBF_CONTAINER = "spotter-site-clone-deobf"
START_CLONE_SERVICES = (
    "sudo ./spotter compose up -d --build site-clone-api site-clone-deobf"
)
START_DEOBF_WORKER = "sudo ./spotter compose up -d --build site-clone-deobf"


def expected_workflows(root: Path | None = None) -> list[dict[str, Any]]:
    base = Path(root or ROOT) / "n8n-workflows"
    rows: list[dict[str, Any]] = []
    for path in sorted(base.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        hooks = []
        for node in data.get("nodes") or []:
            if node.get("type") != "n8n-nodes-base.webhook":
                continue
            params = node.get("parameters") or {}
            hooks.append({
                "method": str(params.get("httpMethod") or "GET").upper(),
                "path": str(params.get("path") or node.get("webhookId") or "").strip("/"),
            })
        rows.append({
            "file": path.name,
            "rel": "n8n-workflows/%s" % path.name,
            "id": data.get("id"),
            "name": data.get("name"),
            "want_active": bool(data.get("active")),
            "webhooks": hooks,
        })
    return rows


def site_clone_expected(rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = rows if rows is not None else expected_workflows()
    for row in rows:
        if row["file"] == SITE_CLONE_FILE:
            return row
    raise SystemExit("n8n-workflows/%s is missing from the checkout" % SITE_CLONE_FILE)


def _read_env_value(env_file: Path, key: str) -> str:
    if not env_file.is_file():
        return ""
    last = ""
    for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith(key + "="):
            last = line.split("=", 1)[1].strip().strip("'").strip('"')
    return last


def resolve_n8n_db(root: Path | None = None) -> Path | None:
    base = Path(root or ROOT)
    explicit = os.environ.get("N8N_DB_PATH") or ""
    if explicit:
        p = Path(explicit)
        return p if p.is_file() else p
    state = os.environ.get("SPOTTER_N8N_DATA") or _read_env_value(base / ".env", "SPOTTER_N8N_DATA")
    state = state.replace("${SPOTTER_HOME}", str(base)).replace("$SPOTTER_HOME", str(base))
    if state:
        return Path(state) / "database.sqlite"
    return None


def docker_cmd() -> list[str] | None:
    for prefix in ([], ["sudo", "-n"]):
        try:
            r = subprocess.run(
                prefix + ["docker", "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if r.returncode == 0:
                return prefix + ["docker"]
        except FileNotFoundError:
            return None
    return None


def container_running(docker: list[str], name: str) -> bool:
    r = subprocess.run(
        docker + ["inspect", "-f", "{{.State.Running}}", name],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False,
    )
    return r.stdout.strip() == "true"


def live_workflows(db_path: Path) -> dict[str, dict[str, Any]]:
    con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        cols = {row[1] for row in con.execute("PRAGMA table_info(workflow_entity)")}
        want = ["id", "name"]
        if "active" in cols:
            want.append("active")
        if "isArchived" in cols:
            want.append("isArchived")
        out: dict[str, dict[str, Any]] = {}
        for rec in con.execute("SELECT %s FROM workflow_entity" % ", ".join(want)):
            row = dict(zip(want, rec))
            out[str(row["id"])] = row
        return out
    finally:
        con.close()


def is_active(row: dict[str, Any]) -> bool:
    if row.get("isArchived") in (1, True, "1"):
        return False
    val = row.get("active", 0)
    return val in (1, True, "1", "true", "TRUE")


def compare_inventory(
    expected: list[dict[str, Any]],
    live: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    problems = []
    for row in expected:
        if not row.get("want_active"):
            continue
        wid = str(row.get("id") or "")
        cur = live.get(wid)
        hooks = ", ".join("%s /webhook/%s" % (h["method"], h["path"]) for h in row["webhooks"]) or "no webhook"
        if cur is None:
            problems.append({
                "id": wid,
                "file": row["rel"],
                "name": row["name"],
                "kind": "missing",
                "hooks": hooks,
            })
        elif not is_active(cur):
            problems.append({
                "id": wid,
                "file": row["rel"],
                "name": row["name"],
                "kind": "inactive",
                "hooks": hooks,
            })
    return problems


def site_clone_deploy_hint() -> str:
    return DEPLOY_SITE_CLONE


def _probe_text(status: int, body: str) -> str:
    return "HTTP %s %s" % (status, (body or "").replace("\n", " ").strip()[:300])


def classify_site_clone_probe(status: int, body: str) -> str:
    """Return 'registered', 'unregistered', or 'unknown'."""
    text = body or ""
    lowered = text.lower()
    if "not registered" in lowered or "webhook not found" in lowered:
        return "unregistered"
    if status in (404,):
        return "unregistered"
    if status == 0:
        return "unknown"
    if 200 <= status < 300:
        return "registered"
    if status == 500 and "not registered" in lowered:
        return "unregistered"
    if status in (401, 403):
        return "registered"
    return "unknown"


def probe_site_clone(docker: list[str], container: str) -> tuple[int, str]:
    payload = '{"action":"status","job_id":"__spotter_doctor__"}'
    script = (
        "const payload = process.argv[1];"
        "fetch('http://127.0.0.1:5678/webhook/site-clone', {"
        "method:'POST',"
        "headers:{'Content-Type':'application/json','Accept':'application/json'},"
        "body:payload"
        "}).then(async r => {"
        "  const t = await r.text();"
        "  process.stdout.write(JSON.stringify({status:r.status, body:t.slice(0,800)}));"
        "}).catch(e => {"
        "  process.stdout.write(JSON.stringify({status:0, body:String(e && e.message || e)}));"
        "  process.exit(0);"
        "});"
    )
    r = subprocess.run(
        docker + ["exec", container, "node", "-e", script, payload],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    raw = (r.stdout or "").strip().splitlines()
    line = raw[-1] if raw else ""
    try:
        data = json.loads(line)
        return int(data.get("status") or 0), str(data.get("body") or "")
    except Exception:
        err = (r.stderr or r.stdout or "probe failed").strip()[:300]
        return 0, err


def _print(status: str, msg: str, fixes: list[str] | None = None) -> None:
    color = {"PASS": "\033[32m", "FAIL": "\033[31m", "WARN": "\033[33m"}.get(status, "")
    reset = "\033[0m" if sys.stdout.isatty() else ""
    if not sys.stdout.isatty():
        color = reset = ""
    print("  %s%s%s %s" % (color, status, reset, msg))
    for hint in fixes or []:
        print("       fix: %s" % hint)


def check_clone_containers(docker: list[str] | None) -> list[dict[str, Any]]:
    """Return FAIL rows for missing Site Clone API or deobf worker containers."""
    if not docker:
        return []
    rows: list[dict[str, Any]] = []
    if container_running(docker, SITE_CLONE_API_CONTAINER):
        rows.append({
            "ok": True,
            "msg": "site-clone-api container running (%s)" % SITE_CLONE_API_CONTAINER,
            "hints": [],
        })
    else:
        rows.append({
            "ok": False,
            "msg": "site-clone-api container is not running (%s)" % SITE_CLONE_API_CONTAINER,
            "hints": [START_CLONE_SERVICES],
        })
    if container_running(docker, SITE_CLONE_DEOBF_CONTAINER):
        rows.append({
            "ok": True,
            "msg": "site-clone-deobf worker running (%s, network_mode: none)" % SITE_CLONE_DEOBF_CONTAINER,
            "hints": [],
        })
    else:
        rows.append({
            "ok": False,
            "msg": (
                "site-clone-deobf worker is not running (%s) — under OPSEC, "
                "JavaScript deobfuscation will be skipped"
            ) % SITE_CLONE_DEOBF_CONTAINER,
            "hints": [START_DEOBF_WORKER],
        })
    return rows


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "-h" in args or "--help" in args:
        print(__doc__.strip())
        print("\nSite Clone deploy command:\n  %s" % DEPLOY_SITE_CLONE)
        return 0
    container = os.environ.get("N8N_CONTAINER") or "spotter-n8n"
    expected = expected_workflows()
    sc = site_clone_expected(expected)
    hooks = sc.get("webhooks") or []
    if not sc["want_active"] or sc["id"] != SITE_CLONE_ID or not any(
        h["method"] == "POST" and h["path"] == SITE_CLONE_PATH for h in hooks
    ):
        _print("FAIL", "n8n-workflows/%s does not declare an active POST /webhook/site-clone" % SITE_CLONE_FILE)
        return 1

    print("n8n webhook preflight (imported and active workflows)")
    _print("PASS", "repo ships %d workflow file(s); %s is active POST /webhook/%s" % (
        len(expected), SITE_CLONE_FILE, SITE_CLONE_PATH))

    fails = 0
    docker = docker_cmd()
    db = resolve_n8n_db()
    live: dict[str, dict[str, Any]] | None = None
    if db and Path(db).is_file():
        try:
            live = live_workflows(Path(db))
            _print("PASS", "readable n8n database at %s (%d workflow(s))" % (db, len(live)))
        except Exception as e:
            _print("WARN", "could not read n8n database at %s (%s: %s)" % (db, type(e).__name__, e))
            live = None
    elif db:
        _print("WARN", "n8n database not found at %s" % db)
    else:
        _print("WARN", "n8n database path not resolved (set N8N_DB_PATH or SPOTTER_N8N_DATA)")

    if live is not None:
        problems = compare_inventory(expected, live)
        if not problems:
            _print("PASS", "every active repo workflow id is present and active in n8n")
        else:
            for p in problems:
                if p["kind"] == "missing":
                    _print(
                        "FAIL",
                        "%s (%s) is not imported — %s is not registered" % (p["file"], p["name"], p["hooks"]),
                        [DEPLOY_SITE_CLONE if p["file"].endswith(SITE_CLONE_FILE) else
                         "sudo ./scripts/deploy_workflow.sh %s" % p["file"],
                         DEPLOY_ALL],
                    )
                else:
                    _print(
                        "FAIL",
                        "%s (%s) is imported but not active — %s is not registered" % (
                            p["file"], p["name"], p["hooks"]),
                        [DEPLOY_SITE_CLONE if p["file"].endswith(SITE_CLONE_FILE) else
                         "sudo ./scripts/deploy_workflow.sh %s" % p["file"]],
                    )
                fails += 1
        sc_live = live.get(SITE_CLONE_ID)
        if sc_live is None:
            # already counted above
            pass
        elif not is_active(sc_live) :
            pass

    probe_state = "skipped"
    if docker and container_running(docker, container):
        _print("PASS", "n8n container running (%s)" % container)
        status, body = probe_site_clone(docker, container)
        probe_state = classify_site_clone_probe(status, body)
        if probe_state == "registered":
            _print("PASS", "POST /webhook/site-clone is registered (%s)" % _probe_text(status, body))
        elif probe_state == "unregistered":
            _print(
                "FAIL",
                "POST /webhook/site-clone is not registered in n8n (%s)" % _probe_text(status, body),
                [
                    "Site Clone workflow not active in n8n — import/activate WF32",
                    DEPLOY_SITE_CLONE,
                ],
            )
            fails += 1
        else:
            _print(
                "WARN",
                "could not confirm POST /webhook/site-clone (%s)" % _probe_text(status, body),
            )
    elif docker:
        _print(
            "FAIL",
            "n8n container is not running (%s) — cannot confirm the site-clone webhook" % container,
            ["./spotter up", DEPLOY_SITE_CLONE],
        )
        fails += 1
    else:
        _print(
            "FAIL",
            "docker is not reachable, so the site-clone webhook could not be confirmed",
            ["start Docker, or re-run with sudo: sudo ./spotter doctor"],
        )
        fails += 1

    for row in check_clone_containers(docker):
        if row["ok"]:
            _print("PASS", row["msg"])
        else:
            _print("FAIL", row["msg"], row.get("hints") or [])
            fails += 1

    if fails:
        print("")
        print("n8n webhook preflight: %d check(s) failed." % fails)
        print("If Active → Site Clone reports a crashed or missing webhook, import WF32:")
        print("  %s" % DEPLOY_SITE_CLONE)
        print("If JavaScript deobfuscation is skipped under OPSEC, start the worker:")
        print("  %s" % START_DEOBF_WORKER)
        return 1
    print("")
    print("n8n webhook preflight passed: Site Clone and other active workflows are registered.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
