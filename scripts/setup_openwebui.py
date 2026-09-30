#!/usr/bin/env python3
"""
setup_openwebui.py — Install SPOTTER tools into Open WebUI and configure Qwen3.5

Run once after the stack is up and you've created your Open WebUI admin account:

    python3 scripts/setup_openwebui.py \
        --url http://localhost:3000 \
        --email admin@example.com \
        --password yourpassword

What this does:
  1. Authenticates with Open WebUI
  2. Installs (or updates) all SPOTTER tools (search, dossier, attack paths, cypher,
     technology, tech-context, AD Kerberos, AD ADCS/coercion, AD attack paths)
  3. Creates two model entries (default qwen3.8:27b, override with --model):
       - "<model>"              the SPOTTER entry, with the 9 tools attached and the
                               llm/system-prompt.md system prompt set
       - "<model>-spotter-ui"   a deliberately bare copy the frontend Prompt tab uses,
                               which sends its own prompt and runs its own tools

After running, open the SPOTTER PROMPT tab and start querying.
"""

import argparse
import json
import os
import sys

import requests

HERE         = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR    = os.path.join(HERE, "..", "llm", "tools")
SYSPROMPT    = os.path.join(HERE, "..", "llm", "system-prompt.md")
# The vLLM/OpenAI-compatible model ID SPOTTER is deployed on. Override with
# --model or SPOTTER_LLM_MODEL. Keep it identical to VLLM_MODEL in .env.
# A workspace model whose id is not served is created happily but cannot be
# chatted with, so confirm it first with GET /v1/models.
MODEL_ID     = os.environ.get("SPOTTER_LLM_MODEL", os.environ.get("VLLM_MODEL", "Qwen/Qwen3.8-27B-FP8"))

# The tooled profile lives under its OWN id and points at MODEL_ID through
# base_model_id. It must never be registered AS MODEL_ID, which is the trap this
# script fell into while the stack was on Ollama.
#
# Why: a workspace entry whose id equals a served model id SHADOWS it in
# GET /api/models — and Open WebUI builds a workspace entry's response from the
# database row, so the served model's own fields are lost. Measured 2026-09-04:
#
#     Qwen/Qwen3.8-27B-FP8   owned_by=openai   max_model_len=49152
#     <any workspace entry>  owned_by=openai   max_model_len=None
#
# The frontend Prompt tab reads max_model_len to size each turn against the real
# context window (see _contextLimitFor in frontend/index.html). Shadowing the raw
# id would hide vLLM's 49152, drop the tab to its conservative fallback, and make
# it decline tool calls on a model that has plenty of room. So the raw model stays
# unshadowed and IS the Prompt tab's bare entry — no second entry is needed, which
# is also why configure_ui_model() is gone.
PROFILE_ID   = os.environ.get("SPOTTER_OWUI_PROFILE_ID", "spotter")
PROFILE_NAME = "SPOTTER"

# id = the tool's id in Open WebUI. It must match what is already installed or a
# second copy is created and the models keep pointing at the old one, so the file
# stem (what a UI install produces) is canonical and the historical spotter_* id is
# carried in "aliases" for in-place upgrades.
TOOL_DEFS = [
    {
        "id":   "flowsint_search_tool",
        "aliases": ("spotter_search",),
        "name": "Search SPOTTER Graph",
        "file": "flowsint_search_tool.py",
        "desc": "Search Flowsint graph entities by keyword or type (Individual, IP, Computer, Group…)",
    },
    {
        "id":   "dossier_tool",
        "aliases": ("spotter_dossier",),
        "name": "Get SPOTTER Dossier",
        "file": "dossier_tool.py",
        "desc": "Fetch a complete intelligence dossier for an Individual (beacons, AD perms, creds, tech stack)",
    },
    {
        "id":   "attack_path_tool",
        "aliases": ("spotter_attack_paths",),
        "name": "Get Attack Paths",
        "file": "attack_path_tool.py",
        "desc": "Score and enumerate ACE-based attack paths from a compromised Individual node",
    },
    {
        "id":   "graph_query_tool",
        "aliases": ("spotter_cypher",),
        "name": "Run Graph Query",
        "file": "graph_query_tool.py",
        "desc": "Translate natural language to Cypher and execute it read-only against the Neo4j graph",
    },
    {
        "id":   "technology_tool",
        "aliases": ("spotter_technology",),
        "name": "Get Technology Intelligence",
        "file": "technology_tool.py",
        "desc": "OS inventory, per-user tech stacks, high-value technology users, and attack narratives",
    },
    {
        "id":   "tech_context_tool",
        "aliases": ("spotter_tech_context",),
        "name": "Get Technology Context",
        "file": "tech_context_tool.py",
        "desc": "CVE and MITRE ATT&CK contextualization for technologies and hosts",
    },
    {
        "id":   "company_site_tool",
        "aliases": ("spotter_company_site",),
        "name": "Ask the Company Website",
        "file": "company_site_tool.py",
        "desc": "Answer questions about the target organization from its own crawled "
                "website, with a citation URL for every passage",
    },
    {
        "id":   "vulnerability_tool",
        "aliases": ("spotter_vulnerabilities",),
        "name": "Get Vulnerability Findings",
        "file": "vulnerability_tool.py",
        "desc": "Nessus/Tenable scan findings: severity picture, per-host findings, "
                "hosts affected by a CVE, and which findings have public exploit code",
    },
    {
        "id":   "ad_kerberos_tool",
        "aliases": ("spotter_ad_kerberos",),
        "name": "Find Kerberos Abuse",
        "file": "ad_kerberos_tool.py",
        "desc": "Find kerberoastable / AS-REP roastable users and delegation (unconstrained/constrained/RBCD) paths",
    },
    {
        "id":   "ad_adcs_tool",
        "aliases": ("spotter_ad_adcs",),
        "name": "Find ADCS & Coercion",
        "file": "ad_adcs_tool.py",
        "desc": "Find ADCS ESC1/ESC8 misconfigurations and NTLM coercion+relay targets (Certipy / PetitPotam)",
    },
    {
        "id":   "ad_attack_paths_tool",
        "aliases": ("spotter_ad_paths",),
        "name": "AD Attack Paths",
        "file": "ad_attack_paths_tool.py",
        "desc": "Shortest path to Tier-0 (Domain/Enterprise Admins, DCs) and GPO-abuse enumeration",
    },
]


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def signin(base, email, password):
    r = requests.post(
        f"{base}/api/v1/auths/signin",
        json={"email": email, "password": password},
        timeout=15,
    )
    if not r.ok:
        die(f"Sign-in failed ({r.status_code}): {r.text[:300]}")
    return r.json()["token"]


def headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _api_post(base, token, paths, payload, timeout=60):
    """POST to the first route this Open WebUI build actually serves.

    Route names moved between versions — 0.6.x serves /tools/create and
    /tools/id/{id}/update where older builds served /tools/add and
    /tools/{id}/update (the old paths now return 405, which used to make this
    script report success for tools it had not installed). Try current first,
    fall back to legacy, so one script works against both.
    """
    resp = None
    for path in paths:
        resp = requests.post(f"{base}{path}", json=payload, headers=headers(token), timeout=timeout)
        if resp.status_code not in (404, 405):
            return resp
    return resp


def list_tool_ids(base, token):
    """Ids of the tools already installed, so we update in place instead of
    creating a duplicate under a different id."""
    for path in ("/api/v1/tools/", "/api/v1/tools/list"):
        try:
            r = requests.get(f"{base}{path}", headers=headers(token), timeout=15)
            if r.ok:
                data = r.json()
                if isinstance(data, list):
                    return {t.get("id") for t in data if isinstance(t, dict)}
        except Exception:
            continue
    return set()


def install_tool(base, token, td, existing_ids):
    """Install or update one tool. Returns the id it ended up under, or None."""
    path = os.path.join(TOOLS_DIR, td["file"])
    with open(path) as f:
        content = f.read()

    # Tools added through the Open WebUI UI take the file stem as their id, while
    # older runs of this script used the spotter_* ids. Update whichever is already
    # installed — otherwise a second copy appears and the models stay attached to
    # the stale one.
    target = next((i for i in (td["id"], *td.get("aliases", ())) if i in existing_ids), None)

    payload = {
        "id":      target or td["id"],
        "name":    td["name"],
        "content": content,
        "meta": {
            "name":        td["name"],
            "description": td["desc"],
            "manifest":    {},
        },
    }

    if target:
        # Preserve the installed name/meta so descriptions and attachments survive.
        try:
            cur = requests.get(f"{base}/api/v1/tools/id/{target}", headers=headers(token), timeout=15)
            if cur.ok:
                cj = cur.json()
                payload["name"] = cj.get("name") or payload["name"]
                payload["meta"] = cj.get("meta") or payload["meta"]
        except Exception:
            pass
        r = _api_post(base, token,
                      [f"/api/v1/tools/id/{target}/update", f"/api/v1/tools/{target}/update"],
                      payload)
    else:
        r = _api_post(base, token, ["/api/v1/tools/create", "/api/v1/tools/add"], payload)
        if r is not None and r.status_code in (400, 401, 409):
            tid = payload["id"]
            r = _api_post(base, token,
                          [f"/api/v1/tools/id/{tid}/update", f"/api/v1/tools/{tid}/update"],
                          payload)

    if r is None or not r.ok:
        code = "no matching route" if r is None else r.status_code
        body = "" if r is None else r.text[:200]
        print(f"  WARN: {payload['id']} — HTTP {code}: {body}", file=sys.stderr)
        return None
    return payload["id"]


def configure_model(base, token, tool_ids, system_prompt):
    """Create/refresh the tooled profile Open WebUI's own chat UI uses.

    Carries the ~7.5k-token system prompt and every tool, injected server-side on
    each request. The SPOTTER dashboard's Prompt tab must NOT use this entry — it
    sends its own prompt and runs its own tools, so it would pay for two copies of
    both (measured 8,450 input tokens here vs 20 on the bare model). The tab uses
    MODEL_ID directly instead; see the PROFILE_ID comment above.
    """
    payload = {
        "id":   PROFILE_ID,
        "name": PROFILE_NAME,
        "base_model_id": MODEL_ID,
        "meta": {
            "description":       f"{MODEL_ID} with SPOTTER Flowsint graph access",
            "profile_image_url": "",
            "capabilities":      {"vision": False},
            # Open WebUI reads meta.toolIds (camelCase) — backend
            # utils/automations.py::_resolve_model_tool_ids and Chat.svelte both use
            # that key. ModelMeta allows extra fields, so the snake_case "tool_ids"
            # this script used to send was stored and silently ignored: the model
            # showed tools in the database but could not call any of them. Send both,
            # camelCase first, so the attachment actually takes effect.
            "toolIds":           tool_ids,
            "tool_ids":          tool_ids,
        },
        "params": {
            "system": system_prompt,
        },
        # 0.6.x re-validates ModelForm inside the update handler, and access_grants is
        # typed list[...] with a None default — omitting it (or sending the older
        # access_control key) makes that re-validation fail with a 500. Send an empty
        # grant list: same meaning as the old access_control=None (owner-only).
        "access_grants": [],
    }

    # 0.6.x: /models/create and /models/model/update (id comes from the body, not
    # the path). Older builds: /models/add and /models/{id}/update.
    r = _api_post(base, token, ["/api/v1/models/create", "/api/v1/models/add"], payload)
    # 0.6.x answers "this model id is already registered" with 401, not 409, so treat
    # any of these as "it exists, update it instead".
    if r is not None and r.status_code in (400, 401, 409):
        r = _api_post(base, token,
                      ["/api/v1/models/model/update", f"/api/v1/models/{PROFILE_ID}/update"],
                      payload)
    if r is None:
        return False, "no matching route for model create/update"
    if not r.ok:
        return False, f"HTTP {r.status_code}: {r.text[:300]}"
    return True, None


def list_model_ids(base, token):
    """(workspace entry ids, ids actually served by a backend).

    A workspace model whose base is not served is created happily and then cannot
    be chatted with ("Model not found"), so the served set is what validates it.
    Anything with an `owned_by` came from a backend; anything else is a row in
    Open WebUI's own model table.
    """
    r = requests.get(f"{base}/api/models", headers=headers(token), timeout=30)
    if not r.ok:
        return set(), set()
    entries = (r.json() or {}).get("data") or []
    visible = {m["id"] for m in entries if isinstance(m, dict) and m.get("id")}
    # A workspace row INHERITS owned_by from its base and is listed here exactly
    # like a backend model, so owned_by alone cannot tell the two apart — trusting
    # it made every stale `*-spotter-ui` row look served and survive a prune.
    # Subtracting the model table is what actually isolates the backends.
    rows, _err = _workspace_rows(base, token)
    return visible, visible - rows


def delete_model(base, token, model_id):
    """Remove one workspace entry.

    The route is POST with the id in the BODY. `DELETE .../model/delete?id=` and
    `DELETE .../delete?id=` both answer 405, and POST .../model/delete with the id
    only in the query string answers 422 — all three look like a permissions
    problem and are not.
    """
    r = requests.post(f"{base}/api/v1/models/model/delete", json={"id": model_id},
                      headers=headers(token), timeout=30)
    return r.ok


def prune_models(base, token, keep):
    """Delete workspace entries that are neither `keep` nor served by a backend.

    This is what clears the leftovers of a backend swap. Entries pointing at tags
    that no longer exist are invisible in GET /api/models yet still occupy the
    picker and any config that names them, so they cannot be found by browsing.
    """
    removed, failed = [], []
    rows, err = _workspace_rows(base, token)
    if err:
        return removed, [err]
    _, served = list_model_ids(base, token)
    for mid in sorted(rows):
        if mid in keep or mid in served:
            continue
        (removed if delete_model(base, token, mid) else failed).append(mid)
    return removed, failed


def _workspace_rows(base, token):
    """Every id in Open WebUI's own model table, from both routes that expose it.

    Two routes are needed and neither is enough alone: /models/list returns rows
    that have a base_model_id, /models/base returns the rows with base_model_id
    NULL (the ones that shadow a backend tag). Note the trailing slash matters —
    `GET /api/v1/models/` serves the SPA's index.html with HTTP 200, so a caller
    that trusts r.ok and calls .json() dies on "Expecting value: line 1 column 1".
    """
    ids, saw_any = set(), False
    for path, key in (("/api/v1/models/list", "items"), ("/api/v1/models/base", None)):
        try:
            r = requests.get(f"{base}{path}", headers=headers(token), timeout=30)
            if not r.ok or "json" not in r.headers.get("content-type", ""):
                continue
            data = r.json()
            rows = data.get(key) or [] if key else data
            if not isinstance(rows, list):
                continue
            saw_any = True
            ids.update(m["id"] for m in rows if isinstance(m, dict) and m.get("id"))
        except Exception:
            continue
    if not saw_any:
        return set(), "could not list workspace models on any known route"
    return ids, None


def main():
    global MODEL_ID
    ap = argparse.ArgumentParser(description="Install SPOTTER tools into Open WebUI")
    ap.add_argument("--url",      default="http://localhost:3000", help="Open WebUI base URL")
    ap.add_argument("--email",    required=True,  help="Admin account email")
    ap.add_argument("--password", required=True,  help="Admin account password")
    ap.add_argument("--model",    default=MODEL_ID,
                    help=f"vLLM/OpenAI-compatible model ID to configure (default: {MODEL_ID})")
    ap.add_argument("--prune", action="store_true",
                    help="delete workspace model entries that no backend serves any more "
                         "(the leftovers of a backend swap)")
    args = ap.parse_args()

    MODEL_ID = args.model

    base = args.url.rstrip("/")
    print(f"Open WebUI: {base}  |  model: {MODEL_ID}  |  tooled profile: {PROFILE_ID}")

    token = signin(base, args.email, args.password)
    print("Authenticated\n")

    # Registering a profile on top of a model no backend serves is the one failure
    # this script cannot detect later: create/update both succeed and the entry only
    # fails when someone tries to chat with it.
    _, served = list_model_ids(base, token)
    if served and MODEL_ID not in served:
        print(f"WARNING: {MODEL_ID} is not served by any backend right now.")
        print(f"         Served: {', '.join(sorted(served)) or '(none)'}")
        print("         Check vLLM is healthy and VLLM_MODEL matches, or pass --model.\n")

    existing_ids = list_tool_ids(base, token)
    if existing_ids:
        print(f"Already installed: {', '.join(sorted(existing_ids))}\n")

    installed = []
    for td in TOOL_DEFS:
        print(f"Installing tool: {td['name']} ({td['id']})")
        tool_id = install_tool(base, token, td, existing_ids)
        if tool_id:
            installed.append(tool_id)
            print(f"  OK ({'updated' if tool_id in existing_ids else 'created'} as {tool_id})")
        else:
            print("  FAILED (see warning above)")

    print(f"\nConfiguring tooled profile: {PROFILE_ID} (base: {MODEL_ID})")
    try:
        with open(SYSPROMPT) as f:
            sysprompt = f.read()
    except FileNotFoundError:
        die(f"System prompt not found at {SYSPROMPT}")

    ok, err = configure_model(base, token, installed, sysprompt)
    if ok:
        print("  Model config applied — tools and system prompt set")
    else:
        print(f"  Model config failed: {err}")
        print(f"  Manual fallback: in Open WebUI, go to Admin → Models → {PROFILE_NAME} ({PROFILE_ID})")
        print("  and enable the SPOTTER tools under 'Tools' and paste llm/system-prompt.md")

    if args.prune:
        print("\nPruning workspace entries no backend serves")
        removed, failed = prune_models(base, token, keep={PROFILE_ID})
        for mid in removed:
            print(f"  removed {mid}")
        for mid in failed:
            print(f"  FAILED  {mid}")
        if not removed and not failed:
            print("  nothing to remove")

    print(f"\nDone. Tools installed: {', '.join(installed)}")
    print(f"Open WebUI chat: use '{PROFILE_NAME}' ({PROFILE_ID}) — prompt + tools attached.")
    print(f"SPOTTER dashboard Prompt tab: uses {MODEL_ID} directly (bare, keeps max_model_len).")


if __name__ == "__main__":
    main()
