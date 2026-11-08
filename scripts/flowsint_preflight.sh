#!/usr/bin/env bash
# SPOTTER — Flowsint preflight.
#
#   scripts/flowsint_preflight.sh [--retries N] [--delay SECONDS]
#   ./spotter check-flowsint
#
# Checks everything campaign sketch provisioning (WF16, /webhook/create-sketch)
# depends on, from the same place WF16 runs: the n8n task-runners container,
# using its own FLOWSINT_API_URL / FLOWSINT_API_KEY and scripts/flowsint_client.py.
# A failure here means "could not resolve or create investigation" on every new
# campaign until it is fixed; afterwards, use Retry Provision in the campaign
# panel instead of recreating the campaign.
#
# Never prints secrets. Exit 0 when every check passes, 1 otherwise.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RETRIES=5
DELAY=3
while [[ $# -gt 0 ]]; do
    case "$1" in
        --retries) RETRIES="${2:-5}"; shift 2 ;;
        --delay)   DELAY="${2:-3}"; shift 2 ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

RUNNERS="${SPOTTER_RUNNERS_CONTAINER:-spotter-n8n-runners}"
NEO4J_CONTAINER="${SPOTTER_NEO4J_CONTAINER:-flowsint-neo4j-prod}"
DEFAULT_INTERNAL_URL="http://flowsint-api:5001"
DEFAULT_HOST_URL="http://127.0.0.1:5001"

BOLD=$'\033[1m'; RESET=$'\033[0m'; RED=$'\033[31m'; GREEN=$'\033[32m'
[[ -t 1 ]] || { BOLD=""; RESET=""; RED=""; GREEN=""; }
FAILS=0
pass() { echo "  ${GREEN}PASS${RESET} $1"; }
fail() { echo "  ${RED}FAIL${RESET} $1"; shift; for h in "$@"; do echo "       fix: $h"; done; FAILS=$((FAILS+1)); }

retry() {
    local i
    for ((i=1; i<=RETRIES; i++)); do
        "$@" && return 0
        (( i < RETRIES )) && sleep $(( DELAY * i ))
    done
    return 1
}

DOCKER=(docker)
if ! docker info >/dev/null 2>&1; then
    if sudo -n docker info >/dev/null 2>&1; then DOCKER=(sudo -n docker); fi
fi

running() { [[ "$("${DOCKER[@]}" inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == "true" ]]; }

find_api_container() {
    local c
    c="$("${DOCKER[@]}" ps -q --filter label=com.docker.compose.project=spotter \
          --filter label=com.docker.compose.service=api 2>/dev/null | head -1)"
    [[ -z "$c" ]] && c="$("${DOCKER[@]}" ps -q --filter name=flowsint-api 2>/dev/null | head -1)"
    printf "%s" "$c"
}

echo "${BOLD}Flowsint preflight (what campaign sketch provisioning needs)${RESET}"

if ! command -v docker >/dev/null 2>&1 || ! "${DOCKER[@]}" info >/dev/null 2>&1; then
    fail "docker daemon reachable" "start Docker, or re-run with sudo: sudo ./spotter check-flowsint"
    echo ""; echo "${RED}Flowsint preflight: docker unavailable, nothing else checked.${RESET}"
    exit 1
fi
pass "docker daemon reachable"

API_C=""
retry_api() { API_C="$(find_api_container)"; [[ -n "$API_C" ]] && running "$API_C"; }
if retry retry_api; then
    pass "Flowsint API container running ($("${DOCKER[@]}" inspect -f '{{.Name}}' "$API_C" | sed 's#^/##'))"
else
    fail "Flowsint API container running" "./spotter up" "./spotter logs api"
fi

if retry running "$NEO4J_CONTAINER"; then
    pass "Neo4j container running ($NEO4J_CONTAINER)"
else
    fail "Neo4j container running ($NEO4J_CONTAINER)" "./spotter up" "./spotter logs neo4j"
fi

# Runs inside the task-runners container, exactly as WF16's Python Code node does.
PROBE='
import os, sys, json
sys.path.insert(0, "/data/scripts")
out = {"url": os.environ.get("FLOWSINT_API_URL") or "", "key_set": bool(os.environ.get("FLOWSINT_API_KEY"))}
try:
    import requests
except Exception as e:
    out["fatal"] = "python requests missing: %s" % e
    print(json.dumps(out)); sys.exit(0)
base = out["url"] or "'"$DEFAULT_INTERNAL_URL"'"
out["url"] = base
try:
    r = requests.get(base.rstrip("/") + "/api/investigations",
                     headers={"Authorization": "Bearer " + os.environ.get("FLOWSINT_API_KEY", "")}, timeout=10)
    out["inv_status"] = r.status_code
    if r.status_code == 200:
        try: out["inv_count"] = len(r.json())
        except Exception: out["inv_count"] = -1
except Exception as e:
    out["inv_error"] = type(e).__name__ + ": " + str(e)[:200]
try:
    import flowsint_client  # noqa: F401
    out["client_ok"] = True
except Exception as e:
    out["client_ok"] = False
    out["client_error"] = str(e)[:200]
nurl = os.environ.get("NEO4J_HTTP_URL") or "http://flowsint-neo4j-prod:7474"
out["neo4j_url"] = nurl
try:
    r = requests.post(nurl.rstrip("/") + "/db/neo4j/tx/commit",
                      json={"statements": [{"statement": "RETURN 1"}]},
                      auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ.get("NEO4J_PASSWORD", "")), timeout=10)
    out["neo4j_status"] = r.status_code
    try: out["neo4j_errors"] = len(r.json().get("errors") or [])
    except Exception: out["neo4j_errors"] = -1
except Exception as e:
    out["neo4j_error"] = type(e).__name__ + ": " + str(e)[:200]
print(json.dumps(out))
'

field() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); v=d.get(sys.argv[2], ""); print(v if not isinstance(v,bool) else ("1" if v else ""))' "$1" "$2" 2>/dev/null; }

RESULT=""
probe_ok() {
    RESULT="$("${DOCKER[@]}" exec "$RUNNERS" python3 -c "$PROBE" 2>/dev/null | tail -1)"
    [[ -n "$RESULT" && "$(field "$RESULT" inv_status)" == "200" && "$(field "$RESULT" neo4j_status)" == "200" ]]
}

if ! retry running "$RUNNERS"; then
    fail "n8n task-runners container running ($RUNNERS) — WF16 runs its Python here" \
         "./spotter up" "./spotter logs task-runners"
else
    pass "n8n task-runners container running ($RUNNERS)"
    retry probe_ok
    if [[ -z "$RESULT" ]]; then
        fail "probe executed inside $RUNNERS" "docker exec $RUNNERS python3 -V   (python3 must exist in the runners image)"
    elif [[ -n "$(field "$RESULT" fatal)" ]]; then
        fail "probe executed inside $RUNNERS: $(field "$RESULT" fatal)" "rebuild the runners image: ./spotter compose build task-runners"
    else
        url="$(field "$RESULT" url)"
        if [[ -n "$(field "$RESULT" key_set)" ]]; then
            pass "FLOWSINT_API_KEY present in $RUNNERS (value not shown)"
        else
            fail "FLOWSINT_API_KEY present in $RUNNERS" \
                 "store it: sudo python3 scripts/refresh_flowsint_token.py  (or re-run ./spotter bootstrap)" \
                 "then recreate: ./spotter compose up -d --no-deps --force-recreate n8n task-runners"
        fi
        st="$(field "$RESULT" inv_status)"
        case "$st" in
            200) pass "GET $url/api/investigations -> 200 ($(field "$RESULT" inv_count) investigations); token accepted" ;;
            401|403) fail "GET $url/api/investigations -> $st (token rejected or expired)" \
                 "sudo python3 scripts/refresh_flowsint_token.py" \
                 "./spotter compose up -d --no-deps --force-recreate n8n task-runners" ;;
            "") fail "GET $url/api/investigations unreachable from $RUNNERS: $(field "$RESULT" inv_error)" \
                 "check FLOWSINT_API_URL (default $DEFAULT_INTERNAL_URL) and that both containers share the flowsint network" \
                 "./spotter logs api" ;;
            *) fail "GET $url/api/investigations -> HTTP $st" "./spotter logs api   (5xx usually means Postgres/Neo4j behind it is down)" ;;
        esac
        if [[ -n "$(field "$RESULT" client_ok)" ]]; then
            pass "flowsint_client importable from /data/scripts"
        else
            fail "flowsint_client importable from /data/scripts: $(field "$RESULT" client_error)" \
                 "check SPOTTER_SCRIPTS_DIR in .env points at $ROOT_DIR/scripts, then recreate task-runners"
        fi
        nst="$(field "$RESULT" neo4j_status)"; nurl="$(field "$RESULT" neo4j_url)"
        if [[ "$nst" == "200" && "$(field "$RESULT" neo4j_errors)" == "0" ]]; then
            pass "Neo4j answers at $nurl (auth ok)"
        elif [[ "$nst" == "401" || "$nst" == "403" ]]; then
            fail "Neo4j at $nurl -> $nst (credentials rejected)" "check NEO4J_USER / NEO4J_PASSWORD in SPOTTER config match Flowsint's Neo4j"
        elif [[ -z "$nst" ]]; then
            fail "Neo4j unreachable at $nurl: $(field "$RESULT" neo4j_error)" "./spotter logs neo4j"
        else
            fail "Neo4j at $nurl -> HTTP $nst" "./spotter logs neo4j"
        fi
    fi
fi

echo ""
if (( FAILS == 0 )); then
    echo "${GREEN}Flowsint preflight passed: campaign sketch provisioning should work.${RESET}"
    exit 0
fi
echo "${RED}Flowsint preflight: $FAILS check(s) failed.${RESET} New campaigns will show"
echo "\"sketch provisioning failed\" until this passes. After fixing, re-run:"
echo "  sudo ./spotter check-flowsint"
echo "then press Retry Provision on any affected campaign."
exit 1
