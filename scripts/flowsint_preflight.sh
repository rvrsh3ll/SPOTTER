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
DEFAULT_INTERNAL_URL="http://flowsint-api-prod:5001"
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
import os, sys, json, base64, urllib.request, urllib.error
sys.path.insert(0, "/data/scripts")
out = {"py": sys.executable, "url": os.environ.get("FLOWSINT_API_URL") or "", "key_set": bool(os.environ.get("FLOWSINT_API_KEY"))}
def call(url, headers, data=None):
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
base = out["url"] or "'"$DEFAULT_INTERNAL_URL"'"
out["url"] = base
try:
    st, body = call(base.rstrip("/") + "/api/investigations",
                    {"Authorization": "Bearer " + os.environ.get("FLOWSINT_API_KEY", ""), "Accept": "application/json"})
    out["inv_status"] = st
    if st == 200:
        try: out["inv_count"] = len(json.loads(body))
        except Exception: out["inv_count"] = -1
except Exception as e:
    out["inv_error"] = type(e).__name__ + ": " + str(e)[:200]
try:
    import requests  # noqa: F401
    out["requests_ok"] = True
except Exception as e:
    out["requests_ok"] = False
    out["requests_error"] = str(e)[:200]
try:
    import flowsint_client  # noqa: F401
    out["client_ok"] = True
except Exception as e:
    out["client_ok"] = False
    out["client_error"] = str(e)[:200]
nurl = os.environ.get("NEO4J_HTTP_URL") or "http://flowsint-neo4j-prod:7474"
out["neo4j_url"] = nurl
auth = base64.b64encode(("%s:%s" % (os.environ.get("NEO4J_USER", "neo4j"), os.environ.get("NEO4J_PASSWORD", ""))).encode()).decode()
try:
    st, body = call(nurl.rstrip("/") + "/db/neo4j/tx/commit",
                    {"Authorization": "Basic " + auth, "Content-Type": "application/json", "Accept": "application/json"},
                    json.dumps({"statements": [{"statement": "RETURN 1"}]}).encode())
    out["neo4j_status"] = st
    try: out["neo4j_errors"] = len(json.loads(body).get("errors") or [])
    except Exception: out["neo4j_errors"] = -1
except Exception as e:
    out["neo4j_error"] = type(e).__name__ + ": " + str(e)[:200]
print(json.dumps(out))
'

dns_candidates() {
    local nets n
    nets="$("${DOCKER[@]}" inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$RUNNERS" 2>/dev/null)"
    for n in $nets; do
        "${DOCKER[@]}" network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$n" 2>/dev/null
    done | tr ' ' '\n' | grep -iE 'flowsint.*api' | sort -u | tr '\n' ' ' | sed 's/ $//'
}

field() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); v=d.get(sys.argv[2], ""); print(v if not isinstance(v,bool) else ("1" if v else ""))' "$1" "$2" 2>/dev/null; }

# WF16's Code node runs under the task runner's venv interpreter (see
# deployment/n8n-task-runners.json), not the image's system python3.
RUNNER_PY="${SPOTTER_RUNNER_PYTHON:-/opt/runners/task-runner-python/.venv/bin/python}"
RESULT=""
probe_ok() {
    local py="$RUNNER_PY"
    "${DOCKER[@]}" exec "$RUNNERS" test -x "$py" 2>/dev/null || py=python3
    RESULT="$("${DOCKER[@]}" exec "$RUNNERS" "$py" -c "$PROBE" 2>/dev/null | tail -1)"
    [[ -n "$RESULT" && "$(field "$RESULT" inv_status)" == "200" && "$(field "$RESULT" neo4j_status)" == "200" ]]
}

if ! retry running "$RUNNERS"; then
    fail "n8n task-runners container running ($RUNNERS) — WF16 runs its Python here" \
         "./spotter up" "./spotter logs task-runners"
else
    pass "n8n task-runners container running ($RUNNERS)"
    retry probe_ok
    if [[ -z "$RESULT" ]]; then
        fail "probe executed inside $RUNNERS" "docker exec $RUNNERS $RUNNER_PY -V   (the runner venv interpreter must exist)"
    else
        if [[ -n "$(field "$RESULT" requests_ok)" ]]; then
            pass "python requests available to the task runner ($(field "$RESULT" py))"
        else
            fail "python requests available to the task runner ($(field "$RESULT" py)) — flowsint_client needs it, so WF16 fails without it" \
                 "rebuild the runners image: docker build -t spotter-n8n-runners:local deployment/ -f deployment/Dockerfile.runners" \
                 "then: ./spotter compose up -d --no-deps --force-recreate task-runners"
        fi
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
            "")
                err="$(field "$RESULT" inv_error)"
                if [[ "$err" =~ [Nn]ame\ or\ service\ not\ known|[Tt]emporary\ failure\ in\ name\ resolution|getaddrinfo|NameResolution|nodename\ nor\ servname|No\ address\ associated ]]; then
                    host="$(printf "%s" "$url" | sed -E 's#^[a-z]+://##; s#[:/].*$##')"
                    cands="$(dns_candidates)"
                    fail "GET $url/api/investigations: DNS cannot resolve '$host' from $RUNNERS" \
                         "Flowsint API containers on the shared network: ${cands:-none found}" \
                         "set FLOWSINT_API_URL=http://${cands%% *}:5001 (sudo python3 scripts/migrate_flowsint_url.py fixes the old default)" \
                         "then: ./spotter compose up -d --no-deps --force-recreate n8n task-runners open-webui"
                else
                    fail "GET $url/api/investigations unreachable from $RUNNERS: $err" \
                         "check FLOWSINT_API_URL (default $DEFAULT_INTERNAL_URL) and that both containers share the flowsint network" \
                         "./spotter logs api"
                fi ;;
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
