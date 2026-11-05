#!/usr/bin/env bash
# Post-install validation: check that all 4 login layers and core services are working.
#
# Usage:
#   python3 scripts/smoke_deploy.py --user <operator>   # first (existing)
#   scripts/smoke_postinstall.sh                         # then this
#
# Checks:
#   1. Docker containers healthy
#   2. SPOTTER portal auth gate responds
#   3. Flowsint API reachable with current token
#   4. Flowsint token expiration
#   5. Open WebUI reachable
#   6. n8n reachable
#   7. vLLM model loaded (if local tier)
#   8. Flowsint token rotation timer (if installed)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$ROOT_DIR/scripts/spotter_compose.sh"

BOLD=$'\033[1m'; RESET=$'\033[0m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
pass() { echo "  ${GREEN}PASS${RESET}  $*"; }
fail() { echo "  ${RED}FAIL${RESET}  $*"; }
warn() { echo "  ${YELLOW}WARN${RESET}  $*"; }
info() { echo "        $*"; }

# One value from .env or the encrypted tiers, through spotter_env.get().
env_get() {
    KEY="$1" ROOTD="$ROOT_DIR" sudo --preserve-env=KEY,ROOTD python3 -c '
import os, sys
sys.path.insert(0, os.path.join(os.environ["ROOTD"], "scripts"))
import spotter_env
sys.stdout.write(spotter_env.get(os.environ["KEY"]) or "")
' 2>/dev/null || true
}

FAILURES=0
check() {
    if eval "$2" >/dev/null 2>&1; then
        pass "$1"
    else
        fail "$1"
        ((FAILURES++)) || true
    fi
}

echo ""
echo "${BOLD}═══ SPOTTER Post-Install Validation ═══${RESET}"
echo ""

# ── 1. Container health ──────────────────────────────────────────────────────
echo "${BOLD}── Container health ──${RESET}"
if [[ -x "$COMPOSE" ]]; then
    UNHEALTHY=$(sudo "$COMPOSE" ps --format json 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        d = json.loads(line)
        if "unhealthy" in d.get("Health","").lower() or d.get("State") == "restarting":
            print(d.get("Name","?"))
    except: pass
' 2>/dev/null || true)
    if [[ -z "$UNHEALTHY" ]]; then
        pass "All containers healthy"
    else
        fail "Unhealthy containers: $UNHEALTHY"
    fi
else
    warn "spotter_compose.sh not executable — skipping container check"
fi
echo ""

# ── 2. SPOTTER portal auth gate ──────────────────────────────────────────────
echo "${BOLD}── SPOTTER portal ──${RESET}"
check "Dashboard reachable (https://spotter.localhost:5443)" \
    'curl -sk -o /dev/null -w "%{http_code}" https://spotter.localhost:5443 | grep -qE "200|302|401"'
echo ""

# ── 3. Flowsint API ──────────────────────────────────────────────────────────
echo "${BOLD}── Flowsint API ──${RESET}"

# Token from .env or the encrypted tier. Exported, not interpolated into the
# check strings, so it never ends up inside an eval'd command line.
FLOWSINT_KEY="$(env_get FLOWSINT_API_KEY)"
export FLOWSINT_KEY

if [[ -n "$FLOWSINT_KEY" ]]; then
    check "Flowsint API responds to auth test" \
        'curl -sf -H "Authorization: Bearer $FLOWSINT_KEY" http://127.0.0.1:5001/api/auth/test'

    # Token expiry check
    EXPIRY=$(python3 -c "
import base64, json, os, sys
token = os.environ['FLOWSINT_KEY']
try:
    payload = token.split('.')[1]
    payload += '=' * (4 - len(payload) % 4)
    exp = json.loads(base64.urlsafe_b64decode(payload))['exp']
    import datetime
    dt = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
    remaining = dt - datetime.datetime.now(tz=datetime.timezone.utc)
    hours = remaining.total_seconds() / 3600
    print(f'{hours:.1f}')
except: print('-1')
" 2>/dev/null || echo "-1")

    if [[ "$EXPIRY" != "-1" ]]; then
        HOURS_INT=${EXPIRY%.*}
        if (( HOURS_INT > 24 )); then
            pass "Flowsint token expires in ${EXPIRY}h"
        elif (( HOURS_INT > 0 )); then
            warn "Flowsint token expires in ${EXPIRY}h — rotation needed soon"
        else
            fail "Flowsint token EXPIRED — run: sudo python3 scripts/rotate_flowsint_token.py --force"
        fi
    fi
else
    fail "FLOWSINT_API_KEY not found"
fi
echo ""

# ── 4. Open WebUI ────────────────────────────────────────────────────────────
echo "${BOLD}── Open WebUI ──${RESET}"
check "Open WebUI reachable (https://chat.spotter.localhost:5443)" \
    'curl -sk -o /dev/null -w "%{http_code}" https://chat.spotter.localhost:5443 | grep -qE "200|302"'
echo ""

# ── 5. n8n ───────────────────────────────────────────────────────────────────
echo "${BOLD}── n8n ──${RESET}"
check "n8n editor reachable (https://n8n.spotter.localhost:5443)" \
    'curl -sk -o /dev/null -w "%{http_code}" https://n8n.spotter.localhost:5443 | grep -qE "200|302|401"'
echo ""

# ── 6. vLLM (if local tier) ─────────────────────────────────────────────────
LLM_TIER=$(sudo sed -n 's/^SPOTTER_LLM_TIER=//p' "$ROOT_DIR/.env" 2>/dev/null | tail -1)
if [[ "$LLM_TIER" == "local-small" || "$LLM_TIER" == "local-large" ]]; then
    echo "${BOLD}── vLLM ──${RESET}"
    # vLLM itself is on 8000 and wants its API key; 8001 is llm-gateway,
    # which does not serve /v1/models.
    VLLM_API_KEY="$(env_get VLLM_API_KEY)"
    export VLLM_API_KEY
    VLLM_HEALTH=$(docker inspect -f '{{.State.Health.Status}}' spotter-vllm 2>/dev/null || true)
    if [[ "$VLLM_HEALTH" == "starting" ]]; then
        warn "vLLM is still starting (model may be downloading) — watch: docker logs -f spotter-vllm"
    else
        check "vLLM /v1/models responds" \
            'curl -sf -H "Authorization: Bearer $VLLM_API_KEY" http://127.0.0.1:8000/v1/models'
    fi
    MODEL_INFO=$(curl -sf -H "Authorization: Bearer $VLLM_API_KEY" http://127.0.0.1:8000/v1/models 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    m = d["data"][0]
    print(f"{m[\"id\"]}  ctx={m.get(\"max_model_len\",\"?\")}")
except: print("unknown")
' 2>/dev/null || echo "unknown")
    info "Model: $MODEL_INFO"
    echo ""
fi

# ── 7. Token rotation timer ─────────────────────────────────────────────────
echo "${BOLD}── Auto-rotation ──${RESET}"
if systemctl is-enabled spotter-flowsint-rotation.timer >/dev/null 2>&1; then
    NEXT=$(systemctl list-timers spotter-flowsint-rotation.timer --no-pager 2>/dev/null | tail -n +2 | awk '{print $1, $2, $3}' | head -1)
    pass "Flowsint token rotation timer active (next: $NEXT)"
else
    warn "Flowsint token rotation timer not installed"
    info "Install with: sudo scripts/install_flowsint_rotation.sh"
fi
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo "${BOLD}═══════════════════════════════════════${RESET}"
if [[ $FAILURES -eq 0 ]]; then
    echo "${GREEN}${BOLD}All checks passed.${RESET}"
else
    echo "${RED}${BOLD}$FAILURES check(s) failed.${RESET}"
fi
echo ""
exit $FAILURES
