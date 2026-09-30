#!/usr/bin/env bash
# SPOTTER — take a fresh host from clone to a working stack.
#
#   scripts/bootstrap.sh
#
# Idempotent and resumable: every step checks whether it has already been done,
# so re-running after a failure picks up where it stopped. Nothing here is
# destructive to an existing install -- it creates accounts and config, and never
# deletes data.
#
# WHAT THIS SOLVES
#
# The steps below have a strict order that is not discoverable from the compose
# files, and two of the dependencies are circular:
#
#   * The Flowsint registration page sits BEHIND SPOTTER's nginx auth gate, so
#     you cannot get a Flowsint API token until a SPOTTER portal operator exists.
#     Create that operator here, or leave the username empty and use the browser
#     setup wizard. This script still talks to flowsint-api on 127.0.0.1:5001
#     directly for the Flowsint service account.
#
#   * FLOWSINT_API_KEY and FLOWSINT_SKETCH_ID are baked into containers at CREATE
#     time, but can only be obtained after those containers are running. So the
#     stack has to come up, then be told, then be recreated. A restart is not
#     enough and this is the step people miss.
#
# Everything it does can be done by hand; INSTALL.md spells out each step.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
COMPOSE="$ROOT_DIR/scripts/spotter_compose.sh"

BOLD=$'\033[1m'; RESET=$'\033[0m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
step()  { echo ""; echo "${BOLD}==> $*${RESET}"; }
ok()    { echo "    ${GREEN}ok${RESET}  $*"; }
info()  { echo "        $*"; }
warn()  { echo "    ${YELLOW}warn${RESET} $*" >&2; }
die()   { echo "    ${RED}FAIL${RESET} $*" >&2; exit 1; }

# Reads .env, then the encrypted tiers. Without the second half, is_unset()
# would report FLOWSINT_API_KEY as absent on every re-run, and bootstrap would
# prompt for Flowsint credentials again on a host that is already set up.
# Returns a placeholder, not the value: callers only test emptiness, and the
# real secret has no reason to travel through a command substitution.
env_value() {
    local v; v="$(sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | tail -1)"
    if [[ -z "$v" && -d "$ROOT_DIR/secrets" ]] && command -v sops >/dev/null 2>&1; then
        if [[ "$(python3 "$ROOT_DIR/scripts/spotter_env.py" --status "$1" 2>/dev/null)" == "set" ]]; then
            v="<set-in-encrypted-tier>"
        fi
    fi
    printf "%s" "$v"
}
env_set() {
    # Route through spotter_env: FLOWSINT_API_KEY and OWUI_ADMIN_PASSWORD are
    # secrets and now live in secrets/machine.sops.env. Writing them straight
    # into .env, as this used to, would re-create the plaintext copies the
    # split removed -- silently, because everything would keep working.
    #
    # Falls back to the original in-place .env rewrite when the repo has not
    # been split yet (fresh clone, no secrets/), so a first bootstrap works.
    if [[ -d "$ROOT_DIR/secrets" ]] && command -v sops >/dev/null 2>&1; then
        KEY="$1" VALUE="$2" ROOTD="$ROOT_DIR" python3 -c '
import os, sys
sys.path.insert(0, os.path.join(os.environ["ROOTD"], "scripts"))
import spotter_env
spotter_env.set_value(os.environ["KEY"], os.environ["VALUE"])
'
        return
    fi
    KEY="$1" VALUE="$2" ENVF="$ENV_FILE" python3 - <<'PY'
import os, pathlib
key, value, path = os.environ['KEY'], os.environ['VALUE'], pathlib.Path(os.environ['ENVF'])
lines = path.read_text().splitlines(keepends=True)
out, done = [], False
for line in lines:
    if not done and line.split('=', 1)[0].strip() == key and not line.lstrip().startswith('#'):
        out.append(f'{key}={value}\n'); done = True
    else:
        out.append(line)
if not done:
    if out and not out[-1].endswith('\n'):
        out[-1] += '\n'
    out.append(f'{key}={value}\n')
path.write_text(''.join(out))
PY
}
is_unset() {
    local v; v="$(env_value "$1")"
    [[ -z "$v" || "$v" == REPLACE_WITH_* || "$v" == /absolute/path/to/* ]]
}

# ── 0. preconditions ─────────────────────────────────────────────────────────
step "Checking prerequisites"
for bin in docker python3 curl openssl jq git sops age-keygen; do
    command -v "$bin" >/dev/null || die "$bin is required but not installed"
done
[[ "$EUID" -eq 0 ]] || die "bootstrap requires root: spotter_compose.sh mounts a ramfs for decrypted secrets. Run from a checkout and HOME accessible to root; the age identity will be under root's HOME unless SOPS_AGE_KEY_FILE is set."
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon (is it running, and are you in the docker group?)"
ok "docker, compose, python3, curl, jq, git, openssl, sops, age-keygen, root"

# ── 1. .env ──────────────────────────────────────────────────────────────────
step "Environment file"
if [[ ! -f "$ENV_FILE" ]] || is_unset AUTH_SECRET; then
    "$ROOT_DIR/deployment/setup-secrets.sh"
else
    ok ".env present with secrets — running setup-secrets.sh to pick up new keys"
    "$ROOT_DIR/deployment/setup-secrets.sh" >/dev/null
fi
FLOWSINT_HOME="$(env_value FLOWSINT_HOME)"
[[ -n "$FLOWSINT_HOME" ]] || die "FLOWSINT_HOME not set in .env"

# ── 2. Flowsint checkout, pinned and patched ─────────────────────────────────
step "Flowsint checkout ($FLOWSINT_HOME)"
# shellcheck disable=SC1091
source "$ROOT_DIR/deployment/flowsint.lock"
if [[ ! -d "$FLOWSINT_HOME/.git" ]]; then
    info "cloning $FLOWSINT_REPO at $FLOWSINT_COMMIT"
    # Default target is $ROOT_DIR/vendor/flowsint, so the parent may not exist
    # yet. vendor/ is gitignored: this is an upstream checkout with its own
    # history, vendored so the whole stack is one copyable directory.
    mkdir -p "$(dirname "$FLOWSINT_HOME")"
    git clone -q "$FLOWSINT_REPO" "$FLOWSINT_HOME"
    git -C "$FLOWSINT_HOME" checkout -q "$FLOWSINT_COMMIT"
    ok "cloned at the pinned commit"
else
    CURRENT="$(git -C "$FLOWSINT_HOME" rev-parse HEAD)"
    if [[ "$CURRENT" == "$FLOWSINT_COMMIT" ]]; then
        ok "already at the pinned commit"
    else
        warn "at $CURRENT, deployment/flowsint.lock pins $FLOWSINT_COMMIT"
        warn "  leaving it alone — the patches below may not apply"
    fi
fi

# Patches are security-relevant, so a failure to apply is a hard stop.
for patch in "$ROOT_DIR"/deployment/flowsint-patches/*.patch; do
    [[ -e "$patch" ]] || continue
    name="$(basename "$patch")"
    if git -C "$FLOWSINT_HOME" apply --check "$patch" >/dev/null 2>&1; then
        git -C "$FLOWSINT_HOME" apply "$patch"
        ok "applied $name"
    elif git -C "$FLOWSINT_HOME" apply --reverse --check "$patch" >/dev/null 2>&1; then
        ok "$name already applied"
    else
        die "$name does not apply and is not already applied. Do not continue:
        these patches close a hole where the Flowsint UI is reachable on the LAN
        without passing the SPOTTER login. Re-check deployment/flowsint.lock."
    fi
done
# setup-secrets.sh links the env file, but only if the checkout already existed.
"$ROOT_DIR/deployment/setup-secrets.sh" >/dev/null

# Chunked browser uploads and EyeWitness screenshots are written by uid 1000
# (the ingest sidecar and the task runner). Docker creates a missing bind
# source as root, and uid 1000 then cannot write it.
step "Host directories written by uid 1000"
for _dir in "$ROOT_DIR/ingest-staging" "$ROOT_DIR/screenshots"; do
    mkdir -p "$_dir"
    chown 1000:1000 "$_dir" || warn "could not chown $_dir to uid 1000 — chunked ingest and screenshot copy will fail until you do"
    chmod 0770 "$_dir" || true
done
ok "ingest-staging and screenshots exist and are owned by uid 1000"

# ── 3. runners image ─────────────────────────────────────────────────────────
step "Task-runner image"
if docker image inspect spotter-n8n-runners:local >/dev/null 2>&1; then
    ok "spotter-n8n-runners:local present (rebuild after editing deployment/Dockerfile.runners)"
else
    info "building — first run takes a few minutes"
    docker build -q -t spotter-n8n-runners:local "$ROOT_DIR/deployment" \
        -f "$ROOT_DIR/deployment/Dockerfile.runners" >/dev/null
    ok "built spotter-n8n-runners:local"
fi

# ── 4. bring the stack up ────────────────────────────────────────────────────
step "Starting the stack"
"$COMPOSE" up -d
ok "compose up completed"

wait_for() {
    local name="$1" url="$2" timeout="${3:-180}" waited=0
    printf '        waiting for %s ' "$name"
    while (( waited < timeout )); do
        if curl -fsS -o /dev/null --max-time 3 "$url" 2>/dev/null; then
            echo " ready"; return 0
        fi
        printf '.'; sleep 3; waited=$((waited + 3))
    done
    echo ""
    return 1
}
wait_for "flowsint-api" "http://127.0.0.1:5001/docs" 240 \
    || die "flowsint-api never became reachable on 127.0.0.1:5001.
        Check: $COMPOSE logs api --tail 50
        A failing neo4j healthcheck stops it starting at all, and the usual cause
        is a NEO4J_PASSWORD that disagrees with the one already in the volume."

# ── 5. SPOTTER portal operator ───────────────────────────────────────────────
# First, because nothing in a browser works without it: the nginx auth_request
# gate covers the dashboard, n8n and the Flowsint UI alike.
step "SPOTTER portal operator"
# `list` always prints a USERNAME header, so count the rows below it rather than
# matching any non-blank line -- otherwise an empty account table reads as "an
# operator already exists" and the dashboard ends up with no way in.
if [[ "$(python3 "$ROOT_DIR/scripts/spotter_user.py" list 2>/dev/null | tail -n +2 | grep -c '[^[:space:]]')" -gt 0 ]]; then
    ok "an operator account already exists"
else
    info "This is the login for the SPOTTER dashboard itself."
    info "Press Enter with no username to create the administrator in the browser wizard."
    read -r -p "        operator username: " SPOTTER_OP
    if [[ -z "$SPOTTER_OP" ]]; then
        ok "no console account — the first browser visit opens administrator setup"
    else
        python3 "$ROOT_DIR/scripts/spotter_user.py" add "$SPOTTER_OP" --admin
        ok "created portal operator '$SPOTTER_OP'"
    fi
fi

# Vendor-key updates from the Admin tab go through this host process. The age
# key stays here; spotter-auth only has the socket. Safe to re-run.
step "Vendor-secret broker"
if python3 "$ROOT_DIR/scripts/spotter_secret_broker.py" --daemon; then
    ok "vendor-secret broker listening on /run/spotter/broker.sock"
else
    warn "vendor-secret broker did not start; portal key updates will fail until it is running"
fi

# ── 6. Flowsint account + API token ──────────────────────────────────────────
step "Flowsint account and API token"
FL_API="http://127.0.0.1:5001"
if is_unset FLOWSINT_API_KEY; then
    read -r -p "        Flowsint account email: " FL_EMAIL
    read -r -s -p "        Flowsint account password: " FL_PASS; echo ""
    [[ -n "$FL_EMAIL" && -n "$FL_PASS" ]] || die "email and password are required"

    code="$(curl -sS -o /tmp/fl_reg.$$ -w '%{http_code}' -X POST "$FL_API/api/auth/register" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg e "$FL_EMAIL" --arg p "$FL_PASS" '{email:$e,password:$p}')")"
    case "$code" in
        201) ok "registered $FL_EMAIL" ;;
        400) ok "$FL_EMAIL already registered — signing in" ;;
        *)   die "registration failed (HTTP $code): $(cat /tmp/fl_reg.$$)" ;;
    esac
    rm -f /tmp/fl_reg.$$

    # NB: /api/auth/token is an OAuth2 password form, not JSON, and the email
    # goes in the field called `username`.
    TOKEN="$(curl -sS -X POST "$FL_API/api/auth/token" \
        --data-urlencode "username=$FL_EMAIL" \
        --data-urlencode "password=$FL_PASS" | jq -r '.access_token // empty')"
    [[ -n "$TOKEN" ]] || die "could not mint a Flowsint token — check the password"
    env_set FLOWSINT_API_KEY "$TOKEN"
    ok "FLOWSINT_API_KEY stored (encrypted tier if configured, else .env)"
    warn "This token EXPIRES (Flowsint's default is about 2.5 days). When the stack"
    warn "  starts answering 401 everywhere at once, that is what happened:"
    warn "  re-run scripts/refresh_flowsint_token.py"
else
    TOKEN="$(env_value FLOWSINT_API_KEY)"
    ok "FLOWSINT_API_KEY already set"
fi

# ── 7. fallback sketch ───────────────────────────────────────────────────────
step "Fallback Flowsint sketch"
if is_unset FLOWSINT_SKETCH_ID; then
    SKETCH="$(FLOWSINT_API_URL="$FL_API" TOKEN="$TOKEN" \
        "$ROOT_DIR/scripts/create_flowsint_investigation_and_sketch.sh" \
        | sed -n 's/^FLOWSINT_SKETCH_ID=//p' | tail -1)"
    [[ -n "$SKETCH" ]] || die "sketch creation did not return an id"
    env_set FLOWSINT_SKETCH_ID "$SKETCH"
    ok "FLOWSINT_SKETCH_ID=$SKETCH"
    info "This is only a FALLBACK for requests that carry no sketch_id."
    info "Each campaign provisions its own sketch; campaign data does not land here."
else
    ok "FLOWSINT_SKETCH_ID already set"
fi

# ── 8. recreate what bakes those values in ───────────────────────────────────
step "Applying the new values"
info "container env is fixed at CREATE time, so these three need recreating"
"$COMPOSE" up -d --no-deps --force-recreate n8n task-runners open-webui
ok "n8n, task-runners and open-webui recreated"

# ── 9. Flowsint custom node types ────────────────────────────────────────────
# Not optional. Without the Company type, the whole sketch's graph endpoint
# answers HTTP 500 the moment WF13 writes its first Company node.
step "Registering Flowsint custom node types"
for t in company nessus pingcastle cloudschism; do
    script="$ROOT_DIR/scripts/register_${t}_type.py"
    [[ -f "$script" ]] || { warn "no register_${t}_type.py — skipped"; continue; }
    if python3 "$script" --apply >/dev/null 2>&1; then
        ok "$t"
    else
        warn "$t registration reported a problem — re-run: python3 $script --apply"
    fi
done

# ── 10. workflows ────────────────────────────────────────────────────────────
# Always through deploy_workflow.sh: it also repairs the publication pointers,
# which a hand-import through the n8n UI does not.
step "Deploying workflows"
"$ROOT_DIR/scripts/deploy_workflow.sh" --all
ok "workflows deployed"

# ── 11. Open WebUI admin ─────────────────────────────────────────────────────
# Open WebUI has no env var that provisions an account; the FIRST account created
# becomes admin. setup_openwebui.py can only consume an account, never create one.
step "Open WebUI admin account"
OWUI="http://127.0.0.1:3000"
wait_for "open-webui" "$OWUI/health" 120 || warn "open-webui not answering yet"
if is_unset OWUI_ADMIN_EMAIL; then
    read -r -p "        Open WebUI admin email: " OW_EMAIL
    read -r -s -p "        Open WebUI admin password: " OW_PASS; echo ""
    code="$(curl -sS -o /tmp/ow.$$ -w '%{http_code}' -X POST "$OWUI/api/v1/auths/signup" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg e "$OW_EMAIL" --arg p "$OW_PASS" \
              '{name:"spotter",email:$e,password:$p}')")"
    if [[ "$code" == "200" ]]; then
        ok "created $OW_EMAIL (first account — it is the admin)"
    else
        warn "signup returned HTTP $code: $(head -c 200 /tmp/ow.$$)"
        warn "  if an account already exists, sign up is refused — that is fine"
    fi
    rm -f /tmp/ow.$$
    # Recorded, not configured: nothing reads these but setup_openwebui.py.
    env_set OWUI_ADMIN_EMAIL "$OW_EMAIL"
    env_set OWUI_ADMIN_PASSWORD "$OW_PASS"
else
    OW_EMAIL="$(env_value OWUI_ADMIN_EMAIL)"; OW_PASS="$(env_value OWUI_ADMIN_PASSWORD)"
    ok "OWUI_ADMIN_EMAIL already recorded"
fi

step "Installing Open WebUI tools"
if python3 "$ROOT_DIR/scripts/setup_openwebui.py" --url "$OWUI" \
        --email "$OW_EMAIL" --password "$OW_PASS" >/dev/null 2>&1; then
    ok "tools and the spotter model profile installed"
else
    warn "setup_openwebui.py failed — usually vLLM is still loading its weights."
    warn "  Watch it with: docker logs -f spotter-vllm"
    warn "  Then re-run:   python3 scripts/setup_openwebui.py --url $OWUI \\"
    warn "                   --email \"\$OWUI_ADMIN_EMAIL\" --password \"\$OWUI_ADMIN_PASSWORD\""
fi

# ── 12. verify ───────────────────────────────────────────────────────────────
step "Preflight"
python3 "$ROOT_DIR/scripts/preflight_env_check.py" --env-file "$ENV_FILE" || \
    warn "preflight reported problems — see above"

echo ""
echo "${BOLD}SPOTTER is up.${RESET}"
echo ""
echo "  The hostnames below are *.localhost, which resolve to 127.0.0.1 on their own"
echo "  in any current browser/OS (RFC 6761) -- no /etc/hosts edit needed."
echo ""
echo "  Dashboard   https://spotter.localhost:5443       (portal login)"
echo "  n8n         https://n8n.spotter.localhost:5443   (same login)"
echo "  Flowsint    https://graph.spotter.localhost:5443 (same login)"
echo "  Open WebUI  https://chat.spotter.localhost:5443  (its own account)"
echo ""
echo "  Trust Caddy's internal CA to stop the browser warning per hostname:"
echo "    docker exec spotter-caddy cat /data/caddy/pki/authorities/local/root.crt"
echo ""
echo "  Verify:  python3 scripts/smoke_deploy.py"
echo "  Docs:    INSTALL.md, then README.md"
