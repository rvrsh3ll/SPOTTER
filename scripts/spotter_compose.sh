#!/usr/bin/env bash
# SPOTTER — the one correct way to invoke docker compose against this stack.
#
#   scripts/spotter_compose.sh ps
#   scripts/spotter_compose.sh up -d
#   scripts/spotter_compose.sh up -d --no-deps --force-recreate n8n
#   scripts/spotter_compose.sh config
#
# Everything after the script name is passed straight to `docker compose`.
#
# WHY THIS EXISTS
#
# The stack is a multi-file compose invocation whose FIRST -f belongs to a
# different repository (Flowsint). Three things follow from that, and each one
# has cost real time on this project:
#
#   1. Compose sets the project working directory to the dirname of the first
#      -f file — the Flowsint checkout, NOT this repo. Every relative path in
#      deployment/*.yml therefore resolved one directory too high. That silently
#      mounted an empty dir over the enrichers for ~3 weeks (registry stuck at
#      50), and later mounted a STALE n8n-task-runners.json that enforced an
#      older import allowlist, so code nodes died on modules this repo
#      allowlists. Every such path is absolute now, derived from SPOTTER_HOME.
#
#   2. `-p spotter` is not optional. Without it compose derives the project name
#      from the working directory, finds nothing running under that name, and
#      `restart` exits 0 having restarted NOTHING. The exit code does not tell
#      you; `docker ps` showing an uptime in days rather than seconds does.
#
#   3. `--project-directory` is deliberately NOT passed. Compose's project
#      directory is therefore the dirname of the first -f, i.e. vendor/flowsint
#      — which is exactly where Flowsint's own `./flowsint-app/nginx.conf` has
#      to resolve. Passing it would point that at $SPOTTER_HOME/flowsint-app/,
#      which does not exist; Docker would CREATE it as a directory and nginx
#      would die with "is a directory". Do not add it "for tidiness".
#      The corollary is the guard below: a RELATIVE *_DIR override resolves
#      against vendor/flowsint, and upstream ships its own sharphound-drops/,
#      so a relative value lands somewhere real and wrong instead of failing.
#
# SPOTTER_HOME is derived from this script's own location, so it is right even
# when .env is wrong, and exported so compose interpolation sees it either way.
set -euo pipefail

SPOTTER_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SPOTTER_HOME

ENV_FILE="$SPOTTER_HOME/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    echo "spotter_compose: no .env at $ENV_FILE — run deployment/setup-secrets.sh first" >&2
    exit 1
fi

# .env is NOT shell-sourceable: EDGAR_USER_AGENT carries unquoted parens, which
# makes `set -a; . .env` die with a syntax error. Read the one key we need.
read_env() {
    local key="$1"
    sed -n "s/^${key}=//p" "$ENV_FILE" | tail -1
}

# --- secrets: decrypt the SOPS tiers and merge them with the plaintext config --
#
# .env holds configuration only; the credentials live in secrets/*.sops.env,
# encrypted to the age recipients listed in .sops.yaml. Compose cannot read those,
# so they are merged into one file here for the life of THIS command.
#
# That window is genuinely short: compose reads --env-file at CLI parse time and
# interpolates the values into the container config at create time, so the file is
# not needed once the command returns.
#
# The merge target is a ramfs, not /run or /dev/shm. Both of those are tmpfs, whose
# pages CAN be written to swap -- and this host swaps (8 GB, in use). ramfs has no
# backing store, so the plaintext cannot reach the disk even under memory pressure.
#
# Process substitution was tried first and is NOT safe here: `--env-file <(...)`
# makes compose read every value as the empty string, silently, which would start
# the whole stack with blank credentials.
SECRETS_DIR="$SPOTTER_HOME/secrets"
MERGED_ENV=""
_RAMFS_MNT="/run/spotter-secrets"
_WE_MOUNTED=0

_cleanup_merged() {
    [[ -n "$MERGED_ENV" && -e "$MERGED_ENV" ]] && rm -f "$MERGED_ENV"
    # Only tear the mount down if we put it up AND nobody else is using it, so
    # two overlapping invocations cannot pull it out from under each other.
    if [[ "$_WE_MOUNTED" == "1" ]] && mountpoint -q "$_RAMFS_MNT" 2>/dev/null; then
        if [[ -z "$(ls -A "$_RAMFS_MNT" 2>/dev/null)" ]]; then
            umount "$_RAMFS_MNT" 2>/dev/null || true
            rmdir "$_RAMFS_MNT" 2>/dev/null || true
        fi
    fi
}

shopt -s nullglob
_TIERS=( "$SECRETS_DIR"/*.sops.env )
shopt -u nullglob

if (( ${#_TIERS[@]} > 0 )); then
    if ! command -v sops >/dev/null 2>&1; then
        echo "spotter_compose: secrets/ holds encrypted tiers but sops is not installed." >&2
        echo "  see README.md -- Generate secrets" >&2
        exit 1
    fi
    trap _cleanup_merged EXIT INT TERM
    mkdir -p "$_RAMFS_MNT"
    if ! mountpoint -q "$_RAMFS_MNT" 2>/dev/null; then
        if ! mount -t ramfs ramfs "$_RAMFS_MNT" 2>/dev/null; then
            echo "spotter_compose: could not mount ramfs at $_RAMFS_MNT (need root)." >&2
            exit 1
        fi
        _WE_MOUNTED=1
    fi
    chmod 700 "$_RAMFS_MNT"
    MERGED_ENV="$_RAMFS_MNT/env.$$"
    ( umask 077; : > "$MERGED_ENV" )
    cat "$ENV_FILE" > "$MERGED_ENV"
    for _t in "${_TIERS[@]}"; do
        printf '\n# --- %s ---\n' "$(basename "$_t")" >> "$MERGED_ENV"
        if ! sops --decrypt --input-type dotenv --output-type dotenv "$_t" >> "$MERGED_ENV"; then
            echo "spotter_compose: could not decrypt $_t." >&2
            echo "  The age identity is read from SOPS_AGE_KEY_FILE, or" >&2
            echo "  \$HOME/.config/sops/age/keys.txt by default." >&2
            exit 1
        fi
    done
    # Everything downstream -- read_env, the guards, --env-file -- now sees the
    # merged view, so no other line in this script has to know secrets moved.
    ENV_FILE="$MERGED_ENV"
fi

# A relative *_DIR value does NOT resolve against this repo. Compose resolves it
# against the project directory, which is vendor/flowsint (see 3. above) — and
# upstream Flowsint ships its own sharphound-drops/, so a relative value lands in
# a real, wrong, gitignored directory rather than failing. That is how the
# enrichers sat behind an empty mount for ~3 weeks. Refuse to launch instead.
# The persistent-state mounts. UNSET is the pre-folder layout and is fully
# supported: each compose entry falls back to the named volume it has always
# used (${SPOTTER_NEO4J_DATA:-neo4j_data_prod} and friends), so a host installed
# before the folder layout is untouched by everything below. SET means a bind
# mount inside the checkout, which is what makes a tar of SPOTTER_HOME complete.
SPOTTER_STATE_VARS="SPOTTER_NEO4J_DATA SPOTTER_NEO4J_LOGS SPOTTER_NEO4J_IMPORT \
SPOTTER_NEO4J_PLUGINS SPOTTER_PG_DATA SPOTTER_REDIS_DATA SPOTTER_N8N_DATA \
SPOTTER_OPEN_WEBUI_DATA SPOTTER_TOR_DATA SPOTTER_CADDY_DATA_DIR"

# Expand only the forms the documented values actually use. Deliberately NOT
# `eval`: .env is not shell-sourceable (EDGAR_USER_AGENT carries unquoted parens),
# which is why read_env greps single keys in the first place.
_expand_path() {
    local _p="$1"
    _p="${_p//\$\{SPOTTER_HOME\}/$SPOTTER_HOME}"
    _p="${_p//\$SPOTTER_HOME/$SPOTTER_HOME}"
    _p="${_p/#\~/$HOME}"
    printf '%s' "$_p"
}

_rel_offenders=""
for _k in SPOTTER_SCRIPTS_DIR SPOTTER_ENRICHERS_DIR SPOTTER_RUNNERS_CONFIG \
          SPOTTER_CACHE_HOST_DIR SPOTTER_SCREENSHOTS_DIR SPOTTER_INGEST_STAGING_DIR \
          SHARPHOUND_DROP_DIR \
          SSH_KEY_DIR SPOTTER_TUNNEL_KEYS_DIR $SPOTTER_STATE_VARS; do
    _v="$(read_env "$_k")"
    # SPOTTER_REDIS_DATA carries "<source>:/data" because upstream gives redis no
    # volumes: key at all and the target has to come from here. Everything else is
    # a bare source. Judge the part before the first colon either way.
    _v="${_v%%:*}"
    # ${...} and ~ are expanded by compose/the shell later, so only a value that
    # starts with a literal path segment is a real offender.
    case "$_v" in
        ""|/*|'${'*|'~'*) ;;
        *) _rel_offenders="$_rel_offenders
  $_k=$_v   ->  would resolve to \$FLOWSINT_HOME/$_v" ;;
    esac
done
if [[ -n "$_rel_offenders" ]]; then
    cat >&2 <<EOF
spotter_compose: refusing to start — these .env paths are relative:
$_rel_offenders

Compose resolves them against the project directory (the Flowsint checkout), not
this repo, and Docker CREATES a missing bind source rather than erroring. Make
them absolute; \${SPOTTER_HOME}/... is the intended form.
EOF
    exit 1
fi

# A state mount that IS set must already exist. For every other bind source a
# missing directory is merely an empty mount; for these it is a database that
# comes up EMPTY and reports no error at all -- an empty campaign list, not a
# failed start. deployment/setup-secrets.sh creates them with the right owner.
_missing_state=""
for _k in $SPOTTER_STATE_VARS; do
    _v="$(read_env "$_k")"
    [[ -n "$_v" ]] || continue              # unset => named volume; nothing to check
    _src="$(_expand_path "${_v%%:*}")"
    case "$_src" in /*) ;; *) continue ;; esac   # non-absolute already refused above
    [[ -d "$_src" ]] || _missing_state="$_missing_state
  $_k  ->  $_src"
done
if [[ -n "$_missing_state" ]]; then
    cat >&2 <<EOF
spotter_compose: refusing to start — these state directories do not exist:
$_missing_state

Docker would CREATE each one as an empty root-owned directory and the database
would initialise into it, silently, with no error and no data. Run
  deployment/setup-secrets.sh
to create them with the ownership each service needs, or unset the variable to
go back to the named volume.
EOF
    exit 1
fi

FLOWSINT_HOME="${FLOWSINT_HOME:-$(read_env FLOWSINT_HOME)}"
# Default layout: the Flowsint checkout lives INSIDE this one, at vendor/flowsint,
# so the whole stack is a single copyable directory. scripts/bootstrap.sh clones it
# there at deployment/flowsint.lock's pinned commit. An explicit FLOWSINT_HOME in
# .env still wins, so a pre-existing sibling checkout keeps working untouched.
FLOWSINT_HOME="${FLOWSINT_HOME:-$SPOTTER_HOME/vendor/flowsint}"
export FLOWSINT_HOME

FLOWSINT_COMPOSE="$FLOWSINT_HOME/docker-compose.prod.yml"
if [[ ! -f "$FLOWSINT_COMPOSE" ]]; then
    cat >&2 <<EOF
spotter_compose: Flowsint compose file not found at
  $FLOWSINT_COMPOSE

SPOTTER does not define the data tier — Neo4j, Postgres, Redis, flowsint-api and
the Flowsint UI all live in that separate repository, and this stack includes its
compose file rather than duplicating it. Run scripts/bootstrap.sh, which clones
it to vendor/flowsint at the commit pinned in deployment/flowsint.lock and applies
the patches this repo carries — or set FLOWSINT_HOME in .env to an existing checkout.
EOF
    exit 1
fi

# ── LLM tier ─────────────────────────────────────────────────────────────────
# SPOTTER_LLM_TIER selects which model backend is part of the stack:
#
#   local-large  the 27B on a ~49 GB card (the original, and the default)
#   local-small  a smaller model for a single consumer GPU
#   remote       no local server; VLLM_URL points at someone else's endpoint
#   none         no model at all; analysis workflows and the Prompt tab say so
#
# The first two start the `vllm` service (compose profile llm-local); the last two
# do not, which is what makes a GPU-less host work at all.
PROFILE_ARGS=()
LLM_TIER="${SPOTTER_LLM_TIER:-$(read_env SPOTTER_LLM_TIER)}"
LLM_TIER="${LLM_TIER:-local-large}"
case "$LLM_TIER" in
    local-large|local-small) PROFILE_ARGS+=(--profile llm-local) ;;
    remote|none)             ;;
    *) echo "spotter_compose: unknown SPOTTER_LLM_TIER '$LLM_TIER'" >&2
       echo "  expected one of: local-large, local-small, remote, none" >&2
       exit 1 ;;
esac

# The embedding server is a separate opt-in: without it, the RAG index silently
# falls back to a pure-Python TF-IDF vectoriser rather than real embeddings.
if [[ "$(read_env VLLM_EMBEDDING_MODE)" == "remote" ]]; then
    PROFILE_ARGS+=(--profile embed)
fi

# A required secret that arrives EMPTY is the quietest failure this stack has.
# Compose substitutes an unset variable with the empty string and only warns, so
# the stack starts, the container holds "", and the fault surfaces far away as a
# 401 from a sidecar or an empty panel. The values below used to be backstopped
# by literal defaults in the compose files (VLLM_API_KEY defaulted to a string
# published in this repo), which is worse: the stack works, authenticated by a
# credential anyone can read.
#
# Scoped to the subcommands that actually interpolate values into new containers.
# `down`, `ps`, `logs` and `config` must keep working when a secret is missing,
# or a half-configured stack could not even be torn down or diagnosed.
_subcommand=""
for _a in "$@"; do
    case "$_a" in -*) ;; *) _subcommand="$_a"; break ;; esac
done
case "$_subcommand" in
    up|create|run)
        _required="AUTH_SECRET MASTER_VAULT_KEY_V1 NEO4J_PASSWORD N8N_ENCRYPTION_KEY
                   WEBUI_SECRET_KEY TUNNEL_API_TOKEN FLOWSINT_API_KEY"
        # Only meaningful when an LLM tier is actually being started.
        [[ "$LLM_TIER" != "none" ]] && _required="$_required VLLM_API_KEY"
        # Deliberately NOT required: POSTGRES_PASSWORD and NEO4J_PASSWORD are
        # init-only, and deployment/setup-secrets.sh leaves POSTGRES_PASSWORD
        # unset on a host whose database volume already exists rather than
        # locking the operator out of live data. Demanding it here would refuse
        # to start exactly those hosts. NEO4J_PASSWORD is listed because clients
        # authenticate with it on every query, not just at init.
        _missing_secrets=""
        for _k in $_required; do
            [[ -n "$(read_env "$_k")" ]] || _missing_secrets="$_missing_secrets
  $_k"
        done
        if [[ -n "$_missing_secrets" ]]; then
            cat >&2 <<EOF
spotter_compose: refusing to start — these secrets are empty in .env:
$_missing_secrets

Compose would substitute an empty string and start anyway, leaving the fault to
surface later as an auth error from an unrelated service. Run
  deployment/setup-secrets.sh
to generate the machine-local ones, or paste the third-party keys in by hand.
EOF
            exit 1
        fi

        # A credential sitting in .env as plaintext is the failure this whole
        # arrangement exists to prevent, and .env is gitignored so the commit
        # guards structurally cannot see it. Refuse the launch rather than start
        # a stack whose secrets are half encrypted and half not.
        #
        # Same scope rule as above: `up|create|run` only. A half-configured stack
        # must still be stoppable and inspectable.
        if [[ -x "$SPOTTER_HOME/scripts/spotter_secret.py" ]]; then
            if ! _audit_out="$(python3 "$SPOTTER_HOME/scripts/spotter_secret.py" audit 2>&1)"; then
                echo "spotter_compose: refusing to start — plaintext credentials in .env" >&2
                echo "" >&2
                printf '%s\n' "$_audit_out" >&2
                exit 1
            fi
        fi
        ;;
esac

# The Admin tab's vendor-key forms go spotter-auth -> /run/spotter/broker.sock ->
# a HOST process that compose knows nothing about. Before this, only bootstrap.sh
# started it, so a host that pulled the portal and relaunched here got a new
# spotter-auth with nothing behind the socket: "secret broker is not running" and
# no key forms at all. Idempotent (a live broker is left alone), and a warning
# rather than a refusal because nothing else in the stack depends on it.
#
# /run is tmpfs. After a reboot Docker restarts the containers without this
# script, so the broker stays down until the next `up` here.
case "$_subcommand" in
    up|create|run|start|restart)
        if ! python3 "$SPOTTER_HOME/scripts/spotter_secret_broker.py" --daemon >/dev/null; then
            echo "spotter_compose: warning — the vendor-secret broker did not start;" >&2
            echo "  Admin-tab key updates will fail. Run it in the foreground to see why:" >&2
            echo "  python3 scripts/spotter_secret_broker.py" >&2
        fi
        ;;
esac

# NOT `exec`: exec replaces this shell, so the EXIT trap would never run and the
# decrypted env file would outlive the command it was made for.
_rc=0
docker compose \
    -p spotter \
    "${PROFILE_ARGS[@]}" \
    --env-file "$ENV_FILE" \
    -f "$FLOWSINT_COMPOSE" \
    -f "$SPOTTER_HOME/deployment/docker-compose.n8n.yml" \
    -f "$SPOTTER_HOME/deployment/docker-compose.llm.yml" \
    -f "$SPOTTER_HOME/deployment/docker-compose.flowsint.yml" \
    -f "$SPOTTER_HOME/deployment/docker-compose.frontend.yml" \
    -f "$SPOTTER_HOME/deployment/docker-compose.caddy.yml" \
    "$@" || _rc=$?

_cleanup_merged
trap - EXIT INT TERM
exit "$_rc"
