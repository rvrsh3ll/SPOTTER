#!/usr/bin/env bash
# SPOTTER — environment bootstrap.
#
#   deployment/setup-secrets.sh
#
# Creates .env from .env.example, generates every secret that must be unique per
# install, resolves the host-layout paths, and prepares the directories the
# stack bind-mounts. TLS for the Caddy front door (:5443) is self-provisioned
# by Caddy itself on first start (its own internal CA) -- nothing to generate here.
#
# Safe to re-run: it never overwrites a value you have already set. Re-running
# after pulling a new .env.example is how you pick up newly added keys.
#
# WHY IT SEEDS FROM .env.example RATHER THAN LISTING KEYS ITSELF
#
# It used to carry its own list of ~30 keys. .env.example carries ~150 and is
# maintained; the script was not touched for months. The two drifted until the
# script silently omitted N8N_ENCRYPTION_KEY, TUNNEL_API_TOKEN, VLLM_API_KEY and
# every SPOTTER_*_DIR path, and a deployer who ran it got a stack that came up
# and then failed in ways that pointed nowhere near the missing variable.
# .env.example is now the single source of which keys exist. This file only
# decides which of them can be generated.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
EXAMPLE_FILE="$ROOT_DIR/.env.example"

log()  { echo "[setup-secrets] $*"; }
warn() { echo "[setup-secrets] WARN: $*" >&2; }
die()  { echo "[setup-secrets] ERROR: $*" >&2; exit 1; }

[[ -f "$EXAMPLE_FILE" ]] || die "no .env.example at $EXAMPLE_FILE"
command -v openssl >/dev/null || die "openssl not found"
command -v python3 >/dev/null || die "python3 not found"

# ── generators ───────────────────────────────────────────────────────────────
gen_hex()  { openssl rand -hex 32; }
gen_b64()  { python3 -c "import os, base64; print('base64:' + base64.b64encode(os.urandom(32)).decode())"; }
gen_pass() { openssl rand -base64 24 | tr -d '=/+' | head -c 32; }

# ── .env helpers ─────────────────────────────────────────────────────────────
# A value counts as unset if the key is absent, empty, or still a placeholder.
# Everything else is treated as deliberate and is never touched.
env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -1; }
env_has_key() { grep -q "^$1=" "$ENV_FILE" 2>/dev/null; }
# Whether the key appears AT ALL, including commented out. The append path below
# adds placeholder keys in commented form, and env_has_key does not see those --
# so every run re-appended the same three lines under a fresh dated banner, and
# .env grew by a block per bootstrap. Only the append path wants this; fill() and
# needs_value() must keep ignoring commented lines, or a key commented out on
# purpose could never be filled.
env_mentions_key() { grep -qE "^[[:space:]]*#?[[:space:]]*$1=" "$ENV_FILE" 2>/dev/null; }

# A key that is resolvable from an ENCRYPTED TIER must not be regenerated.
#
# This is the sharp edge of moving secrets out of .env. After the split, .env
# carries `# AUTH_SECRET -> secrets/machine.sops.env` where the value used to be,
# so env_value() returns empty and the old needs_value() would have said "unset"
# for every generated secret. On a re-run against a host that already has data,
# fill() would then mint a NEW AUTH_SECRET (the Flowsint JWT signing key) and a
# new MASTER_VAULT_KEY_V1 (the vault key) -- invalidating every issued token and
# making the vault undecryptable. Ask the tiers before concluding anything.
secret_status() {
    [[ -d "$ROOT_DIR/secrets" ]] || { echo missing; return; }
    python3 "$ROOT_DIR/scripts/spotter_env.py" --status "$1" 2>/dev/null || echo missing
}

needs_value() {
    local v; v="$(env_value "$1")"
    if [[ -n "$v" && "$v" != REPLACE_WITH_* && "$v" != /absolute/path/to/* ]]; then
        return 1                      # present in .env; nothing to do
    fi
    [[ "$(secret_status "$1")" != "set" ]]
}

# Rewrite a key in place, preserving its position and the comments above it.
# Uses python rather than sed -i because values contain /, & and other characters
# sed would interpret, and because sed -i replaces the inode -- which would turn
# the FLOWSINT_HOME/.env symlink back into a divergent real file.
set_value() {
    local key="$1" value="$2"
    KEY="$key" VALUE="$value" ENVF="$ENV_FILE" python3 - <<'PY'
import os, pathlib
key, value, path = os.environ['KEY'], os.environ['VALUE'], pathlib.Path(os.environ['ENVF'])
lines = path.read_text().splitlines(keepends=True)
out, done = [], False
for line in lines:
    if not done and line.split('=', 1)[0].strip() == key and not line.lstrip().startswith('#'):
        end = '\n' if line.endswith('\n') else ''
        out.append(f'{key}={value}{end}'); done = True
    else:
        out.append(line)
if not done:
    if out and not out[-1].endswith('\n'):
        out[-1] += '\n'
    out.append(f'{key}={value}\n')
path.write_text(''.join(out))
PY
}

volume_exists() { docker volume inspect "$1" >/dev/null 2>&1; }

# Set only if not already meaningfully set. Returns 0 if it wrote.
fill() {
    local key="$1" value="$2" label="${3:-generated}"
    if needs_value "$key"; then
        set_value "$key" "$value"; log "  $key $label"
    else
        log "  $key already set — keeping"
    fi
}

# ── 1. seed .env from .env.example ───────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    cp "$EXAMPLE_FILE" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    log "created $ENV_FILE from .env.example"
else
    log "$ENV_FILE exists — adding only keys it does not have"
    # A key whose example value is still a placeholder is added COMMENTED OUT.
    # Appending it live would be actively worse than leaving it absent: compose
    # interpolates the literal "REPLACE_WITH_..." string, whereas an absent key
    # falls back to the `:-` default in the compose file. That is the difference
    # between postgres keeping its password and every client suddenly sending
    # "REPLACE_WITH_STRONG_PASSWORD" after the next recreate.
    missing=()
    while IFS= read -r line; do
        [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
        k="${line%%=*}"; v="${line#*=}"
        env_mentions_key "$k" && continue
        case "$v" in
            REPLACE_WITH_*|/absolute/path/to/*) missing+=("# $line") ;;
            *) missing+=("$line") ;;
        esac
    done < "$EXAMPLE_FILE"
    if ((${#missing[@]})); then
        { echo ""
          echo "# ── Added by setup-secrets.sh on $(date -u +%Y-%m-%d) from .env.example ──"
          printf '%s\n' "${missing[@]}"
        } >> "$ENV_FILE"
        log "  added ${#missing[@]} new key(s) from .env.example"
    else
        log "  no new keys"
    fi
fi
echo ""

# ── 2. host layout ───────────────────────────────────────────────────────────
# Derived, not asked for: SPOTTER_HOME is wherever this checkout actually is.
log "--- Host layout ---"
set_value SPOTTER_HOME "$ROOT_DIR"; log "  SPOTTER_HOME=$ROOT_DIR"

FLOWSINT_HOME_VALUE="${FLOWSINT_HOME:-$(env_value FLOWSINT_HOME)}"
case "$FLOWSINT_HOME_VALUE" in
    # Default layout: vendored INSIDE this repo, so the stack is one directory.
    ""|/absolute/path/to/*) FLOWSINT_HOME_VALUE="$ROOT_DIR/vendor/flowsint" ;;
esac
set_value FLOWSINT_HOME "$FLOWSINT_HOME_VALUE"; log "  FLOWSINT_HOME=$FLOWSINT_HOME_VALUE"

# The remaining path vars default from SPOTTER_HOME inside the compose files, so
# these are written for clarity rather than necessity -- but an explicit absolute
# value is what survives someone later launching compose by hand.
log "--- Derived paths ---"
fill SPOTTER_SCRIPTS_DIR     "$ROOT_DIR/scripts"                              "-> $ROOT_DIR/scripts"
fill SPOTTER_ENRICHERS_DIR   "$ROOT_DIR/flowsint-custom/enrichers"            "-> enrichers"
fill SPOTTER_RUNNERS_CONFIG  "$ROOT_DIR/deployment/n8n-task-runners.json"     "-> runner config"
fill SPOTTER_CACHE_HOST_DIR  "$ROOT_DIR/.spotter-cache"                       "-> cache"
fill SPOTTER_SCREENSHOTS_DIR "$ROOT_DIR/screenshots"                          "-> screenshots"
fill SHARPHOUND_DROP_DIR     "$ROOT_DIR/sharphound-drops"                     "-> drop dir"
echo ""

# ── 2b. persistent-state layout — NEW INSTALLS ONLY ──────────────────────────
# Where the databases live. Two supported layouts:
#
#   volumes  the pre-folder layout. Every SPOTTER_*_DATA stays UNSET and each
#            compose entry falls back to the named volume it has always used
#            (${SPOTTER_NEO4J_DATA:-neo4j_data_prod} and friends). The rendered
#            project is byte-identical to what the host already runs.
#   folder   bind mounts under $ROOT_DIR/data, so a cold copy of this directory
#            is the whole system.
#
# A host whose volumes already exist keeps them, and that is not a preference.
# bootstrap.sh runs this script on EVERY run, so writing these values unasked
# would repoint a live Neo4j at an empty directory on the next bootstrap — and
# the failure is silent. Docker creates the missing bind source, Neo4j
# initialises into it, and the operator sees an empty campaign list rather than
# any error at all.
#
# The decision is sticky once recorded, so a host cannot flip layouts underneath
# itself. It is deliberately NOT in .env.example: the append path in §1 would
# then seed it on an existing host, which is the one place it must never appear
# without this check having run.
log "--- Persistent-state layout ---"
LEGACY_VOLUMES=(spotter_neo4j_data_prod spotter_pg_data_prod spotter_n8n_data
                spotter_open_webui_data spotter_spotter_tor_data)
STATE_LAYOUT="$(env_value SPOTTER_STATE_LAYOUT)"

if [[ -n "$STATE_LAYOUT" ]]; then
    log "  SPOTTER_STATE_LAYOUT=$STATE_LAYOUT (already recorded — keeping)"
elif ! command -v docker >/dev/null 2>&1; then
    # Cannot tell whether this host has volumes. Assume it does, which is the
    # conservative answer (leaves every var unset = current behaviour), and do
    # NOT record it, so the next run with docker present decides properly.
    STATE_LAYOUT="volumes"
    warn "docker not on PATH — assuming the existing named-volume layout and not recording it."
    warn "  Re-run this script once docker is available to pick the folder layout."
else
    STATE_LAYOUT="folder"
    for _v in "${LEGACY_VOLUMES[@]}"; do
        if volume_exists "$_v"; then
            STATE_LAYOUT="volumes"
            log "  found existing volume '$_v' — this host stays on named volumes"
            break
        fi
    done
    set_value SPOTTER_STATE_LAYOUT "$STATE_LAYOUT"
    [[ "$STATE_LAYOUT" == "folder" ]] && log "  no pre-existing volumes — using in-folder state under $ROOT_DIR/data"
fi

STATE_DIR="$ROOT_DIR/data"
if [[ "$STATE_LAYOUT" == "folder" ]]; then
    fill SPOTTER_NEO4J_DATA      "$STATE_DIR/neo4j/data"       "-> neo4j store"
    fill SPOTTER_NEO4J_LOGS      "$STATE_DIR/neo4j/logs"       "-> neo4j logs"
    fill SPOTTER_NEO4J_IMPORT    "$STATE_DIR/neo4j/import"     "-> neo4j import"
    fill SPOTTER_NEO4J_PLUGINS   "$STATE_DIR/neo4j/plugins"    "-> neo4j plugins"
    fill SPOTTER_PG_DATA         "$STATE_DIR/postgres"         "-> postgres"
    # Upstream gives redis no volumes: key at all, so this variable has to carry
    # the target as well as the source. Unset it renders as a bare "/data", which
    # is the anonymous volume the image's own VOLUME directive already creates.
    fill SPOTTER_REDIS_DATA      "$STATE_DIR/redis:/data"      "-> redis"
    fill SPOTTER_N8N_DATA        "$STATE_DIR/n8n"              "-> n8n (workflows + credentials)"
    fill SPOTTER_OPEN_WEBUI_DATA "$STATE_DIR/open-webui"       "-> open-webui"
    fill SPOTTER_TOR_DATA        "$STATE_DIR/tor"              "-> tor guard set"
    fill SPOTTER_CADDY_DATA_DIR  "$STATE_DIR/caddy"            "-> caddy internal CA + certs"
else
    log "  leaving every SPOTTER_*_DATA unset — the compose files fall back to the named volumes"
fi
echo ""

# ── 3. secrets that must be unique per install ───────────────────────────────
# NEO4J_PASSWORD and POSTGRES_PASSWORD are INIT-ONLY: the database images apply
# them while initialising an EMPTY data volume and ignore them forever after.
# Generating a fresh one against a volume that already exists does not rotate
# anything -- it just makes every client send a password the database does not
# have, and the stack fails on the next recreate rather than now. So: if the
# volume is already there, refuse to invent a value.
fill_init_only() {
    local key="$1" volume="$2" datadir="$3" value="$4" where=""
    # Under the folder layout there is no volume to find, so the volume check
    # alone would wave through the exact case it exists to prevent: an install
    # whose .env was lost but whose data/postgres survived would get a freshly
    # generated password against an already-initialised database. Same failure,
    # different door.
    datadir="${datadir%%:*}"                       # redis-style "<src>:/data"
    datadir="${datadir//\$\{SPOTTER_HOME\}/$ROOT_DIR}"
    if command -v docker >/dev/null 2>&1 && volume_exists "$volume"; then
        where="the volume '$volume'"
    elif [[ -n "$datadir" && -d "$datadir" && -n "$(ls -A "$datadir" 2>/dev/null)" ]]; then
        where="the data directory '$datadir'"
    fi

    if ! needs_value "$key"; then
        log "  $key already set — keeping"
    elif [[ -n "$where" ]]; then
        warn "$key is unset but $where already exists and holds data."
        warn "  This is an INIT-ONLY secret: the database kept whatever it was first"
        warn "  initialised with, and a value generated now would only lock clients out."
        warn "  Either set $key to the password already in use, or destroy that store"
        warn "  to start clean (which DELETES its data). Leaving it unset."
    else
        set_value "$key" "$value"; log "  $key generated (init-only — applied at first start)"
    fi
}

log "--- Generated secrets ---"
fill AUTH_SECRET         "$(gen_hex)"
fill MASTER_VAULT_KEY_V1 "$(gen_b64)"
fill_init_only NEO4J_PASSWORD    spotter_neo4j_data_prod "$(env_value SPOTTER_NEO4J_DATA)" "$(gen_pass)"
fill_init_only POSTGRES_PASSWORD spotter_pg_data_prod    "$(env_value SPOTTER_PG_DATA)"    "$(gen_pass)"
fill N8N_USER            "admin"        "defaulted to admin"
fill N8N_PASSWORD        "$(gen_pass)"
fill N8N_ENCRYPTION_KEY  "$(gen_hex)"
fill WEBUI_SECRET_KEY    "$(gen_hex)"
fill VLLM_API_KEY        "$(gen_hex)"
# Only if the key is actually present: it ships commented out, because real
# embeddings need EMBEDDING_URL set as well and the default is deliberately the
# pure-Python TF-IDF fallback. Appending it unasked would put an orphan key at the
# end of the file, far from the block that explains it.
if env_has_key EMBEDDING_API_KEY; then
    fill EMBEDDING_API_KEY "$(env_value VLLM_API_KEY)" "matched to VLLM_API_KEY"
fi
fill TUNNEL_API_TOKEN    "$(gen_hex)"
echo ""

# ── 4. directories the stack bind-mounts ─────────────────────────────────────
# Docker creates a missing bind source as an empty root-owned directory, which
# then silently fails to be writable by the runner (uid 1000). Create them here
# with the right ownership instead.
RUNNER_GID="$(env_value SPOTTER_RUNNER_GID)"; RUNNER_GID="${RUNNER_GID:-1000}"

ensure_shared_dir() {
    local path="$1"
    mkdir -p "$path"
    if chown "0:${RUNNER_GID}" "$path" 2>/dev/null; then
        chmod g+rwx,g+s "$path"
    else
        warn "could not chown $path to gid $RUNNER_GID; ensure it is group-writable by the runner"
        chmod g+rwx,g+s "$path" 2>/dev/null || true
    fi
    log "  $path"
}

log "--- Shared directories ---"
ensure_shared_dir "$(env_value SPOTTER_CACHE_HOST_DIR)"
ensure_shared_dir "$(env_value SPOTTER_SCREENSHOTS_DIR)"
ensure_shared_dir "$(env_value SHARPHOUND_DROP_DIR)"
mkdir -p "$ROOT_DIR/deployment/auth-data"; log "  $ROOT_DIR/deployment/auth-data"
# The tunnel key root is NOT a shared directory: it holds private keys, so it is
# 0700 root-only, not group-writable like the others. ssh-tunnel-api runs as
# root and is the only thing that reads it.
TUNNEL_KEYS_DIR="$(env_value SPOTTER_TUNNEL_KEYS_DIR)"
TUNNEL_KEYS_DIR="${TUNNEL_KEYS_DIR:-$ROOT_DIR/tunnel-keys}"
# The seeded value is literal "${SPOTTER_HOME}/tunnel-keys" -- compose expands
# that, but this shell must too before it can create the directory.
TUNNEL_KEYS_DIR="${TUNNEL_KEYS_DIR//\$\{SPOTTER_HOME\}/$ROOT_DIR}"
mkdir -p "$TUNNEL_KEYS_DIR"; chmod 700 "$TUNNEL_KEYS_DIR"; log "  $TUNNEL_KEYS_DIR (0700)"
echo ""

# ── 4b. persistent-state bind sources ────────────────────────────────────────
# Deliberately NOT ensure_shared_dir. That helper sets 0:$RUNNER_GID with
# g+rwx,g+s, which is right for a cache the task runner writes and actively
# wrong for a database -- it would make the graph store group-writable by every
# Code node. Each of these is owned by exactly one container's uid and nothing
# else may write it.
#
# The uids are the images' own, confirmed against the live volumes rather than
# assumed: neo4j 7474, postgres 70 (the ALPINE image; the debian one is 999),
# redis 999:1000, n8n 1000, open-webui root, tor root (the sidecar runs as root
# and chowns to debian-tor itself at every start).
#
# neo4j/postgres/redis entrypoints all self-heal ownership when they start as
# root. n8n does NOT -- its container user is `node` and never root -- so
# data/n8n is the one directory that MUST be correct before the first start.
ensure_state_dir() {
    local path="$1" owner="$2" mode="$3"
    path="${path%%:*}"                             # redis-style "<src>:/data"
    path="${path//\$\{SPOTTER_HOME\}/$ROOT_DIR}"
    [[ -n "$path" ]] || return 0                   # unset => named volume; nothing to create
    mkdir -p "$path"
    chown "$owner" "$path" 2>/dev/null \
        || warn "could not chown $path to $owner — run as root, or $1's container will not start"
    chmod "$mode" "$path"
    log "  $path ($owner $mode)"
}

if [[ "$STATE_LAYOUT" == "folder" ]]; then
    log "--- State directories ---"
    ensure_state_dir "$(env_value SPOTTER_NEO4J_DATA)"      7474:7474 0755
    ensure_state_dir "$(env_value SPOTTER_NEO4J_LOGS)"      7474:7474 0755
    ensure_state_dir "$(env_value SPOTTER_NEO4J_IMPORT)"    7474:7474 0700
    ensure_state_dir "$(env_value SPOTTER_NEO4J_PLUGINS)"   7474:7474 0755
    ensure_state_dir "$(env_value SPOTTER_PG_DATA)"         70:70     0700
    ensure_state_dir "$(env_value SPOTTER_REDIS_DATA)"      999:1000  0755
    ensure_state_dir "$(env_value SPOTTER_N8N_DATA)"        1000:1000 0755
    ensure_state_dir "$(env_value SPOTTER_OPEN_WEBUI_DATA)" 0:0       0755
    ensure_state_dir "$(env_value SPOTTER_TOR_DATA)"        0:0       0700
    # Caddy's own entrypoint runs as root and fixes ownership of /data itself.
    ensure_state_dir "$(env_value SPOTTER_CADDY_DATA_DIR)"  0:0       0700
    echo ""
fi

# ── 5. one env file, not five ────────────────────────────────────────────────
# Compose reads the env file from the PROJECT directory -- the dirname of the
# first -f, i.e. the Flowsint checkout. This used to be handled by copying .env
# into four places; the copies drifted, and two secrets sat empty in the live
# containers for a week because a var added here never reached the copy. A
# symlink makes that impossible. Note `sed -i` on either path replaces the inode
# and quietly breaks the link again -- scripts/preflight_env_check.py checks for
# exactly that.
log "--- Compose env file ---"
if [[ -d "$FLOWSINT_HOME_VALUE" ]]; then
    TARGET="$FLOWSINT_HOME_VALUE/.env"
    if [[ -L "$TARGET" && "$(readlink -f "$TARGET")" == "$(readlink -f "$ENV_FILE")" ]]; then
        log "  $TARGET -> $ENV_FILE (already linked)"
    else
        if [[ -e "$TARGET" ]]; then
            BACKUP="$TARGET.bak-$(date -u +%Y%m%d%H%M%S)"
            mv "$TARGET" "$BACKUP"
            warn "existing $TARGET moved to $BACKUP — it may hold values this one does not"
        fi
        ln -s "$ENV_FILE" "$TARGET"
        log "  linked $TARGET -> $ENV_FILE"
    fi
else
    warn "$FLOWSINT_HOME_VALUE does not exist yet — clone Flowsint, then re-run this script"
fi

# ── move the generated secrets into the encrypted tiers ──────────────────────
#
# Everything above writes to $ENV_FILE, including ~10 machine-tier credentials.
# That is deliberate and is NOT worth changing: the needs_value/fill_init_only
# logic here is careful -- fill_init_only refuses to regenerate NEO4J_PASSWORD or
# POSTGRES_PASSWORD against a database volume that already has data, which is
# what stops an operator locking themselves out of live client data. Teaching all
# of that to speak sops would put that guard at risk for no gain.
#
# So generate into .env as before, then hand the result to the splitter, which
# owns the classification. Without this step a fresh host finishes bootstrap with
# every credential in plaintext -- the exact layout this arrangement removes.
if command -v sops >/dev/null 2>&1 && command -v age-keygen >/dev/null 2>&1; then
    echo ""
    log "Encrypting secrets into secrets/*.sops.env"

    AGE_KEY_FILE="${SOPS_AGE_KEY_FILE:-$HOME/.config/sops/age/keys.txt}"
    if [[ ! -f "$AGE_KEY_FILE" ]]; then
        mkdir -p "$(dirname "$AGE_KEY_FILE")"
        chmod 700 "$(dirname "$AGE_KEY_FILE")" 2>/dev/null || true
        age-keygen -o "$AGE_KEY_FILE" >/dev/null 2>&1
        chmod 600 "$AGE_KEY_FILE"
        log "  new age identity: $AGE_KEY_FILE"
        log "  BACK THIS UP SEPARATELY. Without it the tiers cannot be decrypted,"
        log "  and a backup holding both it and the tiers protects nothing."
    else
        log "  using the existing age identity at $AGE_KEY_FILE"
    fi

    if [[ ! -f "$ROOT_DIR/.sops.yaml" ]]; then
        RECIPIENT="$(age-keygen -y "$AGE_KEY_FILE")"
        cat > "$ROOT_DIR/.sops.yaml" <<SOPSEOF
# Which age recipients may decrypt each secret tier. Public keys only -- safe to
# commit. Add a teammate by appending their public key to the relevant list and
# running: sops updatekeys secrets/<file>.sops.env
# Values are re-wrapped to the new recipient set and none of them change, so
# nothing has to be rotated just because the roster moved.
creation_rules:
  # Generated per host; never shared between installs.
  - path_regex: secrets/machine\.sops\.env\$
    key_groups:
      - age:
          - $RECIPIENT

    # Optional third-party API keys. This tier is local to the install and is not
    # tracked; each host uses its own age recipient configuration.
  - path_regex: secrets/vendors\.sops\.env\$
    key_groups:
      - age:
          - $RECIPIENT

  # Reaches live operator infrastructure. Narrowest tier, shortest life.
  - path_regex: secrets/engagement\.sops\.env\$
    key_groups:
      - age:
          - $RECIPIENT
SOPSEOF
        log "  wrote $ROOT_DIR/.sops.yaml"
    fi

    python3 "$ROOT_DIR/scripts/split_env_to_sops.py" --merge --no-backup || \
        warn "could not encrypt the secrets -- they are still PLAINTEXT in $ENV_FILE"
else
    echo ""
    warn "sops and/or age are not installed, so the generated credentials are"
    warn "sitting in $ENV_FILE as PLAINTEXT. Install them and run:"
    warn "    scripts/split_env_to_sops.py --merge"
    warn "See README.md -- Generate secrets."
fi

echo ""
log "Done. Review $ENV_FILE, then:"
log ""
log "  scripts/bootstrap.sh"
log ""
log "which brings the stack up and creates the accounts in the order they depend"
log "on each other. See INSTALL.md for what it does and how to do it by hand."
log ""
log "Values it CANNOT generate, because they come from outside this host."
log "Add each with:  scripts/spotter_secret.py set <KEY>   (prompts; never echoes)"
log "  FLARE_API_KEY, SHODAN_API_KEY, FOFA_API_KEY, SERP_API_KEY,"
log "  TAVILY_API_KEY, GRAYHATWARFARE_API_KEY,"
log "  NVD_API_KEY                           — optional; each disables one feature"
log "  CS_API_TOKEN, ADAPTIX_*               — optional; C2 ingest only"
log "FLOWSINT_API_KEY and FLOWSINT_SKETCH_ID are obtained by the bootstrap, not here."
log ""
log "Credentials live ENCRYPTED in secrets/*.sops.env, never in $ENV_FILE. Review"
log "the configuration in $ENV_FILE; check the credentials with:"
log "  scripts/spotter_secret.py list"
