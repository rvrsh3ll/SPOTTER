#!/usr/bin/env bash
# SPOTTER — migration BACKUP (run on the SOURCE host)
#
# Snapshots everything the running SPOTTER stack keeps state in, so the whole
# system can be cloned onto another host.
#
# Companion: migrate-restore.sh (run on the TARGET host).
#
# ── Why discovery goes through `spotter_compose.sh config` ───────────────────
# This script used to find volumes with
#     docker volume ls --filter label=com.docker.compose.project=spotter
# and that silently lost almost everything. Compose only labels a volume when it
# CREATES it, and the volumes that matter here predate the current `-p spotter`
# project name, so they carry no labels at all:
#
#     spotter_neo4j_data_prod    labels=null     <- the graph
#     spotter_n8n_data           labels=null     <- every workflow AND credential
#     spotter_pg_data_prod       labels=null
#     spotter_open_webui_data    labels=null
#     spotter_neo4j_plugins_prod labels=null
#     spotter_vllm_model_cache   labels=null
#
# The label filter matched four volumes, two of which this script's own skip
# rules then dropped, and one of which (spotter_spotter_cache) was removed from
# the compose files in August. A backup run archived two dead caches, printed
# "Done.", and exited 0. migrate-restore.sh then printed "All volumes restored."
#
# The rendered compose project cannot drift from the compose files the stack is
# actually launched with, and its top-level `volumes:` map carries each volume's
# REAL name (`spotter_`-prefixed) already resolved. It also lists every bind
# mount, which is how the in-folder state below gets captured — the previous
# version of this script never touched any of it.
#
# It must go through scripts/spotter_compose.sh rather than a bare
# `docker compose`, so the project name, --env-file, the profile flags and the
# absolute -f list all match what `up` actually uses.
#
# ── What still travels separately ───────────────────────────────────────────
#   - the repo itself (compose files, scripts, workflows, enrichers)  -> git/rsync
#   - your .env (host paths, config only)                             -> copy by hand
#   - secrets/*.sops.env (already encrypted at rest)                  -> copy as-is
#   - the age identity that decrypts them                             -> NEVER in a backup
#   - the runners image + sidecar images                              -> rebuilt on target
#   - browser localStorage (campaign annotations, analysis history)   -> per-operator
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="spotter"
OUTDIR=""
HOT=0
INCLUDE_MODELS=0
LIST_ONLY=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [-p PROJECT] [-o OUTDIR] [--hot] [--include-models] [--list]

Backs up the live state of compose project PROJECT (default: spotter) into
OUTDIR as .tar.gz files, plus a MANIFEST.txt that migrate-restore.sh reads.

Two kinds of thing are archived, both discovered from the rendered compose
project rather than guessed:
  * named Docker volumes        -> neo4j, postgres, n8n, open-webui, tor, ...
  * read-write bind mounts that live inside the checkout
                                -> auth-data, screenshots, sharphound-drops,
                                   .spotter-cache, tunnel-keys, caddy TLS state

By default the whole project is STOPPED for a consistent (cold) snapshot and
restarted afterwards. This causes a brief outage but guarantees the database
copies are not mid-write. A tar of a live Neo4j store or an open
database.sqlite-wal is not a backup.

Options:
  -p PROJECT        compose project name            (default: spotter)
  -o OUTDIR         output directory                (default: ./spotter-migration)
  --hot             do NOT stop containers first    (faster; DB copy may be inconsistent)
  --include-models  also archive the vLLM model cache (~32 GB, re-downloadable)
  --list            print what WOULD be archived and exit; touches nothing, stops
                    nothing. Run this first — it is the only way to see that the
                    backup covers what you think it does.
  -h, --help        show this help

Always skipped: the neo4j logs/import scratch volumes, anonymous volumes, and
read-only code mounts (scripts/, frontend/, enrichers/) which travel with the
repo. The vLLM model cache is skipped unless --include-models is given.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p) PROJECT="${2:?}"; shift 2;;
    -o) OUTDIR="${2:?}"; shift 2;;
    --hot) HOT=1; shift;;
    --include-models) INCLUDE_MODELS=1; shift;;
    --list) LIST_ONLY=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 1;;
  esac
done

OUTDIR="${OUTDIR:-$PWD/spotter-migration}"
log(){ echo "[migrate-backup] $*"; }
die(){ echo "[migrate-backup] ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"
[[ -x "$REPO_ROOT/scripts/spotter_compose.sh" ]] \
  || die "scripts/spotter_compose.sh not found or not executable under $REPO_ROOT"

# ── discover from the rendered compose project ────────────────────────────────
# Emits one TSV record per line:  volume<TAB><real name>
#                                 bind<TAB><abs source><TAB><path relative to repo>
log "Reading the rendered compose project ..."
# Via a temp file, not a pipe: the python program below arrives on stdin as a
# heredoc, so stdin is not available to carry the JSON as well.
RENDERED_JSON="$(mktemp -t spotter-rendered.XXXXXX.json)"
DISCOVERED="$(mktemp -t spotter-discovered.XXXXXX)"
cleanup_rendered() { rm -f "$RENDERED_JSON" "$DISCOVERED"; }
trap cleanup_rendered EXIT
"$REPO_ROOT/scripts/spotter_compose.sh" config --format json >"$RENDERED_JSON" 2>/dev/null \
  || die "'spotter_compose.sh config' failed — fix the stack config before backing it up"

if ! INCLUDE_MODELS="$INCLUDE_MODELS" REPO_ROOT="$REPO_ROOT" \
  RENDERED_JSON="$RENDERED_JSON" python3 - >"$DISCOVERED" <<'PY'
import json, os, sys

with open(os.environ["RENDERED_JSON"], encoding="utf-8") as fh:
    doc = json.load(fh)
repo = os.path.realpath(os.environ["REPO_ROOT"])
include_models = os.environ.get("INCLUDE_MODELS") == "1"

skipped = []

# --- named volumes -----------------------------------------------------------
# The top-level map is keyed by the name as DECLARED and carries the real,
# project-prefixed name under "name". Under the folder layout compose prunes
# declarations whose only user became a bind mount, so this list shrinks by
# itself and never needs a parallel "is this host on volumes?" flag.
for declared, spec in sorted((doc.get("volumes") or {}).items()):
    real = (spec or {}).get("name") or declared
    if "neo4j_logs" in declared:
        skipped.append(f"{real} (logs, scratch)"); continue
    if "neo4j_import" in declared:
        skipped.append(f"{real} (import scratch)"); continue
    if "vllm_model_cache" in declared and not include_models:
        skipped.append(f"{real} (model cache; --include-models to archive)"); continue
    print(f"volume\t{real}")

# --- bind mounts that hold state ---------------------------------------------
# Rule: a read-write bind whose source is inside the checkout. Every code mount
# (scripts/, frontend/, enrichers/, the runner config, nginx.conf) is :ro and
# travels with the repo, so read-write is what separates state from code without
# a hand-maintained list that would go stale.
#
RO_STATE = set()

seen = {}
for svc in sorted((doc.get("services") or {}).keys()):
    for m in (doc["services"][svc].get("volumes") or []):
        if m.get("type") != "bind":
            continue
        src = m.get("source") or ""
        if not src.startswith("/"):
            continue
        real = os.path.realpath(src)
        if os.path.commonpath([real, repo]) != repo or real == repo:
            continue                      # outside the checkout (e.g. docker.sock)
        rel = os.path.relpath(real, repo)
        if not os.path.isdir(real):
            continue                      # single-file config mounts travel with the repo
        if rel.startswith("vendor" + os.sep) or rel == "vendor":
            continue                      # the pinned Flowsint checkout; bootstrap re-clones it
        writable = not m.get("read_only", False)
        if not writable and rel not in RO_STATE:
            continue
        # A path can appear more than once (tunnel-keys is mounted ro AND rw;
        # screenshots is written by the runners and read by nginx). Keep it once,
        # and let a writable appearance win over a read-only one.
        seen[rel] = seen.get(rel, False) or writable

for rel in sorted(seen):
    print(f"bind\t{os.path.join(repo, rel)}\t{rel}")

for s in skipped:
    print(f"skip\t{s}")
PY
then
  die "failed to parse the rendered compose project (see the traceback above)"
fi
mapfile -t RECORDS < "$DISCOVERED"

VOLS=(); BIND_ABS=(); BIND_REL=(); SKIPPED=()
for rec in "${RECORDS[@]}"; do
  IFS=$'\t' read -r kind a b <<<"$rec"
  case "$kind" in
    volume) VOLS+=("$a");;
    bind)   BIND_ABS+=("$a"); BIND_REL+=("$b");;
    skip)   SKIPPED+=("$a");;
  esac
done

(( ${#VOLS[@]} + ${#BIND_ABS[@]} > 0 )) || die "nothing to back up — is the stack configured?"

log "Project:  ${PROJECT}"
log "Output:   ${OUTDIR}"
log "Will archive ${#VOLS[@]} volume(s) and ${#BIND_ABS[@]} in-folder director(ies):"
for v in "${VOLS[@]}";     do log "   + volume  $v"; done
for r in "${BIND_REL[@]}"; do log "   + folder  $r"; done
if (( ${#SKIPPED[@]} )); then log "Skipping:"; for s in "${SKIPPED[@]}"; do log "   - $s"; done; fi

if (( LIST_ONLY )); then
  log ""
  log "--list given: nothing was archived, stopped or written."
  exit 0
fi

mkdir -p "$OUTDIR"

# ── checkpoint the auth DB before anything copies it ─────────────────────────
# auth.db is SQLite in WAL mode, and the WAL is routinely LARGER than the
# database (4 MB against 28 KB on the host this was written for). Copying
# auth.db without auth.db-wal loses every operator account created since the
# last checkpoint. The tar below takes all three files, but checkpointing first
# means the archive is consistent even if someone later copies only auth.db.
AUTH_DB="$REPO_ROOT/deployment/auth-data/auth.db"
if [[ -f "$AUTH_DB" ]] && command -v sqlite3 >/dev/null 2>&1; then
  log "Checkpointing auth.db WAL ..."
  sqlite3 "$AUTH_DB" 'PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null \
    || log "WARN: wal_checkpoint failed — the archive still takes auth.db-wal, so this is not fatal"
elif [[ -f "$AUTH_DB" ]]; then
  log "WARN: sqlite3 not on PATH — auth.db WAL not checkpointed (archive still takes -wal/-shm)"
fi

# ── stop for a cold, consistent snapshot ──────────────────────────────────────
RUNNING=()
if [[ $HOT -eq 0 ]]; then
  mapfile -t RUNNING < <(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Names}}')
  if [[ ${#RUNNING[@]} -gt 0 ]]; then
    log "Stopping ${#RUNNING[@]} running container(s) for a cold snapshot..."
    docker stop "${RUNNING[@]}" >/dev/null
  else
    log "No running containers for '${PROJECT}' — assuming already stopped."
  fi
else
  log "WARNING: --hot set — copying live state without stopping. DB snapshots may be inconsistent."
fi

restart() {
  if [[ $HOT -eq 0 && ${#RUNNING[@]} -gt 0 ]]; then
    log "Restarting ${#RUNNING[@]} container(s)..."
    docker start "${RUNNING[@]}" >/dev/null 2>&1 || log "WARN: some containers failed to restart — check 'docker ps -a'"
  fi
  cleanup_rendered          # replaces the earlier EXIT trap, so do its work too
}
trap restart EXIT

# ── archive ───────────────────────────────────────────────────────────────────
{
  echo "# SPOTTER migration manifest"
  echo "project=${PROJECT}"
  echo "llm_backend=vllm"
  echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "source_host=$(hostname)"
  echo "source_root=${REPO_ROOT}"
  echo "# entries: '<kind> <name-or-relpath> <archive> <size>'"
} > "$OUTDIR/MANIFEST.txt"

for v in "${VOLS[@]}"; do
  log "  archiving volume ${v} ..."
  docker run --rm -v "${v}":/from:ro -v "${OUTDIR}":/to alpine \
    tar czf "/to/${v}.tar.gz" -C /from . || die "failed archiving volume ${v}"
  sz=$(du -h "${OUTDIR}/${v}.tar.gz" | cut -f1)
  echo "volume ${v} ${v}.tar.gz ${sz}" >> "$OUTDIR/MANIFEST.txt"
  log "    -> ${OUTDIR}/${v}.tar.gz (${sz})"
done

for i in "${!BIND_ABS[@]}"; do
  rel="${BIND_REL[$i]}"; abs="${BIND_ABS[$i]}"
  # Slug the relative path so the archive name says what it is and restore can
  # read the real destination out of the manifest rather than the filename.
  arch="folder__${rel//\//__}.tar.gz"
  log "  archiving folder ${rel} ..."
  # --numeric-owner so the uids survive a restore onto a host with different
  # account names; -p so modes survive (tunnel-keys is 0700, caddy's data dir 0700).
  tar czf "${OUTDIR}/${arch}" --numeric-owner -p -C "$abs" . \
    || die "failed archiving folder ${rel}"
  sz=$(du -h "${OUTDIR}/${arch}" | cut -f1)
  echo "bind ${rel} ${arch} ${sz}" >> "$OUTDIR/MANIFEST.txt"
  log "    -> ${OUTDIR}/${arch} (${sz})"
done

total=$(du -ch "${OUTDIR}"/*.tar.gz | tail -1 | cut -f1)
log "Done. $(( ${#VOLS[@]} + ${#BIND_ABS[@]} )) archive(s), total ${total}, in: ${OUTDIR}"
log ""
log "Next: copy '${OUTDIR}' + the repo + your .env to the target host, then run:"
log "  bash deployment/migrate-restore.sh -i <copied-dir-on-target>"
log ""
log "Secrets: .env holds configuration only. Local secrets/*.sops.env and"
log "  .sops.yaml are gitignored and are not included in these archives. Transfer"
log "  encrypted tiers out of band when cloning this install, then add the target's"
log "  age recipient and run 'sops updatekeys secrets/<file>' there. The age identity"
log "  defaults to \$HOME/.config/sops/age/keys.txt; transfer it separately and"
log "  securely, never alongside the ciphertext. For a fresh install, generate new"
log "  machine credentials and enter optional vendor credentials locally."

# These archives contain the engagement graph, n8n's credential store and the
# ingest staging area. They are written to an ordinary directory on a host with
# no full-disk encryption, so tighten the modes rather than relying on umask.
chmod 700 "${OUTDIR}" 2>/dev/null || true
chmod 600 "${OUTDIR}"/*.tar.gz 2>/dev/null || true

if command -v age >/dev/null 2>&1 && [[ -n "${SPOTTER_BACKUP_AGE_RECIPIENT:-}" ]]; then
    log ""
    log "SPOTTER_BACKUP_AGE_RECIPIENT is set -- encrypting each archive with age."
    for _f in "${OUTDIR}"/*.tar.gz; do
        [[ -e "$_f" ]] || continue
        if age -r "${SPOTTER_BACKUP_AGE_RECIPIENT}" -o "${_f}.age" "$_f"; then
            shred -u "$_f" 2>/dev/null || rm -f "$_f"
            log "  encrypted $(basename "${_f}").age"
        else
            log "  WARNING: could not encrypt $(basename "$_f") -- left in the clear"
        fi
    done
else
    log ""
    log "NOTE: archives are PLAINTEXT. This host has no full-disk encryption, so a"
    log "  copy of '${OUTDIR}' is a copy of the engagement data. To encrypt them,"
    log "  set SPOTTER_BACKUP_AGE_RECIPIENT=<age1...> and re-run, then decrypt with"
    log "  'age -d -i <identity> -o archive.tar.gz archive.tar.gz.age'."
fi
