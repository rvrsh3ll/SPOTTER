#!/usr/bin/env bash
# SPOTTER — migration RESTORE (run on the TARGET host)
#
# Recreates SPOTTER's state from migrate-backup.sh archives. Run this BEFORE the
# first `scripts/spotter_compose.sh up` on the new host (or after an `up`
# followed by a `stop`), so the stack starts on the migrated data.
#
# Two kinds of archive, distinguished by MANIFEST.txt:
#   volume <name> <archive>   -> restored into the Docker volume of that name
#   bind   <relpath> <archive> -> extracted to <checkout>/<relpath>
#
# The manifest is authoritative. A directory's destination cannot be recovered
# from a filename, and guessing it is how a restore quietly puts the operator
# account database somewhere nothing reads.
#
# Archives produced by the pre-manifest version of migrate-backup.sh are still
# understood: with no typed manifest lines, every *.tar.gz is treated as a volume
# named after its basename, which is what that version meant.
#
# Volume names carry their project prefix (spotter_pg_data_prod), so the stack
# must be launched on this host under the SAME project name — which is exactly
# what scripts/spotter_compose.sh supplies.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INDIR=""
FORCE=0

usage() {
  cat <<EOF
Usage: $(basename "$0") -i INDIR [--force]

Restores the archives in INDIR, reading MANIFEST.txt to decide what each one is.

Options:
  -i INDIR    directory containing the migrate-backup.sh archives (+ MANIFEST.txt)
  --force     overwrite volumes/directories that already contain data
              (DELETES current contents)
  -h, --help  show this help

Safety: a target that already has data is left untouched unless --force is given,
so re-running never silently clobbers a populated stack.

Run as root if the archive contains tunnel-keys/ or auth-data/ — restoring those
needs to set uids and modes (private keys are 0600, tunnel-keys/ is 0700).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i) INDIR="${2:?}"; shift 2;;
    --force) FORCE=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 1;;
  esac
done

log(){ echo "[migrate-restore] $*"; }
die(){ echo "[migrate-restore] ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
[[ -n "$INDIR" ]] || { usage; die "-i INDIR is required"; }
[[ -d "$INDIR" ]] || die "input dir not found: $INDIR"
INDIR="$(cd "$INDIR" && pwd)"

shopt -s nullglob
archives=("$INDIR"/*.tar.gz)
[[ ${#archives[@]} -gt 0 ]] || die "no *.tar.gz archives found in $INDIR"

MANIFEST="$INDIR/MANIFEST.txt"
[[ -f "$MANIFEST" ]] && { log "Manifest:"; sed 's/^/   /' "$MANIFEST"; echo; }

# ── build the work list ───────────────────────────────────────────────────────
KINDS=(); NAMES=(); FILES=()

if [[ -f "$MANIFEST" ]] && grep -qE '^(volume|bind) ' "$MANIFEST"; then
  while read -r kind name arch _rest; do
    [[ -n "${arch:-}" ]] || continue
    [[ -f "$INDIR/$arch" ]] || die "manifest names '$arch' but it is not in $INDIR"
    KINDS+=("$kind"); NAMES+=("$name"); FILES+=("$arch")
  done < <(grep -E '^(volume|bind) ' "$MANIFEST")
  log "Manifest lists ${#KINDS[@]} item(s)."
else
  log "No typed manifest entries — treating every archive as a named volume (legacy set)."
  for a in "${archives[@]}"; do
    base="$(basename "$a")"
    KINDS+=("volume"); NAMES+=("${base%.tar.gz}"); FILES+=("$base")
  done
fi

# Anything in the directory the manifest did not account for is a real signal:
# it usually means an archive was copied in from a different backup run.
for a in "${archives[@]}"; do
  base="$(basename "$a")"
  found=0
  for f in "${FILES[@]}"; do [[ "$f" == "$base" ]] && { found=1; break; }; done
  (( found )) || log "WARN: ${base} is in ${INDIR} but not in the manifest — NOT restoring it"
done

log "Restoring ${#KINDS[@]} item(s) from ${INDIR}"

for i in "${!KINDS[@]}"; do
  kind="${KINDS[$i]}"; name="${NAMES[$i]}"; base="${FILES[$i]}"

  if [[ "$kind" == "volume" ]]; then
    log "  volume ${name}  <-  ${base}"
    docker volume create "$name" >/dev/null

    existing=$(docker run --rm -v "$name":/v alpine sh -c 'ls -A /v 2>/dev/null | head -1' || true)
    if [[ -n "$existing" ]]; then
      if [[ $FORCE -eq 0 ]]; then
        die "volume '${name}' already contains data. Re-run with --force to overwrite it."
      fi
      log "    --force: wiping existing '${name}' before restore"
      docker volume rm "$name" >/dev/null 2>&1 \
        || die "could not remove '${name}' (in use? stop the stack first)"
      docker volume create "$name" >/dev/null
    fi

    docker run --rm -v "$name":/to -v "$INDIR":/from alpine \
      sh -c "cd /to && tar xzf /from/${base}" || die "failed restoring volume ${name}"
    log "    restored."

  else
    # Destination is relative to THIS checkout, not to the source host's path --
    # that is the whole point of recording a relative path in the manifest.
    dest="$REPO_ROOT/$name"
    log "  folder ${name}  <-  ${base}"

    if [[ -d "$dest" ]] && [[ -n "$(ls -A "$dest" 2>/dev/null || true)" ]]; then
      if [[ $FORCE -eq 0 ]]; then
        die "'${dest}' already contains data. Re-run with --force to overwrite it."
      fi
      log "    --force: clearing existing '${dest}' before restore"
      find "$dest" -mindepth 1 -maxdepth 1 -exec rm -rf {} + \
        || die "could not clear ${dest}"
    fi

    mkdir -p "$dest"
    # -p and --numeric-owner so modes and uids survive: tunnel-keys/ is 0700 with
    # 0600 keys inside, and .spotter-cache is setgid so the task runner
    # (gid 1000) can write it. Extracting as a normal user drops all of that
    # silently.
    tar xzpf "$INDIR/$base" --numeric-owner -C "$dest" \
      || die "failed restoring folder ${name}"
    log "    restored to ${dest}"
    if [[ $EUID -ne 0 ]]; then
      log "    WARN: not running as root — uids/modes in '${name}' may not have been preserved"
    fi
  fi
done

cat <<EOF

[migrate-restore] Restore complete. Remaining steps on this host:
  1. Edit .env host paths for THIS machine. All must be ABSOLUTE — a relative value
     resolves against vendor/flowsint and Docker creates it rather than erroring:
       SPOTTER_HOME / FLOWSINT_HOME -> this checkout, and vendor/flowsint inside it
       SPOTTER_SCRIPTS_DIR          -> absolute path to this checkout's SPOTTER/scripts
       SSH_KEY_DIR                  -> this host's read-only SSH key dir
       SPOTTER_TUNNEL_KEYS_DIR      -> the writable key root (\${SPOTTER_HOME}/tunnel-keys)
     (Machine secrets, Flowsint API key, sketch/flow UUIDs stay as-is — they live
      in the migrated postgres/neo4j volumes and remain valid.)
  2. Clone Flowsint INTO this checkout at the pinned commit and symlink .env into it:
       scripts/bootstrap.sh does both (see README step 2).
     Re-run deployment/setup-secrets.sh afterwards: it re-derives SPOTTER_HOME for
     this path and re-applies the ownership the restored directories need.
  3. Build images on this host:
       docker build -t spotter-n8n-runners:local deployment/ -f deployment/Dockerfile.runners
       (sidecars build automatically on 'up' via docker-compose.flowsint.yml)
  4. Launch. The wrapper supplies the same project name the volumes were created
     under, which is what makes them reattach:
       scripts/spotter_compose.sh up -d
  5. If you did NOT migrate the vLLM model-cache volume, vLLM downloads the configured
     Hugging Face model on first boot. Budget the time, or re-run the backup with
     --include-models and copy that archive over.
  6. Sanity check: python3 scripts/preflight_env_check.py --env-file .env

  NOTE: campaign annotations, analysis history and the ingest log live in the
  operator's BROWSER (localStorage), not on the host, and are not carried by this
  script. Each operator re-creates them, or exports them from the old host first.
EOF
