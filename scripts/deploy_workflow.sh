#!/usr/bin/env bash
#
# Deploy one or more workflow JSON files into the running n8n container.
#
#   scripts/deploy_workflow.sh n8n-workflows/05-dossier-exporter.json [...]
#   scripts/deploy_workflow.sh --all
#
# Editing a file in n8n-workflows/ changes nothing on the live stack, and the
# manual sequence has three separate traps:
#
#   1. `import:workflow` DEACTIVATES the workflow it imports, so a plain import
#      silently takes the webhook offline.
#   2. `publish:workflow` re-activates it but does NOT reload the running process
#      -- the old code keeps serving until n8n restarts.
#   3. `publishVersion()` sets only workflow_entity.active/activeVersionId. It
#      never touches workflow_published_version, so re-importing bumps versionId
#      and strands publishedVersionId on the old one. Once that stranded version
#      is >24h old it breaks n8n's hourly workflow-history pruner: the pruner
#      excludes versionId and activeVersionId but not publishedVersionId, whose FK
#      is ON DELETE RESTRICT (migration 1772619247762). The bulk DELETE is then
#      rejected every hour with a bare "SQLITE_CONSTRAINT: FOREIGN KEY constraint
#      failed" and workflow_history grows forever.
#
# This script does all four steps in order so none of them can be skipped.
set -euo pipefail

CONTAINER="${N8N_CONTAINER:-spotter-n8n}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Where n8n's database.sqlite is on the host. Three cases, in order: an explicit
# N8N_DB_PATH override; the folder layout, where SPOTTER_N8N_DATA is a bind mount
# inside the checkout; or the named-volume layout, where only Docker knows.
N8N_VOLUME="${N8N_VOLUME:-spotter_n8n_data}"
if [ -n "${N8N_DB_PATH:-}" ]; then
  DB_HOST_PATH="$N8N_DB_PATH"
else
  # Under the folder layout there is no volume to inspect: SPOTTER_N8N_DATA names
  # a bind mount inside the checkout and the database sits directly in it. Read
  # it from .env rather than requiring the caller to export it, since that file
  # is where setup-secrets.sh records the decision.
  STATE_N8N="${SPOTTER_N8N_DATA:-$(sed -n 's/^SPOTTER_N8N_DATA=//p' "$REPO_ROOT/.env" 2>/dev/null | tail -1)}"
  STATE_N8N="${STATE_N8N//\$\{SPOTTER_HOME\}/$REPO_ROOT}"
  if [ -n "$STATE_N8N" ]; then
    DB_HOST_PATH="$STATE_N8N/database.sqlite"
  else
    # Named-volume layout. Ask Docker where the volume actually lives rather than
    # assuming the default /var/lib/docker/volumes path — it is wrong under a
    # relocated data-root, under rootless Docker, and under Podman. The volume
    # name is project-scoped, so it also depends on `-p spotter`.
    VOL_MOUNTPOINT="$(docker volume inspect "$N8N_VOLUME" -f '{{.Mountpoint}}' 2>/dev/null || true)"
    if [ -z "$VOL_MOUNTPOINT" ]; then
      echo "deploy_workflow: docker volume '$N8N_VOLUME' not found, and" >&2
      echo "  SPOTTER_N8N_DATA is not set in .env either." >&2
      echo "  The stack must be up (scripts/spotter_compose.sh up -d) and launched" >&2
      echo "  with -p spotter. Override with N8N_VOLUME= or N8N_DB_PATH= if needed." >&2
      exit 1
    fi
    DB_HOST_PATH="$VOL_MOUNTPOINT/database.sqlite"
  fi
fi

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <workflow.json> [...]   |   $0 --all" >&2
  exit 2
fi

if [ "${1:-}" = "--all" ]; then
  mapfile -t FILES < <(ls -1 "$REPO_ROOT"/n8n-workflows/*.json)
else
  FILES=("$@")
fi

# Pre-flight: refuse an import that would DUPLICATE a live workflow instead of
# updating it. `import:workflow` keys on the JSON's own "id", so a JSON whose id
# is absent from the live DB creates a NEW workflow -- and if a live workflow
# already serves that name, you now have two active copies of the same thing
# (two schedules, two webhooks racing for one path, every outbound lookup
# doubled). This is reachable whenever a workflow was created in the n8n UI
# first: n8n assigns a nanoid, and WF14 (vDcm9CPv2Vb4HO9p) is exactly that case,
# which is why its JSON does not follow the spotter-workflow-NN convention.
#
# A genuinely new workflow -- id absent AND no live workflow of that name -- is
# still allowed through, because that is what deploying a new workflow IS.
echo "==> checking ${#FILES[@]} workflow id(s) against the live database"
python3 - "$DB_HOST_PATH" "${FILES[@]}" <<'PY'
import json, sqlite3, sys, os

db, files = sys.argv[1], sys.argv[2:]
if not os.path.exists(db):
    print(f"    WARNING: {db} not found - skipping the duplicate check")
    raise SystemExit(0)
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
live_ids = {r[0] for r in con.execute("SELECT id FROM workflow_entity")}
by_name = {}
for wid, name in con.execute("SELECT id, name FROM workflow_entity"):
    by_name.setdefault(name, []).append(wid)
con.close()

problems = []
for f in files:
    # A missing or unparseable file is reported by the import loop below, which
    # already has a clean message for it. Don't pre-empt that with a traceback.
    if not os.path.isfile(f):
        continue
    try:
        d = json.load(open(f))
    except (ValueError, OSError):
        continue
    wid, name = d.get("id"), d.get("name")
    if wid in live_ids:
        continue
    clash = by_name.get(name, [])
    if clash:
        problems.append(
            f"    {os.path.basename(f)}\n"
            f"        JSON id : {wid!r}  (no such workflow live)\n"
            f"        live id : {', '.join(repr(c) for c in clash)}  named {name!r}\n"
            f"        -> importing this would CREATE A SECOND active copy.\n"
            f"           Set the JSON's \"id\" to the live id above, then re-run."
        )
    else:
        print(f"    {os.path.basename(f)}: new workflow {wid!r} - will be created")

if problems:
    print("\nREFUSING TO DEPLOY - id mismatch would duplicate a live workflow:\n")
    print("\n\n".join(problems))
    raise SystemExit(1)
print("    all ids resolve to live workflows (or are genuinely new)")
PY

echo "==> importing ${#FILES[@]} workflow(s) into $CONTAINER"
IDS=()
for f in "${FILES[@]}"; do
  [ -f "$f" ] || { echo "no such file: $f" >&2; exit 1; }
  id=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['id'])" "$f")
  IDS+=("$id")
  docker cp "$f" "$CONTAINER:/tmp/_deploy.json" >/dev/null
  docker exec "$CONTAINER" n8n import:workflow --input=/tmp/_deploy.json 2>&1 \
    | grep -viE 'error tracking|posthog|deprecat' | sed 's/^/    /'
done
docker exec -u root "$CONTAINER" rm -f /tmp/_deploy.json >/dev/null 2>&1 || true

# Only re-publish workflows whose JSON asks to be active. Importing an
# active:false workflow and then publishing it would silently switch it on, so
# the JSON's own "active" flag is the single source of truth for whether a
# webhook or schedule goes live. (All 29 currently ship active:true; this gate
# exists so that shipping one inactive stays a decision the JSON can express,
# rather than something a deploy quietly overrides.)
echo "==> publishing"
for i in "${!FILES[@]}"; do
  want_active=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('active') and 1 or 0)" "${FILES[$i]}")
  if [ "$want_active" = "1" ]; then
    docker exec "$CONTAINER" n8n publish:workflow --id="${IDS[$i]}" 2>&1 \
      | grep -viE 'error tracking|posthog|deprecat|will not take effect|Please restart' | sed 's/^/    /'
  else
    echo "    ${IDS[$i]}: JSON says active:false - left deactivated"
  fi
done

echo "==> stopping n8n to repair publication pointers"
docker stop "$CONTAINER" >/dev/null

python3 - "$DB_HOST_PATH" <<'PY'
import sqlite3, sys
db = sys.argv[1]
c = sqlite3.connect(db, timeout=30)
c.execute('PRAGMA foreign_keys=ON')
n = c.execute("""UPDATE workflow_published_version
   SET publishedVersionId = (SELECT versionId FROM workflow_entity WHERE id = workflowId),
       updatedAt = STRFTIME('%Y-%m-%d %H:%M:%f','NOW')
 WHERE publishedVersionId <> (SELECT versionId FROM workflow_entity WHERE id = workflowId)""").rowcount
c.commit()
stale = c.execute("""SELECT count(*) FROM workflow_published_version p
                     JOIN workflow_entity w ON w.id = p.workflowId
                     WHERE p.publishedVersionId <> w.versionId""").fetchone()[0]
print(f"    repointed {n} publication row(s); stale remaining: {stale}")
assert stale == 0, "publication pointers still stale - the hourly history prune will fail"
c.close()
PY

echo "==> restarting n8n"
docker restart "$CONTAINER" >/dev/null

echo "==> done. Verify through the authenticated nginx route, or from inside n8n:"
echo "    docker exec $CONTAINER wget -qO- --header='Content-Type: application/json' --post-data='{}' http://127.0.0.1:5678/webhook/<path>"
