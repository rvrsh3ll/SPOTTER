#!/usr/bin/env bash
set -euo pipefail

# Create a Flowsint investigation + sketch and print both IDs.
# Usage:
#   TOKEN="<bearer_token>" ./scripts/create_flowsint_investigation_and_sketch.sh
#   ./scripts/create_flowsint_investigation_and_sketch.sh "<bearer_token>"
#
# Optional env vars:
#   FLOWSINT_API_URL   (default: http://localhost:5001)
#   INVESTIGATION_NAME (default: SPOTTER Lab)
#   INVESTIGATION_DESC (default: SPOTTER bootstrap investigation)
#   SKETCH_TITLE       (default: Default Sketch)
#   SKETCH_DESC        (default: SPOTTER working graph)

API_URL="${FLOWSINT_API_URL:-http://localhost:5001}"
TOKEN="${TOKEN:-${1:-}}"

INVESTIGATION_NAME="${INVESTIGATION_NAME:-SPOTTER Lab}"
INVESTIGATION_DESC="${INVESTIGATION_DESC:-SPOTTER bootstrap investigation}"
SKETCH_TITLE="${SKETCH_TITLE:-Default Sketch}"
SKETCH_DESC="${SKETCH_DESC:-SPOTTER working graph}"

if [[ -z "$TOKEN" ]]; then
  echo "ERROR: Missing bearer token." >&2
  echo "Set TOKEN env var or pass it as first argument." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required but not found." >&2
  echo "Install jq and re-run this script." >&2
  exit 1
fi

echo "Creating investigation..."
INV_JSON="$(curl -sS -X POST "$API_URL/api/investigations/create" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$INVESTIGATION_NAME\",\"description\":\"$INVESTIGATION_DESC\"}")"

INV_ID="$(echo "$INV_JSON" | jq -r '.id // empty')"
if [[ -z "$INV_ID" ]]; then
  echo "ERROR: Failed to create investigation." >&2
  echo "$INV_JSON" >&2
  exit 1
fi

echo "Investigation created: $INV_ID"

echo "Creating sketch..."
SKETCH_JSON="$(curl -sS -X POST "$API_URL/api/sketches/create" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"title\":\"$SKETCH_TITLE\",\"description\":\"$SKETCH_DESC\",\"investigation_id\":\"$INV_ID\"}")"

SKETCH_ID="$(echo "$SKETCH_JSON" | jq -r '.id // empty')"
if [[ -z "$SKETCH_ID" ]]; then
  echo "ERROR: Failed to create sketch." >&2
  echo "$SKETCH_JSON" >&2
  exit 1
fi

echo "Sketch created: $SKETCH_ID"
echo

echo "Set this in .env:"
echo "FLOWSINT_SKETCH_ID=$SKETCH_ID"
