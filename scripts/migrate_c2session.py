"""
migrate_c2session.py — Migrate CobaltBeacon → C2Session.

Two jobs, and the ORDER between them is not negotiable:

  1. Register the C2Session custom type in Flowsint (POST /api/custom-types).
  2. Relabel any existing CobaltBeacon nodes and rename their properties.

Flowsint's graph serializer raises on a nodeType it cannot resolve and has no
per-node try/except, so a SINGLE node carrying an unregistered type makes
GET /api/sketches/{id}/graph return HTTP 500 for the WHOLE sketch — the app goes
dark for that campaign, not just for one node. Step 1 therefore runs first and
hard-aborts on failure. Step 1 is also required on its own before WF01 or WF21
ingests anything, because both now create nodes with node_type='C2Session'.

The CobaltBeacon type registration is deliberately NOT deleted: leaving it
resolvable keeps any node this script misses (another sketch, a restored backup)
from taking its sketch down.

Property renames applied to each migrated node:
    beacon_id  → session_id
    cs_server  → c2_server
    (new)      → c2_framework = 'cobalt_strike'   — the only framework that
                                                    existed before the rename
    (new)      → session_key  = 'cobalt_strike:<session_id>'

Both the Neo4j label and the nodeType property are updated; Flowsint stores them
as matching CamelCase values (verified against a live graph: Subdomain, WebAsset,
Service, DomainBreach), while consumer code lower-cases before comparing.

Dry-run by default — it reports what it would do and changes nothing. Pass
--apply to write. Re-running after a successful apply is a no-op.

Usage (from the host; both services publish to 127.0.0.1):

    python3 scripts/migrate_c2session.py \\
        --api-url http://localhost:5001 --neo4j-url http://localhost:7474
    python3 scripts/migrate_c2session.py ... --apply

Environment (CLI flags win):
    FLOWSINT_API_URL, FLOWSINT_API_KEY, NEO4J_HTTP_URL, NEO4J_USER, NEO4J_PASSWORD
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from typing import Any, Dict, List, Optional

import requests

TYPE_NAME = "C2Session"
LEGACY_TYPE_NAME = "CobaltBeacon"

# Flat {"type": ...} properties, matching how the other SPOTTER types are
# registered (see GET /api/custom-types on a provisioned install).
C2SESSION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "c2_framework":     {"type": "string"},
        "session_id":       {"type": "string"},
        "session_key":      {"type": "string"},
        "c2_server":        {"type": "string"},
        "hostname":         {"type": "string"},
        "internal_ip":      {"type": "string"},
        "external_ip":      {"type": "string"},
        "listener_ip":      {"type": "string"},
        "os_version":       {"type": "string"},
        "arch":             {"type": "string"},
        "username":         {"type": "string"},
        "sam_account_name": {"type": "string"},
        "process_name":     {"type": "string"},
        "pid":              {"type": "integer"},
        "thread_id":        {"type": "integer"},
        "is_admin":         {"type": "boolean"},
        "last_checkin":     {"type": "string"},
        "sleep_seconds":    {"type": "integer"},
        "jitter_pct":       {"type": "integer"},
        "listener":         {"type": "string"},
        "note":             {"type": "string"},
        "process_list":     {"type": "array"},
        "tech_stack":       {"type": "array"},
        "priority_score":   {"type": "integer"},
        "is_pivot":         {"type": "boolean"},
        "pivot_parent":     {"type": "string"},
        "pivot_channel":    {"type": "string"},
        "is_dead":          {"type": "boolean"},
        "source":           {"type": "string"},
    },
}

TYPE_DESCRIPTION = (
    "C2 session from any framework (Cobalt Strike beacon, Brute Ratel badger); "
    "discriminated by c2_framework. Replaces CobaltBeacon."
)

# ── Counting ─────────────────────────────────────────────────────────────────

_COUNT_LEGACY = """
MATCH (n)
WHERE toLower(coalesce(n.nodeType, '')) = 'cobaltbeacon' OR 'CobaltBeacon' IN labels(n)
RETURN count(n) AS c
"""

_COUNT_CURRENT = """
MATCH (n)
WHERE toLower(coalesce(n.nodeType, '')) = 'c2session' OR 'C2Session' IN labels(n)
RETURN count(n) AS c
"""

_SAMPLE_LEGACY = """
MATCH (n)
WHERE toLower(coalesce(n.nodeType, '')) = 'cobaltbeacon' OR 'CobaltBeacon' IN labels(n)
RETURN labels(n) AS labels,
       n.nodeType AS nodeType,
       n.sketch_id AS sketch_id,
       n.`nodeProperties.beacon_id` AS beacon_id,
       n.`nodeProperties.session_id` AS session_id,
       n.`nodeProperties.hostname` AS hostname
LIMIT 10
"""

# ── Migration ────────────────────────────────────────────────────────────────

# Swap the Neo4j label. APOC is present (WF19/WF20 rely on apoc.create.*).
_MIGRATE_LABELS = """
MATCH (n:CobaltBeacon)
CALL apoc.create.addLabels(n, ['C2Session']) YIELD node AS added
CALL apoc.create.removeLabels(added, ['CobaltBeacon']) YIELD node AS done
RETURN count(done) AS c
"""

# Values are resolved in a WITH before any SET so that no SET item reads a value
# another SET item in the same clause has already overwritten.
_MIGRATE_PROPS = """
MATCH (n)
WHERE toLower(coalesce(n.nodeType, '')) = 'cobaltbeacon'
   OR (toLower(coalesce(n.nodeType, '')) = 'c2session'
       AND n.`nodeProperties.beacon_id` IS NOT NULL)
WITH n,
     coalesce(n.`nodeProperties.session_id`, n.`nodeProperties.beacon_id`, '') AS sid,
     coalesce(n.`nodeProperties.c2_server`, n.`nodeProperties.cs_server`, '')  AS srv,
     coalesce(n.`nodeProperties.c2_framework`, 'cobalt_strike')                AS fw
SET n.nodeType = 'C2Session',
    n.`nodeProperties.session_id`   = sid,
    n.`nodeProperties.c2_server`    = srv,
    n.`nodeProperties.c2_framework` = fw,
    n.`nodeProperties.session_key`  = coalesce(n.`nodeProperties.session_key`, fw + ':' + sid)
REMOVE n.`nodeProperties.beacon_id`, n.`nodeProperties.cs_server`
RETURN count(n) AS c
"""


class Neo4jHTTP:
    """Minimal Neo4j HTTP transactional client — same shape as WF19/WF20 use."""

    def __init__(self, url: str, user: str, password: str) -> None:
        self.url = url.rstrip("/")
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
        }

    def query(self, statement: str, parameters: Optional[Dict[str, Any]] = None) -> List[List[Any]]:
        resp = requests.post(
            f"{self.url}/db/neo4j/tx/commit",
            headers=self.headers,
            json={"statements": [{"statement": statement, "parameters": parameters or {}}]},
            timeout=300,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("errors"):
            raise RuntimeError(str(body["errors"])[:500])
        data = body["results"][0]["data"]
        return [row["row"] for row in data]

    def scalar(self, statement: str) -> int:
        rows = self.query(statement)
        return int(rows[0][0]) if rows else 0


def ensure_custom_type(api_url: str, api_key: str, apply: bool) -> str:
    """
    Make sure C2Session is a registered, published custom type.

    Returns a status string. Raises on anything that would leave the type
    unresolvable, because relabeling nodes to an unregistered type breaks
    GET /graph for the entire sketch.
    """
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    resp = requests.get(f"{api_url.rstrip('/')}/api/custom-types", headers=headers, timeout=60)
    resp.raise_for_status()
    existing = resp.json() or []
    names = {(t.get("name") or "").lower() for t in existing if isinstance(t, dict)}

    if TYPE_NAME.lower() in names:
        return "already registered"

    if not apply:
        return "WOULD REGISTER (dry-run)"

    body = {
        "name": TYPE_NAME,
        "schema": C2SESSION_SCHEMA,
        "status": "published",
        "category": "custom_types_category",
        # color/icon are non-Optional with defaults on CustomTypeCreate; the other
        # SPOTTER types were registered with nulls, so mirror WF20's coercion.
        "color": "#8E9E8C",
        "icon": "Minus",
        "description": TYPE_DESCRIPTION,
    }
    resp = requests.post(
        f"{api_url.rstrip('/')}/api/custom-types", headers=headers, json=body, timeout=60
    )
    if resp.status_code >= 400:
        raise RuntimeError(
            f"registering {TYPE_NAME} failed: HTTP {resp.status_code} {resp.text[:300]}"
        )
    return "registered"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Migrate CobaltBeacon nodes and type registration to C2Session.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--api-url", default=os.environ.get("FLOWSINT_API_URL", "http://localhost:5001"))
    parser.add_argument("--api-key", default=os.environ.get("FLOWSINT_API_KEY", ""))
    parser.add_argument("--neo4j-url", default=os.environ.get("NEO4J_HTTP_URL", "http://localhost:7474"))
    parser.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    parser.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD", ""))
    parser.add_argument("--apply", action="store_true",
                        help="Actually write. Without it the script only reports.")
    args = parser.parse_args(argv)

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"migrate_c2session: {mode}")

    if not args.api_key:
        print("error: FLOWSINT_API_KEY not set (needed to register the custom type)", file=sys.stderr)
        return 1
    if not args.neo4j_password:
        print("error: NEO4J_PASSWORD not set", file=sys.stderr)
        return 1

    # ── Step 1: type registration. Must precede any relabel. ─────────────────
    try:
        status = ensure_custom_type(args.api_url, args.api_key, args.apply)
    except Exception as exc:
        print(f"error: step 1 failed, refusing to relabel nodes: {exc}", file=sys.stderr)
        return 1
    print(f"  step 1  custom type {TYPE_NAME}: {status}")
    print(f"          {LEGACY_TYPE_NAME} registration left in place on purpose "
          f"(keeps un-migrated nodes resolvable)")

    # ── Step 2: survey ───────────────────────────────────────────────────────
    neo = Neo4jHTTP(args.neo4j_url, args.neo4j_user, args.neo4j_password)
    try:
        legacy = neo.scalar(_COUNT_LEGACY)
        current = neo.scalar(_COUNT_CURRENT)
    except Exception as exc:
        print(f"error: could not read the graph: {exc}", file=sys.stderr)
        return 1

    print(f"  step 2  nodes: {legacy} legacy {LEGACY_TYPE_NAME}, {current} already {TYPE_NAME}")

    if legacy:
        for row in neo.query(_SAMPLE_LEGACY):
            labels, ntype, sketch, bid, sid, host = row
            print(f"            labels={labels} nodeType={ntype} sketch={sketch} "
                  f"beacon_id={bid} session_id={sid} host={host}")

    if not legacy:
        print("  step 3  nothing to relabel")
        if not args.apply and status.startswith("WOULD"):
            print("\nRe-run with --apply to register the type. Node data needs no migration.")
        return 0

    # ── Step 3: relabel ──────────────────────────────────────────────────────
    if not args.apply:
        print(f"  step 3  WOULD relabel {legacy} node(s): label+nodeType → {TYPE_NAME}, "
              f"beacon_id → session_id, cs_server → c2_server, "
              f"+c2_framework='cobalt_strike', +session_key")
        print("\nRe-run with --apply to write.")
        return 0

    try:
        relabelled = neo.scalar(_MIGRATE_LABELS)
        print(f"  step 3  Neo4j labels swapped on {relabelled} node(s)")
        migrated = neo.scalar(_MIGRATE_PROPS)
        print(f"          nodeType + properties migrated on {migrated} node(s)")
    except Exception as exc:
        print(f"error: relabel failed (type IS registered, so the graph still "
              f"serialises): {exc}", file=sys.stderr)
        return 1

    remaining = neo.scalar(_COUNT_LEGACY)
    print(f"  verify  {remaining} legacy node(s) remaining, "
          f"{neo.scalar(_COUNT_CURRENT)} now {TYPE_NAME}")
    if remaining:
        print("warning: some legacy nodes survived — re-run to converge", file=sys.stderr)
        return 1

    print("\nDone. Restart flowsint-api-prod and flowsint-celery-prod if the "
          "enricher files were also updated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
