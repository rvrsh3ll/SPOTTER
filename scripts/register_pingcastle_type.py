"""
register_pingcastle_type.py — Register the ADRisk custom type in Flowsint.

PingCastle ingestion (`scripts/pingcastle_parser.py`, WF06 route `pingcastle`)
creates one **ADRisk** node per triggered risk rule. ADRisk is a custom type, so
it has to exist in Flowsint's type registry before any such node is written.

This is not optional and not a soft failure. Flowsint's graph serializer raises
on a nodeType it cannot resolve and has no per-node try/except, so a *single*
ADRisk node in an install that never registered the type makes
`GET /api/sketches/{id}/graph` return HTTP 500 for the **entire sketch** — the
campaign goes dark in the UI, not just that node.

Run once per install:

    python3 scripts/register_pingcastle_type.py --apply

Dry-run by default: it reports what it would do and changes nothing. Re-running
after a successful apply is a no-op. Until it is applied, `upload_router` still
ingests PingCastle reports — it just drops the ADRisk nodes and returns a
warning, so the domain / DC / privileged-account data still lands.

Environment (same variables the workflows use):
    FLOWSINT_API_URL   default http://localhost:5001
    FLOWSINT_API_KEY   required
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

import requests

TYPE_NAME = "ADRisk"
TYPE_DESCRIPTION = (
    "Active Directory configuration risk finding (PingCastle health check rule)"
)

# Kept in sync with flowsint-custom/types/ad_risk.py :: ADRisk.REGISTERED_SCHEMA.
#
# String-typed properties ONLY, deliberately. A DB-registered custom type is
# rebuilt by _build_pydantic_model_from_schema, which types every declared
# property as Optional[str] whatever the schema says; Pydantic v2 will not coerce
# an int or bool into str and the serializer silently drops fields that fail
# validation. points / details_count / is_high_risk / details are therefore left
# undeclared so they pass through as extras and keep their native Neo4j type.
ADRISK_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "risk_id":      {"type": "string"},
        "category":     {"type": "string"},
        "model":        {"type": "string"},
        "severity":     {"type": "string"},
        "rationale":    {"type": "string"},
        "domain":       {"type": "string"},
        "source":       {"type": "string"},
        "generated_at": {"type": "string"},
        "reference":    {"type": "string"},
    },
}


def fetch_types(api_url: str, api_key: str) -> List[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    resp = requests.get(
        f"{api_url.rstrip('/')}/api/custom-types", headers=headers, timeout=60
    )
    resp.raise_for_status()
    body = resp.json()
    if not isinstance(body, list):
        raise RuntimeError(f"unexpected /api/custom-types response: {str(body)[:200]}")
    return [t for t in body if isinstance(t, dict)]


def ensure_custom_type(api_url: str, api_key: str, apply: bool) -> str:
    """Make sure ADRisk is a registered, published custom type."""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    existing = fetch_types(api_url, api_key)

    for entry in existing:
        if (entry.get("name") or "").lower() != TYPE_NAME.lower():
            continue
        if entry.get("status") == "published":
            return "already registered"
        if not apply:
            return f"WOULD PUBLISH (currently {entry.get('status')})"
        resp = requests.put(
            f"{api_url.rstrip('/')}/api/custom-types/{entry['id']}",
            headers=headers,
            json={"status": "published", "schema": ADRISK_SCHEMA},
            timeout=60,
        )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"publishing {TYPE_NAME} failed: HTTP {resp.status_code} {resp.text[:300]}"
            )
        return "published"

    if not apply:
        return "WOULD REGISTER (dry-run)"

    body = {
        "name": TYPE_NAME,
        "schema": ADRISK_SCHEMA,
        "status": "published",
        "category": "custom_types_category",
        # color/icon are non-Optional with defaults on CustomTypeCreate; mirror
        # how the other SPOTTER types were registered.
        "color": "#B4553F",
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
        description="Register the ADRisk custom type used by PingCastle ingestion.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--api-url", default=os.environ.get("FLOWSINT_API_URL", "http://localhost:5001")
    )
    parser.add_argument("--api-key", default=os.environ.get("FLOWSINT_API_KEY", ""))
    parser.add_argument(
        "--apply", action="store_true",
        help="Actually register. Without it the script only reports.",
    )
    parser.add_argument(
        "--show-schema", action="store_true", help="Print the schema and exit."
    )
    args = parser.parse_args(argv)

    if args.show_schema:
        print(json.dumps(ADRISK_SCHEMA, indent=2))
        return 0

    print(f"register_pingcastle_type: {'APPLY' if args.apply else 'DRY-RUN'}")

    if not args.api_key:
        print("error: FLOWSINT_API_KEY not set", file=sys.stderr)
        return 1

    try:
        status = ensure_custom_type(args.api_url, args.api_key, args.apply)
    except Exception as exc:                        # noqa: BLE001 - operator-facing
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"  custom type {TYPE_NAME}: {status}")
    if status.startswith("WOULD"):
        print("\nRe-run with --apply to write. PingCastle uploads will keep dropping "
              "ADRisk nodes until then.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
