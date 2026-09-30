"""
register_cloudschism_type.py — Register the CloudSchism custom types in Flowsint.

CloudSchism ingestion (`scripts/cloudschism_parser.py`, WF06 route `cloudschism`)
creates two kinds of custom node:

    CloudFinding      one per cloud posture / misconfiguration finding
    CloudAttackPath   one per deterministic attack path chaining those findings

Both are custom types, so they have to exist in Flowsint's type registry before any
such node is written.

This is not optional and not a soft failure. Flowsint's graph serializer raises on
a nodeType it cannot resolve and has no per-node try/except, so a *single*
unregistered node makes `GET /api/sketches/{id}/graph` return HTTP 500 for the
**entire sketch** — the campaign goes dark in the UI, not just that node.

Run once per install:

    python3 scripts/register_cloudschism_type.py --apply

Dry-run by default: it reports what it would do and changes nothing. Re-running
after a successful apply is a no-op. Until it is applied, `upload_router` still
ingests CloudSchism output — it just drops the nodes of whichever type is missing
and returns a warning, so the public endpoints, cloud assets and identities still
land. The two types are gated independently, so registering one is not wasted.

The other types this route emits (CloudAsset, Service) are already registered, and
Domain / Ip / Organization / Individual are built-ins, so these two are the only
gates.

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

TYPE_NAME = "CloudFinding"
TYPE_DESCRIPTION = (
    "Cloud posture / misconfiguration finding (CloudSchism AWS, Azure, M365, GCP scan)"
)

ATTACK_PATH_TYPE_NAME = "CloudAttackPath"
ATTACK_PATH_TYPE_DESCRIPTION = (
    "Deterministic cloud attack path chaining findings from an entry point (CloudSchism)"
)

# Kept in sync with flowsint-custom/types/cloud_finding.py :: CloudFinding.REGISTERED_SCHEMA.
#
# String-typed properties ONLY, deliberately. A DB-registered custom type is rebuilt
# by _build_pydantic_model_from_schema, which types every declared property as
# Optional[str] whatever the schema says; Pydantic v2 will not coerce a bool into
# str and the serializer silently drops fields that fail validation.
# attack_path_relevance / suppressed / related_techniques are therefore left
# undeclared so they pass through as extras and keep their native Neo4j type.
CLOUDFINDING_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "finding_id":     {"type": "string"},
        "control_id":     {"type": "string"},
        "title":          {"type": "string"},
        "severity":       {"type": "string"},
        "provider":       {"type": "string"},
        "service":        {"type": "string"},
        "resource_id":    {"type": "string"},
        "region":         {"type": "string"},
        "account_id":     {"type": "string"},
        "finding_class":  {"type": "string"},
        "exploitability": {"type": "string"},
        "evidence_state": {"type": "string"},
        "confidence":     {"type": "string"},
        "flagged_reason": {"type": "string"},
        "remediation":    {"type": "string"},
        "source":         {"type": "string"},
    },
}

# Kept in sync with flowsint-custom/types/cloud_attack_path.py ::
# CloudAttackPath.REGISTERED_SCHEMA. Same string-only rule as above:
# confidence_score / severity_ceiling_applied / has_contradictions /
# affected_resource_count / finding_count are left undeclared so they keep their
# int and bool types in Neo4j.
CLOUDATTACKPATH_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "path_id":               {"type": "string"},
        "title":                 {"type": "string"},
        "severity":              {"type": "string"},
        "provider":              {"type": "string"},
        "rule_id":               {"type": "string"},
        "path_type":             {"type": "string"},
        "trust_state":           {"type": "string"},
        "evidence_state":        {"type": "string"},
        "evidence_confidence":   {"type": "string"},
        "completeness":          {"type": "string"},
        "rule_confidence":       {"type": "string"},
        "account_id":            {"type": "string"},
        "reasoning":             {"type": "string"},
        "remediation":           {"type": "string"},
        "tactic_chain":          {"type": "string"},
        "entry_points":          {"type": "string"},
        "missing_prerequisites": {"type": "string"},
        "source":                {"type": "string"},
    },
}

# Every custom type this ingest path emits: (name, schema, description, colour).
# Both are registered together because a CloudSchism scan produces both, and a
# half-registered install fails in exactly the confusing way this script exists
# to prevent.
CLOUDSCHISM_TYPES = (
    (TYPE_NAME, CLOUDFINDING_SCHEMA, TYPE_DESCRIPTION, "#3F7FB4"),
    (ATTACK_PATH_TYPE_NAME, CLOUDATTACKPATH_SCHEMA, ATTACK_PATH_TYPE_DESCRIPTION, "#6F4FA8"),
)


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


def ensure_custom_type(api_url: str, api_key: str, apply: bool, name: str,
                       schema: Dict[str, Any], description: str,
                       color: str, existing: Optional[List[Dict[str, Any]]] = None) -> str:
    """Make sure one custom type is registered and published."""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    if existing is None:
        existing = fetch_types(api_url, api_key)

    for entry in existing:
        if (entry.get("name") or "").lower() != name.lower():
            continue
        if entry.get("status") == "published":
            return "already registered"
        if not apply:
            return f"WOULD PUBLISH (currently {entry.get('status')})"
        resp = requests.put(
            f"{api_url.rstrip('/')}/api/custom-types/{entry['id']}",
            headers=headers,
            json={"status": "published", "schema": schema},
            timeout=60,
        )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"publishing {name} failed: HTTP {resp.status_code} {resp.text[:300]}"
            )
        return "published"

    if not apply:
        return "WOULD REGISTER (dry-run)"

    body = {
        "name": name,
        "schema": schema,
        "status": "published",
        "category": "custom_types_category",
        # color/icon are non-Optional with defaults on CustomTypeCreate; mirror how
        # the other SPOTTER types were registered.
        "color": color,
        "icon": "Minus",
        "description": description,
    }
    resp = requests.post(
        f"{api_url.rstrip('/')}/api/custom-types", headers=headers, json=body, timeout=60
    )
    if resp.status_code >= 400:
        raise RuntimeError(
            f"registering {name} failed: HTTP {resp.status_code} {resp.text[:300]}"
        )
    return "registered"


def ensure_all(api_url: str, api_key: str, apply: bool) -> Dict[str, str]:
    """Register every CloudSchism custom type. One registry read for all of them."""
    existing = fetch_types(api_url, api_key)
    return {
        name: ensure_custom_type(api_url, api_key, apply, name, schema,
                                 description, color, existing)
        for name, schema, description, color in CLOUDSCHISM_TYPES
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Register the custom types used by CloudSchism ingestion "
                    "(CloudFinding, CloudAttackPath).",
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
        "--show-schema", action="store_true", help="Print the schemas and exit."
    )
    args = parser.parse_args(argv)

    if args.show_schema:
        print(json.dumps({name: schema for name, schema, _d, _c in CLOUDSCHISM_TYPES},
                         indent=2))
        return 0

    print(f"register_cloudschism_type: {'APPLY' if args.apply else 'DRY-RUN'}")

    if not args.api_key:
        print("error: FLOWSINT_API_KEY not set", file=sys.stderr)
        return 1

    try:
        statuses = ensure_all(args.api_url, args.api_key, args.apply)
    except Exception as exc:                        # noqa: BLE001 - operator-facing
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for name, status in statuses.items():
        print(f"  custom type {name}: {status}")
    pending = [n for n, s in statuses.items() if s.startswith("WOULD")]
    if pending:
        print(f"\nRe-run with --apply to write. CloudSchism uploads will keep dropping "
              f"{', '.join(pending)} nodes until then.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
