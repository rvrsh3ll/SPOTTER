"""
shareacl_normalizer.py - Convert shareacl BOF output into Flowsint batches.

The BOF prints one JSON object per share, prefixed with "[shareacl] ":

    [shareacl] {"host":"FILESERVER","share_name":"Finance$",...}

This module parses that console output and produces (nodes, edges) ready for
flowsint_client.batch_import().

All data processed here originates from an authorized Beacon running under the
engagement's Rules of Engagement.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

SHAREACL_PREFIX = re.compile(r"^\s*\[shareacl\]\s+(\{.*)\s*$")

# Mapping from share effective access strings to a rank for summary generation.
_ACCESS_RANK = {
    "FULL": 4,
    "WRITE": 3,
    "READ": 2,
    "EXECUTE": 1,
    "DENY": 0,
    "CUSTOM": -1,
    "UNKNOWN": -2,
}


def _node_id(kind: str, key: str) -> str:
    """Deterministic temp ID used by batch_import."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", key).lower()
    return f"{kind}:{safe}"


def _principal_entity_type(trustee_type: str) -> str:
    """Map the BOF trustee_type string to a Flowsint entity type."""
    t = (trustee_type or "").lower()
    if t == "user":
        return "Individual"
    if t in {"group", "alias", "wellknowngroup"}:
        return "Group"
    if t == "computer":
        return "Computer"
    return "Individual"


def _principal_label(ace: Dict[str, Any]) -> str:
    """Return the best display label for a trustee."""
    name = ace.get("trustee_name", "")
    domain = ace.get("trustee_domain", "")
    sid = ace.get("trustee_sid", "")

    if name:
        if domain:
            return f"{domain}\\{name}"
        return name
    if sid:
        return sid
    return "unknown_trustee"


def _principal_temp_id(ace: Dict[str, Any]) -> str:
    """Stable temp ID for a trustee node. Prefer SID, fall back to name."""
    sid = ace.get("trustee_sid", "")
    if sid:
        return _node_id("sid", sid)
    return _node_id("principal", _principal_label(ace))


def parse_bof_output_detailed(
    text: str,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Extract JSON records from the BOF console output.

    Skips non-JSON header/footer lines (e.g. start/done events) and malformed
    lines, returning only share records that contain a 'share_name' key. A
    malformed line is reported separately so upload callers cannot mistake a
    partially parsed capture for a complete one.
    """
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        m = SHAREACL_PREFIX.match(line)
        if not m:
            continue
        try:
            record = json.loads(m.group(1))
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number}: invalid ShareACL JSON: {exc.msg}")
            continue
        if not isinstance(record, dict):
            errors.append(f"line {line_number}: ShareACL record is not a JSON object")
            continue
        if record.get("share_name"):
            records.append(record)
    return records, errors


def parse_bof_output(text: str) -> List[Dict[str, Any]]:
    """Extract valid share records while preserving the legacy API."""
    records, _errors = parse_bof_output_detailed(text)
    return records


def _highest_access(acls: List[Dict[str, Any]]) -> str:
    """Return the highest observed access level across allowed ACEs."""
    best = "UNKNOWN"
    best_rank = _ACCESS_RANK.get(best, -99)
    for ace in acls:
        if ace.get("ace_type") == "ACCESS_DENIED":
            continue
        eff = ace.get("effective_access", "UNKNOWN")
        rank = _ACCESS_RANK.get(eff, -99)
        if rank > best_rank:
            best_rank = rank
            best = eff
    return best


def _is_interesting(share_name: str, acls: List[Dict[str, Any]]) -> bool:
    """Flag shares that are hidden AND have broad write/full access."""
    if not share_name.endswith("$"):
        return False
    broad = {"Everyone", "Authenticated Users", "Domain Users", "Users"}
    for ace in acls:
        if ace.get("ace_type") != "ACCESS_ALLOWED":
            continue
        label = _principal_label(ace).lower()
        if any(b.lower() in label for b in broad):
            if ace.get("effective_access") in {"FULL", "WRITE"}:
                return True
    return False


def to_flowsint_batch(
    records: List[Dict[str, Any]],
    discovered_via: str = "shareacl_bof",
    source_host: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Convert shareacl records to Flowsint batch-import nodes and edges.

    Returns (nodes, edges) where:
      - FileShare nodes are keyed by lowercase UNC path.
      - Trustee nodes (Individual/Group/Computer) are keyed by SID or name.
      - Edges are labelled HAS_PERMISSION and carry the ACE details.
    """
    nodes_by_id: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    for rec in records:
        host = source_host or rec.get("host", "unknown")
        share_name = rec.get("share_name", "")
        unc = rec.get("unc_path", f"\\\\{host}\\{share_name}").lower()

        share_id = _node_id("share", unc)
        highest = _highest_access(rec.get("acls", []))

        nodes_by_id[share_id] = {
            "id": share_id,
            "node_id": share_id,
            "entity_type": "FileShare",
            "nodeLabel": unc,
            "include": True,
            "data": {
                "unc_path": unc,
                "share_name": share_name,
                "host": host.lower(),
                "access_type": highest if highest != "UNKNOWN" else None,
                "is_hidden": share_name.endswith("$"),
                "discovered_via": discovered_via,
                "source": rec.get("source", discovered_via),
                "share_type": rec.get("share_type"),
                "acl_error_code": rec.get("error_code"),
                "interesting_share": _is_interesting(share_name, rec.get("acls", [])),
            },
        }

        for ace in rec.get("acls", []):
            principal_id = _principal_temp_id(ace)
            label = _principal_label(ace)
            entity_type = _principal_entity_type(ace.get("trustee_type"))

            if principal_id not in nodes_by_id:
                nodes_by_id[principal_id] = {
                    "id": principal_id,
                    "node_id": principal_id,
                    "entity_type": entity_type,
                    "nodeLabel": label,
                    "include": True,
                    "data": {
                        "sid": ace.get("trustee_sid"),
                        "name": ace.get("trustee_name"),
                        "domain": ace.get("trustee_domain"),
                        "trustee_type": ace.get("trustee_type"),
                        "discovered_via": discovered_via,
                    },
                }

            eff = ace.get("effective_access", "UNKNOWN").upper()
            rel_label = f"SHARE_{eff}" if eff in {"READ", "WRITE", "FULL", "EXECUTE", "DENY"} else "SHARE_CUSTOM"

            edges.append({
                "from_id": principal_id,
                "to_id": share_id,
                "label": rel_label,
                "data": {
                    "permission_type": rel_label,
                    "ace_type": ace.get("ace_type"),
                    "access_mask": ace.get("access_mask"),
                    "access_mask_hex": ace.get("access_mask_hex"),
                    "rights": ace.get("rights", []),
                    "effective_access": eff,
                    "source": discovered_via,
                },
            })

    return list(nodes_by_id.values()), edges


def normalize(
    bof_text: str,
    discovered_via: str = "shareacl_bof",
    source_host: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Convenience helper: BOF text -> (nodes, edges)."""
    records = parse_bof_output(bof_text)
    return to_flowsint_batch(records, discovered_via, source_host)


def normalize_file(
    path: str,
    discovered_via: str = "shareacl_bof",
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Parse a file containing saved shareacl BOF console output."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    return normalize(text, discovered_via)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <bof_output_file>")
        sys.exit(1)

    nodes, edges = normalize_file(sys.argv[1])
    print(json.dumps({"nodes": nodes, "edges": edges}, indent=2))
