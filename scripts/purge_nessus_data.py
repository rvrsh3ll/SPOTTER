#!/usr/bin/env python3
"""
purge_nessus_data.py — Remove one campaign's ingested Nessus data, so a scan can
be re-imported cleanly.

WHY NOT JUST CLEAR THE GRAPH
----------------------------
WF07 / the Clear Graph button wipes the ENTIRE sketch — SharpHound, C2 sessions,
OSINT, everything. That is the right tool only when the campaign holds nothing
but the scan. This script removes the scan and leaves the rest standing.

WHY NOT THE FLOWSINT DELETE API
-------------------------------
`DELETE /api/sketches/{id}/nodes` is a **soft** delete: it sets `deleted_at` and
leaves the node in Neo4j (see the comment in WF07's code node, which says so
explicitly). Every reader filters `WHERE n.deleted_at IS NULL`, so a soft-deleted
node is invisible — but Flowsint MERGEs on `(node_type, nodeLabel, sketch_id)`
and MERGE does **not** filter on `deleted_at`. Re-importing the same report would
therefore merge straight back onto the tombstoned nodes, report a successful
import, and produce a graph where nothing can be read. That is the worst possible
outcome of a "clear and re-import", so this script hard-deletes through Neo4j the
same way WF07's durable path does.

WHAT IT REMOVES
---------------
  Vulnerability nodes            DETACH DELETE (takes HAS_VULNERABILITY with them)
  nessus_* properties on hosts   REMOVEd key by key, leaving the host node itself

WHAT IT DELIBERATELY LEAVES
---------------------------
  Device / Ip host nodes   They are shared with SharpHound, PingCastle and nmap.
                           DC01.CORP.LOCAL is the *same node* the AD ingest
                           created; deleting it to tidy up a scan would take the
                           domain controller's ACEs with it. Only the `nessus_*`
                           namespace is stripped — which is exactly why the
                           parser namespaces it. Use --drop-scan-only-hosts for
                           hosts that exist for no other reason.
  Technology nodes         A re-import MERGEs them by label, so leaving them is
                           idempotent, and a node may carry an nmap or
                           process-list contribution too. --drop-technologies
                           removes the ones Nessus wrote last.
  RESOLVES_TO / USES_TECH  Not distinguishable. Edge `data` does NOT survive
                           ingest: batch_import's bulk path and its REST fallback
                           both send only (from, to, label), so the `source`
                           marker written on these edges never reaches Neo4j.
                           They are also idempotent on re-import (the importer
                           skips pre-existing edges), so leaving them is correct.

LEGACY GARBAGE (--drop-legacy-csv)
----------------------------------
A Nessus CSV uploaded BEFORE the nessus format existed fell through to the
generic CSV branch, which reads a column literally called `name` as a person's
name. Every row under 10 000 became an `individual` node labelled with the plugin
name ("SSL Medium Strength Cipher Suites Supported"), carrying
`source='csv_upload'` and no username or email. Over 10 000 rows the branch
raised and nothing was imported at all.

Those nodes are reported separately and removed only with --drop-legacy-csv,
because a *legitimate* user-list upload also writes `source='csv_upload'` — the
only thing separating them is the missing username/email. Read the sample the
report prints before using the flag.

USAGE
-----
Run it inside the runner container. NEO4J_HTTP_URL points at `flowsint-neo4j-prod`,
a name that only resolves on the docker network — from the host it will simply
fail to connect. The runner already holds every variable this needs:

    RUN="docker exec spotter-n8n-runners \\
         /opt/runners/task-runner-python/.venv/bin/python /data/scripts/purge_nessus_data.py"

    $RUN --list                              # campaigns and their sketch ids
    $RUN --sketch <sketch-id>                # 1. REPORT ONLY. Changes nothing.
    $RUN --sketch <sketch-id> --apply        # 2. remove the findings

    # Optional extras, each opt-in:
    #   --drop-technologies      also remove Technology nodes Nessus wrote last
    #   --drop-scan-only-hosts   also remove hosts left with no other data or edges
    #   --drop-legacy-csv        also remove the pre-fix misparsed individuals

There is no Neo4j backup on this host. The report is not decoration.

Environment (same variables the workflows use):
    NEO4J_HTTP_URL, NEO4J_USER, NEO4J_PASSWORD    required — everything here,
                                                  including the campaign registry
                                                  behind --list, reads Neo4j
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import flowsint_client as fc  # noqa: E402


# Every property key the Nessus path writes onto a host node. Enumerated rather
# than matched by prefix because removing a dynamic key list needs APOC, which is
# not guaranteed to be installed. Keep in sync with:
#   nessus_parser.parse_bytes   (the host props block)
#   nessus_context.rollup_hosts (the patch dict)
NESSUS_HOST_KEYS = [
    "nessus_scanned",
    "nessus_seen_as_address",
    "nessus_finding_count",
    "nessus_critical_count",
    "nessus_high_count",
    "nessus_medium_count",
    "nessus_low_count",
    "nessus_info_count",
    "nessus_risk_score",
    "nessus_cve_exposure",
    "nessus_exploitable_findings",
    "nessus_cves",
    "nessus_cpes",
    "nessus_scan_date",
    "nessus_os",
    "nessus_netbios_name",
    "nessus_top_findings",
    "nessus_context_at",
]

# Neo4j stores Flowsint properties under a "nodeProperties." prefix.
_PROP = "nodeProperties."

# Nodes are deleted in batches so a large report cannot exceed the transaction
# timeout — the same shape WF07's purge loop uses.
_BATCH = 20000
_MAX_BATCHES = 500

# "This host exists for no reason other than the scan."
#
# The obvious test — "has no relationships left once the findings are gone" —
# misses the commonest case. A host known by BOTH name and address becomes a
# Device plus a companion Ip joined by RESOLVES_TO, so the pair holds each
# OTHER's only edge and neither ever looks orphaned. The USES_TECH edges to the
# Technology nodes the scan's own CPE enumeration created do the same thing.
#
# So the edges that do not count as evidence of a life outside the scan are
# RESOLVES_TO and USES_TECH edges to another nessus-sourced node — which also
# makes this test independent of whether --drop-technologies ran first.
#
# A host any other ingest touched is not matched: SharpHound devices carry ACE
# and membership edges, and a host nmap or the AD ingest wrote last has a
# different `source`.
_SCAN_ONLY_WHERE = (
    f"coalesce(n.`{_PROP}source`,'') = 'nessus' "
    "AND toLower(coalesce(n.nodeType,'')) IN ['device','ip'] "
    "AND size([(n)-[r]-(m) WHERE NOT (type(r) IN ['RESOLVES_TO','USES_TECH'] "
    f"AND coalesce(m.`{_PROP}source`,'') = 'nessus') | r]) = 0"
)


def _rows(statement: str, params: Optional[Dict[str, Any]] = None) -> List[List[Any]]:
    """Run one Cypher statement and return its rows. Raises on a Neo4j error."""
    body = fc._neo4j_commit(statement, params or {}, timeout=300)
    results = body.get("results") or [{}]
    return [r["row"] for r in (results[0].get("data") or [])]


def _scalar(statement: str, params: Optional[Dict[str, Any]] = None, default: Any = 0) -> Any:
    rows = _rows(statement, params)
    return rows[0][0] if rows and rows[0] else default


# ── Inspection ────────────────────────────────────────────────────────────────

def inspect(sketch_id: str) -> Dict[str, Any]:
    """
    What Nessus-attributable data this sketch holds, without changing anything.

    Matching is on `nodeType`, not on the Neo4j label: built-in types land as
    lowercase labels and custom types as PascalCase, and a graph assembled from
    several ingest paths carries both spellings. Keying on nodeType is correct
    whichever one this install produced.
    """
    out: Dict[str, Any] = {"sketch_id": sketch_id}

    out["total_nodes"] = _scalar(
        "MATCH (n {sketch_id:$s}) RETURN count(n)", {"s": sketch_id})
    out["total_nodes_alive"] = _scalar(
        "MATCH (n {sketch_id:$s}) WHERE n.deleted_at IS NULL RETURN count(n)",
        {"s": sketch_id})

    out["vulnerability_nodes"] = _scalar(
        "MATCH (n {sketch_id:$s}) "
        "WHERE toLower(coalesce(n.nodeType,'')) = 'vulnerability' RETURN count(n)",
        {"s": sketch_id})
    out["finding_edges"] = _scalar(
        "MATCH ({sketch_id:$s})-[r:HAS_VULNERABILITY]->() RETURN count(r)",
        {"s": sketch_id})

    scanned_key = _PROP + "nessus_scanned"
    out["hosts_with_nessus_props"] = _scalar(
        f"MATCH (n {{sketch_id:$s}}) WHERE n.`{scanned_key}` IS NOT NULL "
        "RETURN count(n)", {"s": sketch_id})

    # A host that exists for no reason other than the scan: Nessus flagged it,
    # Nessus was the last writer, and every edge it has is a finding edge — so
    # once step 1 removes those it would be left with nothing at all.
    # A pattern comprehension rather than an EXISTS{} subquery, which is Neo4j
    # 5-only; this form works on 4.x too.
    out["scan_only_hosts"] = _scalar(
        f"MATCH (n {{sketch_id:$s}}) WHERE {_SCAN_ONLY_WHERE} "
        "RETURN count(n)", {"s": sketch_id})

    out["nessus_technologies"] = _scalar(
        f"MATCH (n {{sketch_id:$s}}) "
        "WHERE toLower(coalesce(n.nodeType,'')) = 'technology' "
        f"AND coalesce(n.`{_PROP}source`,'') = 'nessus' RETURN count(n)",
        {"s": sketch_id})

    # Pre-fix misparse: individuals invented from plugin-name rows.
    legacy_where = (
        "toLower(coalesce(n.nodeType,'')) = 'individual' "
        f"AND coalesce(n.`{_PROP}source`,'') = 'csv_upload' "
        f"AND coalesce(n.`{_PROP}username`,'') = '' "
        f"AND coalesce(n.`{_PROP}email`,'') = ''"
    )
    out["legacy_csv_individuals"] = _scalar(
        f"MATCH (n {{sketch_id:$s}}) WHERE {legacy_where} RETURN count(n)",
        {"s": sketch_id})
    out["legacy_csv_sample"] = [
        r[0] for r in _rows(
            f"MATCH (n {{sketch_id:$s}}) WHERE {legacy_where} "
            "RETURN n.nodeLabel AS l LIMIT 10", {"s": sketch_id})
    ]
    # The strongest signal that these are real people rather than plugin rows:
    # a misparsed CSV row is emitted with no edges at all, so anything that has
    # since been enriched, given a session, or linked to a group is NOT scan
    # debris. --drop-legacy-csv is a DETACH DELETE and would take those edges too.
    out["legacy_csv_with_edges"] = _scalar(
        f"MATCH (n {{sketch_id:$s}}) WHERE {legacy_where} AND (n)-[]-() "
        "RETURN count(n)", {"s": sketch_id})

    # Context for the operator: what else is in here that must survive.
    out["nodes_by_type"] = {
        (r[0] or "(none)"): r[1]
        for r in _rows(
            "MATCH (n {sketch_id:$s}) WHERE n.deleted_at IS NULL "
            "RETURN coalesce(n.nodeType,'') AS t, count(n) AS c ORDER BY c DESC",
            {"s": sketch_id})
    }
    return out


# ── Deletion ──────────────────────────────────────────────────────────────────

def _detach_delete(where: str, sketch_id: str) -> int:
    """Batched DETACH DELETE of every node matching `where`. Returns the count."""
    removed = 0
    for _ in range(_MAX_BATCHES):
        count = _scalar(
            f"MATCH (n {{sketch_id:$s}}) WHERE {where} "
            f"WITH n LIMIT {_BATCH} DETACH DELETE n RETURN count(n)",
            {"s": sketch_id})
        removed += count
        if not count:
            break
    return removed


def purge(sketch_id: str, drop_technologies: bool = False,
          drop_scan_only_hosts: bool = False,
          drop_legacy_csv: bool = False) -> Dict[str, Any]:
    """Hard-delete the scan data. Assumes the caller has read inspect()."""
    result: Dict[str, Any] = {"sketch_id": sketch_id, "errors": []}

    # 1. Findings. DETACH takes every HAS_VULNERABILITY edge with them.
    try:
        result["vulnerability_nodes_deleted"] = _detach_delete(
            "toLower(coalesce(n.nodeType,'')) = 'vulnerability'", sketch_id)
    except Exception as exc:
        result["errors"].append(f"vulnerability delete: {exc}")
        # Everything below assumes the findings are gone; stop rather than
        # half-clear a graph the operator is about to re-import into.
        return result

    # 2. Host properties. The node stays — it is shared with the AD ingest.
    removes = ", ".join(f"n.`{_PROP}{k}`" for k in NESSUS_HOST_KEYS)
    try:
        result["hosts_stripped"] = _scalar(
            f"MATCH (n {{sketch_id:$s}}) WHERE n.`{_PROP}nessus_scanned` IS NOT NULL "
            f"OR n.`{_PROP}nessus_seen_as_address` IS NOT NULL "
            f"WITH n REMOVE {removes} RETURN count(n)", {"s": sketch_id})
    except Exception as exc:
        result["errors"].append(f"host property strip: {exc}")

    # 3. Opt-in extras. Technologies BEFORE hosts: a scan-created Technology
    # holds its host by a USES_TECH edge, and deleting the host first would leave
    # the technology behind while deleting the technology first frees the host.
    # _SCAN_ONLY_WHERE discounts those edges anyway, so this ordering is belt to
    # that braces rather than the only thing making it work.
    if drop_technologies:
        try:
            result["technologies_deleted"] = _detach_delete(
                "toLower(coalesce(n.nodeType,'')) = 'technology' "
                f"AND coalesce(n.`{_PROP}source`,'') = 'nessus'", sketch_id)
        except Exception as exc:
            result["errors"].append(f"technology delete: {exc}")

    if drop_scan_only_hosts:
        try:
            # Runs after the findings (step 1) and the technologies above, so the
            # only edges left to reason about are the RESOLVES_TO companion pairs.
            result["scan_only_hosts_deleted"] = _detach_delete(
                _SCAN_ONLY_WHERE, sketch_id)
        except Exception as exc:
            result["errors"].append(f"scan-only host delete: {exc}")

    if drop_legacy_csv:
        try:
            result["legacy_csv_individuals_deleted"] = _detach_delete(
                "toLower(coalesce(n.nodeType,'')) = 'individual' "
                f"AND coalesce(n.`{_PROP}source`,'') = 'csv_upload' "
                f"AND coalesce(n.`{_PROP}username`,'') = '' "
                f"AND coalesce(n.`{_PROP}email`,'') = ''", sketch_id)
        except Exception as exc:
            result["errors"].append(f"legacy csv delete: {exc}")

    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sketch", default="",
                    help="sketch id to purge (default: most recent campaign)")
    ap.add_argument("--apply", action="store_true",
                    help="actually delete. Without it, nothing is written.")
    ap.add_argument("--drop-technologies", action="store_true",
                    help="also delete Technology nodes Nessus wrote last")
    ap.add_argument("--drop-scan-only-hosts", action="store_true",
                    help="also delete hosts left with no other data or edges")
    ap.add_argument("--drop-legacy-csv", action="store_true",
                    help="also delete individuals invented by a PRE-FIX Nessus "
                         "CSV upload (read the report's sample first)")
    ap.add_argument("--list", action="store_true",
                    help="list campaigns and their sketch ids, then exit")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    # Checked before --list too: the campaign registry lives in Neo4j as well, and
    # list_campaigns() swallows a connection failure and returns [] — which would
    # read as "you have no campaigns" rather than "I could not reach the database".
    if not fc._neo4j_enabled():
        print("error: NEO4J_HTTP_URL / NEO4J_PASSWORD are not set. Run this "
              "inside the runner container, which already has them:\n"
              "  docker exec spotter-n8n-runners "
              "/opt/runners/task-runner-python/.venv/bin/python "
              "/data/scripts/purge_nessus_data.py --list", file=sys.stderr)
        return 2

    if args.list:
        try:
            camps = fc.list_campaigns()
        except Exception as exc:                    # noqa: BLE001 - operator-facing
            print(f"error: could not read the campaign registry: {exc}",
                  file=sys.stderr)
            return 1
        if not camps:
            print("no campaigns in the registry")
            return 0
        for camp in camps:
            if not isinstance(camp, dict):
                continue
            print(f"  {str(camp.get('sketchId') or '(no sketch)'):<40} "
                  f"{camp.get('name') or camp.get('id') or '?'}")
        return 0

    sketch_id = args.sketch or fc.resolve_campaign_sketch()
    if not sketch_id:
        print("error: no sketch id resolved. Pass --sketch explicitly; this "
              "script refuses to run unscoped.", file=sys.stderr)
        return 2

    try:
        report = inspect(sketch_id)
    except Exception as exc:                        # noqa: BLE001 - operator-facing
        print(f"error: inspection failed: {exc}", file=sys.stderr)
        return 1

    if args.json and not args.apply:
        print(json.dumps(report, indent=2, default=str))
        return 0

    print(f"sketch {sketch_id}")
    print(f"  total nodes                 {report['total_nodes']} "
          f"({report['total_nodes_alive']} alive)")
    print(f"  Vulnerability nodes         {report['vulnerability_nodes']}")
    print(f"  HAS_VULNERABILITY edges     {report['finding_edges']}")
    print(f"  hosts carrying nessus_*     {report['hosts_with_nessus_props']}")
    print(f"  Technology (source=nessus)  {report['nessus_technologies']}")
    print(f"  hosts only the scan created {report['scan_only_hosts']}")
    print(f"  legacy misparsed individuals {report['legacy_csv_individuals']}")
    if report["legacy_csv_sample"]:
        print("    sample labels (these should look like PLUGIN NAMES, not people):")
        for label in report["legacy_csv_sample"]:
            print(f"      {label}")
        if report["legacy_csv_with_edges"]:
            print(f"    !! {report['legacy_csv_with_edges']} of them HAVE "
                  f"relationships. A misparsed CSV row is created with no edges, "
                  f"so these are probably real people — do NOT use "
                  f"--drop-legacy-csv without checking them individually.")
    print("  everything in this sketch, by type:")
    for node_type, count in report["nodes_by_type"].items():
        print(f"      {count:>8}  {node_type}")

    if not args.apply:
        print("\nDRY RUN — nothing was changed. Re-run with --apply to delete "
              "the Vulnerability nodes and strip nessus_* from the hosts.")
        if report["legacy_csv_individuals"]:
            print("Legacy individuals are NOT removed without --drop-legacy-csv. "
                  "A real user-list upload writes the same source marker, so "
                  "check the sample labels above first.")
        return 0

    # Every opt-in extra counts toward "is there anything to do", or a run that
    # asked only for --drop-scan-only-hosts short-circuits on the main counts
    # being zero and reports "nothing to delete" while leaving work undone.
    pending = (
        report["vulnerability_nodes"]
        or report["hosts_with_nessus_props"]
        or (args.drop_legacy_csv and report["legacy_csv_individuals"])
        or (args.drop_scan_only_hosts and report["scan_only_hosts"])
        or (args.drop_technologies and report["nessus_technologies"])
    )
    if not pending:
        print("\nNothing to delete — this sketch holds no Nessus data.")
        return 0

    print("\napplying…")
    out = purge(sketch_id,
                drop_technologies=args.drop_technologies,
                drop_scan_only_hosts=args.drop_scan_only_hosts,
                drop_legacy_csv=args.drop_legacy_csv)
    for key, value in out.items():
        if key not in ("sketch_id", "errors"):
            print(f"  {key:<32} {value}")
    for err in out["errors"]:
        print(f"  ! {err}")

    after = inspect(sketch_id)
    print(f"\nafter: {after['vulnerability_nodes']} Vulnerability nodes, "
          f"{after['finding_edges']} finding edges, "
          f"{after['hosts_with_nessus_props']} hosts carrying nessus_*")
    print("\nNext: clear the browser-side cache too, or the Tech Intel tab will "
          "keep showing the old findings —\n"
          "  DevTools console:  localStorage.removeItem('s.vulnScan')\n"
          "then remove the old entry from the Ingest tab's log and re-upload.")
    return 1 if out["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
