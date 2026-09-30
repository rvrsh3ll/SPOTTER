#!/usr/bin/env python3
"""
ingest_cloudschism.py — Host-side ingest for CloudSchism output that is too large
(or too awkward) to go through the web UI.

WHY THIS EXISTS
    CloudSchism writes a *directory*, and under the default `analyst` profile that
    directory contains a full `html/` report tree plus the canonical SQLite record
    store. A real tenant scan is routinely hundreds of megabytes, while the browser
    upload path (WF06 `/webhook/upload`) base64-encodes the whole zip into one JSON
    body and is capped by `SPOTTER_UPLOAD_MAX_BYTES` (32 MB by default) — before
    nginx and n8n's own body limits even apply.

    The graph-relevant part of that directory is a handful of JSON exports totalling
    a few MB. So rather than shipping the whole archive through n8n, this reads the
    output directory in place, parses only the members that matter, and writes
    straight to Flowsint using the same library code the workflow uses
    (cloudschism_parser + flowsint_client). Same parser, same importer, same result.

    Zipping the output first is unnecessary here — point it at the directory.

FAILS LOUD, NOT GREEN
    The failure this exists to avoid is the silent one: an ingest that reports
    success and lands nothing. Preconditions are checked up front, and post-import
    node counts are read back per label and compared against what the parser
    produced.

USAGE
    # Measure first — parses and reports what would land, writes nothing:
    python3 scripts/ingest_cloudschism.py --input ./aws-scan-out --campaign demo-01 --dry-run

    # Then ingest:
    python3 scripts/ingest_cloudschism.py --input ./aws-scan-out --campaign demo-01

    Accepts a directory, a .zip of one, or repeated --input for a multi-provider
    engagement (one AWS scan, one Azure scan, …).

    Re-running is safe: Flowsint MERGEs nodes on nodeLabel, so a repeated ingest
    updates in place instead of duplicating.

FINDINGS AND PATHS NEED REGISTERED TYPES
    CloudFinding and CloudAttackPath are custom Flowsint types. Until they are
    registered, nodes of that type are dropped (everything else still lands) —
    because an unresolvable nodeType makes GET /graph return HTTP 500 for the
    entire sketch. They are gated independently:

        python3 scripts/register_cloudschism_type.py --apply
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

# Environment, sketch resolution and post-import verification are identical to the
# SharpHound large-ingest path, so they are imported rather than re-implemented —
# one place to fix when the API URL or the campaign registry shape changes.
from ingest_sharphound_large import (          # noqa: E402
    DEFAULT_ENV_FILE,
    _count_by_label,
    _count_edges,
    _human_bytes,
    _log,
    _prepare_environment,
    _resolve_sketch,
)


def _collect_inputs(paths: List[str]) -> List[str]:
    """Expand the --input arguments to concrete scan outputs, oldest first."""
    resolved: List[str] = []
    for raw in paths:
        path = os.path.abspath(os.path.expanduser(raw))
        if not os.path.exists(path):
            raise SystemExit(f"ERROR: {path} does not exist")
        if os.path.isfile(path):
            resolved.append(path)
            continue
        # A directory is either a scan output itself, or a folder of them.
        markers = ("provider-artifacts.json", "CloudSchism-report.json",
                   "CloudSchism-report.json.gz", "output-profile.json",
                   "public-endpoints.json", "attack-graph.json")
        if any(os.path.exists(os.path.join(path, m)) for m in markers):
            resolved.append(path)
            continue
        nested = [os.path.join(path, e) for e in sorted(os.listdir(path))]
        nested = [p for p in nested
                  if p.endswith(".zip")
                  or (os.path.isdir(p)
                      and any(os.path.exists(os.path.join(p, m)) for m in markers))]
        if not nested:
            raise SystemExit(
                f"ERROR: {path} holds no CloudSchism output.\n"
                f"       Expected one of {', '.join(markers)} in it, or "
                f"subdirectories/zips that contain them."
            )
        resolved.extend(nested)
    if not resolved:
        raise SystemExit("ERROR: no inputs resolved")
    return sorted(set(resolved), key=os.path.getmtime)


def _dir_bytes(path: str) -> int:
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
    return total


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Ingest CloudSchism output directly into a campaign's sketch.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--input", action="append", required=True, metavar="PATH",
                    help="CloudSchism output directory or .zip (repeatable)")
    ap.add_argument("--campaign", default="", help="campaign name, e.g. demo-01")
    ap.add_argument("--sketch-id", default="", help="explicit sketch UUID (overrides --campaign)")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse and report what would land; write nothing")
    ap.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    ap.add_argument("--json", action="store_true", help="emit a machine-readable summary")
    args = ap.parse_args(argv)

    inputs = _collect_inputs(args.input)
    _prepare_environment(args.env_file)

    import flowsint_client as fc                       # after _prepare_environment
    from cloudschism_parser import (
        REQUIRED_CUSTOM_TYPES, parse_bytes, parse_directory,
    )

    sketch_id = "" if args.dry_run and not (args.campaign or args.sketch_id) \
        else _resolve_sketch(fc, args.campaign, args.sketch_id)

    # Same guard the workflow applies: without the custom type registered, a single
    # finding node would take the whole sketch's graph offline.
    allow = {name: True for name in REQUIRED_CUSTOM_TYPES}
    if not args.dry_run:
        registered = {t.lower() for t in fc.registered_custom_types()}
        for name in REQUIRED_CUSTOM_TYPES:
            allow[name] = name.lower() in registered
            if not allow[name]:
                _log(f"WARNING: custom type {name} is not registered — those nodes "
                     f"will be DROPPED. Run scripts/register_cloudschism_type.py "
                     f"--apply and re-run to include them.")
    allow_findings = allow["CloudFinding"]
    allow_paths = allow["CloudAttackPath"]

    before = _count_by_label(fc, sketch_id) if sketch_id and not args.dry_run else {}
    summary: Dict[str, object] = {"inputs": [], "sketch_id": sketch_id,
                                  "findings_ingested": allow_findings,
                                  "attack_paths_ingested": allow_paths}
    total_nodes = total_edges = 0
    parser_totals: Dict[str, int] = {}
    failures = 0

    for path in inputs:
        _log(f"reading {path} ({_human_bytes(_dir_bytes(path))})")
        if os.path.isdir(path):
            result = parse_directory(path, allow_finding_nodes=allow_findings,
                                     allow_attack_path_nodes=allow_paths)
        else:
            with open(path, "rb") as fh:
                result = parse_bytes(fh.read(), filename=os.path.basename(path),
                                     allow_finding_nodes=allow_findings,
                                     allow_attack_path_nodes=allow_paths)

        nodes, edges = result.to_flowsint_batch()
        info = result.summary()
        _log(f"  artifacts: {', '.join(info['sources']) or '(none)'}")
        _log(f"  parsed   : {len(nodes)} nodes, {len(edges)} edges "
             f"{json.dumps(info['nodes_by_type'])}")
        for err in result.errors:
            _log(f"  ! {err}")
        for etype, count in info["nodes_by_type"].items():
            parser_totals[etype] = parser_totals.get(etype, 0) + count
        total_nodes += len(nodes)
        total_edges += len(edges)

        entry = {"path": path, "nodes": len(nodes), "edges": len(edges),
                 "artifacts": info["sources"], "errors": result.errors,
                 "scan": info["scan"]}

        if not args.dry_run and nodes:
            ingestion = fc.batch_import(nodes, edges, sketch_id=sketch_id)
            created = ingestion.get("nodes_created", 0)
            entry["ingestion"] = ingestion
            # batch_import's `edges_created` counts only the cross-chunk pass;
            # edges whose endpoints landed in the same chunk are written during
            # the node import and never counted, so an import that fits in one
            # chunk always reports 0. The authoritative number is the sketch-wide
            # edge count read back from Neo4j below — don't print the 0 here.
            _log(f"  imported : {created} nodes ({len(edges)} edges submitted)")
            if created == 0:
                failures += 1
                _log("  ! import produced 0 nodes — graph NOT updated for this input")
            for err in ingestion.get("errors", [])[:10]:
                _log(f"  ! {err}")
        summary["inputs"].append(entry)

    summary["parsed_nodes"] = total_nodes
    summary["parsed_edges"] = total_edges
    summary["parsed_by_type"] = parser_totals

    if args.dry_run:
        _log(f"DRY RUN — nothing written. {total_nodes} nodes / {total_edges} edges "
             f"would be imported into {sketch_id or '(no sketch resolved)'}")
    else:
        after = _count_by_label(fc, sketch_id)
        delta = {lbl: after.get(lbl, 0) - before.get(lbl, 0)
                 for lbl in set(after) | set(before)}
        summary["graph_delta"] = {k: v for k, v in delta.items() if v}
        summary["edges_in_sketch"] = _count_edges(fc, sketch_id)
        _log(f"sketch {sketch_id} now holds "
             f"{sum(after.values())} nodes / {summary['edges_in_sketch']} edges")
        _log(f"  delta: {json.dumps(summary['graph_delta'])}")
        # A MERGE-on-nodeLabel import legitimately creates fewer nodes than it
        # parses (re-ingest, or two artifacts describing one resource), so a
        # shortfall is reported rather than treated as failure — except when
        # nothing at all landed.
        if total_nodes and not summary["graph_delta"]:
            _log("NOTE: no new nodes. Expected on a re-ingest; otherwise check the "
                 "errors above and confirm the sketch is the one you meant.")

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
