#!/usr/bin/env python3
"""
ingest_eyewitness.py — Host-side ingest for EyeWitness web-recon output that is too
large to base64 through the web UI.

WHY THIS EXISTS
    A wide web sweep (a /16 of http(s) endpoints, or an Nmap-XML-driven run) produces
    a `screens/` directory of hundreds or thousands of PNGs. The browser upload path
    (WF06 `/webhook/upload`) base64-encodes the whole zip into one JSON body and is
    capped at ~90 MB decoded — a real sweep blows past that.

    This reads the EyeWitness output in place, parses only `Requests.csv`, copies each
    screenshot into the served screenshots directory, and writes the Website/Ip nodes
    straight to Flowsint using the same library code the workflow uses
    (eyewitness_parser + flowsint_client). Same parser, same importer, same result.

    Accepts either an EyeWitness output DIRECTORY (read in place) or a .zip of one.

FAILS LOUD, NOT GREEN
    Preconditions are checked up front and post-import node counts are read back per
    label and compared against what the parser produced — the failure this exists to
    avoid is the silent one: an ingest that reports success and lands nothing.

SCREENSHOTS
    --screenshots-dir defaults to the repo's `screenshots/` directory, which is the
    host side of the bind mount nginx serves (auth-gated) at /screenshots/. When
    running on a box that is not the SPOTTER host, point it wherever that mount's host
    path is, or omit it to ingest metadata only.

USAGE
    # Measure first — parses and reports what would land, writes nothing:
    python3 scripts/ingest_eyewitness.py --input ./ew-out --campaign demo-01 --dry-run

    # Then ingest:
    python3 scripts/ingest_eyewitness.py --input ./ew-out --campaign demo-01

    Re-running is safe: Flowsint MERGEs nodes on nodeLabel (the URL), so a repeated
    ingest updates in place instead of duplicating.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPTS_DIR)
sys.path.insert(0, SCRIPTS_DIR)

# Environment, sketch resolution and post-import verification are shared with the
# other large-ingest paths — one place to fix when the API URL or campaign registry
# shape changes.
from ingest_sharphound_large import (          # noqa: E402
    DEFAULT_ENV_FILE,
    _count_by_label,
    _count_edges,
    _human_bytes,
    _log,
    _prepare_environment,
    _resolve_sketch,
)

DEFAULT_SCREENSHOTS_DIR = os.environ.get(
    "SPOTTER_SCREENSHOTS_DIR", os.path.join(REPO_ROOT, "screenshots"))


def _collect_inputs(paths: List[str]) -> List[str]:
    """Expand --input arguments to concrete EyeWitness outputs, oldest first."""
    resolved: List[str] = []
    for raw in paths:
        path = os.path.abspath(os.path.expanduser(raw))
        if not os.path.exists(path):
            raise SystemExit(f"ERROR: {path} does not exist")
        if os.path.isfile(path):
            resolved.append(path)
            continue
        # A directory is either an EyeWitness output itself (has Requests.csv), or a
        # folder of them.
        if any(n.lower() == "requests.csv" for n in os.listdir(path)):
            resolved.append(path)
            continue
        nested = [os.path.join(path, e) for e in sorted(os.listdir(path))]
        nested = [p for p in nested
                  if p.endswith(".zip")
                  or (os.path.isdir(p)
                      and any(n.lower() == "requests.csv" for n in os.listdir(p)))]
        if not nested:
            raise SystemExit(
                f"ERROR: {path} holds no EyeWitness output.\n"
                f"       Expected Requests.csv in it, or subdirectories/zips that "
                f"contain one (run EyeWitness in multi mode: -f urls.txt / -x scan.xml)."
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
        description="Ingest EyeWitness output directly into a campaign's sketch.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--input", action="append", required=True, metavar="PATH",
                    help="EyeWitness output directory or .zip (repeatable)")
    ap.add_argument("--campaign", default="", help="campaign name, e.g. demo-01")
    ap.add_argument("--sketch-id", default="", help="explicit sketch UUID (overrides --campaign)")
    ap.add_argument("--screenshots-dir", default=DEFAULT_SCREENSHOTS_DIR,
                    help="writable root nginx serves at /screenshots/ "
                         f"(default: {DEFAULT_SCREENSHOTS_DIR})")
    ap.add_argument("--no-screenshots", action="store_true",
                    help="ingest metadata only; do not copy PNGs")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse and report what would land; write nothing")
    ap.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    ap.add_argument("--json", action="store_true", help="emit a machine-readable summary")
    args = ap.parse_args(argv)

    inputs = _collect_inputs(args.input)
    _prepare_environment(args.env_file)

    import flowsint_client as fc                       # after _prepare_environment
    from eyewitness_parser import parse_bytes, parse_directory

    sketch_id = "" if args.dry_run and not (args.campaign or args.sketch_id) \
        else _resolve_sketch(fc, args.campaign, args.sketch_id)

    # Screenshots are written on parse, so a dry run must not touch disk. Website is
    # a built-in type, so there is no custom-type registration guard to run.
    shot_dir = None if (args.dry_run or args.no_screenshots) else args.screenshots_dir
    if shot_dir:
        try:
            os.makedirs(shot_dir, exist_ok=True)
        except Exception as exc:
            _log(f"WARNING: cannot write {shot_dir} ({exc}); ingesting metadata only.")
            shot_dir = None

    before = _count_by_label(fc, sketch_id) if sketch_id and not args.dry_run else {}
    summary: Dict[str, object] = {"inputs": [], "sketch_id": sketch_id,
                                  "screenshots_dir": shot_dir}
    total_nodes = total_edges = 0
    failures = 0

    for path in inputs:
        _log(f"reading {path} ({_human_bytes(_dir_bytes(path))})")
        if os.path.isdir(path):
            result = parse_directory(path, sketch_id=sketch_id or None,
                                     screenshots_dir=shot_dir)
        else:
            with open(path, "rb") as fh:
                result = parse_bytes(fh.read(), sketch_id=sketch_id or None,
                                     screenshots_dir=shot_dir)

        nodes, edges = result.to_flowsint_batch()
        info = result.summary()
        _log(f"  parsed  : {len(nodes)} nodes, {len(edges)} edges "
             f"({info['hosts']} web endpoints, {info['with_screenshot']} screenshots, "
             f"{info['with_default_creds']} default-cred hits, {info['high_value']} high-value)")
        _log(f"  by cat  : {json.dumps(info['by_category'])}")
        for err in result.errors:
            _log(f"  ! {err}")
        total_nodes += len(nodes)
        total_edges += len(edges)

        entry = {"path": path, "nodes": len(nodes), "edges": len(edges),
                 "report": info, "errors": result.errors}

        if not args.dry_run and nodes:
            ingestion = fc.batch_import(nodes, edges, sketch_id=sketch_id)
            created = ingestion.get("nodes_created", 0)
            entry["ingestion"] = ingestion
            # batch_import's edges_created counts only the cross-chunk pass, so a
            # small import can report 0 while every edge landed; the authoritative
            # number is the sketch-wide edge count read back below.
            _log(f"  imported: {created} nodes ({len(edges)} edges submitted)")
            if created == 0:
                failures += 1
                _log("  ! import produced 0 nodes — graph NOT updated for this input")
            for err in ingestion.get("errors", [])[:10]:
                _log(f"  ! {err}")
        summary["inputs"].append(entry)

    summary["parsed_nodes"] = total_nodes
    summary["parsed_edges"] = total_edges

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
        if total_nodes and not summary["graph_delta"]:
            _log("NOTE: no new nodes. Expected on a re-ingest; otherwise check the "
                 "errors above and confirm the sketch is the one you meant.")

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
