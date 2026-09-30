#!/usr/bin/env python3
"""
ingest_nessus_large.py — Host-side ingest for Nessus reports too large for the
web UI: the .nessus XML export, or a big CSV export.

WHY THIS EXISTS
    The browser / WF06 `/webhook/upload` path base64-encodes the whole file into
    a single JSON body, which is capped by nginx `client_max_body_size` (128 MB),
    `N8N_PAYLOAD_SIZE_MAX` (128 MB) and `SPOTTER_UPLOAD_MAX_BYTES` (90 MB raw).
    A .nessus XML is the most verbose Nessus export there is — routinely several
    times the size of the same scan's CSV — so an AD-scale scan cannot use that
    path at all. Unlike SharpHound and EyeWitness, Nessus had no host-side path,
    which meant a large scan could not be ingested by any route.

    So for a big report we skip n8n: parse on the host with real RAM and write
    straight to Flowsint + Neo4j using the same library code the webhook uses
    (nessus_parser + flowsint_client). Same parser, same importer, same result.

STREAMS THE XML, DOES NOT LOAD IT WHOLE
    nessus_parser.parse_file streams a .nessus export with ElementTree.iterparse,
    clearing each element as it closes, so peak memory tracks the accumulating
    graph (deduped plugins, per-host findings) rather than the size of the file.
    A multi-gigabyte .nessus does not have to fit in memory as a DOM tree.

FAILS LOUD, NOT GREEN
    The bug this exists to avoid is the silent one — a run that reports success
    and lands nothing. Every precondition is checked up front and every failure
    exits non-zero:
      * the target sketch must actually exist (a stale id 404s every write while
        "succeeding"),
      * the Vulnerability custom type must be registered before findings are
        written — an unresolvable nodeType makes GET /graph 500 for the WHOLE
        sketch, not just that node (run scripts/register_nessus_type.py --apply);
        pass --skip-vuln-nodes to deliberately import hosts + technologies only,
      * the Neo4j bulk-edge fast path is checked before a large import starts
        (the REST fallback creates edges slowly and truncates at 100k nodes),
      * post-import node counts are read back per label and reported.

USAGE
    # Measure first — parses and reports counts, writes nothing:
    python3 scripts/ingest_nessus_large.py --input scan.nessus --campaign demo-01 --dry-run

    # Then ingest:
    python3 scripts/ingest_nessus_large.py --input scan.nessus --campaign demo-01

    Accepts repeated --input, a big .nessus OR .csv, and a directory (every
    *.nessus / *.csv inside it, oldest first). Re-running is safe: Flowsint MERGEs
    on nodeLabel, so an interrupted import resumes by skipping what already landed.

AFTERWARDS
    The webhook path fires WF25 (/webhook/vuln-context) automatically; this one
    does not. Contextualize the findings once ingest is done — from the Tech Intel
    tab's "Contextualize" button, or on the host (--verify only READS back, so run
    the bare command first to actually contextualize):
        python3 scripts/nessus_context.py --sketch <sketch-id>
        python3 scripts/nessus_context.py --sketch <sketch-id> --verify
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Optional

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

# Environment, sketch resolution and post-import verification are shared with the
# other large-ingest paths — one place to fix when the API URL or campaign
# registry shape changes.
from ingest_sharphound_large import (          # noqa: E402
    DEFAULT_ENV_FILE,
    _count_by_label,
    _count_edges,
    _human_bytes,
    _log,
    _mem_available_bytes,
    _peak_rss_gb,
    _prepare_environment,
    _resolve_sketch,
)

# The formats parse_file understands. .nessus is the reason this script exists; a
# large CSV export can also outgrow the webhook cap, and the same parser reads it.
_NESSUS_EXTS = (".nessus", ".csv")

# Advisory only. The parser streams the file, so peak RSS tracks the graph it
# builds — deduped plugins plus per-(host,plugin) findings, each holding up to
# ~800 chars of plugin output — not the raw file size. There is no clean measured
# constant like SharpHound's here (the ratio swings with how findings-dense the
# scan is), so this is a soft warning, not a hard refusal.
_RSS_ADVISORY_MULTIPLE = 4.0


def _collect_inputs(paths: List[str]) -> List[str]:
    """Expand --input arguments into concrete report files, oldest mtime first."""
    found: List[str] = []
    for raw in paths:
        path = os.path.abspath(os.path.expanduser(raw))
        if os.path.isdir(path):
            found.extend(
                os.path.join(path, f) for f in os.listdir(path)
                if f.lower().endswith(_NESSUS_EXTS)
            )
        elif os.path.isfile(path):
            found.append(path)
        else:
            raise SystemExit(f"ERROR: no such file or directory: {path}")
    if not found:
        raise SystemExit(
            "ERROR: no .nessus / .csv reports found in the given paths"
        )
    return sorted(set(found), key=os.path.getmtime)


def _preflight_memory(paths: List[str], force: bool) -> None:
    """Report input sizes vs available RAM; warn (do not refuse) if it looks tight."""
    total = sum(os.path.getsize(p) for p in paths)
    available = _mem_available_bytes()
    estimate = int(total * _RSS_ADVISORY_MULTIPLE)
    _log("── preflight ─────────────────────────────────────────")
    for p in paths:
        _log(f"   {os.path.basename(p):<48} {_human_bytes(os.path.getsize(p))}")
    _log(f"   total on disk           : {_human_bytes(total)}")
    _log(f"   rough peak-memory guide : {_human_bytes(estimate)} "
         f"(~{_RSS_ADVISORY_MULTIPLE}x, advisory — the file is streamed)")
    _log(f"   memory available now    : {_human_bytes(available)}")
    if available and estimate > available * 0.8 and not force:
        _log("   WARNING: this report may be memory-heavy relative to free RAM. "
             "The file is streamed so it will likely still fit, but if it OOMs, "
             "ingest the reports one at a time (--input each) or free memory.")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Ingest a large Nessus (.nessus XML or CSV) report into a SPOTTER campaign.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--input", action="append", required=True, metavar="PATH",
                    help="a .nessus / .csv report or a directory of them; repeatable")
    ap.add_argument("--campaign", default="", help="campaign name, e.g. demo-01")
    ap.add_argument("--sketch-id", default="", help="explicit sketch UUID (overrides --campaign)")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse and report counts; write nothing")
    ap.add_argument("--include-info", action="store_true",
                    help="keep severity-None informational plugins as nodes "
                         "(default: skipped but still mined for OS/CPE facts)")
    ap.add_argument("--skip-vuln-nodes", action="store_true",
                    help="import hosts + technologies only, no Vulnerability nodes "
                         "(use when the custom type is not registered)")
    ap.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    ap.add_argument("--force", action="store_true",
                    help="silence the preflight memory warning and proceed")
    ap.add_argument("--allow-rest-edges", action="store_true",
                    help="proceed even if the Neo4j bulk-edge fast path is unavailable "
                         "(the REST fallback is slow and truncates at 100k nodes)")
    args = ap.parse_args(argv)

    _prepare_environment(args.env_file)
    import flowsint_client as fc                          # noqa: E402 (env first)
    from nessus_parser import VULN_NODE_TYPE, parse_file  # noqa: E402

    _log(f"flowsint api : {fc.API_URL}")
    _log(f"neo4j http   : {os.environ.get('NEO4J_HTTP_URL', '(unset)')}")

    inputs = _collect_inputs(args.input)
    total_bytes = sum(os.path.getsize(p) for p in inputs)
    _log(f"reports      : {len(inputs)} ({_human_bytes(total_bytes)} total)")

    _preflight_memory(inputs, args.force)

    # Preconditions, all before any parsing work. A dry run may omit the target
    # (pure "how big / how many findings?" mode), but a named target is validated
    # even on a dry run — surfacing a bad sketch id before a long parse is the point.
    if args.campaign or args.sketch_id:
        sketch_id = _resolve_sketch(fc, args.campaign, args.sketch_id)
    elif args.dry_run:
        sketch_id = ""
        _log("target sketch: (none given — dry run will only report parse results)")
    else:
        raise SystemExit("ERROR: specify --campaign NAME or --sketch-id UUID")

    # The Vulnerability custom type must exist before its nodes are written, or the
    # whole sketch's /graph read 500s. Checked here so a real ingest refuses up
    # front rather than poisoning the graph — the same guard upload_router applies.
    allow_vuln_nodes = not args.skip_vuln_nodes
    if allow_vuln_nodes and not args.dry_run:
        try:
            registered = fc.is_type_registered(VULN_NODE_TYPE)
        except Exception as exc:                          # unreachable API, etc.
            raise SystemExit(f"ERROR: could not check custom types: {exc}")
        if not registered:
            raise SystemExit(
                f"ERROR: the {VULN_NODE_TYPE!r} custom type is not registered. Writing\n"
                f"       its nodes would make GET /graph 500 for the entire sketch.\n"
                f"       Run: python3 scripts/register_nessus_type.py --apply\n"
                f"       then re-run this ingest — or pass --skip-vuln-nodes to import\n"
                f"       hosts and technologies only."
            )

    bulk_ok = fc._neo4j_enabled()
    _log(f"neo4j bulk-edge fast path: {'available' if bulk_ok else 'UNAVAILABLE'}")
    if not args.dry_run and not bulk_ok and not args.allow_rest_edges:
        raise SystemExit(
            "ERROR: the Neo4j bulk-edge fast path is unavailable (NEO4J_HTTP_URL /\n"
            "       NEO4J_PASSWORD not set or unreachable). The REST fallback creates\n"
            "       edges slowly and resolves them through a full-graph read that\n"
            "       truncates at 100k nodes. Fix the Neo4j settings, or pass\n"
            "       --allow-rest-edges to accept that cost deliberately."
        )

    include_info = True if args.include_info else None    # None ⇒ read the env flag
    before = _count_by_label(fc, sketch_id) if (sketch_id and not args.dry_run) else {}
    if before:
        _log(f"sketch already holds: {before} (re-runs skip existing nodes)")

    grand_nodes = grand_edges = 0
    grand_findings = grand_hosts = grand_plugins = 0
    failures: List[str] = []

    for path in inputs:
        _log(f"── parsing {os.path.basename(path)} ─────────────────────────")
        t0 = time.time()
        try:
            result = parse_file(path, allow_vuln_nodes=allow_vuln_nodes,
                                include_info=include_info)
        except Exception as exc:
            failures.append(f"{os.path.basename(path)}: parse failed: {exc}")
            _log(f"   PARSE FAILED: {exc}")
            continue

        nodes, edges = result.to_flowsint_batch()
        s = result.summary()
        grand_nodes += len(nodes)
        grand_edges += len(edges)
        grand_findings += s["findings"]
        grand_hosts += s["hosts"]
        grand_plugins += s["plugins"]
        _log(f"   format {result.source_format} | {s['hosts']:,} hosts | "
             f"{s['plugins']:,} plugins | {s['findings']:,} findings | "
             f"{s['technologies']:,} tech | {len(nodes):,} nodes / {len(edges):,} edges | "
             f"{time.time() - t0:,.1f}s | peak RSS {_peak_rss_gb():.1f} GB")
        # A parser error here is often the load-bearing signal (an XML that broke
        # off mid-file, an all-informational report, a cap hit) — surface it.
        if result.errors:
            _log(f"   parser reported {len(result.errors)} note(s):")
            for e in result.errors[:5]:
                _log(f"     - {e}")

        if args.dry_run:
            _log("   dry run — nothing written")
            continue

        if not nodes:
            _log("   nothing to import from this report")
            continue

        # Progress for the chunked node import. flowsint_client has no progress
        # hook, so wrap its chunk call rather than reimplementing the batching.
        done = {"n": 0}
        original_import_execute = fc._import_execute

        def _with_progress(chunk, chunk_edges, sid, _orig=original_import_execute,
                           _total=len(nodes)):
            res = _orig(chunk, chunk_edges, sid)
            done["n"] += len(chunk)
            if done["n"] % (fc._IMPORT_CHUNK * 20) < fc._IMPORT_CHUNK or done["n"] >= _total:
                pct = 100.0 * done["n"] / max(_total, 1)
                _log(f"   nodes {done['n']:,}/{_total:,} ({pct:.0f}%)")
            return res

        fc._import_execute = _with_progress
        t1 = time.time()
        try:
            outcome = fc.batch_import(nodes, edges, sketch_id=sketch_id)
        except Exception as exc:
            failures.append(f"{os.path.basename(path)}: import failed: {exc}")
            _log(f"   IMPORT FAILED: {exc}")
            continue
        finally:
            fc._import_execute = original_import_execute

        _log(f"   imported in {time.time() - t1:,.1f}s — created "
             f"{outcome.get('nodes_created', 0):,}, skipped "
             f"{outcome.get('nodes_skipped', 0):,}, edges {outcome.get('edges_created', 0):,}")
        errs = outcome.get("errors") or []
        if errs:
            failures.append(f"{os.path.basename(path)}: {len(errs)} import error(s)")
            _log(f"   {len(errs)} import error(s); first 5:")
            for e in errs[:5]:
                _log(f"     - {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    _log(f"parsed totals: {grand_hosts:,} hosts / {grand_plugins:,} plugins / "
         f"{grand_findings:,} findings | {grand_nodes:,} nodes / {grand_edges:,} edges "
         f"| peak RSS {_peak_rss_gb():.1f} GB")

    if args.dry_run:
        _log("DRY RUN complete — nothing was written.")
        return 1 if failures else 0

    after = _count_by_label(fc, sketch_id)
    _log(f"sketch now holds {sum(after.values()):,} nodes / {_count_edges(fc, sketch_id):,} edges:")
    for lbl, c in sorted(after.items(), key=lambda kv: -kv[1]):
        delta = c - before.get(lbl, 0)
        _log(f"   {lbl:<18} {c:>10,}  (+{delta:,})")

    # Failure here means "nothing is in the sketch", not "nothing was added":
    # Flowsint MERGEs on nodeLabel, so re-running a completed import is a legitimate
    # no-op (that is what makes an interrupted run resumable). The graph label is
    # lowercase 'vulnerability' — batch_import lowercases custom types.
    total_after = sum(after.values())
    if total_after == 0:
        failures.append("nothing landed in the sketch — every write failed silently")
    elif total_after == sum(before.values()):
        _log("   note: no new nodes — these findings were already present "
             "(re-run/resume, not an error)")

    if failures:
        print()
        _log("COMPLETED WITH FAILURES:")
        for f in failures:
            _log(f"   - {f}")
        return 1

    print()
    _log("OK — ingest complete and verified.")
    _log("Next: contextualize the findings (exploit availability, ATT&CK, priority).")
    _log("Run it, then read it back (--verify only reads; it does NOT contextualize):")
    _log(f"   python3 scripts/nessus_context.py --sketch {sketch_id}")
    _log(f"   python3 scripts/nessus_context.py --sketch {sketch_id} --verify")
    return 0


if __name__ == "__main__":
    sys.exit(main())
