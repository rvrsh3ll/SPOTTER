#!/usr/bin/env python3
"""
ingest_sharphound_large.py — Host-side ingest for SharpHound archives that are
too large to go through the web UI or WF02.

WHY THIS EXISTS
    The browser upload path (WF06 `/webhook/upload`) base64-encodes the whole
    archive into a single JSON body. That inflates the file by 4/3 and is capped
    three times over: nginx `client_max_body_size` (128 MB), `N8N_PAYLOAD_SIZE_MAX`
    (128 MB) and `SPOTTER_UPLOAD_MAX_BYTES` (90 MB). A 700 MB collection is a
    ~930 MB body — it cannot use that path at any setting worth having.

    WF02's drop-folder path parses inside the n8n Python runner and returns the
    full `nodes` + `edges` arrays in the node's item JSON. n8n serialises item
    JSON into its SQLite execution store, so a multi-million-entity graph is
    written to SQLite as one blob. WF06 strips those arrays for exactly this
    reason ("a ~40MB node output overwhelms n8n's inter-node serialization");
    WF02 does not. At AD scale that destabilises n8n itself.

    So for big archives we skip n8n: parse on the host, where there is real RAM,
    and write straight to Flowsint + Neo4j using the same library code the
    workflows use (sharphound_parser + flowsint_client). Same parser, same
    importer, same result — just without the serialisation layer in the middle.

FAILS LOUD, NOT GREEN
    The bug this tooling exists to avoid is the silent one: an upload that is
    accepted, reports success, and lands nothing. Every precondition here is
    checked up front and every failure exits non-zero:
      * the target sketch must actually exist (a stale FLOWSINT_SKETCH_ID points
        at a deleted sketch and every write 404s while "succeeding"),
      * the Neo4j bulk-edge fast path must be available before a large import
        starts (the REST fallback reads the whole graph and truncates at 100k),
      * post-import node counts are read back per label and compared to what the
        parser produced, with any shortfall reported.

USAGE
    # Measure first — parses and reports counts, writes nothing:
    python3 scripts/ingest_sharphound_large.py --zip /path/coll.zip --campaign demo-01 --dry-run

    # Then ingest:
    python3 scripts/ingest_sharphound_large.py --zip /path/coll.zip --campaign demo-01

    Accepts repeated --zip, and a directory (all *.zip inside it, oldest first).
    Re-running is safe: Flowsint MERGEs nodes on nodeLabel, so an interrupted
    import resumes by skipping what already landed.

DO NOT stage a large archive in the WF02 drop folder. That folder is swept every
2 minutes and the archive would be parsed inside the runner — the failure mode
above. Stage it anywhere else (e.g. /root/SPOTTER/ingest-staging/). If the file
must live there, --claim-ledger records its fingerprint in the shared dedup
ledger first so WF02 skips it.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import socket
import sys
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
# The repo's own .env, derived from this file's location like every other script
# here. It used to name the Flowsint checkout's copy, which is only ever a
# SYMLINK to this one — and which moved when Flowsint was vendored.
DEFAULT_ENV_FILE = os.path.join(os.path.dirname(SCRIPTS_DIR), ".env")

# Published loopback ports for the two services, used when this script runs on
# the host and the .env values are Docker-network hostnames (see _hostify).
_LOOPBACK_PORTS = {"flowsint-api-prod": 5001, "flowsint-neo4j-prod": 7474}


# ── Environment ───────────────────────────────────────────────────────────────

def _load_env_file(path: str) -> Dict[str, str]:
    """Parse a docker-compose style .env into a dict (no interpolation)."""
    out: Dict[str, str] = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _hostify(url: str) -> str:
    """
    Rewrite a Docker-network URL to loopback when the hostname does not resolve.

    The .env is written for containers (http://flowsint-api-prod:5001). Run from
    the host, that name does not resolve; both services publish on 127.0.0.1, so
    swap the host and keep the scheme/path. A resolvable name is left untouched,
    which means this same script also works when run inside a container.
    """
    if not url:
        return url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    try:
        socket.getaddrinfo(host, None)
        return url
    except OSError:
        port = parsed.port or _LOOPBACK_PORTS.get(host)
        if not port:
            return url
        return urlunparse(parsed._replace(netloc=f"127.0.0.1:{port}"))


def _prepare_environment(env_file: str) -> None:
    """
    Populate os.environ BEFORE flowsint_client is imported.

    flowsint_client reads API_URL / API_KEY / NEO4J_* into module-level constants
    at import time, so anything set afterwards is ignored. Real environment
    variables win over the .env file.
    """
    # The secrets this needs (FLOWSINT_API_KEY, NEO4J_PASSWORD) are no longer in
    # .env -- they are in secrets/*.sops.env. Prefer the shared loader, which
    # returns the merged view, and fall back to the raw file scan so an install
    # that has not been split yet still works.
    try:
        sys.path.insert(0, SCRIPTS_DIR)
        import spotter_env
        file_env = spotter_env.load()
    except Exception:
        file_env = _load_env_file(env_file)
    for key in ("FLOWSINT_API_URL", "FLOWSINT_API_KEY", "FLOWSINT_SKETCH_ID",
                "NEO4J_HTTP_URL", "NEO4J_USER", "NEO4J_PASSWORD"):
        if not os.environ.get(key) and file_env.get(key):
            os.environ[key] = file_env[key]
    for key in ("FLOWSINT_API_URL", "NEO4J_HTTP_URL"):
        if os.environ.get(key):
            os.environ[key] = _hostify(os.environ[key])


# ── Reporting helpers ─────────────────────────────────────────────────────────

def _peak_rss_gb() -> float:
    """Peak resident set size of this process, in GB (Linux reports KB)."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024.0 * 1024.0)


def _human_bytes(n: int) -> str:
    val = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if val < 1024 or unit == "GB":
            return f"{val:,.1f} {unit}" if unit != "B" else f"{int(val):,} B"
        val /= 1024
    return f"{val:,.1f} GB"


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ── Archive discovery ─────────────────────────────────────────────────────────

# Peak RSS observed per byte of uncompressed JSON, measured on this stack:
# a ~300 MB JSON payload (hundreds of thousands of entities / over a million
# edges) peaked at ~2.2 GB. The cost is dominated by Python object overhead for
# the parsed dicts, which the parser holds entirely in memory, plus the
# duplicate list to_flowsint_batch() builds.
_RSS_PER_JSON_BYTE = 7.5


def _mem_available_bytes() -> int:
    """MemAvailable from /proc/meminfo — what we can actually use without swapping."""
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    return 0


def _preflight_memory(zips: List[str], force: bool) -> None:
    """
    Estimate peak memory from the ZIP central directory before decompressing.

    Reading the directory is effectively free (no member is inflated), so this
    can refuse an archive that would OOM the box instead of discovering it 20
    minutes in. The parser holds the whole collection in memory, so peak RSS
    tracks the *uncompressed* JSON size, not the archive size — and SharpHound
    JSON compresses 10-45x, which makes the archive size a poor predictor.
    """
    import zipfile

    total_uncompressed = 0
    _log("── preflight ─────────────────────────────────────────")
    for zpath in zips:
        try:
            with zipfile.ZipFile(zpath) as zf:
                members = [i for i in zf.infolist() if i.filename.lower().endswith(".json")]
        except Exception as exc:
            raise SystemExit(f"ERROR: cannot read {zpath} as a ZIP: {exc}")
        if not members:
            _log(f"   WARNING: {os.path.basename(zpath)} contains no .json members")
        sub = sum(i.file_size for i in members)
        total_uncompressed += sub
        comp = sum(i.compress_size for i in members) or 1
        _log(f"   {os.path.basename(zpath)}: {len(members)} json member(s), "
             f"{_human_bytes(sub)} uncompressed ({sub / comp:.1f}x)")
        for i in sorted(members, key=lambda m: -m.file_size)[:5]:
            _log(f"       {os.path.basename(i.filename):<40} {_human_bytes(i.file_size)}")

    estimate = int(total_uncompressed * _RSS_PER_JSON_BYTE)
    available = _mem_available_bytes()
    _log(f"   total uncompressed JSON : {_human_bytes(total_uncompressed)}")
    _log(f"   estimated peak memory   : {_human_bytes(estimate)} (~{_RSS_PER_JSON_BYTE}x, measured)")
    _log(f"   memory available now    : {_human_bytes(available)}")

    if available and estimate > available * 0.8:
        msg = (
            f"ERROR: this collection is estimated to need {_human_bytes(estimate)} of RAM but only\n"
            f"       {_human_bytes(available)} is available. The parser holds the whole graph in\n"
            f"       memory, so this would likely OOM partway through and leave a partial import.\n"
            f"       Options: ingest the archives one at a time (--zip each separately), free\n"
            f"       memory, or re-run with --force to proceed anyway."
        )
        if not force:
            raise SystemExit(msg)
        _log("   WARNING: estimate exceeds available memory; proceeding because --force was given")


def _collect_zips(paths: List[str]) -> List[str]:
    """Expand the --zip arguments into a concrete file list, oldest mtime first."""
    found: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            found.extend(
                os.path.join(p, f) for f in os.listdir(p) if f.lower().endswith(".zip")
            )
        elif os.path.isfile(p):
            found.append(p)
        else:
            raise SystemExit(f"ERROR: no such file or directory: {p}")
    if not found:
        raise SystemExit("ERROR: no .zip files found in the given paths")
    return sorted(set(found), key=os.path.getmtime)


# ── Sketch resolution (the silent-404 guard) ──────────────────────────────────

def _resolve_sketch(fc, campaign: str, sketch_id: str) -> str:
    """
    Resolve the destination sketch and prove it exists.

    An id that does not exist is the single most expensive failure in this
    system: every write 404s, the run still reports success, and the operator
    finds an empty graph hours later. So resolution never falls back silently —
    it either returns a sketch confirmed present in Flowsint, or exits.
    """
    sketches = {s["id"]: s.get("title", "") for s in fc.list_sketches()}

    if sketch_id:
        if sketch_id not in sketches:
            raise SystemExit(
                f"ERROR: sketch {sketch_id} does not exist in Flowsint.\n"
                f"       Known sketches: {json.dumps(sketches, indent=2)}"
            )
        _log(f"target sketch: {sketch_id} ({sketches[sketch_id]!r}) [explicit]")
        return sketch_id

    campaigns = fc.list_campaigns()
    if campaign:
        matches = [c for c in campaigns
                   if str(c.get("name", "")).lower() == campaign.lower()
                   or str(c.get("id", "")).lower() == campaign.lower()]
        if not matches:
            known = [c.get("name") for c in campaigns]
            raise SystemExit(
                f"ERROR: no campaign named {campaign!r}. Known campaigns: {known}"
            )
        resolved = matches[0].get("sketchId") or ""
        if not resolved:
            raise SystemExit(
                f"ERROR: campaign {campaign!r} has no sketch yet — provision it in the UI first."
            )
        if resolved not in sketches:
            raise SystemExit(
                f"ERROR: campaign {campaign!r} points at sketch {resolved}, which no longer "
                f"exists in Flowsint. Re-provision the campaign before ingesting."
            )
        _log(f"target sketch: {resolved} ({sketches[resolved]!r}) [campaign {campaign!r}]")
        return resolved

    raise SystemExit("ERROR: specify --campaign NAME or --sketch-id UUID")


# ── Dedup ledger (keeps WF02's 2-minute sweep off the archive) ────────────────

def _ledger_fingerprint(path: str) -> str:
    """Same name:size:mtime fingerprint WF02 uses, so the two agree."""
    st = os.stat(path)
    return f"{os.path.basename(path)}:{st.st_size}:{int(st.st_mtime)}"


def _claim_in_ledger(fc, fingerprints: List[str]) -> None:
    """
    Record fingerprints in the shared SpotterMeta ledger that WF02 consults.

    Claimed BEFORE parsing, not after: WF02 sweeps every 2 minutes, so an archive
    sitting in the drop folder would otherwise be picked up mid-run and parsed a
    second time inside the runner.
    """
    rows = fc._neo4j_rows(
        "MATCH (m:SpotterMeta {key:'sharphound_ingested'}) RETURN m.data AS data LIMIT 1", {}
    )
    seen: List[str] = []
    if rows and rows[0].get("data"):
        try:
            seen = json.loads(rows[0]["data"]) or []
        except Exception:
            seen = []
    added = [f for f in fingerprints if f not in seen]
    if not added:
        _log("dedup ledger: already claimed, nothing to add")
        return
    seen.extend(added)
    fc._neo4j_rows(
        "MERGE (m:SpotterMeta {key:'sharphound_ingested'}) SET m.data = $d",
        {"d": json.dumps(seen[-200:])},
    )
    _log(f"dedup ledger: claimed {len(added)} archive(s) so WF02 will skip them")


# ── Post-import verification ──────────────────────────────────────────────────

def _count_by_label(fc, sketch_id: str) -> Dict[str, int]:
    rows = fc._neo4j_rows(
        "MATCH (n {sketch_id:$sid}) RETURN labels(n)[0] AS lbl, count(*) AS c",
        {"sid": sketch_id},
    )
    return {r["lbl"]: r["c"] for r in rows if r.get("lbl")}


def _count_edges(fc, sketch_id: str) -> int:
    rows = fc._neo4j_rows(
        "MATCH ({sketch_id:$sid})-[r]->({sketch_id:$sid}) RETURN count(r) AS c",
        {"sid": sketch_id},
    )
    return rows[0]["c"] if rows else 0


# ── Main ──────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Ingest large SharpHound archives directly into a SPOTTER campaign.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--zip", action="append", required=True, metavar="PATH",
                    help="archive or directory of archives; repeatable")
    ap.add_argument("--campaign", default="", help="campaign name, e.g. demo-01")
    ap.add_argument("--sketch-id", default="", help="explicit sketch UUID (overrides --campaign)")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse and report counts; write nothing")
    ap.add_argument("--claim-ledger", action="store_true",
                    help="record fingerprints so WF02's sweep skips these archives")
    ap.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    ap.add_argument("--force", action="store_true",
                    help="proceed even if the preflight estimates the archive will not fit in RAM")
    ap.add_argument("--allow-rest-edges", action="store_true",
                    help="proceed even if the Neo4j bulk-edge fast path is unavailable "
                         "(the REST fallback is ~400x slower and truncates at 100k nodes)")
    args = ap.parse_args(argv)

    _prepare_environment(args.env_file)
    sys.path.insert(0, SCRIPTS_DIR)
    import flowsint_client as fc                      # noqa: E402  (env must precede import)
    from sharphound_parser import parse_zip_file      # noqa: E402

    _log(f"flowsint api : {fc.API_URL}")
    _log(f"neo4j http   : {os.environ.get('NEO4J_HTTP_URL', '(unset)')}")

    zips = _collect_zips(args.zip)
    total_bytes = sum(os.path.getsize(z) for z in zips)
    _log(f"archives     : {len(zips)} ({_human_bytes(total_bytes)} total)")
    for z in zips:
        _log(f"   {os.path.basename(z)}  {_human_bytes(os.path.getsize(z))}")

    _preflight_memory(zips, args.force)

    # Preconditions, all before any parsing work.
    # A dry run may omit the target entirely (pure "how big is this?" mode), but if
    # a target IS named it gets validated even on a dry run — the point of a dry run
    # is to surface exactly this kind of problem before committing to a long import.
    if args.campaign or args.sketch_id:
        sketch_id = _resolve_sketch(fc, args.campaign, args.sketch_id)
    elif args.dry_run:
        sketch_id = ""
        _log("target sketch: (none given — dry run will only report parse results)")
    else:
        raise SystemExit("ERROR: specify --campaign NAME or --sketch-id UUID")

    bulk_ok = fc._neo4j_enabled()
    _log(f"neo4j bulk-edge fast path: {'available' if bulk_ok else 'UNAVAILABLE'}")
    if not args.dry_run and not bulk_ok and not args.allow_rest_edges:
        raise SystemExit(
            "ERROR: the Neo4j bulk-edge fast path is unavailable (NEO4J_HTTP_URL /\n"
            "       NEO4J_PASSWORD not set or unreachable). The REST fallback creates\n"
            "       edges at ~100/s and resolves them through a full-graph read that\n"
            "       truncates at 100k nodes, which silently drops relationships on an\n"
            "       AD-sized import. Fix the Neo4j settings, or pass --allow-rest-edges\n"
            "       to accept that cost deliberately."
        )

    if args.claim_ledger and not args.dry_run:
        _claim_in_ledger(fc, [_ledger_fingerprint(z) for z in zips])

    before = _count_by_label(fc, sketch_id) if (sketch_id and not args.dry_run) else {}
    if before:
        _log(f"sketch already holds: {before} (re-runs skip existing nodes)")

    grand_nodes = grand_edges = 0
    failures: List[str] = []

    for zpath in zips:
        _log(f"── parsing {os.path.basename(zpath)} ─────────────────────────")
        t0 = time.time()
        try:
            result = parse_zip_file(zpath)
        except Exception as exc:
            failures.append(f"{os.path.basename(zpath)}: parse failed: {exc}")
            _log(f"   PARSE FAILED: {exc}")
            continue

        nodes, edges = result.to_flowsint_batch()
        _log(f"   schema {result.schema_version} | {len(nodes):,} nodes | "
             f"{len(edges):,} edges | {time.time() - t0:,.1f}s | peak RSS {_peak_rss_gb():.1f} GB")
        if result.errors:
            _log(f"   parser reported {len(result.errors)} error(s); first 3:")
            for e in result.errors[:3]:
                _log(f"     - {e}")
        if result.high_value_aces:
            _log(f"   high-value ACEs: {len(result.high_value_aces):,}")

        grand_nodes += len(nodes)
        grand_edges += len(edges)

        if args.dry_run:
            _log("   dry run — nothing written")
            continue

        # Progress for the chunked node import. flowsint_client has no progress
        # hook, so wrap its chunk call rather than reimplementing the batching.
        done = {"n": 0}
        original_import_execute = fc._import_execute

        def _with_progress(chunk, chunk_edges, sid, _orig=original_import_execute):
            res = _orig(chunk, chunk_edges, sid)
            done["n"] += len(chunk)
            if done["n"] % (fc._IMPORT_CHUNK * 20) < fc._IMPORT_CHUNK or done["n"] >= len(nodes):
                pct = 100.0 * done["n"] / max(len(nodes), 1)
                _log(f"   nodes {done['n']:,}/{len(nodes):,} ({pct:.0f}%)")
            return res

        fc._import_execute = _with_progress
        t1 = time.time()
        try:
            outcome = fc.batch_import(nodes, edges, sketch_id=sketch_id)
        except Exception as exc:
            failures.append(f"{os.path.basename(zpath)}: import failed: {exc}")
            _log(f"   IMPORT FAILED: {exc}")
            continue
        finally:
            fc._import_execute = original_import_execute

        _log(f"   imported in {time.time() - t1:,.1f}s — created {outcome.get('nodes_created', 0):,}, "
             f"skipped {outcome.get('nodes_skipped', 0):,}, edges {outcome.get('edges_created', 0):,}")
        errs = outcome.get("errors") or []
        if errs:
            failures.append(f"{os.path.basename(zpath)}: {len(errs)} import error(s)")
            _log(f"   {len(errs)} import error(s); first 5:")
            for e in errs[:5]:
                _log(f"     - {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    _log(f"parsed totals: {grand_nodes:,} nodes / {grand_edges:,} edges "
         f"| peak RSS {_peak_rss_gb():.1f} GB")

    if args.dry_run:
        _log("DRY RUN complete — nothing was written.")
        return 1 if failures else 0

    after = _count_by_label(fc, sketch_id)
    _log(f"sketch now holds {sum(after.values()):,} nodes / {_count_edges(fc, sketch_id):,} edges:")
    for lbl, c in sorted(after.items(), key=lambda kv: -kv[1]):
        delta = c - before.get(lbl, 0)
        _log(f"   {lbl:<18} {c:>10,}  (+{delta:,})")

    # What counts as failure here is "nothing is in the sketch", not "nothing was
    # added". Flowsint MERGEs on nodeLabel, so re-running a completed import is a
    # legitimate no-op — that is what makes an interrupted run resumable. Treating
    # a zero delta as failure would flag every successful resume.
    total_after = sum(after.values())
    if total_after == 0:
        failures.append("nothing landed in the sketch — every write failed silently")
    elif total_after == sum(before.values()):
        _log("   note: no new nodes — this archive's entities were already present "
             "(re-run/resume, not an error)")

    if failures:
        print()
        _log("COMPLETED WITH FAILURES:")
        for f in failures:
            _log(f"   - {f}")
        return 1

    _log("OK — ingest complete and verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
