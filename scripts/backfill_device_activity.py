"""
backfill_device_activity.py — Populate last-logon timestamps on existing device nodes.

Why this exists: SharpHound's computers.json carries lastlogontimestamp, lastlogon,
pwdlastset and whencreated on every computer object, but sharphound_parser dropped
those keys until now. Sketches ingested before that fix have devices whose only
liveness signal is `enabled`, which on a real domain excludes ~2% of objects. The
Tech Intel tab therefore reports on every computer account the domain has ever had,
including boxes decommissioned years ago.

This script closes the gap without a re-ingest: it re-reads the original SharpHound
zip, joins on SID, and writes the timestamps straight into Neo4j. Nothing else about
the nodes is touched — no relabeling, no new nodes, no edges.

Properties written (POSIX seconds, 0 = unknown — never None, because Flowsint's
graph serializer drops None but keeps 0):

    nodeProperties.last_logon
    nodeProperties.last_logon_timestamp
    nodeProperties.pwd_last_set
    nodeProperties.when_created
    nodeProperties.last_activity_ts   max of the three logon-ish fields
    nodeProperties.activity_source    'sharphound_backfill'

activity_source is set unconditionally, including for hosts whose timestamps are all
zero. WF12 uses its presence to measure *coverage* ("how many devices have been
assessed for freshness") separately from *value*, and refuses to filter at all when
coverage is too low — that is what stops the Tech Intel tab going dark on a graph
that was never backfilled.

Timestamp normalisation is imported from sharphound_parser._epoch so the backfill and
the live parser can never drift apart.

Dry-run by default. Re-running after a successful apply is a no-op (rows whose
last_activity_ts already matches are skipped).

Usage (from the host; Neo4j publishes to 127.0.0.1:7474):

    python3 scripts/backfill_device_activity.py --sketch-id <uuid>
    python3 scripts/backfill_device_activity.py --sketch-id <uuid> --apply

Note: FLOWSINT_SKETCH_ID in .env is the drop-folder fallback sketch, which is not
the campaign sketch you are looking at in the UI. Pass --sketch-id explicitly.

Environment (CLI flags win):
    NEO4J_HTTP_URL, NEO4J_USER / NEO4J_USERNAME, NEO4J_PASSWORD, FLOWSINT_SKETCH_ID
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import socket
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from migrate_c2session import Neo4jHTTP  # noqa: E402  minimal HTTP tx client, no side effects
from sharphound_parser import _epoch     # noqa: E402  single source of truth for epoch handling

REPO_ROOT = Path(__file__).resolve().parent.parent

# Same shard-naming family _parse_v2 accepts: computers.json, 20260804195255_computers.json,
# computers_01.json, 20260804195255_computers_01.json.
COMPUTER_SHARD_RE = re.compile(r"^(?:\d+_)?computers(?:_\d+)?\.json$", re.IGNORECASE)

DEFAULT_BATCH = 5000
DEFAULT_STALE_DAYS = 90


def _host_reachable_url(url: str) -> str:
    """
    Rewrite an unresolvable container hostname to localhost.

    .env sets NEO4J_HTTP_URL to the compose service name (flowsint-neo4j-prod),
    which only resolves inside the docker network. This script runs on the HOST,
    where Neo4j is published on 127.0.0.1:7474. Without this guard, sourcing .env
    before running the script makes it fail with a DNS error.
    """
    parts = urlsplit(url)
    if not parts.hostname:
        return url
    try:
        socket.gethostbyname(parts.hostname)
        return url
    except OSError:
        netloc = f"localhost:{parts.port or 7474}"
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def load_zip_timestamps(zip_paths: List[Path]) -> Dict[str, Dict[str, int]]:
    """
    Build {sid: {ll, llt, pls, wc, ts}} from the computer shards of one or more zips.

    Shards are loaded and discarded one at a time — the uncompressed computers.json
    on a 50k-host domain is ~200 MB, and json.load peaks at several GB.

    Across multiple zips (successive collections) the element-wise max wins. That
    makes the result independent of the order the zips are processed in, which is
    what keeps repeated runs idempotent.
    """
    by_sid: Dict[str, Dict[str, int]] = {}

    for zip_path in zip_paths:
        with zipfile.ZipFile(zip_path) as zf:
            shards = [n for n in zf.namelist() if COMPUTER_SHARD_RE.match(os.path.basename(n))]
            if not shards:
                print(f"  {zip_path.name}: no computer shards found", file=sys.stderr)
                continue
            for shard in sorted(shards):
                raw = json.loads(zf.read(shard))
                rows = raw.get("data", raw if isinstance(raw, list) else [])
                print(f"  {zip_path.name}:{shard} — {len(rows)} computers")
                for computer in rows:
                    sid = computer.get("ObjectIdentifier") or ""
                    if not sid:
                        continue
                    props = computer.get("Properties") or {}
                    ll = _epoch(props.get("lastlogon"))
                    llt = _epoch(props.get("lastlogontimestamp"))
                    pls = _epoch(props.get("pwdlastset"))
                    wc = _epoch(props.get("whencreated"))
                    cur = by_sid.get(sid)
                    if cur is None:
                        by_sid[sid] = {
                            "ll": ll, "llt": llt, "pls": pls, "wc": wc,
                            "ts": max(ll, llt, pls),
                        }
                    else:
                        cur["ll"] = max(cur["ll"], ll)
                        cur["llt"] = max(cur["llt"], llt)
                        cur["pls"] = max(cur["pls"], pls)
                        cur["wc"] = max(cur["wc"], wc)
                        cur["ts"] = max(cur["ll"], cur["llt"], cur["pls"])
                del raw, rows

    return by_sid


def fetch_graph_devices(neo: Neo4jHTTP, sketch_id: str) -> List[List[Any]]:
    """
    One read of every device in the sketch: [elementId, sid, current last_activity_ts].

    Uses the lowercase `device` label (Flowsint stores AD object types lowercase) so
    the idx_device_sketch index applies. -1 for a missing timestamp distinguishes
    "never written" from a legitimately stored 0.
    """
    return neo.query(
        "MATCH (n:device) WHERE n.sketch_id = $s AND n.deleted_at IS NULL "
        "RETURN elementId(n) AS eid, "
        "       coalesce(n.`nodeProperties.sid`, n.`nodeProperties.device_id`) AS sid, "
        "       coalesce(n.`nodeProperties.last_activity_ts`, -1) AS cur, "
        "       coalesce(n.`nodeProperties.hostname`, n.nodeLabel, '') AS hostname",
        {"s": sketch_id},
    )


WRITE_CYPHER = """
UNWIND $rows AS row
MATCH (n) WHERE elementId(n) = row.eid
SET n.`nodeProperties.last_logon`           = row.ll,
    n.`nodeProperties.last_logon_timestamp` = row.llt,
    n.`nodeProperties.pwd_last_set`         = row.pls,
    n.`nodeProperties.when_created`         = row.wc,
    n.`nodeProperties.last_activity_ts`     = row.ts,
    n.`nodeProperties.activity_source`      = 'sharphound_backfill'
RETURN count(n) AS c
"""


def _fmt_date(ts: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts)) if ts else "—"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zip", action="append", default=[],
                    help="SharpHound zip (repeatable). Default: sharphound-drops/*.zip")
    ap.add_argument("--sketch-id", default=os.environ.get("FLOWSINT_SKETCH_ID", ""),
                    help="Target sketch UUID. The .env default is the drop-folder fallback sketch — pass this explicitly.")
    ap.add_argument("--neo4j-url", default=os.environ.get("NEO4J_HTTP_URL", "http://localhost:7474"))
    ap.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER") or os.environ.get("NEO4J_USERNAME", "neo4j"))
    ap.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD", ""))
    ap.add_argument("--batch", type=int, default=DEFAULT_BATCH, help=f"Rows per write transaction (default {DEFAULT_BATCH})")
    ap.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS,
                    help=f"Window used only for the summary report (default {DEFAULT_STALE_DAYS})")
    ap.add_argument("--apply", action="store_true", help="Write. Without this, report only.")
    args = ap.parse_args(argv)

    if not args.sketch_id:
        print("error: --sketch-id is required (FLOWSINT_SKETCH_ID is unset)", file=sys.stderr)
        return 2
    if not args.neo4j_password:
        print("error: --neo4j-password is required (NEO4J_PASSWORD is unset)", file=sys.stderr)
        return 2

    zip_paths = [Path(z) for z in args.zip] or [
        Path(p) for p in sorted(glob.glob(str(REPO_ROOT / "sharphound-drops" / "*.zip")))
    ]
    zip_paths = [p for p in zip_paths if p.is_file()]
    if not zip_paths:
        print("error: no SharpHound zips found (looked in sharphound-drops/)", file=sys.stderr)
        return 2

    neo4j_url = _host_reachable_url(args.neo4j_url)
    if neo4j_url != args.neo4j_url:
        print(f"note: {args.neo4j_url} does not resolve from the host — using {neo4j_url}")

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"=== backfill_device_activity ({mode}) ===")
    print(f"sketch   {args.sketch_id}")
    print(f"zips     {', '.join(p.name for p in zip_paths)}")
    print()

    print("reading zip(s)...")
    by_sid = load_zip_timestamps(zip_paths)
    print(f"  {len(by_sid)} unique computer SIDs\n")

    neo = Neo4jHTTP(neo4j_url, args.neo4j_user, args.neo4j_password)
    print("reading graph...")
    graph_rows = fetch_graph_devices(neo, args.sketch_id)
    print(f"  {len(graph_rows)} device nodes\n")

    rows: List[Dict[str, Any]] = []
    samples: List[str] = []
    unchanged = matched = unmatched_graph = 0
    now = int(time.time())

    for eid, sid, cur, hostname in graph_rows:
        rec = by_sid.get(sid or "")
        if rec is None:
            unmatched_graph += 1
            continue
        matched += 1
        if int(cur) == rec["ts"]:
            unchanged += 1
            continue
        rows.append({"eid": eid, **rec})
        if len(samples) < 5:
            days = (now - rec["ts"]) // 86400 if rec["ts"] else None
            samples.append(
                f"    {hostname[:44]:<44} ts={rec['ts']} ({_fmt_date(rec['ts'])})"
                f"  {'no logon data' if days is None else f'{days}d ago'}"
            )

    unmatched_zip = len(by_sid) - matched

    print(f"graph devices      {len(graph_rows)}")
    print(f"zip computers      {len(by_sid)}")
    print(f"matched            {matched}")
    print(f"  to update        {len(rows)}")
    print(f"  unchanged        {unchanged}")
    print(f"unmatched (graph)  {unmatched_graph}   # device in sketch, absent from every zip")
    print(f"unmatched (zip)    {unmatched_zip}   # computer in zip, absent from sketch")

    if samples:
        print("\nsample rows:")
        print("\n".join(samples))

    cutoff = now - args.stale_days * 86400
    active = sum(1 for r in by_sid.values() if r["ts"] >= cutoff)
    no_ts = sum(1 for r in by_sid.values() if not r["ts"])
    print(f"\nat a {args.stale_days}-day cutoff (zip data, before the `enabled` check):")
    print(f"  active   {active}")
    print(f"  stale    {len(by_sid) - active - no_ts}")
    print(f"  no data  {no_ts}")

    if not args.apply:
        print("\nDRY-RUN — nothing written. Re-run with --apply.")
        return 0

    if not rows:
        print("\nnothing to write — already up to date.")
        return 0

    print(f"\nwriting {len(rows)} nodes in batches of {args.batch}...")
    written = 0
    for i in range(0, len(rows), args.batch):
        chunk = rows[i:i + args.batch]
        result = neo.query(WRITE_CYPHER, {"rows": chunk})
        written += int(result[0][0]) if result else 0
        print(f"  {written}/{len(rows)}")

    print(f"\nwrote {written} device nodes.")

    verify = neo.query(
        "MATCH (n:device) WHERE n.sketch_id = $s AND n.deleted_at IS NULL "
        "RETURN count(n), "
        "       count(n.`nodeProperties.last_activity_ts`), "
        "       sum(CASE WHEN coalesce(n.`nodeProperties.last_activity_ts`, 0) = 0 THEN 1 ELSE 0 END), "
        "       sum(CASE WHEN n.`nodeProperties.enabled` <> false "
        "                 AND coalesce(n.`nodeProperties.last_activity_ts`, 0) >= $c "
        "                THEN 1 ELSE 0 END)",
        {"s": args.sketch_id, "c": cutoff},
    )
    if verify:
        total, with_ts, zero_ts, live = verify[0]
        print("\nverification (graph):")
        print(f"  devices              {total}")
        print(f"  with last_activity_ts {with_ts}")
        print(f"  timestamp == 0        {zero_ts}")
        print(f"  in use (<{args.stale_days}d, enabled) {live}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
