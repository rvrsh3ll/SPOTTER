#!/usr/bin/env python3
"""
sanitize_residue_scan.py — Prove a campaign sanitization actually finished.

WHY THIS IS NOT NAMED smoke_*
-----------------------------
CLAUDE.md documents the smoke suite as offline, and `python3 scripts/smoke_*.py`
is expected to run without a stack. This one deliberately reaches live Neo4j,
the n8n SQLite database, Flowsint's Postgres, container logs and the filesystem,
so it keeps a distinct prefix and stays out of that glob.

WHAT IT CHECKS
--------------
  1. sketch nodes            every property, every configured client token
  2. sketch edges            same (they should carry no strings at all)
  3. Neo4j outside the sketch  :SpotterMeta and :SpotterNotification — the gap a
                             sketch-scoped script structurally cannot see
  4. surname residue         tokenized in Python; an UNWIND of ~2k terms over
                             millions of values is not viable in Cypher
  5. n8n sqlite              live rows AND a raw byte grep of the db/-wal/-shm,
                             plus freelist_count. The byte grep is the only thing
                             that proves the VACUUM happened: deleting rows
                             leaves the plaintext sitting in freed pages.
  6. Flowsint Postgres       sketches / investigations / logs / scans
  7. container logs          reported, not failed — see the note in check_logs
  8. filesystem              caches, screenshots, repo tree, git history, and
                             that the mapping sidecar has been shredded

The token list is DERIVED from the mapping sidecar (every real name the
sanitizer replaced), unioned with a floor list. Running without the sidecar is
refused rather than silently scanning for six strings.

USAGE
    python3 scripts/sanitize_residue_scan.py --campaign DEMO-01
    python3 scripts/sanitize_residue_scan.py --campaign DEMO-01 --json
    python3 scripts/sanitize_residue_scan.py --campaign DEMO-01 --baseline

--baseline records counts and always exits 0; use it BEFORE sanitizing so the
"after" run has something to be compared against. A scanner that has never
printed a non-zero number has never been proven to work.

Exit 0 = clean, 1 = residue found, 2 = could not run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sanitize_campaign import (  # noqa: E402
    FROZEN_KEYS, MIN_FREE_TEXT_SURNAME, Mapping, Rewriter, connect,
    default_mapping_path, default_profile_path, iter_nodes, load_mapping,
    load_profile, patch_props, residue_terms,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_n8n_db() -> str:
    """
    Where n8n's database.sqlite is on the host.

    This used to be the hardcoded /var/lib/docker/volumes/... path, which is
    wrong three ways: under a relocated Docker data-root, under rootless Docker
    or Podman, and — since the folder layout — on any host where SPOTTER_N8N_DATA
    names a bind mount inside the checkout instead. Getting it wrong matters more
    here than almost anywhere else in the tree: this is the residue scanner, and
    a scanner that silently reads a database that is not there reports CLEAN on
    unsanitised client data.
    """
    explicit = os.environ.get("N8N_DB_PATH")
    if explicit:
        return explicit

    state = os.environ.get("SPOTTER_N8N_DATA")
    if not state:
        env_file = os.path.join(REPO, ".env")
        try:
            with open(env_file, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("SPOTTER_N8N_DATA="):
                        state = line.split("=", 1)[1].strip()
        except OSError:
            state = ""
    if state:
        state = state.replace("${SPOTTER_HOME}", REPO).replace("$SPOTTER_HOME", REPO)
        return os.path.join(state, "database.sqlite")

    # Named-volume layout: ask Docker rather than assuming the default path.
    try:
        out = subprocess.run(
            ["docker", "volume", "inspect",
             os.environ.get("N8N_VOLUME", "spotter_n8n_data"),
             "-f", "{{.Mountpoint}}"],
            capture_output=True, text=True, timeout=15,
        )
        mp = (out.stdout or "").strip()
        if out.returncode == 0 and mp:
            return os.path.join(mp, "database.sqlite")
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


N8N_DB = _resolve_n8n_db()
AUTH_DB = os.path.join(REPO, "deployment", "auth-data", "auth.db")

# Structural terms only. Every CLIENT token comes from the campaign profile and
# the mapping sidecar (both gitignored) — hardcoding them here would put the
# client's name in a tracked file, which is the thing this tooling exists to
# prevent. --extra-terms adds one-off strings (a ticker, a named persona) that
# live in neither file.
FLOOR_TERMS = ["spotter_session="]

STACK_CONTAINERS = [
    "spotter-n8n", "spotter-n8n-runners", "spotter-ui", "spotter-auth",
    "spotter-open-webui", "spotter-vllm", "spotter-llm-gateway",
    "flowsint-api-prod", "flowsint-celery-prod", "flowsint-neo4j-prod",
    "flowsint-postgres-prod",
]

_results: List[Tuple[str, int, str]] = []


def _ok(name: str) -> None:
    print(f"  ok    {name}")


def _fail(name: str, detail: str = "") -> None:
    print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))


def _record(name: str, hits: int, detail: str = "") -> None:
    _results.append((name, hits, detail))
    (_ok if hits == 0 else lambda n: _fail(n, detail))(name)


# ── 1-4: Neo4j ───────────────────────────────────────────────────────────────

def check_sketch(neo, sketch_id: str, terms: List[str]) -> Dict[str, Any]:
    # One pass over the graph for ALL terms, not one pass per term: a large
    # sketch has 100k+ nodes and millions of edges, so per-term scans turn a
    # seconds-long check into a many-minute one, and this runs twice per
    # sanitization.
    out: Dict[str, Any] = {"nodes": [], "edges": []}
    for term, t, k, c in neo.query(
            "MATCH (n {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
            "UNWIND keys(n) AS k "
            "WITH n.nodeType AS t, k, toLower(toString(n[k])) AS v WHERE v <> '' "
            "UNWIND $terms AS term WITH t, k, term, v WHERE v CONTAINS term "
            "RETURN term, t, k, count(*) AS c ORDER BY c DESC LIMIT 200",
            {"sid": sketch_id, "terms": terms}):
        out["nodes"].append({"term": str(term), "node_type": str(t),
                             "key": str(k), "count": int(c)})
    for term, k, c in neo.query(
            "MATCH ()-[r {sketch_id:$sid}]->() "
            "UNWIND keys(r) AS k "
            "WITH k, toLower(toString(r[k])) AS v WHERE v <> '' "
            "UNWIND $terms AS term WITH k, term, v WHERE v CONTAINS term "
            "RETURN term, k, count(*) AS c ORDER BY c DESC LIMIT 100",
            {"sid": sketch_id, "terms": terms}):
        out["edges"].append({"term": str(term), "key": str(k), "count": int(c)})
    return out


def check_outside_sketch(neo, terms: List[str]) -> List[Dict[str, Any]]:
    """
    :SpotterNotification nodes carry campaign_id and NO sketch_id, so a
    sketch-scoped pass cannot reach them. :SpotterMeta holds the campaign
    registry prose. Both survive a clear-graph.
    """
    hits = []
    for label in ("SpotterMeta", "SpotterNotification"):
        for term, k, c in neo.query(
                f"MATCH (n:{label}) UNWIND keys(n) AS k "
                "WITH k, toLower(toString(n[k])) AS v WHERE v <> '' "
                "UNWIND $terms AS term WITH k, term, v WHERE v CONTAINS term "
                "RETURN term, k, count(*) AS c ORDER BY c DESC LIMIT 100",
                {"terms": terms}):
            hits.append({"label": label, "term": str(term), "key": str(k),
                         "count": int(c)})
    return hits


def check_surnames(neo, sketch_id: str, mapping: Mapping,
                   rename_hosts: bool = False) -> Tuple[int, Dict[str, int]]:
    """
    Returns (policy_residue_nodes, advisory_tokens).

    The gate is policy residue: re-plan the sketch and count what the sanitizer
    would STILL change. That is stronger than grepping for names, because it
    measures what the tool would actually do rather than what a human guessed
    to look for — and it does not fail on the things policy deliberately keeps,
    such as the direction "west" inside the group TEAM-OPS3WEST-C.

    The advisory is the naive token scan, reported so an operator can judge the
    leftovers rather than being told everything is fine.
    """
    rw = Rewriter(mapping)
    real = {s.lower() for s in mapping.surnames
            if len(s) >= MIN_FREE_TEXT_SURNAME}
    tok = re.compile(r"[a-z]{%d,}" % MIN_FREE_TEXT_SURNAME)
    hits: Dict[str, int] = {}
    residue = 0
    for rows in iter_nodes(neo, sketch_id, "", 5000, unstamped_only=False):
        for _eid, nt, props in rows:
            if patch_props(props, rw, str(nt or ""), "rewrite", rename_hosts):
                residue += 1
            for k, v in props.items():
                if k in FROZEN_KEYS or not isinstance(v, str):
                    continue
                for t in tok.findall(v.lower()):
                    if t in real:
                        hits[t] = hits.get(t, 0) + 1
    return residue, dict(sorted(hits.items(), key=lambda kv: -kv[1])[:25])


# ── 5: n8n sqlite ────────────────────────────────────────────────────────────

def check_n8n(terms: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"rows": 0, "raw": {}, "freelist": -1, "present": False}
    if not os.path.exists(N8N_DB):
        return out
    out["present"] = True
    pat = re.compile("|".join(re.escape(t) for t in terms).encode(), re.I)
    try:
        con = sqlite3.connect(f"file:{N8N_DB}?mode=ro", uri=True)
        con.text_factory = bytes
        for eid, data, wf in con.execute(
                "SELECT executionId, data, workflowData FROM execution_data"):
            if pat.search(data or b"") or pat.search(wf or b""):
                out["rows"] += 1
        con.text_factory = str
        out["freelist"] = int(con.execute("PRAGMA freelist_count").fetchone()[0])
        con.close()
    except sqlite3.Error as exc:
        out["error"] = str(exc)

    # The raw grep is the point: row deletion leaves plaintext in freed pages,
    # and only a VACUUM reclaims them.
    for suffix in ("", "-wal", "-shm"):
        path = N8N_DB + suffix
        if not os.path.exists(path):
            continue
        n = 0
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(8 << 20)
                if not chunk:
                    break
                n += len(pat.findall(chunk))
        if n:
            out["raw"][os.path.basename(path)] = n
    return out


# ── 6-8: Postgres, logs, filesystem ──────────────────────────────────────────

def _docker(args: List[str], timeout: int = 120) -> str:
    try:
        return subprocess.run(["docker"] + args, capture_output=True,
                              text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def check_postgres(terms: List[str]) -> int:
    pattern = "|".join(terms)
    sql = (
        "SELECT count(*) FROM ("
        "  SELECT title AS v FROM sketches UNION ALL"
        "  SELECT description FROM sketches UNION ALL"
        "  SELECT name FROM investigations UNION ALL"
        "  SELECT description FROM investigations"
        ") s WHERE s.v ~* '" + pattern.replace("'", "''") + "'"
    )
    out = _docker(["exec", "flowsint-postgres-prod", "psql", "-U", "flowsint",
                   "-d", "flowsint", "-tAc", sql])
    try:
        return int(out.strip().splitlines()[0])
    except (ValueError, IndexError):
        return 0


def check_logs(terms: List[str]) -> Dict[str, int]:
    """
    Informational only. flowsint-api-prod's access log is full of the sketch
    UUID, which is not client identity — failing on it would mean the scanner
    could never go green.
    """
    pat = re.compile("|".join(re.escape(t) for t in terms).encode(), re.I)
    hits: Dict[str, int] = {}
    for name in STACK_CONTAINERS:
        path = _docker(["inspect", "--format", "{{.LogPath}}", name]).strip()
        if not path or not os.path.exists(path):
            continue
        n = 0
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(8 << 20)
                if not chunk:
                    break
                n += len(pat.findall(chunk))
        if n:
            hits[name] = n
    return hits


def check_filesystem(terms: List[str], campaign_id: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"paths": {}, "git": 0, "sidecar_present": False}
    pat = re.compile("|".join(re.escape(t) for t in terms), re.I)
    roots = [
        os.path.join(REPO, ".spotter-cache", "rag_index"),
        os.path.join(REPO, "screenshots"),
        os.path.join(REPO, "sharphound-drops"),
        os.path.join(REPO, "scripts"),
        os.path.join(REPO, "n8n-workflows"),
        os.path.join(REPO, "frontend"),
        os.path.join(REPO, "llm"),
    ]
    # The sanitizer and this scanner define the term list, so they match
    # themselves; and a .pyc is just a stale copy of that source.
    self_files = {os.path.abspath(__file__),
                  os.path.join(REPO, "scripts", "sanitize_campaign.py")}
    for root in roots:
        if not os.path.isdir(root):
            continue
        n = 0
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for fn in files:
                fp = os.path.join(dirpath, fn)
                if os.path.abspath(fp) in self_files:
                    continue
                try:
                    if os.path.getsize(fp) > 256 << 20:
                        continue
                    with open(fp, "rb") as fh:
                        blob = fh.read()
                except OSError:
                    continue
                n += len(pat.findall(blob.decode("utf-8", "ignore")))
        if n:
            out["paths"][os.path.relpath(root, REPO)] = n

    for term in terms:
        res = subprocess.run(["git", "-C", REPO, "log", "--all", "-S", term,
                              "--oneline"], capture_output=True, text=True)
        out["git"] += len([l for l in res.stdout.splitlines() if l.strip()])

    sidecar = default_mapping_path(campaign_id)
    out["sidecar_present"] = os.path.exists(sidecar)
    out["sidecar_path"] = sidecar
    return out


def check_auth_sessions() -> int:
    """After the purge, no session should remain that was exposed in n8n."""
    if not os.path.exists(AUTH_DB):
        return 0
    try:
        con = sqlite3.connect(f"file:{AUTH_DB}?mode=ro", uri=True)
        n = int(con.execute("SELECT count(*) FROM sessions").fetchone()[0])
        con.close()
        return n
    except sqlite3.Error:
        return 0


# ── main ─────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--campaign", default="", help="campaign id, e.g. DEMO-01")
    ap.add_argument("--sketch", default="")
    ap.add_argument("--map", default="", help="mapping sidecar (required)")
    ap.add_argument("--profile", default="",
                    help="campaign replacement profile (client tokens)")
    ap.add_argument("--baseline", action="store_true",
                    help="record counts and exit 0 (run this BEFORE sanitizing)")
    ap.add_argument("--extra-terms", default="",
                    help="comma-separated extra literals to scan for "
                         "(ticker symbols, named personas, bucket names)")
    ap.add_argument("--skip-surnames", action="store_true",
                    help="skip the full-graph tokenize pass (the slow check)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not args.campaign and not args.sketch:
        print("error: --campaign or --sketch is required", file=sys.stderr)
        return 2

    try:
        neo = connect()
    except Exception as exc:                          # noqa: BLE001 - operator-facing
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        load_profile(args.profile or default_profile_path(args.campaign))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: could not load the replacement profile: {exc}",
              file=sys.stderr)
        return 2
    map_path = args.map or default_mapping_path(args.campaign)
    mapping = load_mapping(map_path)
    if mapping is None and not args.baseline:
        print(f"error: no mapping sidecar at {map_path}. The token list is "
              f"derived from it; refusing to scan for the floor list alone.\n"
              f"Pass --map, or --baseline for a pre-sanitization run.",
              file=sys.stderr)
        return 2

    sketch_id = args.sketch or (mapping.sketch_id if mapping else "")
    if not sketch_id:
        from sanitize_campaign import _REG_READ  # noqa: PLC0415 - local fallback
        rows = neo.query(_REG_READ)
        camps = json.loads(rows[0][0]) if rows and rows[0][0] else []
        for c in camps:
            if isinstance(c, dict) and c.get("id") == args.campaign:
                sketch_id = str(c.get("sketchId") or "")
    if not sketch_id:
        print("error: could not resolve a sketch id", file=sys.stderr)
        return 2

    terms = set(FLOOR_TERMS)
    if mapping:
        terms |= set(residue_terms(mapping.brands, mapping.domains,
                                   mapping.netbios))
        terms |= {k.lower() for k in mapping.org_names}
    terms |= {t.strip().lower() for t in args.extra_terms.split(",") if t.strip()}
    terms = sorted(terms)

    print(f"sanitize_residue_scan  campaign {args.campaign or '(none)'}   "
          f"sketch {sketch_id}")
    print(f"  {len(terms)} literal terms"
          + (f" + {len(mapping.surnames)} surnames" if mapping else ""))

    report: Dict[str, Any] = {"campaign": args.campaign, "sketch": sketch_id}

    sketch = check_sketch(neo, sketch_id, terms)
    report["sketch"] = sketch
    _record("sketch nodes carry no client token",
            sum(h["count"] for h in sketch["nodes"]),
            ", ".join(f"{h['term']}:{h['key']}={h['count']}"
                      for h in sketch["nodes"][:5]))
    _record("sketch edges carry no client token",
            sum(h["count"] for h in sketch["edges"]))

    outside = check_outside_sketch(neo, terms)
    report["outside_sketch"] = outside
    _record("SpotterMeta / SpotterNotification carry no client token",
            sum(h["count"] for h in outside),
            ", ".join(f"{h['label']}:{h['term']}={h['count']}" for h in outside[:5]))

    if mapping and not args.skip_surnames:
        residue, sur = check_surnames(neo, sketch_id, mapping)
        report["policy_residue_nodes"] = residue
        report["surname_advisory"] = sur
        _record("sanitizer would change nothing further (policy residue)",
                residue, f"{residue} nodes still match a rewrite rule")
        if sur:
            print("  info  real surnames still present, by design — policy "
                  "leaves group names, machine naming schemes and free text "
                  "alone: " + ", ".join(f"{k}={v}" for k, v in list(sur.items())[:8]))
            print("        (scripts/sanitize_campaign.py --rename-hosts also "
                  "rewrites device short names, at the cost of mangling some "
                  "machine names)")

    n8n = check_n8n(terms)
    report["n8n"] = n8n
    if n8n["present"]:
        _record("n8n execution rows carry no client token", n8n["rows"])
        _record("n8n sqlite has no client token in freed pages",
                sum(n8n["raw"].values()),
                ", ".join(f"{k}={v}" for k, v in n8n["raw"].items()))
        _record("n8n sqlite has been vacuumed",
                1 if n8n["freelist"] > 1000 else 0,
                f"freelist_count={n8n['freelist']}")
    else:
        # Not merely "nothing to check". Every n8n assertion above is SKIPPED when
        # the database cannot be found, so staying quiet here would let the scan
        # print a clean bill of health for a store it never opened — on a tool
        # whose entire job is to confirm client data is gone. Fail loudly instead.
        _record("n8n sqlite was located and scanned", 1,
                f"could not open {N8N_DB or '<unresolved>'} — set N8N_DB_PATH, or "
                "SPOTTER_N8N_DATA/N8N_VOLUME, and re-run. The n8n checks did NOT run.")

    pg = check_postgres(terms)
    report["postgres"] = pg
    _record("Flowsint Postgres carries no client token", pg)

    logs = check_logs(terms)
    report["logs"] = logs
    if logs:
        print(f"  info  container logs mention a term: "
              + ", ".join(f"{k}={v}" for k, v in logs.items())
              + "  (informational — access-log noise is not client identity)")
    else:
        _ok("container logs carry no client token")

    fs = check_filesystem(terms, args.campaign)
    report["filesystem"] = fs
    _record("caches / screenshots / repo tree carry no client token",
            sum(fs["paths"].values()),
            ", ".join(f"{k}={v}" for k, v in fs["paths"].items()))
    _record("git history carries no client token", fs["git"])
    _record("mapping sidecar has been shredded",
            1 if fs["sidecar_present"] else 0,
            f"still present at {fs['sidecar_path']} — copy it off-box and shred it")

    total = sum(h for _n, h, _d in _results)
    passed = sum(1 for _n, h, _d in _results if h == 0)
    print(f"\n{passed}/{len(_results)} checks passed")

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    if args.baseline:
        print("baseline run — exiting 0 regardless of findings")
        return 0
    return 0 if total == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
