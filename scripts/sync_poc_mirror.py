#!/usr/bin/env python3
"""
sync_poc_mirror.py — Refresh the local PoC-in-GitHub mirror and its search index.

Clones (or pulls) https://github.com/nomi-sec/PoC-in-GitHub into
$SPOTTER_CACHE_DIR/poc-in-github, then rebuilds:

    poc_fts.sqlite       repos + FTS5 index over name/description, and per-owner
                         PoC counts (the "prolific researcher" trust signal)
    poc_mirror_meta.json synced_at / cve_count / repo_count / bytes

Run from the HOST, never from inside a container. Two reasons: git is not
guaranteed present in the n8n runner image, and a multi-minute clone inside a
workflow execution is the wrong failure mode — it would surface as a task
timeout rather than as "the mirror is stale".

Usage:
    python3 scripts/sync_poc_mirror.py --dry-run     # report size, change nothing
    python3 scripts/sync_poc_mirror.py               # clone or pull, then reindex
    python3 scripts/sync_poc_mirror.py --reindex-only
    python3 scripts/sync_poc_mirror.py --year-from 2015

Weekly cron is ample; upstream is append-mostly:
    17 4 * * 0  cd /root/SPOTTER && python3 scripts/sync_poc_mirror.py \
                  >> /var/log/spotter-poc-sync.log 2>&1

Size as measured 2026-08-18: 62 MB working tree (6.7 MB of that .git),
9,416 CVE files spanning 1999-2026. --year-from exists for hosts where even that
is unwelcome; it prunes the INDEX, not the clone (git has already fetched the
tree by then, and a partial clone would silently answer "no PoC" for the years
it omitted).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from poc_client import (  # noqa: E402
    INDEX_FILENAME,
    META_FILENAME,
    MIRROR_DIRNAME,
    UPSTREAM_REPO,
    normalise_cve,
)
from spotter_cache import ensure_cache_tree  # noqa: E402

DEFAULT_CACHE_DIR = str(REPO_ROOT / ".spotter-cache")
YEAR_DIR_RE = re.compile(r"^(19|20)\d{2}$")


def _run(cmd: list[str], cwd: str | None = None, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, timeout=timeout, capture_output=True, text=True, check=False)


def _require_git() -> None:
    if shutil.which("git") is None:
        sys.exit("git is not on PATH — required to sync the PoC mirror")


def _dir_bytes(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def _human(n: int) -> str:
    f = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if f < 1024 or unit == "GiB":
            return f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} GiB"


# ── clone / pull ─────────────────────────────────────────────────────────────

def sync_mirror(mirror_dir: Path, dry_run: bool = False) -> str:
    """Clone or fast-forward the mirror. Returns 'cloned' | 'pulled' | 'dry-run'."""
    _require_git()

    if dry_run:
        if (mirror_dir / ".git").is_dir():
            r = _run(["git", "-C", str(mirror_dir), "fetch", "--dry-run", "--depth", "1", "origin"])
            print(f"[dry-run] existing mirror at {mirror_dir}")
            print(f"[dry-run] current size: {_human(_dir_bytes(mirror_dir))}")
            if r.stderr.strip():
                print(f"[dry-run] upstream has changes:\n{r.stderr.strip()}")
            else:
                print("[dry-run] already up to date")
        else:
            print(f"[dry-run] would clone {UPSTREAM_REPO}")
            print("[dry-run] expected ~62 MiB working tree, ~9.4k CVE files (measured 2026-08-18)")
        return "dry-run"

    if (mirror_dir / ".git").is_dir():
        # A shallow clone cannot be merged normally; fetch then hard-reset, which
        # is correct here because the mirror is a read-only artifact with no local
        # commits worth preserving.
        fetch = _run(["git", "-C", str(mirror_dir), "fetch", "--depth", "1", "origin", "HEAD"])
        if fetch.returncode != 0:
            sys.exit(f"git fetch failed:\n{fetch.stderr}")
        reset = _run(["git", "-C", str(mirror_dir), "reset", "--hard", "FETCH_HEAD"])
        if reset.returncode != 0:
            sys.exit(f"git reset failed:\n{reset.stderr}")
        _run(["git", "-C", str(mirror_dir), "reflog", "expire", "--expire=now", "--all"])
        _run(["git", "-C", str(mirror_dir), "gc", "--prune=now", "--quiet"])
        return "pulled"

    mirror_dir.parent.mkdir(parents=True, exist_ok=True)
    clone = _run(["git", "clone", "--depth", "1", "--quiet", UPSTREAM_REPO, str(mirror_dir)])
    if clone.returncode != 0:
        sys.exit(f"git clone failed:\n{clone.stderr}")
    return "cloned"


# ── index ────────────────────────────────────────────────────────────────────

def build_index(mirror_dir: Path, index_path: Path, year_from: int | None = None) -> dict:
    """
    Rebuild poc_fts.sqlite from the mirror. Written to a temp file and moved into
    place so a lookup running concurrently never sees a half-built index.
    """
    tmp_path = index_path.with_suffix(".sqlite.tmp")
    if tmp_path.exists():
        tmp_path.unlink()

    conn = sqlite3.connect(str(tmp_path))
    conn.executescript(
        """
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous  = OFF;
        CREATE TABLE repos (
            cve_id    TEXT NOT NULL,
            full_name TEXT,
            owner     TEXT,
            stars     INTEGER DEFAULT 0,
            payload   TEXT NOT NULL
        );
        CREATE INDEX idx_repos_cve   ON repos(cve_id);
        CREATE INDEX idx_repos_owner ON repos(owner);
        CREATE VIRTUAL TABLE poc_fts USING fts5(
            name, description, content=''
        );
        CREATE TABLE owner_stats (
            owner     TEXT PRIMARY KEY,
            cve_count INTEGER NOT NULL,
            repo_count INTEGER NOT NULL
        );
        """
    )

    cve_count = 0
    repo_count = 0
    skipped_years = 0
    owner_cves: dict[str, set] = {}
    owner_repos: dict[str, int] = {}

    for year_dir in sorted(p for p in mirror_dir.iterdir() if p.is_dir() and YEAR_DIR_RE.match(p.name)):
        if year_from is not None and int(year_dir.name) < year_from:
            skipped_years += 1
            continue
        for json_path in sorted(year_dir.glob("CVE-*.json")):
            canon = normalise_cve(json_path.stem)
            if not canon:
                continue
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    repos = json.load(f)
            except Exception:
                continue
            if not isinstance(repos, list) or not repos:
                continue
            cve_count += 1
            for repo in repos:
                if not isinstance(repo, dict):
                    continue
                owner = (repo.get("owner") or {}).get("login")
                cur = conn.execute(
                    "INSERT INTO repos (cve_id, full_name, owner, stars, payload) VALUES (?,?,?,?,?)",
                    (
                        canon,
                        repo.get("full_name"),
                        owner,
                        int(repo.get("stargazers_count") or 0),
                        json.dumps(repo, separators=(",", ":")),
                    ),
                )
                conn.execute(
                    "INSERT INTO poc_fts (rowid, name, description) VALUES (?,?,?)",
                    (cur.lastrowid, repo.get("full_name") or "", repo.get("description") or ""),
                )
                repo_count += 1
                if owner:
                    owner_cves.setdefault(owner, set()).add(canon)
                    owner_repos[owner] = owner_repos.get(owner, 0) + 1

    conn.executemany(
        "INSERT INTO owner_stats (owner, cve_count, repo_count) VALUES (?,?,?)",
        [(o, len(cves), owner_repos.get(o, 0)) for o, cves in owner_cves.items()],
    )
    conn.commit()
    conn.close()

    tmp_path.replace(index_path)
    return {
        "cve_count": cve_count,
        "repo_count": repo_count,
        "owner_count": len(owner_cves),
        "skipped_years": skipped_years,
    }


def fix_permissions(cache_dir: Path, gid: int = 1000) -> str:
    """
    Make the cache group-writable by the n8n task runner.

    The runner executes as uid/gid 1000 while everything here is created by root
    on the host, so a default-permission cache is READ-ONLY to the code node that
    has to write cve_cache.db, the ATT&CK bundle and the RAG index. That failure
    is quiet in exactly the wrong way -- lookups still succeed from the mirror, so
    enrichment appears to work while nothing is ever cached.

    Group-owned by the runner's gid rather than user-owned: the mirror stays owned
    by root so a `git pull` from host cron does not trip git's dubious-ownership
    check, and setgid on the directories makes newly created files inherit the
    group instead of needing this run again.
    """
    ensure_cache_tree(cache_dir, gid=gid)
    if cache_dir.exists():
        return f"cache group-owned by gid {gid}, group-writable"
    return "SKIPPED (cache directory missing)"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cache-dir", default=os.environ.get("SPOTTER_CACHE_DIR") or DEFAULT_CACHE_DIR)
    ap.add_argument("--mirror-dir", default=os.environ.get("POC_MIRROR_DIR") or None)
    ap.add_argument("--dry-run", action="store_true", help="report size and pending changes, write nothing")
    ap.add_argument("--reindex-only", action="store_true", help="skip git, rebuild the index from what is on disk")
    ap.add_argument("--year-from", type=int, default=None, help="omit CVE years before this from the INDEX")
    ap.add_argument("--runner-gid", type=int, default=1000,
                    help="gid of the n8n python task runner (default 1000); "
                         "the cache is made group-writable by it")
    ap.add_argument("--no-chown", action="store_true", help="skip the permission fix")
    args = ap.parse_args()

    cache_dir = Path(args.cache_dir).resolve()
    mirror_dir = Path(args.mirror_dir).resolve() if args.mirror_dir else cache_dir / MIRROR_DIRNAME
    index_path = cache_dir / INDEX_FILENAME
    meta_path = cache_dir / META_FILENAME

    cache_dir.mkdir(parents=True, exist_ok=True)

    if args.dry_run:
        sync_mirror(mirror_dir, dry_run=True)
        return 0

    action = "skipped"
    if not args.reindex_only:
        action = sync_mirror(mirror_dir)
        print(f"mirror {action}: {mirror_dir}")

    if not mirror_dir.is_dir():
        sys.exit(f"mirror directory does not exist: {mirror_dir}")

    stats = build_index(mirror_dir, index_path, year_from=args.year_from)
    total_bytes = _dir_bytes(mirror_dir) + (index_path.stat().st_size if index_path.exists() else 0)

    meta = {
        "synced_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "action": action,
        "source": UPSTREAM_REPO,
        "mirror_dir": str(mirror_dir),
        "bytes": total_bytes,
        "year_from": args.year_from,
        **stats,
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    if not args.no_chown:
        print(f"permissions: {fix_permissions(cache_dir, gid=args.runner_gid)}")

    print(
        f"indexed {stats['cve_count']:,} CVEs / {stats['repo_count']:,} repos "
        f"/ {stats['owner_count']:,} authors — {_human(total_bytes)} on disk"
    )
    if stats["skipped_years"]:
        # Never let a bounded index look like a complete one.
        print(f"NOTE: --year-from {args.year_from} omitted {stats['skipped_years']} year(s) from the index")
    print(f"index: {index_path}")
    print(f"meta:  {meta_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
