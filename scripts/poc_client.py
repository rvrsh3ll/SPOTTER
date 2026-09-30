"""
poc_client.py — Exploit-availability lookups against a local PoC-in-GitHub mirror.

Answers one question that NVD cannot: *is there public exploit code for this CVE,
and is any of it worth an operator's time?*

Data source: https://github.com/nomi-sec/PoC-in-GitHub — a static tree of
`{year}/CVE-YYYY-NNNN.json` files, each a JSON array of GitHub repository objects
whose name or description matched that CVE ID. Roughly 9.4k CVEs / 62 MB as of
2026-08.

WHY A LOCAL MIRROR RATHER THAN LIVE FETCHES
-------------------------------------------
Three reasons, in order of how much they matter:

  1. OPSEC. Fetching per-CVE from the engagement's own source IP publishes which
     vulnerabilities the operator is interested in — which is a description of the
     target's estate. One clone of a very popular public repo carries no such
      signal. NVD product/version searches in cve_client.py carry target-derived
      terms too; set NVD_PROXY_URL, or BUCKET_PROBE_PROXY as its fallback, to route
      those lookups through managed egress.
  2. Offline. Lookups keep working when the engagement host has no egress, which
     is when an operator most needs to know whether an exploit exists.
  3. Speed. A lookup is one file open, not a network round trip, so enriching
     several hundred Technology nodes in a single WF14 pass is viable.

The mirror is refreshed from the HOST by scripts/sync_poc_mirror.py. This module
only ever reads it, and degrades to an empty result — never an exception — when
the mirror is missing, so a workflow that has not been synced yet reports "no
data" rather than taking the run down with it.

TRUST
-----
These repositories are UNVETTED. Membership is decided by regex-matching a CVE ID
against repository names and descriptions, so the corpus contains forks of forks,
empty stubs, unrelated projects, coursework, and occasionally malware. Every
record this module returns therefore carries `unvetted: True` and `warning`, and
nothing here ever downloads or executes repository contents.

`trust` is a deliberately readable heuristic (see `score_repo`), not a tuned
model — an operator has to be able to disagree with it at a glance.

Environment:
    SPOTTER_CACHE_DIR — cache directory (default: ./.spotter-cache)
    POC_MIRROR_DIR    — mirror location (default: $SPOTTER_CACHE_DIR/poc-in-github)
    POC_MIN_STARS     — drop repos below this star count (default 0 = keep all)
    POC_MAX_PER_CVE   — cap returned per CVE (default 10)
    POC_MIRROR_MAX_AGE_DAYS — report the mirror stale past this age (default 30)
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from spotter_cache import ensure_cache_path

DEFAULT_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".spotter-cache")

MIRROR_DIRNAME = "poc-in-github"
INDEX_FILENAME = "poc_fts.sqlite"
META_FILENAME = "poc_mirror_meta.json"

UPSTREAM_REPO = "https://github.com/nomi-sec/PoC-in-GitHub.git"

# Shown on every record, and repeated by the LLM tool and the frontend. Kept as a
# single constant so the three surfaces cannot drift into softer wording.
UNVETTED_WARNING = (
    "Unvetted third-party code from GitHub. Membership in this list means a "
    "repository name or description matched the CVE ID — nothing more. Read the "
    "source before running it, and never execute it on engagement infrastructure."
)

CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)


def normalise_cve(cve_id: str) -> Optional[str]:
    """Canonical upper-case CVE ID, or None if it is not shaped like one."""
    if not cve_id:
        return None
    m = CVE_RE.match(str(cve_id).strip())
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


def _parse_ts(value: Any) -> Optional[datetime]:
    """Parse a GitHub ISO-8601 'Z' timestamp; None on anything unexpected."""
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# ── Trust scoring ────────────────────────────────────────────────────────────
# Every term is an independent, individually defensible signal, and each is
# small enough that no single one decides the tier on its own. Deliberately NOT
# tuned against a labelled set — there isn't one, and a precise-looking score
# over unvetted data would imply a confidence nobody has earned.

TRUST_HIGH = 10.0
TRUST_MEDIUM = 5.0


def score_repo(repo: Dict[str, Any], cve_id: str = "", owner_poc_count: int = 0) -> Dict[str, Any]:
    """
    Return {'score': float, 'trust': 'high'|'medium'|'low', 'signals': [...]}.

    `signals` is the human-readable reason for the score. It exists so the UI and
    the LLM can explain a ranking instead of asserting one.
    """
    signals: List[str] = []
    score = 0.0

    stars = int(repo.get("stargazers_count") or 0)
    forks = int(repo.get("forks_count") or 0)
    watchers = int(repo.get("subscribers_count") or 0)
    is_fork = bool(repo.get("fork"))
    desc = (repo.get("description") or "").strip()

    # Popularity. Capped: past ~500 stars the marginal star says nothing more,
    # and without a cap Log4Shell's top repos would swamp every other term.
    if stars:
        score += min(stars, 500) / 50.0
        signals.append(f"{stars} stars")

    if not is_fork:
        score += 3.0
        signals.append("not a fork")
    elif stars == 0:
        score -= 2.0
        signals.append("dead fork (fork, no stars)")

    if len(desc) >= 40:
        score += 2.0
        signals.append("substantive description")
    elif desc:
        score += 1.0

    if watchers >= 3:
        score += 2.0
        signals.append(f"{watchers} watchers")

    if forks >= 5:
        score += 1.5
        signals.append(f"forked {forks}x")

    # Timeliness. A PoC published while the CVE was current is more likely to be
    # original research; much later ones are disproportionately reposts and
    # coursework. Measured against the CVE's own year, which is all the ID gives.
    created = _parse_ts(repo.get("created_at"))
    canon = normalise_cve(cve_id)
    if created and canon:
        cve_year = int(canon.split("-")[1])
        cve_epoch = datetime(cve_year, 1, 1, tzinfo=timezone.utc)
        if timedelta(0) <= (created - cve_epoch) <= timedelta(days=548):  # ~18 months
            score += 1.5
            signals.append("published while the CVE was current")

    # A researcher with PoCs across several CVEs is a different proposition from
    # a single-repo account. Requires the sync-time index; silently contributes
    # nothing when the index is absent (documented in mirror_status()).
    if owner_poc_count >= 3:
        score += 1.5
        signals.append(f"author has PoCs for {owner_poc_count} CVEs")

    # Empty stub: no stars, no description. Very common, near-uniformly useless.
    if stars == 0 and not desc:
        score -= 4.0
        signals.append("empty stub (no stars, no description)")

    trust = "high" if score >= TRUST_HIGH else ("medium" if score >= TRUST_MEDIUM else "low")
    return {"score": round(score, 2), "trust": trust, "signals": signals}


def shape_repo(repo: Dict[str, Any], cve_id: str = "", owner_poc_count: int = 0) -> Dict[str, Any]:
    """Upstream repo object → the record SPOTTER passes around."""
    owner = repo.get("owner") or {}
    scored = score_repo(repo, cve_id=cve_id, owner_poc_count=owner_poc_count)
    return {
        "cve_id": normalise_cve(cve_id) or cve_id,
        "full_name": repo.get("full_name"),
        "url": repo.get("html_url"),
        "description": (repo.get("description") or "").strip() or None,
        "owner": owner.get("login"),
        "stars": int(repo.get("stargazers_count") or 0),
        "forks": int(repo.get("forks_count") or 0),
        "watchers": int(repo.get("subscribers_count") or 0),
        "is_fork": bool(repo.get("fork")),
        "created_at": repo.get("created_at"),
        "pushed_at": repo.get("pushed_at"),
        "trust": scored["trust"],
        "trust_score": scored["score"],
        "trust_signals": scored["signals"],
        # Non-negotiable, on every record. See the module docstring.
        "unvetted": True,
        "warning": UNVETTED_WARNING,
    }


class PoCClient:
    def __init__(self, cache_dir: Optional[str] = None, mirror_dir: Optional[str] = None):
        # normpath so mirror_status() reports "/root/SPOTTER/.spotter-cache/..."
        # rather than the "/scripts/../" form the module-relative default produces —
        # this string is shown to operators when the mirror is missing.
        self.cache_dir = os.path.normpath(
            cache_dir or os.environ.get("SPOTTER_CACHE_DIR") or DEFAULT_CACHE_DIR
        )
        self.mirror_dir = os.path.normpath(
            mirror_dir
            or os.environ.get("POC_MIRROR_DIR")
            or os.path.join(self.cache_dir, MIRROR_DIRNAME)
        )
        self.index_path = os.path.join(self.cache_dir, INDEX_FILENAME)
        self.meta_path = os.path.join(self.cache_dir, META_FILENAME)
        ensure_cache_path(self.cache_dir, is_dir=True)
        for path in (self.index_path, self.meta_path):
            if os.path.exists(path):
                ensure_cache_path(path, is_dir=False)
        self._owner_counts: Optional[Dict[str, int]] = None

    # ── mirror state ─────────────────────────────────────────────────────────

    def available(self) -> bool:
        return os.path.isdir(self.mirror_dir)

    def _load_meta(self) -> Dict[str, Any]:
        try:
            with open(self.meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def mirror_status(self) -> Dict[str, Any]:
        """
        Describe the mirror without ever raising.

        `stale` matters more than it looks: a months-old mirror answers "no public
        exploit" for every recent CVE, which is indistinguishable from a real
        negative unless the caller surfaces the age.
        """
        meta = self._load_meta()
        max_age = int(os.environ.get("POC_MIRROR_MAX_AGE_DAYS") or 30)
        synced_at = meta.get("synced_at")
        age_days: Optional[float] = None
        synced = _parse_ts(synced_at)
        if synced:
            age_days = round((datetime.now(timezone.utc) - synced).total_seconds() / 86400.0, 2)
        return {
            "available": self.available(),
            "mirror_dir": self.mirror_dir,
            "indexed": os.path.exists(self.index_path),
            "owner_signal_available": os.path.exists(self.index_path),
            "synced_at": synced_at,
            "age_days": age_days,
            "max_age_days": max_age,
            "stale": (age_days is None) or (age_days > max_age),
            "cve_count": meta.get("cve_count"),
            "repo_count": meta.get("repo_count"),
            "bytes": meta.get("bytes"),
            "source": UPSTREAM_REPO,
        }

    # ── owner reputation (from the sync-time index) ──────────────────────────

    def _owner_count(self, login: Optional[str]) -> int:
        if not login:
            return 0
        if self._owner_counts is None:
            self._owner_counts = {}
            try:
                with sqlite3.connect(f"file:{self.index_path}?mode=ro", uri=True) as conn:
                    rows = conn.execute("SELECT owner, cve_count FROM owner_stats").fetchall()
                self._owner_counts = {r[0]: int(r[1]) for r in rows}
            except Exception:
                # No index yet: the term simply contributes nothing.
                self._owner_counts = {}
        return self._owner_counts.get(login, 0)

    # ── lookups ──────────────────────────────────────────────────────────────

    def _cve_path(self, canon: str) -> str:
        year = canon.split("-")[1]
        return os.path.join(self.mirror_dir, year, f"{canon}.json")

    def pocs_for_cve(
        self,
        cve_id: str,
        limit: Optional[int] = None,
        min_stars: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Ranked PoC repositories for one CVE. Empty list when the CVE has none, the
        mirror is absent, or the ID is malformed — never an exception.
        """
        canon = normalise_cve(cve_id)
        if not canon:
            return []
        if limit is None:
            limit = int(os.environ.get("POC_MAX_PER_CVE") or 10)
        if min_stars is None:
            min_stars = int(os.environ.get("POC_MIN_STARS") or 0)

        try:
            with open(self._cve_path(canon), "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            return []
        if not isinstance(raw, list):
            return []

        out = [
            shape_repo(r, cve_id=canon, owner_poc_count=self._owner_count((r.get("owner") or {}).get("login")))
            for r in raw
            if isinstance(r, dict) and int(r.get("stargazers_count") or 0) >= min_stars
        ]
        out.sort(key=lambda r: (-r["trust_score"], -r["stars"], r["full_name"] or ""))
        return out[:limit]

    def pocs_for_cves(
        self,
        cve_ids: Iterable[str],
        limit: Optional[int] = None,
        min_stars: Optional[int] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Batch form. Only CVEs with at least one PoC appear in the result."""
        out: Dict[str, List[Dict[str, Any]]] = {}
        for cve_id in cve_ids or []:
            hits = self.pocs_for_cve(cve_id, limit=limit, min_stars=min_stars)
            if hits:
                out[hits[0]["cve_id"]] = hits
        return out

    def has_poc(self, cve_id: str) -> bool:
        canon = normalise_cve(cve_id)
        return bool(canon) and os.path.exists(self._cve_path(canon))

    def search(self, keyword: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Keyword search over repo names and descriptions, for the case where a
        product name is known but no CVE is. Requires the sync-time FTS index;
        returns [] without it rather than falling back to a 9.4k-file scan.
        """
        keyword = (keyword or "").strip()
        if not keyword or not os.path.exists(self.index_path):
            return []
        try:
            with sqlite3.connect(f"file:{self.index_path}?mode=ro", uri=True) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT r.cve_id, r.payload FROM poc_fts f "
                    "JOIN repos r ON r.rowid = f.rowid "
                    "WHERE poc_fts MATCH ? ORDER BY r.stars DESC LIMIT ?",
                    (keyword, max(1, min(limit * 5, 500))),
                ).fetchall()
        except Exception:
            return []

        out: List[Dict[str, Any]] = []
        for row in rows:
            try:
                repo = json.loads(row["payload"])
            except Exception:
                continue
            out.append(
                shape_repo(
                    repo,
                    cve_id=row["cve_id"],
                    owner_poc_count=self._owner_count((repo.get("owner") or {}).get("login")),
                )
            )
        out.sort(key=lambda r: (-r["trust_score"], -r["stars"]))
        return out[:limit]

    def summarise_for_cves(self, cve_ids: Iterable[str], top_n: int = 3) -> Dict[str, Any]:
        """
        Compact rollup for writing onto a graph node or into an LLM prompt.

        Returns poc_count / exploit_available / cves_with_pocs / top_pocs, where
        top_pocs is the best `top_n` repositories across every supplied CVE.
        """
        by_cve = self.pocs_for_cves(cve_ids)
        flat = [r for hits in by_cve.values() for r in hits]
        flat.sort(key=lambda r: (-r["trust_score"], -r["stars"]))
        return {
            "poc_count": len(flat),
            "exploit_available": bool(flat),
            "cves_with_pocs": sorted(by_cve.keys()),
            "top_pocs": flat[:top_n],
            "best_trust": flat[0]["trust"] if flat else None,
        }


if __name__ == "__main__":
    import sys

    client = PoCClient()
    print(json.dumps(client.mirror_status(), indent=2))
    target = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print(json.dumps(client.pocs_for_cve(target, limit=5), indent=2))
