"""Shared cache-directory helpers for SPOTTER scripts.

The cache is a host bind mount shared by root-run maintenance scripts and the
n8n Python task runner (uid/gid 1000). Keep directories setgid and group-writable
so whichever side writes first does not lock the other one out.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

PathLike = Union[str, os.PathLike[str]]


def _runner_gid() -> int:
    try:
        return int(os.environ.get("SPOTTER_RUNNER_GID") or 1000)
    except (TypeError, ValueError):
        return 1000


RUNNER_GID = _runner_gid()


def ensure_cache_path(path: PathLike, *, is_dir: Optional[bool] = None, gid: int = RUNNER_GID) -> None:
    """Best-effort group-write/setgid permissions for shared cache paths."""
    p = Path(path)
    try:
        if is_dir is None:
            is_dir = p.is_dir()
        if is_dir:
            p.mkdir(parents=True, exist_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chown(p, -1, gid)
        except PermissionError:
            pass
        except OSError:
            pass
        mode = p.stat().st_mode
        if is_dir:
            os.chmod(p, mode | 0o2070)
        else:
            os.chmod(p, mode | 0o060)
    except OSError:
        pass


def ensure_cache_tree(path: PathLike, *, gid: int = RUNNER_GID) -> None:
    """Best-effort recursive group-write/setgid permissions for a cache tree."""
    root = Path(path)
    ensure_cache_path(root, is_dir=True, gid=gid)
    try:
        walker = os.walk(root)
    except OSError:
        return
    for cur, dirs, files in walker:
        ensure_cache_path(cur, is_dir=True, gid=gid)
        for dirname in dirs:
            ensure_cache_path(Path(cur) / dirname, is_dir=True, gid=gid)
        for filename in files:
            ensure_cache_path(Path(cur) / filename, is_dir=False, gid=gid)
