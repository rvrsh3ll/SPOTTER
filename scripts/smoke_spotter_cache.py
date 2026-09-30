#!/usr/bin/env python3
"""Smoke tests for shared SPOTTER cache permission helpers."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from spotter_cache import ensure_cache_path, ensure_cache_tree


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _ok(name: str) -> None:
    print(f"  ok    {name}")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "cache"
        ensure_cache_path(root, is_dir=True)
        assert root.is_dir()
        assert _mode(root) & stat.S_IRWXG == stat.S_IRWXG
        assert _mode(root) & stat.S_ISGID == stat.S_ISGID
        _ok("cache directories are created group-writable and setgid")

        data = root / "cve_cache.db"
        data.write_text("cache", encoding="utf-8")
        os.chmod(data, 0o600)
        ensure_cache_path(data, is_dir=False)
        assert _mode(data) & stat.S_IRGRP
        assert _mode(data) & stat.S_IWGRP
        _ok("cache files are repaired group-readable and group-writable")

        nested = root / "rag_index" / "collection.json"
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_text("{}", encoding="utf-8")
        os.chmod(nested.parent, 0o700)
        os.chmod(nested, 0o600)
        ensure_cache_tree(root)
        assert _mode(nested.parent) & stat.S_IRWXG == stat.S_IRWXG
        assert _mode(nested.parent) & stat.S_ISGID == stat.S_ISGID
        assert _mode(nested) & stat.S_IRGRP
        assert _mode(nested) & stat.S_IWGRP
        _ok("cache trees are repaired recursively")

    print("3/3 checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
