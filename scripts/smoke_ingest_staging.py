#!/usr/bin/env python3
"""Offline smoke test for chunked-upload staging.

No Docker, no n8n, no network. The sidecar is a thin wrapper over this
library, so the cases here are the contract the browser and WF06 rely on.

    python3 scripts/smoke_ingest_staging.py
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from ingest_staging import (  # noqa: E402
    CHUNK_MAX_BYTES,
    COMPLETE_TTL_SECONDS,
    INCOMPLETE_TTL_SECONDS,
    StagingError,
    append_chunk,
    complete,
    create_upload,
    host_command,
    release_staged,
    resolve_staged,
    status,
    sweep,
)

failures = 0
checks = 0


def ok(cond: bool, label: str, extra: str = "") -> None:
    global failures, checks
    checks += 1
    if cond:
        print(f"  ok    {label}")
        return
    failures += 1
    print(f"  FAIL  {label}" + (f"\n        {extra}" if extra else ""))


def expect(exc_type, status: int, fn, label: str):
    try:
        fn()
    except exc_type as exc:
        got = getattr(exc, "status", None)
        ok(got == status, label, f"status={got} msg={exc}")
        return exc
    except Exception as exc:  # noqa: BLE001
        ok(False, label, f"raised {type(exc).__name__}: {exc}")
        return None
    ok(False, label, "did not raise")
    return None


def main() -> int:
    saved = {
        k: os.environ.get(k)
        for k in (
            "SPOTTER_INGEST_STAGING_DIR",
            "SPOTTER_STAGED_UPLOAD_MAX_BYTES",
            "SPOTTER_STAGED_UPLOAD_DISK_CAP",
        )
    }
    tmp = tempfile.TemporaryDirectory(prefix="spotter-staging-")
    root = Path(tmp.name)
    os.environ["SPOTTER_INGEST_STAGING_DIR"] = str(root)
    os.environ["SPOTTER_STAGED_UPLOAD_MAX_BYTES"] = str(4 * 1024 ** 3)
    os.environ["SPOTTER_STAGED_UPLOAD_DISK_CAP"] = str(20 * 1024 ** 3)
    try:
        _run(root)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        tmp.cleanup()
    print()
    if failures:
        print(f"{failures} FAILURE(S) of {checks}")
        return 1
    print(f"smoke_ingest_staging: all {checks} checks passed")
    return 0


def _run(root: Path) -> None:
    print("── create, append, resume, complete")
    created = create_upload("alice", "report.zip", 8)
    upload_id = created["upload_id"]
    ok(len(upload_id) == 32 and upload_id.isalnum(), "id is 32 hex", upload_id)
    ok(created["offset"] == 0 and created["size"] == 8, "create reports offset 0")
    data_path = root / upload_id
    ok(data_path.is_file(), "data file is a direct child of the staging root")
    ok((data_path.stat().st_mode & 0o007) == 0, "staged file is not world-readable")

    first = append_chunk("alice", upload_id, 0, b"abcd")
    ok(first["offset"] == 4, "first chunk advances the offset", str(first))
    st = status("alice", upload_id)
    ok(st["offset"] == 4 and st["complete"] is False, "status reports the server offset")

    mismatch = expect(
        StagingError, 409,
        lambda: append_chunk("alice", upload_id, 0, b"zzzz"),
        "a retried offset is rejected with the current offset",
    )
    if mismatch is not None:
        ok(mismatch.extra.get("offset") == 4, "mismatch names the server offset", str(mismatch.extra))

    second = append_chunk("alice", upload_id, 4, b"efgh")
    ok(second["offset"] == 8, "resume from the server offset completes the file")
    done = complete("alice", upload_id)
    ok(done["size"] == 8, "complete accepts a byte-identical file")
    ok(data_path.read_bytes() == b"abcdefgh", "bytes on disk match what was sent")
    resolved = resolve_staged(upload_id)
    ok(resolved["path"] == str(data_path.resolve()), "resolve returns the confined path", resolved["path"])
    ok(resolved["filename"] == "report.zip" and resolved["size"] == 8, "resolve returns filename and size")

    print("── refusals")
    expect(StagingError, 400, lambda: status("alice", "../etc/passwd"), "traversal id is rejected")
    expect(StagingError, 400, lambda: status("alice", "not-a-uuid"), "non-uuid id is rejected")
    expect(
        StagingError, 404,
        lambda: status("bob", upload_id),
        "another user cannot read the offset",
    )
    expect(
        StagingError, 404,
        lambda: append_chunk("bob", upload_id, 8, b"x"),
        "another user cannot append",
    )
    expect(
        StagingError, 404,
        lambda: complete("bob", upload_id),
        "another user cannot complete",
    )

    print("── one active upload, caps, sweep")
    # A completed upload does not block the next one. An incomplete one does.
    first_open = create_upload("carol", "open.bin", 4)
    busy = expect(
        StagingError, 409,
        lambda: create_upload("carol", "different.bin", 4),
        "one active upload per owner",
    )
    if busy is not None:
        ok(busy.extra.get("upload_id") == first_open["upload_id"], "409 names the existing id")
        ok(busy.extra.get("filename") == "open.bin", "409 names the existing filename")
    expect(
        StagingError, 400,
        lambda: append_chunk("carol", first_open["upload_id"], 0, b"abcde"),
        "a chunk past the declared size is rejected",
    )
    os.environ["SPOTTER_STAGED_UPLOAD_DISK_CAP"] = "3"
    expect(
        StagingError, 507,
        lambda: create_upload("dave", "big.bin", 4),
        "create is refused when the disk cap would be exceeded",
    )
    os.environ["SPOTTER_STAGED_UPLOAD_DISK_CAP"] = str(20 * 1024 ** 3)
    os.environ["SPOTTER_STAGED_UPLOAD_MAX_BYTES"] = "3"
    expect(
        StagingError, 413,
        lambda: create_upload("dave", "big.bin", 4),
        "create is refused over the per-file cap",
    )
    os.environ["SPOTTER_STAGED_UPLOAD_MAX_BYTES"] = str(4 * 1024 ** 3)
    # carol's upload is still incomplete and has promised 4 bytes it has not
    # written. Those bytes have to count, or a second upload walks into the cap.
    os.environ["SPOTTER_STAGED_UPLOAD_DISK_CAP"] = "6"
    expect(
        StagingError, 507,
        lambda: create_upload("dave", "overlap.bin", 4),
        "an incomplete upload's unpaid bytes count against the disk cap",
    )
    os.environ["SPOTTER_STAGED_UPLOAD_DISK_CAP"] = str(20 * 1024 ** 3)
    from ingest_staging import limits
    info = limits()
    ok(info.get("disk_reserved", 0) >= 4, "limits reports bytes still promised", str(info))
    ok(info.get("runner_cap") == 1024 ** 3, "limits reports the runner cap", str(info.get("runner_cap")))
    ok("disk_remaining" in info and "file_cap" in info, "limits is what the browser asks before a chunk")

    real_usage = shutil.disk_usage
    usage = type("usage", (), {})
    low = usage()
    low.total, low.used, low.free = 100, 95, 1
    shutil.disk_usage = lambda _path: low
    try:
        expect(
            StagingError, 507,
            lambda: create_upload("dave", "big.bin", 4),
            "create is refused when free space cannot hold the declared size",
        )
    finally:
        shutil.disk_usage = real_usage

    expect(
        StagingError, 413,
        lambda: append_chunk("carol", first_open["upload_id"], 0, b"x" * (CHUNK_MAX_BYTES + 1)),
        "a chunk over 32 MiB is rejected",
    )

    os.environ["SPOTTER_INGEST_STAGING_DIR"] = "relative/staging"
    expect(StagingError, 500, lambda: create_upload("dave", "x.bin", 1), "a relative staging root is refused")
    os.environ["SPOTTER_INGEST_STAGING_DIR"] = str(root)

    print("── sweep and release")
    meta = root / (first_open["upload_id"] + ".meta")
    _backdate(meta, time.time() - INCOMPLETE_TTL_SECONDS - 60)
    removed = sweep()
    ok(removed >= 1 and not (root / first_open["upload_id"]).exists(), "incomplete uploads older than 24h are swept")

    fresh = create_upload("erin", "keep.bin", 2)
    append_chunk("erin", fresh["upload_id"], 0, b"ok")
    complete("erin", fresh["upload_id"])
    ok(sweep() == 0 or (root / fresh["upload_id"]).exists(), "a fresh completed file survives the sweep")
    _backdate(root / (fresh["upload_id"] + ".meta"), time.time() - COMPLETE_TTL_SECONDS - 60)
    sweep()
    ok(not (root / fresh["upload_id"]).exists(), "a completed file older than 7 days is swept")

    kept = create_upload("frank", "keep2.bin", 3)
    append_chunk("frank", kept["upload_id"], 0, b"xyz")
    complete("frank", kept["upload_id"])
    outside = root.parent / "not-staged.bin"
    outside.write_bytes(b"nope")
    ok(release_staged(str(outside)) is False and outside.exists(), "release refuses a path outside the staging root")
    outside.unlink()
    ok(release_staged(str(root / kept["upload_id"])) is True, "release unlinks a uuid under the root")
    ok(not (root / kept["upload_id"]).exists(), "released data file is gone")
    ok(not (root / (kept["upload_id"] + ".meta")).exists(), "released meta file is gone")

    planted = create_upload("gina", "link.bin", 1)
    append_chunk("gina", planted["upload_id"], 0, b"Z")
    complete("gina", planted["upload_id"])
    # The symlink target must be outside the staging root to prove confinement.
    outside_target = Path(tempfile.mkdtemp(prefix="spotter-escape-")) / "secret"
    outside_target.write_bytes(b"secret")
    link = root / planted["upload_id"]
    link.unlink()
    link.symlink_to(outside_target)
    expect(StagingError, 400, lambda: resolve_staged(planted["upload_id"]), "a symlink out of the staging root is rejected")
    ok(outside_target.exists(), "the escape target was not unlinked")
    link.unlink()
    outside_target.unlink()
    outside_target.parent.rmdir()

    incomplete = create_upload("hank", "partial.bin", 4)
    append_chunk("hank", incomplete["upload_id"], 0, b"ab")
    expect(StagingError, 409, lambda: resolve_staged(incomplete["upload_id"]), "an incomplete id cannot be resolved")

    print("── host command")
    ok("ingest_sharphound_large.py" in host_command("sharphound", "/data/ingest-staging/abc"), "sharphound names its host script")
    ok("ingest_nessus_large.py" in host_command("nessus", "/tmp/x"), "nessus names its host script")
    ok("no streaming host ingest" in host_command("text", "/tmp/x"), "an unknown format does not invent a host script")


def _backdate(meta_path: Path, created: float) -> None:
    import json
    meta = json.loads(meta_path.read_text())
    meta["created"] = created
    meta_path.write_text(json.dumps(meta))


if __name__ == "__main__":
    raise SystemExit(main())
