"""Chunked browser uploads that will not fit in one JSON webhook body.

The on-disk name is a 32-character hex uuid. The client filename lives only in
the sidecar meta file, so a crafted name cannot escape the staging root.
WF06 resolves a completed id to that path and parses the file in place.

State is files plus an exclusive lock, so more than one gunicorn worker is
safe. A relative staging root is refused: under the multi-file compose
invocation a relative bind source resolves against the Flowsint checkout.
"""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

# One PATCH must fit the nginx location cap. The browser sends 16 MB; 32 MB
# is the ceiling so a buggy client cannot put the whole file in one request.
CHUNK_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_FILE_CAP = 4 * 1024 ** 3
DEFAULT_DISK_CAP = 20 * 1024 ** 3
DEFAULT_RUNNER_CAP = 1024 ** 3
INCOMPLETE_TTL_SECONDS = 24 * 3600
# Backstop only. A successful parse deletes the file; this catches a completed
# upload whose workflow never reached that delete.
COMPLETE_TTL_SECONDS = 7 * 24 * 3600
ID_RE_TEXT = r"^[0-9a-f]{32}$"

_DEFAULT_ROOT = "/data/ingest-staging"


class StagingError(Exception):
    """A refused staging operation. `status` is the HTTP status the sidecar returns."""

    def __init__(self, message: str, status: int = 400, extra: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status = status
        self.extra = extra or {}


def file_cap() -> int:
    return int(os.environ.get("SPOTTER_STAGED_UPLOAD_MAX_BYTES", str(DEFAULT_FILE_CAP)))


def disk_cap() -> int:
    return int(os.environ.get("SPOTTER_STAGED_UPLOAD_DISK_CAP", str(DEFAULT_DISK_CAP)))


def runner_cap() -> int:
    return int(os.environ.get("SPOTTER_RUNNER_PARSE_MAX_BYTES", str(DEFAULT_RUNNER_CAP)))


def staging_root() -> Path:
    raw = os.environ.get("SPOTTER_INGEST_STAGING_DIR", _DEFAULT_ROOT)
    if not raw or not os.path.isabs(raw):
        raise StagingError("SPOTTER_INGEST_STAGING_DIR must be an absolute path", 500)
    root = Path(raw).resolve()
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StagingError(
            f"staging directory is not writable ({root}): {exc}. "
            "Create it and chown it to uid 1000 before starting the stack.",
            500,
        ) from exc
    return root


def _is_id(value: str) -> bool:
    if not value or len(value) != 32:
        return False
    for ch in value:
        if ch not in "0123456789abcdef":
            return False
    return True


def _confined(root: Path, name: str) -> Path:
    """Resolve `name` and refuse anything that is not a direct child of `root`."""
    if not name or name != os.path.basename(name) or "/" in name or "\\" in name:
        raise StagingError("upload id is not a staging id", 400)
    path = (root / name).resolve()
    if path.parent != root:
        raise StagingError("upload id escapes the staging root", 400)
    return path


def _paths(upload_id: str) -> Tuple[Path, Path, Path]:
    if not _is_id(upload_id or ""):
        raise StagingError("upload id is not a staging id", 400)
    root = staging_root()
    data = _confined(root, upload_id)
    meta = _confined(root, upload_id + ".meta")
    lock = _confined(root, upload_id + ".lock")
    return data, meta, lock


def _read_meta(meta_path: Path) -> Dict[str, Any]:
    try:
        with meta_path.open("r", encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise StagingError(f"staging metadata is unreadable: {exc}", 500) from exc
    if not isinstance(meta, dict):
        raise StagingError("staging metadata is unreadable", 500)
    return meta


def _write_meta(meta_path: Path, meta: Dict[str, Any]) -> None:
    tmp = meta_path.with_name(meta_path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(meta, fh, separators=(",", ":"))
        fh.write("\n")
    os.chmod(tmp, 0o640)
    os.replace(tmp, meta_path)


@contextmanager
def _flock(path: Path) -> Iterator[None]:
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o640)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _root_lock_path(root: Path) -> Path:
    return _confined(root, ".staging.lock")


def _safe_filename(filename: str) -> str:
    name = os.path.basename(str(filename or "").replace("\\", "/")).replace("\x00", "")
    name = name.strip() or "upload"
    return name[:255]


def _disk_used(root: Path) -> int:
    total = 0
    try:
        names = os.listdir(root)
    except OSError:
        return 0
    for name in names:
        if not _is_id(name):
            continue
        try:
            total += (root / name).stat().st_size
        except OSError:
            continue
    return total


def _disk_reserved(root: Path) -> int:
    """Bytes incomplete uploads have promised but not written yet.

    Counting only bytes already on disk would let a second upload start while
    the first still has gigabytes outstanding, and both would then pass the cap.
    """
    pending = 0
    for upload_id, _meta_path, meta in _iter_meta(root):
        if meta.get("complete"):
            continue
        declared = int(meta.get("declared_size") or 0)
        try:
            have = (root / upload_id).stat().st_size
        except OSError:
            have = 0
        pending += max(0, declared - have)
    return pending


def _disk_committed(root: Path) -> int:
    return _disk_used(root) + _disk_reserved(root)


def limits() -> Dict[str, Any]:
    """Caps and room left. The browser reads this before sending a chunk."""
    root = staging_root()
    used = _disk_used(root)
    reserved = _disk_reserved(root)
    try:
        free = shutil.disk_usage(root).free
    except OSError as exc:
        raise StagingError(f"could not check free disk: {exc}", 500) from exc
    cap = disk_cap()
    return {
        "file_cap": file_cap(),
        "runner_cap": runner_cap(),
        "disk_cap": cap,
        "disk_used": used,
        "disk_reserved": reserved,
        "disk_free": free,
        "disk_remaining": max(0, min(cap - used - reserved, free)),
    }


def _iter_meta(root: Path) -> Iterator[Tuple[str, Path, Dict[str, Any]]]:
    try:
        names = os.listdir(root)
    except OSError:
        return
    for name in names:
        if not name.endswith(".meta"):
            continue
        upload_id = name[:-5]
        if not _is_id(upload_id):
            continue
        meta_path = root / name
        try:
            meta = _read_meta(meta_path)
        except StagingError:
            continue
        yield upload_id, meta_path, meta


def sweep(now: Optional[float] = None) -> int:
    """Delete abandoned incomplete uploads, and completed files the parser never released."""
    root = staging_root()
    now = time.time() if now is None else now
    removed = 0
    with _flock(_root_lock_path(root)):
        for upload_id, meta_path, meta in list(_iter_meta(root)):
            created = float(meta.get("created") or 0)
            age = now - created
            complete = bool(meta.get("complete"))
            stale = (not complete and age > INCOMPLETE_TTL_SECONDS) or (
                complete and age > COMPLETE_TTL_SECONDS
            )
            if not stale:
                continue
            data = root / upload_id
            lock = root / (upload_id + ".lock")
            for path in (data, meta_path, lock):
                try:
                    path.unlink()
                    removed += 1
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
    return removed


def _active_for(root: Path, owner: str) -> Optional[Dict[str, Any]]:
    for upload_id, _meta_path, meta in _iter_meta(root):
        if meta.get("owner") != owner or meta.get("complete"):
            continue
        data = root / upload_id
        try:
            offset = data.stat().st_size
        except OSError:
            offset = 0
        return {
            "upload_id": upload_id,
            "offset": offset,
            "filename": meta.get("filename") or "upload",
            "size": int(meta.get("declared_size") or 0),
        }
    return None


def create_upload(owner: str, filename: str, declared_size: Any) -> Dict[str, Any]:
    owner = str(owner or "").strip()
    if not owner:
        raise StagingError("missing owner", 401)
    try:
        declared = int(declared_size)
    except (TypeError, ValueError) as exc:
        raise StagingError("size must be an integer", 400) from exc
    cap = file_cap()
    if declared < 1:
        raise StagingError("size must be at least 1 byte", 400)
    if declared > cap:
        raise StagingError(
            f"file is {declared} bytes, over the {cap} byte staging cap. "
            "Ingest it on the host with scripts/ingest_sharphound_large.py, "
            "scripts/ingest_nessus_large.py, scripts/ingest_eyewitness.py, "
            "or scripts/ingest_cloudschism.py.",
            413,
        )
    root = staging_root()
    sweep()
    with _flock(_root_lock_path(root)):
        existing = _active_for(root, owner)
        if existing:
            raise StagingError(
                "an upload is already in progress",
                409,
                existing,
            )
        used = _disk_committed(root)
        if used + declared > disk_cap():
            raise StagingError(
                "staging disk cap would be exceeded "
                f"({used + declared} bytes > {disk_cap()} bytes)",
                507,
            )
        try:
            free = shutil.disk_usage(root).free
        except OSError as exc:
            raise StagingError(f"could not check free disk: {exc}", 500) from exc
        if free < declared:
            raise StagingError(
                f"not enough free disk for the declared size ({free} bytes free, {declared} required)",
                507,
            )
        upload_id = uuid.uuid4().hex
        data, meta_path, lock = _paths(upload_id)
        try:
            fd = os.open(data, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
            os.close(fd)
        except OSError as exc:
            raise StagingError(
                f"could not create staged file: {exc}. "
                "The staging directory must be writable by uid 1000.",
                500,
            ) from exc
        _write_meta(meta_path, {
            "owner": owner,
            "filename": _safe_filename(filename),
            "declared_size": declared,
            "created": time.time(),
            "complete": False,
        })
        # Touch the lock file as the same user so a later worker can flock it.
        os.close(os.open(lock, os.O_CREAT | os.O_RDWR, 0o640))
    return {
        "upload_id": upload_id,
        "offset": 0,
        "filename": _safe_filename(filename),
        "size": declared,
    }


def _owned(owner: str, upload_id: str) -> Tuple[Path, Dict[str, Any], Path]:
    owner = str(owner or "").strip()
    if not owner:
        raise StagingError("missing owner", 401)
    data, meta_path, lock = _paths(upload_id)
    if not meta_path.is_file():
        raise StagingError("upload not found", 404)
    meta = _read_meta(meta_path)
    if meta.get("owner") != owner:
        # Same response as a missing id: do not confirm that the id exists.
        raise StagingError("upload not found", 404)
    return data, meta, meta_path


def status(owner: str, upload_id: str) -> Dict[str, Any]:
    data, meta, _meta_path = _owned(owner, upload_id)
    try:
        offset = data.stat().st_size
    except OSError:
        offset = 0
    return {
        "upload_id": upload_id,
        "offset": offset,
        "complete": bool(meta.get("complete")),
        "filename": meta.get("filename") or "upload",
        "size": int(meta.get("declared_size") or 0),
    }


def append_chunk(owner: str, upload_id: str, offset: Any, chunk: bytes) -> Dict[str, Any]:
    try:
        want = int(offset)
    except (TypeError, ValueError) as exc:
        raise StagingError("Upload-Offset must be an integer", 400) from exc
    if want < 0:
        raise StagingError("Upload-Offset must be >= 0", 400)
    if not isinstance(chunk, (bytes, bytearray)) or not chunk:
        raise StagingError("chunk is empty", 400)
    if len(chunk) > CHUNK_MAX_BYTES:
        raise StagingError(
            f"chunk is {len(chunk)} bytes; max is {CHUNK_MAX_BYTES}",
            413,
        )
    data, meta, _meta_path = _owned(owner, upload_id)
    _data, _meta, lock = _paths(upload_id)
    with _flock(lock):
        # Re-read under the lock. A retry and a new chunk can race.
        meta = _read_meta(_meta)
        if meta.get("complete"):
            raise StagingError("upload is already complete", 409)
        try:
            current = data.stat().st_size
        except OSError as exc:
            raise StagingError(f"staged file is missing: {exc}", 500) from exc
        if want != current:
            raise StagingError(
                f"offset mismatch: client sent {want}, server has {current}",
                409,
                {"upload_id": upload_id, "offset": current},
            )
        declared = int(meta.get("declared_size") or 0)
        if current + len(chunk) > declared:
            raise StagingError(
                f"chunk would pass the declared size ({current + len(chunk)} > {declared})",
                400,
            )
        with data.open("ab") as fh:
            fh.write(chunk)
        new_offset = current + len(chunk)
    return {"upload_id": upload_id, "offset": new_offset}


def complete(owner: str, upload_id: str) -> Dict[str, Any]:
    data, meta, meta_path = _owned(owner, upload_id)
    _data, _meta, lock = _paths(upload_id)
    with _flock(lock):
        meta = _read_meta(meta_path)
        if meta.get("complete"):
            return {
                "upload_id": upload_id,
                "size": int(meta.get("declared_size") or 0),
                "filename": meta.get("filename") or "upload",
            }
        try:
            size = data.stat().st_size
        except OSError as exc:
            raise StagingError(f"staged file is missing: {exc}", 500) from exc
        declared = int(meta.get("declared_size") or 0)
        if size != declared:
            raise StagingError(
                f"incomplete upload: {size} bytes on disk, {declared} declared",
                400,
                {"upload_id": upload_id, "offset": size, "size": declared},
            )
        meta["complete"] = True
        meta["completed"] = time.time()
        _write_meta(meta_path, meta)
    return {
        "upload_id": upload_id,
        "size": declared,
        "filename": meta.get("filename") or "upload",
    }


def resolve_staged(upload_id: str) -> Dict[str, Any]:
    """Map a completed id to its path. Used by WF06, which does not re-check the owner.

    The id is an unguessable capability and the webhook is already behind the
    session gate. Incomplete, non-uuid, and out-of-root ids are rejected.
    """
    data, meta_path, _lock = _paths(upload_id)
    if not meta_path.is_file() or not data.is_file():
        raise StagingError("staged upload not found", 404)
    # realpath confinement: a symlink planted in the staging dir must not
    # point the parser at an arbitrary file.
    root = staging_root()
    real = data.resolve()
    if real.parent != root or real.name != upload_id:
        raise StagingError("staged path escapes the staging root", 400)
    meta = _read_meta(meta_path)
    if not meta.get("complete"):
        raise StagingError("staged upload is not complete", 409)
    size = real.stat().st_size
    declared = int(meta.get("declared_size") or 0)
    if size != declared:
        raise StagingError(
            f"staged upload size mismatch ({size} bytes on disk, {declared} declared)",
            400,
        )
    return {
        "path": str(real),
        "filename": meta.get("filename") or "upload",
        "size": size,
        "complete": True,
    }


def release_staged(path: str) -> bool:
    """Unlink a staged file and its meta. No-op unless the realpath is a uuid under the root.

    Called after a successful parse. A failed parse leaves the file so the
    operator can retry without uploading it again.
    """
    if not path:
        return False
    try:
        root = staging_root()
    except StagingError:
        return False
    try:
        real = Path(path).resolve()
    except OSError:
        return False
    if real.parent != root or not _is_id(real.name):
        return False
    removed = False
    for name in (real.name, real.name + ".meta", real.name + ".lock"):
        try:
            (root / name).unlink()
            removed = True
        except FileNotFoundError:
            pass
        except OSError:
            pass
    return removed


def host_command(fmt: str, path: str) -> str:
    """The host ingest command for a file the runner will not read."""
    fmt = (fmt or "").strip().lower()
    if fmt == "sharphound":
        return f"python3 scripts/ingest_sharphound_large.py --zip {path} --campaign <name>"
    if fmt == "nessus":
        return f"python3 scripts/ingest_nessus_large.py --input {path} --campaign <name>"
    if fmt == "eyewitness":
        return f"python3 scripts/ingest_eyewitness.py --input {path} --campaign <name>"
    if fmt == "cloudschism":
        return f"python3 scripts/ingest_cloudschism.py --input {path} --campaign <name>"
    return (
        f"no streaming host ingest is registered for format {fmt or 'unknown'}; "
        f"the file is at {path}. Split it, or raise SPOTTER_RUNNER_PARSE_MAX_BYTES "
        "only if this host can spare the RAM to parse it in the runner."
    )
