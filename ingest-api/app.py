"""Chunked-upload sidecar for the dashboard ingest path.

nginx overwrites X-Spotter-User from the session, so this process trusts that
header and nothing the client sends as an identity. No host port: the dashboard
server proxies /ingest/ here. Upload state lives in ingest-staging/, not in
this process, so a restart does not lose an in-progress upload.
"""

from __future__ import annotations

import sys

sys.path.insert(0, "/data/scripts")

from flask import Flask, request

from ingest_staging import (  # noqa: E402
    StagingError,
    append_chunk,
    complete,
    create_upload,
    limits,
    status,
)

app = Flask(__name__)


def _owner() -> str:
    return str(request.headers.get("X-Spotter-User") or "").strip()


def _error(exc: StagingError):
    body = {"error": str(exc)}
    body.update(exc.extra)
    return body, exc.status


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/ingest/limits")
def get_limits():
    """Caps and free room. Called before the first chunk, so a file that cannot
    be parsed — or will not fit — is refused with no bytes uploaded."""
    if not _owner():
        return {"error": "missing owner"}, 401
    try:
        return limits()
    except StagingError as exc:
        return _error(exc)


@app.post("/ingest/uploads")
def create():
    owner = _owner()
    if not owner:
        return {"error": "missing owner"}, 401
    payload = request.get_json(silent=True) or {}
    try:
        return create_upload(owner, payload.get("filename"), payload.get("size"))
    except StagingError as exc:
        return _error(exc)


@app.get("/ingest/uploads/<upload_id>")
def get_status(upload_id: str):
    try:
        return status(_owner(), upload_id)
    except StagingError as exc:
        return _error(exc)


@app.patch("/ingest/uploads/<upload_id>")
def patch_chunk(upload_id: str):
    try:
        return append_chunk(
            _owner(),
            upload_id,
            request.headers.get("Upload-Offset"),
            request.get_data() or b"",
        )
    except StagingError as exc:
        return _error(exc)


@app.post("/ingest/uploads/<upload_id>/complete")
def finish(upload_id: str):
    try:
        return complete(_owner(), upload_id)
    except StagingError as exc:
        return _error(exc)
