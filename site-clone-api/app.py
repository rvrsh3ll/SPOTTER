#!/usr/bin/env python3
"""HTTP API for SPOTTER Site Clone jobs.

POST /clone            start a job (async), returns {job_id, status}
GET  /jobs/<id>        status, progress, analysis summary (no raw secrets)
POST /jobs/<id>/cancel request cancel
GET  /health           liveness
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(os.environ.get("SPOTTER_SCRIPTS_DIR") or "/data/scripts")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import site_clone  # noqa: E402

DATA = Path(os.environ.get("SITE_CLONE_DATA") or "/data/clones")
SAFE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
JOBS: dict[str, dict[str, Any]] = {}
LOCK = threading.Lock()
PROCS: dict[str, Any] = {}


def _job_dir(campaign_id: str, job_id: str) -> Path:
    camp = campaign_id if SAFE.match(campaign_id or "") else "unknown"
    if not SAFE.match(job_id or ""):
        raise ValueError("invalid job id")
    return DATA / camp / job_id


def _public(job: dict[str, Any]) -> dict[str, Any]:
    """Strip anything a browser or log should not see."""
    analysis = job.get("analysis") or {}
    findings = analysis.get("findings") or []
    out = {
        "job_id": job.get("job_id"),
        "campaign_id": job.get("campaign_id"),
        "url": job.get("url"),
        "status": job.get("status"),
        "error": job.get("error"),
        "progress": job.get("progress") or {},
        "options": job.get("options") or {},
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "files": job.get("files"),
        "bytes": job.get("bytes"),
        "elapsed_seconds": job.get("elapsed_seconds"),
        "warnings": list(job.get("warnings") or [])[:40],
        "deobfuscation": job.get("deobfuscation") or None,
        "ocr": job.get("ocr") or None,
        "dns": job.get("dns") or None,
        "ingested": job.get("ingested") or _load_ingested(job) or None,
        "analysis": {
            "ok": analysis.get("ok"),
            "files_scanned": analysis.get("files_scanned"),
            "finding_count": analysis.get("finding_count"),
            "high_or_critical": analysis.get("high_or_critical"),
            "summary": analysis.get("summary") or {},
            "truncated": analysis.get("truncated"),
            "findings": findings,
        } if analysis else None,
    }
    return out



def _ingested_path(job: dict[str, Any]) -> Path:
    return _job_dir(job["campaign_id"], job["job_id"]) / "ingested.json"


def _load_ingested(job: dict[str, Any]) -> dict[str, Any] | None:
    path = _ingested_path(job)
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None

def _save(job: dict[str, Any]) -> None:
    try:
        path = _job_dir(job["campaign_id"], job["job_id"]) / "status.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_public(job), indent=2), encoding="utf-8")
    except Exception:
        pass


def _run_job(job_id: str) -> None:
    with LOCK:
        job = JOBS.get(job_id)
    if not job:
        return
    job["status"] = "running"
    job["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _save(job)

    def progress_cb(p: dict[str, Any]) -> None:
        job["progress"] = p
        if p.get("dns"):
            job["dns"] = p["dns"]
            _save(job)
        if job.get("cancel"):
            raise KeyboardInterrupt("cancelled")

    try:
        dest = _job_dir(job["campaign_id"], job_id)
        dest.mkdir(parents=True, exist_ok=True)
        result = site_clone.run_clone(
            job["url"], dest,
            options=job.get("options"),
            opsec=job.get("opsec"),
            proxy=job.get("proxy"),
            progress_cb=progress_cb,
        )
        job.update({
            "status": "done" if result.get("ok") else "failed",
            "error": result.get("error"),
            "files": result.get("files"),
            "bytes": result.get("bytes"),
            "elapsed_seconds": result.get("elapsed_seconds"),
            "analysis": result.get("analysis"),
            "timed_out": result.get("timed_out"),
            "warnings": result.get("warnings") or [],
            "deobfuscation": result.get("deobfuscation") or {},
            "ocr": result.get("ocr") or {},
            "dns": result.get("dns") or job.get("dns") or {},
        })
        if job.get("cancel"):
            job["status"] = "cancelled"
            job["error"] = "cancelled"
    except KeyboardInterrupt:
        job["status"] = "cancelled"
        job["error"] = "cancelled"
    except Exception as e:
        job["status"] = "failed"
        job["error"] = type(e).__name__ + ": " + str(e)[:200]
        job["trace"] = traceback.format_exc()[-500:]
    job["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _save(job)


def _start(body: dict[str, Any]) -> dict[str, Any]:
    url = site_clone.sanitize_url(str(body.get("url") or ""))
    campaign_id = str(body.get("campaign_id") or "unknown")
    if not SAFE.match(campaign_id):
        campaign_id = re.sub(r"[^A-Za-z0-9._-]+", "-", campaign_id)[:80] or "unknown"
    job_id = str(body.get("job_id") or uuid.uuid4().hex)
    if not SAFE.match(job_id):
        job_id = uuid.uuid4().hex
    options = site_clone.normalize_options(body.get("options") or body)
    job = {
        "job_id": job_id,
        "campaign_id": campaign_id,
        "url": url,
        "status": "queued",
        "options": options,
        "opsec": body.get("opsec") or {},
        "proxy": body.get("proxy") or {},
        "progress": {},
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cancel": False,
    }
    with LOCK:
        JOBS[job_id] = job
    _save(job)
    t = threading.Thread(target=_run_job, args=(job_id,), daemon=True)
    t.start()
    return {"ok": True, "job_id": job_id, "status": "queued", "url": url}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, obj: Any) -> None:
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/health":
            info = {"ok": True}
            try:
                from site_clone_deobfuscate import tool_status
                info["webcrack"] = tool_status()
            except Exception as e:
                info["webcrack"] = {"available": False, "error": type(e).__name__}
            try:
                from site_clone_ocr import tool_status as ocr_status
                info["ocr"] = ocr_status()
            except Exception as e:
                info["ocr"] = {"available": False, "error": type(e).__name__}
            try:
                from site_clone_dns import capabilities
                info["dns"] = capabilities()
            except Exception as e:
                info["dns"] = {"error": type(e).__name__}
            self._send(200, info)
            return
        m = re.match(r"^/jobs/([A-Za-z0-9._-]+)$", path)
        if m:
            job_id = m.group(1)
            with LOCK:
                job = JOBS.get(job_id)
            if not job:
                # Recover a finished job from disk if the process restarted.
                for camp in DATA.iterdir() if DATA.exists() else []:
                    status = camp / job_id / "status.json"
                    if status.is_file():
                        try:
                            self._send(200, json.loads(status.read_text()))
                            return
                        except Exception:
                            break
                self._send(404, {"ok": False, "error": "unknown job"})
                return
            self._send(200, {"ok": True, **_public(job)})
            return
        self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(max(0, min(length, 1_000_000))) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            self._send(400, {"ok": False, "error": "invalid JSON"})
            return
        if not isinstance(body, dict):
            self._send(400, {"ok": False, "error": "JSON object required"})
            return
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/clone":
            try:
                self._send(202, _start(body))
            except ValueError as e:
                self._send(400, {"ok": False, "error": str(e)})
            except Exception as e:
                self._send(500, {"ok": False, "error": type(e).__name__})
            return
        m = re.match(r"^/jobs/([A-Za-z0-9._-]+)/cancel$", path)
        if m:
            job_id = m.group(1)
            with LOCK:
                job = JOBS.get(job_id)
            if not job:
                self._send(404, {"ok": False, "error": "unknown job"})
                return
            job["cancel"] = True
            self._send(200, {"ok": True, "job_id": job_id, "status": job.get("status")})
            return
        m = re.match(r"^/jobs/([A-Za-z0-9._-]+)/ingested$", path)
        if m:
            job_id = m.group(1)
            with LOCK:
                job = JOBS.get(job_id)
            if not job:
                self._send(404, {"ok": False, "error": "unknown job"})
                return
            job["ingested"] = body
            try:
                _ingested_path(job).write_text(json.dumps(body), encoding="utf-8")
            except Exception:
                pass
            self._send(200, {"ok": True, "job_id": job_id})
            return
        self._send(404, {"ok": False, "error": "not found"})


def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    host = os.environ.get("SITE_CLONE_BIND", "0.0.0.0")
    port = int(os.environ.get("SITE_CLONE_PORT", "7052"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print("site-clone-api listening on %s:%s" % (host, port), flush=True)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
