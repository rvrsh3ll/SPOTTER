"""
Titus sidecar — thin HTTP wrapper around the Titus secrets scanner binary.

POST /scan
  - Accepts a multipart file upload + sketch_id query param.
  - Runs `titus scan <tempfile> --format json`.
  - Returns normalised findings: value_hash (salted SHA-256), value_masked,
    severity, cred_type, validated, source_file, service, username_context.
  - Plaintext secret values are discarded after hashing — never returned.

GET /health
  - Returns {"ok": true}; used by Docker healthcheck.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Query, UploadFile
from fastapi.responses import JSONResponse

app = FastAPI(title="titus-sidecar", version="1.0.0")

# Patterns for extracting a username from surrounding file context.
# Tries domain\user, user@domain, and bare lowercase word before a colon/equals.
_USERNAME_PATTERNS = [
    re.compile(r'(?i)(?:^|[\s,;:\'"])([A-Z0-9_\-]+\\[A-Z0-9_\-\.]+)', re.MULTILINE),  # DOMAIN\user
    re.compile(r'(?i)([a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,})'),                          # email
    re.compile(r'(?i)(?:username|user|login|account)\s*[=:]\s*["\']?([A-Z0-9_\-\.@]+)', re.MULTILINE),
]


def _extract_username(context: str) -> str:
    """Try to pull a username/email out of the surrounding source context."""
    for pat in _USERNAME_PATTERNS:
        m = pat.search(context)
        if m:
            return m.group(1)
    return ""


def _hash_value(sketch_id: str, raw: str) -> str:
    """SHA-256(sketch_id:raw_value) — salted per engagement."""
    payload = f"{sketch_id}:{raw}".encode()
    return hashlib.sha256(payload).hexdigest()


def _mask_value(raw: str) -> str:
    """Return first 4 chars + *** for display; never expose the full value."""
    if not raw:
        return "***"
    prefix = raw[:4] if len(raw) >= 4 else raw
    return f"{prefix}***"


def _is_ntlm(cred_type: str, raw: str) -> bool:
    """NTLM NT hashes are already hashes — store as-is, skip SHA-256."""
    nt_types = {"ntlm_hash", "ntlm_nt_hash", "net_ntlm", "nthash"}
    if cred_type.lower() in nt_types:
        return True
    # Bare 32-char hex (NT hash format)
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", raw.strip()))


def _b64(value: Any) -> str:
    """Titus base64-encodes captured groups and snippets; decode leniently."""
    if not isinstance(value, str) or not value:
        return ""
    try:
        return base64.b64decode(value, validate=False).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return value


def _records(raw: Any) -> List[Dict[str, Any]]:
    """
    Pull the finding records out of whatever shape the scanner returned.

    `titus scan --format json` writes a bare JSON **array**. This used to assume
    a {"matches": [...]} object, so the endpoint raised
    AttributeError: 'list' object has no attribute 'get' on every scan — WF11
    caught the resulting 500 and reported "No credentials found", which is why the
    credential scanner never produced a single finding.
    """
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        for key in ("matches", "findings", "results"):
            inner = raw.get(key)
            if isinstance(inner, list):
                return [r for r in inner if isinstance(r, dict)]
    return []


def _normalize_findings(raw: Any, sketch_id: str,
                        source_file: str = "") -> List[Dict[str, Any]]:
    """
    Convert Titus JSON output to SPOTTER credential records.

    Handles the real Titus/Nosey Parker schema (CamelCase, base64 Groups and
    Snippet) as well as the flat snake_case shape, so a scanner upgrade that
    changes spelling degrades to fewer fields rather than to zero findings.

    The plaintext secret never leaves this function: it is hashed (salted with
    the sketch id) and masked, and the context recorded alongside it is the text
    *preceding* the match, never the match itself.
    """
    out: List[Dict[str, Any]] = []
    for match in _records(raw):
        groups = [_b64(g) for g in (match.get("Groups") or []) if g]
        snippet = match.get("Snippet") or {}
        matching = _b64(snippet.get("Matching")) if isinstance(snippet, dict) else ""
        before = _b64(snippet.get("Before")) if isinstance(snippet, dict) else ""
        after = _b64(snippet.get("After")) if isinstance(snippet, dict) else ""

        val: str = (
            match.get("secret", "")
            or match.get("value", "")
            or ":".join(g for g in groups if g)
            or matching
        ).strip()
        if not val:
            continue

        cred_type: str = (
            match.get("rule_name", "")
            or match.get("detector_name", "")
            or match.get("RuleName", "")
            or match.get("RuleID", "")
            or "unknown"
        )
        # `np.aws.6` -> `aws`; used as the service label on the credential node.
        rule_id = str(match.get("RuleID") or match.get("rule_id") or "")
        service = match.get("service") or match.get("source") or ""
        if not service and rule_id.startswith("np."):
            parts = rule_id.split(".")
            service = parts[1] if len(parts) > 2 else ""

        # Two different contexts, on purpose.
        #
        # `window` is the full ±3-line snippet Titus returns. It is good for
        # finding the username that goes with the secret, and it is NEVER stored:
        # in a credentials file the neighbouring lines are other people's secrets,
        # so shipping it would re-introduce the plaintext this sidecar exists to
        # strip (verified — the GitHub hit's window contained the AWS key).
        #
        # `context` is what leaves this process: the current line up to the point
        # the match starts, i.e. the assignment key like "aws_access_key_id = ".
        # Before ends exactly at the match, so its last line cannot contain any
        # secret, this record's or a neighbour's.
        window: str = (
            match.get("line_content", "")
            or match.get("context", "")
            or f"{before}{after}"
        )
        context: str = (before.rsplit("\n", 1)[-1] if before
                        else match.get("line_content", "") or match.get("context", ""))
        for secret in (*groups, val):
            if secret and len(secret) > 3:
                context = context.replace(secret, "***")

        line = 0
        location = match.get("Location") or {}
        if isinstance(location, dict):
            source = location.get("Source") or {}
            start = source.get("Start") if isinstance(source, dict) else None
            if isinstance(start, dict):
                line = int(start.get("Line") or 0)

        if _is_ntlm(cred_type, val):
            # Store NT hash directly — it is already a one-way hash.
            value_hash = val.strip().lower()
            masked = f"{value_hash[:4]}***"
        else:
            value_hash = _hash_value(sketch_id, val)
            masked = _mask_value(val)

        out.append({
            "cred_type":        cred_type,
            "value_hash":       value_hash,
            "value_masked":     masked,
            "severity":         (match.get("severity") or "info").lower(),
            "severity_score":   int(match.get("score") or match.get("severity_score") or 0),
            "validated":        bool(match.get("validated") or match.get("is_active")),
            "source_file":      match.get("file") or match.get("filename") or source_file,
            "source_line":      line,
            "source_context":   context[:120],
            "service":          service,
            "username_context": _extract_username(window),
        })

    # Deduplicate on (cred_type, value_hash) — same credential found in multiple places
    seen: set = set()
    deduped: List[Dict[str, Any]] = []
    for item in out:
        key = (item["cred_type"], item["value_hash"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"ok": True})


@app.post("/scan")
async def scan(
    file: UploadFile = File(...),
    sketch_id: str = Query(default="", description="SPOTTER sketch ID — used as hash salt"),
) -> JSONResponse:
    """
    Scan an uploaded file with Titus and return normalised credential findings.

    Returns:
        {
          "findings": [ { cred_type, value_hash, value_masked, severity,
                          severity_score, validated, source_file,
                          source_context, service, username_context } ],
          "count": <int>,
          "filename": <str>
        }
    """
    content = await file.read()

    suffix = os.path.splitext(file.filename or "upload")[1] or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # --output :memory: keeps each scan isolated. The default writes to a
        # persistent `titus.ds` datastore in the working directory, so every scan
        # returned its own findings *plus every earlier upload's* — one
        # engagement's credentials surfacing in another campaign's graph.
        result = subprocess.run(
            ["titus", "scan", tmp_path, "--format", "json", "--output", ":memory:"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        error = ""
        try:
            raw: Any = json.loads(result.stdout) if result.stdout.strip() else []
        except json.JSONDecodeError:
            raw = []
            # Do not swallow this: an unparseable scan is indistinguishable from a
            # clean file to every caller downstream.
            error = (result.stderr or result.stdout or "").strip()[-300:]

        if result.returncode != 0 and not error:
            error = (result.stderr or "").strip()[-300:]

        findings = _normalize_findings(raw, sketch_id or "default", file.filename or "")
        payload: Dict[str, Any] = {
            "findings": findings,
            "count":    len(findings),
            "filename": file.filename or "",
        }
        if error:
            payload["error"] = error
        return JSONResponse(payload)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
