#!/usr/bin/env python3
"""
Smoke test for workflow 06 (Manual Upload Handler).

Runs WF06's code nodes the way n8n runs them and evaluates the Ack Started
expression, asserting the two properties the workflow was restructured to
guarantee:

  1. The ack reports the format the BACKEND detected. WF06 used to respond
     before it looked at the bytes, so the browser kept its filename guess --
     which called every .zip "SharpHound", including CloudSchism scan output.

  2. An upload that cannot be parsed is rejected in the ack and routed to the
     switch's dead end. A password-protected archive is the case that motivated
     this: member names are stored in the clear, so detection succeeds on an
     archive whose every artifact is unreadable, and the old flow reported a
     zero-node success that was indistinguishable from a scan with no findings.

No network and no Flowsint writes -- fixtures are built in-process.

    python3 scripts/smoke_workflow06.py
"""
from __future__ import annotations

import base64
import io
import json
import os
import struct
import sys
import tempfile
import textwrap
import zipfile
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parent.parent
WF = REPO / "n8n-workflows" / "06-manual-upload-handler.json"

sys.path.insert(0, str(REPO / "scripts"))
os.environ.setdefault("SPOTTER_UPLOAD_MAX_BYTES", str(90 * 1024 * 1024))

WORKFLOW = json.loads(WF.read_text())
CODE = {
    n.get("name", ""): n.get("parameters", {}).get("pythonCode", "")
    for n in WORKFLOW.get("nodes", [])
    if n.get("type") == "n8n-nodes-base.code"
}
SWITCH = [
    r["outputKey"]
    for r in next(n for n in WORKFLOW["nodes"] if n["name"] == "Route by Format")
    ["parameters"]["rules"]["values"]
]
BRANCHES = WORKFLOW["connections"]["Route by Format"]["main"]


def run_code_node(name: str, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    src = f"def __n8n_exec(_items):\n" + textwrap.indent(CODE[name], "    ")
    ns: Dict[str, Any] = {}
    exec(compile(src, f"<{name}>", "exec"), ns, ns)
    return ns["__n8n_exec"](items)


def ack(item: Dict[str, Any]) -> Dict[str, Any]:
    """Mirror of the Ack Started responseBody expression."""
    return {
        "message": "Upload rejected" if item.get("accepted") is False else "Workflow was started",
        "accepted": item.get("accepted") is not False,
        "format": item.get("detected_format") or "unknown",
        "errors": item.get("errors") or [],
    }


def route(item: Dict[str, Any]) -> str:
    """Mirror of Route by Format: rule 0 is the reject guard, then format equality."""
    if item.get("accepted") is False:
        idx = 0
    else:
        fmt = item.get("detected_format")
        idx = SWITCH.index(fmt) if fmt in SWITCH[1:] else len(SWITCH)
    branch = BRANCHES[idx]
    return branch[0]["node"] if branch else "DEAD END"


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _zip(members: Dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in members.items():
            zf.writestr(name, body)
    return buf.getvalue()


def _mark_encrypted(data: bytes) -> bytes:
    """
    Set the 'encrypted' bit on every member of a zip.

    zipfile cannot WRITE encrypted archives, and the guard under test reads
    exactly one thing -- bit 0 of the general-purpose flag, in both the local
    header and the central directory. Flipping it reproduces what a real
    ZipCrypto archive presents, and Python then refuses to read the members for
    the same reason it refuses a real one.
    """
    out = bytearray(data)
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = 0
        while True:
            pos = out.find(sig, pos)
            if pos < 0:
                break
            i = pos + off
            flags = struct.unpack_from("<H", out, i)[0]
            struct.pack_into("<H", out, i, flags | 0x1)
            pos += 4
    return bytes(out)


CLOUDSCHISM = _zip({
    "scan/attack-graph.json": '{"nodes": [], "edges": []}',
    "scan/attack-paths.json": "[]",
})
SHARPHOUND = _zip({
    "20260804195255_users.json": json.dumps(
        {"meta": {"type": "users", "count": 1},
         "data": [{"ObjectIdentifier": "S-1-5-21-1-1-1-500",
                   "Properties": {"name": "ADMIN@X.LOCAL", "domain": "X.LOCAL"},
                   "Aces": []}]}),
    "20260804195255_computers.json": json.dumps({"meta": {"type": "computers", "count": 0}, "data": []}),
})
EYEWITNESS = _zip({
    "Requests.csv": ("Protocol,Port,Domain,URL,Resolved,Request Status,Title,"
                     "Category,Default Creds,Screenshot Path, Source Path\n"
                     "https,443,example.com,https://example.com/,1.2.3.4,Successful,"
                     '"Home",cms,None,/o/screens/ex.png,/o/source/ex.txt'),
    "screens/ex.png": "PNGDATA",
    "ew.db": "SQLite format 3\x00",
})


def upload(raw: bytes, filename: str) -> List[Dict[str, Any]]:
    return [{"json": {"body": {
        "zip_b64": base64.b64encode(raw).decode(),
        "filename": filename,
        "sketch_id": "smoke-wf06",
    }}}]


# (name, items, want_accepted, want_format, want_destination)
CASES = [
    ("CloudSchism zip is reported as CloudSchism, not SharpHound",
     upload(CLOUDSCHISM, "cloudschism-out.zip"), True, "cloudschism", "Parse CloudSchism"),
    ("SharpHound zip is still reported as SharpHound",
     upload(SHARPHOUND, "20260804_bloodhound.zip"), True, "sharphound", "Parse SharpHound"),
    ("EyeWitness zip routes to Parse EyeWitness, not zip_unknown",
     upload(EYEWITNESS, "eyewitness.zip"), True, "eyewitness", "Parse EyeWitness"),
    ("password-protected archive is rejected, not silently imported as empty",
     upload(_mark_encrypted(CLOUDSCHISM), "cloudschism-out.zip"), False, "cloudschism", "DEAD END"),
    ("an empty payload field is rejected",
     [{"json": {"body": {"zip_b64": "", "filename": "x.zip"}}}], False, "empty", "DEAD END"),
    # The size check runs before detect_format, so fmt is still '' -> 'oversize'.
    ("an oversize upload is rejected",
     upload(b"PK\x03\x04" + b"\x00" * (91 * 1024 * 1024), "big.zip"), False, "oversize", "DEAD END"),
    ("a plain paste still reaches the LLM extractor",
     [{"json": {"body": {"text": "hello world", "filename": "paste.txt"}}}], True, "text", "Parse Text (LLM)"),
]


def main() -> int:
    failures = 0

    for name, items, want_accepted, want_format, want_dest in CASES:
        out = run_code_node("Detect Format", items)[0]["json"]
        a, dest = ack(out), route(out)
        ok = (a["accepted"] == want_accepted
              and a["format"] == want_format
              and dest == want_dest)
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        print(f"        ack: accepted={a['accepted']} format={a['format']!r} -> {dest}")
        for e in a["errors"]:
            print(f"        {e}")
        if not ok:
            print(f"        EXPECTED accepted={want_accepted} format={want_format!r} -> {want_dest}")

    # Structural guards: the ack must sit between detection and routing, and the
    # reject rule must be evaluated before any format rule.
    conns = WORKFLOW["connections"]
    checks = [
        ("webhook acks only after detection",
         [c["node"] for c in conns["Upload Webhook"]["main"][0]] == ["Detect Format"]),
        ("detection feeds the ack",
         [c["node"] for c in conns["Detect Format"]["main"][0]] == ["Ack Started"]),
        ("routing happens after the ack",
         "Route by Format" in [c["node"] for c in conns["Ack Started"]["main"][0]]),
        ("reject rule is evaluated first", SWITCH[0] == "rejected"),
        ("rejected uploads reach no parser", BRANCHES[0] == []),
        ("every switch output is wired", len(BRANCHES) == len(SWITCH) + 1),
    ]
    for label, ok in checks:
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}")

    # A rejected upload has no bytes; the credential scanner must not run on it.
    rejected = run_code_node("Detect Format", upload(_mark_encrypted(CLOUDSCHISM), "cs.zip"))
    titus = run_code_node("Scan Credentials (Titus)", rejected)[0]["json"]
    ok = titus.get("status") == "skipped"
    failures += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] credential scan skips a rejected upload")

    staged_failures = _staged_checks()
    failures += staged_failures

    print()
    if failures:
        print(f"{failures} FAILURE(S)")
        return 1
    # +5 is the staged-id block in _staged_checks. +1 is the Titus skip above.
    print(f"smoke_workflow06: all {len(CASES) + len(checks) + 1 + 5} checks passed")
    return 0


def _staged_checks() -> int:
    """A chunked upload is a staged id. These need a temp staging root, so they
    are not in CASES."""
    from ingest_staging import append_chunk, complete, create_upload

    failures = 0
    saved_root = os.environ.get("SPOTTER_INGEST_STAGING_DIR")
    saved_cap = os.environ.get("SPOTTER_RUNNER_PARSE_MAX_BYTES")
    tmp = tempfile.TemporaryDirectory(prefix="spotter-wf06-staging-")
    os.environ["SPOTTER_INGEST_STAGING_DIR"] = tmp.name
    os.environ["SPOTTER_RUNNER_PARSE_MAX_BYTES"] = str(1024 ** 3)
    try:
        body = b"hello from a staged upload\n"
        created = create_upload("smoke", "notes.txt", len(body))
        append_chunk("smoke", created["upload_id"], 0, body)
        complete("smoke", created["upload_id"])
        out = run_code_node("Detect Format", [{"json": {"body": {
            "staged_id": created["upload_id"],
            "filename": "notes.txt",
            "sketch_id": "smoke-wf06",
        }}}])[0]["json"]
        ok = (
            out.get("accepted") is True
            and out.get("staged") is True
            and out.get("detected_format") not in ("oversize", "empty", "staged")
            and "raw_b64" not in out
            and out.get("file_path", "").endswith(created["upload_id"])
            and Path(out["file_path"]).read_bytes() == body
        )
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] a staged id resolves and is not treated as oversize")
        if not ok:
            print(f"        got accepted={out.get('accepted')} staged={out.get('staged')} "
                  f"format={out.get('detected_format')!r} path={out.get('file_path')!r}")

        escaped = run_code_node("Detect Format", [{"json": {"body": {
            "staged_id": "../etc/passwd",
            "filename": "x",
        }}}])[0]["json"]
        ok = escaped.get("accepted") is False and route(escaped) == "DEAD END"
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] a non-uuid staged id is rejected")

        missing = run_code_node("Detect Format", [{"json": {"body": {
            "staged_id": "a" * 32,
            "filename": "x",
        }}}])[0]["json"]
        ok = missing.get("accepted") is False
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] an unknown staged id is rejected")

        os.environ["SPOTTER_RUNNER_PARSE_MAX_BYTES"] = "10"
        big = b"x" * 64
        over = create_upload("smoke", "scan.nessus", len(big))
        append_chunk("smoke", over["upload_id"], 0, big)
        complete("smoke", over["upload_id"])
        kept = Path(tmp.name) / over["upload_id"]
        rejected = run_code_node("Detect Format", [{"json": {"body": {
            "staged_id": over["upload_id"],
            "filename": "scan.nessus",
            "sketch_id": "smoke-wf06",
        }}}])[0]["json"]
        message = " ".join(rejected.get("errors") or [])
        ok = (
            rejected.get("accepted") is False
            and "raw_b64" not in rejected
            and kept.is_file()
            and str(kept) in message
            and "Ingest it on the host" in message
            and route(rejected) == "DEAD END"
        )
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] a staged file over the runner cap is kept and names the host command")
        if not ok:
            print(f"        {message!r}")

        titus = run_code_node("Scan Credentials (Titus)", [{"json": {
            "filename": "dump.txt",
            "detected_format": "text",
            "accepted": True,
            "sketch_id": "smoke-wf06",
            "size": 20 * 1024 * 1024,
            "file_path": "/no/such/staged-file",
            "staged": True,
        }}])[0]["json"]
        ok = titus.get("status") == "skipped" and titus.get("reason") == "file too large for credential scan"
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] credential scan skips a staged file over 10 MB without reading it")
        if not ok:
            print(f"        got {titus!r}")
    finally:
        if saved_root is None:
            os.environ.pop("SPOTTER_INGEST_STAGING_DIR", None)
        else:
            os.environ["SPOTTER_INGEST_STAGING_DIR"] = saved_root
        if saved_cap is None:
            os.environ.pop("SPOTTER_RUNNER_PARSE_MAX_BYTES", None)
        else:
            os.environ["SPOTTER_RUNNER_PARSE_MAX_BYTES"] = saved_cap
        tmp.cleanup()
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
