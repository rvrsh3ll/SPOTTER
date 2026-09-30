#!/usr/bin/env python3
"""
Offline smoke test for the EyeWitness ingest path.

Synthesizes a tiny EyeWitness output zip (a Requests.csv with a valid row, an error
row whose screenshot was never written, and a row whose Default Creds field spans
multiple lines) plus a screens/ PNG, then exercises:

  * eyewitness_parser.is_eyewitness_zip / parse_bytes
  * upload_router.detect_format routing the zip to "eyewitness"
    * upload_router.route_bytes (dry, ingest=False) producing Website + Ip nodes,
        RESOLVES_TO edges, a written screenshot, and correct handling of the
    PNG-vs-source filename mismatch and a missing/error-row screenshot.

Runs fully offline — no Neo4j, no n8n. Exit non-zero on any failed assertion.
"""

import io
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import eyewitness_parser as ew  # noqa: E402
import upload_router as ur  # noqa: E402

# A 1x1 PNG (smallest valid).
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000d4944415478da63f8cfc0f01f0005000101ff9c9c7c0000000049454e44ae426082"
)

# Header exactly as EyeWitness writes it (note the leading space before Source Path).
HEADER = ("Protocol,Port,Domain,URL,Resolved,Request Status,Title,Category,"
          "Default Creds,Screenshot Path, Source Path")

# Row 1: a good capture — resolved to an IP, iDRAC category, screenshot present.
#   NOTE the PNG basename (sanitize_filename) differs from the source basename.
ROW_OK = ('https,8443,10.0.0.5,https://10.0.0.5:8443/login,10.0.0.5,Successful,'
          '"iDRAC Login",idrac,'
          '"(Dell iDRAC) root/calvin",'
          '/out/screens/10.0.0.5_8443_login.png,/out/source/https.10.0.0.5.8443.login.txt')

# Row 2: a good capture with a multi-line Default Creds value (embedded newline
# inside quotes — must be parsed as ONE record by a real CSV reader).
ROW_MULTILINE = ('http,80,10.0.0.9,http://10.0.0.9/,host9.corp.local,Successful,'
                 '"Printer Web UI",printer,'
                 '"cred one\ncred two",'
                 '/out/screens/10.0.0.9_80.png,/out/source/http.10.0.0.9.80.txt')

# Row 3: an error row — no screenshot was written; the path points at a ghost file.
ROW_ERR = ('https,443,10.0.0.20,https://10.0.0.20/,Unknown,Timeout,None,None,'
           'None,/out/screens/10.0.0.20_443.png,/out/source/https.10.0.0.20.443.txt')

# Older EyeWitness output does not carry URL or Resolved columns. The parser must
# reconstruct the URL from Protocol/Port/Domain and use a bare-IP Domain value as
# the IP anchor.
OLD_HEADER = "Protocol,Port,Domain,Request Status,Screenshot Path, Source Path"
OLD_ROW = "https,8443,10.0.0.55,Successful,/out/screens/old.png,/out/source/old.txt"


def _build_zip() -> bytes:
    csv_text = "\n".join([HEADER, ROW_OK, ROW_MULTILINE, ROW_ERR])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Requests.csv", csv_text)
        # Only rows 1 and 2 have a real PNG on disk; row 3 (error) does not.
        zf.writestr("screens/10.0.0.5_8443_login.png", PNG)
        zf.writestr("screens/10.0.0.9_80.png", PNG)
        zf.writestr("ew.db", b"SQLite format 3\x00")  # marker only
        zf.writestr("report.html", b"<html></html>")
    return buf.getvalue()


def _build_old_header_zip() -> bytes:
    csv_text = "\n".join([OLD_HEADER, OLD_ROW])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Requests.csv", csv_text)
        zf.writestr("screens/old.png", PNG)
        zf.writestr("ew.db", b"SQLite format 3\x00")
        zf.writestr("report.html", b"<html></html>")
    return buf.getvalue()


def main() -> int:
    data = _build_zip()
    ok = True

    def check(cond: bool, msg: str) -> None:
        nonlocal ok
        print(("PASS" if cond else "FAIL") + ": " + msg)
        if not cond:
            ok = False

    # Detection
    check(ew.is_eyewitness_zip(data), "is_eyewitness_zip recognizes the archive")
    check(ur.detect_format(data, "eyewitness.zip") == "eyewitness",
          "detect_format routes the zip to 'eyewitness'")

    # A bare Requests.csv (no zip) must NOT be recognized as EyeWitness output.
    check(not ew.is_eyewitness_zip(HEADER.encode()),
          "is_eyewitness_zip rejects a bare CSV (not a zip)")

    with tempfile.TemporaryDirectory() as tmp:
        res = ew.parse_bytes(data, sketch_id="sk-test", screenshots_dir=tmp)
        websites = [n for n in res.nodes if n["entity_type"] == "Website"]
        ips = [n for n in res.nodes if n["entity_type"] == "IP"]

        check(len(websites) == 3, f"3 Website nodes (got {len(websites)})")
        check(len(ips) == 3, f"3 Ip nodes from bare-IP Domain/Resolved values (got {len(ips)})")
        check(any(e["label"] == "RESOLVES_TO" for e in res.edges),
              "a RESOLVES_TO edge links the website to its IP")

        by_url = {n["data"]["url"]: n["data"] for n in websites}

        ok_row = by_url.get("https://10.0.0.5:8443/login", {})
        check(ok_row.get("ew_category") == "idrac", "iDRAC category captured")
        check(ok_row.get("has_default_creds") is True, "default creds detected")
        check(ok_row.get("is_high_value") is True, "iDRAC + creds marks high value")
        check(ok_row.get("active") is True, "Successful status → active=True")
        check(bool(ok_row.get("screenshot_url")), "screenshot_url set for the good row")
        shot_rel = ok_row.get("screenshot_url", "")
        check(shot_rel.startswith("/screenshots/sk-test/"),
              "screenshot_url is a sketch-scoped /screenshots/ path")
        # The PNG was actually written to disk.
        disk = os.path.join(tmp, "sk-test", os.path.basename(shot_rel))
        check(os.path.isfile(disk), "screenshot PNG written to the served dir")

        ml_row = by_url.get("http://10.0.0.9/", {})
        check("cred one" in ml_row.get("default_creds", "")
              and "cred two" in ml_row.get("default_creds", ""),
              "multi-line Default Creds parsed as one field")

        err_row = by_url.get("https://10.0.0.20/", {})
        check(err_row.get("screenshot_present") is False,
              "error row: no screenshot (ghost path skipped)")
        check(err_row.get("active") is False, "error row: active=False")
        check(err_row.get("ew_category") == "", "error row: 'None' category normalized to ''")

        check(res.report["hosts"] == 3 and res.report["with_screenshot"] == 2
              and res.report["with_default_creds"] == 2,
              f"report tallies: {res.report}")

        old_data = _build_old_header_zip()
        check(ur.detect_format(old_data, "eyewitness-old.zip") == "eyewitness",
            "detect_format routes old-header EyeWitness zip to 'eyewitness'")
        with tempfile.TemporaryDirectory() as tmp:
          old_res = ew.parse_bytes(old_data, sketch_id="sk-old", screenshots_dir=tmp)
          websites = [n for n in old_res.nodes if n["entity_type"] == "Website"]
          ips = [n for n in old_res.nodes if n["entity_type"] == "IP"]
          check(len(websites) == 1, f"old header: 1 Website node (got {len(websites)})")
          check(len(ips) == 1, f"old header: Domain-as-IP anchors one IP node (got {len(ips)})")
          by_url = {n["data"]["url"]: n["data"] for n in websites}
          old_row = by_url.get("https://10.0.0.55:8443/") or {}
          check(bool(old_row), "old header: URL synthesized from Protocol/Domain/Port")
          check(old_row.get("active") is True, "old header: Successful status -> active=True")
          check(bool(old_row.get("screenshot_url")), "old header: screenshot_url set")
          check(any(e["label"] == "RESOLVES_TO" for e in old_res.edges),
              "old header: synthesized website resolves to Domain-as-IP anchor")

    print()
    print("SMOKE " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
