#!/usr/bin/env python3
"""Offline smoke for translate-sidecar path guards and document extract.

The path helper lives in spotter_translate so this does not need FastAPI.
When fastapi + pypdf are importable the HTTP surface is also exercised.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

os.environ["SPOTTER_CACHE_DIR"] = tempfile.mkdtemp(prefix="spotter-smoke-tr-side-")
os.environ["TRANSLATE_ENABLED"] = "0"  # no model for document extract

import spotter_translate as tr  # noqa: E402

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    if cond:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s%s" % (label, (" -- " + detail) if detail else ""))
        FAILURES.append(label)


def test_path_guards() -> None:
    print("\n-- screenshot path guards")
    root = tempfile.mkdtemp(prefix="spotter-shots-")
    sketch = os.path.join(root, "sk-1")
    os.makedirs(sketch)
    png = os.path.join(sketch, "a.png")
    with open(png, "wb") as fh:
        fh.write(b"\x89PNG\r\n")
    got = tr.resolve_screenshot_path("/screenshots/sk-1/a.png", "sk-1", root=root)
    check("in-sketch PNG resolves", os.path.realpath(got) == os.path.realpath(png), got)
    try:
        tr.resolve_screenshot_path("/screenshots/sk-1/../sk-2/a.png", "sk-1", root=root)
        check("traversal is rejected", False)
    except ValueError:
        check("traversal is rejected", True)
    try:
        tr.resolve_screenshot_path("/screenshots/sk-OTHER/a.png", "sk-1", root=root)
        check("sketch mismatch is PermissionError", False)
    except PermissionError:
        check("sketch mismatch is PermissionError", True)


def test_http_optional() -> None:
    print("\n-- sidecar HTTP (optional)")
    try:
        from fastapi.testclient import TestClient  # type: ignore
    except Exception:
        print("  skip  fastapi not installed")
        return
    sidecar = Path(__file__).resolve().parents[1] / "translate-sidecar"
    sys.path.insert(0, str(sidecar))
    os.environ["SPOTTER_SCREENSHOTS_DIR"] = tempfile.mkdtemp(prefix="spotter-side-shots-")
    import main as side  # noqa: WPS433

    client = TestClient(side.app)
    h = client.get("/health")
    check("GET /health is 200", h.status_code == 200, str(h.status_code))
    bad = client.post("/ocr", json={
        "screenshot_url": "/screenshots/sk-1/../etc/passwd",
        "sketch_id": "sk-1",
    })
    check("OCR traversal is 400", bad.status_code == 400, str(bad.status_code))
    mismatch = client.post("/ocr", json={
        "screenshot_url": "/screenshots/other/a.png",
        "sketch_id": "sk-1",
    })
    check("OCR sketch mismatch is 403", mismatch.status_code == 403,
          str(mismatch.status_code))

    try:
        from pypdf import PdfWriter  # type: ignore
    except Exception:
        print("  skip  pypdf not installed")
        return
    buf = io.BytesIO()
    w = PdfWriter()
    w.add_blank_page(width=72, height=72)
    w.write(buf)
    res = client.post(
        "/document",
        files={"file": ("blank.pdf", buf.getvalue(), "application/pdf")},
        data={"target": "en"},
    )
    check("POST /document on a PDF is 200", res.status_code == 200, str(res.status_code))
    body = res.json()
    check("document kind is pdf", body.get("kind") == "pdf", str(body))


def main() -> int:
    test_path_guards()
    test_http_optional()
    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("all translate-sidecar checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
