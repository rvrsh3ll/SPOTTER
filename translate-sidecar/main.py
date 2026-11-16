"""Translate sidecar — OCR, document extract, and a session-gated text MT front.

POST /translate
  JSON {text, target?, source?} — same envelope as scripts/spotter_translate.

POST /ocr
  JSON {screenshot_url, sketch_id, target?}
  screenshot_url is a same-origin /screenshots/<sketch>/… path. Bytes are read
  from the bind-mounted screenshots dir; the browser does not round-trip PNGs.
  Writes <png>.ocr.json next to the image so a re-open is free.

POST /document
  multipart file + target. PDF (pypdf) or DOCX (python-docx) or plain text.
  Password-protected PDFs return an error without failing the process.

GET /health
  {ok, tessdata, vllm}

nginx overwrites X-Spotter-User on the browser path. Workflow callers on the
Docker network skip the session header and pass sketch_id themselves.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, File, Form, Header, UploadFile
from fastapi.responses import JSONResponse

SCRIPTS = os.environ.get("SPOTTER_SCRIPTS_DIR", "/data/scripts")
if SCRIPTS and os.path.isdir(SCRIPTS) and SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

SCREEN_ROOT = Path(os.environ.get("SPOTTER_SCREENSHOTS_DIR", "/data/screenshots"))
TESS_LANGS = os.environ.get("TRANSLATE_TESS_LANGS", "eng+rus+ukr+ara")
OCR_MAX_PAGES = int(os.environ.get("TRANSLATE_OCR_MAX_PAGES", "8") or 8)

app = FastAPI(title="spotter-translate", version="1.0.0")


def _owner(x_spotter_user: Optional[str]) -> str:
    return str(x_spotter_user or "").strip()


def _error(status: int, message: str, extra: Optional[Dict[str, Any]] = None):
    body: Dict[str, Any] = {"ok": False, "error": message}
    if extra:
        body.update(extra)
    return JSONResponse(status_code=status, content=body)


def _translate_mod():
    import spotter_translate as st  # noqa: WPS433
    return st


@app.get("/health")
def health() -> Dict[str, Any]:
    tess = bool(shutil.which("tesseract"))
    vllm = True
    try:
        import llm_client  # noqa: F401
    except Exception:
        vllm = False
    return {"ok": True, "tessdata": tess, "vllm": vllm, "tess_langs": TESS_LANGS}


@app.post("/translate")
def translate(
    payload: Dict[str, Any],
    x_spotter_user: Optional[str] = Header(default=""),
) -> Any:
    # Browser path requires a session; in-cluster workflow callers omit it.
    text = payload.get("text") if isinstance(payload, dict) else ""
    if not isinstance(text, str):
        return _error(400, "text must be a string")
    st = _translate_mod()
    return st.translate_text(
        text,
        target=str(payload.get("target") or ""),
        source=str(payload.get("source") or ""),
        for_ingest=False,
    )


def _resolve_screenshot(screenshot_url: str, sketch_id: str) -> Path:
    st = _translate_mod()
    return Path(st.resolve_screenshot_path(
        screenshot_url, sketch_id, root=str(SCREEN_ROOT)))


def _tesseract(path: Path) -> Tuple[str, str]:
    if not shutil.which("tesseract"):
        return "", "tesseract_missing"
    try:
        proc = subprocess.run(
            ["tesseract", str(path), "stdout", "-l", TESS_LANGS, "--psm", "6"],
            capture_output=True, timeout=60, check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return "", "tesseract_failed:%s" % (repr(exc)[:120],)
    text = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    if proc.returncode != 0 and not text:
        err = (proc.stderr or b"").decode("utf-8", errors="replace")[:160]
        return "", "tesseract_rc:%s" % err
    return text, ""


@app.post("/ocr")
def ocr(
    payload: Dict[str, Any],
    x_spotter_user: Optional[str] = Header(default=""),
) -> Any:
    if not isinstance(payload, dict):
        return _error(400, "JSON body required")
    url = str(payload.get("screenshot_url") or "").strip()
    sketch = str(payload.get("sketch_id") or "").strip()
    target = str(payload.get("target") or "")
    try:
        path = _resolve_screenshot(url, sketch)
    except PermissionError as exc:
        return _error(403, str(exc))
    except FileNotFoundError:
        return _error(404, "screenshot file is missing")
    except ValueError as exc:
        return _error(400, str(exc))

    sidecar = path.with_name(path.name + ".ocr.json")
    if sidecar.is_file() and not payload.get("force"):
        try:
            cached = json.loads(sidecar.read_text(encoding="utf-8"))
            if isinstance(cached, dict) and cached.get("ocr_text") is not None:
                return cached
        except Exception:
            pass

    ocr_text, tess_err = _tesseract(path)
    st = _translate_mod()
    translated = st.translate_text(ocr_text, target=target, for_ingest=False) if ocr_text else {
        "source_lang": "", "target_lang": st.target_lang(), "original": "",
        "translated": "", "skipped": tess_err or "empty_ocr", "error": tess_err,
    }
    out = {
        "ok": True,
        "screenshot_url": url,
        "sketch_id": sketch,
        "ocr_text": ocr_text,
        "source_lang": translated.get("source_lang") or st.detect_lang(ocr_text),
        "translated": translated.get("translated") or "",
        "skipped": translated.get("skipped") or tess_err,
        "error": translated.get("error") or tess_err,
    }
    try:
        sidecar.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass
    return out


def _extract_pdf(data: bytes) -> Tuple[str, List[str], str]:
    try:
        from pypdf import PdfReader  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return "", [], "pypdf_missing:%s" % (repr(exc)[:80],)
    try:
        import io
        reader = PdfReader(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).lower()
        if "password" in msg or "encrypted" in msg:
            return "", [], "pdf_encrypted"
        return "", [], "pdf_unreadable:%s" % (repr(exc)[:120],)
    if getattr(reader, "is_encrypted", False):
        return "", [], "pdf_encrypted"
    pages: List[str] = []
    for page in list(reader.pages)[: max(1, OCR_MAX_PAGES * 4)]:
        try:
            pages.append((page.extract_text() or "").strip())
        except Exception:
            pages.append("")
    text = "\n\n".join(p for p in pages if p)
    return text, pages, ""


def _extract_docx(data: bytes) -> Tuple[str, str]:
    try:
        from docx import Document  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return "", "python_docx_missing:%s" % (repr(exc)[:80],)
    import io
    try:
        doc = Document(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        return "", "docx_unreadable:%s" % (repr(exc)[:120],)
    parts = [p.text.strip() for p in doc.paragraphs if (p.text or "").strip()]
    return "\n".join(parts), ""


@app.post("/document")
async def document(
    file: UploadFile = File(...),
    target: str = Form(default=""),
    x_spotter_user: Optional[str] = Header(default=""),
) -> Any:
    filename = file.filename or "upload"
    data = await file.read()
    if not data:
        return _error(400, "empty file")
    kind = "text"
    pages: List[str] = []
    err = ""
    text = ""
    lower = filename.lower()
    if data[:5] == b"%PDF-" or lower.endswith(".pdf"):
        kind = "pdf"
        text, pages, err = _extract_pdf(data)
    elif lower.endswith(".docx") or (
        data[:2] == b"PK" and b"word/" in data[:8192]
    ):
        kind = "docx"
        text, err = _extract_docx(data)
    else:
        text = data.decode("utf-8", errors="replace")

    st = _translate_mod()
    translated = st.translate_text(text, target=target, for_ingest=False) if text else {
        "source_lang": "", "translated": "", "skipped": err or "empty", "error": err,
    }
    return {
        "ok": not err or bool(text),
        "filename": filename,
        "kind": kind,
        "text": text,
        "pages": len(pages) if pages else (1 if text else 0),
        "source_lang": translated.get("source_lang") or st.detect_lang(text),
        "translated": translated.get("translated") or "",
        "skipped": translated.get("skipped") or "",
        "error": err or translated.get("error") or "",
    }
