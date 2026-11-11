#!/usr/bin/env python3
"""OCR cloned images (and image-based PDFs) after a Site Clone.

Tesseract runs in the site-clone sidecar, after HTTrack and optional
JavaScript deobfuscation. Text is written under job_dir/ocr/ so analysis
and the Prompt-tab indexer can use it without touching the raw mirror.

Caps (overridable via job options or env) keep a large dump from hanging
the sidecar: max image size, max images per job, timeout per image, and
a per-PDF page cap. The step is fail-open: a missing binary or a failed
file is recorded as a warning and the rest of the job continues.

Environment:
  SPOTTER_TESSERACT        override the tesseract binary
  SPOTTER_PDFTOPPM         override pdftoppm (image-based PDFs)
  SPOTTER_PDFTOTEXT        override pdftotext (skip raster when a PDF
                           already has extractable text)
  SPOTTER_OCR_MAX_IMAGES
  SPOTTER_OCR_MAX_IMAGE_BYTES
  SPOTTER_OCR_TIMEOUT      seconds per image
  SPOTTER_OCR_MAX_PDF_PAGES
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

IMG_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".tif", ".tiff", ".bmp",
}
PDF_EXT = ".pdf"
SKIP_DIRS = {"hts-cache", ".work", "__pycache__", "ocr"}

DEFAULT_MAX_IMAGES = 40
DEFAULT_MAX_IMAGE_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 15
DEFAULT_MAX_PDF_PAGES = 5
DEFAULT_LANG = "eng"
# A text PDF already handled by the ASCII extractor does not need raster OCR.
_MIN_TEXT_PDF_CHARS = 80
_MAX_WARNINGS = 24
_MAX_TEXT_CHARS = 100_000


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except ValueError:
        return default


def default_caps() -> dict[str, int]:
    return {
        "max_images": _int_env("SPOTTER_OCR_MAX_IMAGES", DEFAULT_MAX_IMAGES, 1, 400),
        "max_image_bytes": _int_env(
            "SPOTTER_OCR_MAX_IMAGE_BYTES", DEFAULT_MAX_IMAGE_BYTES, 32_768, 64 * 1024 * 1024),
        "timeout": _int_env("SPOTTER_OCR_TIMEOUT", DEFAULT_TIMEOUT, 3, 120),
        "max_pdf_pages": _int_env(
            "SPOTTER_OCR_MAX_PDF_PAGES", DEFAULT_MAX_PDF_PAGES, 1, 20),
    }


def tesseract_bin() -> str | None:
    override = (os.environ.get("SPOTTER_TESSERACT") or "").strip()
    if override:
        return override if os.path.isfile(override) and os.access(override, os.X_OK) else None
    return shutil.which("tesseract")


def pdftoppm_bin() -> str | None:
    override = (os.environ.get("SPOTTER_PDFTOPPM") or "").strip()
    if override:
        return override if os.path.isfile(override) and os.access(override, os.X_OK) else None
    return shutil.which("pdftoppm")


def pdftotext_bin() -> str | None:
    override = (os.environ.get("SPOTTER_PDFTOTEXT") or "").strip()
    if override:
        return override if os.path.isfile(override) and os.access(override, os.X_OK) else None
    return shutil.which("pdftotext")


def tool_status() -> dict[str, Any]:
    binary = tesseract_bin()
    out: dict[str, Any] = {
        "available": bool(binary),
        "binary": binary or "",
        "engine": "tesseract",
        "lang": DEFAULT_LANG,
        "pdftoppm": bool(pdftoppm_bin()),
        "pdftotext": bool(pdftotext_bin()),
        "version": "",
    }
    if not binary:
        return out
    try:
        proc = subprocess.run(
            [binary, "--version"], capture_output=True, timeout=8, check=False)
        blob = (proc.stdout or proc.stderr or b"").decode("utf-8", errors="replace")
        first = (blob.splitlines() or [""])[0].strip()
        out["version"] = first[:80]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return out


def _caps_from_options(options: dict[str, Any] | None) -> dict[str, int]:
    base = default_caps()
    if not options:
        return base
    mapping = {
        "max_images": ("ocr_max_images", "ocrMaxImages"),
        "max_image_bytes": ("ocr_max_image_bytes", "ocrMaxImageBytes"),
        "timeout": ("ocr_timeout", "ocrTimeout"),
        "max_pdf_pages": ("ocr_max_pdf_pages", "ocrMaxPdfPages"),
    }
    bounds = {
        "max_images": (1, 400),
        "max_image_bytes": (32_768, 64 * 1024 * 1024),
        "timeout": (3, 120),
        "max_pdf_pages": (1, 20),
    }
    for key, aliases in mapping.items():
        lo, hi = bounds[key]
        for alias in aliases:
            if alias in (options or {}) and options[alias] is not None:
                try:
                    base[key] = max(lo, min(hi, int(options[alias])))
                except (TypeError, ValueError):
                    pass
                break
    return base


def _safe_rel(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()).as_posix())
    except ValueError:
        return path.name


def _iter_targets(root: Path) -> list[Path]:
    found: list[Path] = []
    if not root.is_dir():
        return found
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            path = Path(dirpath) / name
            ext = path.suffix.lower()
            if ext in IMG_EXTS or ext == PDF_EXT:
                found.append(path)
    found.sort(key=lambda p: _safe_rel(root, p).lower())
    return found


def _run_tesseract(binary: str, src: Path, timeout: int, lang: str = DEFAULT_LANG) -> str:
    cmd = [binary, str(src), "stdout", "-l", lang, "--psm", "3"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout, check=False,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError("tesseract timed out after %ss on %s" % (timeout, src.name)) from e
    except OSError as e:
        raise RuntimeError("tesseract failed to start: %s" % type(e).__name__) from e
    if proc.returncode not in (0,):
        err = (proc.stderr or b"").decode("utf-8", errors="replace").strip().splitlines()
        tail = err[-1] if err else ("exit %s" % proc.returncode)
        raise RuntimeError("tesseract exited %s: %s" % (proc.returncode, tail[:200]))
    text = (proc.stdout or b"").decode("utf-8", errors="replace")
    return text.strip()[:_MAX_TEXT_CHARS]


def _pdf_extractable_text(path: Path, timeout: int) -> str:
    binary = pdftotext_bin()
    if not binary:
        return ""
    try:
        proc = subprocess.run(
            [binary, "-enc", "UTF-8", "-q", str(path), "-"],
            capture_output=True, timeout=min(timeout, 30), check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return (proc.stdout or b"").decode("utf-8", errors="replace").strip()


def _raster_pdf(path: Path, dest_dir: Path, max_pages: int, timeout: int) -> list[Path]:
    binary = pdftoppm_bin()
    if not binary:
        return []
    prefix = dest_dir / "page"
    try:
        proc = subprocess.run(
            [binary, "-png", "-f", "1", "-l", str(max_pages), "-r", "150",
             str(path), str(prefix)],
            capture_output=True, timeout=max(timeout * 2, 30), check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    pages = sorted(dest_dir.glob("page*.png"))
    return pages[:max_pages]


def _write_text(dest_root: Path, rel: str, text: str) -> Path | None:
    if not text or not text.strip():
        return None
    out = dest_root / (rel + ".txt")
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text.strip() + "\n", encoding="utf-8")
        return out
    except OSError:
        return None


def ocr_tree(
    mirror: str | Path,
    dest: str | Path,
    options: dict[str, Any] | None = None,
    progress_cb: Any = None,
) -> dict[str, Any]:
    """OCR images under mirror/ into dest/. Fail-open; never raises."""
    options = options or {}
    caps = _caps_from_options(options)
    dest_root = Path(dest)
    root = Path(mirror)
    meta: dict[str, Any] = {
        "ok": True,
        "enabled": True,
        "available": False,
        "engine": "tesseract",
        "version": "",
        "lang": DEFAULT_LANG,
        "files_considered": 0,
        "files_ocrd": 0,
        "pages_ocrd": 0,
        "skipped": 0,
        "timed_out": 0,
        "truncated": False,
        "warnings": [],
        "caps": caps,
    }
    warnings: list[str] = meta["warnings"]

    def warn(msg: str) -> None:
        if len(warnings) < _MAX_WARNINGS:
            warnings.append(msg[:300])

    status = tool_status()
    meta["available"] = bool(status.get("available"))
    meta["version"] = status.get("version") or ""
    meta["pdftoppm"] = bool(status.get("pdftoppm"))
    binary = tesseract_bin()
    if not binary:
        warn("OCR skipped: tesseract is not installed in this container")
        return meta

    try:
        dest_root.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        warn("OCR could not create output directory: %s" % type(e).__name__)
        return meta

    targets = _iter_targets(root)
    budget = caps["max_images"]
    used = 0
    started = time.time()

    for path in targets:
        meta["files_considered"] += 1
        if used >= budget:
            meta["truncated"] = True
            meta["skipped"] += 1
            continue
        try:
            size = path.stat().st_size
        except OSError:
            meta["skipped"] += 1
            continue
        if size <= 0:
            meta["skipped"] += 1
            continue
        if size > caps["max_image_bytes"]:
            meta["skipped"] += 1
            warn("OCR skipped oversized file %s (%s bytes)" % (path.name, size))
            continue
        rel = _safe_rel(root, path)
        ext = path.suffix.lower()
        if progress_cb:
            try:
                progress_cb({
                    "stage": "ocr",
                    "file": rel,
                    "files": used,
                    "elapsed": int(time.time() - started),
                })
            except Exception:
                pass
        try:
            if ext == PDF_EXT:
                n, empty = _ocr_pdf(binary, path, dest_root, rel, caps, budget - used)
            else:
                n, empty = _ocr_image(binary, path, dest_root, rel, caps["timeout"])
        except TimeoutError as e:
            meta["timed_out"] += 1
            meta["skipped"] += 1
            warn(str(e)[:300])
            used += 1
            continue
        except Exception as e:
            meta["skipped"] += 1
            warn("OCR failed on %s: %s" % (path.name, str(e)[:200]))
            continue
        if n:
            meta["files_ocrd"] += 1
            meta["pages_ocrd"] += n
            used += n
        else:
            meta["skipped"] += 1
            if empty:
                pass
            # empty text is not a hard failure
        if used >= budget and path is not targets[-1]:
            # remaining files after this one will be marked truncated next loop
            pass

    if meta["truncated"]:
        warn("OCR stopped after %s image(s) (job cap)" % caps["max_images"])
    return meta


def _ocr_image(binary: str, path: Path, dest_root: Path, rel: str,
               timeout: int) -> tuple[int, bool]:
    text = _run_tesseract(binary, path, timeout)
    if not text:
        return 0, True
    written = _write_text(dest_root, rel, text)
    return (1, False) if written else (0, True)


def _ocr_pdf(binary: str, path: Path, dest_root: Path, rel: str,
             caps: dict[str, int], remaining: int) -> tuple[int, bool]:
    """Rasterize an image-based PDF and OCR up to max_pdf_pages.

    If pdftotext already yields a reasonable amount of text, skip raster
    OCR — the analyzer already mines printable text from the PDF bytes.
    """
    extracted = _pdf_extractable_text(path, caps["timeout"])
    letters = sum(1 for c in extracted if c.isalpha())
    if letters >= _MIN_TEXT_PDF_CHARS:
        return 0, True
    if not pdftoppm_bin():
        return 0, True
    page_budget = min(caps["max_pdf_pages"], max(0, remaining))
    if page_budget <= 0:
        return 0, True
    with tempfile.TemporaryDirectory(prefix="spotter-ocr-pdf-") as tmp:
        pages = _raster_pdf(path, Path(tmp), page_budget, caps["timeout"])
        if not pages:
            return 0, True
        wrote = 0
        for i, page in enumerate(pages, start=1):
            try:
                text = _run_tesseract(binary, page, caps["timeout"])
            except TimeoutError:
                raise
            except Exception:
                continue
            if not text:
                continue
            if _write_text(dest_root, "%s.page-%d" % (rel, i), text):
                wrote += 1
        return (wrote, wrote == 0)
