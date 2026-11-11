#!/usr/bin/env python3
"""Parse an offline website tree (HTTrack output) for useful campaign intelligence.

Finds emails, phones, names, HTML comments, hidden form fields, meta tags,
forms, links, JavaScript endpoints and secret-shaped strings, sourcemap
references, image EXIF, and text extracted from cloned documents.

Secret-shaped values are redacted in the output. This script never prints a
raw secret. It only reads files under the given tree; it does not fetch URLs.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d{1,3}[\s\-.]?)?(?:\(?\d{3}\)?[\s\-.]?)\d{3}[\s\-.]?\d{4}(?!\w)")
# Common secret assignments in JS / HTML / env-like files.
SECRET_RE = re.compile(
    r"""(?ix)
    (AKIA[0-9A-Z]{16})
    | ((?:sk_live_|rk_live_|sk_test_|rk_test_)[0-9A-Za-z]{16,})
    | (?:api[_-]?key|auth[_-]?token|access[_-]?token|secret[_-]?key|client[_-]?secret|aws_?access_?key_?id)
      \s*[:=]\s*['\"]([A-Za-z0-9_\-/.]{12,})
    """
)
JS_ENDPOINT_RE = re.compile(
    r"""(?ix)
    (?:fetch|axios\.(?:get|post|put|patch|delete)|XMLHttpRequest)
    \s*\(\s*['\"]([^'\"]+)['\"]
    |
    (?:api_?base|base_?url|endpoint)\s*[:=]\s*['\"](https?://[^'\"]+)['\"]
    """
)
SOURCEMAP_RE = re.compile(r"sourceMappingURL\s*=\s*(\S+)")
COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/|//[^\n]*")

HTML_EXTS = {".html", ".htm", ".xhtml", ".php", ".asp", ".aspx", ".jsp"}
JS_EXTS = {".js", ".mjs", ".cjs"}
CSS_EXTS = {".css"}
IMG_EXTS = {".jpg", ".jpeg", ".tif", ".tiff"}
DOC_EXTS = {".txt", ".md", ".csv", ".json", ".xml", ".pdf", ".env", ".yml", ".yaml", ".ini", ".cfg"}

SKIP_DIR_NAMES = {"hts-cache", "hts-log.txt"}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 5000
MAX_EVIDENCE = 240


def redact(value: str) -> str:
    value = (value or "").strip()
    if len(value) <= 8:
        return value[:2] + "***" if value else ""
    return value[:4] + "***" + value[-2:]


def scrub(text: str) -> str:
    """Replace every secret-shaped substring in a snippet with a mask."""
    def _sub(m: re.Match) -> str:
        raw = next((g for g in m.groups() if g), m.group(0))
        return m.group(0).replace(raw, redact(raw))
    return SECRET_RE.sub(_sub, text or "")


def snippet(text: str, start: int = 0, width: int = MAX_EVIDENCE) -> str:
    text = re.sub(r"\s+", " ", (text or "")[max(0, start - 40): start + width]).strip()
    return text[:MAX_EVIDENCE]


def _safe_rel(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()).as_posix())
    except ValueError:
        return path.name


def _line_at(text: str, index: int) -> int:
    if index <= 0:
        return 1
    return text.count("\n", 0, index) + 1


def _read_text(path: Path, limit: int = MAX_FILE_BYTES) -> str:
    raw = path.read_bytes()[:limit]
    return raw.decode("utf-8", errors="replace")


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.emails: list[tuple[str, str]] = []
        self.phones: list[tuple[str, str]] = []
        self.comments: list[str] = []
        self.hidden: list[tuple[str, str]] = []
        self.metas: list[tuple[str, str]] = []
        self.forms: list[dict[str, Any]] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.json_ld: list[Any] = []
        self.title = ""
        self._in_title = False
        self._in_ld = False
        self._ld_buf: list[str] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            name = ad.get("name") or ad.get("property") or ad.get("http-equiv") or ""
            content = ad.get("content") or ""
            if name and content:
                self.metas.append((name, content))
        elif tag == "a" and ad.get("href"):
            self.links.append(ad["href"])
        elif tag == "script":
            typ = ad.get("type", "")
            if "ld+json" in typ:
                self._in_ld = True
                self._ld_buf = []
            if ad.get("src"):
                self.scripts.append(ad["src"])
        elif tag == "form":
            self._form = {"action": ad.get("action", ""), "method": ad.get("method", "get"), "fields": []}
        elif tag == "input" and self._form is not None:
            typ = (ad.get("type") or "text").lower()
            name = ad.get("name") or ad.get("id") or typ
            self._form["fields"].append(name)
            if typ == "hidden":
                self.hidden.append((name, ad.get("value") or ""))
        elif tag == "link" and ad.get("href"):
            self.links.append(ad["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._in_ld:
            self._in_ld = False
            raw = "".join(self._ld_buf).strip()
            if raw:
                try:
                    self.json_ld.append(json.loads(raw))
                except Exception:
                    pass
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._in_ld:
            self._ld_buf.append(data)
        for m in EMAIL_RE.finditer(data):
            self.emails.append((m.group(0), snippet(data, m.start())))
        for m in PHONE_RE.finditer(data):
            self.phones.append((m.group(0), snippet(data, m.start())))

    def handle_comment(self, data: str) -> None:
        c = data.strip()
        if c:
            self.comments.append(c[:MAX_EVIDENCE])


def _walk_jsonld_people(obj: Any) -> Iterable[dict[str, str]]:
    if isinstance(obj, list):
        for x in obj:
            yield from _walk_jsonld_people(x)
        return
    if not isinstance(obj, dict):
        return
    typ = obj.get("@type") or obj.get("type") or ""
    if isinstance(typ, list):
        typ = " ".join(str(t) for t in typ)
    if re.search(r"Person", str(typ), re.I):
        yield {
            "name": str(obj.get("name") or ""),
            "jobTitle": str(obj.get("jobTitle") or obj.get("role") or ""),
            "email": str(obj.get("email") or ""),
        }
    for v in obj.values():
        if isinstance(v, (dict, list)):
            yield from _walk_jsonld_people(v)


def _finding(category: str, severity: str, usefulness: str, value: str,
             evidence: str, source_path: str, tags: dict[str, Any] | None = None,
             **extra: Any) -> dict[str, Any]:
    rec = {
        "category": category,
        "severity": severity,
        "usefulness": usefulness,
        "value": value,
        "evidence": evidence[:MAX_EVIDENCE],
        "source_path": source_path,
    }
    rec.update(extra)
    if tags:
        prefix = str(tags.get("source_prefix") or "")
        rec.update({k: v for k, v in tags.items() if k != "source_prefix" and v != ""})
        if prefix:
            rec["source_path"] = prefix.rstrip("/") + "/" + rec["source_path"]
    rec["evidence"] = scrub(rec.get("evidence") or "")[:MAX_EVIDENCE]
    if rec.get("category") != "js_secret":
        rec["value"] = scrub(str(rec.get("value") or ""))[:MAX_EVIDENCE]
    return rec


def _collect_secrets(text: str, source_path: str, findings: list[dict[str, Any]],
                     tags: dict[str, Any] | None = None) -> None:
    for m in SECRET_RE.finditer(text):
        raw = next(g for g in m.groups() if g)
        findings.append(_finding(
            "js_secret", "high", "high", redact(raw),
            snippet(text, m.start()).replace(raw, redact(raw)),
            source_path, secret_kind="credential_pattern", tags=tags,
            source_line=_line_at(text, m.start())))


def parse_html(path: Path, root: Path, findings: list[dict[str, Any]],
               tags: dict[str, Any] | None = None) -> None:
    rel = _safe_rel(root, path)
    text = _read_text(path)
    p = _PageParser()
    try:
        p.feed(text)
    except Exception:
        pass
    for email, ev in p.emails:
        findings.append(_finding("email", "medium", "high", email.lower(), ev, rel, tags=tags))
    for phone, ev in p.phones:
        findings.append(_finding("phone", "low", "medium", re.sub(r"\s+", " ", phone), ev, rel, tags=tags))
    for c in p.comments:
        findings.append(_finding("html_comment", "info", "medium", c[:200], c, rel, tags=tags))
    for name, val in p.hidden:
        findings.append(_finding(
            "hidden_field", "low", "medium", name,
            "hidden %s=%s" % (name, redact(val) if len(val) > 8 else val), rel, tags=tags))
    for name, content in p.metas:
        sev = "low" if name.lower() in {"generator", "author", "description"} else "info"
        findings.append(_finding("meta", sev, "medium" if sev == "low" else "low",
                                 "%s=%s" % (name, content[:160]), content[:200], rel, tags=tags))
    for form in p.forms:
        findings.append(_finding(
            "form", "info", "medium",
            "%s %s" % (form.get("method") or "get", form.get("action") or ""),
            "fields: " + ", ".join(form.get("fields") or [])[:200], rel, tags=tags))
    for href in p.links:
        if href.startswith("#") or href.lower().startswith("javascript:"):
            continue
        findings.append(_finding("link", "info", "low", href, href, rel, tags=tags))
    for person in (item for blob in p.json_ld for item in _walk_jsonld_people(blob)):
        if person.get("name"):
            findings.append(_finding(
                "name", "medium", "high", person["name"],
                json.dumps({k: v for k, v in person.items() if v}, sort_keys=True)[:200],
                rel, email=person.get("email") or "", role=person.get("jobTitle") or "", tags=tags))
        if person.get("email"):
            findings.append(_finding("email", "medium", "high", person["email"].lower(),
                                     person["name"], rel, tags=tags))
    _collect_secrets(text, rel, findings, tags)


def parse_js(path: Path, root: Path, findings: list[dict[str, Any]],
             tags: dict[str, Any] | None = None) -> None:
    rel = _safe_rel(root, path)
    text = _read_text(path)
    for m in JS_ENDPOINT_RE.finditer(text):
        url = next(g for g in m.groups() if g)
        findings.append(_finding(
            "js_endpoint", "medium", "high", url, snippet(text, m.start()), rel,
            tags=tags, source_line=_line_at(text, m.start())))
    for m in SOURCEMAP_RE.finditer(text):
        findings.append(_finding(
            "sourcemap", "medium", "high", m.group(1), m.group(0)[:200], rel,
            tags=tags, source_line=_line_at(text, m.start())))
    for m in COMMENT_RE.finditer(text):
        c = m.group(0).strip()
        if len(c) > 8:
            findings.append(_finding(
                "js_comment", "info", "low", c[:200], snippet(text, m.start()), rel,
                tags=tags, source_line=_line_at(text, m.start())))
    _collect_secrets(text, rel, findings, tags)
    for m in EMAIL_RE.finditer(text):
        findings.append(_finding(
            "email", "medium", "high", m.group(0).lower(), snippet(text, m.start()), rel,
            tags=tags, source_line=_line_at(text, m.start())))


def parse_textish(path: Path, root: Path, findings: list[dict[str, Any]],
                  tags: dict[str, Any] | None = None) -> None:
    rel = _safe_rel(root, path)
    raw = path.read_bytes()[:MAX_FILE_BYTES]
    text = raw.decode("utf-8", errors="replace")
    if path.suffix.lower() == ".pdf":
        # Best-effort: extract printable runs from the raw PDF without a parser.
        text = "\n".join(m.group(0) for m in re.finditer(rb"[\x20-\x7e]{8,}", raw))
        if isinstance(text, bytes):
            text = text.decode("ascii", errors="replace")
    for m in EMAIL_RE.finditer(text):
        findings.append(_finding("email", "medium", "high", m.group(0).lower(), snippet(text, m.start()), rel, tags=tags))
    for m in PHONE_RE.finditer(text):
        findings.append(_finding("phone", "low", "medium", m.group(0), snippet(text, m.start()), rel, tags=tags))
    _collect_secrets(text, rel, findings, tags)
    if path.suffix.lower() in {".txt", ".md", ".csv"} and text.strip():
        findings.append(_finding("document", "info", "low", path.name, snippet(text, 0, 200), rel, tags=tags))


def _exif_ascii(blob: bytes) -> dict[str, str]:
    """Tiny JPEG EXIF reader for make/model and GPS if present."""
    out: dict[str, str] = {}
    if blob[:2] != b"\xff\xd8":
        return out
    i = 2
    while i + 4 < len(blob) and blob[i] == 0xFF:
        marker = blob[i + 1]
        if marker == 0xDA:
            break
        seglen = int.from_bytes(blob[i + 2:i + 4], "big")
        seg = blob[i + 4:i + 2 + seglen]
        i += 2 + seglen
        if marker == 0xE1 and seg.startswith(b"Exif\x00\x00"):
            # Pull readable ASCII tags (make/model/software/date) without a full TIFF parser.
            ascii_runs = re.findall(rb"[\x20-\x7e]{4,}", seg[6:6000])
            labels = [s.decode("ascii", "replace") for s in ascii_runs]
            if labels:
                out["ascii"] = " | ".join(labels[:8])[:240]
            if b"GPS" in seg or re.search(rb"GPS[A-Z]", seg):
                out["gps_present"] = "yes"
    return out


def parse_image(path: Path, root: Path, findings: list[dict[str, Any]],
                tags: dict[str, Any] | None = None) -> None:
    rel = _safe_rel(root, path)
    try:
        info = _exif_ascii(path.read_bytes()[:64 * 1024])
    except Exception:
        return
    if not info:
        return
    value = info.get("ascii") or "EXIF present"
    sev = "medium" if info.get("gps_present") else "low"
    findings.append(_finding("exif", sev, "medium" if sev == "medium" else "low",
                             value, json.dumps(info)[:200], rel,
                             gps=bool(info.get("gps_present")), tags=tags))



def _tags_for(deobfuscated: bool, deobfuscator: str, deobfuscator_version: str,
              source_prefix: str) -> dict[str, Any]:
    tags: dict[str, Any] = {}
    if deobfuscated:
        tags["deobfuscated"] = True
        if deobfuscator:
            tags["deobfuscator"] = deobfuscator
        if deobfuscator_version:
            tags["deobfuscator_version"] = deobfuscator_version
    if source_prefix:
        tags["source_prefix"] = source_prefix
    return tags


def analyze_tree(
    root: str | Path,
    start_url: str = "",
    *,
    deobfuscated: bool = False,
    deobfuscator: str = "",
    deobfuscator_version: str = "",
    source_prefix: str = "",
    skip_dirs: set[str] | None = None,
) -> dict[str, Any]:
    root_p = Path(root)
    findings: list[dict[str, Any]] = []
    files_scanned = 0
    tags = _tags_for(deobfuscated, deobfuscator, deobfuscator_version, source_prefix)
    skip = set(SKIP_DIR_NAMES)
    if skip_dirs:
        skip |= set(skip_dirs)
    if not root_p.is_dir():
        return {"ok": False, "error": "clone tree not found", "findings": [], "summary": {}}

    for dirpath, dirnames, filenames in os.walk(root_p):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".")]
        for name in filenames:
            if name.startswith(".") or name in {"hts-log.txt", "hts-cache.ndx", "hts-cache.dat", "manifest.json"}:
                continue
            path = Path(dirpath) / name
            if not path.is_file():
                continue
            ext = path.suffix.lower()
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size == 0:
                continue
            files_scanned += 1
            try:
                if ext in HTML_EXTS:
                    parse_html(path, root_p, findings, tags)
                elif ext in JS_EXTS:
                    parse_js(path, root_p, findings, tags)
                elif ext in IMG_EXTS:
                    parse_image(path, root_p, findings, tags)
                elif ext in DOC_EXTS or ext in CSS_EXTS:
                    parse_textish(path, root_p, findings, tags)
            except Exception as e:
                findings.append(_finding("document", "info", "low", path.name,
                                         "parse error: %s" % type(e).__name__,
                                         _safe_rel(root_p, path), tags=tags))
            if len(findings) >= MAX_FINDINGS:
                break
        if len(findings) >= MAX_FINDINGS:
            break

    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = (f["category"], str(f.get("value") or "").lower(), f.get("source_path") or "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    counts: dict[str, int] = {}
    for f in unique:
        counts[f["category"]] = counts.get(f["category"], 0) + 1
    high = sum(1 for f in unique if f["severity"] in {"high", "critical"})
    return {
        "ok": True,
        "start_url": start_url,
        "root": str(root_p),
        "files_scanned": files_scanned,
        "finding_count": len(unique),
        "high_or_critical": high,
        "summary": counts,
        "findings": unique,
        "truncated": len(findings) >= MAX_FINDINGS,
    }


def _rank_finding(f: dict[str, Any]) -> int:
    if f.get("deobfuscator") == "sourcemap":
        return 2
    if f.get("deobfuscated"):
        return 1
    if f.get("ocr"):
        return -1
    return 0


def merge_reports(*reports: dict[str, Any], start_url: str = "") -> dict[str, Any]:
    """Combine analyzer reports, preferring recovered sources for the same value."""
    findings: list[dict[str, Any]] = []
    files_scanned = 0
    truncated = False
    url = start_url
    root = ""
    by: dict[tuple[str, str], int] = {}
    for report in reports:
        if not report:
            continue
        if not url:
            url = str(report.get("start_url") or "")
        if not root:
            root = str(report.get("root") or "")
        files_scanned += int(report.get("files_scanned") or 0)
        truncated = truncated or bool(report.get("truncated"))
        for f in report.get("findings") or []:
            key = (str(f.get("category") or ""), str(f.get("value") or "").lower())
            if key in by:
                i = by[key]
                if _rank_finding(f) > _rank_finding(findings[i]):
                    findings[i] = f
                continue
            if len(findings) >= MAX_FINDINGS:
                truncated = True
                break
            by[key] = len(findings)
            findings.append(f)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["category"]] = counts.get(f["category"], 0) + 1
    high = sum(1 for f in findings if f.get("severity") in {"high", "critical"})
    return {
        "ok": True,
        "start_url": url,
        "root": root,
        "files_scanned": files_scanned,
        "finding_count": len(findings),
        "high_or_critical": high,
        "summary": counts,
        "findings": findings,
        "truncated": truncated,
    }


def analyze_ocr_dir(ocr_dir: str | Path, start_url: str = "") -> dict[str, Any]:
    """Mine emails, phones, and secret-shaped strings from OCR text files.

    Does not emit a document finding for every image; those would drown
    the report. Each finding is tagged ocr=true.
    """
    root = Path(ocr_dir)
    findings: list[dict[str, Any]] = []
    files = 0
    truncated = False
    tags = {"ocr": True, "source_prefix": "ocr"}
    if root.is_dir():
        paths = sorted(
            [p for p in root.rglob("*.txt") if p.is_file()],
            key=lambda p: str(p).lower(),
        )
        for path in paths:
            if any(part in {".work", "__pycache__"} or part.startswith(".")
                   for part in path.relative_to(root).parts[:-1]):
                continue
            files += 1
            text = _read_text(path)
            if not text.strip():
                continue
            rel = _safe_rel(root, path)
            for m in EMAIL_RE.finditer(text):
                findings.append(_finding(
                    "email", "medium", "high", m.group().lower(),
                    snippet(text, m.start()), rel, tags=tags,
                    source_line=_line_at(text, m.start())))
            for m in PHONE_RE.finditer(text):
                findings.append(_finding(
                    "phone", "low", "medium", m.group(),
                    snippet(text, m.start()), rel, tags=tags,
                    source_line=_line_at(text, m.start())))
            _collect_secrets(text, rel, findings, tags=tags)
            if len(findings) >= MAX_FINDINGS:
                truncated = True
                break
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["category"]] = counts.get(f["category"], 0) + 1
    return {
        "ok": True,
        "start_url": start_url,
        "root": str(root),
        "files_scanned": files,
        "finding_count": len(findings),
        "high_or_critical": sum(1 for f in findings if f.get("severity") in {"high", "critical"}),
        "summary": counts,
        "findings": findings,
        "truncated": truncated,
    }


def analyze_clone_outputs(
    mirror: str | Path,
    deobf_dir: str | Path | None,
    start_url: str = "",
    deobf_meta: dict[str, Any] | None = None,
    ocr_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Analyze the raw mirror plus any recovered or deobfuscated tree."""
    raw = analyze_tree(mirror, start_url)
    extras: list[dict[str, Any]] = []
    dest = Path(deobf_dir) if deobf_dir else None
    meta = deobf_meta or {}
    version = str(meta.get("version") or meta.get("pinned") or "")
    if dest and dest.is_dir():
        sm = dest / "sourcemaps"
        if sm.is_dir():
            extras.append(analyze_tree(
                sm, start_url, deobfuscated=True, deobfuscator="sourcemap",
                source_prefix="deobf/sourcemaps",
            ))
        extras.append(analyze_tree(
            dest, start_url, deobfuscated=True, deobfuscator="webcrack",
            deobfuscator_version=version, source_prefix="deobf",
            skip_dirs={"sourcemaps", ".work"},
        ))
    if ocr_dir and Path(ocr_dir).is_dir():
        extras.append(analyze_ocr_dir(ocr_dir, start_url))
    report = merge_reports(raw, *extras, start_url=start_url)
    report["root"] = str(Path(mirror))
    return report


SOURCE_ROOTS = ("deobf", "ocr", "mirror")
MAX_SOURCE_BYTES = 512 * 1024
DEFAULT_SOURCE_CONTEXT = 20
MAX_SOURCE_CONTEXT = 80


def resolve_job_source(job_dir: str | Path, rel: str) -> Path | None:
    """Resolve a job-relative source path, or None if it is not readable.

    Only deobf/, ocr/, and mirror/ under the job directory are allowed.
    Symlinks and parent-directory escapes are rejected.
    """
    rel = (rel or "").replace("\\", "/").strip()
    if not rel or rel.startswith("/") or rel.startswith("~"):
        return None
    parts = [p for p in Path(rel).parts if p not in ("", ".")]
    if not parts or parts[0] not in SOURCE_ROOTS:
        return None
    if any(p == ".." or p.startswith("/") for p in parts):
        return None
    root = Path(job_dir).resolve()
    target = root.joinpath(*parts)
    try:
        resolved = target.resolve()
        resolved.relative_to(root)
    except (ValueError, OSError):
        return None
    # Reject a symlink at the file or any directory on the way, so a planted
    # link cannot walk out of the job tree.
    cursor = root
    for part in parts:
        cursor = cursor / part
        try:
            if cursor.is_symlink():
                return None
        except OSError:
            return None
    if not resolved.is_file() or resolved.is_symlink():
        return None
    return resolved


def _focus_line(text: str, line: int, evidence: str) -> int:
    total = text.count("\n") + (1 if text else 0)
    try:
        n = int(line or 0)
    except (TypeError, ValueError):
        n = 0
    if 1 <= n <= max(total, 1):
        return n
    ev = (evidence or "").strip()
    if ev:
        # Evidence is often whitespace-collapsed and may already be scrubbed.
        needle = ev[:80]
        idx = text.find(needle)
        if idx < 0:
            compact = re.sub(r"\s+", " ", text)
            cidx = compact.find(re.sub(r"\s+", " ", needle))
            if cidx >= 0:
                # Map compact offset back approximately by walking the original.
                raw_i = 0
                compact_i = 0
                while raw_i < len(text) and compact_i < cidx:
                    if text[raw_i].isspace():
                        if compact_i < len(compact) and compact[compact_i] == " ":
                            compact_i += 1
                        raw_i += 1
                        while raw_i < len(text) and text[raw_i].isspace():
                            raw_i += 1
                    else:
                        compact_i += 1
                        raw_i += 1
                idx = raw_i
        if idx >= 0:
            return _line_at(text, idx)
    return 1


def source_snippet(
    job_dir: str | Path,
    rel: str,
    *,
    line: int = 0,
    evidence: str = "",
    context: int = DEFAULT_SOURCE_CONTEXT,
) -> dict[str, Any]:
    """Return a scrubbed, windowed view of a recovered clone source file.

    Never raises. The text is secret-scrubbed and is meant to be shown as
    text in the UI, not executed.
    """
    try:
        ctx = int(context or DEFAULT_SOURCE_CONTEXT)
    except (TypeError, ValueError):
        ctx = DEFAULT_SOURCE_CONTEXT
    ctx = max(1, min(MAX_SOURCE_CONTEXT, ctx))
    path = resolve_job_source(job_dir, rel)
    if path is None:
        return {"ok": False, "error": "path is not a readable clone source"}
    try:
        size = path.stat().st_size
    except OSError as e:
        return {"ok": False, "error": "could not read source: %s" % type(e).__name__}
    if size <= 0:
        return {"ok": False, "error": "source file is empty"}
    try:
        raw = path.read_bytes()[:MAX_SOURCE_BYTES]
    except OSError as e:
        return {"ok": False, "error": "could not read source: %s" % type(e).__name__}
    if b"\x00" in raw[:4096]:
        return {"ok": False, "error": "source is not a text file"}
    text = raw.decode("utf-8", errors="replace")
    rel_out = "/".join(
        p for p in Path((rel or "").replace("\\", "/")).parts if p not in ("", ".")
    )
    focus = _focus_line(text, line, evidence)
    lines = text.splitlines()
    if not lines:
        return {"ok": False, "error": "source file is empty"}
    start = max(1, focus - ctx)
    end = min(len(lines), focus + ctx)
    window = "\n".join(lines[start - 1:end])
    return {
        "ok": True,
        "path": rel_out,
        "start_line": start,
        "end_line": end,
        "focus_line": min(focus, len(lines)),
        "line_count": len(lines),
        "text": scrub(window),
        "truncated": size > MAX_SOURCE_BYTES or end < len(lines) or start > 1,
    }



def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("tree", help="path to the cloned site tree")
    ap.add_argument("--start-url", default="")
    ap.add_argument("-o", "--output", help="write JSON here instead of stdout")
    args = ap.parse_args()
    report = analyze_tree(args.tree, args.start_url)
    blob = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(blob + "\n", encoding="utf-8")
    else:
        sys.stdout.write(blob + "\n")
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
