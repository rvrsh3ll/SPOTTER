#!/usr/bin/env python3
"""Local translation of retrieved OSINT text.

WHY THIS EXISTS
---------------
hh.ru, EGRUL, Russian corporate sites and EyeWitness titles arrive in the
source language. The Prompt-tab site corpus is worse: rag_indexer's default
TF-IDF tokenizer only matches [a-z0-9], so Cyrillic crawl chunks are
unsearchable. This module turns source-language text into a parallel
translation without sending engagement data off-box.

The original string is the source of truth. Callers store it next to the
translation (description_translated, metadata.original). Verbatim LLM
extraction, employment matching and report citations all keep using the
original.

CONSTRAINTS
-----------
Runs inside the n8n Python task runner: stdlib + requests + allowlisted
local modules. No langdetect, no Argos, no cloud MT. The analysis model
(Qwen via llm_client) is already multilingual and already forces JSON
mode, so the prompt asks for a JSON envelope.

Fail closed on display, open on the crawl: if vLLM is down the original
is returned with skipped='llm_unavailable' and the caller still indexes
or renders it.

Environment / settings (spotter_settings, then env, then defaults):
    TRANSLATE_ENABLED        1 to translate                (default 1)
    TRANSLATE_TARGET_LANG    en|ru|uk|zh|ja|ko|ar          (default en)
    TRANSLATE_ON_INGEST      1 to translate at ingest      (default 1)
    TRANSLATE_MAX_CHARS      per-call cap                  (default 4000)
    TRANSLATE_TIMEOUT        seconds                       (default 60)
    TRANSLATE_API_URL        sidecar base                  (http://translate-api:8052)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from spotter_cache import ensure_cache_path


TARGET_LANGS = ("en", "ru", "uk", "zh", "ja", "ko", "ar")

_UK_LETTERS = set("іїєґІЇЄҐ")
_CYR_RE = re.compile(r"[\u0400-\u04FF]")
_HIRA_KATA_RE = re.compile(r"[\u3040-\u30FF]")
_HANGUL_RE = re.compile(r"[\uAC00-\uD7AF]")
_CJK_RE = re.compile(r"[\u4E00-\u9FFF]")
_ARABIC_RE = re.compile(r"[\u0600-\u06FF]")
_LATIN_RE = re.compile(r"[A-Za-z]")

# Tokens the model must copy unchanged. Named so a post-pass can restore them
# if the model still rewrites one. INN is 10 or 12 digits; OGRN is 13 or 15.
_PASS_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I),
    re.compile(r"https?://[^\s<>\"']+", re.I),
    re.compile(r"\b(?:CVE|cve)-\d{4}-\d{4,7}\b"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\bS-\d+(?:-\d+){2,}\b"),
    re.compile(r"\b[A-Fa-f0-9]{32}\b"),
    re.compile(r"\b[A-Fa-f0-9]{40}\b"),
    re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    re.compile(r"\b(?:INN|ИНН)[:\s]*\d{10}(?:\d{2})?\b", re.I),
    re.compile(r"\b(?:OGRN|ОГРН)[:\s]*\d{13}(?:\d{2})?\b", re.I),
    re.compile(r"\b[A-Za-z0-9._\-]+\.(?:com|net|org|ru|su|io|gov|mil|info|biz)\b", re.I),
)

_PLACEHOLDER = "⟦T%d⟧"

_SYSTEM = (
    "You translate retrieved intelligence text for an authorized security "
    "assessment. Reply with JSON only, matching "
    '{"source_lang": "<iso 639-1 or empty>", "translated": "<text>"}. '
    "Preserve meaning. Copy emails, URLs, IP addresses, CVE IDs, hashes, "
    "Windows SIDs, domain names, INN and OGRN numbers, and any token wrapped "
    "in ⟦T…⟧ exactly. Do not add commentary."
)


def _as_int(name: str, default: int) -> int:
    try:
        import spotter_settings as ss
        return int(ss.resolve_int(name))
    except Exception:
        raw = (os.environ.get(name) or "").strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            return default


def enabled() -> bool:
    return _as_int("TRANSLATE_ENABLED", 1) != 0


def ingest_enabled() -> bool:
    return enabled() and _as_int("TRANSLATE_ON_INGEST", 1) != 0


def target_lang() -> str:
    try:
        import spotter_settings as ss
        val = str(ss.resolve("TRANSLATE_TARGET_LANG") or "").strip().lower()
    except Exception:
        val = (os.environ.get("TRANSLATE_TARGET_LANG") or "en").strip().lower()
    return val if val in TARGET_LANGS else "en"


def max_chars() -> int:
    return max(200, min(20000, _as_int("TRANSLATE_MAX_CHARS", 4000)))


def max_chunks() -> int:
    return max(0, min(400, _as_int("TRANSLATE_MAX_CHUNKS", 80)))


def timeout_s() -> int:
    return max(5, min(180, _as_int("TRANSLATE_TIMEOUT", 60)))


def api_url() -> str:
    return (os.environ.get("TRANSLATE_API_URL") or "http://translate-api:8052").rstrip("/")


def ocr_enabled() -> bool:
    return enabled() and _as_int("TRANSLATE_OCR_ENABLED", 1) != 0


def ocr_on_ingest() -> bool:
    return ocr_enabled() and _as_int("TRANSLATE_OCR_ON_INGEST", 0) != 0


def ocr_via_sidecar(
    screenshot_url: str,
    sketch_id: str,
    *,
    target: str = "",
) -> Dict[str, Any]:
    """POST /ocr on the sidecar. Never raises."""
    try:
        import requests
        r = requests.post(
            api_url() + "/ocr",
            json={
                "screenshot_url": screenshot_url,
                "sketch_id": sketch_id,
                "target": target or target_lang(),
            },
            timeout=timeout_s() + 30,
        )
        body = r.json() if r.content else {}
        if isinstance(body, dict):
            return body
        return {"ok": False, "error": "bad_json"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": repr(exc)[:160]}


def extract_document_via_sidecar(
    data: bytes,
    filename: str = "upload",
    *,
    target: str = "",
) -> Dict[str, Any]:
    """POST /document on the sidecar. Never raises."""
    try:
        import requests
        r = requests.post(
            api_url() + "/document",
            files={"file": (filename or "upload", data)},
            data={"target": target or target_lang()},
            timeout=timeout_s() + 60,
        )
        body = r.json() if r.content else {}
        if isinstance(body, dict):
            return body
        return {"ok": False, "error": "bad_json", "text": ""}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": repr(exc)[:160], "text": ""}


# Screenshot URLs the Web tab already serves, auth-gated, at /screenshots/.
# The sidecar reads the file from the same host dir the runners write; the
# browser never posts PNG bytes. Sketch mismatch is 403, traversal is 400.
_SHOT_RE = re.compile(
    r"^/screenshots/([A-Za-z0-9._-]+)/([A-Za-z0-9._/-]+\.(?:png|jpe?g|webp))$",
    re.I,
)


def resolve_screenshot_path(
    screenshot_url: str,
    sketch_id: str,
    *,
    root: str = "",
) -> str:
    """Return the absolute file path for a /screenshots/<sketch>/… URL.

    Raises ValueError on a malformed URL or traversal, PermissionError when
    the URL's sketch does not match, FileNotFoundError when the file is
    missing. `root` defaults to SPOTTER_SCREENSHOTS_DIR or /data/screenshots.
    """
    raw = str(screenshot_url or "").strip()
    m = _SHOT_RE.match(raw)
    if not m:
        raise ValueError("screenshot_url must be /screenshots/<sketch>/<file>.png")
    url_sketch, rel = m.group(1), m.group(2)
    want = str(sketch_id or "").strip()
    if not want:
        raise ValueError("sketch_id is required")
    if url_sketch != want:
        raise PermissionError("screenshot is not in this campaign's sketch")
    if ".." in rel or rel.startswith("/") or rel.startswith("\\"):
        raise ValueError("path traversal")
    base = root or os.environ.get("SPOTTER_SCREENSHOTS_DIR") or "/data/screenshots"
    base_real = os.path.realpath(base)
    full = os.path.realpath(os.path.join(base, url_sketch, rel))
    prefix = base_real if base_real.endswith(os.sep) else base_real + os.sep
    if full != base_real and not full.startswith(prefix):
        raise ValueError("path escapes screenshot root")
    if not os.path.isfile(full):
        raise FileNotFoundError(full)
    return full


def detect_lang(text: str) -> str:
    """Script heuristic. Empty string means 'too short / unknown, skip'."""
    letters = [c for c in (text or "") if c.isalpha()]
    if len(letters) < 4:
        return ""
    n = len(letters)
    blob = "".join(letters)

    def ratio(pat: re.Pattern[str]) -> float:
        return len(pat.findall(blob)) / n

    if ratio(_CYR_RE) >= 0.25:
        return "uk" if any(c in _UK_LETTERS for c in letters) else "ru"
    if ratio(_HANGUL_RE) >= 0.2:
        return "ko"
    if ratio(_HIRA_KATA_RE) >= 0.08:
        return "ja"
    if ratio(_CJK_RE) >= 0.2:
        return "zh"
    if ratio(_ARABIC_RE) >= 0.25:
        return "ar"
    if ratio(_LATIN_RE) >= 0.6:
        return "en"
    return "other"


def needs_translation(text: str, target: str = "") -> bool:
    tgt = (target or target_lang()).lower()
    src = detect_lang(text)
    if not src or src == tgt:
        return False
    # 'other' still goes to the model; 'en' against a non-en target does too.
    return True


def _protect(text: str) -> Tuple[str, List[str]]:
    found: List[str] = []
    out = text

    def repl(m: re.Match[str]) -> str:
        found.append(m.group(0))
        return _PLACEHOLDER % (len(found) - 1)

    for pat in _PASS_PATTERNS:
        out = pat.sub(repl, out)
    return out, found


def _restore(text: str, tokens: Sequence[str]) -> str:
    out = text
    for i, tok in enumerate(tokens):
        marker = _PLACEHOLDER % i
        if marker in out:
            out = out.replace(marker, tok)
        elif tok not in out:
            out = out.rstrip() + " " + tok
    return out


def _parse_model_json(raw: str) -> Dict[str, Any]:
    s = (raw or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s, count=1, flags=re.I)
        s = re.sub(r"\s*```$", "", s)
    data = json.loads(s)
    return data if isinstance(data, dict) else {}


def _cache_path(target: str, source: str, text: str) -> str:
    root = os.environ.get("SPOTTER_CACHE_DIR") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", ".spotter-cache"
    )
    folder = os.path.join(root, "translate")
    ensure_cache_path(folder, is_dir=True)
    key = hashlib.sha256(("%s|%s|%s" % (target, source, text)).encode("utf-8")).hexdigest()
    return os.path.join(folder, key + ".json")


def _cache_get(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _cache_put(path: str, payload: Dict[str, Any]) -> None:
    try:
        ensure_cache_path(path, is_dir=False)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        pass


def _empty(original: str, *, skipped: str = "", error: str = "",
           source_lang: str = "", target: str = "") -> Dict[str, Any]:
    return {
        "source_lang": source_lang or detect_lang(original),
        "target_lang": target or target_lang(),
        "original": original,
        "translated": "",
        "skipped": skipped,
        "error": error,
    }


def translate_text(
    text: str,
    *,
    target: str = "",
    source: str = "",
    for_ingest: bool = False,
) -> Dict[str, Any]:
    """Translate `text` into `target`. Never raises.

    `for_ingest=True` honours TRANSLATE_ON_INGEST so a crawl can skip the
    model when the operator only wants on-demand translation.
    """
    original = text if isinstance(text, str) else str(text or "")
    tgt = (target or target_lang()).lower()
    if tgt not in TARGET_LANGS:
        tgt = "en"

    if not original.strip():
        return _empty(original, skipped="empty", target=tgt)
    if not enabled():
        return _empty(original, skipped="disabled", target=tgt)
    if for_ingest and not ingest_enabled():
        return _empty(original, skipped="ingest_off", target=tgt)

    src = (source or detect_lang(original)).lower()
    if src == tgt or not needs_translation(original, tgt):
        return {
            "source_lang": src or detect_lang(original),
            "target_lang": tgt,
            "original": original,
            "translated": "",
            "skipped": "already_target",
            "error": "",
        }

    clipped = original[: max_chars()]
    cache = _cache_path(tgt, src, clipped)
    hit = _cache_get(cache)
    if hit and hit.get("translated"):
        hit.setdefault("original", original)
        hit.setdefault("skipped", "")
        hit.setdefault("error", "")
        return hit

    protected, tokens = _protect(clipped)
    messages = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content":
         "Target language: %s\nDetected source language: %s\n\nText:\n%s"
         % (tgt, src or "unknown", protected)},
    ]
    try:
        import llm_client
        raw = llm_client.chat_completion(messages, timeout=timeout_s())
    except Exception as exc:  # noqa: BLE001
        return _empty(original, skipped="llm_unavailable", error=repr(exc)[:200],
                      source_lang=src, target=tgt)

    try:
        data = _parse_model_json(raw if isinstance(raw, str) else "")
    except Exception as exc:  # noqa: BLE001
        return _empty(original, skipped="bad_json", error=repr(exc)[:200],
                      source_lang=src, target=tgt)

    translated = str(data.get("translated") or "").strip()
    if not translated:
        return _empty(original, skipped="empty_model", source_lang=src, target=tgt)

    translated = _restore(translated, tokens)
    out = {
        "source_lang": str(data.get("source_lang") or src or detect_lang(original)),
        "target_lang": tgt,
        "original": original,
        "translated": translated,
        "skipped": "",
        "error": "",
    }
    _cache_put(cache, out)
    return out


def translate_fields(
    obj: Dict[str, Any],
    keys: Iterable[str],
    *,
    for_ingest: bool = True,
    target: str = "",
) -> Dict[str, Any]:
    """Copy translated values onto `<key>_translated` plus `source_lang`.

    Mutates and returns `obj`. Keys whose text is already the target language
    are left without a `_translated` sibling.
    """
    if not isinstance(obj, dict):
        return obj
    langs: List[str] = []
    for key in keys:
        val = obj.get(key)
        if not isinstance(val, str) or not val.strip():
            continue
        result = translate_text(val, target=target, for_ingest=for_ingest)
        if result.get("source_lang"):
            langs.append(str(result["source_lang"]))
        if result.get("translated") and result["translated"] != val:
            obj[key + "_translated"] = result["translated"]
    if langs:
        obj.setdefault("source_lang", langs[0])
    return obj


def index_body(text: str, *, for_ingest: bool = True, target: str = "") -> Dict[str, Any]:
    """Choose the string that should be embedded, keeping the original beside it.

    Returns {index_text, original, lang, translated, skipped}. `index_text` is
    the translation when one was produced, else the original — so English
    Prompt queries hit a Russian page.
    """
    original = text if isinstance(text, str) else str(text or "")
    result = translate_text(original, target=target, for_ingest=for_ingest)
    translated = str(result.get("translated") or "")
    return {
        "index_text": translated or original,
        "original": original,
        "lang": result.get("source_lang") or detect_lang(original),
        "translated": translated,
        "skipped": result.get("skipped") or "",
    }
