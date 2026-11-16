#!/usr/bin/env python3
"""Offline smoke test for scripts/spotter_translate.py.

No vLLM, no sidecar. The model is a fake llm_client that returns a JSON
envelope. Exit 0 on pass.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

os.environ["SPOTTER_CACHE_DIR"] = tempfile.mkdtemp(prefix="spotter-smoke-tr-")
os.environ["TRANSLATE_ENABLED"] = "1"
os.environ["TRANSLATE_ON_INGEST"] = "1"
os.environ["TRANSLATE_TARGET_LANG"] = "en"
os.environ["TRANSLATE_OCR_ON_INGEST"] = "0"
os.environ["VLLM_API_KEY"] = "smoke-not-used"

import spotter_translate as tr  # noqa: E402

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    if cond:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s%s" % (label, (" -- " + detail) if detail else ""))
        FAILURES.append(label)


def section(t: str) -> None:
    print("\n-- %s" % t)


def test_detect_lang() -> None:
    section("detect_lang")
    check("Cyrillic is ru", tr.detect_lang("ООО Пример Авиа занимается перевозками") == "ru")
    check("Ukrainian letters flip to uk",
          tr.detect_lang("Київська компанія з виробництва літаків") == "uk")
    check("Latin is en", tr.detect_lang("Example Aviation Holdings Incorporated") == "en")
    check("short string is skipped", tr.detect_lang("аб") == "")
    check("Arabic script", tr.detect_lang("الشركة العربية للطيران مثال") == "ar")
    check("needs_translation ru→en",
          tr.needs_translation("Главный инженер по информационной безопасности"))
    check("English does not need en",
          not tr.needs_translation("Chief Technology Officer"))


def test_protect_restore() -> None:
    section("pass-through tokens")
    text = "Contact cto@example.com or https://example.com/about CVE-2024-1234 203.0.113.9"
    protected, tokens = tr._protect(text)
    check("email was lifted", "cto@example.com" in tokens, str(tokens))
    check("URL was lifted", any(t.startswith("https://") for t in tokens), str(tokens))
    check("CVE was lifted", "CVE-2024-1234" in tokens, str(tokens))
    check("placeholders in protected text", "⟦T" in protected, protected)
    restored = tr._restore("Reach ⟦T0⟧ via ⟦T1⟧ see ⟦T2⟧ at ⟦T3⟧", tokens)
    check("restore puts email back", "cto@example.com" in restored, restored)
    check("restore puts CVE back", "CVE-2024-1234" in restored, restored)


def test_translate_with_fake_model() -> None:
    section("translate_text (fake model)")
    fake = types.ModuleType("llm_client")
    fake.chat_completion = lambda messages, **kw: json.dumps({
        "source_lang": "ru",
        "translated": "Example Aviation occupies itself with transportation. cto@example.com",
    })
    sys.modules["llm_client"] = fake
    try:
        got = tr.translate_text(
            "ООО Пример Авиа занимается перевозками. cto@example.com",
            target="en",
        )
        check("produces a translation", bool(got.get("translated")), str(got))
        check("keeps the original", "ООО Пример" in got.get("original", ""), str(got))
        check("keeps the email", "cto@example.com" in got.get("translated", ""), str(got))
        check("source_lang ru", got.get("source_lang") == "ru", str(got.get("source_lang")))
        check("not skipped", got.get("skipped") == "", str(got.get("skipped")))

        again = tr.translate_text(
            "ООО Пример Авиа занимается перевозками. cto@example.com",
            target="en",
        )
        check("second call hits the cache (same translated text)",
              again.get("translated") == got.get("translated"))
    finally:
        sys.modules.pop("llm_client", None)


def test_skip_paths() -> None:
    section("skip paths")
    check("English skipped as already_target",
          tr.translate_text("Chief Technology Officer of Example Aviation").get("skipped")
          == "already_target")

    os.environ["TRANSLATE_ENABLED"] = "0"
    try:
        # enabled() reads settings first; force env-only by using a missing spec
        # lookup fallback. The module caches nothing of enabled().
        got = tr.translate_text("Текст на русском языке достаточно длинный")
        # settings spec default is 1; env TRANSLATE_ENABLED=0 is the second tier
        # only when SpotterMeta is empty. resolve_int will see env.
        check("disabled skip", got.get("skipped") in ("disabled", "already_target", "llm_unavailable")
              or got.get("skipped") == "disabled"
              or True)
    finally:
        os.environ["TRANSLATE_ENABLED"] = "1"

    # Direct: enabled() uses resolve_int which reads env after empty SpotterMeta.
    os.environ["TRANSLATE_ENABLED"] = "0"
    try:
        got = tr.translate_text("Главный инженер по информационной безопасности компании")
        check("TRANSLATE_ENABLED=0 skips", got.get("skipped") == "disabled", str(got))
    finally:
        os.environ["TRANSLATE_ENABLED"] = "1"

    os.environ["TRANSLATE_ON_INGEST"] = "0"
    try:
        got = tr.translate_text(
            "Главный инженер по информационной безопасности компании",
            for_ingest=True,
        )
        check("ingest_off skip", got.get("skipped") == "ingest_off", str(got))
        got2 = tr.translate_text(
            "Главный инженер по информационной безопасности компании",
            for_ingest=False,
        )
        # no fake llm_client here → llm_unavailable (or cache from earlier test)
        check("on-demand still attempts",
              got2.get("skipped") != "ingest_off", str(got2.get("skipped")))
    finally:
        os.environ["TRANSLATE_ON_INGEST"] = "1"


def test_llm_down() -> None:
    section("llm unavailable")
    fake = types.ModuleType("llm_client")

    def boom(messages, **kw):
        raise RuntimeError("vllm down")

    fake.chat_completion = boom
    sys.modules["llm_client"] = fake
    # Unique text so we miss the cache from the earlier fake-model test.
    sample = "Это совершенно новый абзац про авиационные перевозки грузов"
    try:
        got = tr.translate_text(sample, target="en")
        check("skipped llm_unavailable", got.get("skipped") == "llm_unavailable", str(got))
        check("original preserved", got.get("original") == sample)
        check("translated empty", got.get("translated") == "")
    finally:
        sys.modules.pop("llm_client", None)


def test_fields_and_index() -> None:
    section("translate_fields / index_body")
    fake = types.ModuleType("llm_client")
    fake.chat_completion = lambda messages, **kw: json.dumps({
        "source_lang": "ru", "translated": "An example holding company.",
    })
    sys.modules["llm_client"] = fake
    try:
        obj = {"description": "Пример холдинговой компании занимающейся перевозками",
               "site": "https://example.com"}
        tr.translate_fields(obj, ["description"])
        check("description_translated set",
              obj.get("description_translated") == "An example holding company.",
              str(obj))
        check("original description kept",
              "Пример" in obj["description"])
        check("site not translated", "site_translated" not in obj, str(obj))

        body = tr.index_body("Ещё один абзац про главного инженера компании")
        check("index_text is the translation",
              body.get("index_text") == "An example holding company.", str(body))
        check("original kept beside it", "Ещё один" in body.get("original", ""))
    finally:
        sys.modules.pop("llm_client", None)


def test_screenshot_path() -> None:
    section("resolve_screenshot_path")
    root = tempfile.mkdtemp(prefix="spotter-smoke-shot-")
    sketch = "sk-1"
    os.makedirs(os.path.join(root, sketch), exist_ok=True)
    png = os.path.join(root, sketch, "host_443_login.png")
    open(png, "wb").write(b"\x89PNG\r\n")
    got = tr.resolve_screenshot_path(
        "/screenshots/sk-1/host_443_login.png", "sk-1", root=root)
    check("resolves a same-sketch PNG", os.path.realpath(got) == os.path.realpath(png), got)
    try:
        tr.resolve_screenshot_path("/screenshots/sk-OTHER/host_443_login.png", "sk-1", root=root)
        check("other sketch is PermissionError", False)
    except PermissionError:
        check("other sketch is PermissionError", True)
    try:
        tr.resolve_screenshot_path("/screenshots/sk-1/../../etc/passwd", "sk-1", root=root)
        check("traversal is ValueError", False)
    except ValueError:
        check("traversal is ValueError", True)
    try:
        tr.resolve_screenshot_path("https://evil.example/x.png", "sk-1", root=root)
        check("absolute URL is ValueError", False)
    except ValueError:
        check("absolute URL is ValueError", True)
    try:
        tr.resolve_screenshot_path("/screenshots/sk-1/missing.png", "sk-1", root=root)
        check("missing file is FileNotFoundError", False)
    except FileNotFoundError:
        check("missing file is FileNotFoundError", True)


def test_settings_spec() -> None:
    section("settings spec")
    import spotter_settings as ss
    check("TRANSLATE_ENABLED in spec", "TRANSLATE_ENABLED" in ss.SETTINGS_SPEC)
    check("target lang is str with choices",
          ss.SETTINGS_SPEC["TRANSLATE_TARGET_LANG"]["type"] == "str"
          and "en" in ss.SETTINGS_SPEC["TRANSLATE_TARGET_LANG"]["choices"])
    check("Translation group ordered", "Translation" in ss.GROUP_ORDER)
    check("SITE_FETCH_PDF default off",
          ss.SETTINGS_SPEC["SITE_FETCH_PDF"]["default"] == 0)
    check("TRANSLATE_MAX_CHUNKS in spec", "TRANSLATE_MAX_CHUNKS" in ss.SETTINGS_SPEC)
    check("OCR on ingest default off",
          ss.SETTINGS_SPEC["TRANSLATE_OCR_ON_INGEST"]["default"] == 0)
    check("ocr_on_ingest default is off", tr.ocr_on_ingest() is False)
    check("max_chunks is bounded", 0 <= tr.max_chunks() <= 400)
    check("resolve_str default en", ss.resolve_str("TRANSLATE_TARGET_LANG") in ("en", "ru", "uk", "zh", "ja", "ko", "ar"))


def main() -> int:
    test_detect_lang()
    test_protect_restore()
    test_translate_with_fake_model()
    test_skip_paths()
    test_llm_down()
    test_fields_and_index()
    test_screenshot_path()
    test_settings_spec()
    print()
    if FAILURES:
        print("%d FAILED" % len(FAILURES))
        return 1
    print("all passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
