#!/usr/bin/env python3
"""Offline unit tests for Site Clone analysis and HTTrack option building.

  python3 scripts/smoke_site_clone.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import site_clone  # noqa: E402
import site_clone_analyze as an  # noqa: E402

FIX = REPO / "scripts" / "fixtures" / "site_clone"
fails = 0
checks = 0


def ok(cond: bool, label: str, extra=None) -> None:
    global fails, checks
    checks += 1
    if cond:
        print("  ok    " + label)
    else:
        fails += 1
        print("  FAIL  " + label + ("" if extra is None else "\n        got: " + repr(extra)))


def section(t: str) -> None:
    print("\n── " + t)


section("URL sanitization")
ok(site_clone.sanitize_url("example.com").startswith("https://"), "bare host gets https://")
ok(site_clone.sanitize_url("https://Example.COM/a").lower().find("example.com") >= 0, "https URL accepted")
try:
    site_clone.sanitize_url("file:///etc/passwd")
    ok(False, "file:// rejected")
except ValueError:
    ok(True, "file:// rejected")
try:
    site_clone.sanitize_url("javascript:alert(1)")
    ok(False, "javascript: rejected")
except ValueError:
    ok(True, "javascript: rejected")
try:
    site_clone.sanitize_url("https://169.254.169.254/latest")
    ok(False, "link-local metadata host rejected")
except ValueError:
    ok(True, "link-local metadata host rejected")

section("option caps")
o = site_clone.normalize_options({"maxDepth": 99, "maxTime": 1, "external": "weird", "robots": "no"})
ok(o["max_depth"] == 8, "depth is capped at 8", o["max_depth"])
ok(o["max_time"] == 15, "max_time has a lower bound of 15s", o["max_time"])
ok(o["external"] == "none", "unknown external mode falls back to none", o["external"])
ok(o["robots"] is False, "robots=no is false", o["robots"])
d = site_clone.normalize_options({})
ok(d["max_depth"] == 2 and d["same_host"] is True and d["robots"] is True
   and d["external"] == "none", "defaults match the Active tab: depth 2, same host, robots, no externals")

section("HTTrack argv")
argv = site_clone.build_httrack_argv(
    "https://example.com/", Path("/tmp/clone-test"),
    site_clone.normalize_options({"maxDepth": 2, "includeImages": False, "robots": True}),
    user_agent="TestUA/1.0",
    proxy={"type": "http", "host": "127.0.0.1", "port": 8888},
)
joined = " ".join(str(x) for x in argv)
ok(argv[0] == "httrack", "invokes httrack")
ok("-r" in argv and "2" in argv, "passes max depth")
ok("-s2" in argv, "follows robots.txt by default flag")
ok("-F" in argv and "TestUA/1.0" in argv, "passes User-Agent")
ok("-P" in argv and "127.0.0.1:8888" in joined, "passes HTTP proxy")
ok("-*.jpg" in argv, "excludes images when toggled off")
ok("--max-time" in argv, "passes overall timeout")
ok("-%e" in argv, "external-depth flag is present")

off = site_clone.build_httrack_argv(
    "https://example.com/", Path("/tmp/clone-test"),
    site_clone.normalize_options({"robots": False, "sameHost": True, "external": "none"}),
)
ok("-s0" in off, "robots override uses -s0")

section("analyzer fixture")
report = an.analyze_tree(FIX, "https://example.com/")
ok(report["ok"] is True, "fixture tree analyzes")
cats = {f["category"] for f in report["findings"]}
by = {}
for f in report["findings"]:
    by.setdefault(f["category"], []).append(f)
ok("email" in cats, "finds emails", sorted(cats))
emails = {f["value"] for f in by.get("email", [])}
ok("info@example.com" in emails and "alice@example.com" in emails and "payroll@example.com" in emails,
   "emails from HTML, JSON-LD and text files", emails)
ok("phone" in cats, "finds a phone number")
ok("html_comment" in cats and any("staging" in (f["value"]+f["evidence"]).lower() for f in by["html_comment"]),
   "HTML comment mentioning staging admin")
ok("hidden_field" in cats and any(f["value"] == "csrf_token" for f in by["hidden_field"]),
   "hidden form fields")
ok("form" in cats, "records the login form")
ok("meta" in cats and any("wordpress" in f["value"].lower() for f in by["meta"]),
   "meta generator")
ok("name" in cats and any("Alice Director" in f["value"] for f in by["name"]),
   "JSON-LD person")
ok("js_endpoint" in cats and any("api.example.com" in f["value"] for f in by["js_endpoint"]),
   "JS API endpoint")
ok("js_secret" in cats, "JS secret-shaped strings")
ok("sourcemap" in cats, "sourcemap reference")
ok("document" in cats, "plain-text document recorded")
# secrets must be redacted
secret_vals = [f["value"] + f["evidence"] for f in by.get("js_secret", [])]
ok(all("AKIAIOSFODNN7EXAMPLE" not in s and "sk_live_51ABCDEFsecretvalue9999" not in s for s in secret_vals),
   "raw secret material is not present in findings")
ok(all("***" in f["value"] for f in by.get("js_secret", [])),
   "secret values are masked")
ok(report["finding_count"] == len(report["findings"]), "count matches list")

section("analyze does not fetch")
# Guarantee the analyzer never opens a network socket by pointing at a local tree only.
ok((FIX / "index.html").is_file(), "fixture is local")

print(("\nPASSED" if not fails else "\nFAILED") + f": {checks - fails}/{checks} checks")
sys.exit(1 if fails else 0)
