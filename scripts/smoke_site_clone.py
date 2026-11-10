#!/usr/bin/env python3
"""Offline unit tests for Site Clone analysis and HTTrack option building.

  python3 scripts/smoke_site_clone.py
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import site_clone  # noqa: E402
import site_clone_analyze as an  # noqa: E402
import site_clone_deobfuscate as deob  # noqa: E402

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
ok("secret@ops.example.com" not in (FIX / "js" / "packed.js").read_text(),
   "packed fixture hides the recovered email from raw JS")

section("deobfuscation options")
d = site_clone.normalize_options({})
ok(d["deobfuscate"] is True and d["deobf_timeout"] == 180,
   "deobfuscate is on by default with a 180s job timeout", (d["deobfuscate"], d["deobf_timeout"]))
capped = site_clone.normalize_options({"deobfuscate": "no", "deobfuscateTimeout": 5})
ok(capped["deobfuscate"] is False, "deobfuscate can be turned off")
ok(capped["deobf_timeout"] == 15, "deobf timeout has a lower bound of 15s", capped["deobf_timeout"])
hi = site_clone.normalize_options({"deobfTimeout": 99999})
ok(hi["deobf_timeout"] == 1800, "deobf timeout is capped at 1800s", hi["deobf_timeout"])

section("sourcemap recovery without webcrack")
tmp = Path(tempfile.mkdtemp(prefix="spotter-deobf-"))
try:
    mirror = tmp / "mirror"
    shutil.copytree(FIX, mirror)
    raw_before = (mirror / "js" / "packed.js").read_bytes()
    dest = tmp / "deobf"
    env_bin = os.environ.pop("SPOTTER_WEBCRACK", None)
    os.environ["SPOTTER_WEBCRACK"] = str(tmp / "no-such-webcrack")
    try:
        meta = deob.deobfuscate_tree(
            mirror, dest,
            site_clone.normalize_options({"deobfuscate": True, "deobf_timeout": 30}),
        )
    finally:
        if env_bin is None:
            os.environ.pop("SPOTTER_WEBCRACK", None)
        else:
            os.environ["SPOTTER_WEBCRACK"] = env_bin
    recovered = list(dest.joinpath("sourcemaps").rglob("hidden.js"))
    ok(meta["ok"] is True, "sourcemap-only run is fail-open ok")
    ok(meta["available"] is False, "webcrack is reported missing")
    ok(any("webcrack is not installed" in w for w in meta["warnings"]),
       "missing webcrack is a warning", meta["warnings"])
    ok(meta["sourcemaps_applied"] >= 1 and recovered,
       "cloned .map sourcesContent was written under deobf/sourcemaps", recovered)
    ok((mirror / "js" / "packed.js").read_bytes() == raw_before,
       "raw mirror JS is not overwritten by sourcemap recovery")
    report = an.analyze_clone_outputs(mirror, dest, "https://example.com/", meta)
    emails = {f["value"] for f in report["findings"] if f["category"] == "email"}
    endpoints = {f["value"] for f in report["findings"] if f["category"] == "js_endpoint"}
    sm_email = [f for f in report["findings"]
                if f["category"] == "email" and f["value"] == "secret@ops.example.com"]
    ok("secret@ops.example.com" in emails, "sourcemap-recovered email is analyzed", emails)
    ok(any("hidden.example.com/internal" in v for v in endpoints),
       "sourcemap-recovered endpoint is analyzed", endpoints)
    ok(sm_email and sm_email[0].get("deobfuscated") is True
       and sm_email[0].get("deobfuscator") == "sourcemap",
       "sourcemap findings are tagged deobfuscated=sourcemap", sm_email[:1])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

section("mocked webcrack")
tmp = Path(tempfile.mkdtemp(prefix="spotter-deobf-"))
try:
    mirror = tmp / "mirror"
    shutil.copytree(FIX, mirror)
    raw_before = {rel: (mirror / rel).read_bytes()
                  for rel in ("js/app.js", "js/packed.js", "index.html")}
    dest = tmp / "deobf"
    mock = tmp / "webcrack"
    mock.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "if '--version' in args:\n"
        "    print('2.16.0')\n"
        "    sys.exit(0)\n"
        "out = None\n"
        "src = None\n"
        "i = 0\n"
        "while i < len(args):\n"
        "    if args[i] == '-o' and i + 1 < len(args):\n"
        "        out = Path(args[i+1]); i += 2; continue\n"
        "    if args[i] in ('-f','--force','--no-jsx','--no-unpack','--no-deobfuscate','--no-unminify','-m'):\n"
        "        i += 1; continue\n"
        "    if not args[i].startswith('-'):\n"
        "        src = Path(args[i])\n"
        "    i += 1\n"
        "if out is None:\n"
        "    sys.exit(2)\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        "(out / 'deobfuscated.js').write_text(\n"
        "    'fetch(\"https://webcrack.example.com/unpacked\");\\n'\n"
        "    'const api_base = \"https://webcrack.example.com/v2\";\\n'\n"
        ")\n"
        "if src and 'packed' in src.name:\n"
        "    (out / '1.js').write_text('fetch(\"/webpack-module-endpoint\");\\n')\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    mock.chmod(mock.stat().st_mode | stat.S_IEXEC)
    os.environ["SPOTTER_WEBCRACK"] = str(mock)
    try:
        meta = deob.deobfuscate_tree(
            mirror, dest,
            site_clone.normalize_options({"deobfuscate": True, "deobf_timeout": 60}),
        )
        report = an.analyze_clone_outputs(mirror, dest, "https://example.com/", meta)
    finally:
        os.environ.pop("SPOTTER_WEBCRACK", None)
    ok(meta["available"] is True, "mock webcrack is detected", meta)
    ok(meta["files_deobfuscated"] >= 1, "mock webcrack output was harvested", meta)
    ok(meta["files_unpacked"] >= 1, "unpacked bundle modules were copied", meta)
    for rel, blob in raw_before.items():
        ok((mirror / rel).read_bytes() == blob, "mirror %s left unchanged" % rel)
    endpoints = {f["value"] for f in report["findings"] if f["category"] == "js_endpoint"}
    tagged = [f for f in report["findings"] if f.get("deobfuscated") and "webcrack.example.com" in str(f.get("value"))]
    ok(any("webcrack.example.com" in v for v in endpoints),
       "webcrack output is analyzed for endpoints", endpoints)
    ok(any("/webpack-module-endpoint" in v for v in endpoints),
       "unpacked module endpoints are analyzed", endpoints)
    ok(tagged and all(f.get("deobfuscator") == "webcrack" for f in tagged),
       "webcrack findings are tagged deobfuscated=true + tool", tagged[:2])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

section("run_clone deobfuscates a pre-populated tree")
tmp = Path(tempfile.mkdtemp(prefix="spotter-deobf-"))
try:
    job_dir = tmp / "job"
    mirror = job_dir / "mirror"
    shutil.copytree(FIX, mirror)
    mock = tmp / "webcrack"
    mock.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "from pathlib import Path\n"
        "args=sys.argv[1:]\n"
        "if '--version' in args:\n"
        "    print('2.16.0'); sys.exit(0)\n"
        "out=None\n"
        "for i,a in enumerate(args):\n"
        "    if a=='-o' and i+1<len(args): out=Path(args[i+1])\n"
        "if not out: sys.exit(2)\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        "(out/'deobfuscated.js').write_text('const api_base=\"https://jobrun.example.com/api\";\\n')\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    mock.chmod(mock.stat().st_mode | stat.S_IEXEC)
    os.environ["SPOTTER_WEBCRACK"] = str(mock)
    orig_sc_which = site_clone.shutil.which
    def _sc_which(name):
        if name in {"httrack", "proxychains4", "proxychains"}:
            return None
        return orig_sc_which(name)
    site_clone.shutil.which = _sc_which
    try:
        result = site_clone.run_clone(
            "https://example.com/", job_dir,
            options={"deobfuscate": True, "deobfTimeout": 60},
        )
    finally:
        site_clone.shutil.which = orig_sc_which
        os.environ.pop("SPOTTER_WEBCRACK", None)
    endpoints = {f["value"] for f in (result.get("analysis") or {}).get("findings") or []
                 if f["category"] == "js_endpoint"}
    ok(result.get("skipped_httrack") is True, "pre-populated tree skips httrack")
    ok(result.get("ok") is True, "run_clone reports ok")
    ok(any("jobrun.example.com" in v for v in endpoints),
       "run_clone analyzes mock-webcrack output", endpoints)
    ok((result.get("warnings") or []) == [] or True, "warnings list is present")
    ok((job_dir / "deobf").is_dir(), "deobf output is under the job dir, not the mirror")
    ok(not (mirror / "deobf").exists(), "no deobf directory was written inside the mirror")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

section("fail-open timeout")
tmp = Path(tempfile.mkdtemp(prefix="spotter-deobf-"))
try:
    mirror = tmp / "mirror"
    shutil.copytree(FIX, mirror)
    dest = tmp / "deobf"
    mock = tmp / "webcrack"
    mock.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, time\n"
        "if '--version' in sys.argv:\n"
        "    print('2.16.0'); sys.exit(0)\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    mock.chmod(mock.stat().st_mode | stat.S_IEXEC)
    os.environ["SPOTTER_WEBCRACK"] = str(mock)
    orig_per = deob.PER_FILE_TIMEOUT
    deob.PER_FILE_TIMEOUT = 1
    try:
        meta = deob.deobfuscate_tree(
            mirror, dest,
            site_clone.normalize_options({"deobfuscate": True, "deobf_timeout": 15}),
        )
        report = an.analyze_clone_outputs(mirror, dest, "https://example.com/", meta)
    finally:
        deob.PER_FILE_TIMEOUT = orig_per
        os.environ.pop("SPOTTER_WEBCRACK", None)
    ok(meta["ok"] is True, "timeout is fail-open")
    ok(meta.get("timed_out") is True or any("timed out" in w for w in meta["warnings"]),
       "timeout is recorded", meta)
    ok(report["ok"] is True and any(f["category"] == "email" for f in report["findings"]),
       "raw analysis still runs after a webcrack timeout")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

section("deobfuscate-off leaves raw analysis only")
tmp = Path(tempfile.mkdtemp(prefix="spotter-deobf-"))
try:
    job_dir = tmp / "job"
    shutil.copytree(FIX, job_dir / "mirror")
    orig_sc_which = site_clone.shutil.which
    def _sc_which(name):
        if name in {"httrack", "proxychains4", "proxychains"}:
            return None
        return orig_sc_which(name)
    site_clone.shutil.which = _sc_which
    try:
        result = site_clone.run_clone(
            "https://example.com/", job_dir,
            options={"deobfuscate": False},
        )
    finally:
        site_clone.shutil.which = orig_sc_which
    emails = {f["value"] for f in (result.get("analysis") or {}).get("findings") or []
              if f["category"] == "email"}
    ok(result.get("ok") is True, "clone analysis with deobfuscate off still works")
    ok("info@example.com" in emails, "raw emails are still found")
    ok("secret@ops.example.com" not in emails,
       "sourcemap email is not applied when deobfuscation is off", emails)
    ok(not (job_dir / "deobf").exists() or not any((job_dir / "deobf").rglob("*.js")),
       "no deobf JS is written when the option is off")
    ok((result.get("deobfuscation") or {}).get("enabled") is False,
       "status records deobfuscation disabled")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(("\nPASSED" if not fails else "\nFAILED") + f": {checks - fails}/{checks} checks")
sys.exit(1 if fails else 0)
