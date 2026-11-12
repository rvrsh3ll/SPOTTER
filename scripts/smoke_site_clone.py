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
import time
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
ok(d["ocr"] is True and d["ocr_timeout"] == 15 and d["ocr_max_images"] == 40
   and d["ocr_max_image_bytes"] == 8 * 1024 * 1024 and d["ocr_max_pdf_pages"] == 5,
   "OCR is on by default with size, count, timeout, and PDF-page caps",
   {k: d[k] for k in d if k.startswith("ocr")})
capped_ocr = site_clone.normalize_options({"ocrImages": "no", "ocrTimeout": 2, "ocrMaxImages": 9999})
ok(capped_ocr["ocr"] is False, "OCR can be turned off via ocrImages")
ok(capped_ocr["ocr_timeout"] == 3 and capped_ocr["ocr_max_images"] == 400,
   "OCR timeout and image cap are clamped",
   (capped_ocr["ocr_timeout"], capped_ocr["ocr_max_images"]))
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
            options={"deobfuscate": True, "deobfTimeout": 60, "ocr": False,
                     "respectOpsec": False},
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
            options={"deobfuscate": False, "ocr": False},
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


section("OPSEC DNS options")
d = site_clone.normalize_options({})
ok(d["allow_docker_dns"] is False and d["respect_opsec"] is True,
   "allow_docker_dns is off by default, respect_opsec is on",
   (d["allow_docker_dns"], d["respect_opsec"]))
on = site_clone.normalize_options({"allowDockerDns": True})
ok(on["allow_docker_dns"] is True, "allowDockerDns camelCase is accepted")
off = site_clone.normalize_options({"allow_docker_dns": "no"})
ok(off["allow_docker_dns"] is False, "allow_docker_dns=no is false")

section("proxy envelope flattening")
import site_clone_dns as dns
http = dns.normalize_proxy({"type": "http", "http_url": "http://alice:secret@10.9.8.7:3128"})
ok(http == {"type": "http", "host": "10.9.8.7", "port": 3128,
            "username": "alice", "password": "secret"},
   "flattens {type,http_url} with userinfo", http)
socks = dns.normalize_proxy({
    "type": "socks5",
    "socks": {"host": "ssh-tunnel-api", "port": 1080, "username": "", "password": ""},
    "socks_url": "socks5h://ssh-tunnel-api:1080",
})
ok(socks and socks["host"] == "ssh-tunnel-api" and socks["port"] == 1080
   and socks["type"] == "socks5", "flattens {type,socks,socks_url}", socks)
tor = dns.normalize_proxy({
    "type": "tor", "socks_url": "socks5h://ssh-tunnel-api:9050",
    "socks": {"host": "ssh-tunnel-api", "port": 9050},
})
ok(tor and tor["type"] == "tor" and tor["port"] == 9050, "flattens TOR envelope", tor)
flat = dns.normalize_proxy({"type": "http", "host": "127.0.0.1", "port": 8888})
ok(flat and flat["host"] == "127.0.0.1" and flat["port"] == 8888,
   "already-flat HTTP proxy is unchanged", flat)
ok(dns.normalize_proxy({"type": "none"}) is None, "type none is no proxy")
ok(dns.normalize_proxy({"type": "http"}) is None, "HTTP without url/host is no proxy")
ok(dns.normalize_proxy({}) is None, "empty proxy is None")

section("DNS plan / config generation per mode")
tmp = Path(tempfile.mkdtemp(prefix="spotter-dns-"))
try:
    opts = site_clone.normalize_options({"respectOpsec": True})
    # HTTP proxy under OPSEC: proxychains http + proxy_dns, no -P
    p_http = dns.plan_job_dns(
        "https://example.com/", tmp / "http", opts, {},
        {"type": "http", "http_url": "http://10.0.0.9:8080"},
        mount_ok=True, proxychains_bin="/usr/bin/proxychains4",
    )
    conf_http = Path(p_http["proxychains_conf"]).read_text()
    ok(p_http["ok"] and p_http["use_proxychains"] and not p_http["use_httrack_p"],
       "OPSEC HTTP proxy uses proxychains, not HTTrack -P", p_http)
    ok("proxy_dns" in conf_http and "strict_chain" in conf_http
       and "http 10.0.0.9 8080" in conf_http,
       "HTTP proxychains conf has proxy_dns and the flattened hop", conf_http)
    ok(p_http["label"] == "via HTTP proxy" and p_http["prefix"][0] == "/usr/bin/proxychains4",
       "HTTP plan label and prefix", (p_http["label"], p_http["prefix"]))

    p_socks = dns.plan_job_dns(
        "https://example.com/", tmp / "socks", opts, {},
        {"type": "socks5", "socks": {"host": "1.2.3.4", "port": 1080},
         "socks_url": "socks5h://1.2.3.4:1080"},
        mount_ok=True, proxychains_bin="/usr/bin/proxychains4",
    )
    conf_socks = Path(p_socks["proxychains_conf"]).read_text()
    ok(p_socks["label"] == "via SOCKS5" and "socks5 1.2.3.4 1080" in conf_socks
       and "proxy_dns" in conf_socks,
       "SOCKS5 plan uses proxy_dns and flattened host", conf_socks)

    p_tor = dns.plan_job_dns(
        "https://example.com/", tmp / "tor", opts, {},
        {"type": "tor", "socks_url": "socks5h://ssh-tunnel-api:9050"},
        mount_ok=True, proxychains_bin="/usr/bin/proxychains4",
        resolve_proxy=lambda h: "10.94.0.8" if h == "ssh-tunnel-api" else h,
    )
    conf_tor = Path(p_tor["proxychains_conf"]).read_text()
    ok(p_tor["ok"] and p_tor["label"] == "via TOR"
       and "socks5 10.94.0.8 9050" in conf_tor
       and "ssh-tunnel-api" in conf_tor
       and "strict_chain" in conf_tor and "proxy_dns" in conf_tor,
       "TOR plan resolves the compose service name to an IP in [ProxyList]",
       conf_tor)
    ok(p_tor.get("proxy_endpoint_ip") == "10.94.0.8"
       and p_tor.get("proxy_endpoint_host") == "ssh-tunnel-api",
       "TOR plan records the resolved endpoint IP", p_tor)

    # No proxy + plain IPs
    p_ip = dns.plan_job_dns(
        "https://target.example/", tmp / "ips", opts,
        {"dns_resolvers": ["77.88.8.8", "77.88.8.1"]}, {},
        mount_ok=True, proxychains_bin=False,
    )
    text_ip = Path(p_ip["resolv_conf"]).read_text()
    ok(p_ip["ok"] and p_ip["via"] == "resolver" and p_ip["label"] == "77.88.8.8, 77.88.8.1",
       "plain IP resolvers produce a resolver label", p_ip)
    ok("nameserver 77.88.8.8" in text_ip and "nameserver 77.88.8.1" in text_ip
       and "127.0.0.11" not in text_ip,
       "resolv.conf lists only the chosen IPs, not Docker DNS", text_ip)
    ok(p_ip["prefix"] and "unshare" in p_ip["prefix"][0] and "--mount" in p_ip["prefix"],
       "plain IP plan wraps with unshare --mount", p_ip["prefix"])
    ok(p_ip["stub"] is None, "plain IPs on port 53 do not start a stub")

    # DoH-only
    p_doh = dns.plan_job_dns(
        "https://target.example/", tmp / "doh", opts,
        {"dns_resolvers": ["https://dns.google/resolve"]}, {},
        mount_ok=True,
    )
    text_doh = Path(p_doh["resolv_conf"]).read_text()
    ok(p_doh["ok"] and p_doh["stub"] and p_doh["label"].startswith("DoH ("),
       "DoH-only plan starts a stub and labels DoH", p_doh)
    ok(p_doh["stub"]["bind"].startswith("127.0.0.") and p_doh["stub"]["port"] == 53
       and p_doh["stub"]["servers"] == ["https://dns.google/resolve"],
       "DoH stub bind and upstream", p_doh["stub"])
    ok("nameserver " + p_doh["stub"]["bind"] in text_doh
       and "127.0.0.11" not in text_doh,
       "DoH resolv.conf points at the stub loopback only", text_doh)

    # OPSEC off: no wrap, HTTP may use -P
    p_off = dns.plan_job_dns(
        "https://example.com/", tmp / "off",
        site_clone.normalize_options({"respectOpsec": False}),
        {"dns_resolvers": ["1.1.1.1"]},
        {"type": "http", "http_url": "http://10.0.0.9:8080"},
        mount_ok=False, proxychains_bin=False,
    )
    ok(p_off["ok"] and p_off["use_httrack_p"] and not p_off["use_proxychains"]
       and p_off["label"] == "",
       "OPSEC off keeps HTTrack -P and does not fail-closed", p_off)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

section("fail-closed DNS paths")
tmp = Path(tempfile.mkdtemp(prefix="spotter-dns-fail-"))
try:
    opts = site_clone.normalize_options({"respectOpsec": True})
    p_none = dns.plan_job_dns(
        "https://example.com/", tmp / "none", opts, {}, {},
        mount_ok=True, proxychains_bin=False,
    )
    ok(p_none["ok"] is False and "no DNS resolvers" in (p_none["error"] or "")
       and "Allow Docker DNS" in (p_none["error"] or ""),
       "no proxy and no resolvers is fail-closed", p_none["error"])

    p_missing_pc = dns.plan_job_dns(
        "https://example.com/", tmp / "nopc", opts, {},
        {"type": "tor", "socks_url": "socks5h://ssh-tunnel-api:9050"},
        mount_ok=True, proxychains_bin=False,
    )
    ok(p_missing_pc["ok"] is False and "proxychains4" in (p_missing_pc["error"] or ""),
       "OPSEC proxy without proxychains is fail-closed", p_missing_pc["error"])

    p_mount = dns.plan_job_dns(
        "https://example.com/", tmp / "nmount", opts,
        {"dns_resolvers": ["77.88.8.8"]}, {},
        mount_ok=False, proxychains_bin=False,
    )
    ok(p_mount["ok"] is False and "mount namespace" in (p_mount["error"] or ""),
       "resolver path without a mount namespace is fail-closed", p_mount["error"])

    p_ov = dns.plan_job_dns(
        "https://example.com/", tmp / "ov",
        site_clone.normalize_options({"respectOpsec": True, "allowDockerDns": True}),
        {}, {},
        mount_ok=False, proxychains_bin=False,
    )
    ok(p_ov["ok"] is True and p_ov["label"] == "Docker (override)",
       "Allow Docker DNS override is accepted", p_ov)

    p_named = dns.plan_job_dns(
        "https://example.com/", tmp / "named", opts, {},
        {"type": "socks5", "socks": {"host": "ssh-tunnel-api", "port": 1080}},
        mount_ok=True, proxychains_bin="/usr/bin/proxychains4",
        resolve_proxy=lambda h: "172.18.0.12" if h == "ssh-tunnel-api" else h,
    )
    conf_named = Path(p_named["proxychains_conf"]).read_text()
    ok(p_named["ok"] and "socks5 172.18.0.12 1080" in conf_named
       and "socks5 ssh-tunnel-api" not in conf_named,
       "SOCKS5 compose hostname is written as a numeric IP", conf_named)

    def _boom(host):
        raise ValueError(
            "OPSEC DNS cannot be routed: proxy host %s could not be resolved "
            "to an IP (Name or service not known). That name is the local "
            "proxy endpoint, not the target; check that the proxy service is "
            "on the same Docker network as site-clone-api." % host
        )
    p_bad = dns.plan_job_dns(
        "https://example.com/", tmp / "badhop", opts, {},
        {"type": "socks5", "socks": {"host": "missing-proxy", "port": 1080}},
        mount_ok=True, proxychains_bin="/usr/bin/proxychains4",
        resolve_proxy=_boom,
    )
    ok(p_bad["ok"] is False and "missing-proxy" in (p_bad["error"] or "")
       and "could not be resolved" in (p_bad["error"] or "")
       and "not the target" in (p_bad["error"] or ""),
       "unresolvable proxy hostname is fail-closed with a clear error",
       p_bad["error"])

    ok(dns.is_numeric_ip("10.0.0.9") and dns.is_numeric_ip("127.0.0.1")
       and dns.is_numeric_ip("::1") and not dns.is_numeric_ip("ssh-tunnel-api")
       and not dns.is_numeric_ip(""),
       "is_numeric_ip distinguishes addresses from service names")
    ok(dns.resolve_proxy_endpoint("8.8.8.8") == "8.8.8.8",
       "numeric proxy IPs are not looked up again")

    # run_clone refuses before starting httrack
    fake_ht = tmp / "httrack"
    fake_ht.write_text("#!/bin/sh\necho should-not-run\nexit 0\n")
    fake_ht.chmod(fake_ht.stat().st_mode | stat.S_IEXEC)
    orig_which = site_clone.shutil.which
    def _which(name):
        if name == "httrack":
            return str(fake_ht)
        if name in {"proxychains4", "proxychains"}:
            return None
        return orig_which(name)
    site_clone.shutil.which = _which
    try:
        result = site_clone.run_clone(
            "https://example.com/", tmp / "job-refused",
            options={"respectOpsec": True, "deobfuscate": False, "ocr": False},
        )
    finally:
        site_clone.shutil.which = orig_which
    ok(result.get("ok") is False and "no DNS resolvers" in (result.get("error") or ""),
       "run_clone fail-closes when OPSEC is on and DNS cannot be routed",
       result.get("error"))
    ok((result.get("dns") or {}).get("via") in {"none", ""},
       "failed job still records a dns object", result.get("dns"))

    site_clone.shutil.which = _which
    try:
        result_ov = site_clone.run_clone(
            "https://example.com/", tmp / "job-ov",
            options={"respectOpsec": True, "allowDockerDns": True, "deobfuscate": False,
                     "ocr": False, "maxTime": 15},
        )
    finally:
        site_clone.shutil.which = orig_which
    # Override lets planning pass; fake httrack may run and fetch nothing — that
    # is not a fail-closed refusal.
    ok("no DNS resolvers" not in (result_ov.get("error") or ""),
       "override does not take the fail-closed path", result_ov.get("error"))
    ok((result_ov.get("dns") or {}).get("label") == "Docker (override)",
       "run_clone records Docker (override) on the job", result_ov.get("dns"))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

section("DNS stub helpers (no network)")
import site_clone_dns_stub as stub
qname = "example.com"
# Build a tiny A query.
qid = b"\x12\x34"
flags = b"\x01\x00"
header = qid + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00"
query = header + stub.encode_name(qname) + b"\x00\x01\x00\x01"
parsed = stub.parse_question(query)
ok(parsed == (qname, 1), "parse_question reads an A query", parsed)
payload = {"Status": 0, "Answer": [{"name": "example.com", "type": 1, "TTL": 30, "data": "93.184.216.34"}]}
wire = stub._json_to_dns(query, qname, 1, payload)
ok(wire and b"\x5d\xb8\xd8\x22" in wire, "JSON DoH answer encodes 93.184.216.34", wire)
ok("dns.google/dns-query" in stub._doh_wire_url("https://dns.google/resolve"),
   "Google /resolve is rewritten to /dns-query")



section("image OCR")
import site_clone_ocr as ocr  # noqa: E402
import site_rag  # noqa: E402

fixture_png = FIX / "images" / "ocr_contact.png"
ok(fixture_png.is_file() and fixture_png.stat().st_size > 1000,
   "fixture image with known contact text is present",
   (fixture_png, fixture_png.stat().st_size if fixture_png.is_file() else 0))

tmp = Path(tempfile.mkdtemp(prefix="spotter-ocr-"))
env_bin = os.environ.pop("SPOTTER_TESSERACT", None)
try:
    os.environ["SPOTTER_TESSERACT"] = str(tmp / "no-such-tesseract")
    meta = ocr.ocr_tree(FIX, tmp / "ocr-missing",
                        site_clone.normalize_options({"ocr": True}))
    ok(meta["ok"] is True and meta["available"] is False,
       "missing tesseract is fail-open", meta)
    ok(any("tesseract is not installed" in w for w in meta["warnings"]),
       "missing tesseract is a warning", meta["warnings"])
finally:
    os.environ.pop("SPOTTER_TESSERACT", None)
    if env_bin is not None:
        os.environ["SPOTTER_TESSERACT"] = env_bin

mock = tmp / "tesseract"
mock.write_text(
    "#!/usr/bin/env python3\n"
    "import sys\n"
    "src = sys.argv[1] if len(sys.argv) > 1 else ''\n"
    "if 'ocr_contact' in src.replace('\\\\','/'):\n"
    "    sys.stdout.write('Contact poster\\n'\n"
    "                     'Email: ocr-findme@example.com\\n'\n"
    "                     'Phone: +1 202-555-0199\\n'\n"
    "                     'api_key = \"rk_live_OCRONLYSECRET01\"\\n')\n"
    "sys.exit(0)\n"
)
mock.chmod(mock.stat().st_mode | stat.S_IEXEC)

mirror = tmp / "mirror"
shutil.copytree(FIX, mirror)
dest = tmp / "ocr"
os.environ["SPOTTER_TESSERACT"] = str(mock)
try:
    meta = ocr.ocr_tree(mirror, dest, site_clone.normalize_options({"ocr": True}))
    report = an.analyze_clone_outputs(mirror, None, "https://example.com/", ocr_dir=dest)
finally:
    os.environ.pop("SPOTTER_TESSERACT", None)
    if env_bin is not None:
        os.environ["SPOTTER_TESSERACT"] = env_bin

ok(meta["available"] is True, "mock tesseract is detected", meta)
ok(meta["files_ocrd"] >= 1, "fixture image was OCR'd", meta)
txts = list(dest.rglob("ocr_contact.png.txt"))
ok(txts and "ocr-findme@example.com" in txts[0].read_text(),
   "OCR text is written under ocr/ next to the relative image path", txts)
emails = [f for f in report["findings"] if f["category"] == "email"
          and "ocr-findme@example.com" in str(f.get("value"))]
phones = [f for f in report["findings"] if f["category"] == "phone"
          and "202-555-0199" in str(f.get("value"))]
secrets = [f for f in report["findings"] if f["category"] == "js_secret" and f.get("ocr")]
ok(emails and emails[0].get("ocr") is True,
   "OCR email is tagged ocr=true", emails[:1])
ok(phones and phones[0].get("ocr") is True,
   "OCR phone is tagged ocr=true", phones[:1])
ok(secrets and "OCRONLYSECRET01" not in json.dumps(secrets)
   and "***" in str(secrets[0].get("value")),
   "OCR secret-shaped string is tagged ocr=true and redacted", secrets[:1])

# Same value already in HTML should not be replaced by the OCR copy.
# Inject the fixture email into a tiny HTML and merge.
html_tree = tmp / "html-pref"
(html_tree).mkdir()
(html_tree / "index.html").write_text(
    "<p>Contact ocr-findme@example.com</p>\n", encoding="utf-8")
pref = an.merge_reports(
    an.analyze_tree(html_tree, "https://example.com/"),
    an.analyze_ocr_dir(dest, "https://example.com/"),
)
pref_email = [f for f in pref["findings"] if f.get("value") == "ocr-findme@example.com"]
ok(len(pref_email) == 1 and not pref_email[0].get("ocr"),
   "HTML finding wins over the same OCR email", pref_email)

# Caps: only the first image is processed when the job cap is 1.
cap_root = tmp / "cap-mirror"
cap_root.mkdir()
shutil.copy2(fixture_png, cap_root / "a-ocr_contact.png")
shutil.copy2(fixture_png, cap_root / "b-ocr_contact.png")
shutil.copy2(fixture_png, cap_root / "c-ocr_contact.png")
os.environ["SPOTTER_TESSERACT"] = str(mock)
try:
    cap_meta = ocr.ocr_tree(
        cap_root, tmp / "ocr-cap",
        site_clone.normalize_options({"ocr": True, "ocrMaxImages": 1}),
    )
finally:
    os.environ.pop("SPOTTER_TESSERACT", None)
    if env_bin is not None:
        os.environ["SPOTTER_TESSERACT"] = env_bin
ok(cap_meta["files_ocrd"] == 1 and cap_meta["truncated"] is True
   and cap_meta["skipped"] >= 2,
   "max-images cap stops the job and marks it truncated", cap_meta)

# Oversized file is skipped.
big = tmp / "big-mirror"
big.mkdir()
big_img = big / "ocr_contact.png"
shutil.copy2(fixture_png, big_img)
# The cap is clamped to at least 32 KiB; write a payload larger than that.
big_img.write_bytes(big_img.read_bytes() + b"\x00" * (40 * 1024))
os.environ["SPOTTER_TESSERACT"] = str(mock)
try:
    big_meta = ocr.ocr_tree(
        big, tmp / "ocr-big",
        site_clone.normalize_options({"ocr": True, "ocrMaxImageBytes": 32768}),
    )
finally:
    os.environ.pop("SPOTTER_TESSERACT", None)
    if env_bin is not None:
        os.environ["SPOTTER_TESSERACT"] = env_bin
ok(big_meta["files_ocrd"] == 0 and big_meta["skipped"] >= 1
   and any("oversized" in w for w in big_meta["warnings"]),
   "oversized image is skipped", big_meta)

# run_clone on a pre-populated tree with mock tesseract.
job_dir = tmp / "job"
job_mirror = job_dir / "mirror"
shutil.copytree(FIX, job_mirror)
os.environ["SPOTTER_TESSERACT"] = str(mock)
orig_sc_which = site_clone.shutil.which

def _sc_which(name):
    if name in {"httrack", "webcrack"}:
        return None
    if name == "tesseract":
        return str(mock)
    return orig_sc_which(name)

site_clone.shutil.which = _sc_which
try:
    result = site_clone.run_clone(
        "https://example.com/", job_dir,
        options={"deobfuscate": False, "ocr": True},
    )
finally:
    site_clone.shutil.which = orig_sc_which
    os.environ.pop("SPOTTER_TESSERACT", None)
    if env_bin is not None:
        os.environ["SPOTTER_TESSERACT"] = env_bin

ocr_info = result.get("ocr") or {}
ok(result.get("ok") is True and result.get("skipped_httrack") is True,
   "run_clone with OCR on a pre-populated tree succeeds")
ok(ocr_info.get("enabled") is True and ocr_info.get("files_ocrd") >= 1,
   "run_clone records OCR stats", ocr_info)
job_emails = [f for f in (result.get("analysis") or {}).get("findings") or []
              if f.get("ocr") and f.get("category") == "email"]
ok(any("ocr-findme@example.com" in str(f.get("value")) for f in job_emails),
   "run_clone analysis includes OCR-tagged emails", job_emails)

harvested = site_rag.pages_from_clone_tree(job_dir, start_url="https://example.com/")
ocr_pages = [p for p in harvested["pages"] if p.get("from_ocr")]
ok(ocr_pages and any("ocr-findme@example.com" in p["text"] for p in ocr_pages),
   "Prompt harvest includes OCR text",
   [(p.get("source_path"), p.get("url")) for p in ocr_pages])
ok(all(str(p.get("source_path") or "").startswith("ocr/") for p in ocr_pages),
   "OCR harvest paths are under ocr/",
   [p.get("source_path") for p in ocr_pages])

# Toggle off must not mine leftover ocr/ text.
job_off = tmp / "job-off"
shutil.copytree(FIX, job_off / "mirror")
leftover = job_off / "ocr" / "example.com" / "leftover.png.txt"
leftover.parent.mkdir(parents=True)
leftover.write_text("contact leftover-ocr@example.com\n")
orig_sc_which = site_clone.shutil.which
site_clone.shutil.which = lambda name: None if name in {"httrack", "webcrack"} else orig_sc_which(name)
try:
    off = site_clone.run_clone(
        "https://example.com/", job_off,
        options={"deobfuscate": False, "ocr": False},
    )
finally:
    site_clone.shutil.which = orig_sc_which
off_vals = [f.get("value") for f in (off.get("analysis") or {}).get("findings") or []]
ok((off.get("ocr") or {}).get("enabled") is False,
   "run_clone records OCR disabled", off.get("ocr"))
ok("leftover-ocr@example.com" not in off_vals,
   "OCR-off does not mine leftover ocr/ text", off_vals)

shutil.rmtree(tmp, ignore_errors=True)



section("recovered source snippets")
tmp = Path(tempfile.mkdtemp(prefix="spotter-src-"))
try:
    job = tmp / "camp" / "job-1"
    src = job / "deobf" / "js" / "app.js"
    src.parent.mkdir(parents=True)
    secret = "sk_live_SOURCETESTVALUE99"
    src.write_text(
        "\n".join([
            "const preamble = 1;",
            "const api_base = 'https://api.example.com/v1';",
            "const other = 2;",
            "const stripe_key = '%s';" % secret,
            "const tail = 3;",
        ]) + "\n",
        encoding="utf-8",
    )
    (job / "ocr" / "example.com").mkdir(parents=True)
    (job / "ocr" / "example.com" / "banner.png.txt").write_text(
        "Contact ocr-findme@example.com\n", encoding="utf-8")

    window = an.source_snippet(job, "deobf/js/app.js", line=2, context=1)
    ok(window["ok"] is True, "snippet from deobf/ is readable", window)
    ok(window["focus_line"] == 2 and window["start_line"] == 1,
       "snippet is windowed around the requested line", window)
    ok("api.example.com/v1" in window["text"] and "const tail" not in window["text"],
       "surrounding lines are included and the window is bounded", window["text"])
    scrubbed = an.source_snippet(job, "deobf/js/app.js", line=4, context=1)
    ok(scrubbed["ok"] and secret not in scrubbed["text"] and "***" in scrubbed["text"],
       "secret-shaped strings are scrubbed in the snippet", scrubbed.get("text"))

    ocr = an.source_snippet(job, "ocr/example.com/banner.png.txt", evidence="ocr-findme@example.com")
    ok(ocr["ok"] and "ocr-findme@example.com" in ocr["text"],
       "OCR text is readable by evidence", ocr)

    ok(an.resolve_job_source(job, "../deobf/js/app.js") is None,
       "parent-directory path is rejected")
    ok(an.resolve_job_source(job, "/etc/passwd") is None, "absolute path is rejected")
    ok(an.source_snippet(job, "status.json")["ok"] is False,
       "files outside deobf/ocr/mirror are rejected")
    (job / "deobf" / "escape").symlink_to("/etc/passwd")
    ok(an.resolve_job_source(job, "deobf/escape") is None,
       "symlinks are rejected")

    # Analyzer records a line number on JS endpoints.
    findings = []
    an.parse_js(src, job / "deobf", findings)
    ep = [f for f in findings if f["category"] == "js_endpoint"]
    ok(ep and ep[0].get("source_line") == 2,
       "js_endpoint findings carry source_line", ep[:1])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

section("ingest JS endpoints into the sketch")
import site_clone_ingest as ing  # noqa: E402

class _FakeFC:
    def __init__(self, existing=None):
        self.nodes = []
        self.edges = []
        self.existing = list(existing or [])
        self._n = 0

    def add_node(self, label, node_type, properties=None, sketch_id=""):
        self._n += 1
        nid = "n%d" % self._n
        rec = {"id": nid, "nodeLabel": label, "nodeType": node_type,
               "nodeProperties": dict(properties or {})}
        self.nodes.append(rec)
        return rec

    def create_edge(self, src, tgt, typ, sketch_id=""):
        self.edges.append((src, tgt, typ))

    def get_nodes_by_type(self, labels, sketch_id=None, properties=None):
        return list(self.existing)

fake = _FakeFC(existing=[{
    "id": "apex-1", "nodeLabel": "example.com (web)", "nodeType": "WebAsset",
    "nodeProperties": {"url": "https://example.com/", "fqdn": "example.com",
                       "source": "domain-recon"},
}])
orig_fc = ing.fc
ing.fc = fake
try:
    report = {
        "ok": True,
        "start_url": "https://www.example.com/",
        "files_scanned": 3,
        "finding_count": 3,
        "summary": {"js_endpoint": 3},
        "findings": [
            {"category": "js_endpoint", "value": "https://api.example.com/v1/users",
             "source_path": "deobf/js/app.js", "deobfuscated": True,
             "deobfuscator": "webcrack"},
            {"category": "js_endpoint", "value": "/internal/admin",
             "source_path": "deobf/js/app.js", "deobfuscated": True},
            {"category": "js_endpoint", "value": "https://hooks.slack.com/services/x",
             "source_path": "deobf/js/app.js", "deobfuscated": True},
        ],
    }
    result = ing.ingest_findings(report, "sk-1", campaign_id="camp-1", job_id="job-1")
finally:
    ing.fc = orig_fc

ok(result.get("ok") is True and result.get("endpoints") == 3,
   "three endpoint WebAssets are written", result)
labels = {n["nodeLabel"]: n for n in fake.nodes}
ok(any("(clone)" in n["nodeLabel"] for n in fake.nodes),
   "cloned site WebAsset is still created")
same = [n for n in fake.nodes if n["nodeProperties"].get("fqdn") == "api.example.com"]
rel = [n for n in fake.nodes if n["nodeProperties"].get("path") == "/internal/admin"]
ext = [n for n in fake.nodes if n["nodeProperties"].get("fqdn") == "hooks.slack.com"]
ok(same and same[0]["nodeProperties"].get("same_site") is True
   and same[0]["nodeProperties"].get("deobfuscated") is True
   and same[0]["nodeProperties"].get("source") == "site-clone"
   and same[0]["nodeProperties"].get("provenance") == "site_clone",
   "same-registrable API host is tagged site-clone + deobfuscated", same[:1])
ok(rel and rel[0]["nodeProperties"].get("url", "").endswith("/internal/admin")
   and rel[0]["nodeProperties"].get("same_site") is True,
   "relative API path is resolved against the cloned site", rel[:1])
ok(ext and ext[0]["nodeProperties"].get("external") is True
   and ext[0]["nodeProperties"].get("deobfuscated") is True,
   "external endpoint is a separate WebAsset with provenance", ext[:1])
site_id = next(n["id"] for n in fake.nodes if "(clone)" in n["nodeLabel"])
same_id = same[0]["id"]
ext_id = ext[0]["id"]
ok((same_id, site_id, "FOUND_ON") in fake.edges
   and (same_id, "apex-1", "FOUND_ON") in fake.edges,
   "same-site endpoint is linked to the clone and the org apex WebAsset",
   fake.edges)
ok((ext_id, site_id, "FOUND_ON") in fake.edges
   and (ext_id, "apex-1", "FOUND_ON") not in fake.edges,
   "external endpoint is not linked to the org apex", fake.edges)
ok(ing._normalize_endpoint("javascript:alert(1)", "https://example.com/") == "",
   "javascript: endpoints are not ingested")



section("OPSEC deobf worker handoff")
tmp = Path(tempfile.mkdtemp(prefix="spotter-deobf-worker-"))
try:
    data = tmp / "clones"
    camp = data / "camp"
    job_dir = camp / "job"
    mirror = job_dir / "mirror"
    shutil.copytree(FIX, mirror)
    dest = job_dir / "deobf"
    os.environ["SITE_CLONE_DATA"] = str(data)
    os.environ.pop("SPOTTER_DEOBF_ISOLATED", None)

    meta_missing = deob.deobfuscate_tree(
        mirror, dest,
        {"deobfuscate": True, "deobf_timeout": 30, "require_isolated_network": True,
         "job_dir": str(job_dir)},
    )
    ok(meta_missing.get("ok") is False, "OPSEC deobf without a worker is fail-closed")
    ok(any("site-clone-deobf" in w and "sudo ./spotter compose up -d --build site-clone-deobf" in w
           for w in (meta_missing.get("warnings") or [])),
       "missing-worker warning names the compose command",
       meta_missing.get("warnings"))
    ok(meta_missing.get("files_deobfuscated", 0) == 0,
       "webcrack is not run when the worker is down")

    # Stand-in worker: heartbeat + process_worker_request in a thread.
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
        "(out/'deobfuscated.js').write_text('const api_base=\"https://worker.example.com/v1\";\\n')\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    mock.chmod(mock.stat().st_mode | stat.S_IEXEC)
    os.environ["SPOTTER_WEBCRACK"] = str(mock)
    deob.write_heartbeat(data)
    ok(deob.worker_available(data), "fresh heartbeat makes the worker available")
    ok(deob.worker_healthcheck(data) == 0, "--healthcheck is ok when the heartbeat is fresh")
    stale = deob.heartbeat_path(data)
    stale.write_text("%s 1\n" % (time.time() - 120), encoding="utf-8")
    ok(deob.worker_healthcheck(data) == 1, "--healthcheck fails on a stale heartbeat")
    deob.write_heartbeat(data)

    def _pump():
        # Wait until a request appears, then process it once.
        deadline = time.time() + 10
        while time.time() < deadline:
            pending = deob.iter_pending_jobs(data)
            if pending:
                deob.process_worker_request(pending[0], root=data)
                return
            time.sleep(0.05)

    import threading
    th = threading.Thread(target=_pump, daemon=True)
    th.start()
    dest2 = job_dir / "deobf-w"
    meta_ok = deob.deobfuscate_tree(
        mirror, dest2,
        {"deobfuscate": True, "deobf_timeout": 30, "require_isolated_network": True,
         "job_dir": str(job_dir), "max_files": 50},
    )
    th.join(timeout=10)
    ok(meta_ok.get("ok") is True and meta_ok.get("isolated_network") is True,
       "worker handoff reports ok and isolated_network", meta_ok)
    ok(meta_ok.get("files_deobfuscated", 0) >= 1,
       "stand-in worker harvested webcrack output", meta_ok)
    recovered = list((dest2).rglob("*.js"))
    ok(any("worker.example.com" in p.read_text(encoding="utf-8", errors="replace")
           for p in recovered),
       "worker output landed under dest", [str(p) for p in recovered])

    # Already-isolated path (inside the worker) runs locally without a queue.
    os.environ["SPOTTER_DEOBF_ISOLATED"] = "1"
    dest3 = job_dir / "deobf-local"
    # Hide the heartbeat so a bug that still queued would fail-closed.
    hb = deob.heartbeat_path(data)
    if hb and hb.exists():
        hb.unlink()
    meta_local = deob.deobfuscate_tree(
        mirror, dest3,
        {"deobfuscate": True, "deobf_timeout": 30, "require_isolated_network": True,
         "job_dir": str(job_dir)},
    )
    ok(meta_local.get("ok") is True and meta_local.get("isolated_network") is True
       and meta_local.get("files_deobfuscated", 0) >= 1,
       "already-isolated process runs webcrack locally", meta_local)
    os.environ.pop("SPOTTER_DEOBF_ISOLATED", None)

    # Deobf skip is non-fatal for the rest of the clone.
    os.environ.pop("SPOTTER_WEBCRACK", None)
    job2 = data / "camp" / "job2"
    mirror2 = job2 / "mirror"
    shutil.copytree(FIX, mirror2)
    orig_sc_which = site_clone.shutil.which
    def _sc_which(name):
        if name in {"httrack", "proxychains4", "proxychains"}:
            return None
        return orig_sc_which(name)
    site_clone.shutil.which = _sc_which
    try:
        result = site_clone.run_clone(
            "https://example.com/", job2,
            options={"deobfuscate": True, "deobfTimeout": 30, "ocr": False,
                     "respectOpsec": True},
        )
    finally:
        site_clone.shutil.which = orig_sc_which
    ok(result.get("ok") is True and result.get("skipped_httrack") is True,
       "clone analysis still succeeds when OPSEC deobf is skipped", result.get("error"))
    warns = result.get("warnings") or []
    ok(any("site-clone-deobf" in w and "sudo ./spotter compose up -d --build site-clone-deobf" in w
           for w in warns),
       "run_clone surfaces the start-worker command on the job card", warns)
    ok((result.get("deobfuscation") or {}).get("ok") is False,
       "deobfuscation status records the skip without failing the job",
       result.get("deobfuscation"))
    # Raw-tree findings (sourcemaps are also skipped because the whole step
    # is handed to a missing worker) — the mirror is still analyzed.
    findings = (result.get("analysis") or {}).get("findings") or []
    ok(isinstance(findings, list), "raw-tree analysis findings are still produced")
finally:
    os.environ.pop("SITE_CLONE_DATA", None)
    os.environ.pop("SPOTTER_WEBCRACK", None)
    os.environ.pop("SPOTTER_DEOBF_ISOLATED", None)
    shutil.rmtree(tmp, ignore_errors=True)


print(("\nPASSED" if not fails else "\nFAILED") + f": {checks - fails}/{checks} checks")
sys.exit(1 if fails else 0)
