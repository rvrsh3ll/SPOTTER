#!/usr/bin/env python3
"""Run HTTrack with operator caps and the campaign OPSEC envelope, then analyze.

Intended to run inside the site-clone-api container (Debian + httrack), or
anywhere `httrack` is on PATH. Never prints secrets. Only http(s) start URLs
are accepted.

HTTrack flags used (see httrack --help):
  -r N            max recursion depth
  -%e N           external depth (0 = stay on start host)
  -s0 / -s2       ignore / follow robots.txt
  -T N            I/O timeout seconds
  --max-time N    overall job time
  -M N            max mirror size in bytes
  -#N             max number of files (when supported)
  -F UA           User-Agent
  -P host:port    HTTP proxy (OPSEC off only; bookworm HTTrack 3.49.4
                  leaks HTTPS DNS/connect with -P, so OPSEC uses proxychains4)
  -%f             keep original filenames
SOCKS/TOR and OPSEC HTTP proxies are applied via proxychains4 with proxy_dns.
OPSEC DNS routing (per-job resolv.conf, DoH stub, fail-closed policy) lives in
site_clone_dns.py; see that module's docstring for the per-mode table.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from site_clone_analyze import analyze_clone_outputs
from site_clone_deobfuscate import deobfuscate_tree
from site_clone_dns import (
    normalize_proxy,
    plan_job_dns,
    preflight_resolve,
    public_dns,
    start_stub,
    stop_stub,
    write_proxychains_conf,
)
from site_clone_ocr import ocr_tree

DEFAULTS = {
    "max_depth": 2,
    "connect_timeout": 20,
    "max_time": 300,
    "max_bytes": 100 * 1024 * 1024,
    "max_files": 2000,
    "same_host": True,
    "robots": True,
    "include_images": True,
    "include_js": True,
    "include_css": True,
    "include_other": True,
    "external": "none",  # none | same_registrable | all
    "respect_opsec": True,
    "allow_docker_dns": False,
    "deobfuscate": True,
    "deobf_timeout": 180,
    "ocr": True,
    "ocr_timeout": 15,
    "ocr_max_images": 40,
    "ocr_max_image_bytes": 8 * 1024 * 1024,
    "ocr_max_pdf_pages": 5,
}

ALLOWED_SCHEMES = {"http", "https"}
SAFE_JOB = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
MAX_URL = 2048


def sanitize_url(url: str) -> str:
    url = (url or "").strip()
    if not url or len(url) > MAX_URL:
        raise ValueError("URL is empty or too long")
    scheme_m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", url)
    if scheme_m and scheme_m.group(1).lower() not in ALLOWED_SCHEMES:
        raise ValueError("only http and https URLs can be cloned")
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    if p.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("only http and https URLs can be cloned")
    if not p.netloc or p.netloc.startswith("."):
        raise ValueError("URL has no host")
    host = p.hostname or ""
    # Block obviously local/metadata targets; operator can still clone a LAN
    # host if they use a real hostname.
    if host.lower() in {"169.254.169.254", "metadata.google.internal"}:
        raise ValueError("that host is not allowed")
    return p.geturl()


def _int(v: Any, default: int, lo: int, hi: int) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        n = default
    return max(lo, min(hi, n))


def _bool(v: Any, default: bool) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "on"}
    if v is None:
        return default
    return bool(v)


def normalize_options(opts: dict[str, Any] | None) -> dict[str, Any]:
    o = dict(DEFAULTS)
    src = opts or {}
    # Accept both snake_case (API) and camelCase (frontend).
    aliases = {
        "max_depth": ("maxDepth", "max_depth"),
        "connect_timeout": ("connectTimeout", "connect_timeout"),
        "max_time": ("maxTime", "max_time"),
        "max_bytes": ("maxBytes", "max_bytes"),
        "max_files": ("maxFiles", "max_files"),
        "same_host": ("sameHost", "same_host"),
        "robots": ("robots", "followRobots", "follow_robots"),
        "include_images": ("includeImages", "include_images"),
        "include_js": ("includeJs", "include_js"),
        "include_css": ("includeCss", "include_css"),
        "include_other": ("includeOther", "include_other"),
        "external": ("external",),
        "respect_opsec": ("respectOpsec", "respect_opsec"),
        "allow_docker_dns": ("allowDockerDns", "allow_docker_dns",
                             "allowDockerDNS"),
        "deobfuscate": ("deobfuscate", "deobfuscateJs", "deobfuscate_js",
                        "deobfuscateJavascript"),
        "deobf_timeout": ("deobfTimeout", "deobfuscateTimeout", "deobf_timeout",
                          "deobfuscate_timeout"),
        "ocr": ("ocr", "ocrImages", "ocr_images"),
        "ocr_timeout": ("ocrTimeout", "ocr_timeout"),
        "ocr_max_images": ("ocrMaxImages", "ocr_max_images"),
        "ocr_max_image_bytes": ("ocrMaxImageBytes", "ocr_max_image_bytes"),
        "ocr_max_pdf_pages": ("ocrMaxPdfPages", "ocr_max_pdf_pages"),
    }
    for key, names in aliases.items():
        for n in names:
            if n in src and src[n] is not None:
                o[key] = src[n]
                break
    o["max_depth"] = _int(o["max_depth"], 2, 0, 8)
    o["connect_timeout"] = _int(o["connect_timeout"], 20, 3, 120)
    o["max_time"] = _int(o["max_time"], 300, 15, 3600)
    o["max_bytes"] = _int(o["max_bytes"], DEFAULTS["max_bytes"], 1024 * 1024, 2 * 1024 * 1024 * 1024)
    o["max_files"] = _int(o["max_files"], 2000, 10, 20000)
    o["same_host"] = _bool(o["same_host"], True)
    o["robots"] = _bool(o["robots"], True)
    for k in ("include_images", "include_js", "include_css", "include_other",
              "respect_opsec", "deobfuscate", "ocr"):
        o[k] = _bool(o[k], True)
    o["allow_docker_dns"] = _bool(o["allow_docker_dns"], False)
    o["deobf_timeout"] = _int(o["deobf_timeout"], 180, 15, 1800)
    o["ocr_timeout"] = _int(o["ocr_timeout"], 15, 3, 120)
    o["ocr_max_images"] = _int(o["ocr_max_images"], 40, 1, 400)
    o["ocr_max_image_bytes"] = _int(
        o["ocr_max_image_bytes"], 8 * 1024 * 1024, 32_768, 64 * 1024 * 1024)
    o["ocr_max_pdf_pages"] = _int(o["ocr_max_pdf_pages"], 5, 1, 20)
    ext = str(o.get("external") or "none").lower().replace("-", "_")
    if ext not in {"none", "same_registrable", "all"}:
        ext = "none"
    o["external"] = ext
    return o


def _registrable(host: str) -> str:
    parts = (host or "").lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def build_httrack_argv(url: str, out_dir: Path, options: dict[str, Any],
                       user_agent: str = "", proxy: dict[str, Any] | None = None) -> list[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    argv = [
        "httrack", url,
        "-O", str(out_dir),
        "-r", str(options["max_depth"]),
        "-T", str(options["connect_timeout"]),
        "--max-time", str(options["max_time"]),
        "-M", str(options["max_bytes"]),
        "-s2" if options["robots"] else "-s0",
        "-c8",
        "-q",
        "-%f",
        "--disable-security-limits",
    ]
    # File cap: newer HTTrack accepts -#N as "maximum number of connections" in
    # some builds and --max-files in others. We also enforce it after the run.
    argv += ["--max-files", str(options["max_files"])]

    if options["same_host"] and options["external"] == "none":
        argv += ["-%e", "0"]
    elif options["external"] == "same_registrable":
        host = urlparse(url).hostname or ""
        root = _registrable(host)
        if root:
            argv += ["-%e", "1", "+*." + root + "/*"]
        else:
            argv += ["-%e", "0"]
    else:
        argv += ["-%e", "1"]

    # Exclude classes the operator turned off. HTTrack filters are suffix-based.
    if not options["include_images"]:
        argv += ["-*.png", "-*.jpg", "-*.jpeg", "-*.gif", "-*.webp", "-*.svg", "-*.ico", "-*.bmp"]
    if not options["include_js"]:
        argv += ["-*.js", "-*.mjs", "-*.map"]
    if not options["include_css"]:
        argv += ["-*.css"]
    if not options["include_other"]:
        argv += ["-*.pdf", "-*.doc", "-*.docx", "-*.xls", "-*.xlsx", "-*.zip", "-*.mp4", "-*.mp3"]

    ua = (user_agent or "").strip()[:256]
    if ua:
        argv += ["-F", ua]

    if proxy and proxy.get("host"):
        typ = str(proxy.get("type") or "http").lower()
        if typ in {"http", "https"}:
            auth = ""
            if proxy.get("username"):
                # HTTrack's -P is host:port; credentials go via http://user:pass@host:port
                # in some builds. Prefer the URL form when creds exist.
                user = str(proxy.get("username") or "")
                pw = str(proxy.get("password") or "")
                hostport = "%s:%s" % (proxy["host"], int(proxy.get("port") or 8080))
                argv += ["-P", ("%s:%s@%s" % (user, pw, hostport)) if user else hostport]
            else:
                argv += ["-P", "%s:%s" % (proxy["host"], int(proxy.get("port") or 8080))]
    return argv


def _socks_proxy(proxy: dict[str, Any] | None) -> dict[str, Any] | None:
    """Back-compat helper: flatten then keep SOCKS/TOR only."""
    flat = normalize_proxy(proxy)
    if flat and flat["type"] in {"socks5", "tor"}:
        return flat
    return None


def _write_proxychains_conf(job_dir: Path, proxy: dict[str, Any]) -> Path:
    return write_proxychains_conf(job_dir, normalize_proxy(proxy) or proxy)


def count_tree_files(root: Path) -> tuple[int, int]:
    n, b = 0, 0
    if not root.is_dir():
        return 0, 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "hts-cache"]
        for name in filenames:
            if name.startswith("hts-"):
                continue
            p = Path(dirpath) / name
            try:
                st = p.stat()
            except OSError:
                continue
            n += 1
            b += st.st_size
    return n, b



def _public_ocr(ocr_meta: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "ok", "enabled", "available", "engine", "version", "lang",
        "files_considered", "files_ocrd", "pages_ocrd", "skipped",
        "timed_out", "truncated", "caps",
    )
    return {k: ocr_meta[k] for k in keys if k in ocr_meta}


def _analyze_job(
    url: str,
    job_dir: Path,
    mirror: Path,
    options: dict[str, Any],
    progress_cb: Any = None,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Deobfuscate JS, OCR images, then analyze the raw and recovered trees."""
    warnings: list[str] = []
    deobf_dir = job_dir / "deobf"
    deobf_meta: dict[str, Any] = {
        "ok": True, "enabled": bool(options.get("deobfuscate")),
        "available": False, "tool": "webcrack", "version": "",
        "warnings": [],
    }
    if options.get("deobfuscate"):
        deobf_opts = dict(options)
        # Under OPSEC, webcrack must not have the container network. Isolation
        # is required; if unshare is denied the step is skipped (fail-closed).
        deobf_opts["require_isolated_network"] = bool(options.get("respect_opsec"))
        deobf_meta = deobfuscate_tree(mirror, deobf_dir, deobf_opts, progress_cb=progress_cb)
        warnings.extend(deobf_meta.get("warnings") or [])
    elif deobf_dir.exists():
        # A previous run may have left files; do not reuse them if the
        # operator turned deobfuscation off for this job.
        deobf_dir = None  # type: ignore[assignment]
    ocr_dir = job_dir / "ocr"
    ocr_meta: dict[str, Any] = {
        "ok": True, "enabled": bool(options.get("ocr")),
        "available": False, "engine": "tesseract", "version": "",
        "warnings": [],
    }
    if options.get("ocr"):
        ocr_meta = ocr_tree(mirror, ocr_dir, options, progress_cb=progress_cb)
        warnings.extend(ocr_meta.get("warnings") or [])
    elif ocr_dir.exists():
        # A previous run may have left text; do not mine it if OCR is off.
        ocr_dir = None  # type: ignore[assignment]
    report = analyze_clone_outputs(
        mirror,
        deobf_dir if options.get("deobfuscate") and deobf_dir and deobf_dir.is_dir() else None,
        url,
        deobf_meta if options.get("deobfuscate") else None,
        ocr_dir if options.get("ocr") and ocr_dir and ocr_dir.is_dir() else None,
    )
    report["deobfuscation"] = {k: deobf_meta.get(k) for k in (
        "ok", "enabled", "available", "tool", "version", "pinned",
        "files_considered", "files_deobfuscated", "files_unpacked",
        "sourcemaps_applied", "skipped", "timed_out", "isolated_network",
    ) if k in deobf_meta or k in {"ok", "enabled", "available", "tool", "version"}}
    report["ocr"] = _public_ocr(ocr_meta)
    report["warnings"] = warnings
    return report, deobf_meta, warnings


def run_clone(
    url: str,
    job_dir: str | Path,
    options: dict[str, Any] | None = None,
    opsec: dict[str, Any] | None = None,
    proxy: dict[str, Any] | None = None,
    progress_cb: Any = None,
) -> dict[str, Any]:
    """Execute HTTrack, analyze the tree, return a job result dict (no secrets)."""
    url = sanitize_url(url)
    options = normalize_options(options)
    job_dir = Path(job_dir)
    mirror = job_dir / "mirror"
    mirror.mkdir(parents=True, exist_ok=True)
    log_path = job_dir / "httrack.log"

    ua = ""
    if options["respect_opsec"] and opsec:
        ua = str(opsec.get("user_agent") or "")

    httrack = shutil.which("httrack")
    pre_populated = mirror.exists() and any(mirror.iterdir())
    if not httrack:
        # Still analyze if a tree was pre-populated (unit tests, retries).
        # No live lookups happen, so the OPSEC DNS policy is not applied.
        if pre_populated:
            report, deobf_meta, warnings = _analyze_job(url, job_dir, mirror, options, progress_cb)
            return {
                "ok": True, "url": url, "skipped_httrack": True,
                "analysis": report, "deobfuscation": report.get("deobfuscation") or deobf_meta,
                "ocr": report.get("ocr") or {},
                "warnings": warnings,
                "options": {k: options[k] for k in DEFAULTS},
            }
        return {"ok": False, "error": "httrack is not installed in this container", "url": url}

    plan = plan_job_dns(url, job_dir, options, opsec, proxy)
    dns = public_dns(plan)
    if progress_cb:
        try:
            progress_cb({"stage": "dns", "dns": dns})
        except Exception:
            pass
    if not plan.get("ok"):
        return {
            "ok": False,
            "error": plan.get("error") or "OPSEC DNS cannot be routed",
            "url": url,
            "options": {k: options[k] for k in DEFAULTS},
            "dns": dns,
        }

    # Under OPSEC, HTTP proxies go through proxychains (proxy_dns), not HTTrack
    # -P: bookworm's HTTrack 3.49.4 still resolves and dials HTTPS origins itself.
    argv_proxy = plan.get("proxy") if plan.get("use_httrack_p") else None
    argv = build_httrack_argv(url, mirror, options, user_agent=ua, proxy=argv_proxy)

    env = os.environ.copy()
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    env.pop("ALL_PROXY", None)
    env.pop("http_proxy", None)
    env.pop("https_proxy", None)
    env.pop("all_proxy", None)
    # Don't leak proxy credentials into the child environment beyond proxychains conf.

    stub_proc = None
    started = time.time()
    try:
        if plan.get("stub"):
            try:
                stub_proc = start_stub(plan["stub"], user_agent=ua)
            except RuntimeError as e:
                err = (
                    "OPSEC DNS cannot be routed: the local DoH/DNS stub failed to start "
                    "(%s). Enable Allow Docker DNS (leaks lookups) or fix the "
                    "configured resolvers."
                ) % (str(e)[:200],)
                dns = public_dns(plan, preflight_ok=False, preflight_error=str(e)[:240])
                return {
                    "ok": False, "error": err, "url": url,
                    "options": {k: options[k] for k in DEFAULTS},
                    "dns": dns,
                }

        ok_pf, answers, pf_err = preflight_resolve(plan.get("host") or "", plan.get("prefix") or [], env=env)
        dns = public_dns(plan, answers=answers, preflight_ok=ok_pf, preflight_error=pf_err)
        if progress_cb:
            try:
                progress_cb({"stage": "dns", "dns": dns, "files": 0, "bytes": 0,
                             "elapsed": int(time.time() - started)})
            except Exception:
                pass

        cmd = list(plan.get("prefix") or []) + argv
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(job_dir), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=env, start_new_session=True,
            )
        except FileNotFoundError:
            return {
                "ok": False, "error": "httrack is not installed in this container",
                "url": url, "dns": dns,
            }

        output_chunks: list[bytes] = []
        timed_out = False
        try:
            deadline = started + options["max_time"] + 15
            while True:
                if proc.poll() is not None:
                    rest = proc.stdout.read() if proc.stdout else b""
                    if rest:
                        output_chunks.append(rest)
                    break
                if time.time() > deadline:
                    timed_out = True
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                        time.sleep(2)
                        os.killpg(proc.pid, signal.SIGKILL)
                    except OSError:
                        proc.kill()
                    break
                line = proc.stdout.readline() if proc.stdout else b""
                if line:
                    output_chunks.append(line)
                files, nbytes = count_tree_files(mirror)
                if progress_cb:
                    try:
                        progress_cb({
                            "files": files, "bytes": nbytes,
                            "elapsed": int(time.time() - started),
                            "dns": dns,
                        })
                    except Exception:
                        pass
                if files > options["max_files"] or nbytes > options["max_bytes"]:
                    timed_out = True
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except OSError:
                        proc.kill()
                    break
                if not line:
                    time.sleep(0.4)
        finally:
            try:
                log_path.write_bytes(b"".join(output_chunks)[-200_000:])
            except OSError:
                pass

        files, nbytes = count_tree_files(mirror)
        report, deobf_meta, warnings = _analyze_job(url, job_dir, mirror, options, progress_cb)
        if pf_err:
            warnings = list(warnings or []) + ["DNS preflight: " + pf_err]
        return {
            "ok": report.get("ok", False) and files > 0,
            "url": url,
            "options": {k: options[k] for k in DEFAULTS},
            "exit_code": proc.returncode,
            "timed_out": timed_out,
            "files": files,
            "bytes": nbytes,
            "elapsed_seconds": round(time.time() - started, 1),
            "analysis": report,
            "deobfuscation": report.get("deobfuscation") or deobf_meta,
            "ocr": report.get("ocr") or {},
            "warnings": warnings,
            "dns": dns,
            "error": (None if files > 0 else
                      ("clone timed out or hit a cap" if timed_out else
                       "HTTrack fetched no files")),
        }
    finally:
        if stub_proc is not None:
            stop_stub(stub_proc, plan.get("stub"))
