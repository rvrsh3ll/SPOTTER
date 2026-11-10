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
  -P host:port    HTTP proxy
  -%f             keep original filenames
SOCKS/TOR proxies are applied via proxychains4 when that binary is present.
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

from site_clone_analyze import analyze_tree

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
    for k in ("include_images", "include_js", "include_css", "include_other", "respect_opsec"):
        o[k] = _bool(o[k], True)
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
    if not proxy:
        return None
    typ = str(proxy.get("type") or "").lower()
    if typ in {"socks5", "socks5h", "socks", "tor"} and proxy.get("host"):
        return proxy
    return None


def _write_proxychains_conf(job_dir: Path, proxy: dict[str, Any]) -> Path:
    path = job_dir / "proxychains.conf"
    typ = str(proxy.get("type") or "socks5").lower()
    # tor and socks5h both go through SOCKS5; remote DNS is the proxychains default
    # when proxy_dns is set.
    kind = "socks5"
    if typ in {"http", "https"}:
        kind = "http"
    port = int(proxy.get("port") or (9050 if typ == "tor" else 1080))
    user = str(proxy.get("username") or "")
    pw = str(proxy.get("password") or "")
    extra = (" %s %s" % (user, pw)) if user else ""
    path.write_text(
        "strict_chain\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n"
        "[ProxyList]\n%s %s %s%s\n" % (kind, proxy["host"], port, extra),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


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
        # dns_resolvers are recorded; a SOCKS/HTTP proxy (when set) is what
        # actually carries DNS. Per-job resolv.conf is not applied here.
    argv = build_httrack_argv(url, mirror, options, user_agent=ua, proxy=proxy)

    wrapper: list[str] = []
    socks = _socks_proxy(proxy) if options["respect_opsec"] else None
    if socks:
        pc = shutil.which("proxychains4") or shutil.which("proxychains")
        if pc:
            conf = _write_proxychains_conf(job_dir, socks)
            wrapper = [pc, "-f", str(conf), "-q"]
        else:
            return {
                "ok": False,
                "error": "SOCKS/TOR proxy is set but proxychains4 is not installed in the clone container",
                "url": url,
                "options": options,
            }

    httrack = shutil.which("httrack")
    if not httrack and not wrapper:
        # Still analyze if a tree was pre-populated (unit tests, retries).
        if any(mirror.iterdir()) if mirror.exists() else False:
            report = analyze_tree(mirror, url)
            return {"ok": True, "url": url, "skipped_httrack": True, "analysis": report}
        return {"ok": False, "error": "httrack is not installed in this container", "url": url}

    cmd = wrapper + argv
    env = os.environ.copy()
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    env.pop("ALL_PROXY", None)
    # Don't leak proxy credentials into the child environment beyond proxychains conf.
    started = time.time()
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(job_dir), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=env, start_new_session=True,
        )
    except FileNotFoundError:
        return {"ok": False, "error": "httrack is not installed in this container", "url": url}

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
                    progress_cb({"files": files, "bytes": nbytes, "elapsed": int(time.time() - started)})
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
    report = analyze_tree(mirror, url)
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
        "error": (None if files > 0 else
                  ("clone timed out or hit a cap" if timed_out else
                   "HTTrack fetched no files")),
    }
