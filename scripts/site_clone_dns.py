#!/usr/bin/env python3
"""OPSEC DNS routing for Active Site Clone.

Where a lookup actually happens (bookworm sidecar: HTTrack 3.49.4-1,
proxychains-ng 4.16-2 as proxychains4):

* No proxy: HTTrack calls getaddrinfo/gethostbyname, which reads the
  container /etc/resolv.conf (Docker embedded DNS, typically 127.0.0.11)
  unless this module bind-mounts a per-job resolv.conf or points it at a
  per-job stub.
* HTTP proxy via HTTrack -P only: for plain http:// origins, 3.49.4
  connects to the proxy and sends an absolute URI, so origin DNS is at
  the proxy. For https:// origins, http_xfopen treats the proxy as "not
  usable here" and calls newhttp() on the origin — local DNS and a
  direct connect. HTTP CONNECT for HTTPS landed in 3.49-13, not in
  Debian bookworm's 3.49.4. The word "CONNECT" in 3.49.4 htsback.c is a
  status string, not tunneling. Under OPSEC we therefore wrap HTTP
  proxies with proxychains4 (type http + proxy_dns) and do not pass -P.
* SOCKS5 / TOR via proxychains4 with proxy_dns: libc resolution is
  intercepted, a fake IP is returned, and the hostname is sent to the
  proxy (SOCKS5 ATYP 3). Origin DNS is at the SOCKS/Tor process. The
  proxy endpoint hostname itself (e.g. ssh-tunnel-api) still uses
  Docker DNS; that is a compose service name, not the target.
* SSH tunnel: ssh -N -D is a SOCKS4/5 dynamic forward. OpenSSH resolves
  SOCKS5 domain requests on the remote SSH host, but only if the client
  sends a hostname (proxy_dns / socks5h), not a pre-resolved IP. The
  frontend "Use Tunnel as SOCKS Proxy" control is type socks5.

The frontend envelope is {type, http_url} or {type, socks:{host,port},
socks_url: "socks5h://..."}. This module flattens that (and the already
flat {host,port,type} form) so proxychains / -P actually attach.

Per-job resolv.conf is applied with
`unshare --user --map-root-user --mount --propagation private` plus a
bind mount. That needs no SYS_ADMIN; it does need a working user
namespace and a security profile that allows mount(2). docker-default
AppArmor denies mount, so the clone service is started
apparmor:unconfined. Concurrent jobs keep the container-global
/etc/resolv.conf unchanged.

DoH-only (and mixed IP+DoH/DoT) presets start scripts/site_clone_dns_stub.py
on 127.0.0.N:53, with resolv.conf pointing at that address. Debian has no
suitable DoH stub package. Binding port 53 uses Docker's default
NET_BIND_SERVICE capability; SYS_ADMIN is not added.

Fail-closed when OPSEC is on and DNS cannot be routed through a proxy or
the chosen resolvers, unless the operator checks "Allow Docker DNS
(leaks lookups)". With OPSEC off, behaviour is unchanged (Docker DNS,
HTTrack -P for HTTP proxies).
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

STUB_SCRIPT = Path(__file__).resolve().parent / "site_clone_dns_stub.py"

_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(?::(\d{1,5}))?$")
_IPV6_BARE = re.compile(r"^[0-9A-Fa-f:]+$")
_IPV6_BRACKETS = re.compile(r"^\[([0-9A-Fa-f:]+)\](?::(\d{1,5}))?$")


def normalize_proxy(proxy: dict[str, Any] | None) -> dict[str, Any] | None:
    """Flatten the frontend infra envelope or a pre-flat proxy dict.

    Accepts:
      {type, host, port, username?, password?}
      {type: 'http', http_url: 'http://user:pass@host:port'}
      {type: 'socks5'|'tor', socks: {host, port, username, password}, socks_url?}
      {type, socks_url: 'socks5h://host:port'}
    Returns {type, host, port, username, password} or None.
    """
    if not proxy or not isinstance(proxy, dict):
        return None
    typ = str(proxy.get("type") or "").strip().lower()
    if typ in {"", "none", "off", "disabled"}:
        typ = ""

    host = str(proxy.get("host") or "").strip()
    port = proxy.get("port")
    user = str(proxy.get("username") or "")
    passwd = str(proxy.get("password") or "")

    socks = proxy.get("socks") if isinstance(proxy.get("socks"), dict) else None
    if not host and socks:
        host = str(socks.get("host") or "").strip()
        if port in (None, "", 0):
            port = socks.get("port")
        if not user:
            user = str(socks.get("username") or "")
        if not passwd:
            passwd = str(socks.get("password") or "")
        if not typ:
            typ = "socks5"

    if not host and proxy.get("http_url"):
        parsed = _authority(str(proxy.get("http_url") or ""))
        if parsed:
            host, port, user, passwd = _fill(parsed, host, port, user, passwd)
        if not typ:
            typ = "http"

    if not host and proxy.get("socks_url"):
        parsed = _authority(str(proxy.get("socks_url") or ""))
        if parsed:
            host, port, user, passwd = _fill(parsed, host, port, user, passwd)
        if not typ:
            typ = "socks5"

    if not typ:
        typ = "http" if proxy.get("http_url") else ("socks5" if (socks or proxy.get("socks_url")) else "")
    if typ in {"socks", "socks5h"}:
        typ = "socks5"
    if typ == "https":
        typ = "http"

    if typ not in {"http", "socks5", "tor"}:
        return None
    if not host:
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    if port in (None, "", 0):
        default = 9050 if typ == "tor" else (1080 if typ == "socks5" else 8080)
        port = default
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        return None
    if port_i < 1 or port_i > 65535:
        return None

    return {
        "type": typ,
        "host": host,
        "port": port_i,
        "username": user,
        "password": passwd,
    }


def _authority(url: str) -> dict[str, Any] | None:
    url = (url or "").strip()
    if not url:
        return None
    # urlparse needs a scheme to split host/auth; socks5h:// is fine.
    if "://" not in url:
        url = "http://" + url
    p = urlparse(url)
    host = p.hostname
    if not host:
        return None
    port = p.port
    user = unquote(p.username) if p.username else ""
    passwd = unquote(p.password) if p.password else ""
    if port is None:
        if p.scheme in {"http"}:
            port = 80
        elif p.scheme in {"https"}:
            port = 443
        else:
            port = None
    return {"host": host, "port": port, "username": user, "password": passwd}


def _fill(parsed: dict[str, Any], host: str, port: Any, user: str, passwd: str
          ) -> tuple[str, Any, str, str]:
    if not host:
        host = parsed["host"]
    if port in (None, "", 0) and parsed.get("port"):
        port = parsed["port"]
    if not user:
        user = parsed.get("username") or ""
    if not passwd:
        passwd = parsed.get("password") or ""
    return host, port, user, passwd


def classify_resolvers(values: Any) -> dict[str, list[str]]:
    """Split opsec.dns_resolvers into ips / doh / dot / invalid."""
    out: dict[str, list[str]] = {"ips": [], "doh": [], "dot": [], "invalid": []}
    if not values:
        return out
    if isinstance(values, str):
        values = [values]
    for raw in values:
        tok = str(raw or "").strip()
        if not tok:
            continue
        if tok.lower().startswith("https://"):
            out["doh"].append(tok)
        elif tok.lower().startswith("tls://"):
            out["dot"].append(tok)
        elif tok.lower().startswith("http://"):
            out["invalid"].append(tok)
        elif _looks_ip(tok):
            out["ips"].append(tok)
        else:
            out["invalid"].append(tok)
    return out


def _looks_ip(tok: str) -> bool:
    if _IPV4.match(tok) or _IPV6_BRACKETS.match(tok):
        return True
    if ":" in tok and _IPV6_BARE.match(tok):
        return True
    return False


def resolv_conf_text(nameservers: list[str], options: str = "timeout:2 attempts:2 ndots:1"
                     ) -> str:
    lines = ["# SPOTTER Site Clone per-job resolvers. Not the container default.",
             "options " + options]
    for ns in nameservers:
        host, port = _nameserver_host(ns)
        # glibc resolv.conf has no port field; non-53 IPs must go through the stub.
        if port not in (None, 53):
            continue
        if ":" in host and not host.startswith("["):
            # Bare IPv6 is valid in resolv.conf.
            lines.append("nameserver " + host)
        else:
            lines.append("nameserver " + host)
    lines.append("")
    return "\n".join(lines)


def _nameserver_host(tok: str) -> tuple[str, int | None]:
    m = _IPV6_BRACKETS.match(tok)
    if m:
        return m.group(1), int(m.group(2)) if m.group(2) else 53
    m = _IPV4.match(tok)
    if m and m.group(2):
        return tok.rsplit(":", 1)[0], int(m.group(2))
    if _IPV4.match(tok) or (":" in tok and _IPV6_BARE.match(tok)):
        return tok, 53
    return tok, 53


def needs_stub(classified: dict[str, list[str]]) -> bool:
    if classified["doh"] or classified["dot"]:
        return True
    for tok in classified["ips"]:
        _, port = _nameserver_host(tok)
        if port not in (None, 53):
            return True
    return False


def write_resolv_conf(path: Path, nameservers: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(resolv_conf_text(nameservers), encoding="utf-8")
    return path


def write_proxychains_conf(job_dir: Path, proxy: dict[str, Any]) -> Path:
    """Write a per-job proxychains-ng conf with remote DNS enabled.

    proxy_dns makes proxychains intercept getaddrinfo/gethostbyname, return
    a fake address, and send the hostname to the proxy (SOCKS5 ATYP 3 or
    HTTP CONNECT host:port). That is socks5h semantics. strict_chain keeps
    a single listed hop.
    """
    path = job_dir / "proxychains.conf"
    typ = str(proxy.get("type") or "socks5").lower()
    kind = "http" if typ in {"http", "https"} else "socks5"
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


def dns_label(via: str, resolver: str = "") -> str:
    """Short label shown as 'DNS: …' on the Active job card."""
    if via == "tor":
        return "via TOR"
    if via == "socks5":
        return "via SOCKS5"
    if via == "http_proxy":
        return "via HTTP proxy"
    if via == "docker_override":
        return "Docker (override)"
    if via == "docker":
        return "Docker"
    if via in {"resolver", "doh", "stub"}:
        return resolver or "resolver"
    return resolver or via or "unknown"


def loopback_alias(job_dir: Path) -> str:
    digest = hashlib.sha256(str(job_dir).encode("utf-8")).digest()[0]
    return "127.0.0.%d" % (2 + (digest % 253))  # 127.0.0.2–254


def probe_mount_namespace(timeout: float = 3.0) -> tuple[bool, str]:
    """Return whether a user+mount namespace can bind-mount /etc/resolv.conf."""
    unshare = shutil.which("unshare")
    if not unshare:
        return False, "unshare is not installed (util-linux)"
    with_tmp = _probe_dir()
    try:
        sample = with_tmp / "resolv.conf"
        sample.write_text("nameserver 9.9.9.9\n", encoding="utf-8")
        marker = with_tmp / "observed"
        inner = (
            "import os,sys\n"
            "src, dst, out = sys.argv[1], '/etc/resolv.conf', sys.argv[2]\n"
            "import subprocess\n"
            "r = subprocess.run(['mount','--bind',src,dst], capture_output=True)\n"
            "if r.returncode != 0:\n"
            "    sys.stderr.write((r.stderr or r.stdout or b'').decode('utf-8','replace'))\n"
            "    sys.exit(r.returncode or 1)\n"
            "open(out,'w').write(open(dst).read())\n"
        )
        cmd = [
            unshare, "--user", "--map-root-user", "--mount",
            "--propagation", "private", "--",
            sys.executable, "-c", inner, str(sample), str(marker),
        ]
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or b"").decode("utf-8", "replace").strip()
            return False, err or "unshare mount probe exited %s" % proc.returncode
        text = marker.read_text(encoding="utf-8") if marker.is_file() else ""
        if "9.9.9.9" not in text:
            return False, "bind mount did not change /etc/resolv.conf inside the namespace"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "unshare mount probe timed out"
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, e)
    finally:
        try:
            shutil.rmtree(with_tmp, ignore_errors=True)
        except Exception:
            pass


def _probe_dir() -> Path:
    base = Path(os.environ.get("TMPDIR") or "/tmp") / "spotter-dns-probe"
    path = Path(str(base) + ".%s" % os.getpid())
    path.mkdir(parents=True, exist_ok=True)
    return path


def mount_namespace_prefix(resolv_conf: Path) -> list[str]:
    unshare = shutil.which("unshare")
    if not unshare:
        return []
    helper = Path(__file__).resolve()
    return [
        unshare, "--user", "--map-root-user", "--mount",
        "--propagation", "private", "--",
        sys.executable, str(helper), "--bind-and-exec", str(resolv_conf),
    ]


def bind_resolv_and_exec(resolv_conf: str, argv: list[str]) -> int:
    """Entry point for --bind-and-exec: bind-mount resolv.conf, then exec argv."""
    target = "/etc/resolv.conf"
    # If resolv.conf is a symlink, bind over the real file glibc will read.
    real = target
    try:
        if os.path.islink(target):
            real = os.path.realpath(target)
    except OSError:
        real = target
    r = subprocess.run(["mount", "--bind", resolv_conf, real], capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(
            "failed to bind-mount %s over %s: %s\n"
            % (resolv_conf, real, (r.stderr or r.stdout or b"").decode("utf-8", "replace"))
        )
        return r.returncode or 1
    os.execvp(argv[0], argv)
    return 127  # unreachable


def public_dns(plan: dict[str, Any], answers: list[str] | None = None,
               preflight_ok: bool | None = None, preflight_error: str = ""
               ) -> dict[str, Any]:
    out = {
        "label": plan.get("label") or "",
        "via": plan.get("via") or "",
        "resolver": plan.get("resolver") or "",
        "host": plan.get("host") or "",
        "answers": list(answers or []),
        "ok": True if preflight_ok is None else bool(preflight_ok),
    }
    if preflight_error:
        out["error"] = preflight_error
    return out


def plan_job_dns(
    url: str,
    job_dir: Path,
    options: dict[str, Any],
    opsec: dict[str, Any] | None,
    proxy: dict[str, Any] | None,
    *,
    mount_ok: bool | None = None,
    proxychains_bin: str | None | bool = True,
) -> dict[str, Any]:
    """Decide how this job will resolve names.

    proxychains_bin: True = look up on PATH, False/None = missing,
    a string = that binary.
    mount_ok: None = probe, else the forced probe result (for tests).
    """
    job_dir = Path(job_dir)
    job_dir.mkdir(parents=True, exist_ok=True)
    host = urlparse(url).hostname or ""
    respect = bool(options.get("respect_opsec"))
    allow = bool(options.get("allow_docker_dns"))
    flat = normalize_proxy(proxy)
    classified = classify_resolvers((opsec or {}).get("dns_resolvers"))
    pc_bin = _which_proxychains(proxychains_bin)

    plan: dict[str, Any] = {
        "ok": True,
        "error": "",
        "label": "",
        "via": "",
        "resolver": "",
        "host": host,
        "use_proxychains": False,
        "use_httrack_p": False,
        "proxychains_conf": None,
        "resolv_conf": None,
        "stub": None,
        "prefix": [],
        "proxy": flat,
        "classified": classified,
        "allow_docker_dns": allow,
        "respect_opsec": respect,
    }

    if not respect:
        # OPSEC off: keep historical behaviour. HTTP may use HTTrack -P
        # (HTTPS still resolved locally on 3.49.4). SOCKS is not wrapped
        # unless the operator also left respect_opsec on.
        if flat and flat["type"] == "http":
            plan["use_httrack_p"] = True
        plan["via"] = "docker"
        plan["label"] = ""
        plan["resolver"] = "Docker"
        return plan

    # OPSEC on: a usable proxy carries DNS at the proxy via proxychains.
    if flat and flat["type"] in {"http", "socks5", "tor"}:
        if not pc_bin:
            plan["ok"] = False
            plan["error"] = (
                "OPSEC DNS cannot be routed: a %s proxy is set but proxychains4 "
                "is not installed in the clone container."
                % ("HTTP" if flat["type"] == "http" else "SOCKS/TOR")
            )
            plan["via"] = flat["type"] if flat["type"] != "http" else "http_proxy"
            plan["label"] = dns_label(plan["via"])
            return plan
        conf = write_proxychains_conf(job_dir, flat)
        plan["use_proxychains"] = True
        plan["proxychains_conf"] = str(conf)
        plan["prefix"] = [pc_bin, "-f", str(conf), "-q"]
        if flat["type"] == "tor":
            plan["via"] = "tor"
            plan["resolver"] = "TOR %s:%s" % (flat["host"], flat["port"])
        elif flat["type"] == "http":
            plan["via"] = "http_proxy"
            plan["resolver"] = "HTTP proxy %s:%s" % (flat["host"], flat["port"])
        else:
            plan["via"] = "socks5"
            plan["resolver"] = "SOCKS5 %s:%s" % (flat["host"], flat["port"])
        plan["label"] = dns_label(plan["via"])
        return plan

    if allow:
        plan["via"] = "docker_override"
        plan["label"] = dns_label("docker_override")
        plan["resolver"] = "Docker (override)"
        return plan

    usable = classified["ips"] + classified["doh"] + classified["dot"]
    if not usable:
        missing = "no DNS resolvers are configured"
        if classified["invalid"]:
            missing = "configured DNS resolvers are not usable (%s)" % (
                ", ".join(classified["invalid"][:3])
            )
        plan["ok"] = False
        plan["error"] = (
            "OPSEC DNS cannot be routed: no proxy is set and %s. "
            "Set Infrastructure DNS resolvers or a proxy, or enable "
            "Allow Docker DNS (leaks lookups)."
        ) % missing
        plan["via"] = "none"
        plan["label"] = ""
        return plan

    if mount_ok is None:
        mount_ok, mount_err = probe_mount_namespace()
    else:
        mount_err = ""
    if not mount_ok:
        plan["ok"] = False
        plan["error"] = (
            "OPSEC DNS cannot be routed: could not apply a per-job resolv.conf "
            "(mount namespace not permitted%s). Enable Allow Docker DNS "
            "(leaks lookups), or see INSTALL for the clone container's "
            "namespace/AppArmor requirements."
        ) % ((": " + mount_err[:180]) if mount_err else "")
        plan["via"] = "resolver"
        plan["label"] = dns_label("resolver", _resolver_label(classified))
        return plan

    stub_needed = needs_stub(classified)
    resolv_ns: list[str]
    stub_spec: dict[str, Any] | None = None
    if stub_needed:
        bind = loopback_alias(job_dir)
        stub_spec = {
            "bind": bind,
            "port": 53,
            "servers": usable,
            "ready": str(job_dir / "dns-stub.ready"),
            "pid": str(job_dir / "dns-stub.pid"),
            "script": str(STUB_SCRIPT),
        }
        resolv_ns = [bind]
        plan["via"] = "stub"
    else:
        resolv_ns = []
        for tok in classified["ips"]:
            host_s, port = _nameserver_host(tok)
            if port in (None, 53):
                resolv_ns.append(host_s)
        plan["via"] = "resolver"

    resolv_path = job_dir / "resolv.conf"
    write_resolv_conf(resolv_path, resolv_ns)
    plan["resolv_conf"] = str(resolv_path)
    plan["stub"] = stub_spec
    plan["prefix"] = mount_namespace_prefix(resolv_path)
    plan["resolver"] = _resolver_label(classified)
    plan["label"] = dns_label(plan["via"], plan["resolver"])
    if not plan["prefix"]:
        plan["ok"] = False
        plan["error"] = (
            "OPSEC DNS cannot be routed: unshare is not installed in the clone "
            "container, so a per-job resolv.conf cannot be applied. Enable "
            "Allow Docker DNS (leaks lookups) or install util-linux."
        )
    return plan


def _resolver_label(classified: dict[str, list[str]]) -> str:
    if classified["ips"] and not classified["doh"] and not classified["dot"]:
        # Prefer a short card label: first IP, plus a count if more.
        ips = [ _nameserver_host(t)[0] for t in classified["ips"] ]
        if len(ips) == 1:
            return ips[0]
        return ", ".join(ips[:2]) + (" +" + str(len(ips) - 2) if len(ips) > 2 else "")
    if classified["doh"] and not classified["ips"]:
        host = urlparse(classified["doh"][0]).hostname or classified["doh"][0]
        return "DoH (%s)" % host
    if classified["dot"] and not classified["ips"] and not classified["doh"]:
        rest = classified["dot"][0].split("://", 1)[-1]
        return "DoT (%s)" % rest.split("/")[0]
    parts = []
    if classified["ips"]:
        parts.append(_nameserver_host(classified["ips"][0])[0])
    if classified["doh"]:
        parts.append(urlparse(classified["doh"][0]).hostname or "DoH")
    return ", ".join(parts) or "resolver"


def _which_proxychains(value: str | None | bool) -> str | None:
    if value is False or value is None:
        return None
    if isinstance(value, str) and value not in {"", "1", "true", "True"}:
        return value
    return shutil.which("proxychains4") or shutil.which("proxychains")


def start_stub(spec: dict[str, Any], user_agent: str = "",
               timeout: float = 5.0) -> subprocess.Popen:
    """Start the per-job stub. Raises RuntimeError if it does not become ready."""
    script = Path(spec["script"])
    if not script.is_file():
        raise RuntimeError("DNS stub script is missing: %s" % script)
    for path_key in ("ready", "pid"):
        p = Path(spec[path_key])
        try:
            if p.exists():
                p.unlink()
        except OSError:
            pass
    argv = [
        sys.executable, str(script),
        "--bind", str(spec["bind"]),
        "--port", str(int(spec["port"])),
        "--ready", str(spec["ready"]),
        "--pid", str(spec["pid"]),
    ]
    if user_agent:
        argv += ["--user-agent", user_agent]
    for server in spec["servers"]:
        argv += ["--server", str(server)]
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )
    deadline = time.time() + timeout
    ready = Path(spec["ready"])
    while time.time() < deadline:
        if proc.poll() is not None:
            err = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", "replace")
            raise RuntimeError(
                "DNS stub exited before becoming ready (code %s): %s"
                % (proc.returncode, (err or "").strip()[:240])
            )
        if ready.is_file():
            return proc
        time.sleep(0.05)
    stop_stub(proc, spec)
    raise RuntimeError(
        "DNS stub did not become ready on %s:%s within %ss"
        % (spec["bind"], spec["port"], int(timeout))
    )


def stop_stub(proc: subprocess.Popen | None, spec: dict[str, Any] | None = None) -> None:
    if proc is None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        proc.wait(timeout=2)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass
    if spec:
        for key in ("ready", "pid"):
            try:
                Path(spec[key]).unlink(missing_ok=True)
            except OSError:
                pass


def preflight_resolve(host: str, prefix: list[str], env: dict[str, str] | None = None,
                      timeout: float = 8.0) -> tuple[bool, list[str], str]:
    """Resolve host through the same wrapper the clone will use."""
    if not host:
        return False, [], "no host to resolve"
    code = (
        "import socket,sys,json\n"
        "h=sys.argv[1]\n"
        "try:\n"
        "    ais=socket.getaddrinfo(h, None)\n"
        "    print(json.dumps(sorted({a[4][0] for a in ais})))\n"
        "except Exception as e:\n"
        "    print('ERR:'+type(e).__name__+':'+str(e), file=sys.stderr)\n"
        "    sys.exit(1)\n"
    )
    cmd = list(prefix or []) + [sys.executable, "-c", code, host]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            env=env or os.environ.copy(),
        )
    except subprocess.TimeoutExpired:
        return False, [], "preflight resolve timed out"
    except OSError as e:
        return False, [], "preflight resolve failed: %s" % type(e).__name__
    err = (proc.stderr or b"").decode("utf-8", "replace").strip()
    out = (proc.stdout or b"").decode("utf-8", "replace").strip()
    if proc.returncode != 0:
        return False, [], (err or out or "preflight resolve exited %s" % proc.returncode)[:240]
    try:
        import json
        answers = [str(x) for x in json.loads(out)]
    except Exception:
        return False, [], "preflight produced no usable addresses"
    return True, answers, ""


def capabilities() -> dict[str, Any]:
    mount_ok, mount_err = probe_mount_namespace()
    return {
        "mount_namespace": mount_ok,
        "mount_error": mount_err or "",
        "proxychains": bool(shutil.which("proxychains4") or shutil.which("proxychains")),
        "stub_script": STUB_SCRIPT.is_file(),
        "unshare": bool(shutil.which("unshare")),
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--bind-and-exec"]:
        if len(argv) < 3:
            print("usage: site_clone_dns.py --bind-and-exec RESOLV_CONF CMD...", file=sys.stderr)
            return 2
        return bind_resolv_and_exec(argv[1], argv[2:])
    print("usage: site_clone_dns.py --bind-and-exec RESOLV_CONF CMD...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
