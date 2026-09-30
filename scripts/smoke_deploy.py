#!/usr/bin/env python3
"""
Post-install verification: does this SPOTTER actually work?

  python3 scripts/smoke_deploy.py                    # anonymous checks only
  python3 scripts/smoke_deploy.py --user alice       # also the gated surfaces

WHY THIS EXISTS

The README's "First-Run Tests" cannot be run by a fresh deployer: every command in
it POSTs to https://spotter.localhost:5443/webhook/..., which nginx puts behind
`auth_request`, so all of them answer 401 until you hold a session cookie — and
the route that issues one (POST /auth/login -> the spotter_session cookie) was not
documented anywhere. This script logs in first and then walks the stack, so the
result reflects what an operator would actually see.

Requires the SPOTTER_DASHBOARD_HOST/SPOTTER_N8N_HOST/SPOTTER_GRAPH_HOST/SPOTTER_CHAT_HOST
hostnames from .env to resolve to wherever the stack runs — same requirement as a real
browser. The *.localhost defaults resolve to 127.0.0.1 on their own (RFC 6761);
only a customized hostname needs /etc/hosts. TLS verification is disabled for these checks:
Caddy's cert comes from its own internal CA, which this script has no reason to
trust independently.

It is read-only: it creates nothing and writes nothing to the graph.

Exit code is 0 only if no check FAILED. A check may be SKIPped (an optional
feature that is not configured) without failing the run.
"""

from __future__ import annotations

import argparse
import getpass
import http.cookiejar
import json
import pathlib
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env"

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
results: list[tuple[str, str, str]] = []


def record(status: str, name: str, detail: str = "") -> None:
    results.append((status, name, detail))
    colour = {"PASS": "\033[32m", "FAIL": "\033[31m", "SKIP": "\033[33m"}[status]
    print(f"  {colour}{status}\033[0m  {name}" + (f"  — {detail}" if detail else ""))


def env_value(key: str) -> str:
    """Config or decrypted secret. FLOWSINT_API_KEY is no longer in .env."""
    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import spotter_env
    return spotter_env.get(key) or ""


# Caddy's cert is minted by its own internal CA -- nothing external to trust it
# against, so verification is disabled for the vhosts behind it. Same posture a
# browser takes on first visit (accept once, or import the CA -- see INSTALL.md).
_INSECURE_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_INSECURE_CTX.check_hostname = False
_INSECURE_CTX.verify_mode = ssl.CERT_NONE

CADDY_PORT = env_value("SPOTTER_CADDY_PORT") or "5443"
DASHBOARD_HOST = env_value("SPOTTER_DASHBOARD_HOST") or "spotter.localhost"
N8N_HOST = env_value("SPOTTER_N8N_HOST") or "n8n.spotter.localhost"
GRAPH_HOST = env_value("SPOTTER_GRAPH_HOST") or "graph.spotter.localhost"
CHAT_HOST = env_value("SPOTTER_CHAT_HOST") or "chat.spotter.localhost"
DASHBOARD = f"https://{DASHBOARD_HOST}:{CADDY_PORT}"
N8N_URL = f"https://{N8N_HOST}:{CADDY_PORT}"
GRAPH_URL = f"https://{GRAPH_HOST}:{CADDY_PORT}"
CHAT_URL = f"https://{CHAT_HOST}:{CADDY_PORT}"


def http(url: str, opener=None, timeout: int = 15, method: str = "GET"):
    req = urllib.request.Request(url, method=method)
    if opener:
        return opener.open(req, timeout=timeout)
    if url.startswith("https://"):
        return urllib.request.urlopen(req, timeout=timeout, context=_INSECURE_CTX)
    return urllib.request.urlopen(req, timeout=timeout)


# ── containers ───────────────────────────────────────────────────────────────
def check_containers() -> None:
    print("\nContainers")
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "--filter", "label=com.docker.compose.project=spotter",
             "--format", "{{.Names}}\t{{.State}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError) as e:
        record(FAIL, "docker ps", str(e))
        return

    rows = [l.split("\t") for l in out.strip().splitlines() if l.strip()]
    if not rows:
        record(FAIL, "stack is running",
               "no containers in project 'spotter' — was it launched with -p spotter?")
        return

    for name, state, status in rows:
        if state == "running" and "unhealthy" not in status:
            # A container that keeps restarting still reports "running".
            if re.search(r"Restarting|Up Less than a second", status):
                record(FAIL, name, status)
            else:
                record(PASS, name, status)
        else:
            record(FAIL, name, f"{state} — {status}")


# ── anonymous endpoints ──────────────────────────────────────────────────────
def check_open_endpoints() -> None:
    print("\nEndpoints that need no session")
    for name, url, ok_codes in [
        ("flowsint-api (127.0.0.1:5001)", "http://127.0.0.1:5001/docs", {200}),
        ("open-webui (127.0.0.1:3000)", "http://127.0.0.1:3000/health", {200}),
        # /login.html, not /login: it is the one page nginx marks
        # `auth_request off`, and the 401 body points at it as {"login": ...}.
        ("portal login page (Caddy)", f"{DASHBOARD}/login.html", {200}),
        ("gate healthz (Caddy)", f"{DASHBOARD}/healthz", {200}),
        # Open WebUI carries its own login, so its vhost is reachable without a
        # SPOTTER session by design — see the :8083 block in frontend/nginx.conf.
        # This is the dashboard's Chat link and the Prompt tab's ENDPOINT.
        ("chat vhost (Caddy)", f"{CHAT_URL}/health", {200}),
    ]:
        try:
            with http(url) as r:
                code = r.status
            record(PASS if code in ok_codes else FAIL, name, f"HTTP {code}")
        except urllib.error.HTTPError as e:
            record(PASS if e.code in ok_codes else FAIL, name, f"HTTP {e.code}")
        except Exception as e:
            record(FAIL, name, str(e))


def check_gate_identities() -> None:
    """Every vhost must NAME ITSELF, not merely answer.

    The dashboard's header links probe exactly this (frontend/index.html,
    probeGateIdentity) because the failure that actually happens is not a dead
    vhost but a live WRONG one — a hostname resolving to the dashboard vhost
    answers healthily to anything that only checks for a response. /_spotter/gate
    is unauthenticated on every port, so this runs without a session.
    """
    print("\nVhost identity (/_spotter/gate)")
    for name, url, want in [
        ("dashboard names itself", DASHBOARD, "portal"),
        ("n8n vhost names itself", N8N_URL, "n8n"),
        ("graph vhost names itself", GRAPH_URL, "flowsint"),
        ("chat vhost names itself", CHAT_URL, "open-webui"),
    ]:
        try:
            with http(f"{url}/_spotter/gate") as r:
                got = (json.loads(r.read()) or {}).get("gate")
        except Exception as e:
            record(FAIL, name, str(e))
            continue
        if got == want:
            record(PASS, name, got)
        else:
            record(FAIL, name,
                   f"{url} reports gate={got!r}, expected {want!r} — this hostname "
                   "reaches the wrong service")


def check_gate_is_closed() -> None:
    """The dashboard must NOT be reachable without a session.

    This is the check that would have caught the Flowsint UI being published on
    0.0.0.0: an auth gate you can walk around is not an auth gate.
    """
    print("\nAuth gate")
    for name, url in [
        ("dashboard refuses anonymous", f"{DASHBOARD}/"),
        ("n8n refuses anonymous", f"{N8N_URL}/"),
        ("flowsint UI refuses anonymous", f"{GRAPH_URL}/"),
    ]:
        try:
            with http(url) as r:
                if r.status == 200 and b"login" not in r.read(4096).lower():
                    record(FAIL, name, f"HTTP {r.status} without a session")
                else:
                    record(PASS, name, "redirected to login")
        except urllib.error.HTTPError as e:
            record(PASS if e.code in (401, 403, 302) else FAIL, name, f"HTTP {e.code}")
        except Exception as e:
            record(FAIL, name, str(e))


def check_flowsint_not_lan_exposed() -> None:
    try:
        out = subprocess.run(["docker", "port", "flowsint-app-prod"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        record(SKIP, "flowsint UI is loopback-only", "container not found")
        return
    if not out.strip():
        record(SKIP, "flowsint UI is loopback-only", "no published ports")
    elif "0.0.0.0" in out or "[::]" in out:
        record(FAIL, "flowsint UI is loopback-only",
               f"published on all interfaces ({out.strip()}) — it bypasses the "
               "login. Apply deployment/flowsint-patches/")
    else:
        record(PASS, "flowsint UI is loopback-only", out.strip().replace("\n", ", "))


# ── authenticated surfaces ───────────────────────────────────────────────────
def check_authenticated(username: str, password: str) -> None:
    print("\nWith an operator session")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=_INSECURE_CTX),
    )

    body = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(f"{DASHBOARD}/auth/login", data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with opener.open(req, timeout=15) as r:
            r.read()
        record(PASS, "portal login", f"as {username}")
    except urllib.error.HTTPError as e:
        record(FAIL, "portal login", f"HTTP {e.code} — {e.read().decode()[:120]}")
        return
    except Exception as e:
        record(FAIL, "portal login", str(e))
        return

    if not any(c.name == "spotter_session" for c in jar):
        record(FAIL, "spotter_session cookie", "login succeeded but set no cookie")
        return

    for name, url in [
        ("dashboard loads", f"{DASHBOARD}/"),
        ("n8n editor reachable", f"{N8N_URL}/"),
        ("flowsint UI reachable", f"{GRAPH_URL}/"),
    ]:
        try:
            with http(url, opener=opener) as r:
                record(PASS if r.status == 200 else FAIL, name, f"HTTP {r.status}")
        except urllib.error.HTTPError as e:
            record(FAIL, name, f"HTTP {e.code}")
        except Exception as e:
            record(FAIL, name, str(e))


# ── configuration sanity ─────────────────────────────────────────────────────
def check_config() -> None:
    print("\nConfiguration")
    token = env_value("FLOWSINT_API_KEY")
    if not token or token.startswith("REPLACE_WITH"):
        record(FAIL, "FLOWSINT_API_KEY set", "still a placeholder")
    else:
        try:
            import base64
            from datetime import datetime, timezone
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            exp = json.loads(base64.urlsafe_b64decode(payload))["exp"]
            when = datetime.fromtimestamp(exp, tz=timezone.utc)
            hours = (when - datetime.now(tz=timezone.utc)).total_seconds() / 3600
            if hours < 0:
                record(FAIL, "FLOWSINT_API_KEY valid",
                       "EXPIRED — run scripts/refresh_flowsint_token.py")
            elif hours < 24:
                record(SKIP, "FLOWSINT_API_KEY valid",
                       f"expires in {hours:.0f}h — refresh soon")
            else:
                record(PASS, "FLOWSINT_API_KEY valid", f"{hours/24:.0f}d left")
        except Exception:
            record(SKIP, "FLOWSINT_API_KEY valid", "not a readable JWT")

    sketch = env_value("FLOWSINT_SKETCH_ID")
    record(PASS if sketch and not sketch.startswith("REPLACE_WITH") else FAIL,
           "FLOWSINT_SKETCH_ID set", sketch or "unset")

    home = env_value("SPOTTER_HOME")
    record(PASS if home == str(REPO_ROOT) else FAIL, "SPOTTER_HOME matches this checkout",
           f"{home or 'unset'} vs {REPO_ROOT}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--user", help="portal operator to log in as (enables gated checks)")
    ap.add_argument("--password", help="that operator's password (prompted if omitted)")
    args = ap.parse_args()

    print("SPOTTER deployment smoke test")
    check_containers()
    check_open_endpoints()
    check_gate_identities()
    check_gate_is_closed()
    check_flowsint_not_lan_exposed()
    check_config()

    if args.user:
        pw = args.password or getpass.getpass(f"password for {args.user}: ")
        check_authenticated(args.user, pw)
    else:
        print("\nWith an operator session")
        record(SKIP, "gated surfaces", "pass --user <operator> to check these")

    failed = [r for r in results if r[0] == FAIL]
    skipped = [r for r in results if r[0] == SKIP]
    print(f"\n{len(results) - len(failed) - len(skipped)} passed, "
          f"{len(failed)} failed, {len(skipped)} skipped")
    if failed:
        print("\nFailures:")
        for _, name, detail in failed:
            print(f"  - {name}: {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
