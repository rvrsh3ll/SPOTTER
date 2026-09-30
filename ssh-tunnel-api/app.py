"""Egress control-plane sidecar for the SPOTTER Infrastructure tab.

Three things live here, all reached under /tunnel/ (the only prefix nginx routes
to this service, and the only one the API token gate covers):

  * /tunnel/*         a single managed SSH SOCKS5 tunnel
  * /tunnel/tor/*     a single managed Tor client, with per-country entry/exit
                      node selection
  * /tunnel/egress    "what does the world see" — fetches an IP-reflection
                      service through a given proxy with a given User-Agent, so
                      the operator can confirm the egress identity BEFORE
                      running an enrichment sweep

Everything is deliberately single-instance: one SSH tunnel, one Tor process. An
operator who is unsure which of three proxies a scan actually used has no opsec
story at all, so the API refuses to start a second one rather than multiplexing.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request

app = Flask(__name__)

_BIND_HOST = (os.environ.get("TUNNEL_BIND_HOST") or "0.0.0.0").strip()
_PROXY_HOST = (os.environ.get("TUNNEL_PROXY_HOST") or "ssh-tunnel-api").strip()
_DEFAULT_KEY_PATH = (os.environ.get("TUNNEL_DEFAULT_KEY_PATH") or "/ssh-keys/id_ed25519").strip()
_ALLOWED_KEY_ROOTS = [
    p.strip() for p in (os.environ.get("TUNNEL_KEY_ROOTS") or "/ssh-keys").split(",") if p.strip()
]
_STARTUP_TIMEOUT = float(os.environ.get("TUNNEL_STARTUP_TIMEOUT") or "6")
# How the tunnel treats the remote host key. "accept-new" trusts a host it has
# not seen and refuses one whose key CHANGED; "no" also proceeds through a
# change; "yes" demands a pre-seeded entry.
#
# Worth knowing before choosing: this container's known_hosts lives on its
# writable layer and is destroyed on every recreate, so the pinning is already
# only as durable as the container. What it reliably does instead is block the
# tunnel with "Host key verification failed" after the far end is rebuilt and
# presents a new key — routine for a disposable redirector. Under "no" the
# store is bypassed entirely rather than left to reset silently.
_HOST_KEY_POLICY = (os.environ.get("TUNNEL_HOST_KEY_POLICY") or "accept-new").strip().lower()
if _HOST_KEY_POLICY not in ("accept-new", "no", "yes"):
    _HOST_KEY_POLICY = "accept-new"
_API_TOKEN = (os.environ.get("TUNNEL_API_TOKEN") or "").strip()
_MAX_SECRET_LENGTH = int(os.environ.get("TUNNEL_MAX_SECRET_LENGTH") or "4096")

# The one root the upload endpoint will write to. Deliberately a separate
# variable rather than "the first entry of TUNNEL_KEY_ROOTS": that list also
# drives the suggestion text in _key_path_rejection(), so the write destination
# would otherwise move whenever someone reordered it. It must still be inside
# _ALLOWED_KEY_ROOTS or /tunnel/start would reject the very keys just uploaded.
_UPLOAD_KEY_ROOT = (os.environ.get("TUNNEL_UPLOAD_KEY_ROOT") or "/ssh-keys-uploaded").strip()
# A private key is small: ~400 B for ed25519, ~3.2 KB for RSA-4096, whose base64
# is ~4.3 KB. _MAX_SECRET_LENGTH (4096) is for passphrases and is too small to
# reuse here, so uploads get their own, larger ceiling.
_MAX_KEY_BYTES = int(os.environ.get("TUNNEL_MAX_KEY_BYTES") or "65536")
# ssh-keygen is only ever used for things that have no in-process equivalent
# (fingerprint, public-key derivation). It never gets a chance to prompt.
_KEYGEN_TIMEOUT = float(os.environ.get("TUNNEL_KEYGEN_TIMEOUT") or "10")

_USER_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_HOST_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")

# ── Tor ──────────────────────────────────────────────────────────────────────
_TOR_BIN = (os.environ.get("TOR_BIN") or "tor").strip()
_TOR_SOCKS_PORT = int(os.environ.get("TOR_SOCKS_PORT") or "9050")
_TOR_DATA_DIR = (os.environ.get("TOR_DATA_DIR") or "/var/lib/spotter-tor").strip()
_TOR_GEOIP = (os.environ.get("TOR_GEOIP_FILE") or "/usr/share/tor/geoip").strip()
_TOR_GEOIP6 = (os.environ.get("TOR_GEOIP6_FILE") or "/usr/share/tor/geoip6").strip()
_TOR_RUN_AS = (os.environ.get("TOR_RUN_AS") or "debian-tor").strip()
_TOR_MAX_COUNTRIES = int(os.environ.get("TOR_MAX_COUNTRIES") or "24")
_TOR_STARTUP_TIMEOUT = float(os.environ.get("TOR_STARTUP_TIMEOUT") or "20")
# Reachable from the other containers on the compose network, and from nothing
# else: the port is never published to the host. Override only to widen it to a
# different private range.
_TOR_SOCKS_POLICY = (
    os.environ.get("TOR_SOCKS_POLICY")
    or "accept 127.0.0.0/8,accept 10.0.0.0/8,accept 172.16.0.0/12,accept 192.168.0.0/16,reject *"
).strip()

_CC_RE = re.compile(r"^[A-Za-z]{2}$")

# ── Egress identity check ────────────────────────────────────────────────────
# These answer "which IP will the target see, and where does it look like it
# is". The list is tried in order and the response records which URL actually
# answered, because none of these JSON shapes is a published contract: the
# parser accepts JSON, bare text or an HTML page, and the first URL yielding a
# parseable PUBLIC address wins.
#
# Order matters and is the whole fix for the blank-geo readout: every source
# ahead of ip.me returns the address AND its location in ONE response, so the
# common path costs exactly one call and the country — the thing this strip
# exists to confirm when Tor is pinned — is populated without a second hop.
# ip.me stays last as an IP-only floor: as of 2026-09-20 its three JSON paths
# are gone (/api/json is HTTP 404, /api and /json serve the HTML page) and only
# the plain-text root still answers, which is exactly how the strip came to
# show an address with no country. The three ahead of it are independent
# vendors, so one going the same way is a degraded answer, not a blank one.
_EGRESS_URLS = [
    u.strip() for u in (
        os.environ.get("EGRESS_IP_URLS")
        or "https://ifconfig.co/json,https://ipwho.is/,https://api.ipapi.is/,https://ip.me/"
    ).split(",") if u.strip()
]
# Second hop for geo, used ONLY when the source that answered gave an IP and no
# location — i.e. when the chain fell through to an IP-only source. It is not an
# extra call on the normal path. It travels the SAME proxy as the first hop, so
# it cannot deanonymise a Tor-routed check; set it empty to refuse the hop
# outright and accept "geo unavailable". {ip} is substituted.
_EGRESS_GEO_URL = (os.environ.get("EGRESS_GEO_URL") or "https://ipwho.is/{ip}").strip()
_EGRESS_TIMEOUT = float(os.environ.get("EGRESS_TIMEOUT") or "12")
# Hard ceiling on the WHOLE check, across every URL and retry. nginx caps the
# /infra/tunnel/ location at 30s: without this, four URLs × two User-Agents ×
# a 12s timeout would blow through it and the browser would get an opaque 504
# instead of the errors[] list explaining which hop failed.
_EGRESS_BUDGET = float(os.environ.get("EGRESS_TOTAL_BUDGET") or "22")
# Used only as a retry when the operator's own User-Agent got an HTML page back
# with no parseable IP in it.
_EGRESS_FALLBACK_UA = (os.environ.get("EGRESS_FALLBACK_UA") or "curl/8.5.0").strip()

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "id": "",
    "pid": None,
    "proc": None,
    "ssh_user": "",
    "ssh_host": "",
    "local_socks_port": 0,
    "proxy_host": _PROXY_HOST,
    "proxy_port": 0,
    "started_at": 0.0,
    "auth_method": "",
    # Anything the sidecar decided on the operator's behalf — the key path it
    # substituted, a passphrase it ignored. Advisory, and never key material.
    "notes": [],
    "error": "",
}


def _error_json(message: str, status_code: int, code: str) -> Any:
    return jsonify({"ok": False, "error": message, "code": code}), status_code


def _extract_supplied_api_token() -> str:
    supplied = (request.headers.get("X-Tunnel-Token") or "").strip()
    if supplied:
        return supplied

    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


@app.before_request
def _enforce_api_token() -> Any:
    # Health endpoint remains open for container healthchecks.
    if request.path == "/health":
        return None
    if not request.path.startswith("/tunnel/"):
        return None
    # Fail closed. This used to `return None`, which left every /tunnel/* route
    # -- key upload, tunnel start, Tor control -- reachable with no credential
    # at all whenever TUNNEL_API_TOKEN failed to reach the container. A dropped
    # variable is exactly what a secrets-store migration is most likely to
    # produce, and this sidecar drives live operator SSH infrastructure, so the
    # misconfigured state has to refuse rather than serve. 503 rather than 401
    # because the fault is server-side configuration, not the caller's
    # credential: a 401 sends the operator hunting for a login problem.
    if not _API_TOKEN:
        return _error_json(
            "Tunnel control is not configured: TUNNEL_API_TOKEN is unset",
            503,
            "not_configured",
        )

    supplied = _extract_supplied_api_token()
    if not supplied or not hmac.compare_digest(supplied, _API_TOKEN):
        return _error_json(
            "Unauthorized tunnel control request",
            401,
            "unauthorized",
        )
    return None


def _path_allowed(path: str) -> bool:
    if not path:
        return False
    if not os.path.isabs(path):
        return False
    resolved = os.path.realpath(path)
    for root in _ALLOWED_KEY_ROOTS:
        root_resolved = os.path.realpath(root)
        if resolved == root_resolved or resolved.startswith(root_resolved + os.sep):
            return True
    return False


def _key_path_rejection(path: str) -> str:
    """Rejection text for a key_path that falls outside the allowed roots.

    The roots are paths *inside this container*, but the natural thing for an
    operator to type is the host path the key actually lives at — which is
    absolute, and really does exist, and is still wrong. The bare "inside
    allowed key roots" wording sent people hunting for a misconfiguration that
    was not there, so name the roots and translate the path they gave.
    """
    roots = ", ".join(_ALLOWED_KEY_ROOTS) or "(none configured)"
    msg = (
        f"key_path {path!r} must be absolute and inside allowed key roots ({roots}). "
        "Keys are mounted into this container from SSH_KEY_DIR, so give the container "
        "path, not the host one"
    )
    base = os.path.basename(path.rstrip("/")) if path else ""
    if base and _ALLOWED_KEY_ROOTS:
        msg += f" — e.g. {os.path.join(_ALLOWED_KEY_ROOTS[0], base)}"
    return msg


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _state_running_nolock() -> bool:
    proc = _state.get("proc")
    if proc is not None:
        return proc.poll() is None
    pid = _state.get("pid")
    return bool(pid and _pid_alive(int(pid)))


def _state_reset_nolock(preserve_error: bool = False) -> None:
    err = _state.get("error", "") if preserve_error else ""
    _state.update(
        {
            "id": "",
            "pid": None,
            "proc": None,
            "ssh_user": "",
            "ssh_host": "",
            "local_socks_port": 0,
            "proxy_host": _PROXY_HOST,
            "proxy_port": 0,
            "started_at": 0.0,
            "auth_method": "",
            "notes": [],
            "error": err,
        }
    )


def _terminate_pid(pid: int) -> None:
    try:
        pgid = os.getpgid(pid)
    except ProcessLookupError:
        return

    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return

    deadline = time.time() + 3.0
    while time.time() < deadline:
        if not _pid_alive(pid):
            return
        time.sleep(0.1)

    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((_BIND_HOST, port))
            return True
        except OSError:
            return False


def _wait_for_listener(port: int, timeout_s: float) -> bool:
    deadline = time.time() + max(0.5, timeout_s)
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.35)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.12)
    return False


def _public_state_nolock() -> Dict[str, Any]:
    running = _state_running_nolock()
    tunnel = None

    if _state.get("id"):
        uptime = 0
        if running and _state.get("started_at"):
            uptime = max(0, int(time.time() - float(_state["started_at"])))
        tunnel = {
            "id": _state.get("id", ""),
            "pid": _state.get("pid"),
            "ssh_user": _state.get("ssh_user", ""),
            "ssh_host": _state.get("ssh_host", ""),
            "local_socks_port": _state.get("local_socks_port", 0),
            "proxy_host": _state.get("proxy_host", _PROXY_HOST),
            "proxy_port": _state.get("proxy_port", 0),
            "auth_method": _state.get("auth_method", ""),
            "notes": list(_state.get("notes") or []),
            "uptime_seconds": uptime,
        }

    return {
        "ok": True,
        "running": running,
        "tunnel": tunnel,
        "error": _state.get("error", ""),
    }


def _build_start_command(payload: Dict[str, Any]) -> Dict[str, Any]:
    auth_method = payload["auth_method"]
    ssh_user = payload["ssh_user"]
    ssh_host = payload["ssh_host"]
    local_port = payload["local_socks_port"]

    key_path = (payload.get("key_path") or _DEFAULT_KEY_PATH).strip()
    password = payload.get("password") or ""
    key_passphrase = payload.get("key_passphrase") or ""

    ssh_cmd = [
        "ssh",
        "-N",
        "-D",
        f"{_BIND_HOST}:{local_port}",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        f"StrictHostKeyChecking={_HOST_KEY_POLICY}",
    ]

    if _HOST_KEY_POLICY == "no":
        # Stateless on purpose: with no store there is nothing to go stale, so a
        # rebuilt far end can never present a "changed" key. Leaving a real file
        # in place under this policy keeps the restrictions ssh applies after a
        # change, for a store that a recreate wipes anyway.
        ssh_cmd.extend([
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "GlobalKnownHostsFile=/dev/null",
        ])

    if auth_method in ("key", "key_passphrase"):
        # IdentitiesOnly confines ssh to the key that was actually selected.
        # Without it a default identity or an agent key can be offered first,
        # and the far end's "Permission denied (publickey)" then describes a key
        # nobody chose — the error has to mean what it says for it to be worth
        # surfacing at all.
        ssh_cmd.extend(["-i", key_path, "-o", "IdentitiesOnly=yes"])
    if auth_method == "password":
        ssh_cmd.extend(["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password"])
    if auth_method == "key":
        ssh_cmd.extend(["-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey"])

    ssh_cmd.append(f"{ssh_user}@{ssh_host}")

    env = os.environ.copy()
    cmd = ssh_cmd
    if auth_method == "password":
        env["SSHPASS"] = password
        cmd = ["sshpass", "-e"] + ssh_cmd
    elif auth_method == "key_passphrase":
        env["SSHPASS"] = key_passphrase
        cmd = ["sshpass", "-e", "-P", "Enter passphrase for key"] + ssh_cmd

    return {"cmd": cmd, "env": env, "key_path": key_path}


def _fallback_key_path(given: str) -> Tuple[str, str]:
    """Resolve a key_path that is not usable, or explain what would be.

    `given` is what the OPERATOR typed, which may be empty — the substituted
    default is deliberately not echoed back, because a message about a path
    nobody chose reads as a misconfiguration that is not there.

    Returns ("", reason) when it cannot be resolved; the reason always names
    what IS present, since "does not exist" on its own sends people looking at
    the mount rather than at the filename.

    Defined here but reliant on _list_available_keys() below: both are only ever
    called at request time.
    """
    what = (
        f"key_path {given!r} does not exist in this container"
        if given else "no key path was given and the configured default is not usable"
    )
    available = _list_available_keys()
    if len(available) == 1:
        only = available[0]["path"]
        return only, f"{what}; used the only key present, {only}"
    if not available:
        roots = ", ".join(_ALLOWED_KEY_ROOTS) or "(none configured)"
        return "", (
            f"{what}, and no keys were found in {roots}. "
            "Upload one from the Infrastructure tab."
        )
    paths = ", ".join(k["path"] for k in available)
    return "", f"{what}. Available: {paths}"


def _resolve_key_auth_method(key_path: str, key_passphrase: str) -> Dict[str, Any]:
    """Pick BatchMode vs sshpass from the KEY, not from the operator's dropdown.

    The two are not interchangeable and the operator cannot see which one a key
    needs. ssh reads the public half out of an ENCRYPTED key without the
    passphrase and offers it quite happily; it only has to decrypt the private
    half at the point the far end ACCEPTS that offer and a signature is due.
    Under BatchMode it cannot prompt there, so it gives up silently and the
    server answers "Permission denied (publickey)" — a message about the far
    end, for a key the far end had just accepted. Deriving the mode here is what
    makes that failure unreachable rather than merely better worded.
    """
    encrypted = _key_is_encrypted(key_path)
    name = os.path.basename(key_path)

    if encrypted is True:
        if not key_passphrase:
            return {
                "ok": False,
                "code": "key_needs_passphrase",
                "error": (
                    f"{name} is passphrase-protected and no passphrase was given. This is "
                    "almost certainly not a problem with the far end: ssh can offer this "
                    "key's public half without the passphrase, so the far end may accept it "
                    "and the attempt still fails as 'Permission denied (publickey)'. Enter "
                    "the key's passphrase and start again, or strip it and re-upload "
                    f"(ssh-keygen -p -N '' -f {name})."
                ),
            }
        return {"ok": True, "auth_method": "key_passphrase", "notes": []}

    if encrypted is False:
        notes = []
        if key_passphrase:
            notes.append(f"{name} has no passphrase — the one supplied was ignored")
        return {"ok": True, "auth_method": "key", "notes": notes}

    # None: a format this parser cannot read. Never block on that — ssh may well
    # handle a key we cannot classify. Fall back to what the operator supplied.
    return {
        "ok": True,
        "auth_method": "key_passphrase" if key_passphrase else "key",
        "notes": [f"could not tell whether {name} is passphrase-protected; used the selected mode"],
    }


def _validate_start_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    ssh_user = str(data.get("ssh_user") or "").strip()
    ssh_host = str(data.get("ssh_host") or "").strip()
    auth_method = str(data.get("auth_method") or "key").strip().lower()

    try:
        local_port = int(data.get("local_socks_port") or 0)
    except (TypeError, ValueError):
        local_port = 0

    if not ssh_user:
        return {"ok": False, "error": "ssh_user is required"}
    if not _USER_RE.match(ssh_user):
        return {"ok": False, "error": "ssh_user contains unsupported characters"}
    if not ssh_host:
        return {"ok": False, "error": "ssh_host is required"}
    if not _HOST_RE.match(ssh_host):
        return {"ok": False, "error": "ssh_host contains unsupported characters"}
    if local_port < 1 or local_port > 65535:
        return {"ok": False, "error": "local_socks_port must be between 1 and 65535"}
    if auth_method not in ("key", "key_passphrase", "password"):
        return {"ok": False, "error": "auth_method must be one of: key, key_passphrase, password"}

    given_key_path = str(data.get("key_path") or "").strip()
    key_path = (given_key_path or _DEFAULT_KEY_PATH) if auth_method in ("key", "key_passphrase") else ""

    notes: List[str] = []

    if auth_method in ("key", "key_passphrase"):
        # Only a path the operator actually typed earns the root rejection. A
        # blank field means they chose nothing, so _DEFAULT_KEY_PATH is OUR
        # guess — and it need not even be inside the roots this deployment
        # configured. Judging it back at them describes a path they never gave.
        if given_key_path and not _path_allowed(key_path):
            return {"ok": False, "error": _key_path_rejection(key_path)}
        if not _path_allowed(key_path) or not os.path.exists(key_path):
            # A filename typo, a SSH_KEY_DIR that did not mount what the
            # operator thinks it did, or a default this deployment never had.
            resolved, why = _fallback_key_path(given_key_path)
            if not resolved:
                return {"ok": False, "code": "key_not_found", "error": why}
            key_path = resolved
            notes.append(why)

    password = str(data.get("password") or "")
    key_passphrase = str(data.get("key_passphrase") or "")

    if len(password) > _MAX_SECRET_LENGTH:
        return {"ok": False, "error": "password exceeds maximum allowed length"}
    if len(key_passphrase) > _MAX_SECRET_LENGTH:
        return {"ok": False, "error": "key_passphrase exceeds maximum allowed length"}

    if auth_method == "password" and not password:
        return {"ok": False, "error": "password auth selected but no password provided"}

    # The key decides which mechanism can actually work; the dropdown is a hint.
    # A missing passphrase for a key that needs one is caught here, by name,
    # instead of six seconds later as the far end's generic rejection.
    requested_auth_method = auth_method
    if auth_method in ("key", "key_passphrase"):
        resolved_auth = _resolve_key_auth_method(key_path, key_passphrase)
        if not resolved_auth.get("ok"):
            return resolved_auth
        auth_method = resolved_auth["auth_method"]
        notes.extend(resolved_auth["notes"])
        if auth_method == "key":
            # Nothing downstream will consume it; do not carry a secret further
            # than the decision that made it irrelevant.
            key_passphrase = ""

    return {
        "ok": True,
        "payload": {
            "ssh_user": ssh_user,
            "ssh_host": ssh_host,
            "auth_method": auth_method,
            "requested_auth_method": requested_auth_method,
            "notes": notes,
            "local_socks_port": local_port,
            "key_path": key_path,
            "password": password,
            "key_passphrase": key_passphrase,
        },
    }


# ════════════════════════════════════════════════════════════════════════════
# Tor
# ════════════════════════════════════════════════════════════════════════════
_tor_lock = threading.Lock()
_tor_state: Dict[str, Any] = {
    "id": "",
    "pid": None,
    "proc": None,
    "socks_port": 0,
    "entry_countries": [],
    "exit_countries": [],
    "strict_nodes": False,
    "started_at": 0.0,
    "bootstrap": 0,
    "error": "",
    "last_log": "",
    "torrc_path": "",
}

_BOOTSTRAP_RE = re.compile(r"Bootstrapped\s+(\d{1,3})%")


def _tor_binary() -> str:
    return shutil.which(_TOR_BIN) or ""


def _tor_running_nolock() -> bool:
    proc = _tor_state.get("proc")
    if proc is not None:
        return proc.poll() is None
    pid = _tor_state.get("pid")
    return bool(pid and _pid_alive(int(pid)))


def _tor_reset_nolock(preserve_error: bool = False) -> None:
    err = _tor_state.get("error", "") if preserve_error else ""
    log = _tor_state.get("last_log", "") if preserve_error else ""
    _tor_state.update(
        {
            "id": "",
            "pid": None,
            "proc": None,
            "socks_port": 0,
            "entry_countries": [],
            "exit_countries": [],
            "strict_nodes": False,
            "started_at": 0.0,
            "bootstrap": 0,
            "error": err,
            "last_log": log,
            "torrc_path": "",
        }
    )


def _normalise_countries(raw: Any) -> Tuple[List[str], str]:
    """Accepts a list or a comma string; returns lowercase ISO alpha-2 codes.

    Rejects anything that is not two letters. This is the only sanitiser between
    a browser field and a torrc line, and a torrc is newline-delimited config —
    so a value carrying a newline would append arbitrary Tor directives.
    """
    if raw is None:
        return [], ""
    if isinstance(raw, str):
        items = [p for p in re.split(r"[,\s]+", raw) if p]
    elif isinstance(raw, (list, tuple)):
        items = [str(p).strip() for p in raw]
    else:
        return [], "country list must be an array or a comma-separated string"

    out: List[str] = []
    for item in items:
        code = item.strip().strip("{}").lower()
        if not code:
            continue
        if not _CC_RE.match(code):
            return [], f"'{item}' is not a two-letter country code"
        if code not in out:
            out.append(code)
    if len(out) > _TOR_MAX_COUNTRIES:
        return [], f"at most {_TOR_MAX_COUNTRIES} countries may be selected"
    return out, ""


def _tor_node_expr(codes: List[str]) -> str:
    return ",".join("{" + c + "}" for c in codes)


def _tor_user_line() -> str:
    """Tor drops privileges itself; we only ask it to when the account exists.

    Running Tor as root works but warns, and the DataDirectory then ends up
    root-owned — which breaks a later start under the unprivileged account.
    """
    if os.geteuid() != 0 or not _TOR_RUN_AS:
        return ""
    try:
        pwd.getpwnam(_TOR_RUN_AS)
    except KeyError:
        return ""
    return f"User {_TOR_RUN_AS}\n"


def _tor_prepare_data_dir() -> str:
    data_dir = os.path.join(_TOR_DATA_DIR, "data")
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    if os.geteuid() == 0 and _TOR_RUN_AS:
        try:
            ent = pwd.getpwnam(_TOR_RUN_AS)
            os.chown(_TOR_DATA_DIR, ent.pw_uid, ent.pw_gid)
            os.chown(data_dir, ent.pw_uid, ent.pw_gid)
        except (KeyError, OSError):
            pass
    os.chmod(data_dir, 0o700)
    return data_dir


def _tor_write_torrc(socks_port: int, entry: List[str], exit_: List[str], strict: bool) -> str:
    data_dir = _tor_prepare_data_dir()
    lines = [
        "# Generated by SPOTTER ssh-tunnel-api. Rewritten on every Tor start.",
        f"SocksPort {_BIND_HOST}:{socks_port}",
        f"DataDirectory {data_dir}",
        "ClientOnly 1",
        "AvoidDiskWrites 1",
        "Log notice stdout",
    ]
    for policy in [p.strip() for p in _TOR_SOCKS_POLICY.split(",") if p.strip()]:
        lines.append(f"SocksPolicy {policy}")
    if os.path.exists(_TOR_GEOIP):
        lines.append(f"GeoIPFile {_TOR_GEOIP}")
    if os.path.exists(_TOR_GEOIP6):
        lines.append(f"GeoIPv6File {_TOR_GEOIP6}")
    if entry:
        lines.append(f"EntryNodes {_tor_node_expr(entry)}")
    if exit_:
        lines.append(f"ExitNodes {_tor_node_expr(exit_)}")
    # StrictNodes only means anything alongside a node restriction. Without one
    # it is noise; with one it turns "prefer" into "fail rather than leave".
    if (entry or exit_) and strict:
        lines.append("StrictNodes 1")

    user_line = _tor_user_line()
    body = "\n".join(lines) + "\n" + user_line

    path = os.path.join(_TOR_DATA_DIR, "torrc")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(path, 0o644)
    return path


def _tor_log_pump(proc: subprocess.Popen) -> None:
    """Follows tor's stdout so bootstrap progress is observable.

    Without this the pipe fills and Tor blocks on write; with it, the operator
    gets the one number that distinguishes "listening but useless" (0%) from
    "usable circuit" (100%), which a bare port check cannot tell apart.
    """
    stream = proc.stdout
    if stream is None:
        return
    for line in iter(stream.readline, ""):
        line = line.strip()
        if not line:
            continue
        with _tor_lock:
            if _tor_state.get("proc") is not proc:
                return
            m = _BOOTSTRAP_RE.search(line)
            if m:
                try:
                    _tor_state["bootstrap"] = max(0, min(100, int(m.group(1))))
                except ValueError:
                    pass
            if "[warn]" in line or "[err]" in line or m:
                _tor_state["last_log"] = line[:400]
    try:
        stream.close()
    except Exception:
        pass


def _tor_public_nolock() -> Dict[str, Any]:
    running = _tor_running_nolock()
    tor = None
    if _tor_state.get("id"):
        uptime = 0
        if running and _tor_state.get("started_at"):
            uptime = max(0, int(time.time() - float(_tor_state["started_at"])))
        tor = {
            "id": _tor_state.get("id", ""),
            "pid": _tor_state.get("pid"),
            "socks_host": _PROXY_HOST,
            "socks_port": _tor_state.get("socks_port", 0),
            "entry_countries": list(_tor_state.get("entry_countries") or []),
            "exit_countries": list(_tor_state.get("exit_countries") or []),
            "strict_nodes": bool(_tor_state.get("strict_nodes")),
            "bootstrap_percent": int(_tor_state.get("bootstrap") or 0),
            "bootstrapped": int(_tor_state.get("bootstrap") or 0) >= 100,
            "uptime_seconds": uptime,
        }
    return {
        "ok": True,
        "available": bool(_tor_binary()),
        "running": running,
        "tor": tor,
        "error": _tor_state.get("error", ""),
        "last_log": _tor_state.get("last_log", ""),
    }


# ── country catalogue ────────────────────────────────────────────────────────
# The authoritative list is the geoip file the LOCAL tor build ships: offering a
# country Tor cannot resolve produces a circuit that silently never builds.
_ISO3166: Dict[str, str] = {
    "ad": "Andorra", "ae": "United Arab Emirates", "af": "Afghanistan", "ag": "Antigua and Barbuda",
    "ai": "Anguilla", "al": "Albania", "am": "Armenia", "ao": "Angola", "aq": "Antarctica",
    "ar": "Argentina", "as": "American Samoa", "at": "Austria", "au": "Australia", "aw": "Aruba",
    "ax": "Aland Islands", "az": "Azerbaijan", "ba": "Bosnia and Herzegovina", "bb": "Barbados",
    "bd": "Bangladesh", "be": "Belgium", "bf": "Burkina Faso", "bg": "Bulgaria", "bh": "Bahrain",
    "bi": "Burundi", "bj": "Benin", "bl": "Saint Barthelemy", "bm": "Bermuda", "bn": "Brunei",
    "bo": "Bolivia", "bq": "Bonaire", "br": "Brazil", "bs": "Bahamas", "bt": "Bhutan",
    "bv": "Bouvet Island", "bw": "Botswana", "by": "Belarus", "bz": "Belize", "ca": "Canada",
    "cc": "Cocos Islands", "cd": "DR Congo", "cf": "Central African Republic", "cg": "Congo",
    "ch": "Switzerland", "ci": "Cote d'Ivoire", "ck": "Cook Islands", "cl": "Chile",
    "cm": "Cameroon", "cn": "China", "co": "Colombia", "cr": "Costa Rica", "cu": "Cuba",
    "cv": "Cabo Verde", "cw": "Curacao", "cx": "Christmas Island", "cy": "Cyprus",
    "cz": "Czechia", "de": "Germany", "dj": "Djibouti", "dk": "Denmark", "dm": "Dominica",
    "do": "Dominican Republic", "dz": "Algeria", "ec": "Ecuador", "ee": "Estonia", "eg": "Egypt",
    "eh": "Western Sahara", "er": "Eritrea", "es": "Spain", "et": "Ethiopia", "fi": "Finland",
    "fj": "Fiji", "fk": "Falkland Islands", "fm": "Micronesia", "fo": "Faroe Islands",
    "fr": "France", "ga": "Gabon", "gb": "United Kingdom", "gd": "Grenada", "ge": "Georgia",
    "gf": "French Guiana", "gg": "Guernsey", "gh": "Ghana", "gi": "Gibraltar", "gl": "Greenland",
    "gm": "Gambia", "gn": "Guinea", "gp": "Guadeloupe", "gq": "Equatorial Guinea", "gr": "Greece",
    "gs": "South Georgia", "gt": "Guatemala", "gu": "Guam", "gw": "Guinea-Bissau", "gy": "Guyana",
    "hk": "Hong Kong", "hm": "Heard Island", "hn": "Honduras", "hr": "Croatia", "ht": "Haiti",
    "hu": "Hungary", "id": "Indonesia", "ie": "Ireland", "il": "Israel", "im": "Isle of Man",
    "in": "India", "io": "British Indian Ocean Territory", "iq": "Iraq", "ir": "Iran",
    "is": "Iceland", "it": "Italy", "je": "Jersey", "jm": "Jamaica", "jo": "Jordan",
    "jp": "Japan", "ke": "Kenya", "kg": "Kyrgyzstan", "kh": "Cambodia", "ki": "Kiribati",
    "km": "Comoros", "kn": "Saint Kitts and Nevis", "kp": "North Korea", "kr": "South Korea",
    "kw": "Kuwait", "ky": "Cayman Islands", "kz": "Kazakhstan", "la": "Laos", "lb": "Lebanon",
    "lc": "Saint Lucia", "li": "Liechtenstein", "lk": "Sri Lanka", "lr": "Liberia",
    "ls": "Lesotho", "lt": "Lithuania", "lu": "Luxembourg", "lv": "Latvia", "ly": "Libya",
    "ma": "Morocco", "mc": "Monaco", "md": "Moldova", "me": "Montenegro", "mf": "Saint Martin",
    "mg": "Madagascar", "mh": "Marshall Islands", "mk": "North Macedonia", "ml": "Mali",
    "mm": "Myanmar", "mn": "Mongolia", "mo": "Macao", "mp": "Northern Mariana Islands",
    "mq": "Martinique", "mr": "Mauritania", "ms": "Montserrat", "mt": "Malta", "mu": "Mauritius",
    "mv": "Maldives", "mw": "Malawi", "mx": "Mexico", "my": "Malaysia", "mz": "Mozambique",
    "na": "Namibia", "nc": "New Caledonia", "ne": "Niger", "nf": "Norfolk Island",
    "ng": "Nigeria", "ni": "Nicaragua", "nl": "Netherlands", "no": "Norway", "np": "Nepal",
    "nr": "Nauru", "nu": "Niue", "nz": "New Zealand", "om": "Oman", "pa": "Panama",
    "pe": "Peru", "pf": "French Polynesia", "pg": "Papua New Guinea", "ph": "Philippines",
    "pk": "Pakistan", "pl": "Poland", "pm": "Saint Pierre and Miquelon", "pn": "Pitcairn",
    "pr": "Puerto Rico", "ps": "Palestine", "pt": "Portugal", "pw": "Palau", "py": "Paraguay",
    "qa": "Qatar", "re": "Reunion", "ro": "Romania", "rs": "Serbia", "ru": "Russia",
    "rw": "Rwanda", "sa": "Saudi Arabia", "sb": "Solomon Islands", "sc": "Seychelles",
    "sd": "Sudan", "se": "Sweden", "sg": "Singapore", "sh": "Saint Helena", "si": "Slovenia",
    "sj": "Svalbard and Jan Mayen", "sk": "Slovakia", "sl": "Sierra Leone", "sm": "San Marino",
    "sn": "Senegal", "so": "Somalia", "sr": "Suriname", "ss": "South Sudan",
    "st": "Sao Tome and Principe", "sv": "El Salvador", "sx": "Sint Maarten", "sy": "Syria",
    "sz": "Eswatini", "tc": "Turks and Caicos Islands", "td": "Chad",
    "tf": "French Southern Territories", "tg": "Togo", "th": "Thailand", "tj": "Tajikistan",
    "tk": "Tokelau", "tl": "Timor-Leste", "tm": "Turkmenistan", "tn": "Tunisia", "to": "Tonga",
    "tr": "Turkiye", "tt": "Trinidad and Tobago", "tv": "Tuvalu", "tw": "Taiwan",
    "tz": "Tanzania", "ua": "Ukraine", "ug": "Uganda", "um": "US Minor Outlying Islands",
    "us": "United States", "uy": "Uruguay", "uz": "Uzbekistan", "va": "Vatican City",
    "vc": "Saint Vincent and the Grenadines", "ve": "Venezuela", "vg": "British Virgin Islands",
    "vi": "US Virgin Islands", "vn": "Vietnam", "vu": "Vanuatu", "wf": "Wallis and Futuna",
    "ws": "Samoa", "ye": "Yemen", "yt": "Mayotte", "za": "South Africa", "zm": "Zambia",
    "zw": "Zimbabwe",
}

_countries_cache: Dict[str, Any] = {"codes": None, "source": ""}


def _read_geoip_countries() -> Tuple[List[str], str]:
    codes = set()
    used = []
    for path in (_TOR_GEOIP, _TOR_GEOIP6):
        if not path or not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    cc = line.rsplit(",", 1)[-1].strip().lower()
                    if _CC_RE.match(cc) and cc != "??":
                        codes.add(cc)
            used.append(path)
        except OSError:
            continue
    return sorted(codes), ",".join(used)


def _country_catalogue() -> Dict[str, Any]:
    if _countries_cache["codes"] is None:
        codes, source = _read_geoip_countries()
        if not codes:
            codes, source = sorted(_ISO3166.keys()), "iso3166-builtin"
        _countries_cache["codes"] = codes
        _countries_cache["source"] = source
    codes = _countries_cache["codes"]
    return {
        "ok": True,
        "source": _countries_cache["source"],
        "count": len(codes),
        "countries": [{"code": c, "name": _ISO3166.get(c, c.upper())} for c in codes],
    }


@app.get("/tunnel/tor/countries")
def tor_countries() -> Any:
    return jsonify(_country_catalogue())


@app.get("/tunnel/tor/status")
def tor_status() -> Any:
    with _tor_lock:
        if not _tor_running_nolock() and _tor_state.get("id"):
            _tor_state["error"] = _tor_state.get("error") or "Tor process is not running"
            _tor_state["pid"] = None
            _tor_state["proc"] = None
        return jsonify(_tor_public_nolock())


@app.post("/tunnel/tor/start")
def tor_start() -> Any:
    data = request.get_json(force=True, silent=True) or {}

    binary = _tor_binary()
    if not binary:
        return _error_json(
            "tor is not installed in this container. Rebuild the ssh-tunnel-api image.",
            501,
            "tor_unavailable",
        )

    entry, err = _normalise_countries(data.get("entry_countries"))
    if err:
        return _error_json("entry_countries: " + err, 400, "invalid_request")
    exit_, err = _normalise_countries(data.get("exit_countries"))
    if err:
        return _error_json("exit_countries: " + err, 400, "invalid_request")

    try:
        socks_port = int(data.get("socks_port") or _TOR_SOCKS_PORT)
    except (TypeError, ValueError):
        socks_port = 0
    if socks_port < 1 or socks_port > 65535:
        return _error_json("socks_port must be between 1 and 65535", 400, "invalid_request")

    strict = bool(data.get("strict_nodes"))

    with _tor_lock:
        if _tor_running_nolock():
            return (
                jsonify(
                    {
                        "ok": False,
                        "code": "already_running",
                        "error": "Tor is already running. Stop it before starting another instance.",
                        "running": True,
                        "tor": _tor_public_nolock().get("tor"),
                    }
                ),
                409,
            )

        if not _port_available(socks_port):
            return _error_json("Requested socks_port is already in use", 409, "port_in_use")

        try:
            torrc_path = _tor_write_torrc(socks_port, entry, exit_, strict)
        except OSError as exc:
            _tor_state["error"] = f"Could not write torrc: {exc}"
            return _error_json(_tor_state["error"], 500, "torrc_failed")

        try:
            proc = subprocess.Popen(
                [binary, "-f", torrc_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=os.setsid,
            )
        except Exception as exc:
            _tor_state["error"] = f"Failed to start tor: {exc}"
            return _error_json(_tor_state["error"], 500, "start_failed")

        _tor_reset_nolock()
        _tor_state.update(
            {
                "id": str(uuid.uuid4()),
                "pid": proc.pid,
                "proc": proc,
                "socks_port": socks_port,
                "entry_countries": entry,
                "exit_countries": exit_,
                "strict_nodes": strict,
                "started_at": time.time(),
                "bootstrap": 0,
                "error": "",
                "last_log": "",
                "torrc_path": torrc_path,
            }
        )

    threading.Thread(target=_tor_log_pump, args=(proc,), daemon=True).start()

    # Return as soon as the SOCKS port answers — NOT when bootstrap hits 100%.
    # nginx caps this location at 30s, and a first-run Tor can take longer than
    # that to build a circuit; the UI polls /tunnel/tor/status for progress.
    if not _wait_for_listener(socks_port, _TOR_STARTUP_TIMEOUT):
        with _tor_lock:
            last = _tor_state.get("last_log", "")
            _terminate_pid(proc.pid)
            _tor_reset_nolock()
            _tor_state["error"] = "Tor did not open its SOCKS listener in time" + (
                " — " + last if last else ""
            )
            _tor_state["last_log"] = last
            return _error_json(_tor_state["error"], 500, "listener_timeout")

    with _tor_lock:
        return jsonify(_tor_public_nolock())


@app.post("/tunnel/tor/stop")
def tor_stop() -> Any:
    with _tor_lock:
        if not _tor_running_nolock():
            _tor_reset_nolock()
            return jsonify({"ok": True, "running": False, "tor": None, "error": ""})
        pid = int(_tor_state.get("pid") or 0)
        if pid:
            _terminate_pid(pid)
        _tor_reset_nolock()
        return jsonify({"ok": True, "running": False, "tor": None, "error": ""})


# ════════════════════════════════════════════════════════════════════════════
# Egress identity (IP-reflection sources, see _EGRESS_URLS)
# ════════════════════════════════════════════════════════════════════════════
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")


def _valid_public_ip(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return ""
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return ""
    return str(addr)


def _first_ip_in_text(text: str) -> str:
    for match in _IPV4_RE.findall(text or ""):
        ip = _valid_public_ip(match)
        if ip:
            return ip
    for match in _IPV6_RE.findall(text or ""):
        ip = _valid_public_ip(match)
        if ip:
            return ip
    return ""


_GEO_KEYS = {
    "country": ("country", "country_name", "countryname", "country_full"),
    "country_code": ("country_code", "countrycode", "country_iso", "countryiso", "cc",
                     "country_code_iso3166", "country_iso_code"),
    "city": ("city", "city_name", "cityname"),
    "region": ("region", "region_name", "state", "subdivision", "province"),
    "org": ("org", "organisation", "organization", "isp", "asn_org", "as_org", "asorganization",
            "company", "company_name"),
    "asn": ("asn", "as", "asn_number", "autonomous_system_number", "as_number"),
    "hostname": ("hostname", "host", "reverse", "rdns", "ptr"),
    "timezone": ("timezone", "time_zone", "tz", "timezone_id"),
    "latitude": ("latitude", "lat"),
    "longitude": ("longitude", "lon", "lng", "long"),
}


def _flatten_one_level(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Geo fields may sit at the top level or one dict down (``{"location":
    {...}}``). One level of flattening handles both without pinning the parser
    to a schema this code cannot verify from inside the deployment."""
    flat: Dict[str, Any] = {}
    for k, v in obj.items():
        key = str(k).strip().lower().replace("-", "_")
        if isinstance(v, dict):
            for k2, v2 in v.items():
                sub = str(k2).strip().lower().replace("-", "_")
                flat.setdefault(sub, v2)
                flat.setdefault(f"{key}_{sub}", v2)
        else:
            flat.setdefault(key, v)
    return flat


def _normalise_geo(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    # Several of these APIs answer HTTP 200 with {"success": false, "message":
    # ...} for an address they cannot place. Harvesting fields out of that body
    # would put a half-built location on the strip, which is worse than none:
    # the operator reads this bar to confirm a country, so a wrong one is the
    # one failure mode that must not be possible.
    if payload.get("success") is False:
        return {}
    flat = _flatten_one_level(payload)
    geo: Dict[str, Any] = {}
    for field, candidates in _GEO_KEYS.items():
        for cand in candidates:
            if cand in flat and flat[cand] not in (None, "", []):
                value = flat[cand]
                geo[field] = value if isinstance(value, (int, float)) else str(value).strip()
                break
    code = str(geo.get("country_code") or "")
    if len(code) == 2:
        geo["country_code"] = code.upper()
        geo.setdefault("country", _ISO3166.get(code.lower(), code.upper()))
    # Some sources give the ASN as a bare number (ipwho.is: 64500), others
    # already prefixed ("AS64500 Example Transit"). The strip renders
    # "<asn> <org>" verbatim, so normalise here rather than teaching the
    # frontend which vendor answered.
    asn = geo.get("asn")
    if isinstance(asn, (int, float)) and not isinstance(asn, bool):
        geo["asn"] = f"AS{int(asn)}"
    elif isinstance(asn, str) and asn.strip().isdigit():
        geo["asn"] = f"AS{asn.strip()}"
    return geo


def _ip_from_payload(payload: Any) -> str:
    if isinstance(payload, dict):
        flat = _flatten_one_level(payload)
        for key in ("ip", "ip_address", "ipaddress", "address", "query", "client_ip", "your_ip"):
            if key in flat:
                ip = _valid_public_ip(str(flat[key]))
                if ip:
                    return ip
    return ""


def _proxy_from_spec(spec: Any) -> Tuple[Optional[Dict[str, str]], str, str]:
    """(requests proxies dict | None, human label, error).

    None with no error means "direct" — which is a legitimate answer, and the
    caller renders it as such rather than as a failed check.
    """
    if not isinstance(spec, dict) or not spec:
        return None, "direct", ""
    if not spec.get("enabled", True):
        return None, "direct", ""

    ptype = str(spec.get("type") or "none").strip().lower()
    if ptype in ("", "none"):
        return None, "direct", ""

    if ptype == "http":
        url = str(spec.get("http_url") or "").strip()
        if not url:
            return None, "", "proxy.type is http but http_url is empty"
        if not re.match(r"^https?://", url):
            return None, "", "http_url must start with http:// or https://"
        return {"http": url, "https": url}, "HTTP proxy", ""

    if ptype in ("socks5", "socks", "tor"):
        url = str(spec.get("socks_url") or "").strip()
        if not url:
            socks = spec.get("socks") if isinstance(spec.get("socks"), dict) else {}
            host = str(socks.get("host") or "").strip()
            try:
                port = int(socks.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
            if ptype == "tor" and not host:
                with _tor_lock:
                    host = _PROXY_HOST
                    port = int(_tor_state.get("socks_port") or 0) or _TOR_SOCKS_PORT
            if not host or port < 1 or port > 65535:
                return None, "", f"proxy.type is {ptype} but no usable SOCKS host/port was given"
            if not _HOST_RE.match(host):
                return None, "", "SOCKS host contains unsupported characters"
            user = str(socks.get("username") or "").strip()
            pwd_ = str(socks.get("password") or "")
            auth = ""
            if user:
                from urllib.parse import quote

                auth = quote(user, safe="") + (":" + quote(pwd_, safe="") if pwd_ else "") + "@"
            # socks5h: resolve DNS at the proxy, never locally. A local lookup
            # leaks the query to the host resolver and defeats the point of Tor.
            url = f"socks5h://{auth}{host}:{port}"
        elif not url.startswith("socks5"):
            return None, "", "socks_url must be a socks5:// or socks5h:// URL"
        return {"http": url, "https": url}, ("Tor" if ptype == "tor" else "SOCKS5 proxy"), ""

    return None, "", f"unsupported proxy type '{ptype}'"


@app.post("/tunnel/egress")
def egress_check() -> Any:
    try:
        import requests  # noqa: WPS433 — deliberately lazy, see below
    except ImportError:
        # Lazy so that an image built before this endpoint existed still serves
        # the SSH tunnel control plane instead of failing to import at boot.
        return _error_json(
            "requests is not installed in this container. Rebuild the ssh-tunnel-api image.",
            501,
            "requests_unavailable",
        )

    data = request.get_json(force=True, silent=True) or {}
    proxies, via, err = _proxy_from_spec(data.get("proxy"))
    if err:
        return _error_json(err, 400, "invalid_request")

    user_agent = str(data.get("user_agent") or "").strip()[:512]
    try:
        timeout = float(data.get("timeout") or _EGRESS_TIMEOUT)
    except (TypeError, ValueError):
        timeout = _EGRESS_TIMEOUT
    timeout = max(2.0, min(20.0, timeout))

    # trust_env=False so that "direct" means direct. An HTTP_PROXY inherited
    # from the container environment would otherwise silently proxy a check
    # whose whole job is to report, truthfully, which route was taken.
    sess = requests.Session()
    sess.trust_env = False

    errors: List[str] = []
    started = time.time()
    deadline = started + _EGRESS_BUDGET
    ip = ""
    geo: Dict[str, Any] = {}
    source = ""
    ua_used = user_agent or _EGRESS_FALLBACK_UA

    def attempt(url: str, ua: str) -> Tuple[str, Dict[str, Any], str]:
        remaining = deadline - time.time()
        if remaining <= 1.0:
            raise TimeoutError("egress time budget exhausted")
        headers = {"User-Agent": ua, "Accept": "application/json, text/plain, */*"}
        resp = sess.get(url, headers=headers, proxies=proxies,
                        timeout=min(timeout, remaining), allow_redirects=True)
        body = (resp.text or "").strip()
        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}")
        payload: Any = None
        ctype = (resp.headers.get("content-type") or "").lower()
        if "json" in ctype or body[:1] in ("{", "["):
            try:
                payload = json.loads(body)
            except ValueError:
                payload = None
        found = _ip_from_payload(payload)
        if not found:
            # Plain text (just the IP) or an HTML page with it embedded.
            found = _valid_public_ip(body) or _first_ip_in_text(body)
        return found, _normalise_geo(payload), body[:120]

    for url in _EGRESS_URLS:
        if time.time() >= deadline - 1.0:
            errors.append("stopped: egress time budget exhausted before " + url)
            break
        for ua in ([ua_used] if ua_used == _EGRESS_FALLBACK_UA else [ua_used, _EGRESS_FALLBACK_UA]):
            try:
                found, found_geo, _snippet = attempt(url, ua)
            except Exception as exc:  # network, proxy, TLS, timeout — all reportable
                errors.append(f"{url}: {type(exc).__name__}: {str(exc)[:180]}")
                break
            if found:
                ip, geo, source, ua_used = found, found_geo, url, ua
                break
            errors.append(f"{url}: no public IP found in response (UA {ua})")
        if ip:
            break

    geo_source = source if geo else ""
    if ip and not geo and _EGRESS_GEO_URL and time.time() < deadline - 1.0:
        try:
            resp = sess.get(
                _EGRESS_GEO_URL.replace("{ip}", ip),
                headers={"User-Agent": ua_used, "Accept": "application/json"},
                proxies=proxies,
                timeout=min(timeout, deadline - time.time()),
            )
            if resp.status_code < 400:
                found_geo = _normalise_geo(resp.json())
                # Only claim a geo_source when the hop actually produced a
                # location — an attributed-but-empty geo reads as a rendering
                # bug when it is really "the lookup declined to place this IP".
                if found_geo:
                    geo, geo_source = found_geo, _EGRESS_GEO_URL
                else:
                    errors.append(f"geo lookup: {_EGRESS_GEO_URL} could not place {ip}")
            else:
                errors.append(f"geo lookup: HTTP {resp.status_code}")
        except Exception as exc:
            errors.append(f"geo lookup: {type(exc).__name__}: {str(exc)[:180]}")

    return jsonify(
        {
            # ok:false here is HTTP 200 on purpose — the check ran, it just
            # could not establish an identity, and errors[] says why. The UI
            # renders that; it must not be collapsed into a thrown string.
            "ok": bool(ip),
            "error": "" if ip else "No usable public IP was returned by any configured source",
            "ip": ip,
            "geo": geo,
            "via": via,
            "proxied": proxies is not None,
            "source": source,
            "geo_source": geo_source,
            "user_agent": ua_used,
            "elapsed_ms": int((time.time() - started) * 1000),
            "checked_at": int(time.time()),
            "errors": errors,
        }
    )


@app.get("/health")
def health() -> Any:
    with _tor_lock:
        tor_running = _tor_running_nolock()
    return jsonify({"ok": True, "tor_available": bool(_tor_binary()), "tor_running": tor_running})


@app.get("/tunnel/status")
def tunnel_status() -> Any:
    with _lock:
        running = _state_running_nolock()
        if not running and _state.get("id"):
            _state["error"] = _state.get("error") or "Tunnel process is not running"
            _state["pid"] = None
            _state["proc"] = None
        return jsonify(_public_state_nolock())


# Filenames that live in a .ssh directory but are never a usable identity.
_NON_KEY_NAMES = {"authorized_keys", "known_hosts", "known_hosts.old", "config", "environment"}
_NON_KEY_SUFFIXES = (".pub", ".old", ".bak", ".cert", ".crt", ".sig")


def _looks_like_private_key_bytes(head: bytes) -> bool:
    """The same test _looks_like_private_key() applies, on bytes in hand.

    Split out so an upload can be rejected before anything touches disk.
    """
    return b"PRIVATE KEY" in head[:64]


def _looks_like_private_key(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
    except OSError:
        return False
    return _looks_like_private_key_bytes(head)


def _key_is_encrypted(path: str) -> Optional[bool]:
    """True, False, or None when the format is not one we can read.

    Read out of the file rather than shelled out to ssh-keygen: deterministic,
    no subprocess, and — unlike a non-zero exit status — it cannot confuse "this
    key has a passphrase" with "this file is not a key at all".
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read(8192)
    except OSError:
        return None
    return _key_is_encrypted_text(text)


def _key_is_encrypted_text(text: str) -> Optional[bool]:
    """The body of _key_is_encrypted(), on text in hand rather than a path."""
    if "BEGIN ENCRYPTED PRIVATE KEY" in text:
        return True
    if "Proc-Type:" in text and "ENCRYPTED" in text:
        return True                                  # legacy PEM

    marker = "-----BEGIN OPENSSH PRIVATE KEY-----"
    if marker in text:
        body = text.split(marker, 1)[1].split("-----END", 1)[0]
        try:
            blob = base64.b64decode("".join(body.split()))
        except Exception:
            return None
        magic = b"openssh-key-v1\x00"
        if not blob.startswith(magic):
            return None
        rest = blob[len(magic):]
        if len(rest) < 4:
            return None
        n = int.from_bytes(rest[:4], "big")
        if n <= 0 or len(rest) < 4 + n:
            return None
        # openssh-key-v1 stores the cipher first; "none" means no passphrase.
        return rest[4:4 + n].decode("ascii", "replace") != "none"

    return False if "PRIVATE KEY" in text else None


def _list_available_keys() -> List[Dict[str, Any]]:
    keys: List[Dict[str, Any]] = []
    seen = set()
    for root in _ALLOWED_KEY_ROOTS:
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            if name in _NON_KEY_NAMES or name.startswith("."):
                continue
            if name.endswith(_NON_KEY_SUFFIXES):
                continue
            path = os.path.join(root, name)
            if not os.path.isfile(path):
                continue
            # Dedup on identity, not on the path string: SSH_KEY_DIR and the
            # upload root are commonly the SAME host directory bound at two
            # container paths, and a path-keyed check would list every key twice.
            try:
                st = os.stat(path)
                ident: Any = (st.st_dev, st.st_ino)
            except OSError:
                ident = path
            if ident in seen:
                continue
            if not _path_allowed(path) or not _looks_like_private_key(path):
                continue
            seen.add(ident)
            keys.append({"path": path, "name": name, "encrypted": _key_is_encrypted(path)})
    return keys


def _drain_stderr(proc: subprocess.Popen) -> str:
    """The meaningful tail of what ssh wrote, or "" if it said nothing.

    Keeps the last three lines rather than one: the line that names the cause is
    often the one BEFORE the verdict — "Load key ...: incorrect passphrase" or
    "bad passphrase given, try again..." precede a bare "Permission denied".
    """
    try:
        raw = (proc.stderr.read() if proc.stderr else "") or ""
    except Exception:
        return ""
    lines = [ln.strip() for ln in raw.strip().splitlines() if ln.strip()]
    # sshpass echoes the prompt it was answering; that is noise, not a cause.
    _noise = ("enter passphrase", "warning: permanently added")
    lines = [ln for ln in lines if not ln.lower().startswith(_noise)]
    return " / ".join(lines[-3:])[:300] if lines else ""


def _pubkey_hint(detail: str) -> str:
    """The next step after a pubkey rejection, wherever one surfaces.

    Only reachable once the auth mode is known to match the key, so a pubkey
    rejection here really is what it appears to be: the far end has no matching
    entry. Shared by both failure branches — a far end that refuses quickly
    exits before the listener check ever runs, and used to get no explanation at
    all purely because it was fast.
    """
    if "permission denied (publickey)" not in detail.lower():
        return ""
    # ssh's own line already ends in a full stop; a second one reads as a typo.
    sep = " " if detail.rstrip().endswith((".", "!", "?")) else ". "
    return (
        f"{sep}The far end has no authorized_keys entry for this key — use 'Show public key' "
        "on this tab and add that line to ~/.ssh/authorized_keys for this user on the "
        "remote host"
    )


def _listener_timeout_error(detail: str, auth_method: str) -> str:
    base = "Tunnel did not open local SOCKS listener in time"
    if detail:
        return f"{base} — ssh said: {detail}{_pubkey_hint(detail)}"
    if auth_method == "key_passphrase":
        # sshpass answers exactly one prompt. A wrong passphrase makes ssh ask
        # again, nothing answers, and ssh sits there mute until it is killed —
        # so silence here is itself the diagnosis.
        return (
            f"{base}, and ssh printed nothing. With a passphrase-protected key that "
            "usually means the passphrase was wrong: ssh re-prompted and nothing "
            "answered. Verify it with: ssh-keygen -y -f <key>"
        )
    return f"{base}, and ssh printed nothing — check that the host is reachable from the sidecar"


@app.get("/tunnel/keys")
def tunnel_keys() -> Any:
    """The identities actually present in the allowed roots.

    The key path is typed by hand into a form and saved in the browser, so it
    outlives any change to SSH_KEY_DIR: repointing the mount leaves a saved
    path that resolves to nothing, and the operator has no way to see what the
    container can actually reach. This endpoint is that visibility.
    """
    keys = _list_available_keys()
    return jsonify({
        "ok": True,
        "roots": list(_ALLOWED_KEY_ROOTS),
        "default_key_path": _DEFAULT_KEY_PATH,
        "keys": keys,
        "count": len(keys),
    })


# ── Key upload ───────────────────────────────────────────────────────────────
# Writes are admin-only. nginx stamps X-Spotter-Admin onto every /infra/tunnel/
# request from the auth subrequest (frontend/nginx.conf) and proxy_set_header
# OVERWRITES whatever the client sent, so the header is exactly as trustworthy
# as the session gate in front of it — which is the same thing the rest of this
# service already relies on. It is never read from a request that did not come
# through that gate, because n8n and the sidecars have no host port.
_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _is_admin_request() -> bool:
    return (request.headers.get("X-Spotter-Admin") or "").strip() == "1"


def _forbidden() -> Any:
    return _error_json(
        "Key management requires an administrator account",
        403,
        "forbidden",
    )


def _upload_root_error() -> Optional[Any]:
    """Refuse writes when the upload root is missing or not actually allowed.

    A root outside _ALLOWED_KEY_ROOTS would accept an upload and then have
    /tunnel/start reject the very key it just wrote, which is the kind of
    half-working state that costs an afternoon.
    """
    if not _UPLOAD_KEY_ROOT or not os.path.isabs(_UPLOAD_KEY_ROOT):
        return _error_json(
            "TUNNEL_UPLOAD_KEY_ROOT is not configured with an absolute path",
            500,
            "upload_root_unset",
        )
    if not _path_allowed(_UPLOAD_KEY_ROOT):
        return _error_json(
            f"Upload root {_UPLOAD_KEY_ROOT} is not inside the allowed key roots "
            f"({', '.join(_ALLOWED_KEY_ROOTS) or 'none'}) — a key written there could "
            "not then be used to start a tunnel",
            500,
            "upload_root_not_allowed",
        )
    if not os.path.isdir(_UPLOAD_KEY_ROOT):
        return _error_json(
            f"Upload root {_UPLOAD_KEY_ROOT} is not mounted into this container",
            500,
            "upload_root_missing",
        )
    if not os.access(_UPLOAD_KEY_ROOT, os.W_OK):
        return _error_json(
            f"Upload root {_UPLOAD_KEY_ROOT} is mounted read-only — bind it rw to "
            "accept uploads",
            500,
            "upload_root_readonly",
        )
    return None


def _validate_key_name(raw: Any) -> str:
    """Return a safe basename, or raise ValueError with the reason.

    basename() first, so a traversal or an absolute path cannot survive; then a
    strict whitelist, which also excludes dotfiles. Names that _list_available_keys()
    filters out are refused here too — a key accepted by the uploader but invisible
    in the list afterwards looks exactly like a silent failure.
    """
    given = (raw or "").strip()
    if not given:
        raise ValueError("a filename is required")
    name = os.path.basename(given)
    # Refuse rather than silently rewrite. basename() alone would turn
    # "../escape" into "escape" and accept it: safe, but it writes a file the
    # operator did not ask for under a name they did not choose, and reports
    # success. A path that is not already a bare filename is an error.
    if name != given:
        raise ValueError(
            "filename must be a bare filename, not a path — "
            f"{given!r} contains a directory component"
        )
    if not _KEY_NAME_RE.match(name):
        raise ValueError(
            "filename must be 1-64 characters of letters, digits, dot, dash or "
            "underscore, and may not begin with a dot"
        )
    if name in _NON_KEY_NAMES:
        raise ValueError(f"{name!r} is an SSH config file, not an identity")
    if name.endswith(_NON_KEY_SUFFIXES):
        raise ValueError(
            f"{name!r} ends with a suffix reserved for public halves and backups "
            f"({', '.join(_NON_KEY_SUFFIXES)})"
        )
    return name


def _normalise_key_bytes(blob: bytes) -> bytes:
    """CRLF -> LF, and guarantee the trailing newline OpenSSH expects.

    A key pasted out of Notepad or a browser textarea otherwise fails inside ssh
    with nothing useful on stderr, which is indistinguishable from a wrong key.
    """
    blob = blob.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if not blob.endswith(b"\n"):
        blob += b"\n"
    return blob


def _key_fingerprint(path: str) -> Optional[str]:
    """ssh-keygen -lf. Reads an ENCRYPTED key without needing its passphrase."""
    try:
        proc = subprocess.run(
            ["ssh-keygen", "-lf", path],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=_KEYGEN_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip() or None


def _derive_public_key(path: str, passphrase: str = "") -> Dict[str, Any]:
    """ssh-keygen -y. The only way to get the public half; no in-process equivalent.

    -P is always passed so ssh-keygen can never fall through to an interactive
    prompt, and stdin is closed as a second guard: an encrypted key with the wrong
    passphrase must FAIL rather than hang until the worker times out.
    """
    try:
        proc = subprocess.run(
            ["ssh-keygen", "-y", "-P", passphrase, "-f", path],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=_KEYGEN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "ssh-keygen timed out deriving the public key"}
    except OSError as err:
        return {"ok": False, "error": f"could not run ssh-keygen ({err.__class__.__name__})"}
    if proc.returncode == 0:
        return {"ok": True, "public_key": (proc.stdout or "").strip()}
    # stderr here can echo the passphrase prompt but never the passphrase itself.
    detail = (proc.stderr or "").strip().splitlines()
    return {
        "ok": False,
        "error": (detail[-1][:200] if detail else "ssh-keygen could not read the key"),
    }


def _resolved_key_path(name: str) -> str:
    return os.path.join(_UPLOAD_KEY_ROOT, name)


@app.post("/tunnel/keys")
def tunnel_key_upload() -> Any:
    """Accept a private key and place it in the writable root.

    JSON rather than multipart, matching how every other upload in this stack
    travels (the ingest path posts base64 in a JSON body). The body is never
    logged and never echoed back.
    """
    if not _is_admin_request():
        return _forbidden()
    bad_root = _upload_root_error()
    if bad_root is not None:
        return bad_root

    data = request.get_json(force=True, silent=True) or {}

    try:
        name = _validate_key_name(data.get("filename"))
    except ValueError as err:
        return _error_json(str(err), 400, "invalid_filename")

    encoded = data.get("key_b64")
    if not isinstance(encoded, str) or not encoded.strip():
        return _error_json("key_b64 is required", 400, "missing_key")
    # Check the ENCODED length first: decoding a hostile body is the expensive
    # part, and base64 is ~4/3 of the plaintext, so this is a safe over-estimate.
    if len(encoded) > _MAX_KEY_BYTES * 2:
        return _error_json(
            f"key exceeds the {_MAX_KEY_BYTES} byte limit", 413, "key_too_large"
        )
    try:
        blob = base64.b64decode(encoded, validate=True)
    except Exception:
        return _error_json("key_b64 is not valid base64", 400, "invalid_encoding")
    if len(blob) > _MAX_KEY_BYTES:
        return _error_json(
            f"key exceeds the {_MAX_KEY_BYTES} byte limit", 413, "key_too_large"
        )
    if not _looks_like_private_key_bytes(blob):
        return _error_json(
            "that file does not look like an SSH private key — its first line "
            "should be a -----BEGIN ... PRIVATE KEY----- header. A .pub is the "
            "public half and cannot authenticate",
            400,
            "not_a_private_key",
        )

    blob = _normalise_key_bytes(blob)
    dest = _resolved_key_path(name)
    # Belt and braces: name validation already makes traversal impossible.
    if not _path_allowed(dest):
        return _error_json(_key_path_rejection(dest), 400, "invalid_key_path")

    overwrite = bool(data.get("overwrite"))
    if os.path.exists(dest) and not overwrite:
        return _error_json(
            f"{name} already exists — pass overwrite to replace it",
            409,
            "key_exists",
        )

    tmp_path = ""
    try:
        # Write to a temp file in the SAME directory, chmod BEFORE it is visible
        # under its final name, then rename. os.replace is atomic, so a reader
        # (or a tunnel start) never sees a partial key or a world-readable one.
        fd, tmp_path = tempfile.mkstemp(dir=_UPLOAD_KEY_ROOT, prefix=".upload-")
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, dest)
        tmp_path = ""
    except OSError as err:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        # Name the errno, never the body.
        return _error_json(
            f"could not write {name}: {err.strerror or err.__class__.__name__}",
            500,
            "write_failed",
        )

    encrypted = _key_is_encrypted(dest)
    return jsonify({
        "ok": True,
        "name": name,
        "path": dest,
        "encrypted": encrypted,
        "fingerprint": _key_fingerprint(dest),
        "bytes": len(blob),
        "overwritten": overwrite,
    })


@app.delete("/tunnel/keys/<name>")
def tunnel_key_delete(name: str) -> Any:
    """Remove a key. Confined to the writable root by construction.

    A key under a read-only SSH_KEY_DIR is deliberately NOT deletable here: that
    directory is the operator's own, and this endpoint is not a file manager.
    """
    if not _is_admin_request():
        return _forbidden()
    bad_root = _upload_root_error()
    if bad_root is not None:
        return bad_root

    try:
        safe = _validate_key_name(name)
    except ValueError as err:
        return _error_json(str(err), 400, "invalid_filename")

    target = _resolved_key_path(safe)
    if not _path_allowed(target):
        return _error_json(_key_path_rejection(target), 400, "invalid_key_path")
    if not os.path.isfile(target):
        return _error_json(
            f"{safe} is not present in {_UPLOAD_KEY_ROOT}. Keys mounted from "
            "SSH_KEY_DIR are read-only and must be removed on the host",
            404,
            "key_not_found",
        )

    try:
        os.unlink(target)
    except OSError as err:
        return _error_json(
            f"could not delete {safe}: {err.strerror or err.__class__.__name__}",
            500,
            "delete_failed",
        )
    return jsonify({"ok": True, "name": safe, "path": target, "deleted": True})


@app.post("/tunnel/keys/<name>/public")
def tunnel_key_public(name: str) -> Any:
    """Derive the public half, so it can be pasted into the far end.

    Reads from EITHER root: deriving a public key is a read, and the operator
    may well want the .pub of a key that was mounted rather than uploaded.
    """
    if not _is_admin_request():
        return _forbidden()
    try:
        safe = _validate_key_name(name)
    except ValueError as err:
        return _error_json(str(err), 400, "invalid_filename")

    data = request.get_json(force=True, silent=True) or {}
    passphrase = data.get("passphrase") or ""
    if not isinstance(passphrase, str):
        return _error_json("passphrase must be a string", 400, "invalid_passphrase")
    if len(passphrase) > _MAX_SECRET_LENGTH:
        return _error_json("passphrase is implausibly long", 400, "invalid_passphrase")

    target = ""
    for root in ([_UPLOAD_KEY_ROOT] if _UPLOAD_KEY_ROOT else []) + _ALLOWED_KEY_ROOTS:
        candidate = os.path.join(root, safe)
        if _path_allowed(candidate) and os.path.isfile(candidate):
            target = candidate
            break
    if not target:
        return _error_json(f"{safe} is not present in any allowed key root", 404, "key_not_found")

    encrypted = _key_is_encrypted(target)
    result = _derive_public_key(target, passphrase)
    if result.get("ok"):
        return jsonify({
            "ok": True,
            "name": safe,
            "path": target,
            "encrypted": encrypted,
            "public_key": result.get("public_key"),
            "fingerprint": _key_fingerprint(target),
        })
    if encrypted and not passphrase:
        return _error_json(
            f"{safe} is passphrase-protected — supply the passphrase to derive its public key",
            400,
            "passphrase_required",
        )
    return _error_json(result.get("error") or "could not derive the public key", 400, "derive_failed")


@app.post("/tunnel/start")
def tunnel_start() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    v = _validate_start_payload(data)
    if not v.get("ok"):
        # A refusal that names its own cause keeps it: "key_needs_passphrase" is
        # the difference between an actionable message and "invalid_request".
        return _error_json(
            v.get("error", "invalid request"), 400, v.get("code", "invalid_request")
        )

    payload = v["payload"]

    with _lock:
        if _state_running_nolock():
            return (
                jsonify(
                    {
                        "ok": False,
                        "code": "already_running",
                        "error": "A managed tunnel is already running. Stop it before starting another.",
                        "running": True,
                        "tunnel": _public_state_nolock().get("tunnel"),
                    }
                ),
                409,
            )

        if not _port_available(payload["local_socks_port"]):
            return (
                jsonify(
                    {
                        "ok": False,
                        "code": "port_in_use",
                        "error": "Requested local_socks_port is already in use",
                    }
                ),
                409,
            )

        launch = _build_start_command(payload)
        cmd = launch["cmd"]
        env = launch["env"]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid,
                env=env,
            )
        except Exception as exc:
            _state["error"] = f"Failed to start tunnel process: {exc}"
            payload["password"] = ""
            payload["key_passphrase"] = ""
            if "SSHPASS" in env:
                env["SSHPASS"] = ""
            return _error_json(_state["error"], 500, "start_failed")

        payload["password"] = ""
        payload["key_passphrase"] = ""
        if "SSHPASS" in env:
            env["SSHPASS"] = ""

        time.sleep(0.35)
        if proc.poll() is not None:
            # Same drain as the timeout branch: a nearby far end that refuses
            # outright dies inside this window, and it was getting a bare verdict
            # with none of the explanation the slower path gets.
            detail = _drain_stderr(proc) or "ssh exited immediately"
            _state["error"] = (detail + _pubkey_hint(detail))[:600]
            return _error_json(_state["error"], 500, "ssh_exited")

        if not _wait_for_listener(payload["local_socks_port"], _STARTUP_TIMEOUT):
            _terminate_pid(proc.pid)
            # The process is dead by now, so the pipe EOFs and this cannot
            # block. Reading it is the whole difference between a stopwatch
            # reading and a cause: "Permission denied (publickey)", a refused
            # connection and a stuck passphrase prompt are indistinguishable
            # from the timeout alone.
            _state["error"] = _listener_timeout_error(
                _drain_stderr(proc), payload["auth_method"]
            )
            return _error_json(_state["error"], 500, "listener_timeout")

        _state_reset_nolock()
        _state.update(
            {
                "id": str(uuid.uuid4()),
                "pid": proc.pid,
                "proc": proc,
                "ssh_user": payload["ssh_user"],
                "ssh_host": payload["ssh_host"],
                "local_socks_port": payload["local_socks_port"],
                "proxy_host": _PROXY_HOST,
                "proxy_port": payload["local_socks_port"],
                "started_at": time.time(),
                "auth_method": payload["auth_method"],
                "notes": list(payload.get("notes") or []),
                "error": "",
            }
        )
        return jsonify(_public_state_nolock())


@app.post("/tunnel/stop")
def tunnel_stop() -> Any:
    body = request.get_json(force=True, silent=True) or {}
    req_id = str(body.get("tunnel_id") or "").strip()

    with _lock:
        running = _state_running_nolock()
        current_id = str(_state.get("id") or "")

        if req_id and current_id and req_id != current_id:
            return _error_json(
                "Requested tunnel_id does not match active tunnel",
                409,
                "tunnel_id_mismatch",
            )

        if not running:
            _state_reset_nolock()
            return jsonify({"ok": True, "running": False, "tunnel": None, "error": ""})

        pid = int(_state.get("pid") or 0)
        if pid:
            _terminate_pid(pid)

        _state_reset_nolock()
        return jsonify({"ok": True, "running": False, "tunnel": None, "error": ""})
