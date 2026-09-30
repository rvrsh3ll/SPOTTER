#!/usr/bin/env python3
"""Host-side broker for SPOTTER vendor API keys.

The dashboard never talks to this process. spotter-auth does, over a Unix
socket. The age private key stays in this process on the host; it is not
mounted into the auth container, n8n, or the dashboard.

    python3 scripts/spotter_secret_broker.py --daemon
    python3 scripts/spotter_secret_broker.py          # foreground, for debugging

Protocol: one JSON object per connection, one JSON object back. Responses never
include a secret value.

    {"op":"status"}
    {"op":"set","key":"SHODAN_API_KEY","value":"..."}
    {"op":"unset","key":"SHODAN_API_KEY"}
    {"op":"apply","keys":["SHODAN_API_KEY"]}
    {"op":"apply-status"}

`apply` recreates only the containers that read those keys. It returns as soon
as the recreate is started; compose can take longer than the auth worker's
request timeout, so the work runs in a background thread. Service names come
from the map below, never from the request.

Only keys listed in spotter_env.VENDORS are accepted. Machine and engagement
secrets stay on `scripts/spotter_secret.py`.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spotter_env as se  # noqa: E402

SOCK_PATH = os.environ.get("SPOTTER_SECRET_BROKER_SOCK", "/run/spotter/broker.sock")
PID_PATH = os.environ.get("SPOTTER_SECRET_BROKER_PID", "/run/spotter/broker.pid")
LOG_PATH = os.environ.get("SPOTTER_SECRET_BROKER_LOG", "/run/spotter/broker.log")
MAX_VALUE_LEN = 512
_CHANGES = os.path.join(se.SECRETS_DIR, "vendor-changes.json")

# Containers that actually receive each key. Derived from the compose files.
# A key with no entry is still stored; apply reports that nothing reads it yet.
CONSUMERS = {
    "FLARE_API_KEY": ("n8n", "task-runners"),
    "FLARE_TENANT_ID": ("n8n", "task-runners"),
    "FOFA_API_KEY": ("n8n", "task-runners"),
    "SHODAN_API_KEY": ("n8n", "task-runners"),
    "GRAYHATWARFARE_API_KEY": ("n8n", "task-runners"),
    "NVD_API_KEY": ("n8n", "task-runners", "open-webui"),
    "TAVILY_API_KEY": ("n8n", "task-runners"),
    "SERP_API_KEY": ("n8n", "task-runners", "linkedin-api"),
    "HH_APP_TOKEN": ("n8n", "task-runners"),
    "HH_CLIENT_ID": ("n8n", "task-runners"),
    "HH_CLIENT_SECRET": ("n8n", "task-runners"),
}

_apply_lock = threading.Lock()
_apply_state = {
    "running": False,
    "ok": None,
    "error": "",
    "services": [],
    "finished_at": 0.0,
}


def check_vendor_key(key: str) -> str | None:
    """Return an error string, or None if this key may be written."""
    if not isinstance(key, str) or not key:
        return "missing key"
    if key not in se.VENDORS or se.classify(key) != "vendors":
        return "not a vendor key"
    return None


def check_value(value: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return "empty value"
    if len(value) > MAX_VALUE_LEN:
        return "value too long"
    if "\n" in value or "\r" in value or "\x00" in value:
        return "value must be a single line"
    return None


def consumers_for(keys: list[str]) -> list[str]:
    out: list[str] = []
    for key in keys:
        if check_vendor_key(key):
            continue
        for svc in CONSUMERS.get(key, ()):
            if svc not in out:
                out.append(svc)
    return out


def _log(msg: str) -> None:
    """Log an operation. Callers must not pass secret values."""
    try:
        sys.stderr.write(msg.rstrip() + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def _read_changes() -> dict[str, float]:
    try:
        with open(_CHANGES, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    out = {}
    for key, ts in data.items():
        if key in se.VENDORS and isinstance(ts, (int, float)):
            out[key] = float(ts)
    return out


def _write_change(key: str) -> None:
    data = _read_changes()
    data[key] = time.time()
    os.makedirs(se.SECRETS_DIR, exist_ok=True)
    tmp = _CHANGES + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, sort_keys=True)
        fh.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, _CHANGES)


def _scrub_env(key: str) -> None:
    """Drop a plaintext assignment so a portal write cannot leave a copy in .env."""
    if not os.path.isfile(se.ENV_PATH):
        return
    with open(se.ENV_PATH, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    out, hit = [], False
    for line in lines:
        m = se._ASSIGN_RE.match(line)
        if m and m.group(1) == key:
            out.append(f"# {key} -> secrets/vendors.sops.env")
            hit = True
        else:
            out.append(line)
    if not hit:
        return
    with open(se.ENV_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    os.chmod(se.ENV_PATH, 0o600)


def _status() -> dict:
    changed = _read_changes()
    secrets = []
    for key in se.VENDORS:
        value = se.get(key)
        secrets.append({
            "key": key,
            "set": bool(value) and not str(value).startswith("REPLACE_WITH_"),
            "changed_at": changed.get(key) or 0,
            "consumers": list(CONSUMERS.get(key, ())),
        })
    with _apply_lock:
        apply_state = dict(_apply_state)
    return {"ok": True, "secrets": secrets, "apply": apply_state}


def _set(key: str, value: str) -> dict:
    err = check_vendor_key(key) or check_value(value)
    if err:
        return {"ok": False, "error": err}
    try:
        se.set_value(key, value, tier="vendors")
        _scrub_env(key)
        _write_change(key)
    except Exception as exc:
        _log(f"set {key} failed: {type(exc).__name__}")
        return {"ok": False, "error": "could not write the encrypted tier"}
    _log(f"set {key}")
    return {"ok": True, "key": key, "set": True}


def _unset(key: str) -> dict:
    err = check_vendor_key(key)
    if err:
        return {"ok": False, "error": err}
    path = se.tier_path("vendors")
    if not os.path.exists(path):
        _scrub_env(key)
        return {"ok": True, "key": key, "set": False}
    proc = subprocess.run(
        ["sops", "unset", path, f'["{key}"]'],
        capture_output=True, text=True, cwd=se.REPO,
    )
    # sops unset exits non-zero when the key is already absent. That is success.
    if proc.returncode != 0 and "not found" not in (proc.stderr or "").lower():
        # Still scrub .env. Do not include stderr: sops has been known to echo values.
        _log(f"unset {key} failed: exit {proc.returncode}")
        return {"ok": False, "error": "could not remove the encrypted tier entry"}
    _scrub_env(key)
    se.load(refresh=True)
    _write_change(key)
    _log(f"unset {key}")
    return {"ok": True, "key": key, "set": False}


def _run_apply(services: list[str]) -> None:
    compose = os.path.join(se.REPO, "scripts", "spotter_compose.sh")
    try:
        proc = subprocess.run(
            [compose, "up", "-d", "--no-deps", "--force-recreate", *services],
            capture_output=True, text=True, cwd=se.REPO, timeout=600,
        )
        ok = proc.returncode == 0
        err = "" if ok else f"recreate failed (exit {proc.returncode})"
        _log(f"apply {'ok' if ok else 'failed'} services={','.join(services)}")
    except Exception as exc:
        ok = False
        err = f"recreate failed: {type(exc).__name__}"
        _log(f"apply failed: {type(exc).__name__}")
    with _apply_lock:
        _apply_state["running"] = False
        _apply_state["ok"] = ok
        _apply_state["error"] = err
        _apply_state["finished_at"] = time.time()


def _apply(keys: list[str] | None) -> dict:
    if os.geteuid() != 0:
        return {"ok": False, "error": "recreate requires the broker to be running as root"}
    if keys is None:
        keys = [row["key"] for row in _status()["secrets"] if row["set"]]
    if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
        return {"ok": False, "error": "keys must be a list of names"}
    unknown = [k for k in keys if check_vendor_key(k)]
    if unknown:
        return {"ok": False, "error": "not a vendor key"}
    services = consumers_for(keys)
    if not services:
        return {"ok": True, "started": False, "services": [],
                "message": "nothing to recreate"}
    with _apply_lock:
        if _apply_state["running"]:
            return {"ok": False, "error": "a recreate is already running",
                    "services": list(_apply_state["services"])}
        _apply_state.update(
            running=True, ok=None, error="", services=services, finished_at=0.0,
        )
    threading.Thread(target=_run_apply, args=(services,), daemon=True).start()
    _log(f"apply started services={','.join(services)}")
    return {"ok": True, "started": True, "services": services}


def handle_request(payload: dict) -> dict:
    if not isinstance(payload, dict):
        return {"ok": False, "error": "expected an object"}
    op = str(payload.get("op") or "")
    if op == "status" or op == "apply-status":
        return _status()
    if op == "set":
        return _set(str(payload.get("key") or ""), str(payload.get("value") or ""))
    if op == "unset":
        return _unset(str(payload.get("key") or ""))
    if op == "apply":
        keys = payload.get("keys")
        return _apply(None if keys is None else keys)
    return {"ok": False, "error": "unknown op"}


def _serve_one(conn: socket.socket) -> None:
    conn.settimeout(30)
    buf = b""
    while b"\n" not in buf and len(buf) < 8192:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    line = buf.split(b"\n", 1)[0]
    try:
        payload = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        reply = {"ok": False, "error": "invalid request"}
    else:
        # Never log `payload`: a set op carries the secret.
        reply = handle_request(payload)
    conn.sendall((json.dumps(reply) + "\n").encode("utf-8"))


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _already_running() -> bool:
    try:
        with open(PID_PATH, encoding="utf-8") as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return False
    return _pid_alive(pid)


def serve(ready_fd: int | None = None) -> None:
    parent = os.path.dirname(SOCK_PATH)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    os.chmod(parent, 0o700)
    if os.path.exists(SOCK_PATH):
        os.unlink(SOCK_PATH)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK_PATH)
    os.chmod(SOCK_PATH, 0o600)
    srv.listen(8)
    if ready_fd is not None:
        os.write(ready_fd, b"1")
        os.close(ready_fd)

    def _stop(signum, _frame):
        try:
            os.unlink(SOCK_PATH)
        except OSError:
            pass
        try:
            os.unlink(PID_PATH)
        except OSError:
            pass
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    _log(f"listening on {SOCK_PATH}")
    while True:
        try:
            conn, _addr = srv.accept()
        except OSError:
            break
        try:
            _serve_one(conn)
        except Exception as exc:
            _log(f"request failed: {type(exc).__name__}")
        finally:
            conn.close()


def _wait_ready(fd: int, timeout: float = 10.0) -> bool:
    ready, _, _ = select.select([fd], [], [], timeout)
    return bool(ready) and os.read(fd, 1) == b"1"


def _daemonize() -> int:
    """Detach, and return the fd serve() signals once it is listening.

    The launching process exits only after that signal, and exits 1 if the
    daemon dies first. Exiting 0 straight after the fork made `--daemon` report
    success for a broker that never bound its socket, so the portal said
    "secret broker is not running" while bootstrap had printed ok.
    """
    r, w = os.pipe()
    if os.fork() > 0:
        os.close(w)
        if _wait_ready(r):
            os._exit(0)
        sys.stderr.write(f"broker did not start; see {LOG_PATH}\n")
        os._exit(1)
    os.close(r)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    log = os.open(LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(log, 1)
    os.dup2(log, 2)
    os.close(log)
    with open(PID_PATH, "w", encoding="utf-8") as fh:
        fh.write(str(os.getpid()) + "\n")
    os.chmod(PID_PATH, 0o600)
    return w


def main() -> int:
    parser = argparse.ArgumentParser(description="SPOTTER vendor-secret broker")
    parser.add_argument("--daemon", action="store_true",
                        help="double-fork into the background")
    args = parser.parse_args()
    parent = os.path.dirname(SOCK_PATH)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    if _already_running() and os.path.exists(SOCK_PATH):
        print(f"broker already running ({SOCK_PATH})")
        return 0
    ready_fd = None
    if args.daemon:
        ready_fd = _daemonize()
    else:
        with open(PID_PATH, "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()) + "\n")
    serve(ready_fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
