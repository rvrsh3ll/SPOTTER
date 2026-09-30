#!/usr/bin/env python3
"""Offline checks that `spotter_secret_broker.py --daemon` reports what happened.

Starts the broker on a temporary socket and sends only an unknown op, so it never
calls sops or reads secrets/vendors.sops.env. Does not touch /run/spotter.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "scripts" / "spotter_secret_broker.py"


def _ok(name: str) -> None:
    print(f"  ok    {name}")


def _env(run_dir: Path, sock: str) -> dict:
    env = dict(os.environ)
    env["SPOTTER_SECRET_BROKER_SOCK"] = sock
    env["SPOTTER_SECRET_BROKER_PID"] = str(run_dir / "broker.pid")
    env["SPOTTER_SECRET_BROKER_LOG"] = str(run_dir / "broker.log")
    return env


def _daemon(env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BROKER), "--daemon"],
        env=env, capture_output=True, text=True, timeout=30,
    )


def _ask(sock: str, payload: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect(sock)
        s.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    return json.loads(buf.split(b"\n", 1)[0])


def _stop(run_dir: Path) -> None:
    try:
        pid = int((run_dir / "broker.pid").read_text().strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except OSError:
            return
        time.sleep(0.1)


def _starts(tmp: Path) -> None:
    run_dir = tmp / "run"
    sock = str(run_dir / "broker.sock")
    env = _env(run_dir, sock)
    try:
        proc = _daemon(env)
        assert proc.returncode == 0, f"--daemon exited {proc.returncode}: {proc.stderr!r}"
        # Readiness is signalled after listen(), so the socket must already accept.
        assert os.path.exists(sock), "--daemon returned before the socket existed"
        reply = _ask(sock, {"op": "nope"})
        assert reply == {"ok": False, "error": "unknown op"}, reply
        _ok("--daemon exits 0 only once the socket is accepting")

        again = _daemon(env)
        assert again.returncode == 0, f"second --daemon exited {again.returncode}"
        assert "already running" in again.stdout, again.stdout
        _ok("a second --daemon leaves the running broker alone")
    finally:
        _stop(run_dir)


def _fails(tmp: Path) -> None:
    run_dir = tmp / "bad"
    # AF_UNIX paths are capped near 108 bytes, so bind() fails after the fork.
    sock = str(run_dir / ("x" * 120 + ".sock"))
    env = _env(run_dir, sock)
    try:
        proc = _daemon(env)
        assert proc.returncode != 0, "--daemon exited 0 for a broker that never bound"
        assert "did not start" in proc.stderr, proc.stderr
        _ok("--daemon exits non-zero when the broker dies before listening")
    finally:
        _stop(run_dir)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        _starts(Path(tmp))
        _fails(Path(tmp))
    print("smoke_secret_broker: pass")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"smoke_secret_broker: FAIL {exc}")
        raise SystemExit(1)
