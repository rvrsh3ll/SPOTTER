#!/usr/bin/env python3
"""Offline checks for administrator setup, pending registration, and vendor-key gating.

Uses a temporary SQLite file. Does not call sops, does not open the broker socket,
and does not read or write secrets/vendors.sops.env.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "auth-api"))


def _ok(name: str) -> None:
    print(f"  ok    {name}")


def _unit(db) -> None:
    import spotter_auth_db as auth

    conn = auth.connect()
    assert auth.user_count(conn) == 0
    assert not auth.setup_complete(conn)
    auth.claim_setup(conn, "Ada", "password1")
    assert auth.setup_complete(conn)
    assert auth.get_user(conn, "ada")["is_admin"] == 1
    try:
        auth.claim_setup(conn, "eve", "password1")
        raise AssertionError("second setup succeeded")
    except auth.SetupClosed:
        pass
    _ok("setup creates one administrator and then stays closed")

    conn.execute("DELETE FROM users")
    conn.commit()
    assert auth.user_count(conn) == 0
    assert auth.setup_complete(conn)
    try:
        auth.claim_setup(conn, "ada", "password1")
        raise AssertionError("deleting every account reopened setup")
    except auth.SetupClosed:
        pass
    _ok("setup_complete stays set after the last account is deleted")

    auth.add_user(conn, "ada", "password1", is_admin=True)
    stored = auth.get_user(conn, "ada")["password"]
    assert auth.request_account(conn, "ada", "other-password-99") == "exists"
    assert auth.get_user(conn, "ada")["password"] == stored
    assert auth.request_account(conn, "bob", "password1") == "created"
    bob = auth.get_user(conn, "bob")
    assert bob["approval_status"] == auth.PENDING
    assert bob["is_admin"] == 0
    assert bob["is_active"] == 0
    ok, _reason = auth.authenticate(conn, "bob", "password1")
    assert not ok
    _ok("registration is pending, non-admin, and cannot overwrite a password")

    auth.approve_user(conn, "bob", "ada")
    ok, reason = auth.authenticate(conn, "bob", "password1")
    assert ok and reason == "ok"
    assert "bob" in auth.list_usernames(conn, active_only=True)
    _ok("an approved account can sign in")

    for op in (
        lambda: auth.set_active(conn, "ada", False),
        lambda: auth.delete_user(conn, "ada"),
        lambda: auth.set_admin(conn, "ada", False),
        lambda: auth.reject_user(conn, "ada", "bob"),
    ):
        try:
            op()
            raise AssertionError("last administrator was removed")
        except auth.LastAdminError:
            pass
    assert auth.active_admin_count(conn) == 1
    _ok("the last active administrator cannot be removed")

    import spotter_env
    import spotter_secret_broker as broker

    # Imported after the DB checks so a missing Flask install still reports those.
    sys.path.insert(0, str(ROOT / "auth-api"))
    import app as auth_app

    assert auth_app.VENDOR_KEYS == frozenset(spotter_env.VENDORS)
    assert broker.check_vendor_key("NEO4J_PASSWORD")
    assert broker.check_vendor_key("SHODAN_API_KEY") is None
    consumers = broker.consumers_for(["SERP_API_KEY"])
    assert consumers == ["n8n", "task-runners", "linkedin-api"]
    _ok("vendor key allowlist matches the broker and the env classifier")


def _flask(db_path: Path) -> None:
    os.environ["SPOTTER_AUTH_DB"] = str(db_path)
    import app as auth_app

    client = auth_app.app.test_client()
    status = client.get("/auth/setup")
    assert status.status_code == 200
    assert status.get_json()["setup_required"] is True

    created = client.post("/auth/setup", json={"username": "ada", "password": "password1"})
    assert created.status_code == 200
    assert created.get_json()["is_admin"] is True
    closed = client.post("/auth/setup", json={"username": "eve", "password": "password1"})
    assert closed.status_code == 403
    _ok("HTTP setup succeeds once and then returns 403")

    payloads = [
        {"username": "carol", "password": "password1"},
        {"username": "carol", "password": "otherpass1"},
        {"username": "x", "password": "short"},
        {"username": "dave", "password": "password1", "is_admin": True},
    ]
    replies = [client.post("/auth/register", json=payload) for payload in payloads]
    bodies = [(r.status_code, r.get_json()) for r in replies]
    assert all(body == bodies[0] for body in bodies)
    assert bodies[0][0] == 200
    _ok("registration replies are identical for new, taken, invalid, and is_admin")

    pending = client.post("/auth/login", json={"username": "carol", "password": "password1"})
    assert pending.status_code == 401
    assert pending.get_json()["error"] == "invalid credentials"
    _ok("a pending account cannot sign in")

    listing = client.get("/auth/admin/users")
    assert listing.status_code == 200
    users = {row["username"]: row for row in listing.get_json()["users"]}
    assert users["dave"]["is_admin"] is False
    assert users["dave"]["state"] == "pending"
    assert users["dave"]["approval_status"] == "pending"

    approved = client.post("/auth/admin/users/carol/approve")
    assert approved.status_code == 200
    operator = auth_app.app.test_client()
    signed_in = operator.post("/auth/login", json={"username": "carol", "password": "password1"})
    assert signed_in.status_code == 200
    denied = operator.get("/auth/admin/users")
    assert denied.status_code == 403
    _ok("a non-administrator cannot open the admin user list")

    secrets = client.get("/auth/admin/secrets")
    assert secrets.status_code == 503
    assert "broker" in (secrets.get_json().get("error") or "")
    _ok("vendor-key routes fail closed when the broker socket is absent")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        os.environ["SPOTTER_AUTH_DB"] = str(root / "unit.db")
        os.environ["SPOTTER_SECRET_BROKER_SOCK"] = str(root / "missing.sock")
        import spotter_auth_db as auth
        _unit(auth)
        os.environ["SPOTTER_AUTH_DB"] = str(root / "http.db")
        _flask(root / "http.db")
    print("smoke_auth_admin: pass")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"smoke_auth_admin: FAIL {exc}")
        raise SystemExit(1)
