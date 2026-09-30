"""SPOTTER authentication sidecar.

Backs the nginx `auth_request` gate in frontend/nginx.conf. nginx issues a
subrequest to /auth/verify for every proxied request; a 200 response carries the
resolved operator name back out in the `X-Spotter-User` header, which nginx then
injects into the upstream request (overwriting anything the client sent).

Routes
  POST /auth/login    {username, password} -> sets the spotter_session cookie
  POST /auth/logout   revokes the current session and clears the cookie
  GET  /auth/verify   nginx auth_request target: 200 + X-Spotter-User, or 401
  GET  /auth/me       {username, is_admin} for the UI header badge
  GET  /auth/users    {users: [...]} usernames, for the campaign share picker
  GET  /auth/setup    {setup_required} — true only before the first administrator
  POST /auth/setup    one-time administrator creation; optional vendor keys
  POST /auth/register pending account request; cannot set is_admin
  /auth/admin/*       administrator account and vendor-key management
  GET  /health        container healthcheck (open)

User records and sessions live in a SQLite file shared with the host-side admin
CLI (scripts/spotter_user.py); all storage and hashing logic is in
spotter_auth_db.py so the two can never disagree.

Vendor API keys are not stored here. This process forwards them to the host
broker on SPOTTER_SECRET_BROKER_SOCK and never logs the values. The age key is
not available in this container.
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import threading
from typing import Any, Optional

from flask import Flask, g, jsonify, request

import spotter_auth_db as db

app = Flask(__name__)

COOKIE_NAME = "spotter_session"
_MAX_BODY_BYTES = 8192
_ADMIN_BODY_BYTES = 32768
_MAX_SECRET_LEN = 512

# Must stay identical to scripts/spotter_env.py VENDORS. smoke_auth_admin.py
# fails if the two lists drift. The portal cannot name a machine or engagement
# secret, even if the broker were later widened.
VENDOR_KEYS = frozenset({
    "FLARE_API_KEY",
    "FLARE_TENANT_ID",
    "FOFA_API_KEY",
    "SHODAN_API_KEY",
    "GRAYHATWARFARE_API_KEY",
    "NVD_API_KEY",
    "TAVILY_API_KEY",
    "SERP_API_KEY",
    "HH_APP_TOKEN",
    "HH_CLIENT_ID",
    "HH_CLIENT_SECRET",
})

_BROKER_SOCK = os.environ.get("SPOTTER_SECRET_BROKER_SOCK", "/run/spotter/broker.sock")

_REGISTER_OK = {
    "ok": True,
    "message": (
        "If this username is available, the request was recorded. "
        "An administrator must approve it before you can sign in."
    ),
}

# Cookies are only marked Secure when the deployment actually terminates TLS.
# On the default loopback/SSH-tunnel deployment the UI is plain http:// and a
# Secure cookie would simply never be sent back.
_COOKIE_SECURE = (os.environ.get("SPOTTER_COOKIE_SECURE") or "false").strip().lower() in (
    "1", "true", "yes", "on",
)

# Dashboard / n8n editor / Flowsint app are now three DIFFERENT hostnames behind
# Caddy (deployment/Caddyfile), not three ports on one host — and a cookie with
# no Domain attribute is host-only, so a login at the dashboard vhost would
# never reach the other two at all. Setting Domain to their shared parent
# (e.g. "spotter.localhost", covering n8n.spotter.localhost and graph.spotter.localhost too)
# restores the "one login covers all three" behaviour. Empty means host-only,
# for a deployment that put something other than Caddy in front.
_COOKIE_DOMAIN = (os.environ.get("SPOTTER_COOKIE_DOMAIN") or "").strip() or None

_local = threading.local()


def _conn():
    """One SQLite connection per worker thread, opened lazily."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = db.connect()
        _local.conn = conn
    return conn


def _supplied_token() -> str:
    return (request.cookies.get(COOKIE_NAME) or "").strip()


def _current_session() -> Optional[dict]:
    """Resolve the session cookie to {username, is_admin}, caching per request."""
    if "spotter_session" not in g:
        g.spotter_session = db.validate_session_row(_conn(), _supplied_token())
    return g.spotter_session


def _current_user() -> Optional[str]:
    """Resolve the session cookie to a username, caching per request."""
    row = _current_session()
    return row["username"] if row else None


def _unauthorized(message: str = "unauthenticated") -> Any:
    return jsonify({"ok": False, "error": message}), 401


def _json_body(limit: int = _MAX_BODY_BYTES) -> dict:
    if request.content_length and request.content_length > limit:
        return {}
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _body_too_large(limit: int) -> bool:
    return bool(request.content_length and request.content_length > limit)


def _set_session_cookie(resp: Any, token: str) -> None:
    resp.set_cookie(
        COOKIE_NAME, token,
        max_age=int(db.session_max_seconds()),
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite="Lax",
        path="/",
        domain=_COOKIE_DOMAIN,
    )


class _BrokerError(Exception):
    pass


def _broker(payload: dict, timeout: float = 20.0) -> dict:
    """Forward one request to the host broker. Never log `payload`."""
    if not os.path.exists(_BROKER_SOCK):
        raise _BrokerError("secret broker is not running")
    raw = (json.dumps(payload) + "\n").encode("utf-8")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(_BROKER_SOCK)
        sock.sendall(raw)
        buf = b""
        while b"\n" not in buf and len(buf) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except OSError as exc:
        raise _BrokerError("secret broker is not running") from exc
    finally:
        sock.close()
    try:
        data = json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _BrokerError("secret broker returned an invalid response") from exc
    if not isinstance(data, dict):
        raise _BrokerError("secret broker returned an invalid response")
    return data


def _require_admin() -> tuple[Optional[str], Any]:
    """Return (username, None) or (None, error_response). Re-reads the role."""
    row = _current_session()
    if not row:
        return None, _unauthorized()
    user = db.get_user(_conn(), row["username"])
    if user is None or not user["is_admin"] or not user["is_active"]:
        return None, (jsonify({"ok": False, "error": "admin required"}), 403)
    if user["approval_status"] != db.APPROVED:
        return None, (jsonify({"ok": False, "error": "admin required"}), 403)
    return row["username"], None


def _admin_user_error(exc: Exception) -> Any:
    if isinstance(exc, KeyError):
        return jsonify({"ok": False, "error": "no such user"}), 404
    if isinstance(exc, db.LastAdminError):
        return jsonify({"ok": False, "error": str(exc)}), 409
    if isinstance(exc, ValueError):
        return jsonify({"ok": False, "error": str(exc)}), 400
    app.logger.exception("admin user operation failed")
    return jsonify({"ok": False, "error": "request failed"}), 500


# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok"})


@app.post("/auth/login")
def login() -> Any:
    body = _json_body()
    username = str(body.get("username") or "")
    password = str(body.get("password") or "")

    if not username or not password:
        return jsonify({"ok": False, "error": "invalid credentials"}), 401

    ok, reason = db.authenticate(_conn(), username, password)
    if not ok:
        # One generic message for every failure mode (unknown user, wrong
        # password, disabled, locked) so the endpoint cannot be used to
        # enumerate accounts. The specific reason goes to the container log.
        app.logger.info("login failed for %r: %s", username[:64], reason)
        return jsonify({"ok": False, "error": "invalid credentials"}), 401

    name = db.normalise_username(username)
    token = db.create_session(_conn(), name)
    row = db.get_user(_conn(), name)

    resp = jsonify({"ok": True, "username": name, "is_admin": bool(row["is_admin"])})
    resp.set_cookie(
        COOKIE_NAME, token,
        max_age=int(db.session_max_seconds()),
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite="Lax",
        path="/",
        domain=_COOKIE_DOMAIN,
    )
    return resp


@app.post("/auth/logout")
def logout() -> Any:
    db.delete_session(_conn(), _supplied_token())
    resp = jsonify({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/", domain=_COOKIE_DOMAIN)
    return resp


@app.get("/auth/verify")
def verify() -> Any:
    """nginx auth_request target. Kept as cheap as possible: it runs on every
    single proxied request, including static assets."""
    user = _current_user()
    if not user:
        return _unauthorized()
    resp = app.make_response("")
    resp.status_code = 200
    resp.headers["X-Spotter-User"] = user
    # Role rides the same subrequest so nginx can stamp it onto the upstream
    # request. Workflows that gate a write on "is this an admin" must not trust
    # the browser for it, and this costs no extra query — validate_session_row
    # already joined `users` to re-check is_active.
    resp.headers["X-Spotter-Admin"] = "1" if (_current_session() or {}).get("is_admin") else "0"
    return resp


@app.get("/auth/me")
def me() -> Any:
    user = _current_user()
    if not user:
        return _unauthorized()
    row = db.get_user(_conn(), user)
    if row is None:
        return _unauthorized()
    return jsonify({"ok": True, "username": user, "is_admin": bool(row["is_admin"])})


@app.get("/auth/users")
def users() -> Any:
    """Usernames only — powers the campaign share picker in the UI.

    Exposes no password, session or lockout state. Any signed-in operator may
    read it, because sharing a campaign requires naming another operator.
    """
    if not _current_user():
        return _unauthorized()
    return jsonify({"ok": True, "users": db.list_usernames(_conn(), active_only=True)})


@app.get("/auth/setup")
def setup_status() -> Any:
    conn = _conn()
    required = (not db.setup_complete(conn)) and db.user_count(conn) == 0
    return jsonify({"ok": True, "setup_required": required})


@app.post("/auth/setup")
def setup() -> Any:
    """Create the first administrator. Closed forever after it succeeds."""
    if _body_too_large(_ADMIN_BODY_BYTES):
        return jsonify({"ok": False, "error": "body too large"}), 400
    body = _json_body(_ADMIN_BODY_BYTES)
    username = str(body.get("username") or "")
    password = str(body.get("password") or "")
    try:
        name = db.claim_setup(_conn(), username, password)
    except db.SetupClosed:
        return jsonify({"ok": False, "error": "setup closed"}), 403
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    saved, failed = _store_vendor_secrets(body.get("secrets"))
    token = db.create_session(_conn(), name)
    resp = jsonify({
        "ok": True, "username": name, "is_admin": True,
        "secrets_saved": saved, "secrets_failed": failed,
    })
    _set_session_cookie(resp, token)
    return resp


@app.post("/auth/register")
def register() -> Any:
    """Request an account. The response does not reveal whether the name exists."""
    if not db.setup_complete(_conn()):
        return jsonify({"ok": False, "error": "setup required"}), 403
    body = _json_body()
    username = str(body.get("username") or "")
    password = str(body.get("password") or "")
    # is_admin in the body is ignored. request_account cannot set it.
    try:
        reason = db.request_account(_conn(), username, password)
    except Exception:
        app.logger.exception("registration failed")
        reason = "error"
    app.logger.info("registration %s for %r", reason, username[:64])
    return jsonify(_REGISTER_OK)


def _store_vendor_secrets(raw: Any) -> tuple[list[str], list[str]]:
    """Write optional vendor keys. Returns (saved names, failed names). No values."""
    saved: list[str] = []
    failed: list[str] = []
    if not isinstance(raw, dict) or not raw:
        return saved, failed
    for key, value in raw.items():
        if value in (None, ""):
            continue
        if key not in VENDOR_KEYS or not isinstance(value, str) or len(value) > _MAX_SECRET_LEN:
            failed.append(str(key)[:64])
            continue
        try:
            result = _broker({"op": "set", "key": key, "value": value})
        except _BrokerError:
            failed.append(key)
            continue
        if result.get("ok"):
            saved.append(key)
        else:
            failed.append(key)
    if failed:
        app.logger.info("vendor key write failed for %s", ", ".join(failed))
    return saved, failed


@app.get("/auth/admin/users")
def admin_users() -> Any:
    admin, err = _require_admin()
    if err:
        return err
    return jsonify({
        "ok": True,
        "users": [db.public_user(u) for u in db.list_users(_conn())],
        "actor": admin,
    })


@app.post("/auth/admin/users")
def admin_create_user() -> Any:
    admin, err = _require_admin()
    if err:
        return err
    body = _json_body()
    username = str(body.get("username") or "")
    password = str(body.get("password") or "")
    is_admin = bool(body.get("is_admin"))
    try:
        name = db.add_user(_conn(), username, password, is_admin=is_admin)
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "user already exists"}), 409
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    app.logger.info("admin %s created %s admin=%s", admin, name, is_admin)
    return jsonify({"ok": True, "username": name, "is_admin": is_admin})


@app.post("/auth/admin/users/<name>/approve")
def admin_approve(name: str) -> Any:
    admin, err = _require_admin()
    if err:
        return err
    try:
        db.approve_user(_conn(), name, admin)
    except (KeyError, ValueError, db.LastAdminError) as exc:
        return _admin_user_error(exc)
    return jsonify({"ok": True})


@app.post("/auth/admin/users/<name>/reject")
def admin_reject(name: str) -> Any:
    admin, err = _require_admin()
    if err:
        return err
    try:
        db.reject_user(_conn(), name, admin)
    except (KeyError, ValueError, db.LastAdminError) as exc:
        return _admin_user_error(exc)
    return jsonify({"ok": True})


@app.post("/auth/admin/users/<name>/disable")
def admin_disable(name: str) -> Any:
    _admin, err = _require_admin()
    if err:
        return err
    try:
        db.set_active(_conn(), name, False)
    except (KeyError, ValueError, db.LastAdminError) as exc:
        return _admin_user_error(exc)
    return jsonify({"ok": True})


@app.post("/auth/admin/users/<name>/enable")
def admin_enable(name: str) -> Any:
    _admin, err = _require_admin()
    if err:
        return err
    try:
        db.set_active(_conn(), name, True)
    except (KeyError, ValueError, db.LastAdminError) as exc:
        return _admin_user_error(exc)
    return jsonify({"ok": True})


@app.post("/auth/admin/users/<name>/delete")
def admin_delete(name: str) -> Any:
    _admin, err = _require_admin()
    if err:
        return err
    try:
        db.delete_user(_conn(), name)
    except (KeyError, ValueError, db.LastAdminError) as exc:
        return _admin_user_error(exc)
    return jsonify({"ok": True})


@app.post("/auth/admin/users/<name>/admin")
def admin_set_role(name: str) -> Any:
    _admin, err = _require_admin()
    if err:
        return err
    body = _json_body()
    try:
        db.set_admin(_conn(), name, bool(body.get("is_admin")))
    except (KeyError, ValueError, db.LastAdminError) as exc:
        return _admin_user_error(exc)
    return jsonify({"ok": True, "is_admin": bool(body.get("is_admin"))})


@app.post("/auth/admin/users/<name>/revoke")
def admin_revoke(name: str) -> Any:
    _admin, err = _require_admin()
    if err:
        return err
    try:
        n = db.delete_sessions_for(_conn(), name)
    except ValueError as exc:
        return _admin_user_error(exc)
    return jsonify({"ok": True, "revoked": n})


@app.post("/auth/admin/users/<name>/passwd")
def admin_passwd(name: str) -> Any:
    """Reset a password. A generated password is returned once and not stored."""
    _admin, err = _require_admin()
    if err:
        return err
    body = _json_body()
    password = str(body.get("password") or "")
    generated = False
    if not password:
        import secrets as _secrets
        password = _secrets.token_urlsafe(18)
        generated = True
    try:
        db.set_password(_conn(), name, password)
        db.delete_sessions_for(_conn(), name)
    except (KeyError, ValueError) as exc:
        return _admin_user_error(exc)
    resp: dict[str, Any] = {"ok": True, "generated": generated}
    if generated:
        resp["password"] = password
    return jsonify(resp)


@app.get("/auth/admin/secrets")
def admin_secrets() -> Any:
    _admin, err = _require_admin()
    if err:
        return err
    try:
        data = _broker({"op": "status"})
    except _BrokerError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503
    # Drop anything the broker might have attached that is not a status field.
    secrets = []
    for row in data.get("secrets") or []:
        if not isinstance(row, dict) or row.get("key") not in VENDOR_KEYS:
            continue
        secrets.append({
            "key": row["key"],
            "set": bool(row.get("set")),
            "changed_at": row.get("changed_at") or 0,
            "consumers": row.get("consumers") or [],
        })
    return jsonify({"ok": True, "secrets": secrets, "apply": data.get("apply") or {}})


@app.put("/auth/admin/secrets/<key>")
def admin_secret_set(key: str) -> Any:
    _admin, err = _require_admin()
    if err:
        return err
    if key not in VENDOR_KEYS:
        return jsonify({"ok": False, "error": "not a vendor key"}), 400
    if _body_too_large(_ADMIN_BODY_BYTES):
        return jsonify({"ok": False, "error": "body too large"}), 400
    body = _json_body(_ADMIN_BODY_BYTES)
    value = body.get("value")
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_SECRET_LEN:
        return jsonify({"ok": False, "error": "invalid value"}), 400
    try:
        result = _broker({"op": "set", "key": key, "value": value})
    except _BrokerError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503
    if not result.get("ok"):
        return jsonify({"ok": False, "error": result.get("error") or "write failed"}), 400
    return jsonify({"ok": True, "key": key, "set": True})


@app.delete("/auth/admin/secrets/<key>")
def admin_secret_unset(key: str) -> Any:
    _admin, err = _require_admin()
    if err:
        return err
    if key not in VENDOR_KEYS:
        return jsonify({"ok": False, "error": "not a vendor key"}), 400
    try:
        result = _broker({"op": "unset", "key": key})
    except _BrokerError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503
    if not result.get("ok"):
        return jsonify({"ok": False, "error": result.get("error") or "clear failed"}), 400
    return jsonify({"ok": True, "key": key, "set": False})


@app.post("/auth/admin/secrets/apply")
def admin_secret_apply() -> Any:
    _admin, err = _require_admin()
    if err:
        return err
    body = _json_body()
    keys = body.get("keys")
    payload: dict[str, Any] = {"op": "apply"}
    if keys is not None:
        if not isinstance(keys, list) or any(k not in VENDOR_KEYS for k in keys):
            return jsonify({"ok": False, "error": "not a vendor key"}), 400
        payload["keys"] = keys
    try:
        result = _broker(payload)
    except _BrokerError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503
    status = 200 if result.get("ok") else 409
    return jsonify(result), status


if __name__ == "__main__":  # pragma: no cover - dev convenience only
    app.run(host="0.0.0.0", port=7052)
