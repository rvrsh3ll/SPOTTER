"""Shared user/session store for SPOTTER authentication.

This module is the single source of truth for the auth database: schema, password
hashing, user CRUD and session lifecycle. It is imported by BOTH:

  * auth-api/app.py            — inside the spotter-auth container (same directory)
  * scripts/spotter_user.py    — on the host, via a sys.path insert

so the hashing parameters can never drift between the service that verifies a
password and the CLI that sets it.

Accounts are not self-activating. The first administrator is created once, by
the setup wizard or by `spotter_user.py add --admin`. Later registrations land
as pending and cannot sign in until an administrator approves them. setup_complete
is sticky: deleting every account does not reopen the wizard.

Stdlib only, by design. The host CLI must run with no virtualenv and no pip
install, and the container image should not need a crypto dependency for this.

The database is a SQLite file (default /data/auth.db, bind-mounted from
deployment/auth-data/) holding two tables:

  users     — one row per operator; carries the lockout counters
  sessions  — one row per live login; only the SHA-256 of the cookie is stored,
              so a stolen database cannot be replayed as a session cookie

Password format is self-describing so the cost parameters can be raised later
without invalidating existing rows:

    scrypt$<n>$<r>$<p>$<salt_b64>$<hash_b64>
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

# ── Password hashing parameters ──────────────────────────────────────────────
# Change these and existing hashes keep working: verify_password() reads the
# parameters back out of each stored string. Only newly-set passwords use the
# new values.
#
# maxmem must exceed 128 * N * r bytes (32 MiB at N=2**15, r=8); OpenSSL's
# default cap is exactly 32 MiB, which this would trip, so it is set explicitly.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024
SALT_BYTES = 16

# ── Session / lockout tuning (env-overridable) ───────────────────────────────
DEFAULT_DB_PATH = "/data/auth.db"
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
MIN_PASSWORD_LEN = 8

APPROVED = "approved"
PENDING = "pending"
REJECTED = "rejected"


class LastAdminError(Exception):
    """Refusing an operation that would leave the install with no active admin."""


class SetupClosed(Exception):
    """The one-time administrator wizard has already been used, or a user exists."""


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return default


def session_idle_seconds() -> float:
    return _env_float("SPOTTER_SESSION_IDLE_HOURS", 12.0) * 3600.0


def session_max_seconds() -> float:
    return _env_float("SPOTTER_SESSION_MAX_DAYS", 7.0) * 86400.0


def login_max_fails() -> int:
    return _env_int("SPOTTER_LOGIN_MAX_FAILS", 10)


def login_lock_seconds() -> float:
    return _env_float("SPOTTER_LOGIN_LOCK_MINUTES", 15.0) * 60.0


def db_path() -> str:
    return (os.environ.get("SPOTTER_AUTH_DB") or DEFAULT_DB_PATH).strip()


# ── Connection / schema ──────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username     TEXT    PRIMARY KEY,
    password     TEXT    NOT NULL,
    is_admin     INTEGER NOT NULL DEFAULT 0,
    is_active    INTEGER NOT NULL DEFAULT 1,
    created_at   REAL    NOT NULL,
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until REAL    NOT NULL DEFAULT 0,
    approval_status TEXT NOT NULL DEFAULT 'approved',
    requested_at REAL    NOT NULL DEFAULT 0,
    approved_by  TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS auth_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_sha256 TEXT PRIMARY KEY,
    username     TEXT NOT NULL,
    created_at   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    expires_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_expires  ON sessions(expires_at);
"""


def connect(path: Optional[str] = None) -> sqlite3.Connection:
    """Open (and initialise) the auth database.

    WAL mode is used because the container and the host CLI may hold the file
    open at the same time; the busy timeout covers the brief write overlap.
    """
    target = path or db_path()
    parent = os.path.dirname(target)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(target, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    _migrate(conn)
    conn.commit()
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns and the setup flag without disturbing an existing install.

    A database that already has operators is treated as set up, so pulling this
    change does not turn the login page into a wizard on a live host. A database
    with no users leaves the wizard open.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    for name, decl in (
        ("approval_status", "TEXT NOT NULL DEFAULT 'approved'"),
        ("requested_at", "REAL NOT NULL DEFAULT 0"),
        ("approved_by", "TEXT NOT NULL DEFAULT ''"),
    ):
        if name not in cols:
            conn.execute(f"ALTER TABLE users ADD COLUMN {name} {decl}")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS auth_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    row = conn.execute(
        "SELECT value FROM auth_meta WHERE key = 'setup_complete'"
    ).fetchone()
    if row is None:
        n = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        conn.execute(
            "INSERT INTO auth_meta (key, value) VALUES ('setup_complete', ?)",
            ("1" if n else "0",),
        )


# ── Password hashing ─────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Return a self-describing scrypt hash string for `password`."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN, maxmem=SCRYPT_MAXMEM,
    )
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check of `password` against a stored hash string."""
    if not password or not encoded:
        return False
    try:
        scheme, n_s, r_s, p_s, salt_b64, hash_b64 = encoded.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.scrypt(
            password.encode("utf-8"), salt=salt,
            n=int(n_s), r=int(r_s), p=int(p_s), dklen=len(expected), maxmem=SCRYPT_MAXMEM,
        )
    except (ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(dk, expected)


def normalise_username(username: str) -> str:
    """Lowercase and validate a username. Raises ValueError if malformed."""
    name = (username or "").strip().lower()
    if not USERNAME_RE.match(name):
        raise ValueError(
            "username must be 1-32 chars of a-z, 0-9, dot, underscore or hyphen, "
            "and start with a letter or digit"
        )
    return name


# ── User CRUD ────────────────────────────────────────────────────────────────

def add_user(conn: sqlite3.Connection, username: str, password: str,
             is_admin: bool = False) -> str:
    """Create an already-approved account. Used by the CLI and the admin portal.

    A pending registration does not come through here — that path cannot set
    is_admin. Creating an administrator also closes the one-time setup wizard.
    """
    name = normalise_username(username)
    conn.execute(
        "INSERT INTO users (username, password, is_admin, is_active, created_at, "
        "approval_status, requested_at, approved_by) "
        "VALUES (?, ?, ?, 1, ?, ?, 0, '')",
        (name, hash_password(password), 1 if is_admin else 0, time.time(), APPROVED),
    )
    if is_admin:
        _mark_setup_complete(conn)
    conn.commit()
    return name


def set_password(conn: sqlite3.Connection, username: str, password: str) -> None:
    name = normalise_username(username)
    cur = conn.execute(
        "UPDATE users SET password = ?, failed_count = 0, locked_until = 0 WHERE username = ?",
        (hash_password(password), name),
    )
    if cur.rowcount == 0:
        raise KeyError(name)
    conn.commit()


def set_active(conn: sqlite3.Connection, username: str, active: bool) -> None:
    name = normalise_username(username)
    row = get_user(conn, name)
    if row is None:
        raise KeyError(name)
    if active and row["approval_status"] != APPROVED:
        raise ValueError("account is not approved")
    if not active:
        _refuse_last_admin(conn, name)
    conn.execute(
        "UPDATE users SET is_active = ? WHERE username = ?", (1 if active else 0, name)
    )
    if not active:
        # Disabling must terminate live sessions, not just block future logins.
        conn.execute("DELETE FROM sessions WHERE username = ?", (name,))
    conn.commit()


def delete_user(conn: sqlite3.Connection, username: str) -> None:
    name = normalise_username(username)
    if get_user(conn, name) is None:
        raise KeyError(name)
    _refuse_last_admin(conn, name)
    cur = conn.execute("DELETE FROM users WHERE username = ?", (name,))
    if cur.rowcount == 0:
        raise KeyError(name)
    conn.execute("DELETE FROM sessions WHERE username = ?", (name,))
    conn.commit()


def get_user(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    try:
        name = normalise_username(username)
    except ValueError:
        return None
    cur = conn.execute("SELECT * FROM users WHERE username = ?", (name,))
    return cur.fetchone()


def list_users(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    cur = conn.execute(
        "SELECT username, is_admin, is_active, created_at, failed_count, locked_until, "
        "approval_status, requested_at, approved_by "
        "FROM users ORDER BY username"
    )
    return [dict(r) for r in cur.fetchall()]


def list_usernames(conn: sqlite3.Connection, active_only: bool = True) -> List[str]:
    sql = "SELECT username FROM users"
    if active_only:
        # Pending and rejected rows are inactive, but keep the approval check so
        # a half-migrated row cannot appear in the campaign share picker.
        sql += " WHERE is_active = 1 AND approval_status = 'approved'"
    sql += " ORDER BY username"
    return [r["username"] for r in conn.execute(sql).fetchall()]


def user_count(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"])


def active_admin_count(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM users "
        "WHERE is_admin = 1 AND is_active = 1 AND approval_status = ?",
        (APPROVED,),
    ).fetchone()
    return int(row["n"])


def setup_complete(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT value FROM auth_meta WHERE key = 'setup_complete'"
    ).fetchone()
    return bool(row and row["value"] == "1")


def _mark_setup_complete(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO auth_meta (key, value) VALUES ('setup_complete', '1') "
        "ON CONFLICT(key) DO UPDATE SET value = '1'"
    )


def mark_setup_complete(conn: sqlite3.Connection) -> None:
    _mark_setup_complete(conn)
    conn.commit()


def _is_active_admin(row: sqlite3.Row) -> bool:
    return (
        bool(row["is_admin"])
        and bool(row["is_active"])
        and row["approval_status"] == APPROVED
    )


def _refuse_last_admin(conn: sqlite3.Connection, username: str) -> None:
    row = get_user(conn, username)
    if row is None or not _is_active_admin(row):
        return
    if active_admin_count(conn) <= 1:
        raise LastAdminError("cannot remove the last active administrator")


def public_user(row: Dict[str, Any]) -> Dict[str, Any]:
    """Account fields safe to return to an administrator. Never includes a hash."""
    now = time.time()
    status = row.get("approval_status") or APPROVED
    if row.get("locked_until") and row["locked_until"] > now:
        state = "locked"
    elif status == PENDING:
        state = "pending"
    elif status == REJECTED:
        state = "rejected"
    elif not row.get("is_active"):
        state = "disabled"
    else:
        state = "active"
    return {
        "username": row["username"],
        "is_admin": bool(row["is_admin"]),
        "is_active": bool(row["is_active"]),
        "approval_status": status,
        "state": state,
        "created_at": row.get("created_at") or 0,
        "approved_by": row.get("approved_by") or "",
    }


def set_admin(conn: sqlite3.Connection, username: str, is_admin: bool) -> None:
    name = normalise_username(username)
    row = get_user(conn, name)
    if row is None:
        raise KeyError(name)
    if is_admin and row["approval_status"] != APPROVED:
        raise ValueError("only an approved account can be an administrator")
    if not is_admin:
        _refuse_last_admin(conn, name)
    conn.execute(
        "UPDATE users SET is_admin = ? WHERE username = ?",
        (1 if is_admin else 0, name),
    )
    if is_admin:
        _mark_setup_complete(conn)
    conn.commit()


def approve_user(conn: sqlite3.Connection, username: str, approver: str) -> None:
    name = normalise_username(username)
    row = get_user(conn, name)
    if row is None:
        raise KeyError(name)
    if row["approval_status"] == REJECTED:
        raise ValueError("rejected accounts must be deleted before they can register again")
    approver_name = normalise_username(approver)
    conn.execute(
        "UPDATE users SET approval_status = ?, is_active = 1, approved_by = ? "
        "WHERE username = ?",
        (APPROVED, approver_name, name),
    )
    conn.commit()


def reject_user(conn: sqlite3.Connection, username: str, approver: str) -> None:
    name = normalise_username(username)
    row = get_user(conn, name)
    if row is None:
        raise KeyError(name)
    _refuse_last_admin(conn, name)
    approver_name = normalise_username(approver)
    conn.execute(
        "UPDATE users SET approval_status = ?, is_active = 0, is_admin = 0, "
        "approved_by = ? WHERE username = ?",
        (REJECTED, approver_name, name),
    )
    conn.execute("DELETE FROM sessions WHERE username = ?", (name,))
    conn.commit()


def _burn_password_check() -> None:
    """Spend a scrypt so a rejected registration is not a fast path."""
    hashlib.scrypt(
        b"absent", salt=b"0" * SALT_BYTES, n=SCRYPT_N, r=SCRYPT_R,
        p=SCRYPT_P, dklen=SCRYPT_DKLEN, maxmem=SCRYPT_MAXMEM,
    )


def request_account(conn: sqlite3.Connection, username: str, password: str) -> str:
    """Record a pending, non-admin account.

    Returns 'created', 'exists', or 'invalid'. Callers must not reflect that
    distinction to the client. An existing username is left untouched, including
    its password — a second registration must not be an account takeover.
    """
    try:
        name = normalise_username(username)
    except ValueError:
        _burn_password_check()
        return "invalid"
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        _burn_password_check()
        return "invalid"
    if get_user(conn, name) is not None:
        hash_password(password)
        return "exists"
    now = time.time()
    conn.execute(
        "INSERT INTO users (username, password, is_admin, is_active, created_at, "
        "approval_status, requested_at, approved_by) "
        "VALUES (?, ?, 0, 0, ?, ?, ?, '')",
        (name, hash_password(password), now, PENDING, now),
    )
    conn.commit()
    return "created"


def claim_setup(conn: sqlite3.Connection, username: str, password: str) -> str:
    """Create the first administrator exactly once.

    Holds a write lock across the emptiness check and the insert, so two
    simultaneous wizard submissions cannot both succeed.
    """
    name = normalise_username(username)
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    password_hash = hash_password(password)
    conn.execute("BEGIN IMMEDIATE")
    try:
        if setup_complete(conn) or user_count(conn) > 0:
            conn.rollback()
            raise SetupClosed("administrator setup is closed")
        now = time.time()
        conn.execute(
            "INSERT INTO users (username, password, is_admin, is_active, created_at, "
            "approval_status, requested_at, approved_by) "
            "VALUES (?, ?, 1, 1, ?, ?, 0, '')",
            (name, password_hash, now, APPROVED),
        )
        _mark_setup_complete(conn)
        conn.commit()
    except SetupClosed:
        raise
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise SetupClosed("administrator setup is closed") from exc
    except Exception:
        conn.rollback()
        raise
    return name


# ── Authentication ───────────────────────────────────────────────────────────

def authenticate(conn: sqlite3.Connection, username: str,
                 password: str) -> Tuple[bool, str]:
    """Verify credentials, applying and maintaining the lockout counters.

    Returns (ok, reason). `reason` is for logging only — callers must return a
    single generic message to the client so the endpoint cannot be used to
    enumerate usernames or discover which accounts are locked.
    """
    row = get_user(conn, username)
    now = time.time()

    if row is None:
        # Spend comparable time on unknown users so response latency does not
        # reveal whether the account exists.
        hashlib.scrypt(b"absent", salt=b"0" * SALT_BYTES, n=SCRYPT_N, r=SCRYPT_R,
                       p=SCRYPT_P, dklen=SCRYPT_DKLEN, maxmem=SCRYPT_MAXMEM)
        return False, "no such user"

    if not row["is_active"] or row["approval_status"] != APPROVED:
        return False, "account disabled"

    if row["locked_until"] and row["locked_until"] > now:
        return False, "account locked"

    if not verify_password(password, row["password"]):
        fails = int(row["failed_count"]) + 1
        locked_until = now + login_lock_seconds() if fails >= login_max_fails() else 0.0
        conn.execute(
            "UPDATE users SET failed_count = ?, locked_until = ? WHERE username = ?",
            (fails, locked_until, row["username"]),
        )
        conn.commit()
        return False, "bad password"

    if row["failed_count"] or row["locked_until"]:
        conn.execute(
            "UPDATE users SET failed_count = 0, locked_until = 0 WHERE username = ?",
            (row["username"],),
        )
        conn.commit()
    return True, "ok"


# ── Sessions ─────────────────────────────────────────────────────────────────

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(conn: sqlite3.Connection, username: str) -> str:
    """Mint a session and return the raw token (only its hash is persisted)."""
    name = normalise_username(username)
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn.execute(
        "INSERT INTO sessions (token_sha256, username, created_at, last_seen, expires_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (_token_hash(token), name, now, now, now + session_max_seconds()),
    )
    conn.commit()
    return token


def validate_session_row(conn: sqlite3.Connection, token: str) -> Optional[Dict[str, Any]]:
    """Return {username, is_admin} for a live session, sliding its idle window.

    Enforces both the absolute lifetime (expires_at, fixed at login) and the
    idle timeout (last_seen). Also re-checks that the account is still active,
    so disabling a user takes effect on their next request.

    `is_admin` rides along on the join that already had to happen for
    `is_active`, so resolving the role costs no extra query — which matters
    because /auth/verify runs on every single proxied request.
    """
    if not token:
        return None
    now = time.time()
    cur = conn.execute(
        "SELECT s.username, s.last_seen, s.expires_at, u.is_active, u.is_admin "
        "FROM sessions s LEFT JOIN users u ON u.username = s.username "
        "WHERE s.token_sha256 = ?",
        (_token_hash(token),),
    )
    row = cur.fetchone()
    if row is None:
        return None

    expired = now > row["expires_at"] or (now - row["last_seen"]) > session_idle_seconds()
    if expired or not row["is_active"]:
        conn.execute("DELETE FROM sessions WHERE token_sha256 = ?", (_token_hash(token),))
        conn.commit()
        return None

    # Only write when the timestamp has moved meaningfully — /auth/verify runs on
    # every proxied request, and a write per request would serialise the whole UI.
    if now - row["last_seen"] > 60:
        conn.execute(
            "UPDATE sessions SET last_seen = ? WHERE token_sha256 = ?",
            (now, _token_hash(token)),
        )
        conn.commit()
    return {"username": row["username"], "is_admin": bool(row["is_admin"])}


def validate_session(conn: sqlite3.Connection, token: str) -> Optional[str]:
    """Username for a live session, or None. Thin wrapper over the row form."""
    row = validate_session_row(conn, token)
    return row["username"] if row else None


def delete_session(conn: sqlite3.Connection, token: str) -> None:
    if not token:
        return
    conn.execute("DELETE FROM sessions WHERE token_sha256 = ?", (_token_hash(token),))
    conn.commit()


def delete_sessions_for(conn: sqlite3.Connection, username: str) -> int:
    name = normalise_username(username)
    cur = conn.execute("DELETE FROM sessions WHERE username = ?", (name,))
    conn.commit()
    return cur.rowcount


def delete_all_sessions(conn: sqlite3.Connection) -> int:
    cur = conn.execute("DELETE FROM sessions")
    conn.commit()
    return cur.rowcount


def list_sessions(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    cur = conn.execute(
        "SELECT username, created_at, last_seen, expires_at FROM sessions "
        "ORDER BY username, created_at"
    )
    return [dict(r) for r in cur.fetchall()]


def purge_expired(conn: sqlite3.Connection) -> int:
    now = time.time()
    cur = conn.execute(
        "DELETE FROM sessions WHERE expires_at < ? OR last_seen < ?",
        (now, now - session_idle_seconds()),
    )
    conn.commit()
    return cur.rowcount
