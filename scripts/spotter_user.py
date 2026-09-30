#!/usr/bin/env python3
"""SPOTTER operator account management.

Headless account management. The browser wizard and the Admin tab are the
other doors; this script writes the same SQLite file the spotter-auth container
uses (bind-mounted at deployment/auth-data/auth.db) and imports the hashing and
session logic from auth-api/spotter_auth_db.py, so a password set here is always
readable by the service.

The first account must be an administrator. That also closes the browser setup
wizard. Later accounts can be created here or requested from the registration
page and approved here.

Stdlib only — run it directly, no virtualenv needed:

    scripts/spotter_user.py add alice --admin
    scripts/spotter_user.py list
    scripts/spotter_user.py passwd alice
    scripts/spotter_user.py disable alice
    scripts/spotter_user.py delete alice
    scripts/spotter_user.py sessions
    scripts/spotter_user.py sessions --revoke alice
    scripts/spotter_user.py sessions --revoke-all

Campaign ownership lives in Neo4j rather than this database, but claiming an
unowned campaign is an admin operation, so it is exposed here too:

    scripts/spotter_user.py campaigns
    scripts/spotter_user.py adopt OPERATION-FOO alice

The service must be restarted after `disable`/`delete` only if it is mid-request;
both commands already drop the user's live sessions, which takes effect on their
next request.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Single source of truth for schema + hashing, shared with the container.
sys.path.insert(0, os.path.join(_REPO_ROOT, "auth-api"))
import spotter_auth_db as db  # noqa: E402

# Host-side view of the volume the spotter-auth container mounts at /data.
HOST_DB_DEFAULT = os.path.join(_REPO_ROOT, "deployment", "auth-data", "auth.db")


def _resolve_db_path(explicit: str | None) -> str:
    if explicit:
        return explicit
    env = (os.environ.get("SPOTTER_AUTH_DB") or "").strip()
    # The container default (/data/auth.db) is meaningless on the host.
    if env and env != db.DEFAULT_DB_PATH:
        return env
    return HOST_DB_DEFAULT


def _load_dotenv() -> dict:
    """Read config + decrypted secrets via the shared loader.

    NEO4J_PASSWORD moved into secrets/machine.sops.env, so a plain scan of .env
    now finds a pointer comment instead of a value -- which would surface as an
    auth failure against Neo4j rather than as a missing secret.
    """
    import sys as _sys
    _sys.path.insert(0, os.path.join(_REPO_ROOT, "scripts"))
    import spotter_env
    return spotter_env.load()

def _prompt_password(username: str, random: bool) -> str:
    if random:
        pw = secrets.token_urlsafe(18)
        print(f"Generated password for {username}: {pw}")
        print("Record it now — it is not recoverable from the database.")
        return pw
    while True:
        first = getpass.getpass(f"New password for {username}: ")
        if len(first) < db.MIN_PASSWORD_LEN:
            print(f"Too short — minimum {db.MIN_PASSWORD_LEN} characters.", file=sys.stderr)
            continue
        second = getpass.getpass("Repeat: ")
        if first != second:
            print("Passwords do not match.", file=sys.stderr)
            continue
        return first


def _fmt_time(ts: float) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


# ── Neo4j campaign registry (same node WF17/WF18 read) ───────────────────────

def _neo4j_candidates() -> list:
    """Host-reachable Neo4j HTTP endpoints, in preference order.

    NEO4J_HTTP_URL in .env names the *container* (flowsint-neo4j-prod:7474) because
    that is what the n8n code nodes need. That hostname does not resolve on the
    host, so this CLI also tries the published loopback port. Order: an explicit
    real environment variable wins, then .env, then loopback.
    """
    seen, out = set(), []
    for url in (os.environ.get("NEO4J_HTTP_URL"),
                _load_dotenv().get("NEO4J_HTTP_URL"),
                "http://127.0.0.1:7474"):
        if url:
            url = url.rstrip("/")
            if url not in seen:
                seen.add(url)
                out.append(url)
    return out


def _cypher(stmt: str, params: dict | None = None) -> list:
    env = _load_dotenv()
    user = os.environ.get("NEO4J_USER") or env.get("NEO4J_USER") or "neo4j"
    password = os.environ.get("NEO4J_PASSWORD") or env.get("NEO4J_PASSWORD") or ""
    if not password:
        raise SystemExit("NEO4J_PASSWORD not set (checked env and .env)")

    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    payload = json.dumps({"statements": [{"statement": stmt, "parameters": params or {}}]})

    candidates = _neo4j_candidates()
    last_error = None
    for url in candidates:
        req = urllib.request.Request(
            f"{url}/db/neo4j/tx/commit", data=payload.encode(),
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            # Reached Neo4j but it refused us (e.g. bad password) — do not retry
            # the next candidate, the credentials are the problem.
            raise SystemExit(f"Neo4j rejected the request ({exc.code} {exc.reason}) at {url}"
                             ) from exc
        except urllib.error.URLError as exc:
            last_error = f"{url}: {exc.reason}"
            continue
        if data.get("errors"):
            raise SystemExit(f"Neo4j error: {str(data['errors'])[:300]}")
        return data["results"][0]["data"]

    raise SystemExit(
        "Could not reach Neo4j from the host. Tried:\n  "
        + "\n  ".join(candidates)
        + f"\nLast error: {last_error}\n"
        "Is the stack up? Neo4j's HTTP port should be published on 127.0.0.1:7474.")


def _read_campaigns() -> list:
    rows = _cypher("MATCH (m:SpotterMeta {key:'campaigns'}) RETURN m.data AS data LIMIT 1")
    if not rows or not rows[0]["row"][0]:
        return []
    try:
        camps = json.loads(rows[0]["row"][0])
    except (TypeError, ValueError):
        return []
    return camps if isinstance(camps, list) else []


def _write_campaigns(camps: list) -> None:
    _cypher(
        "MERGE (m:SpotterMeta {key:'campaigns'}) SET m.data = $data, m.updated_at = timestamp()",
        {"data": json.dumps(camps)},
    )


# ── Commands ─────────────────────────────────────────────────────────────────

def cmd_add(conn, args) -> int:
    name = db.normalise_username(args.username)
    if db.get_user(conn, name):
        print(f"User {name!r} already exists.", file=sys.stderr)
        return 1
    if not args.admin and db.active_admin_count(conn) == 0:
        print("The first account must be an administrator.\n"
              "Re-run with --admin, or leave the username empty in bootstrap "
              "and use the browser setup wizard.", file=sys.stderr)
        return 1
    password = _prompt_password(name, args.random)
    db.add_user(conn, name, password, is_admin=args.admin)
    print(f"Created {name}" + (" (admin)" if args.admin else ""))
    return 0


def cmd_list(conn, args) -> int:
    users = db.list_users(conn)
    if not users:
        print("No users. Create one with: scripts/spotter_user.py add <username>")
        return 0
    now = time.time()
    print(f"{'USERNAME':<24} {'ADMIN':<6} {'STATE':<9} {'CREATED':<17} FAILED")
    for u in users:
        locked = u["locked_until"] and u["locked_until"] > now
        status = u.get("approval_status") or "approved"
        if locked:
            state = "locked"
        elif status == "pending":
            state = "pending"
        elif status == "rejected":
            state = "rejected"
        elif not u["is_active"]:
            state = "disabled"
        else:
            state = "active"
        print(f"{u['username']:<24} {'yes' if u['is_admin'] else 'no':<6} {state:<9} "
              f"{_fmt_time(u['created_at']):<17} {u['failed_count']}")
    return 0


def cmd_passwd(conn, args) -> int:
    name = db.normalise_username(args.username)
    if not db.get_user(conn, name):
        print(f"No such user: {name}", file=sys.stderr)
        return 1
    password = _prompt_password(name, args.random)
    db.set_password(conn, name, password)
    # A password change should invalidate sessions opened with the old one.
    revoked = db.delete_sessions_for(conn, name)
    print(f"Password updated for {name} ({revoked} session(s) revoked)")
    return 0


def cmd_enable_disable(conn, args) -> int:
    name = db.normalise_username(args.username)
    try:
        db.set_active(conn, name, args.command == "enable")
    except KeyError:
        print(f"No such user: {name}", file=sys.stderr)
        return 1
    print(f"{name} {'enabled' if args.command == 'enable' else 'disabled'}")
    return 0


def cmd_delete(conn, args) -> int:
    name = db.normalise_username(args.username)
    if not args.force:
        reply = input(f"Delete user {name!r} and all their sessions? [y/N] ").strip().lower()
        if reply != "y":
            print("Aborted.")
            return 1
    try:
        db.delete_user(conn, name)
    except KeyError:
        print(f"No such user: {name}", file=sys.stderr)
        return 1
    print(f"Deleted {name}")
    print("Note: campaigns they owned are left in place — reassign with "
          f"'scripts/spotter_user.py adopt <campaign_id> <username>'.")
    return 0


def cmd_approve(conn, args) -> int:
    try:
        db.approve_user(conn, args.username, "cli")
    except KeyError:
        print(f"No such user: {args.username}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Approved {db.normalise_username(args.username)}")
    return 0


def cmd_reject(conn, args) -> int:
    try:
        db.reject_user(conn, args.username, "cli")
    except KeyError:
        print(f"No such user: {args.username}", file=sys.stderr)
        return 1
    print(f"Rejected {db.normalise_username(args.username)}")
    return 0


def cmd_role(conn, args) -> int:
    try:
        db.set_admin(conn, args.username, args.admin)
    except KeyError:
        print(f"No such user: {args.username}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    name = db.normalise_username(args.username)
    print(f"{name} is {'now' if args.admin else 'no longer'} an administrator")
    return 0


def cmd_sessions(conn, args) -> int:
    if args.revoke_all:
        print(f"Revoked {db.delete_all_sessions(conn)} session(s)")
        return 0
    if args.revoke:
        name = db.normalise_username(args.revoke)
        print(f"Revoked {db.delete_sessions_for(conn, name)} session(s) for {name}")
        return 0

    db.purge_expired(conn)
    rows = db.list_sessions(conn)
    if not rows:
        print("No active sessions.")
        return 0
    print(f"{'USERNAME':<24} {'LOGIN':<17} {'LAST SEEN':<17} EXPIRES")
    for r in rows:
        print(f"{r['username']:<24} {_fmt_time(r['created_at']):<17} "
              f"{_fmt_time(r['last_seen']):<17} {_fmt_time(r['expires_at'])}")
    return 0


def cmd_campaigns(conn, args) -> int:
    camps = _read_campaigns()
    if not camps:
        print("Campaign registry is empty.")
        return 0
    print(f"{'CAMPAIGN ID':<26} {'OWNER':<20} {'SHARED WITH':<28} NAME")
    for c in camps:
        owner = c.get("owner") or "— unowned —"
        shared = ",".join(c.get("sharedWith") or []) or "-"
        print(f"{str(c.get('id','')):<26} {owner:<20} {shared:<28} {c.get('name','')}")
    return 0


def cmd_adopt(conn, args) -> int:
    name = db.normalise_username(args.username)
    if not db.get_user(conn, name):
        print(f"No such user: {name}", file=sys.stderr)
        return 1

    camps = _read_campaigns()
    target = next((c for c in camps if str(c.get("id")) == args.campaign_id), None)
    if target is None:
        print(f"No such campaign: {args.campaign_id}", file=sys.stderr)
        return 1

    current = target.get("owner")
    if current and current != name and not args.force:
        print(f"Campaign {args.campaign_id!r} is already owned by {current!r}. "
              f"Re-run with --force to reassign.", file=sys.stderr)
        return 1

    owned = sum(1 for c in camps if c.get("owner") == name)
    limit = int(os.environ.get("SPOTTER_MAX_CAMPAIGNS_PER_USER") or
                _load_dotenv().get("SPOTTER_MAX_CAMPAIGNS_PER_USER") or 3)
    if current != name and owned >= limit:

    p = sub.add_parser("approve", help="approve a pending registration")
    p.add_argument("username")

    p = sub.add_parser("reject", help="reject a registration and drop its sessions")
    p.add_argument("username")

    p = sub.add_parser("admin", help="grant or revoke administrator")
    p.add_argument("username")
    role = p.add_mutually_exclusive_group(required=True)
    role.add_argument("--grant", dest="admin", action="store_true")
    role.add_argument("--revoke", dest="admin", action="store_false")
        print(f"{name} already owns {owned} campaign(s); limit is {limit}.", file=sys.stderr)
        return 1

    target["owner"] = name
    target.setdefault("sharedWith", [])
    _write_campaigns(camps)
    print(f"{args.campaign_id} is now owned by {name}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manage SPOTTER operator accounts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--db", help=f"auth database path (default: {HOST_DB_DEFAULT})")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("add", help="create an operator account")
    p.add_argument("username")
    p.add_argument("--admin", action="store_true", help="mark as an admin account")
    p.add_argument("--random", action="store_true", help="generate and print a password")

    sub.add_parser("list", help="list operator accounts")

    p = sub.add_parser("passwd", help="set a password (revokes their sessions)")
    p.add_argument("username")
    p.add_argument("--random", action="store_true", help="generate and print a password")

    for verb, helptext in (("enable", "re-enable an account"),
                           ("disable", "disable an account and drop its sessions")):
        p = sub.add_parser(verb, help=helptext)
        p.add_argument("username")

    p = sub.add_parser("delete", help="delete an account and its sessions")
    p.add_argument("username")
    p.add_argument("--force", action="store_true", help="skip the confirmation prompt")

    p = sub.add_parser("sessions", help="list or revoke live sessions")
    p.add_argument("--revoke", metavar="USERNAME", help="revoke one user's sessions")
    p.add_argument("--revoke-all", action="store_true", help="revoke every session")

    sub.add_parser("campaigns", help="list campaigns and their owners")

    p = sub.add_parser("adopt", help="assign an unowned campaign to a user")
    p.add_argument("campaign_id")
    p.add_argument("username")
    p.add_argument("--force", action="store_true", help="reassign an already-owned campaign")

    args = parser.parse_args()

    path = _resolve_db_path(args.db)
        "approve": cmd_approve, "reject": cmd_reject, "admin": cmd_role,
    }
    try:
        return handlers[args.command](conn, args)
    except db.LastAdminError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1ripts/spotter_user.py add <username>",
              file=sys.stderr)
        return 1

    conn = db.connect(path)
    handlers = {
        "add": cmd_add, "list": cmd_list, "passwd": cmd_passwd,
        "enable": cmd_enable_disable, "disable": cmd_enable_disable,
        "delete": cmd_delete, "sessions": cmd_sessions,
        "campaigns": cmd_campaigns, "adopt": cmd_adopt,
    }
    try:
        return handlers[args.command](conn, args)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    sys.exit(main())
