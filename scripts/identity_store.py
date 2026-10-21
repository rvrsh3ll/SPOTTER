#!/usr/bin/env python3
"""
identity_store.py — CSV-backed disposable identity lifecycle manager for SPOTTER.

WHAT IT IS FOR
--------------
SPOTTER workflows that interact with Russian OSINT services (Getcontact,
Nomerogram, Telegram bots, EGRUL CAPTCHA sessions) need throwaway accounts
that are not linked to the operator. This module manages a local CSV of
disposable identities created by the procedure in scripts/disposable_identity.md.

Each identity has:
  - A generated username (word-word-word-NN)
  - An @atomicmail.io inbox
  - An @duck.com forwarding alias
  - An optional @proton.me account
  - A generated password
  - A purpose tag (which campaign / workflow created it)
  - A status (active / retired / taken)

The CSV lives at ~/.disposable-identities/identities.csv (mode 600).
The directory is created at mode 700 if absent.

THREAD SAFETY
-------------
This module is called from n8n task runners, which are single-process per
workflow. File locking via fcntl.flock is used for the CSV write path so
concurrent identity creation from parallel workflows does not corrupt the file.

IMPORT ALLOWLIST
----------------
This module runs inside the n8n Python task runner. Only stdlib + requests are
available. No bs4, no lxml. The module uses only stdlib here (csv, json, os,
secrets, time, fcntl, pathlib).
"""

from __future__ import annotations

import csv
import fcntl
import json
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Wordlist ──────────────────────────────────────────────────────────────────
# ~150 nature words for username generation. Three words + two digits gives
# ~150^3 * 100 = 337 million combinations, more than enough for throwaway IDs.
_WORDS = [
    "alder", "aspen", "badger", "basil", "beech", "birch", "bison", "brook",
    "cedar", "chive", "coast", "coral", "crane", "creek", "crow", "deer",
    "dove", "eagle", "elm", "falcon", "fern", "finch", "fir", "fox",
    "glade", "goose", "grove", "gull", "hare", "hawk", "hazel", "heron",
    "holly", "hawk", "ibis", "iris", "ivy", "jay", "kestrel", "kite",
    "lark", "laurel", "lily", "linnet", "loon", "lynx", "maple", "marten",
    "meadow", "mint", "moss", "moose", "moth", "nettle", "oak", "olive",
    "oriole", "otter", "owl", "palm", "pine", "plover", "plum", "pond",
    "quail", "raven", "reed", "ridge", "robin", "rose", "rowan", "rush",
    "sage", "sand", "seal", "shrike", "skunk", "slate", "snipe", "sparrow",
    "spruce", "starling", "stone", "stork", "swift", "tanager", "thistle",
    "thrush", "tiger", "trout", "viper", "vixen", "walrus", "wasp", "whale",
    "willow", "wren", "yarrow",
]

# ── Paths ─────────────────────────────────────────────────────────────────────
_DEFAULT_DIR = os.path.expanduser("~/.disposable-identities")
_IDENTITY_DIR = os.environ.get("SPOTTER_IDENTITY_DIR", _DEFAULT_DIR).strip() or _DEFAULT_DIR
_CSV_PATH = os.path.join(_IDENTITY_DIR, "identities.csv")
_SEEDS_DIR = os.path.join(_IDENTITY_DIR, "seeds")

_CSV_COLUMNS = [
    "created", "username", "atomicmail", "duck_alias", "password",
    "purpose", "status", "atomicmail_seed_file", "duck_status",
    "proton_status", "notes",
]


def _ensure_dir() -> None:
    """Create the identity directory structure if absent."""
    p = Path(_IDENTITY_DIR)
    if not p.exists():
        p.mkdir(parents=True, mode=0o700)
    seeds = Path(_SEEDS_DIR)
    if not seeds.exists():
        seeds.mkdir(mode=0o700)
    csv_path = Path(_CSV_PATH)
    if not csv_path.exists():
        csv_path.touch(mode=0o600)


def _generate_username() -> str:
    """Three random nature words + two digits, e.g. eagleprairieplum20."""
    words = [secrets.choice(_WORDS) for _ in range(3)]
    num = secrets.randbelow(100)
    return "".join(words) + f"{num:02d}"


def _generate_password(length: int = 20) -> str:
    """20-char password with upper, lower, digit, symbol."""
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    all_chars = upper + lower + digits + symbols
    while True:
        pw = "".join(secrets.choice(all_chars) for _ in range(length))
        if (any(c in upper for c in pw) and any(c in lower for c in pw)
                and any(c in digits for c in pw) and any(c in symbols for c in pw)):
            return pw


def _read_csv() -> List[Dict[str, str]]:
    """Read the identity CSV, returning a list of row dicts."""
    _ensure_dir()
    rows: List[Dict[str, str]] = []
    try:
        with open(_CSV_PATH, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(dict(row))
    except FileNotFoundError:
        pass
    return rows


def _write_csv(rows: List[Dict[str, str]]) -> None:
    """Write the identity CSV with file locking."""
    _ensure_dir()
    with open(_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            writer = csv.DictWriter(f, fieldnames=_CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


class IdentityStore:
    """Manage disposable identities for SPOTTER workflows."""

    def __init__(self, identity_dir: Optional[str] = None):
        self.identity_dir = identity_dir or _IDENTITY_DIR
        self.csv_path = os.path.join(self.identity_dir, "identities.csv")
        _ensure_dir()

    def create(self, purpose: str = "") -> Dict[str, Any]:
        """Generate a new identity and log it to the CSV.

        Returns the identity dict. Does NOT create the actual email accounts —
        that requires the browser-driven procedure in disposable_identity.md.
        This method only generates the credentials and logs them.
        """
        username = _generate_username()
        password = _generate_password()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        identity = {
            "created": now,
            "username": username,
            "atomicmail": f"{username}@atomicmail.io",
            "duck_alias": f"{username}@duck.com",
            "password": password,
            "purpose": purpose or "unspecified",
            "status": "generated",
            "atomicmail_seed_file": "",
            "duck_status": "pending",
            "proton_status": "",
            "notes": "",
        }

        rows = _read_csv()
        rows.append(identity)
        _write_csv(rows)

        return identity

    def get(self, username: str) -> Optional[Dict[str, str]]:
        """Retrieve an identity by username."""
        for row in _read_csv():
            if row.get("username") == username:
                return row
        return None

    def update(self, username: str, **fields: str) -> bool:
        """Update fields on an existing identity. Returns True if found."""
        rows = _read_csv()
        for row in rows:
            if row.get("username") == username:
                for k, v in fields.items():
                    if k in _CSV_COLUMNS:
                        row[k] = str(v)
                _write_csv(rows)
                return True
        return False

    def retire(self, username: str) -> bool:
        """Mark an identity as retired (burned). Returns True if found."""
        return self.update(username, status="retired")

    def list_active(self) -> List[Dict[str, str]]:
        """Return all non-retired identities."""
        return [r for r in _read_csv() if r.get("status") not in ("retired", "taken")]

    def list_all(self) -> List[Dict[str, str]]:
        """Return every identity regardless of status."""
        return _read_csv()

    def rotate(self, purpose: str) -> Dict[str, Any]:
        """Retire the oldest active identity for this purpose and create a new one."""
        active = [r for r in _read_csv()
                  if r.get("status") not in ("retired", "taken")
                  and r.get("purpose") == purpose]
        if active:
            oldest = min(active, key=lambda r: r.get("created", ""))
            self.retire(oldest["username"])
        return self.create(purpose)

    def save_seed(self, username: str, seed_phrase: str) -> Optional[str]:
        """Save a recovery seed phrase to a file and record its path."""
        seed_file = os.path.join(_SEEDS_DIR, f"seeds-{username}.txt")
        with open(seed_file, "w", encoding="utf-8") as f:
            f.write(seed_phrase)
        os.chmod(seed_file, 0o600)
        self.update(username, atomicmail_seed_file=seed_file)
        return seed_file

    def mark_duck_active(self, username: str) -> bool:
        return self.update(username, duck_status="duck_forwarding_active")

    def mark_proton_active(self, username: str, proton_email: str = "") -> bool:
        note = f"active ({proton_email})" if proton_email else "active"
        return self.update(username, proton_status=note)

    def mark_taken(self, username: str) -> bool:
        return self.update(username, status="taken")

    def add_note(self, username: str, note: str) -> bool:
        """Append a note to an identity's notes field."""
        row = self.get(username)
        if not row:
            return False
        existing = row.get("notes", "")
        new_notes = f"{existing}; {note}" if existing else note
        return self.update(username, notes=new_notes)

    def to_json(self, username: str) -> str:
        """Return an identity as a JSON string (for passing to workflows)."""
        row = self.get(username)
        if not row:
            return json.dumps({"error": f"identity {username!r} not found"})
        return json.dumps(row, indent=2)


# ── CLI entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    store = IdentityStore()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"

    if cmd == "create":
        purpose = sys.argv[2] if len(sys.argv) > 2 else "cli"
        ident = store.create(purpose)
        print(json.dumps(ident, indent=2))
    elif cmd == "get":
        username = sys.argv[2] if len(sys.argv) > 2 else ""
        print(store.to_json(username))
    elif cmd == "retire":
        username = sys.argv[2] if len(sys.argv) > 2 else ""
        ok = store.retire(username)
        print(f"retired: {ok}")
    elif cmd == "rotate":
        purpose = sys.argv[2] if len(sys.argv) > 2 else "cli"
        ident = store.rotate(purpose)
        print(json.dumps(ident, indent=2))
    elif cmd == "list":
        for row in store.list_active():
            print(f"  {row['username']:30s}  {row['status']:12s}  {row['purpose']}")
    elif cmd == "list-all":
        for row in store.list_all():
            print(f"  {row['username']:30s}  {row['status']:12s}  {row['created']}  {row['purpose']}")
    else:
        print(f"Usage: {sys.argv[0]} [create|get|retire|rotate|list|list-all] [args...]")
        sys.exit(1)
