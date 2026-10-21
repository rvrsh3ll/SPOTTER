#!/usr/bin/env python3
"""
generate_identity.py — Disposable identity generator for SPOTTER.

WHAT IT IS FOR
--------------
Wraps the procedure in scripts/disposable_identity.md to create throwaway
identities for use with Russian OSINT services. Generates credentials and
logs them; the actual email account creation (atomicmail, duck.com, proton)
is a separate browser-driven step documented in disposable_identity.md.

This script is the programmatic entry point that SPOTTER workflows call.
The manual procedure (Tor setup, browser signups, CAPTCHA solving) is
documented in disposable_identity.md and is NOT automated here.

USAGE
-----
    # Generate a new identity for a campaign
    python3 scripts/generate_identity.py "campaign-ru-01"

    # Generate with Proton account
    python3 scripts/generate_identity.py "telegram-bot" --with-proton

    # List active identities
    python3 scripts/generate_identity.py --list

    # Retire a burned identity
    python3 scripts/generate_identity.py --retire eagleprairieplum20

    # Rotate: retire oldest for this purpose, create new
    python3 scripts/generate_identity.py --rotate "rus-leak-lookup"
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Ensure the scripts directory is on the path so identity_store is importable
# when called from n8n task runners (which add /data/scripts).
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from identity_store import IdentityStore


def cmd_create(args: argparse.Namespace) -> None:
    store = IdentityStore()
    ident = store.create(purpose=args.purpose)
    print(json.dumps(ident, indent=2))
    if args.with_proton:
        print(f"\nProton account: {ident['username']}@proton.me (create manually per disposable_identity.md §4)")
    print(f"\nNext steps (see scripts/disposable_identity.md):")
    print(f"  1. Create atomicmail inbox: https://atomicmail.io → sign up as {ident['username']}")
    print(f"  2. Create Duck address: https://duckduckgo.com/email/ → {ident['username']}@duck.com")
    if args.with_proton:
        print(f"  3. Create Proton account: https://account.proton.me/signup → {ident['username']}@proton.me")


def cmd_list(args: argparse.Namespace) -> None:
    store = IdentityStore()
    rows = store.list_all() if args.all else store.list_active()
    if not rows:
        print("No identities found.")
        return
    print(f"{'Username':<30s}  {'Status':<12s}  {'Purpose':<25s}  {'Created':<20s}  {'Duck':<10s}")
    print("-" * 100)
    for r in rows:
        print(f"{r['username']:<30s}  {r['status']:<12s}  {(r.get('purpose') or ''):<25s}  "
              f"{(r.get('created') or ''):<20s}  {(r.get('duck_status') or ''):<10s}")


def cmd_retire(args: argparse.Namespace) -> None:
    store = IdentityStore()
    ok = store.retire(args.username)
    if ok:
        print(f"Retired: {args.username}")
    else:
        print(f"Not found: {args.username}", file=sys.stderr)
        sys.exit(1)


def cmd_rotate(args: argparse.Namespace) -> None:
    store = IdentityStore()
    ident = store.rotate(purpose=args.purpose)
    print(json.dumps(ident, indent=2))


def cmd_get(args: argparse.Namespace) -> None:
    store = IdentityStore()
    row = store.get(args.username)
    if row:
        print(json.dumps(row, indent=2))
    else:
        print(f"Not found: {args.username}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SPOTTER disposable identity generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See scripts/disposable_identity.md for the full account-creation procedure.",
    )
    sub = parser.add_subparsers(dest="command")

    p_create = sub.add_parser("create", help="Generate a new identity")
    p_create.add_argument("purpose", nargs="?", default="unspecified",
                          help="Purpose tag (e.g. campaign name, workflow name)")
    p_create.add_argument("--with-proton", action="store_true",
                          help="Also plan a Proton account (manual creation)")

    p_list = sub.add_parser("list", help="List identities")
    p_list.add_argument("--all", action="store_true", help="Include retired/taken")

    p_retire = sub.add_parser("retire", help="Retire a burned identity")
    p_retire.add_argument("username", help="Username to retire")

    p_rotate = sub.add_parser("rotate", help="Rotate identity for a purpose")
    p_rotate.add_argument("purpose", help="Purpose to rotate")

    p_get = sub.add_parser("get", help="Get identity details")
    p_get.add_argument("username", help="Username to look up")

    args = parser.parse_args()

    if args.command == "create":
        cmd_create(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "retire":
        cmd_retire(args)
    elif args.command == "rotate":
        cmd_rotate(args)
    elif args.command == "get":
        cmd_get(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
