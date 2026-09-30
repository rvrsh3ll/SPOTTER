#!/usr/bin/env python3
"""SPOTTER credential management.

This is how an admin adds or changes an API key or password. `.env` is for
CONFIGURATION ONLY -- hosts, ports, paths, limits, feature flags. Credentials
live encrypted in secrets/*.sops.env and only ever get there through this script
or `sops` directly.

Stdlib only -- run it directly, no virtualenv needed:

    scripts/spotter_secret.py list
    scripts/spotter_secret.py set SHODAN_API_KEY
    scripts/spotter_secret.py set CENSYS_API_KEY --tier vendors
    scripts/spotter_secret.py get FLARE_API_KEY
    scripts/spotter_secret.py rm SLACK_WEBHOOK_URL
    scripts/spotter_secret.py edit vendors
    scripts/spotter_secret.py audit

WHY A SCRIPT RATHER THAN "JUST EDIT THE FILE"

Three things go wrong when a human does this by hand, and all three have already
happened in this repo or its neighbours:

  * The value ends up in `.env` in plaintext, because that is what .env.example's
    per-key comments still tell you to do and nothing objects.
  * The value ends up in shell history or `ps` output, the way
    OWUI_ADMIN_PASSWORD still does at scripts/bootstrap.sh:281-288. Every prompt
    here uses getpass, and no subcommand accepts a value as an argument.
  * A tier gets decrypted for editing and not re-encrypted.

Values are never printed except by `get --reveal`, which exists for the case
where you genuinely need to paste a key back into a vendor console.
"""

from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spotter_env as se  # noqa: E402

TIER_BLURB = {
    "machine": "generated per host; never shared or copied between installs",
    "vendors": "optional third-party API accounts; local encrypted tier, not tracked by Git",
    "engagement": "reaches live operator infrastructure; never committed",
}


def _fail(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 1


def _tier_of_file(path: str) -> str:
    return os.path.basename(path).replace(".sops.env", "")


def _env_assignments() -> dict[str, str]:
    """Raw `KEY=value` assignments in .env, ignoring comments."""
    if not os.path.isfile(se.ENV_PATH):
        return {}
    with open(se.ENV_PATH, encoding="utf-8") as fh:
        return se._parse_dotenv(fh.read())


def _remove_from_env(key: str, note: str) -> bool:
    """Drop a plaintext assignment from .env, leaving a pointer comment.

    Without this, `set` would write the encrypted copy and leave the plaintext
    one sitting in .env, where it still wins for any reader that consults .env
    first -- and still leaks.
    """
    with open(se.ENV_PATH, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    out, hit = [], False
    for line in lines:
        m = se._ASSIGN_RE.match(line)
        if m and m.group(1) == key:
            # The note is passed in rather than derived: on `rm` there is no
            # destination tier, and deriving one produced a pointer to
            # "secrets/unknown-secret.sops.env", a file that cannot exist.
            out.append(f"# {key} -> {note}")
            hit = True
        else:
            out.append(line)
    if hit:
        with open(se.ENV_PATH, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
        os.chmod(se.ENV_PATH, 0o600)
    return hit


def _prompt_tier(key: str) -> str | None:
    print(f"\n{key} looks like a credential but is not classified.")
    print("Which tier does it belong in?\n")
    names = [n for n, _ in se.TIERS]
    for i, n in enumerate(names, 1):
        print(f"  {i}. {n:11s} {TIER_BLURB[n]}")
    print()
    try:
        raw = input("tier [1-3, or a name]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if raw.isdigit() and 1 <= int(raw) <= len(names):
        return names[int(raw) - 1]
    if raw in names:
        return raw
    print(f"not a tier: {raw!r}", file=sys.stderr)
    return None


# ── subcommands ──────────────────────────────────────────────────────────────
def cmd_list(args) -> int:
    tiers = se.tier_files()
    if not tiers:
        print("No encrypted tiers yet. Run deployment/setup-secrets.sh, or "
              "scripts/split_env_to_sops.py to create them.")
        return 0
    for path in tiers:
        name = _tier_of_file(path)
        try:
            keys = sorted(se._parse_dotenv(se._decrypt(path)))
        except RuntimeError as exc:
            print(f"{name}: CANNOT DECRYPT — {exc}")
            continue
        print(f"\n{name}  ({len(keys)} keys)  — {TIER_BLURB.get(name, '')}")
        for k in keys:
            # An empty value is worth showing: it means the key is known but
            # unconfigured, which is different from absent.
            value = se.load().get(k) or ""
            print(f"    {k:26s} {'set' if value else '(empty)'}")
    unset = [k for _, keys in se.TIERS for k in keys
             if not (se.load().get(k) or "")]
    if unset:
        print(f"\nKnown but not configured ({len(unset)}): {', '.join(sorted(unset))}")
        print("  scripts/spotter_secret.py set <KEY>")
    return 0


def cmd_set(args) -> int:
    key = args.key
    kind = se.classify(key)
    tier = args.tier

    if not tier:
        if kind in [n for n, _ in se.TIERS]:
            tier = kind
        elif kind == se.UNKNOWN_SECRET:
            tier = _prompt_tier(key)
            if not tier:
                return 1
        else:
            return _fail(
                f"{key} is not a credential -- it classifies as configuration.\n"
                f"Put it in .env directly. If that is wrong, add it to a tier list "
                f"in scripts/spotter_env.py (or to NOT_SECRETS if it only looks "
                f"like a secret)."
            )

    if args.stdin:
        # For scripting. Still not an argument, so it stays out of argv and history.
        value = sys.stdin.readline().rstrip("\n")
    else:
        value = getpass.getpass(f"{key} value (input hidden): ")
        if value and getpass.getpass("confirm: ") != value:
            return _fail("values did not match; nothing written")
    if not value:
        return _fail("empty value; nothing written")

    path = se.set_value(key, value, tier=tier)
    print(f"wrote {key} -> {os.path.relpath(path, se.REPO)}")

    if _remove_from_env(key, f"secrets/{tier}.sops.env   "
                             f"(moved by scripts/spotter_secret.py)"):
        print(f"removed the plaintext {key} from .env (left a pointer comment)")

    if tier == "vendors":
          print("note: vendor credentials are local and gitignored; share them only "
              "through an approved secret-sharing process.")
    if tier == "machine":
        print("note: machine-tier values are per host. A new host generates its "
              "own; do not copy this one.")
    print("\nThe stack reads secrets at container-create time, so this takes "
          "effect on:\n  scripts/spotter_compose.sh up -d --force-recreate <service>")
    return 0


def cmd_get(args) -> int:
    key = args.key
    value = se.get(key)
    where = "not found"
    for path in se.tier_files():
        if key in se._parse_dotenv(se._decrypt(path)):
            where = f"secrets/{_tier_of_file(path)}.sops.env"
            break
    else:
        if key in _env_assignments():
            where = ".env (PLAINTEXT)"

    print(f"{key}: {'set' if value else 'missing'}"
          f"{f' ({len(value)} chars)' if value else ''}")
    print(f"  classified: {se.classify(key)}")
    print(f"  stored in:  {where}")
    if args.reveal:
        if not value:
            return 1
        print(f"  value:      {value}")
    elif value:
        print("  (use --reveal to print the value)")
    return 0


def cmd_rm(args) -> int:
    key = args.key
    target = None
    for path in se.tier_files():
        if key in se._parse_dotenv(se._decrypt(path)):
            target = path
            break
    if not target:
        if _remove_from_env(key, "removed by scripts/spotter_secret.py"):
            print(f"removed the plaintext {key} from .env")
            return 0
        return _fail(f"{key} is not in any tier or in .env")

    if not args.force:
        try:
            if input(f"remove {key} from {os.path.relpath(target, se.REPO)}? [y/N] "
                     ).strip().lower() not in ("y", "yes"):
                print("cancelled")
                return 1
        except (EOFError, KeyboardInterrupt):
            print()
            return 1

    proc = subprocess.run(["sops", "unset", target, f'["{key}"]'],
                          capture_output=True, text=True, cwd=se.REPO)
    if proc.returncode != 0:
        return _fail(f"sops unset failed: {(proc.stderr or '').strip()}")
    se.load(refresh=True)
    print(f"removed {key} from {os.path.relpath(target, se.REPO)}")
    return 0


def cmd_edit(args) -> int:
    path = se.tier_path(args.tier)
    if not os.path.exists(path):
        return _fail(f"no such tier: {path}")
    env = dict(os.environ)
    # sops shells out to $EDITOR and re-encrypts on save. EDITOR is commonly
    # unset on a server, in which case sops fails rather than picking one.
    if not env.get("EDITOR") and not env.get("VISUAL"):
        for cand in ("sensible-editor", "nano", "vim", "vi"):
            found = subprocess.run(["which", cand], capture_output=True, text=True)
            if found.returncode == 0:
                env["EDITOR"] = found.stdout.strip()
                print(f"EDITOR was unset; using {env['EDITOR']}")
                break
    return subprocess.run(["sops", path], cwd=se.REPO, env=env).returncode


def cmd_audit(args) -> int:
    """Report credentials sitting in .env as plaintext.

    Same logic as check_no_plaintext_secrets_in_env() in
    scripts/check_workflow_regressions.py, available on its own so an admin can
    check before committing rather than finding out from a failing build.
    """
    offenders = []
    for key, value in sorted(_env_assignments().items()):
        if not se.is_secret(key):
            continue
        v = (value or "").strip()
        if not v or v.startswith("REPLACE_WITH_"):
            continue            # absent or an untouched placeholder: not a leak
        offenders.append((key, se.classify(key)))

    if not offenders:
        print("OK: no plaintext credentials in .env")
        return 0
    print(f"{len(offenders)} plaintext credential(s) in .env:\n")
    for key, kind in offenders:
        dest = kind if kind != se.UNKNOWN_SECRET else "<choose a tier>"
        print(f"  {key:28s} belongs in {dest}")
    print("\nMove them with:")
    for key, _ in offenders:
        print(f"  scripts/spotter_secret.py set {key}")
    print("\nor all at once:  scripts/split_env_to_sops.py --merge")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Manage SPOTTER's encrypted credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="`.env` is for configuration. Credentials go in secrets/*.sops.env.",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show tiers and key names (never values)")

    p = sub.add_parser("set", help="add or change a credential (prompts; no argv)")
    p.add_argument("key")
    p.add_argument("--tier", choices=[n for n, _ in se.TIERS],
                   help="override the classification")
    p.add_argument("--stdin", action="store_true",
                   help="read the value from stdin instead of prompting")

    p = sub.add_parser("get", help="report whether a key is set, and where")
    p.add_argument("key")
    p.add_argument("--reveal", action="store_true", help="print the value")

    p = sub.add_parser("rm", help="remove a credential from its tier")
    p.add_argument("key")
    p.add_argument("--force", action="store_true", help="skip the confirmation")

    p = sub.add_parser("edit", help="open a tier in $EDITOR via sops")
    p.add_argument("tier", choices=[n for n, _ in se.TIERS])

    sub.add_parser("audit", help="find plaintext credentials in .env")

    args = ap.parse_args()
    return {
        "list": cmd_list, "set": cmd_set, "get": cmd_get,
        "rm": cmd_rm, "edit": cmd_edit, "audit": cmd_audit,
    }[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
