#!/usr/bin/env python3
"""Move the secrets out of .env into encrypted, tiered SOPS files.

WHY THIS EXISTS

`.env` held every secret as plaintext next to ~135 lines of ordinary config. Two
consequences: the file could never be committed or shared, so the configuration
was unreviewable; and sharing the stack with another operator meant handing over
*every* credential at once, including the ones that reach live C2 and tunnel
infrastructure.

This splits it into four files:

    .env                        the non-secret config -- still gitignored, but
                                now diffable and safe to paste into an issue
    secrets/machine.sops.env    generated per host, never shared
    secrets/vendors.sops.env    third-party API keys, local and gitignored
    secrets/engagement.sops.env reaches live operator infra, never committed

Tiering separates credentials by purpose. Share a tier only through an approved
secret-sharing process and only with recipients authorized to use those credentials.

The classification below is an EXPLICIT allowlist, not a pattern match, and it
has to stay that way: `.env` contains SERP_ROLE_KEYWORDS, FLARE_DOMAIN_MAX_CREDS,
VLLM_SPEC_TOKENS, SPOTTER_CRED_SCAN_MAX_BYTES, SPOTTER_TUNNEL_KEYS_DIR and
TUNNEL_HOST_KEY_POLICY, all of which match /KEY|TOKEN|SECRET|CRED/ and none of
which is a secret. A regex would encrypt tunables and make them invisible.

Usage:
    scripts/split_env_to_sops.py --dry-run     # report, change nothing
    scripts/split_env_to_sops.py
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(REPO, ".env")
SECRETS_DIR = os.path.join(REPO, "secrets")

# The tier lists live in spotter_env so that the splitter, the admin CLI
# (scripts/spotter_secret.py) and the plaintext guard in
# scripts/check_workflow_regressions.py all agree on what a secret is. A second
# copy here is exactly how they would drift apart.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spotter_env  # noqa: E402

TIERS = spotter_env.TIERS

ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def tier_of(key: str) -> str | None:
    """The tier a key belongs to, or None to leave it in .env.

    Only keys with a definite tier are moved. A credential-shaped key that
    nobody has classified is reported separately by main() rather than guessed
    at, because picking a tier picks a sharing boundary.
    """
    kind = spotter_env.classify(key)
    return kind if kind in [n for n, _ in TIERS] else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="report the split without writing anything")
    ap.add_argument("--no-backup", action="store_true",
                    help="skip the plaintext .env backup. Used by "
                         "deployment/setup-secrets.sh, where the values were just "
                         "generated so there is nothing to recover -- and the "
                         "backup would be the only plaintext copy left on disk.")
    ap.add_argument("--merge", action="store_true",
                    help="fold newly-found keys into existing tiers, keeping "
                         "what is already there (what setup-secrets.sh uses)")
    ap.add_argument("--force", action="store_true",
                    help="REPLACE existing secrets/*.sops.env with only what .env "
                         "holds -- discards keys already in a tier. Use --merge "
                         "unless you mean that.")
    args = ap.parse_args()

    if not os.path.isfile(ENV_PATH):
        print(f"no .env at {ENV_PATH}", file=sys.stderr)
        return 2

    with open(ENV_PATH, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    # Collect values per tier, and rewrite the .env line into a breadcrumb so
    # the next reader can see where the value went rather than assuming it was
    # lost. A commented-out assignment is left alone: it is documentation.
    collected: dict[str, list[tuple[str, str]]] = {n: [] for n, _ in TIERS}
    out: list[str] = []
    for line in lines:
        m = ASSIGN_RE.match(line)
        if not m:
            out.append(line)
            continue
        key, value = m.group(1), m.group(2)
        tier = tier_of(key)
        if tier is None:
            out.append(line)
            continue
        collected[tier].append((key, value))
        out.append(f"# {key} -> secrets/{tier}.sops.env   (moved by "
                   f"scripts/split_env_to_sops.py)")

    total = sum(len(v) for v in collected.values())
    for name, _ in TIERS:
        got = collected[name]
        print(f"{name:11s} {len(got):3d} keys: "
              f"{', '.join(k for k, _ in got) if got else '(none)'}")
    print(f"{'TOTAL':11s} {total:3d} moved; {len(out) - total} lines stay in .env")

    if args.dry_run:
        print("\n--dry-run: nothing written")
        return 0
    if total == 0:
        print("\nnothing to move -- already split?")
        return 0

    os.makedirs(SECRETS_DIR, exist_ok=True)
    os.chmod(SECRETS_DIR, 0o700)

    for name, _ in TIERS:
        dest = os.path.join(SECRETS_DIR, f"{name}.sops.env")
        existing: dict[str, str] = {}
        if os.path.exists(dest):
            if args.merge:
                # Keep what the tier already holds. Without this, a second run
                # (which is what setup-secrets.sh does on every bootstrap) would
                # rewrite the tier from .env alone and drop every key that is
                # already encrypted -- i.e. all of them.
                existing = spotter_env._parse_dotenv(spotter_env._decrypt(dest))
            elif not args.force:
                print(f"refusing to overwrite {dest} (use --merge, or --force to "
                       "replace it wholesale)", file=sys.stderr)
                return 1
        pairs = collected[name]
        if not pairs and not existing:
            continue
        merged = dict(existing)
        merged.update(dict(pairs))
        pairs = sorted(merged.items())
        # Encrypt from a 0600 temp file inside secrets/ -- not /tmp, and never
        # by piping through a shell, so the plaintext never becomes an argv or
        # leaves this directory.
        fd, tmp = tempfile.mkstemp(dir=SECRETS_DIR, prefix=f".{name}-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                for key, value in pairs:
                    fh.write(f"{key}={value}\n")
            # --filename-override matters: sops matches .sops.yaml's path_regex
            # against the INPUT path, not --output. Without it the temp name is
            # what gets matched and sops exits "no matching creation rules found".
            subprocess.run(
                ["sops", "--encrypt", "--input-type", "dotenv",
                 "--output-type", "dotenv", "--filename-override", dest,
                 "--output", dest, tmp],
                cwd=REPO, check=True,
            )
            os.chmod(dest, 0o600)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        print(f"wrote {dest}")

    backup = None
    if not args.no_backup:
        backup = ENV_PATH + ".pre-sops.bak"
        shutil.copy2(ENV_PATH, backup)
        os.chmod(backup, 0o600)

    # Rewrite in place rather than replacing the file: vendor/flowsint/.env is a
    # symlink to this path and setup-secrets.sh treats this as the one real file.
    with open(ENV_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    os.chmod(ENV_PATH, 0o600)

    print(f"\nrewrote {ENV_PATH} ({total} secret lines replaced with pointers)")
    if backup:
        print(f"PLAINTEXT BACKUP at {backup} -- shred it once you have verified "
              f"the stack comes up:\n  shred -u {backup}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
