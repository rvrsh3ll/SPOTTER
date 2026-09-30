#!/usr/bin/env python3
"""One place to read SPOTTER's configuration and secrets.

WHY THIS EXISTS

Secrets used to live as plaintext `KEY=value` lines in `.env`, and seven scripts
read that file directly with their own line-scanner. They had to: `.env` is NOT
shell-sourceable (EDGAR_USER_AGENT carries unquoted parens, so `set -a; . .env`
dies with a syntax error), so everyone wrote their own `sed`/regex instead.

Now `.env` holds configuration only and the credentials live in
`secrets/*.sops.env`, encrypted to the age recipients in `.sops.yaml`. Those
seven readers would each see a file whose secret lines have become pointer
comments -- a silent "value is missing", not an error. This module is what they
call instead.

Scope note: this is for HOST-SIDE operator scripts. Code running inside the n8n
Python runner still reads `os.environ`, because scripts/spotter_compose.sh
decrypts the tiers and hands the merged result to compose, which interpolates
them into the container environment at create time. Nothing inside a container
needs sops, and nothing inside a container should have the age key.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(REPO, ".env")
SECRETS_DIR = os.path.join(REPO, "secrets")

_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")

_cache: dict[str, str] | None = None


# ── which tier a key belongs to ───────────────────────────────────────────────
#
# These three lists are the single source of truth for the split. Both
# scripts/split_env_to_sops.py and scripts/spotter_secret.py import them, and
# check_no_plaintext_secrets_in_env() in scripts/check_workflow_regressions.py
# decides what counts as a leak from them. Keeping a second copy anywhere is how
# the guard and the splitter would drift into disagreeing about what a secret is.

# Generated per host by deployment/setup-secrets.sh, or minted against this
# install (the Flowsint JWT). Never copied between machines.
MACHINE = [
    "AUTH_SECRET",
    "MASTER_VAULT_KEY_V1",
    "NEO4J_PASSWORD",
    "POSTGRES_PASSWORD",
    "N8N_PASSWORD",
    "N8N_ENCRYPTION_KEY",
    "WEBUI_SECRET_KEY",
    "VLLM_API_KEY",
    "EMBEDDING_API_KEY",
    "TUNNEL_API_TOKEN",
    "FLOWSINT_API_KEY",
    "OWUI_ADMIN_PASSWORD",
]

# Third-party accounts. Billable and attributable, but not engagement-specific,
# so this is the tier a team or a class can share.
VENDORS = [
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
]

# Reaches live operator infrastructure. Narrowest tier, shortest life.
ENGAGEMENT = [
    "CS_API_TOKEN",
    "ADAPTIX_USERNAME",
    "ADAPTIX_PASSWORD",
    "BRC4_WEBHOOK_TOKEN",
    "SLACK_WEBHOOK_URL",
]

TIERS = [("machine", MACHINE), ("vendors", VENDORS), ("engagement", ENGAGEMENT)]

# Keys that LOOK like secrets to the pattern below and are not. This list has to
# stay explicit: every name here matches /KEY|TOKEN|SECRET|PASSWORD|CRED/ and all
# of them are ordinary tunables, paths or policy strings. Classifying one as a
# secret would encrypt it, hide it from review, and -- because a missing config
# value degrades silently rather than erroring -- produce a fault a long way from
# its cause.
NOT_SECRETS = {
    "SERP_ROLE_KEYWORDS",
    "TAVILY_ROLE_KEYWORDS",
    "TAVILY_MAX_CREDITS",
    "FLARE_DOMAIN_MAX_CREDS",
    "VLLM_SPEC_TOKENS",
    "SPOTTER_CRED_SCAN_MAX_BYTES",
    "SPOTTER_CRED_ENRICHER_FLOW_ID",
    "SPOTTER_TUNNEL_KEYS_DIR",
    "SSH_KEY_DIR",
    "TUNNEL_HOST_KEY_POLICY",
    "TUNNEL_KEY_ROOTS",
    "TUNNEL_UPLOAD_KEY_ROOT",
    "TUNNEL_DEFAULT_KEY_PATH",
    "TUNNEL_MAX_KEY_BYTES",
    "TUNNEL_MAX_SECRET_LENGTH",
    "N8N_WEBHOOK_BASE",
    "NEO4J_USER",
    "NEO4J_USERNAME",
    "N8N_USER",
    "OWUI_ADMIN_EMAIL",
    "EDGAR_USER_AGENT",
}

# Default-deny: anything shaped like a credential is treated as one unless it is
# named above. A new vendor key nobody has classified yet therefore trips the
# guard instead of quietly landing in .env as plaintext.
_SECRET_SHAPED_RE = re.compile(
    r"(_API_KEY|_APIKEY|_KEY|_TOKEN|_PASSWORD|_PASSWD|_SECRET|_WEBHOOK_URL)$"
)

CONFIG = "config"
UNKNOWN_SECRET = "unknown-secret"


def classify(key: str) -> str:
    """Return 'machine' | 'vendors' | 'engagement' | 'config' | 'unknown-secret'.

    'unknown-secret' means "looks like a credential, but nobody has said which
    tier it belongs to" -- the case that used to fall through to plaintext .env.
    """
    for name, keys in TIERS:
        if key in keys:
            return name
    if key in NOT_SECRETS:
        return CONFIG
    if _SECRET_SHAPED_RE.search(key):
        return UNKNOWN_SECRET
    return CONFIG


def is_secret(key: str) -> bool:
    return classify(key) != CONFIG


def _parse_dotenv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _ASSIGN_RE.match(line)
        if m:
            # Last assignment wins, matching how `docker compose --env-file` and
            # the repo's own `sed -n ... | tail -1` readers resolve duplicates.
            # .env.example ships SERP_API_KEY twice, so this is load-bearing.
            out[m.group(1)] = m.group(2)
    return out


def tier_files() -> list[str]:
    if not os.path.isdir(SECRETS_DIR):
        return []
    return sorted(
        os.path.join(SECRETS_DIR, n)
        for n in os.listdir(SECRETS_DIR)
        if n.endswith(".sops.env")
    )


def _decrypt(path: str) -> str:
    if not shutil.which("sops"):
        raise RuntimeError(
            f"{os.path.basename(path)} is encrypted but sops is not installed. "
            "See README.md -- Generate secrets."
        )
    proc = subprocess.run(
        ["sops", "--decrypt", "--input-type", "dotenv", "--output-type", "dotenv", path],
        capture_output=True, text=True, cwd=REPO,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"could not decrypt {path}: {(proc.stderr or '').strip()}\n"
            "The age identity is read from SOPS_AGE_KEY_FILE, or "
            "$HOME/.config/sops/age/keys.txt by default."
        )
    return proc.stdout


def load(refresh: bool = False) -> dict[str, str]:
    """Return .env's configuration merged with every decrypted secret tier."""
    global _cache
    if _cache is not None and not refresh:
        return _cache

    merged: dict[str, str] = {}
    if os.path.isfile(ENV_PATH):
        with open(ENV_PATH, encoding="utf-8") as fh:
            merged.update(_parse_dotenv(fh.read()))
    for path in tier_files():
        merged.update(_parse_dotenv(_decrypt(path)))
    _cache = merged
    return merged


def get(key: str, default: str | None = None) -> str | None:
    """A single value. The real environment wins, then .env, then the tiers.

    Environment-first matters for the ingest scripts, which deliberately set
    hostnames in os.environ before importing flowsint_client so that a value
    aimed at a container ("neo4j") can be rewritten to one reachable from the
    host ("localhost").
    """
    live = os.environ.get(key)
    if live not in (None, ""):
        return live
    return load().get(key, default)


def require(key: str) -> str:
    """A value that must be present, or a message that says where to put it."""
    value = get(key)
    if value in (None, ""):
        raise SystemExit(
            f"{key} is not set. It lives in .env (configuration) or one of "
            f"secrets/*.sops.env (credentials); `deployment/setup-secrets.sh` "
            f"generates the machine-local ones."
        )
    return value


def tier_path(tier: str) -> str:
    return os.path.join(SECRETS_DIR, f"{tier}.sops.env")


class UnclassifiedSecret(ValueError):
    """Raised when a credential-shaped key has no tier and the caller named none."""


def owning_file(key: str, tier: str | None = None) -> str:
    """Which file a write to `key` should land in.

    Classification decides, NOT prior physical presence. That distinction is the
    whole fix: this used to ask only "is this key already in a tier file?", so a
    key that is plainly a credential -- including one named in VENDORS, like
    SHODAN_API_KEY, which was commented out when the split ran and therefore
    never made it into a tier -- resolved to .env and was written in the clear.

    A credential-shaped key nobody has classified raises rather than defaulting,
    because every available default is wrong: .env leaks it, and guessing a tier
    picks the wrong sharing boundary.
    """
    if tier:
        if tier not in [n for n, _ in TIERS]:
            raise ValueError(f"unknown tier {tier!r}")
        return tier_path(tier)

    kind = classify(key)
    if kind in [n for n, _ in TIERS]:
        return tier_path(kind)
    if kind == UNKNOWN_SECRET:
        raise UnclassifiedSecret(
            f"{key} looks like a credential but is not classified, so there is no "
            f"safe default: .env would store it in plaintext. Add it with\n"
            f"  scripts/spotter_secret.py set {key}\n"
            f"which asks which tier it belongs in, or add it to a tier list in "
            f"scripts/spotter_env.py."
        )

    # Ordinary config. If it nonetheless already lives in a tier, keep writing
    # there rather than splitting one key across two files.
    for path in tier_files():
        if key in _parse_dotenv(_decrypt(path)):
            return path
    return ENV_PATH


def set_value(key: str, value: str, tier: str | None = None) -> str:
    """Write `key` into whichever file owns it. Returns that path.

    `tier` names the destination explicitly, for a credential-shaped key that
    classify() cannot place.

    Both files are rewritten IN PLACE rather than replaced, because
    vendor/flowsint/.env is a symlink to .env and `preflight_env_check.py` fails
    if that symlink has become a real file.
    """
    path = owning_file(key, tier)
    if path == ENV_PATH:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        replaced = False
        for i, line in enumerate(lines):
            m = _ASSIGN_RE.match(line)
            if m and m.group(1) == key:
                lines[i] = f"{key}={value}"
                replaced = True
        if not replaced:
            lines.append(f"{key}={value}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        os.chmod(path, 0o600)
    else:
        # `sops set` edits the encrypted file without ever writing a decrypted
        # copy to disk. The JSON-encoded value is how sops expects a scalar.
        import json as _json
        proc = subprocess.run(
            ["sops", "set", path, f'["{key}"]', _json.dumps(value)],
            capture_output=True, text=True, cwd=REPO,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"could not write {key} to {path}: {(proc.stderr or '').strip()}"
            )
    load(refresh=True)
    return path


def export_into_environ(keys: list[str] | None = None) -> int:
    """Populate os.environ from the merged view, without clobbering what is set.

    Import-order trap: scripts/flowsint_client.py reads API_URL/API_KEY/NEO4J_*
    into module-level constants at import time, so this has to run BEFORE that
    import, not after. ingest_sharphound_large.py documents the same ordering.
    """
    data = load()
    n = 0
    for key, value in data.items():
        if keys is not None and key not in keys:
            continue
        if os.environ.get(key):
            continue
        os.environ[key] = value
        n += 1
    return n


if __name__ == "__main__":
    # --status answers "is this key resolvable?" WITHOUT printing the value, so
    # shell callers (deployment/setup-secrets.sh) can decide whether to generate
    # a secret without the value ever reaching a pipe, an argv or a shell trace.
    if len(sys.argv) >= 3 and sys.argv[1] == "--status":
        v = get(sys.argv[2])
        if v in (None, ""):
            print("missing")
        elif v.startswith("REPLACE_WITH_") or v.startswith("/absolute/path/to/"):
            print("placeholder")
        else:
            print("set")
        raise SystemExit(0)

    # Deliberately prints NAMES and source files only -- never values.
    data = load()
    print(f"{len(data)} keys visible")
    print(f"  .env            {ENV_PATH}")
    for path in tier_files():
        n = len(_parse_dotenv(_decrypt(path)))
        print(f"  {os.path.basename(path):24s} {n} keys")
    if len(sys.argv) > 1:
        for key in sys.argv[1:]:
            value = get(key)
            print(f"{key}: {'set' if value else 'MISSING'}"
                  f"{f' (len {len(value)})' if value else ''}")
