#!/usr/bin/env python3
"""
Preflight environment validation for SPOTTER.

Checks:
  - SOCIAL_ENRICHMENT_OWNER must be one of: plugin, direct, legacy
  - When owner=plugin, both SOCIAL_MAIGRET_FLOW_ID and
    SOCIAL_LINKEDIN_FLOW_ID must be set and not placeholder values.
  - The env file docker compose actually reads agrees with this repo's .env.
  - Whether a copy of SPOTTER_HOME would be a complete backup, i.e. which
    persistent-state mounts are bind mounts inside the checkout and which are
    still named Docker volumes. Advisory: both layouts are supported.

That last check exists because of a bug that hid for a week. `docker compose` reads
its env file from the PROJECT DIRECTORY, which for this stack is the directory of
the first -f file (/root/flowsint), not /root/SPOTTER. A second .env lived there and
had drifted into a stale subset, so:

  - vars added to SPOTTER/.env after the copy was made resolved to their compose
    defaults instead, or to empty string when they had no default. BRC4_WEBHOOK_TOKEN
    and GRAYHATWARFARE_API_KEY sat empty in the live containers for a week that way,
    which is why the GrayhatWarfare enablement never took, and why WF21's ingress was
    unauthenticated (an unset token makes it skip the check).
  - `docker exec spotter-n8n printenv X` disagreed with every .env on disk.

/root/flowsint/.env is now a symlink to /root/SPOTTER/.env, so there is one file.
This check catches the symlink being replaced by a real file again -- `sed -i` does
exactly that, silently, because it writes a new inode rather than following the link.

Usage:
  python3 scripts/preflight_env_check.py --env-file .env
"""

from __future__ import annotations

import argparse
import os
import subprocess
import re
import sys
from pathlib import Path
from typing import Dict


PLACEHOLDER_RE = re.compile(r"^REPLACE_WITH_", re.IGNORECASE)


def parse_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values

    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

    # The secrets moved out of .env into secrets/*.sops.env, so a plain read of
    # this file now sees pointer comments where ~25 credentials used to be. Every
    # check below -- REPLACE_WITH_ placeholders, and repo-vs-compose agreement --
    # would then pass by simply not looking at them, which is the opposite of
    # what a preflight is for. Overlay the decrypted tiers so the checks see the
    # same merged view that scripts/spotter_compose.sh hands to compose.
    #
    # Only for the repo's own .env (or the vendor symlink to it): an explicit
    # --env-file pointing somewhere else is asked about on its own terms.
    _root = Path(__file__).resolve().parent.parent
    if path.resolve() == (_root / ".env").resolve():
        try:
            sys.path.insert(0, str(_root / "scripts"))
            import spotter_env
            tiers = spotter_env.tier_files()
            for tier in tiers:
                values.update(spotter_env._parse_dotenv(spotter_env._decrypt(tier)))
        except Exception as exc:                # sops absent, no key, not split yet
            # Loud: a preflight that silently stopped checking the credentials is
            # worse than one that fails, because it still prints "Preflight passed".
            print(f"WARN: could not merge encrypted secret tiers ({exc}) — "
                  f"secret values were NOT checked")
    return values


def is_missing(value: str) -> bool:
    v = (value or "").strip()
    if not v:
        return True
    if PLACEHOLDER_RE.match(v):
        return True
    return False


# The env file docker compose reads: the project directory is the directory of the
# first -f argument, and every documented invocation puts the Flowsint checkout
# first. Derive that location instead of hardcoding this host's — FLOWSINT_HOME if
# set, else .env's value, else the sibling-checkout default.
def _flowsint_home() -> Path:
    env = (os.environ.get("FLOWSINT_HOME") or "").strip()
    if env:
        return Path(env)
    repo_root = Path(__file__).resolve().parent.parent
    try:
        for line in (repo_root / ".env").read_text().splitlines():
            line = line.strip()
            if line.startswith("FLOWSINT_HOME=") and not line.startswith("#"):
                value = line.split("=", 1)[1].strip()
                if value:
                    return Path(value)
    except OSError:
        pass
    # Default layout: vendored inside this repo (scripts/bootstrap.sh clones it
    # to vendor/flowsint). A sibling checkout still works via FLOWSINT_HOME.
    return repo_root / "vendor" / "flowsint"


COMPOSE_ENV_PATH = _flowsint_home() / ".env"


def check_compose_env_agrees(repo_env: Path) -> tuple[list[str], list[str]]:
    """
    Compare the env file compose reads against this repo's .env.

    Returns (failures, notes). A missing key is a failure, not a warning: it does not
    fall back to the repo value, it falls back to the compose default (or empty
    string), which is how two secrets ended up blank in production.
    """
    failures: list[str] = []
    notes: list[str] = []

    try:
        repo_resolved = repo_env.resolve()
    except OSError:
        return ([f"cannot resolve {repo_env}"], notes)

    if not COMPOSE_ENV_PATH.exists():
        return ([f"{COMPOSE_ENV_PATH} does not exist - compose would resolve every "
                 "${VAR} to its default, silently"], notes)

    if COMPOSE_ENV_PATH.is_symlink() and COMPOSE_ENV_PATH.resolve() == repo_resolved:
        notes.append(f"{COMPOSE_ENV_PATH} -> {repo_resolved} (single source, good)")
        return (failures, notes)

    notes.append(
        f"{COMPOSE_ENV_PATH} is a separate file, not a symlink to {repo_resolved} - "
        "comparing key by key"
    )
    repo_vals = parse_env_file(repo_env)
    comp_vals = parse_env_file(COMPOSE_ENV_PATH)

    absent = sorted(set(repo_vals) - set(comp_vals))
    differing = sorted(k for k in set(repo_vals) & set(comp_vals)
                       if repo_vals[k] != comp_vals[k])
    extra = sorted(set(comp_vals) - set(repo_vals))

    if absent:
        failures.append(
            f"{len(absent)} var(s) in {repo_env} are absent from {COMPOSE_ENV_PATH}, so "
            f"the containers will NOT get them: {', '.join(absent)}"
        )
    if differing:
        failures.append(
            f"{len(differing)} var(s) disagree between the two files; "
            f"{COMPOSE_ENV_PATH} is the one that wins: {', '.join(differing)}"
        )
    if extra:
        notes.append(f"only in {COMPOSE_ENV_PATH} (harmless): {', '.join(extra)}")

    return (failures, notes)


def check_flowsint_app_is_loopback() -> tuple[list[str], list[str]]:
    """
    The Flowsint SPA must not be published on 0.0.0.0.

    Upstream ships it as a bare "5173:8080". SPOTTER's access control is an nginx
    auth_request gate in front of that UI, so a direct connection to 5173 from the
    LAN walks straight past the login and reaches the graph. The repo carries
    deployment/flowsint-patches/0001-bind-flowsint-app-to-loopback.patch to fix
    it, and this is the backstop for a patch that was skipped, or silently undone
    by an upstream update.

    A compose overlay cannot fix it: compose APPENDS to `ports`, so an override
    leaves the 0.0.0.0 binding in place next to the new one -- which is exactly
    why this checks the RUNNING binding rather than the file.
    """
    failures: list[str] = []
    notes: list[str] = []

    compose = _flowsint_home() / "docker-compose.prod.yml"
    if compose.exists():
        try:
            text = compose.read_text()
        except OSError:
            text = ""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("-") and "5173" in stripped and ":8080" in stripped:
                if "127.0.0.1" not in stripped and "localhost" not in stripped:
                    failures.append(
                        f"{compose} publishes the Flowsint UI on all interfaces "
                        f"({stripped.lstrip('- ').strip()}) - it bypasses the SPOTTER "
                        "auth gate. Apply deployment/flowsint-patches/"
                        "0001-bind-flowsint-app-to-loopback.patch"
                    )
                else:
                    notes.append("Flowsint UI port 5173 is loopback-bound in compose (good)")
                break

    # The file can say one thing and the running container another, because the
    # container keeps whatever it was created with. Check the live binding too.
    try:
        out = subprocess.run(
            ["docker", "port", "flowsint-app-prod"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""
    for line in out.splitlines():
        if "0.0.0.0" in line or "[::]" in line:
            failures.append(
                f"flowsint-app-prod is LISTENING on all interfaces ({line.strip()}) - "
                "recreate it after applying the loopback patch; a running container "
                "keeps the binding it was created with"
            )

    return (failures, notes)


# Each persistent-state mount, with the named volume it falls back to when the
# variable is unset. Unset is the pre-folder layout and is fully supported -- the
# compose files carry these same names as their `:-` defaults.
STATE_MOUNTS = (
    ("SPOTTER_NEO4J_DATA",      "neo4j_data_prod"),
    ("SPOTTER_NEO4J_LOGS",      "neo4j_logs_prod"),
    ("SPOTTER_NEO4J_IMPORT",    "neo4j_import_prod"),
    ("SPOTTER_NEO4J_PLUGINS",   "neo4j_plugins_prod"),
    ("SPOTTER_PG_DATA",         "pg_data_prod"),
    ("SPOTTER_REDIS_DATA",      "(anonymous volume at /data)"),
    ("SPOTTER_N8N_DATA",        "n8n_data"),
    ("SPOTTER_OPEN_WEBUI_DATA", "open_webui_data"),
    ("SPOTTER_TOR_DATA",        "spotter_tor_data"),
)


def check_state_is_portable(values: dict) -> tuple[list[str], list[str]]:
    """
    Report whether a tar of SPOTTER_HOME would actually be a complete backup.

    Advisory on purpose. "All state inside the checkout" is the goal, not a rule:
    a host installed before the folder layout keeps its named volumes and is
    correct, and putting data/neo4j on a separate disk via an absolute path
    outside the checkout is a deliberate choice someone may want -- SSH_KEY_DIR
    already defaults outside by design. A FAIL here would fail correct installs.

    The one hard error is a relative value, which agrees with the launcher and
    with check_env_dirs_are_absolute(): compose resolves it against
    vendor/flowsint and Docker creates it, so the database silently starts empty.
    """
    failures: list[str] = []
    notes: list[str] = []

    home = (values.get("SPOTTER_HOME") or "").strip()
    home_real = os.path.realpath(os.path.expanduser(home)) if home.startswith(("/", "~")) else ""

    inside = outside = on_volumes = unusable = 0
    # Per-mount notes are collected separately: when EVERY mount is unset the host
    # is simply on the pre-folder layout, and nine identical lines saying so teach
    # the operator to skim past warnings. The summary below covers that case.
    unset_notes: list[str] = []

    for key, fallback in STATE_MOUNTS:
        raw = (values.get(key) or "").strip()
        if not raw:
            on_volumes += 1
            unset_notes.append(
                f"{key} unset - that mount is the named volume '{fallback}'"
            )
            continue

        # SPOTTER_REDIS_DATA carries "<source>:/data"; judge the source half.
        src = raw.split(":", 1)[0]
        expanded = src.replace("${SPOTTER_HOME}", home).replace("$SPOTTER_HOME", home)
        expanded = os.path.expanduser(expanded)

        if not expanded.startswith("/"):
            unusable += 1
            failures.append(
                f"{key}={raw} is relative. Compose resolves it against "
                "vendor/flowsint, Docker creates it, and the database initialises "
                "into it empty with no error. Use an absolute path."
            )
            continue

        real = os.path.realpath(expanded)
        if home_real and (real == home_real or real.startswith(home_real + os.sep)):
            inside += 1
            if not os.path.isdir(real):
                notes.append(
                    f"{key} -> {real} does not exist yet "
                    "(deployment/setup-secrets.sh creates it with the right owner)"
                )
        else:
            outside += 1
            notes.append(
                f"{key} -> {real} is OUTSIDE SPOTTER_HOME - deliberate is fine, "
                "but a copy of the checkout will not carry it"
            )

    total = len(STATE_MOUNTS)
    if on_volumes != total:
        # Mixed: which ones are still on volumes is the actionable part.
        notes.extend(unset_notes)

    if on_volumes == total:
        notes.append(
            f"state: 0 of {total} mounts inside SPOTTER_HOME, {total} on named "
            "volumes (pre-folder layout; supported) - a tar of this folder is NOT "
            "a complete backup. Use deployment/migrate-backup.sh --list to see "
            "what one would cover."
        )
    elif inside == total:
        notes.append(f"state: all {total} mounts are inside SPOTTER_HOME - a cold copy of the folder is complete.")
    else:
        broken = f", {unusable} unusable (see FAIL above)" if unusable else ""
        notes.append(
            f"state: {inside} of {total} mounts inside SPOTTER_HOME, "
            f"{outside} elsewhere, {on_volumes} on named volumes{broken} - a "
            "folder copy alone is NOT complete. Use deployment/migrate-backup.sh."
        )

    return (failures, notes)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate required SPOTTER env settings")
    parser.add_argument("--env-file", default=".env", help="Path to env file (default: .env)")
    args = parser.parse_args()

    env_path = Path(args.env_file)
    file_values = parse_env_file(env_path)

    # Environment variables override file values.
    merged = dict(file_values)
    merged.update({k: v for k, v in os.environ.items() if k in {
        "SOCIAL_ENRICHMENT_OWNER",
        "SOCIAL_MAIGRET_FLOW_ID",
        "SOCIAL_LINKEDIN_FLOW_ID",
    }})

    owner = (merged.get("SOCIAL_ENRICHMENT_OWNER", "plugin") or "plugin").strip().lower()

    failures = []
    warnings = []

    # 'direct' is the mode this deployment actually runs (see .env): WF03 calls the
    # maigret/linkedin sidecars itself and writes the graph, rather than handing off to
    # Flowsint plugin flows. WF03 only ever branches on `== 'plugin'`, so every other
    # value takes that same direct path -- 'direct' and 'legacy' are the same code path,
    # named differently. This set omitted 'direct', so preflight failed on a correctly
    # configured host and the real finding (an env var absent from the file compose reads)
    # would have been buried under a bogus FAIL.
    if owner not in {"plugin", "direct", "legacy"}:
        failures.append(
            "SOCIAL_ENRICHMENT_OWNER must be 'plugin', 'direct', or 'legacy' "
            f"(current: {merged.get('SOCIAL_ENRICHMENT_OWNER', '')})"
        )

    if owner == "plugin":
        for key in ("SOCIAL_MAIGRET_FLOW_ID", "SOCIAL_LINKEDIN_FLOW_ID"):
            if is_missing(merged.get(key, "")):
                failures.append(f"{key} is required when SOCIAL_ENRICHMENT_OWNER=plugin")
    else:
        for key in ("SOCIAL_MAIGRET_FLOW_ID", "SOCIAL_LINKEDIN_FLOW_ID"):
            if is_missing(merged.get(key, "")):
                warnings.append(f"{key} not set (ok when owner={owner})")

    env_failures, env_notes = check_compose_env_agrees(env_path)
    failures.extend(env_failures)
    warnings.extend(env_notes)

    port_failures, port_notes = check_flowsint_app_is_loopback()
    failures.extend(port_failures)
    warnings.extend(port_notes)

    state_failures, state_notes = check_state_is_portable(file_values)
    failures.extend(state_failures)
    warnings.extend(state_notes)

    source_note = f"env-file={env_path}" if env_path.exists() else f"env-file={env_path} (not found)"
    print(f"Preflight source: {source_note}")
    print(f"Compose env-file: {COMPOSE_ENV_PATH}")
    print(f"SOCIAL_ENRICHMENT_OWNER={owner}")

    if warnings:
        for w in warnings:
            print(f"WARN: {w}")

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        print("Preflight failed")
        return 1

    print("Preflight passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
