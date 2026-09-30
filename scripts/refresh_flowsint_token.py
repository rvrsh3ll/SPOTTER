#!/usr/bin/env python3
"""
Mint a fresh FLOWSINT_API_KEY and write it into .env.

WHY THIS EXISTS

FLOWSINT_API_KEY is not an API key in the usual sense. Flowsint has no key-issuing
endpoint: the value is an ordinary **login JWT**, signed with AUTH_SECRET, carrying
an `exp` claim. Upstream's default lifetime is ACCESS_TOKEN_EXPIRE_MINUTES = 60*60,
i.e. about two and a half days.

When it expires, every SPOTTER component that talks to Flowsint starts getting 401
at the same moment: n8n code nodes, the task runners, and the Open WebUI tools.
Nothing retries a 401 (the retry policy covers 429 and 5xx only) and nothing logs
it as an expiry, so the failure looks like the graph has gone away rather than like
a credential problem. In a classroom this reliably happens on day three.

  python3 scripts/refresh_flowsint_token.py                  # prompts
  python3 scripts/refresh_flowsint_token.py --email a@b.c    # prompts for password
  python3 scripts/refresh_flowsint_token.py --show-expiry    # just report

After refreshing, the containers that bake the value in must be recreated:

  scripts/spotter_compose.sh up -d --no-deps --force-recreate n8n task-runners open-webui
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env"


# FLOWSINT_API_KEY is a secret, so it no longer lives in .env: it sits in
# secrets/machine.sops.env, encrypted. Both helpers below now go through
# spotter_env, which reads the merged view and -- importantly for env_set --
# writes the renewed JWT back into whichever file OWNS the key. Writing it to
# .env instead would quietly re-create a plaintext copy of the credential this
# migration just removed.
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import spotter_env  # noqa: E402


def env_value(key: str) -> str:
    return spotter_env.get(key) or ""


def env_set(key: str, value: str) -> None:
    """Write the value into whichever file owns the key.

    For a secret that is now an encrypted tier (`sops set`, so no plaintext copy
    is ever written to disk); for ordinary config, .env, rewritten in place. In
    place still matters: replacing the inode would break the FLOWSINT_HOME/.env
    symlink back into a second, diverging file.
    """
    spotter_env.set_value(key, value)


def decode_expiry(token: str) -> datetime | None:
    """Read `exp` out of the JWT payload. No signature check — this only reports."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload)).get("exp")
        return datetime.fromtimestamp(exp, tz=timezone.utc) if exp else None
    except Exception:
        return None


def report_expiry(token: str) -> int:
    if not token:
        print("FLOWSINT_API_KEY is not set in .env")
        return 1
    when = decode_expiry(token)
    if when is None:
        print("FLOWSINT_API_KEY is set but its expiry could not be read "
              "(not a JWT, or malformed)")
        return 1
    left = when - datetime.now(tz=timezone.utc)
    hours = left.total_seconds() / 3600
    print(f"FLOWSINT_API_KEY expires {when:%Y-%m-%d %H:%M UTC}", end="")
    if hours < 0:
        print(f" — EXPIRED {abs(hours):.0f}h ago. Every Flowsint call is answering 401.")
        return 1
    print(f" — {hours:.0f}h left ({left.days}d)")
    if hours < 24:
        print("  Less than a day. Refresh before it bites:  "
              "python3 scripts/refresh_flowsint_token.py")
    return 0


def mint(api_url: str, email: str, password: str) -> str:
    # /api/auth/token is an OAuth2 password form, NOT json, and the email field
    # is called `username`.
    data = urllib.parse.urlencode({"username": email, "password": password}).encode()
    req = urllib.request.Request(
        f"{api_url.rstrip('/')}/api/auth/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            token = json.load(r).get("access_token", "")
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:200]
        raise SystemExit(f"token request failed (HTTP {e.code}): {body}")
    except urllib.error.URLError as e:
        raise SystemExit(
            f"cannot reach flowsint-api at {api_url}: {e.reason}\n"
            "  It publishes on 127.0.0.1:5001; check the stack is up."
        )
    if not token:
        raise SystemExit("no access_token in the response")
    return token


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api-url", default="http://127.0.0.1:5001",
                    help="flowsint-api base URL as reachable FROM THE HOST "
                         "(default: %(default)s — not the in-container name)")
    ap.add_argument("--email", help="Flowsint account email")
    ap.add_argument("--show-expiry", action="store_true",
                    help="report when the current token expires and exit")
    args = ap.parse_args()

    if not ENV_FILE.exists():
        print(f"no .env at {ENV_FILE}", file=sys.stderr)
        return 1

    if args.show_expiry:
        return report_expiry(env_value("FLOWSINT_API_KEY"))

    current = env_value("FLOWSINT_API_KEY")
    if current:
        report_expiry(current)

    email = args.email or input("Flowsint account email: ").strip()
    if not email:
        print("an email is required", file=sys.stderr)
        return 1
    password = getpass.getpass("Flowsint account password: ")

    token = mint(args.api_url, email, password)
    env_set("FLOWSINT_API_KEY", token)
    print(f"\nFLOWSINT_API_KEY updated in {ENV_FILE}")
    report_expiry(token)
    print("\nThe value is baked into containers at CREATE time, so it does not take")
    print("effect until they are recreated — a restart will NOT do it:")
    print("  scripts/spotter_compose.sh up -d --no-deps --force-recreate "
          "n8n task-runners open-webui")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
