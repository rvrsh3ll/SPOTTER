#!/usr/bin/env python3
"""Mint and inspect long-lived Flowsint API tokens. Standard library only.

Flowsint (flowsint-core/core/auth.py) has no API keys and a hardcoded 60-hour
login token. Its token check (flowsint-api/app/api/deps.py) verifies only the
HS256 signature with AUTH_SECRET, the `exp` claim, and that `sub` names an
existing account. SPOTTER holds AUTH_SECRET in its machine tier, so it can sign a
token of the same shape with a longer `exp` -- no upstream patch.

Claim shape matches create_access_token exactly: {"sub": <email>, "exp": <unix>}.

Trade-off: anyone holding the token can act as that account until `exp`. The
only revocation is rotating AUTH_SECRET, which also ends every Flowsint session.
Re-check deps.py whenever deployment/flowsint.lock moves.

Never prints a secret or a token.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request

DEFAULT_DAYS = 365
PLACEHOLDERS = {"CHANGE_ME", "<set-in-encrypted-tier>"}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def encode_hs256(claims: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + _b64url(sig)


def verify_hs256(token: str, secret: str) -> dict:
    """Return the claims if the signature matches; raise ValueError otherwise."""
    try:
        head, body, sig = token.split(".")
    except ValueError:
        raise ValueError("not a JWT")
    expect = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expect, _b64url_decode(sig)):
        raise ValueError("bad signature")
    return json.loads(_b64url_decode(body))


def mint(email: str, secret: str, days: float = DEFAULT_DAYS, now: float | None = None) -> str:
    if not email or not secret:
        raise ValueError("email and AUTH_SECRET are both required")
    now = time.time() if now is None else now
    return encode_hs256({"sub": email, "exp": int(now + days * 86400)}, secret)


def expiry(token: str) -> int | None:
    """Unix `exp` of a JWT without verifying it, or None."""
    try:
        exp = json.loads(_b64url_decode(token.split(".")[1])).get("exp")
        return int(exp) if exp else None
    except Exception:
        return None


def days_left(token: str, now: float | None = None) -> float | None:
    exp = expiry(token)
    if exp is None:
        return None
    return (exp - (time.time() if now is None else now)) / 86400


def check_live(api_url: str, token: str, timeout: int = 15) -> tuple[bool, str]:
    req = urllib.request.Request(
        api_url.rstrip("/") + "/api/investigations",
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status == 200, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def _real(value: str | None) -> str:
    value = (value or "").strip()
    if value in PLACEHOLDERS or value.startswith("REPLACE_WITH_"):
        return ""
    return value


def config_days() -> float:
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import spotter_env
        raw = _real(os.environ.get("FLOWSINT_TOKEN_DAYS") or spotter_env.get("FLOWSINT_TOKEN_DAYS"))
    except Exception:
        raw = _real(os.environ.get("FLOWSINT_TOKEN_DAYS"))
    try:
        d = float(raw) if raw else DEFAULT_DAYS
        return d if d > 0 else DEFAULT_DAYS
    except ValueError:
        return DEFAULT_DAYS


def self_signed_from_config(api_url: str, days: float | None = None, email: str = "") -> tuple[str, str]:
    """Mint from SPOTTER config and verify it live. Returns (token, "") or ("", reason)."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import spotter_env
    secret = _real(spotter_env.get("AUTH_SECRET"))
    email = _real(email) or _real(spotter_env.get("FLOWSINT_ADMIN_EMAIL"))
    if not secret:
        return "", "AUTH_SECRET is not set in SPOTTER's config/secrets"
    if not email:
        return "", "FLOWSINT_ADMIN_EMAIL is not set (bootstrap records it)"
    token = mint(email, secret, days if days else config_days())
    ok, why = check_live(api_url, token)
    if not ok:
        return "", f"self-signed token rejected by {api_url}/api/investigations ({why})"
    return token, ""
