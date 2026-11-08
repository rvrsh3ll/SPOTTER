#!/usr/bin/env python3
"""Unit checks for scripts/flowsint_token.py (no network, no secrets)."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flowsint_token as ft  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(("PASS " if cond else "FAIL ") + name)
    fails += 0 if cond else 1


VECTOR = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
          "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
          "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
got = ft.encode_hs256({"sub": "1234567890", "name": "John Doe", "iat": 1516239022},
                      "your-256-bit-secret")
check("HS256 matches the published reference vector", got == VECTOR)

now = 1_800_000_000
tok = ft.mint("ops@example.test", "s3cret", 365, now=now)
claims = ft.verify_hs256(tok, "s3cret")
check("claim shape is exactly sub + exp", set(claims) == {"sub", "exp"})
check("sub is the admin email", claims["sub"] == "ops@example.test")
check("exp is now + 365 days", claims["exp"] == now + 365 * 86400)
check("expiry() reads exp", ft.expiry(tok) == now + 365 * 86400)
check("days_left() is 365", abs(ft.days_left(tok, now=now) - 365) < 1e-9)
try:
    ft.verify_hs256(tok, "wrong")
    check("wrong secret rejected", False)
except ValueError:
    check("wrong secret rejected", True)
check("garbage has no expiry", ft.expiry("not-a-token") is None)
try:
    ft.mint("", "x")
    check("empty email refused", False)
except ValueError:
    check("empty email refused", True)

cross = None
try:
    from jose import jwt as jose_jwt
    cross = jose_jwt.decode(ft.mint("a@b.c", "k", 1), "k", algorithms=["HS256"])
    lib = "python-jose"
except ImportError:
    try:
        import jwt as pyjwt
        cross = pyjwt.decode(ft.mint("a@b.c", "k", 1), "k", algorithms=["HS256"])
        lib = "PyJWT"
    except ImportError:
        lib = None
if lib:
    check(f"{lib} decodes the minted token", cross["sub"] == "a@b.c" and cross["exp"] > time.time())
else:
    print("SKIP no python-jose / PyJWT installed for cross-check")

print(f"{'PASSED' if not fails else 'FAILED'}: {fails} failure(s)")
sys.exit(1 if fails else 0)
