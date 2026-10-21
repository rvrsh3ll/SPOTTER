#!/usr/bin/env python3
"""
smoke_rus_leak_client.py — Offline contract tests for scripts/rus_leak_client.py.

No live stack needed. Validates:
  - Phone number normalisation
  - Client instantiation and budget tracking
  - Result structure shapes
  - Prefix-based carrier/region lookup
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rus_leak_client import RusLeakClient, normalise_ru_phone, is_ru_phone


_passed = 0
_failed = 0


def check(label, cond, detail=""):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  PASS  {label}")
    else:
        _failed += 1
        print(f"  FAIL  {label}  {detail}")


def test_phone_normalisation():
    print("\n── Phone number normalisation ──")
    check("+7 format", normalise_ru_phone("+79161234567") == "+79161234567")
    check("8 prefix → +7", normalise_ru_phone("89161234567") == "+79161234567")
    check("bare 10 digits", normalise_ru_phone("9161234567") == "+79161234567")
    check("with spaces", normalise_ru_phone("+7 916 123 45 67") == "+79161234567")
    check("with dashes", normalise_ru_phone("+7-916-123-45-67") == "+79161234567")
    check("with parens", normalise_ru_phone("+7 (916) 123-45-67") == "+79161234567")
    check("invalid: too short", normalise_ru_phone("12345") is None)
    check("invalid: too long", normalise_ru_phone("12345678901234") is None)
    check("invalid: letters", normalise_ru_phone("+7abc1234567") is None)
    check("invalid: empty", normalise_ru_phone("") is None)
    check("invalid: None", normalise_ru_phone(None) is None)


def test_is_ru_phone():
    print("\n── is_ru_phone ──")
    check("valid +7", is_ru_phone("+79161234567"))
    check("valid 8 prefix", is_ru_phone("89161234567"))
    check("valid bare", is_ru_phone("9161234567"))
    check("invalid US number", not is_ru_phone("+12025551234"))
    check("invalid short", not is_ru_phone("12345"))
    check("invalid empty", not is_ru_phone(""))


def test_client_instantiation():
    print("\n── Client instantiation ──")
    c = RusLeakClient()
    check("default timeout", c.timeout == 20, f"got {c.timeout}")
    check("default max_requests", c.max_requests == 20, f"got {c.max_requests}")
    check("default max_seconds", c.max_seconds == 90, f"got {c.max_seconds}")
    check("errors starts empty", c.errors == [])
    check("results has keys", set(c.results.keys()) == {"reveng", "phone_lookups"})

    c2 = RusLeakClient(proxy_url="socks5://proxy:1080", reveng_api_key="test-key")
    check("custom proxy set", c2.proxy_url == "socks5://proxy:1080")
    check("custom api key", c2.reveng_api_key == "test-key")


def test_budget_tracking():
    print("\n── Budget tracking ──")
    c = RusLeakClient(max_requests=2, max_seconds=1)
    check("budget not exhausted initially", not c.budget_exhausted())
    c._requests_made = 2
    check("budget exhausted after max_requests", c.budget_exhausted())


def test_phone_lookup():
    print("\n── Phone lookup (prefix-based) ──")
    c = RusLeakClient()

    # MTS prefix
    result = c.lookup_phone("+79161234567")
    check("MTS prefix detected", result is not None and result.get("carrier") == "MTS",
          f"got {result}")

    # Megafon prefix
    result = c.lookup_phone("+79261234567")
    check("Megafon prefix detected", result is not None and result.get("carrier") == "Megafon",
          f"got {result}")

    # Beeline prefix
    result = c.lookup_phone("+79601234567")
    check("Beeline prefix detected", result is not None and result.get("carrier") == "Beeline",
          f"got {result}")

    # Moscow landline
    result = c.lookup_phone("+74951234567")
    check("Moscow region detected", result is not None and result.get("region") == "Moscow",
          f"got {result}")

    # SPb landline
    result = c.lookup_phone("+78121234567")
    check("SPb region detected", result is not None and result.get("region") == "Saint Petersburg",
          f"got {result}")

    # Invalid phone
    result = c.lookup_phone("12345")
    check("invalid phone returns None", result is None)


def test_reveng_no_key():
    print("\n── Reveng.ee without API key ──")
    c = RusLeakClient()
    result = c.search_reveng("test@example.com", query_type="email")
    check("no key → None", result is None)
    check("error noted", any("no API key" in e for e in c.errors), f"errors: {c.errors}")


def test_query_all_empty():
    print("\n── query_all with no identifiers ──")
    c = RusLeakClient()
    result = c.query_all()
    check("result has results key", "results" in result)
    check("result has errors key", "errors" in result)
    check("no phone lookups", result["results"]["phone_lookups"] == [])


def test_query_all_with_phones():
    print("\n── query_all with phone numbers ──")
    c = RusLeakClient()
    result = c.query_all(phones=["+79161234567", "+74951234567"])
    check("phone_lookups populated", len(result["results"]["phone_lookups"]) == 2,
          f"got {len(result['results']['phone_lookups'])}")
    check("first is MTS", result["results"]["phone_lookups"][0].get("carrier") == "MTS")
    check("second is Moscow", result["results"]["phone_lookups"][1].get("region") == "Moscow")


if __name__ == "__main__":
    print("═══ rus_leak_client.py offline contract tests ═══")
    test_phone_normalisation()
    test_is_ru_phone()
    test_client_instantiation()
    test_budget_tracking()
    test_phone_lookup()
    test_reveng_no_key()
    test_query_all_empty()
    test_query_all_with_phones()

    print(f"\n{'═'*50}")
    print(f"  {_passed} passed, {_failed} failed")
    sys.exit(1 if _failed else 0)
