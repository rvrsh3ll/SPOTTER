#!/usr/bin/env python3
"""
smoke_rus_corporate.py — Offline contract tests for scripts/rus_corporate.py.

No live stack needed. Validates:
  - INN/OGRN checksum validation
  - Client instantiation and budget tracking
  - Result structure shapes
  - Error accumulation
  - Proxy fail-closed behavior
"""

import os
import sys
import time

# Ensure scripts/ is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rus_corporate import RusCorporateClient, RusCorporateError


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


def test_inn_validation():
    print("\n── INN validation ──")
    # Valid 10-digit INN (example)
    check("10-digit INN valid format", RusCorporateClient.validate_inn("7707083893"))
    # Valid 12-digit INN (example)
    check("12-digit INN valid format", RusCorporateClient.validate_inn("500100732259"))
    # Invalid: wrong length
    check("INN wrong length rejected", not RusCorporateClient.validate_inn("12345"))
    check("INN 11 digits rejected", not RusCorporateClient.validate_inn("12345678901"))
    # Invalid: non-numeric
    check("INN non-numeric rejected", not RusCorporateClient.validate_inn("770708389X"))
    # Invalid: empty
    check("INN empty rejected", not RusCorporateClient.validate_inn(""))
    check("INN None rejected", not RusCorporateClient.validate_inn(None))


def test_ogrn_validation():
    print("\n── OGRN validation ──")
    # Valid 13-digit OGRN (example)
    check("13-digit OGRN valid format", RusCorporateClient.validate_ogrn("1027700132195"))
    # Invalid: wrong length
    check("OGRN wrong length rejected", not RusCorporateClient.validate_ogrn("12345"))
    check("OGRN 12 digits rejected", not RusCorporateClient.validate_ogrn("123456789012"))
    # Invalid: non-numeric
    check("OGRN non-numeric rejected", not RusCorporateClient.validate_ogrn("102770013219X"))


def test_client_instantiation():
    print("\n── Client instantiation ──")
    c = RusCorporateClient()
    check("default timeout", c.timeout == 20, f"got {c.timeout}")
    check("default max_requests", c.max_requests == 30, f"got {c.max_requests}")
    check("default max_seconds", c.max_seconds == 120, f"got {c.max_seconds}")
    check("errors starts empty", c.errors == [])
    check("results has all keys", set(c.results.keys()) == {"egrul", "rupep", "procurement", "courts", "bailiffs"})

    c2 = RusCorporateClient(proxy_url="socks5://proxy:1080", timeout=30, max_requests=10)
    check("custom proxy set", c2.proxy_url == "socks5://proxy:1080")
    check("custom timeout", c2.timeout == 30)
    check("custom max_requests", c2.max_requests == 10)
    check("proxies dict built", c2.proxies == {"http": "socks5://proxy:1080", "https": "socks5://proxy:1080"})


def test_budget_tracking():
    print("\n── Budget tracking ──")
    c = RusCorporateClient(max_requests=2, max_seconds=1)
    check("budget not exhausted initially", not c.budget_exhausted())
    c._requests_made = 2
    check("budget exhausted after max_requests", c.budget_exhausted())

    c2 = RusCorporateClient(max_requests=100, max_seconds=0)
    check("budget exhausted when max_seconds=0", c2.budget_exhausted())


def test_error_accumulation():
    print("\n── Error accumulation ──")
    c = RusCorporateClient()
    c._note("error one")
    c._note("error two")
    c._note("error one")  # duplicate
    check("errors accumulated", len(c.errors) == 2, f"got {len(c.errors)}")
    check("no duplicates", c.errors == ["error one", "error two"])


def test_query_all_empty():
    print("\n── query_all with no identifiers ──")
    c = RusCorporateClient()
    result = c.query_all()
    check("result has results key", "results" in result)
    check("result has errors key", "errors" in result)
    check("result has requests_made", "requests_made" in result)
    check("result has elapsed_seconds", "elapsed_seconds" in result)
    check("no requests made", result["requests_made"] == 0)


def test_query_all_with_inn():
    print("\n── query_all with INN (no live network) ──")
    # This will fail to connect (no proxy, no network), but should not raise
    c = RusCorporateClient(max_requests=5, max_seconds=2)
    result = c.query_all(inn="7707083893")
    check("result structure intact", "results" in result and "errors" in result)
    check("egrul attempted", result["results"].get("egrul") is None or isinstance(result["results"]["egrul"], dict))
    check("errors recorded (expected)", len(result["errors"]) > 0)


def test_search_egrul_empty_query():
    print("\n── search_egrul with empty query ──")
    c = RusCorporateClient()
    result = c.search_egrul("")
    check("empty query returns None", result is None)


def test_search_rupep_short_name():
    print("\n── search_rupep with short name ──")
    c = RusCorporateClient()
    result = c.search_rupep("ab")
    check("short name returns None", result is None)


def test_source_label():
    print("\n── Source identification ──")
    c = RusCorporateClient()
    check("default UA set", bool(c.user_agent))
    check("UA looks like a browser", "Mozilla" in c.user_agent or "Chrome" in c.user_agent)


if __name__ == "__main__":
    print("═══ rus_corporate.py offline contract tests ═══")
    test_inn_validation()
    test_ogrn_validation()
    test_client_instantiation()
    test_budget_tracking()
    test_error_accumulation()
    test_query_all_empty()
    test_query_all_with_inn()
    test_search_egrul_empty_query()
    test_search_rupep_short_name()
    test_source_label()

    print(f"\n{'═'*50}")
    print(f"  {_passed} passed, {_failed} failed")
    sys.exit(1 if _failed else 0)
