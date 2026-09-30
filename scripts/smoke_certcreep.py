#!/usr/bin/env python3
"""Offline contract checks for the passive CertCreep collector."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import certcreep


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def fake_request(url: str, timeout: int, retries: int, user_agent: str) -> Any:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    check(timeout == 9, "timeout must reach each backend")
    check(retries == 1, "retries must reach each backend")
    check(user_agent == "SPOTTER smoke", "user agent must reach each backend")
    if parsed.netloc == "crt.sh":
        name = query["q"][0]
        if name == "example.com":
            return [{"id": 1, "name_value": "example.com\n*.api.example.com\ncdn.example.net", "not_before": "2026-01-01T00:00:00", "not_after": "2027-01-01T00:00:00", "issuer_name": "Example CA"}]
        return [{"id": 2, "name_value": "example.com\napi.example.com", "not_before": "2026-02-01T00:00:00", "not_after": "2027-02-01T00:00:00", "issuer_name": "Example CA"}]
    if parsed.netloc == "precert.ru":
        check(query["query"] == ["example.com"], "precert query must use the apex")
        return {"data": [{"cn": "vpn.example.com", "issued": "2025-01-01", "expires": "2025-02-01", "issuer": "National CA"}]}
    raise AssertionError(f"unexpected URL: {url}")


def test_scope_metadata_and_deduplication() -> None:
    result = certcreep.collect("example.com", source="both", limit=10, timeout=9, retries=1, user_agent="SPOTTER smoke", request=fake_request)
    records = {record["name"]: record for record in result["records"]}
    check(result["count"] == 3, "only in-scope names should be retained")
    check("cdn.example.net" not in records, "out-of-scope SANs must not be retained")
    check(records["api.example.com"]["wildcard"], "wildcard evidence must survive deduplication")
    check(records["api.example.com"]["last_seen"] == "2026-02-01T00:00:00", "latest certificate observation must win")
    check(records["api.example.com"]["sources"] == ["crtsh"], "duplicate crt.sh rows must fold to one source")
    check(records["vpn.example.com"]["sources"] == ["precert"], "precert provenance must be retained")
    check(records["vpn.example.com"]["state"] == "historical", "expired certificates must be classified")


def test_idn_and_cap() -> None:
    check(certcreep.to_ascii_domain("пример.испытание") == "xn--e1afmkfd.xn--80akhbyknj4f", "IDNs must normalize to A-labels")
    result = certcreep.collect("example.com", source="crtsh", limit=1, timeout=9, retries=1, user_agent="SPOTTER smoke", request=fake_request)
    check(result["count"] == 2, "the count must report all matches before the cap")
    check(result["truncated"], "the cap must be visible to callers")
    check(len(result["records"]) == 1, "the cap must constrain records")


def test_failure_is_structured() -> None:
    def broken_request(url: str, timeout: int, retries: int, user_agent: str) -> Any:
        raise RuntimeError("offline")

    result = certcreep.collect("example.com", source="crtsh", request=broken_request)
    check(result["count"] == 0, "a failed backend must not fabricate names")
    check(result["errors"] == ["crtsh: offline"], "a failed backend must be reported")


def test_state_boundaries() -> None:
    now = datetime(2026, 9, 26, tzinfo=timezone.utc)
    check(certcreep.certificate_state("2026-10-01", now) == "live", "future certificate must be live")
    check(certcreep.certificate_state("2026-08-01", now) == "cooling", "recently expired certificate must be cooling")
    check(certcreep.certificate_state("2025-01-01", now) == "historical", "old certificate must be historical")


def test_ru_tld_is_precert_only() -> None:
    check(certcreep.source_for_domain("example.ru", "both") == "precert", "a .ru TLD must select precert")
    check(certcreep.source_for_domain("SUB.Example.RU.", "crtsh") == "precert", "a .ru TLD must ignore an explicit crt.sh request")
    check(certcreep.source_for_domain("example.com.ru", "both") == "precert", "the TLD, not an interior label, decides")
    check(certcreep.source_for_domain("example.ru.com", "both") == "both", "a name that merely contains ru must keep both sources")
    check(certcreep.source_for_domain("example.com") == "crtsh", "an omitted source keeps the module default")
    seen: list[str] = []

    def recording_request(url: str, timeout: int, retries: int, user_agent: str) -> Any:
        seen.append(urlparse(url).netloc)
        return {"data": [{"cn": "vpn.example.ru", "issued": "2026-01-01", "expires": "2027-01-01", "issuer": "National CA"}]}

    result = certcreep.collect("example.ru", source="both", limit=10, timeout=9, retries=1, user_agent="SPOTTER smoke", request=recording_request)
    check(seen == ["precert.ru"], f"a .ru collect must not call crt.sh, saw {seen}")
    check(result["records"][0]["sources"] == ["precert"], "the retained row must be marked precert")


def main() -> int:
    test_scope_metadata_and_deduplication()
    test_idn_and_cap()
    test_failure_is_structured()
    test_state_boundaries()
    test_ru_tld_is_precert_only()
    print("PASS: certcreep offline contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
