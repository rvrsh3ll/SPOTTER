#!/usr/bin/env python3
"""Passive certificate-transparency discovery for a single apex domain.

Compatible with the SPOTTER WF13 domain-recon contract. The design follows the
public behavior of OOAFA/certcreep (BSD-2-Clause) without requiring a package.

Imported DIRECTLY by WF13's CT block (a second, independent CT source beside
the inline CertKit call), so `certcreep` MUST be listed in
N8N_RUNNERS_EXTERNAL_ALLOW in deployment/docker-compose.n8n.yml and
deployment/n8n-task-runners.json, or the import fails the whole node with a
security violation before line 1 runs.
"""

from __future__ import annotations

import argparse
import json
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

CRTSH_URL = "https://crt.sh/"
PRECERT_URL = "https://precert.ru/results/ajax"
DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 3
DEFAULT_LIMIT = 200
DEFAULT_SOURCE = "crtsh"
DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"


@dataclass
class CertificateName:
    name: str
    unicode: str
    wildcard: bool = False
    first_seen: str = ""
    last_seen: str = ""
    not_after: str = ""
    issuers: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)

    def to_json(self) -> dict[str, Any]:
        result = asdict(self)
        result["issuers"] = sorted(self.issuers)
        result["sources"] = sorted(self.sources)
        result["state"] = certificate_state(self.not_after)
        return result


def to_ascii_domain(value: str) -> str:
    host = value.strip().lower().replace("https://", "").replace("http://", "").split("/", 1)[0]
    host = host.lstrip("*.").rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def source_for_domain(domain: str, requested: str | None = None) -> str:
    """CT backend for this domain.

    A .ru TLD is queried on precert.ru only, the same choice as
    ``certcreep.py --source precert``. An explicit crt.sh or both request is
    not honored for that TLD. Every other TLD keeps the requested source, or
    the module default when the caller did not choose one.
    """
    host = to_ascii_domain(domain).split(":", 1)[0]
    tld = host.rsplit(".", 1)[-1] if host else ""
    if tld == "ru":
        return "precert"
    if requested in ("crtsh", "precert", "both"):
        return requested
    return DEFAULT_SOURCE


def to_unicode_domain(value: str) -> str:
    try:
        return value.encode("ascii").decode("idna")
    except UnicodeError:
        return value


def in_scope(name: str, apex: str) -> bool:
    return name == apex or name.endswith("." + apex)


def parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    for pattern in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value[:19], pattern).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def certificate_state(not_after: str, now: datetime | None = None) -> str:
    expiry = parse_timestamp(not_after)
    if expiry is None:
        return "unknown"
    current = now or datetime.now(timezone.utc)
    if expiry > current:
        return "live"
    if expiry > current - timedelta(days=90):
        return "cooling"
    return "historical"


def _earlier(current: str, candidate: str) -> str:
    if not current or not candidate:
        return current or candidate
    current_time, candidate_time = parse_timestamp(current), parse_timestamp(candidate)
    if current_time is None:
        return candidate
    if candidate_time is None:
        return current
    return current if current_time <= candidate_time else candidate


def _later(current: str, candidate: str) -> str:
    if not current or not candidate:
        return current or candidate
    current_time, candidate_time = parse_timestamp(current), parse_timestamp(candidate)
    if current_time is None:
        return candidate
    if candidate_time is None:
        return current
    return current if current_time >= candidate_time else candidate


def _row_names(row: dict[str, Any]) -> Iterable[str]:
    for key in ("name_value", "common_name", "cn", "san", "dns_names", "name"):
        value = row.get(key)
        if value is None:
            continue
        values = value if isinstance(value, list) else [value]
        for entry in values:
            for name in str(entry).replace(",", "\n").splitlines():
                if name.strip():
                    yield name.strip().lower().rstrip(".")


def merge_rows(rows: Iterable[dict[str, Any]], apex: str, source: str) -> list[CertificateName]:
    names: dict[str, CertificateName] = {}
    for row in rows:
        issued = str(row.get("not_before") or row.get("entry_timestamp") or row.get("issued") or "")
        expires = str(row.get("not_after") or row.get("expires") or row.get("valid_to") or "")
        issuer = str(row.get("issuer_name") or row.get("issuer") or row.get("ca") or "").strip()
        for raw_name in _row_names(row):
            wildcard = raw_name.startswith("*.")
            name = to_ascii_domain(raw_name)
            if "." not in name or not in_scope(name, apex):
                continue
            record = names.get(name)
            if record is None:
                record = CertificateName(name=name, unicode=to_unicode_domain(name))
                names[name] = record
            record.wildcard = record.wildcard or wildcard
            record.first_seen = _earlier(record.first_seen, issued)
            record.last_seen = _later(record.last_seen, issued)
            record.not_after = _later(record.not_after, expires)
            record.sources.add(source)
            if issuer:
                record.issuers.add(issuer)
    return sorted(names.values(), key=lambda record: (parse_timestamp(record.last_seen) or datetime.min.replace(tzinfo=timezone.utc), record.name), reverse=True)


def request_json(url: str, timeout: int, retries: int, user_agent: str) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "application/json,text/plain,*/*"})
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
                payload = response.read().decode("utf-8", errors="replace").lstrip()
            if not payload or payload[0] not in "[{":
                raise ValueError("response was not JSON")
            return json.loads(payload)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as error:
            last_error = error
            if attempt + 1 < retries:
                time.sleep(min(8.0, 1.5 * (attempt + 1)) + random.uniform(0.2, 1.0))
    raise RuntimeError(str(last_error))


def crtsh_rows(apex: str, request: Callable[..., Any], timeout: int, retries: int, user_agent: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for query in (apex, f"%.{apex}"):
        params = urllib.parse.urlencode({"q": query, "output": "json"})
        response = request(f"{CRTSH_URL}?{params}", timeout, retries, user_agent)
        if not isinstance(response, list):
            continue
        for row in response:
            if not isinstance(row, dict):
                continue
            identity = row.get("id") or row.get("min_cert_id") or json.dumps(row, sort_keys=True)
            if identity not in seen:
                seen.add(identity)
                rows.append(row)
    return rows


def precert_rows(apex: str, request: Callable[..., Any], timeout: int, retries: int, user_agent: str) -> list[dict[str, Any]]:
    params = urllib.parse.urlencode({"query": apex, "draw": 1, "start": 0, "length": 1000})
    response = request(f"{PRECERT_URL}?{params}", timeout, retries, user_agent)
    if isinstance(response, dict):
        response = response.get("data") or response.get("rows") or response.get("results") or []
    return [row for row in response if isinstance(row, dict)] if isinstance(response, list) else []


def collect(domain: str, source: str = DEFAULT_SOURCE, limit: int = DEFAULT_LIMIT, timeout: int = DEFAULT_TIMEOUT, retries: int = DEFAULT_RETRIES, user_agent: str = DEFAULT_USER_AGENT, request: Callable[..., Any] = request_json) -> dict[str, Any]:
    apex = to_ascii_domain(domain)
    if not apex or "." not in apex:
        raise ValueError("domain must be an apex domain")
    source = source_for_domain(apex, source)
    records: dict[str, CertificateName] = {}
    errors: list[str] = []
    for backend, loader in (("crtsh", crtsh_rows), ("precert", precert_rows)):
        if source not in (backend, "both"):
            continue
        try:
            for record in merge_rows(loader(apex, request, timeout, retries, user_agent), apex, backend):
                existing = records.get(record.name)
                if existing is None:
                    records[record.name] = record
                else:
                    existing.wildcard = existing.wildcard or record.wildcard
                    existing.first_seen = _earlier(existing.first_seen, record.first_seen)
                    existing.last_seen = _later(existing.last_seen, record.last_seen)
                    existing.not_after = _later(existing.not_after, record.not_after)
                    existing.issuers.update(record.issuers)
                    existing.sources.update(record.sources)
        except Exception as error:
            errors.append(f"{backend}: {error}")
    ordered = sorted(records.values(), key=lambda record: (parse_timestamp(record.last_seen) or datetime.min.replace(tzinfo=timezone.utc), record.name), reverse=True)
    truncated = len(ordered) > limit
    return {
        "domain": apex,
        "records": [record.to_json() for record in ordered[:limit]],
        "count": len(ordered),
        "truncated": truncated,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive CT discovery for one apex domain")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("--source", choices=("crtsh", "precert", "both"), default=DEFAULT_SOURCE,
                        help="CT backend. A .ru TLD is forced to precert regardless of this flag.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    source = source_for_domain(arguments.domain, arguments.source)
    result = collect(arguments.domain, source, max(1, arguments.limit), max(1, arguments.timeout), max(1, arguments.retries), arguments.user_agent)
    if arguments.json:
        print(json.dumps(result, ensure_ascii=False))
    else:
        print("\n".join(record["name"] for record in result["records"]))
    return 0 if result["count"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
