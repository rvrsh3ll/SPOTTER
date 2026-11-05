#!/usr/bin/env python3
"""Passive certificate-transparency discovery for a single apex domain.

Compatible with the SPOTTER WF13 domain-recon contract. The design follows the
public behavior of OOAFA/certcreep (BSD-2-Clause) without requiring a package.

Imported DIRECTLY by WF13's CT block (a second, independent CT source beside
the inline CertKit call), so `certcreep` MUST be listed in
N8N_RUNNERS_EXTERNAL_ALLOW in deployment/docker-compose.n8n.yml and
deployment/n8n-task-runners.json, or the import fails the whole node with a
security violation before line 1 runs.

Upstream OOAFA/certcreep (post-initial) additions folded in here where they
fit the library contract: crt.name as a third CT index, richer timestamp
parsing, unicode-aware in-scope checks, host-shape filtering, and HTTP
no-retry for hard 4xx from rate-limited indexes. SPOTTER-only surfaces kept:
`source_for_domain` / PRECERT_TLDS, injectable `request` + proxies on
`collect()`, and the `{domain, records, count, truncated, errors}` return
shape. CLI `--source both` still means crt.sh + precert.ru (WF13); pass
`crtname` or `all` to include crt.name.
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
CRTNAME_URL = "https://crt.name/v1/search"
DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 3
DEFAULT_LIMIT = 200
DEFAULT_SOURCE = "crtsh"
DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
SOURCES = ("crtsh", "precert", "crtname")


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


# TLDs where precert.ru is the best CT source. These are Russian-language and
# post-Soviet TLDs where precert.ru has better coverage than crt.sh.
PRECERT_TLDS = {"ru", "su", "by", "kz", "ua", "uz", "tj", "kg", "am", "az", "ge", "md"}


def source_for_domain(domain: str, requested: str | None = None) -> str:
    """CT backend for this domain.

    A .ru or other Cyrillic-adjacent TLD is queried on precert.ru only, the
    same choice as ``certcreep.py --source precert``. An explicit crt.sh or
    both request is not honored for those TLDs. Every other TLD keeps the
    requested source, or the module default when the caller did not choose one.
    """
    host = to_ascii_domain(domain).split(":", 1)[0]
    tld = host.rsplit(".", 1)[-1] if host else ""
    if tld in PRECERT_TLDS:
        return "precert"
    if requested in ("crtsh", "precert", "crtname", "both", "all"):
        return requested
    return DEFAULT_SOURCE


def to_unicode_domain(value: str) -> str:
    try:
        return value.encode("ascii").decode("idna")
    except UnicodeError:
        return value


def in_scope(name: str, apex: str) -> bool:
    if name == apex or name.endswith("." + apex):
        return True
    u_name, u_apex = to_unicode_domain(name), to_unicode_domain(apex)
    return u_name == u_apex or u_name.endswith("." + u_apex)


def looks_like_host(part: str) -> bool:
    if not part or "@" in part:
        return False
    if part.startswith("http://") or part.startswith("https://"):
        return False
    if " " in part:
        return False
    if part.replace(".", "").isdigit():
        return False
    return "." in part or part.endswith(".local") or part.endswith(".internal")


def parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().rstrip("Z")
    if not text:
        return None
    for pattern in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d.%m.%Y",
    ):
        try:
            return datetime.strptime(text[:26], pattern).replace(tzinfo=timezone.utc)
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
            if (not looks_like_host(name) and name != apex) or not in_scope(name, apex):
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


def request_json(
    url: str,
    timeout: int,
    retries: int,
    user_agent: str,
    proxies: dict[str, str] | None = None,
    no_retry: tuple[int, ...] = (),
) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "application/json,text/plain,*/*",
            "Accept-Language": "en-US,en;q=0.8",
        },
    )
    proxy_handler = urllib.request.ProxyHandler(proxies) if proxies else urllib.request.ProxyHandler()
    opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            with opener.open(request, timeout=timeout) as response:
                payload = response.read().decode("utf-8", errors="replace").lstrip()
            if not payload or payload[0] not in "[{":
                raise ValueError("response was not JSON")
            return json.loads(payload)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as error:
            last_error = error
            if isinstance(error, urllib.error.HTTPError) and error.code in no_retry:
                raise
            if attempt + 1 < retries:
                time.sleep(min(8.0, 1.5 * (attempt + 1)) + random.uniform(0.2, 1.0))
    raise RuntimeError(str(last_error))


def crtsh_rows(apex: str, request: Callable[..., Any], timeout: int, retries: int, user_agent: str, proxies: dict[str, str] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for query in (apex, f"%.{apex}"):
        params = urllib.parse.urlencode({"q": query, "output": "json"})
        response = request(f"{CRTSH_URL}?{params}", timeout, retries, user_agent, proxies)
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


def precert_rows(apex: str, request: Callable[..., Any], timeout: int, retries: int, user_agent: str, proxies: dict[str, str] | None = None) -> list[dict[str, Any]]:
    params = urllib.parse.urlencode({"query": apex, "draw": 1, "start": 0, "length": 1000})
    response = request(f"{PRECERT_URL}?{params}", timeout, retries, user_agent, proxies)
    if isinstance(response, dict):
        response = response.get("data") or response.get("rows") or response.get("results") or []
    return [row for row in response if isinstance(row, dict)] if isinstance(response, list) else []


def crtname_rows(apex: str, request: Callable[..., Any], timeout: int, retries: int, user_agent: str, proxies: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """crt.name /v1/search: one row per indexed name. Hard 4xx is not retried.

    A sub-apex (corp.example.ru) may get HTTP 400 naming the eTLD+1; retry once
    with that parent and let the in-scope filter narrow it. Free tier is 100
    requests per IP per day.
    """
    no_retry = (400, 401, 403, 404, 429)

    def fetch(q: str) -> Any:
        params = urllib.parse.urlencode({"apex": q, "format": "json", "dates": 1})
        return request(f"{CRTNAME_URL}?{params}", timeout, retries, user_agent, proxies, no_retry)

    try:
        data = fetch(apex)
    except urllib.error.HTTPError as exc:
        if exc.code != 400:
            raise
        body = exc.read().decode("utf-8", errors="replace")
        marker = "eTLD+1 is "
        if marker not in body:
            raise ValueError(f"HTTP 400: {body.strip()[:120]}") from exc
        parent = body.split(marker, 1)[1].strip().rstrip(")").split()[0]
        if not parent or parent == apex:
            raise ValueError(f"HTTP 400: {body.strip()[:120]}") from exc
        data = fetch(parent)
    rows: list[dict[str, Any]] = []
    if not isinstance(data, list):
        return rows
    for item in data:
        if not isinstance(item, dict) or not item.get("sub"):
            continue
        seen = str(item.get("first_seen") or "").rstrip("Z")
        rows.append({"name_value": str(item["sub"]), "entry_timestamp": seen})
    return rows


def _backends_for_source(source: str) -> tuple[str, ...]:
    """Map a SPOTTER/CLI source token to the backend loaders to run."""
    if source == "both":
        return ("crtsh", "precert")
    if source == "all":
        return SOURCES
    if source in SOURCES:
        return (source,)
    return (DEFAULT_SOURCE,)


def collect(
    domain: str,
    source: str = DEFAULT_SOURCE,
    limit: int = DEFAULT_LIMIT,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    user_agent: str = DEFAULT_USER_AGENT,
    request: Callable[..., Any] = request_json,
    proxies: dict[str, str] | None = None,
) -> dict[str, Any]:
    apex = to_ascii_domain(domain)
    if not apex or "." not in apex:
        raise ValueError("domain must be an apex domain")
    source = source_for_domain(apex, source)
    loaders = {
        "crtsh": crtsh_rows,
        "precert": precert_rows,
        "crtname": crtname_rows,
    }
    records: dict[str, CertificateName] = {}
    errors: list[str] = []
    for backend in _backends_for_source(source):
        loader = loaders[backend]
        try:
            for record in merge_rows(loader(apex, request, timeout, retries, user_agent, proxies), apex, backend):
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
    parser.add_argument(
        "--source",
        choices=("crtsh", "precert", "crtname", "both", "all"),
        default=DEFAULT_SOURCE,
        help="CT backend. A .ru TLD is forced to precert regardless of this flag. "
             "'both' = crt.sh + precert.ru (WF13 default); 'all' also includes crt.name.",
    )
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
