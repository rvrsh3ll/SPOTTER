"""
spotter_proxy.py — Centralized proxy resolution for all SPOTTER outbound traffic.

Resolves the effective proxy URL from (first hit wins):
  1. Explicit proxy_url parameter (from workflow envelope)
  2. SPOTTER_PROXY_URL env var (container-level default)
  3. BUCKET_PROBE_PROXY env var (legacy fallback)
  4. Empty string (direct connection)

Also provides helpers for building proxies dicts and extracting DNS resolvers
from the opsec envelope.

Usage:
    from spotter_proxy import resolve_proxy, proxies_dict

    proxy_url = resolve_proxy(explicit=body.get("proxy_url"))
    proxies = proxies_dict(proxy_url)
    requests.get(url, proxies=proxies, timeout=10)
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional


def resolve_proxy(explicit: Optional[str] = None) -> str:
    """Return the effective proxy URL.

    Resolution order (first non-empty wins):
      1. explicit — caller-supplied value (typically from the workflow envelope)
      2. SPOTTER_PROXY_URL — container-level default
      3. BUCKET_PROBE_PROXY — legacy per-source fallback
      4. "" — direct connection
    """
    for candidate in (
        explicit,
        os.environ.get("SPOTTER_PROXY_URL"),
        os.environ.get("BUCKET_PROBE_PROXY"),
    ):
        val = (candidate or "").strip()
        if val:
            return val
    return ""


def proxies_dict(proxy_url: Optional[str] = None, *, explicit: Optional[str] = None) -> Optional[Dict[str, str]]:
    """Return a requests-compatible proxies dict, or None for direct.

    Accepts either a pre-resolved proxy_url or an explicit value to resolve.
    """
    url = proxy_url if proxy_url is not None else resolve_proxy(explicit)
    url = (url or "").strip()
    if not url:
        return None
    return {"http": url, "https": url}


def resolve_dns_resolvers(opsec_cfg: Any) -> List[str]:
    """Extract DNS resolvers from the opsec envelope.

    Returns an empty list when the envelope carries none, so callers can
    unconditionally iterate without a None check.
    """
    if not isinstance(opsec_cfg, dict):
        return []
    raw = opsec_cfg.get("dns_resolvers") or []
    if not isinstance(raw, list):
        return []
    return [str(r).strip() for r in raw if str(r or "").strip()]
