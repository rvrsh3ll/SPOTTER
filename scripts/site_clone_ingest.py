#!/usr/bin/env python3
"""Write Site Clone findings into the campaign's Flowsint sketch.

Reuses flowsint_client the same way WF13 does: add_node + create_edge.
Emails and names become Individual nodes, the cloned site is a WebAsset,
secret-shaped hits become Credential nodes (hash + mask only — never the
raw value), technologies from generator meta become Technology nodes.
API endpoints and JS URLs become WebAsset nodes: same-registrable-domain
ones are correlated to the cloned site and any existing org apex
WebAsset (`{domain} (web)`); external hosts stay separate, with
provenance source=site-clone and deobfuscated/ocr flags when applicable.

Idempotent on (type, label) because add_node MERGEs on the label.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flowsint_client as fc  # noqa: E402


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower().lstrip("www.")


def _id(node: Any) -> str:
    if isinstance(node, dict):
        return str(node.get("id") or node.get("_id") or "")
    return ""


def _hash_secret(sketch_id: str, masked: str) -> str:
    # Raw values never reach this module — the analyzer already redacted them.
    # Hash the masked form plus sketch so a Credential node still dedups.
    return hashlib.sha256(("%s:%s" % (sketch_id, masked)).encode()).hexdigest()


_TWO_LEVEL = {
    "co.uk", "com.au", "co.jp", "com.br", "co.nz", "com.tr",
    "co.za", "co.in", "com.mx", "co.kr", "com.sg", "com.hk",
}


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain; errs toward a longer (stricter) base."""
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in _TWO_LEVEL and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _same_registrable(host_a: str, host_b: str) -> bool:
    a = registrable_domain(host_a)
    b = registrable_domain(host_b)
    return bool(a and b and a == b)


def _normalize_endpoint(value: str, start_url: str) -> str:
    """Turn a JS-discovered URL or API path into an absolute http(s) URL."""
    raw = (value or "").strip()
    if not raw or len(raw) > 2048:
        return ""
    lower = raw.lower()
    if lower.startswith(("javascript:", "data:", "mailto:", "about:", "blob:")):
        return ""
    if raw.startswith("//"):
        scheme = urlparse(start_url).scheme or "https"
        raw = "%s:%s" % (scheme, raw)
    parsed = urlparse(raw)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        # Drop fragments; keep query (it is often part of an API shape).
        return parsed._replace(fragment="").geturl()
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return ""
    base = start_url or ""
    if not base:
        return ""
    from urllib.parse import urljoin
    joined = urljoin(base if base.endswith("/") else base + "/", raw)
    got = urlparse(joined)
    if got.scheme not in {"http", "https"} or not got.netloc:
        return ""
    return got._replace(fragment="").geturl()


def _host_of(node: dict[str, Any]) -> str:
    props = node.get("nodeProperties") or {}
    return (
        _host(str(props.get("fqdn") or props.get("url") or props.get("domain") or ""))
        or _host("https://" + str(node.get("nodeLabel") or ""))
    )


def _existing_org_webassets(sketch_id: str, registrable: str) -> list[dict[str, Any]]:
    """WebAssets already in the sketch that share the org's registrable domain."""
    if not registrable:
        return []
    try:
        nodes = fc.get_nodes_by_type(
            "WebAsset", sketch_id=sketch_id,
            properties=["url", "fqdn", "domain", "source"],
        )
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for n in nodes or []:
        host = _host_of(n)
        label = str(n.get("nodeLabel") or "")
        if _same_registrable(host, registrable) or _same_registrable(
                _host("https://" + label.split(" ", 1)[0]), registrable):
            out.append(n)
    return out


def ingest_findings(
    report: dict[str, Any],
    sketch_id: str,
    campaign_id: str = "",
    job_id: str = "",
) -> dict[str, Any]:
    if not sketch_id:
        return {"ok": False, "error": "missing sketch_id", "written": 0}
    if not report or not report.get("ok"):
        return {"ok": False, "error": "no analysis report", "written": 0}

    start_url = str(report.get("start_url") or "")
    host = _host(start_url) or "cloned-site"
    summary = report.get("summary") or {}
    findings = list(report.get("findings") or [])

    site_label = (host + " (clone)")[:200]
    site_props = {
        "url": start_url,
        "fqdn": host,
        "source": "site-clone",
        "campaign_id": campaign_id,
        "job_id": job_id,
        "files_scanned": int(report.get("files_scanned") or 0),
        "finding_count": int(report.get("finding_count") or 0),
        "summary": {k: int(v) for k, v in summary.items()},
    }
    site = fc.add_node(label=site_label, node_type="WebAsset", properties=site_props, sketch_id=sketch_id)
    site_id = _id(site)
    written = 1 if site_id else 0
    emails = 0
    people = 0
    creds = 0
    techs = 0
    endpoints = 0
    errors: list[str] = []

    def link(src: str, tgt: str, typ: str) -> None:
        if src and tgt:
            try:
                fc.create_edge(src, tgt, typ, sketch_id)
            except Exception as e:
                errors.append("%s: %s" % (typ, type(e).__name__))

    seen_email: set[str] = set()
    seen_name: set[str] = set()
    seen_cred: set[str] = set()
    seen_tech: set[str] = set()
    seen_endpoint: set[str] = set()
    org_reg = registrable_domain(host)
    org_assets: list[dict[str, Any]] | None = None

    for f in findings:
        cat = f.get("category")
        val = str(f.get("value") or "").strip()
        if not val:
            continue
        try:
            if cat == "email":
                em = val.lower()
                if em in seen_email or not re.search(r"^[^@]+@[^@]+\.[^@]+$", em):
                    continue
                seen_email.add(em)
                node = fc.add_node(
                    label=em, node_type="individual",
                    properties={"email": em, "source": "site-clone",
                                "site_evidence": str(f.get("source_path") or "")[:200]},
                    sketch_id=sketch_id,
                )
                nid = _id(node)
                if nid:
                    emails += 1
                    written += 1
                    link(nid, site_id, "FOUND_ON")
            elif cat == "name":
                nm = val[:200]
                key = nm.lower()
                if key in seen_name:
                    continue
                seen_name.add(key)
                props = {"name": nm, "source": "site-clone",
                         "site_evidence": str(f.get("source_path") or "")[:200]}
                if f.get("email"):
                    props["email"] = str(f["email"])[:200]
                if f.get("role"):
                    props["title"] = str(f["role"])[:200]
                node = fc.add_node(label=nm, node_type="individual", properties=props, sketch_id=sketch_id)
                nid = _id(node)
                if nid:
                    people += 1
                    written += 1
                    link(nid, site_id, "NAMED_ON")
            elif cat == "js_secret":
                masked = val  # already redacted by the analyzer
                if masked in seen_cred:
                    continue
                seen_cred.add(masked)
                node = fc.add_node(
                    label=("clone-cred:" + masked)[:200],
                    node_type="credential",
                    properties={
                        "cred_type": str(f.get("secret_kind") or "credential_pattern"),
                        "value_hash": _hash_secret(sketch_id, masked),
                        "value_masked": masked[:80],
                        "severity": str(f.get("severity") or "high"),
                        "source_file": str(f.get("source_path") or "")[:200],
                        "source_context": str(f.get("evidence") or "")[:120],
                        "source": "site-clone",
                    },
                    sketch_id=sketch_id,
                )
                nid = _id(node)
                if nid:
                    creds += 1
                    written += 1
                    link(nid, site_id, "FOUND_IN")
            elif cat == "js_endpoint":
                url = _normalize_endpoint(val, start_url)
                if not url or url in seen_endpoint:
                    continue
                seen_endpoint.add(url)
                ep_host = _host(url) or host
                same = _same_registrable(ep_host, host)
                path = urlparse(url).path or "/"
                label = (url if len(url) <= 180 else (ep_host + path)[:170]) + " (endpoint)"
                props = {
                    "url": url,
                    "fqdn": ep_host,
                    "path": path[:300],
                    "source": "site-clone",
                    "provenance": "site_clone",
                    "campaign_id": campaign_id,
                    "job_id": job_id,
                    "source_file": str(f.get("source_path") or "")[:200],
                    "same_site": same,
                    "external": not same,
                }
                if f.get("deobfuscated"):
                    props["deobfuscated"] = True
                    if f.get("deobfuscator"):
                        props["deobfuscator"] = str(f.get("deobfuscator"))[:40]
                if f.get("ocr"):
                    props["ocr"] = True
                node = fc.add_node(
                    label=label[:200], node_type="WebAsset",
                    properties=props, sketch_id=sketch_id,
                )
                nid = _id(node)
                if nid:
                    endpoints += 1
                    written += 1
                    link(nid, site_id, "FOUND_ON")
                    if same:
                        if org_assets is None:
                            org_assets = _existing_org_webassets(sketch_id, org_reg)
                        for asset in org_assets or []:
                            aid = _id(asset)
                            if aid and aid != site_id and aid != nid:
                                link(nid, aid, "FOUND_ON")
            elif cat == "meta" and val.lower().startswith("generator="):
                tech = val.split("=", 1)[1].strip()[:120]
                key = tech.lower()
                if not tech or key in seen_tech:
                    continue
                seen_tech.add(key)
                node = fc.add_node(
                    label=tech, node_type="Technology",
                    properties={"name": tech, "source": "site-clone"},
                    sketch_id=sketch_id,
                )
                nid = _id(node)
                if nid:
                    techs += 1
                    written += 1
                    link(site_id, nid, "USES_TECH")
        except Exception as e:
            errors.append("%s: %s" % (cat, type(e).__name__))

    return {
        "ok": True,
        "webasset_id": site_id,
        "written": written,
        "emails": emails,
        "people": people,
        "credentials": creds,
        "technologies": techs,
        "endpoints": endpoints,
        "errors": errors[:20],
    }
