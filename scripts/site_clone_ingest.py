#!/usr/bin/env python3
"""Write Site Clone findings into the campaign's Flowsint sketch.

Reuses flowsint_client the same way WF13 does: add_node + create_edge.
Emails and names become Individual nodes, the cloned site is a WebAsset,
secret-shaped hits become Credential nodes (hash + mask only — never the
raw value), technologies from generator meta become Technology nodes.

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
        "errors": errors[:20],
    }
