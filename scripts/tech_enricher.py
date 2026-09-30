#!/usr/bin/env python3
"""
tech_enricher.py — Write CVE / MITRE / exploit context back onto Technology nodes.

THE GAP THIS CLOSES
-------------------
`Technology.cve_count`, `mitre_techniques` and `composite_risk` were read by five
consumers and written by none:

    n8n-workflows/12-tech-inventory.json     -> vulnerable_tech[]
    n8n-workflows/10-security-llm-analysis.json
    llm/tools/technology_tool.py
    llm/tools/tech_context_tool.py
    frontend/index.html                      -> the Vulnerable Technology panel

WF14 discovered technology names and indexed them into RAG, but never wrote the
results anywhere the graph could see. So the Tech Intel tab's empty state
("No CVE-mapped technology found — run enrichment or ensure NVD cache is
populated") described a condition no code path could ever clear. This module is
that missing writer.

WHAT IT WRITES (all under the nodeProperties.* namespace — see _np below)
    cve_count                int    CVEs matched for this technology
    cves                     JSON   [{cve_id, severity, base_score, exploit_available}]
    mitre_techniques         JSON   [{technique_id, name}]
    poc_count                int    public PoC repositories across those CVEs
    exploit_available        bool   at least one CVE has public exploit code
    top_pocs                 JSON   best few repos, with trust tier and warning
    composite_risk           int    tech_context_engine.compute_composite_risk
    tech_context_enriched_at str    ISO timestamp of this pass

Usage (host):
    python3 scripts/tech_enricher.py --sketch <id> --limit 5 --dry-run
    python3 scripts/tech_enricher.py --sketch <id>

Called by n8n-workflows/14-tech-context-indexer.json.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import flowsint_client as fc  # noqa: E402
from asset_labels import TECH_LABELS, TECH_READ_PROPS  # noqa: E402
from poc_client import PoCClient  # noqa: E402
from poc_client import normalise_cve as _normalise_cve  # noqa: E402
from high_value_tech import HIGH_VALUE_TECH  # noqa: E402
from tech_context_engine import TechContextEngine  # noqa: E402


# The labels to enrich and the properties to project both live in
# scripts/asset_labels.py now — WF04, WF12 and the three LLM tools read the same
# vocabulary, and two of the six hand-copies had already drifted. Its docstring
# carries the casing and cpe/cpes reasoning that used to live here.
#
# TECH_READ_PROPS is the ENRICHMENT projection (what you need to FIND CVEs). Do
# not swap it for TECH_SCORING_PROPS, which is WF04's: the two are distinct on
# purpose and mixing them fails silently.
READ_PROPS = TECH_READ_PROPS

# A Service node's nodeLabel is its host, not a product ("203.0.113.25 (2 ports)").
# Feeding that to an NVD keyword search spends the rate limit to retrieve nothing,
# so labels shaped like an address are never used as a search term.
_IPISH_RE = __import__("re").compile(
    r"^\s*(?:\d{1,3}\.){3}\d{1,3}\b|^\s*[0-9a-f:]{6,}\s*(?:\(|$)", __import__("re").I
)


def nvd_lookup_status(api_key: Optional[str] = None) -> Dict[str, Any]:
    """Return non-secret NVD rate-limit status for WF14 summaries."""
    has_key = bool(str(api_key if api_key is not None else os.environ.get("NVD_API_KEY") or "").strip())
    interval = 0.6 if has_key else 6.0
    status: Dict[str, Any] = {
        "provider": "nvd",
        "api_key_configured": has_key,
        "min_interval_seconds": interval,
    }
    if not has_key:
        status["caveat"] = (
            "NVD_API_KEY is not configured; CVE lookups are limited to one "
            "request every 6 seconds and large enrichment runs can take a long time."
        )
    return status


def _np(props: Dict[str, Any]) -> Dict[str, Any]:
    """Prefix an edit_node patch into the nodeProperties namespace.

    add_node nests whatever it is given under nodeProperties.*, but edit_node
    passes `updates` keys through verbatim, so a bare key lands at the node's
    TOP level -- a second namespace that get_nodes_by_type, the dossier query and
    the Technology catalog all read straight past. The write reports success and
    the value is genuinely in Neo4j, just not where anything looks. Every other
    workflow that calls edit_node prefixes the same way (WF09/WF12/WF13/WF21).
    """
    return {"nodeProperties." + k: v for k, v in props.items()}


def _as_list(value: Any) -> List[str]:
    """Property lists arrive as JSON strings; tolerate real lists too."""
    if isinstance(value, list):
        return [str(v) for v in value if v]
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except Exception:
            return [value.strip()]
        if isinstance(parsed, list):
            return [str(v) for v in parsed if v]
        return [str(parsed)] if parsed else []
    return []


def _cpe_keyword(cpe: str) -> Optional[str]:
    """
    'cpe:/a:apache:http_server' -> 'apache http server'.

    WF13 writes CPE 2.2 URIs, which NVD's 2.0 `cpeName` parameter does not
    accept (it wants the 2.3 form), so a 2.2 value would otherwise be silently
    useless. Degrading it to a vendor+product keyword is far better than
    discarding it: it is still a curated identifier, unlike the node label.
    """
    parts = [p for p in (cpe or "").replace("cpe:/", "").replace("cpe:2.3:", "").split(":") if p]
    # parts[0] is the part letter (a/o/h); vendor and product follow.
    words = [p.replace("_", " ") for p in parts[1:3] if p and p != "*"]
    return " ".join(words).strip() or None


def _node_targets(props: Dict[str, Any], node_label: str) -> Dict[str, Any]:
    """
    Decide what to ask NVD about, and what we already know.

    Three tiers, best first:

      known_cves  CVE IDs already recorded on the node. WF13 stores Shodan's
                  per-host findings in `vulns`, which until now was a JSON blob
                  nothing ever read — these are host-specific and authoritative,
                  so they beat anything a keyword search would guess.
      cpe         An exact identifier. Precise, but only the nmap ingest writes
                  the 2.3 form NVD accepts; WF13's 2.2 URIs degrade to keyword.
      name        Product-name keyword search. Noisy, hence CVE_MAX_PER_TECH.

    `name` is deliberately NOT allowed to fall back to a Service node's label.
    """
    name = (props.get("name") or props.get("product") or "").strip()
    if not name and node_label and not _IPISH_RE.match(node_label):
        name = node_label.strip()

    cpes = _as_list(props.get("cpes")) or ([props["cpe"]] if props.get("cpe") else [])
    cpe = next((c for c in cpes if c.strip()), "").strip()

    # A CPE is a better keyword than a bare product name when both exist and the
    # name is missing, e.g. a WF13 Service whose `product` came back empty.
    if not name and cpe:
        name = _cpe_keyword(cpe) or ""

    known = []
    for raw in _as_list(props.get("vulns")):
        canon = _normalise_cve(raw)
        if canon:
            known.append(canon)

    return {
        "name": name or None,
        "version": (props.get("version") or "").strip() or None,
        "cpe": cpe or None,
        "known_cves": sorted(set(known)),
    }


def _match_basis(cves: List[Dict[str, Any]]) -> str:
    """
    Single-word confidence label for how a node's CVE set was derived.

    'keyword' is the weak one and has to be visible: it means the CVEs came from
    an NVD phrase match on a product name, which legitimately returns other
    products' CVEs whose descriptions mention that name. Reporting those with the
    same confidence as a CPE or scanner match is how an operator ends up chasing
    an Ivanti bug on an Apache box.
    """
    kinds = {c.get("discovered_by") or "keyword" for c in cves}
    if not kinds:
        return "none"
    if len(kinds) == 1:
        return kinds.pop()
    return "mixed"


def enrich_technology_nodes(
    sketch_id: str = "",
    limit: Optional[int] = None,
    cves_per_tech: Optional[int] = None,
    dry_run: bool = False,
    engine: Optional[TechContextEngine] = None,
) -> Dict[str, Any]:
    """
    Resolve CVEs + MITRE + PoCs for every Technology/Service node and write the
    results back onto the node.

    Returns a summary dict. Individual node failures are collected into
    `errors` rather than aborting the pass: one unparseable node must not cost
    an operator the other four hundred.
    """
    sid = sketch_id or fc.resolve_campaign_sketch()
    if limit is None:
        limit = int(os.environ.get("TECH_ENRICH_MAX_NODES") or 500)
    if cves_per_tech is None:
        cves_per_tech = int(os.environ.get("CVE_MAX_PER_TECH") or 10)

    engine = engine or TechContextEngine()
    poc = engine.poc_client
    mirror = poc.mirror_status()

    result: Dict[str, Any] = {
        "sketch_id": sid,
        "dry_run": dry_run,
        "nodes_seen": 0,
        "nodes_enriched": 0,
        "nodes_skipped": 0,
        "nodes_with_cves": 0,
        "nodes_with_exploits": 0,
        "cve_ids": [],
        # Inventory of what was examined, so WF14 can index the asset collection
        # without a second graph read.
        "technologies": [],
        "poc_mirror": mirror,
        "cve_lookup": nvd_lookup_status(engine.cve_client.api_key),
        "errors": [],
        "samples": [],
    }

    # NEVER fc.get_graph() here: it is unpaginated, takes 110-235s on an AD-sized
    # sketch and silently truncates at 100k nodes, which would drop technologies
    # from the pass at random.
    try:
        nodes = fc.get_nodes_by_type(TECH_LABELS, sketch_id=sid, properties=READ_PROPS)
    except Exception as exc:
        result["errors"].append(f"node fetch failed: {exc}")
        return result

    result["nodes_seen"] = len(nodes)
    seen_cves: set = set()
    stamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    for node in nodes[:limit]:
        props = node.get("nodeProperties") or {}
        terms = _node_targets(props, node.get("nodeLabel", ""))
        label = terms["name"] or node.get("nodeLabel", "") or "(unnamed)"

        if not terms["name"] and not terms["known_cves"]:
            # Nothing searchable and nothing already known. Skipping is the point:
            # a Service node labelled by IP would otherwise spend NVD quota on a
            # keyword that cannot match.
            result["nodes_skipped"] += 1
            continue

        cves: List[Dict[str, Any]] = []

        # Tier 1 — CVE IDs already on the node (WF13/Shodan `vulns`). Looked up
        # by ID, which is exact and cache-cheap, and finally joins Shodan's
        # findings to the Technology/Service graph instead of leaving them as an
        # unread JSON string.
        for cve_id in terms["known_cves"][:cves_per_tech]:
            try:
                detail = engine.cve_client.get_cve(cve_id)
            except Exception as exc:
                result["errors"].append(f"{label}: {cve_id} lookup failed: {exc}")
                continue
            if detail:
                detail["discovered_by"] = "shodan"
                cves.append(detail)

        # Tiers 2 and 3 — CPE, then product keyword.
        if len(cves) < cves_per_tech:
            remaining = cves_per_tech - len(cves)
            found: List[Dict[str, Any]] = []
            try:
                # A CPE in ANY spelling beats the keyword path — map_cpe_to_cves
                # normalises 2.2 and version-less URIs to a partial 2.3 match.
                # Keyword search is the last resort precisely because it
                # phrase-matches other vendors' CVEs onto your product.
                if terms["cpe"]:
                    found = engine.map_cpe_to_cves(terms["cpe"], limit=remaining)
                    if found:
                        for _c in found:
                            _c["discovered_by"] = "cpe"
                if not found and terms["name"]:
                    found = engine.map_tech_to_cves(
                        terms["name"], terms["version"], limit=remaining
                    )
                    for _c in found:
                        _c.setdefault("discovered_by", "keyword")
            except Exception as exc:
                result["errors"].append(f"{label}: CVE lookup failed: {exc}")
            known_ids = {c.get("cve_id") for c in cves}
            cves.extend(c for c in found if c.get("cve_id") not in known_ids)

        # get_cve() bypasses map_tech_to_cves, so the PoC annotation has to be
        # applied to the merged list rather than assumed.
        engine.annotate_cves_with_pocs(cves)

        try:
            mitre = engine.map_tech_to_mitre(terms["name"], limit=5) if terms["name"] else []
        except Exception:
            mitre = []

        cve_ids = [c.get("cve_id") for c in cves if c.get("cve_id")]
        seen_cves.update(cve_ids)
        exploit = poc.summarise_for_cves(cve_ids, top_n=3)
        exploitable = len(exploit["cves_with_pocs"])

        risk = engine.compute_composite_risk(
            os_risk="supported",
            tech_stack=[terms["name"]] if terms["name"] in HIGH_VALUE_TECH else [],
            cve_exposure=len(cves),
            exploitable_cve_count=exploitable,
        )

        patch = {
            "cve_count": len(cves),
            # Stored as JSON strings: a registered type coerces declared fields
            # and nested structures do not survive the property write intact.
            # Every reader already json.loads() these (see WF12's relevant_cves).
            "cves": json.dumps([
                {
                    "cve_id": c.get("cve_id"),
                    "severity": (c.get("cvss") or {}).get("severity"),
                    "base_score": (c.get("cvss") or {}).get("base_score"),
                    "exploit_available": bool(c.get("exploit_available")),
                    "poc_count": int(c.get("poc_count") or 0),
                    # How this CVE came to be attached, because the three routes
                    # are NOT equally trustworthy and the difference is invisible
                    # downstream otherwise:
                    #   shodan  - the scanner reported it against this exact host
                    #   cpe     - matched on the component's CPE; product-accurate
                    #   keyword - NVD phrase match on the product NAME, which also
                    #             hits other vendors' CVEs whose text mentions it
                    #             (Ivanti Sentry's CVE-2023-38035 names "Apache
                    #             httpd", so it lands on every Apache host)
                    "match": c.get("discovered_by") or "keyword",
                }
                for c in cves
            ]),
            "cve_match_basis": _match_basis(cves),
            # Both key spellings on purpose. The system prompt and the OWUI tools
            # read `technique_id`; the frontend's Vulnerable Technology card reads
            # `m.id` (index.html renderTechIntel). Emitting one would silently
            # render blank tags in whichever surface used the other spelling.
            "mitre_techniques": json.dumps([
                {
                    "technique_id": m.get("technique_id"),
                    "id": m.get("technique_id"),
                    "name": m.get("name"),
                }
                for m in mitre
            ]),
            "poc_count": exploit["poc_count"],
            "exploit_available": exploit["exploit_available"],
            "top_pocs": json.dumps(exploit["top_pocs"]),
            "composite_risk": risk["composite_score"],
            "tech_context_enriched_at": stamp,
        }

        if len(result["samples"]) < 5:
            result["samples"].append({
                "node": label,
                "cve_count": patch["cve_count"],
                "poc_count": patch["poc_count"],
                "exploit_available": patch["exploit_available"],
                "composite_risk": patch["composite_risk"],
            })

        result["technologies"].append({
            "id": node.get("id"),
            "name": terms["name"] or label,
            "version": terms["version"],
            "category": props.get("category"),
            "vendor": props.get("vendor"),
            "node_type": (node.get("nodeType") or "").lower(),
        })

        if cves:
            result["nodes_with_cves"] += 1
        if exploit["exploit_available"]:
            result["nodes_with_exploits"] += 1

        if dry_run:
            result["nodes_enriched"] += 1
            continue

        try:
            fc.edit_node(node["id"], _np(patch), sketch_id=sid)
            result["nodes_enriched"] += 1
        except Exception as exc:
            result["errors"].append(f"{label}: write failed: {exc}")

    result["cve_ids"] = sorted(seen_cves)
    if len(nodes) > limit:
        # Never let a capped pass read as a complete one.
        result["errors"].append(
            f"capped at TECH_ENRICH_MAX_NODES={limit} of {len(nodes)} nodes; "
            "raise the limit or re-run to cover the rest"
        )
    return result


def verify_enrichment(sketch_id: str = "", sample: int = 5) -> Dict[str, Any]:
    """
    Read enriched nodes back out of the graph.

    Exists because edit_node reports success whether or not the keys landed
    somewhere a reader looks: the only proof the namespace was right is a
    read-back through the same path WF12 uses.
    """
    sid = sketch_id or fc.resolve_campaign_sketch()
    nodes = fc.get_nodes_by_type(
        TECH_LABELS, sketch_id=sid,
        properties=["name", "cve_count", "poc_count", "exploit_available",
                    "composite_risk", "tech_context_enriched_at"],
    )
    enriched = [n for n in nodes
                if (n.get("nodeProperties") or {}).get("tech_context_enriched_at")]
    return {
        "sketch_id": sid,
        "total_nodes": len(nodes),
        "enriched_nodes": len(enriched),
        "sample": [n.get("nodeProperties") for n in enriched[:sample]],
    }


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sketch", default="", help="sketch id (default: resolve_campaign_sketch)")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--cves-per-tech", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verify", action="store_true", help="read enriched nodes back and exit")
    args = ap.parse_args()

    if args.verify:
        print(json.dumps(verify_enrichment(args.sketch), indent=2, default=str))
        return 0

    out = enrich_technology_nodes(
        sketch_id=args.sketch, limit=args.limit,
        cves_per_tech=args.cves_per_tech, dry_run=args.dry_run,
    )
    print(json.dumps(out, indent=2, default=str))
    return 0 if not out["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
