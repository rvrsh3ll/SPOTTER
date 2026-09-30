#!/usr/bin/env python3
"""
nessus_context.py — Contextualize ingested Nessus findings, and roll them up
onto the hosts they affect.

WHAT THIS ADDS THAT THE SCAN DOES NOT
-------------------------------------
A Nessus report tells you a plugin fired and how bad Tenable thinks it is. It
does not tell you whether someone has already written a working exploit for it,
which ATT&CK technique using it would be, or how the finding ranks against the
AD position of the host it sits on. Those are the three things that decide
whether a finding is worth an operator's afternoon, and SPOTTER already has all
three sources:

    scripts/poc_client.py          local PoC-in-GitHub mirror  (offline)
    scripts/mitre_client.py        local ATT&CK STIX bundle    (offline)
    scripts/cve_client.py          NVD                         (network, opt-in)

WHAT IT WRITES (all under the nodeProperties.* namespace — see _np below)

  On each Vulnerability node:
    poc_count                int    public PoC repositories across its CVEs
    exploit_available        bool   at least one CVE has public exploit code
    top_pocs                 JSON   best few repos, with trust tier and warning
    cves_with_pocs           JSON   which of its CVEs the PoCs were found for
    mitre_techniques         JSON   [{technique_id, id, name}]
    priority_score           int    recomputed 0-100 WITH exploit availability
    priority_tier            str    band of that score
    nvd_cvss3_base_score     float  only when --with-nvd is used
    context_enriched_at      str    ISO timestamp of this pass

  On each scanned host (Device / Ip), from its HAS_VULNERABILITY edges:
    nessus_risk_score              int    severity-weighted, exploit-weighted
    nessus_critical_count …        int    per-severity counts
    nessus_exploitable_findings    int    findings with public exploit code
    nessus_cve_exposure            int    distinct CVEs on this host
    nessus_top_findings            JSON   worst few, ranked by priority_score
    nessus_context_at              str    ISO timestamp of this pass

The rollup is the half that makes the data reachable: `nessus_cve_exposure` and
`nessus_exploitable_findings` are named to drop straight into
`tech_context_engine.compute_composite_risk(cve_exposure=…,
exploitable_cve_count=…)`, which is what lets a scan finding move a target up
the attack-path ranking instead of sitting in a panel nobody joins to anything.

NVD IS OPT-IN, DELIBERATELY
---------------------------
Nessus already supplies severity, CVSS, description and remediation, so NVD adds
little here — and a live per-CVE lookup publishes to a third party exactly which
CVEs interest you, on an engagement where that inference is not free. Same
reasoning as the PoC mirror being local (see scripts/poc_client.py). Pass
`--with-nvd` / `include_nvd=True` when the cache is warm or the exposure is
acceptable.

PoC repositories are UNVETTED — inclusion means a repo name or description
matched a CVE ID, nothing more. Every record carries that flag and it must be
passed through to the operator verbatim.

Usage (host):
    python3 scripts/nessus_context.py --sketch <id> --dry-run
    python3 scripts/nessus_context.py --sketch <id>
    python3 scripts/nessus_context.py --sketch <id> --verify

Called by n8n-workflows/25-vulnerability-context.json.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import flowsint_client as fc  # noqa: E402
from nessus_parser import (  # noqa: E402
    SEVERITY_ORDER, SEVERITY_RANK, SEVERITY_WEIGHT, VULN_NODE_TYPE,
    compute_priority, priority_tier,
)
from poc_client import PoCClient  # noqa: E402
from tech_context_engine import TechContextEngine  # noqa: E402


# Neo4j label for the custom type.
# BOTH casings, and the lowercase one first because that is what actually lands.
# batch_import writes through /api/import/execute, which LOWERCASES the node type
# — a report ingested that way is labelled `vulnerability`, not `Vulnerability`,
# even though the type is registered in PascalCase. Reading only the PascalCase
# spelling found zero nodes, so the whole contextualization pass ran, reported
# success and did nothing. (Nodes written with fc.add_node keep PascalCase, which
# is why other SPOTTER custom types look different in the graph.)
VULN_LABELS = [VULN_NODE_TYPE.lower(), VULN_NODE_TYPE]
# Same reasoning, same fix, for the hosts a rollup writes back to.
HOST_LABELS = ["device", "Device", "ip", "Ip", "IP"]

# Projected so a pass does not ship the description/solution text it will discard.
READ_PROPS = [
    "plugin_id", "name", "family", "severity", "cve_ids", "cve_count",
    "affected_host_count", "exploit_frameworks", "exploit_framework_available",
    "priority_score", "cvss3_base_score", "cvss_base_score", "synopsis",
]

MAX_MITRE_PER_VULN = 4
MAX_TOP_POCS = 3
MAX_TOP_FINDINGS_PER_HOST = 8
# A per-node failure mode (RAG offline, mirror unreadable) fires once per node.
# Unbounded, a 1000-finding pass answers with 1000 copies of the same sentence
# and the summary that matters scrolls off the top.
MAX_ERRORS = 50


def _err(result: Dict[str, Any], message: str) -> None:
    """Append an error, bounded. The overflow is announced, not dropped silently."""
    errors = result["errors"]
    if len(errors) < MAX_ERRORS:
        errors.append(message)
    elif len(errors) == MAX_ERRORS:
        errors.append(f"... further errors suppressed after {MAX_ERRORS}; the "
                      f"cause is almost certainly the one repeated above")


def _np(props: Dict[str, Any]) -> Dict[str, Any]:
    """Prefix an edit_node patch into the nodeProperties namespace.

    add_node nests whatever it is given under nodeProperties.*, but edit_node
    does NOT — an unprefixed key lands at the node's top level, where no reader
    looks, and every layer still reports success. Every workflow that calls
    edit_node prefixes the same way (WF09/WF12/WF13/WF21, tech_enricher).
    """
    return {"nodeProperties." + k: v for k, v in props.items()}


def _as_list(value: Any) -> List[str]:
    """Read a property that may be a Neo4j array or a JSON string."""
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    if isinstance(value, str) and value.strip():
        text = value.strip()
        if text[:1] in ("[", "{"):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return [text]
            if isinstance(parsed, list):
                return [str(v) for v in parsed if v not in (None, "")]
            return [str(parsed)]
        # Comma-separated is how some exports write the CVE cell.
        return [p.strip() for p in text.split(",") if p.strip()]
    return []


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ── Pass 1: contextualize the Vulnerability nodes ─────────────────────────────

def contextualize_vulnerabilities(
    sketch_id: str = "",
    limit: Optional[int] = None,
    dry_run: bool = False,
    include_nvd: bool = False,
    engine: Optional[TechContextEngine] = None,
) -> Dict[str, Any]:
    """
    Attach exploit availability, ATT&CK context and a recomputed priority score
    to every Vulnerability node, and write the results back onto the node.

    Individual node failures are collected into `errors` rather than aborting:
    one unparseable finding must not cost an operator the other four hundred.
    """
    sid = sketch_id or fc.resolve_campaign_sketch()
    if limit is None:
        limit = int(os.environ.get("NESSUS_CONTEXT_MAX_NODES") or 1000)

    engine = engine or TechContextEngine()
    poc = engine.poc_client
    mirror = poc.mirror_status()

    result: Dict[str, Any] = {
        "sketch_id": sid,
        "dry_run": dry_run,
        "include_nvd": include_nvd,
        "nodes_seen": 0,
        "nodes_enriched": 0,
        "nodes_skipped": 0,
        "nodes_with_cves": 0,
        "nodes_with_exploits": 0,
        "cve_ids": [],
        "poc_mirror": mirror,
        "errors": [],
        "samples": [],
    }

    # NEVER fc.get_graph() here: it is unpaginated, takes 110-235s on an AD-sized
    # sketch and silently truncates at 100k nodes, which would drop findings from
    # the pass at random.
    try:
        nodes = fc.get_nodes_by_type(VULN_LABELS, sketch_id=sid, properties=READ_PROPS)
    except Exception as exc:
        result["errors"].append(f"node fetch failed: {exc}")
        return result

    result["nodes_seen"] = len(nodes)
    seen_cves: set = set()
    stamp = _stamp()
    # One RAG round trip per finding is the expensive part of this pass, and
    # plugins in the same family produce the same query often enough to be worth
    # remembering within a run.
    mitre_memo: Dict[str, List[Dict[str, Any]]] = {}

    for node in nodes[:limit]:
        props = node.get("nodeProperties") or {}
        label = node.get("nodeLabel") or props.get("plugin_id") or "(unnamed)"
        cve_ids = _as_list(props.get("cve_ids"))
        severity = str(props.get("severity") or "info").lower()
        if severity not in SEVERITY_RANK:
            severity = "info"
        host_count = _int(props.get("affected_host_count"))
        frameworks = _as_list(props.get("exploit_frameworks"))

        # ── public exploit code (local mirror, offline, free) ─────────────────
        try:
            exploit = poc.summarise_for_cves(cve_ids, top_n=MAX_TOP_POCS)
        except Exception as exc:
            _err(result, f"{label}: PoC lookup failed: {exc}")
            exploit = {"poc_count": 0, "exploit_available": False,
                       "cves_with_pocs": [], "top_pocs": []}

        # ── ATT&CK context (local STIX + RAG, offline) ────────────────────────
        # Keyed on the plugin family and name rather than a CVE: ATT&CK maps
        # techniques to software and behaviour, not to individual CVEs, so a
        # per-CVE lookup would return nothing for almost every finding.
        mitre: List[Dict[str, Any]] = []
        query = " ".join(str(props.get(k) or "") for k in ("family", "name")).strip()
        if query:
            if query in mitre_memo:
                mitre = mitre_memo[query]
            else:
                try:
                    mitre = engine.map_tech_to_mitre(query, limit=MAX_MITRE_PER_VULN)
                except Exception as exc:
                    _err(result, f"{label}: MITRE lookup failed: {exc}")
                mitre_memo[query] = mitre

        # ── NVD detail (network, opt-in — see the module docstring) ───────────
        nvd_score = None
        nvd_severity = ""
        if include_nvd and cve_ids:
            try:
                detail = engine.cve_client.get_cve(cve_ids[0])
                # cve_client nests the metric: {"cvss": {"version", "base_score",
                # "severity", "vector"}}. Reading detail["base_score"] silently
                # yields None on every CVE.
                cvss = (detail or {}).get("cvss") or {}
                nvd_score = cvss.get("base_score")
                nvd_severity = str(cvss.get("severity") or "")
            except Exception as exc:
                _err(result, f"{label}: NVD lookup failed: {exc}")

        # ── recomputed priority ──────────────────────────────────────────────
        # This is the point of the pass: the ingest-time score could not know
        # whether working exploit code exists, and that is exactly what decides
        # between two findings of the same severity.
        priority = compute_priority(severity, host_count, frameworks,
                                    poc_count=exploit["poc_count"])

        patch: Dict[str, Any] = {
            "poc_count": exploit["poc_count"],
            "exploit_available": exploit["exploit_available"],
            "top_pocs": json.dumps(exploit["top_pocs"]),
            "cves_with_pocs": json.dumps(exploit["cves_with_pocs"]),
            # Both key spellings on purpose. The system prompt and the OWUI tools
            # read `technique_id`; the frontend's cards read `m.id`. Emitting one
            # would silently render blank tags in whichever surface used the other.
            "mitre_techniques": json.dumps([
                {
                    "technique_id": m.get("technique_id"),
                    "id": m.get("technique_id"),
                    "name": m.get("name"),
                }
                for m in mitre
            ]),
            "priority_score": priority,
            "priority_tier": priority_tier(priority),
            "context_enriched_at": stamp,
        }
        if nvd_score is not None:
            patch["nvd_cvss3_base_score"] = nvd_score
        if nvd_severity:
            patch["nvd_severity"] = nvd_severity

        seen_cves.update(cve_ids)
        if cve_ids:
            result["nodes_with_cves"] += 1
        if exploit["exploit_available"]:
            result["nodes_with_exploits"] += 1
        if len(result["samples"]) < 5:
            result["samples"].append({
                "node": label,
                "severity": severity,
                "cve_count": len(cve_ids),
                "poc_count": patch["poc_count"],
                "priority_score": priority,
            })

        if dry_run:
            result["nodes_enriched"] += 1
            continue

        try:
            fc.edit_node(node["id"], _np(patch), sketch_id=sid)
            result["nodes_enriched"] += 1
        except Exception as exc:
            _err(result, f"{label}: write failed: {exc}")

    result["cve_ids"] = sorted(seen_cves)
    if len(nodes) > limit:
        # Never let a capped pass read as a complete one.
        result["errors"].append(
            f"capped at NESSUS_CONTEXT_MAX_NODES={limit} of {len(nodes)} "
            f"vulnerability nodes; raise the limit or re-run to cover the rest"
        )
    return result


# ── Pass 2: roll the findings up onto the hosts ───────────────────────────────

def rollup_hosts(sketch_id: str = "", dry_run: bool = False) -> Dict[str, Any]:
    """
    Recompute each scanned host's severity counts, risk score and CVE exposure
    from the HAS_VULNERABILITY edges actually in the graph.

    Deliberately re-derived from the graph rather than trusted from the upload:
    a host accumulates findings across several scans and several reports, and the
    numbers nessus_parser wrote describe one file. This is the only place the
    per-host totals are true for the whole campaign.
    """
    sid = sketch_id or fc.resolve_campaign_sketch()
    result: Dict[str, Any] = {
        "sketch_id": sid,
        "dry_run": dry_run,
        "hosts_seen": 0,
        "hosts_updated": 0,
        "findings_seen": 0,
        "errors": [],
    }

    try:
        vulns = fc.get_nodes_by_type(
            VULN_LABELS, sketch_id=sid,
            properties=["plugin_id", "name", "severity", "cve_ids",
                        "priority_score", "exploit_available", "poc_count"],
        )
    except Exception as exc:
        result["errors"].append(f"vulnerability fetch failed: {exc}")
        return result

    by_id: Dict[str, Dict[str, Any]] = {}
    for node in vulns:
        props = node.get("nodeProperties") or {}
        severity = str(props.get("severity") or "info").lower()
        by_id[node["id"]] = {
            "label": node.get("nodeLabel") or "",
            "plugin_id": str(props.get("plugin_id") or ""),
            "name": str(props.get("name") or ""),
            "severity": severity if severity in SEVERITY_RANK else "info",
            "cve_ids": _as_list(props.get("cve_ids")),
            "priority_score": _int(props.get("priority_score")),
            "exploit_available": bool(props.get("exploit_available")),
            "poc_count": _int(props.get("poc_count")),
        }

    try:
        # Deliberately NOT anchored with target_label: that parameter takes one
        # label, and the findings can carry either casing (see VULN_LABELS).
        # HAS_VULNERABILITY is written by nothing else, so the relationship type
        # is already the whole filter, and both endpoints are sketch-scoped.
        edges = fc.get_edges_by_type(
            "HAS_VULNERABILITY", sketch_id=sid, resolve_endpoints=True,
        )
    except Exception as exc:
        result["errors"].append(f"finding-edge fetch failed: {exc}")
        return result

    hosts: Dict[str, Dict[str, Any]] = {}
    for edge in edges:
        vuln = by_id.get(edge.get("target") or "")
        if not vuln:
            continue
        result["findings_seen"] += 1
        host_id = edge.get("source") or ""
        host = hosts.get(host_id)
        if host is None:
            host = hosts[host_id] = {
                "label": edge.get("source_label") or "",
                "counts": {s: 0 for s in SEVERITY_ORDER},
                "score": 0,
                "cves": set(),
                "exploitable": 0,
                "findings": [],
            }
        host["counts"][vuln["severity"]] += 1
        host["score"] += SEVERITY_WEIGHT.get(vuln["severity"], 0)
        host["cves"].update(vuln["cve_ids"])
        if vuln["exploit_available"]:
            host["exploitable"] += 1
        host["findings"].append({
            "plugin_id": vuln["plugin_id"],
            "name": vuln["name"] or vuln["label"],
            "severity": vuln["severity"],
            "priority_score": vuln["priority_score"],
            "exploit_available": vuln["exploit_available"],
            "poc_count": vuln["poc_count"],
            "cves": vuln["cve_ids"][:5],
        })

    result["hosts_seen"] = len(hosts)
    stamp = _stamp()

    for host_id, host in hosts.items():
        counts = host["counts"]
        host["findings"].sort(key=lambda f: (-f["priority_score"],
                                             -SEVERITY_RANK.get(f["severity"], 0)))
        # Public exploit code is worth more than another medium: an exploitable
        # finding is work someone has already done for you. Capped so a host with
        # forty exploitable low findings cannot outrank one with a critical.
        score = host["score"] + min(host["exploitable"] * 5, 25)
        patch = {
            "nessus_scanned": True,
            "nessus_finding_count": sum(counts[s] for s in SEVERITY_ORDER
                                        if s != "info"),
            "nessus_critical_count": counts["critical"],
            "nessus_high_count": counts["high"],
            "nessus_medium_count": counts["medium"],
            "nessus_low_count": counts["low"],
            "nessus_risk_score": score,
            # Named to drop straight into
            # tech_context_engine.compute_composite_risk(cve_exposure=…,
            # exploitable_cve_count=…).
            "nessus_cve_exposure": len(host["cves"]),
            "nessus_exploitable_findings": host["exploitable"],
            "nessus_top_findings": json.dumps(
                host["findings"][:MAX_TOP_FINDINGS_PER_HOST]),
            "nessus_context_at": stamp,
        }
        if dry_run:
            result["hosts_updated"] += 1
            continue
        try:
            fc.edit_node(host_id, _np(patch), sketch_id=sid)
            result["hosts_updated"] += 1
        except Exception as exc:
            _err(result, f"{host['label'] or host_id}: host write failed: {exc}")

    return result


# ── Campaign-level summary (what the UI and the LLM read) ─────────────────────

def summarise(sketch_id: str = "", top_n: int = 25) -> Dict[str, Any]:
    """
    The campaign's vulnerability picture, read straight from the graph.

    Serves the Tech Intel tab's Vulnerability Findings panel and the
    spotter_vulnerabilities LLM tool, so both see exactly the same numbers.
    """
    sid = sketch_id or fc.resolve_campaign_sketch()
    out: Dict[str, Any] = {
        "sketch_id": sid,
        "scanned": False,
        "total_findings": 0,
        "total_hosts": 0,
        "severity_counts": {s: 0 for s in SEVERITY_ORDER},
        "cve_count": 0,
        "exploitable_findings": 0,
        "contextualized": 0,
        "top_findings": [],
        "top_hosts": [],
        "poc_mirror": {},
        "errors": [],
    }

    try:
        out["poc_mirror"] = PoCClient().mirror_status()
    except Exception as exc:
        out["poc_mirror"] = {"error": str(exc), "available": False}

    try:
        vulns = fc.get_nodes_by_type(
            VULN_LABELS, sketch_id=sid,
            properties=["plugin_id", "name", "family", "severity", "cve_ids",
                        "priority_score", "priority_tier", "affected_host_count",
                        "exploit_available", "exploit_frameworks", "poc_count",
                        "top_pocs", "mitre_techniques", "synopsis", "solution",
                        "cvss3_base_score", "context_enriched_at"],
        )
    except Exception as exc:
        out["errors"].append(f"vulnerability fetch failed: {exc}")
        return out

    all_cves: set = set()
    rows: List[Dict[str, Any]] = []
    for node in vulns:
        props = node.get("nodeProperties") or {}
        severity = str(props.get("severity") or "info").lower()
        if severity not in out["severity_counts"]:
            severity = "info"
        out["severity_counts"][severity] += 1
        cves = _as_list(props.get("cve_ids"))
        all_cves.update(cves)
        if props.get("exploit_available") or _as_list(props.get("exploit_frameworks")):
            out["exploitable_findings"] += 1
        if props.get("context_enriched_at"):
            out["contextualized"] += 1
        rows.append({
            "plugin_id": str(props.get("plugin_id") or ""),
            "name": str(props.get("name") or node.get("nodeLabel") or ""),
            "family": str(props.get("family") or ""),
            "severity": severity,
            "priority_score": _int(props.get("priority_score")),
            "priority_tier": str(props.get("priority_tier") or ""),
            "hosts": _int(props.get("affected_host_count")),
            "cves": cves[:10],
            "cve_count": len(cves),
            "cvss3": props.get("cvss3_base_score"),
            "exploit_available": bool(props.get("exploit_available")),
            "exploit_frameworks": _as_list(props.get("exploit_frameworks")),
            "poc_count": _int(props.get("poc_count")),
            "top_pocs": _json_prop(props.get("top_pocs")),
            "mitre_techniques": _json_prop(props.get("mitre_techniques")),
            "synopsis": str(props.get("synopsis") or ""),
            "solution": str(props.get("solution") or ""),
        })

    out["scanned"] = bool(rows)
    out["total_findings"] = len(rows)
    out["cve_count"] = len(all_cves)
    rows.sort(key=lambda r: (-r["priority_score"],
                             -SEVERITY_RANK.get(r["severity"], 0),
                             -r["hosts"]))
    out["top_findings"] = rows[:top_n]

    try:
        hosts = fc.get_nodes_by_type(
            HOST_LABELS, sketch_id=sid,
            properties=["nessus_scanned", "nessus_risk_score",
                        "nessus_critical_count", "nessus_high_count",
                        "nessus_medium_count", "nessus_low_count",
                        "nessus_cve_exposure", "nessus_exploitable_findings",
                        "nessus_os", "nessus_top_findings", "nessus_scan_date"],
        )
    except Exception as exc:
        out["errors"].append(f"host fetch failed: {exc}")
        return out

    host_rows = []
    seen_hosts: set = set()
    for node in hosts:
        props = node.get("nodeProperties") or {}
        if not props.get("nessus_scanned"):
            continue
        # HOST_LABELS asks for several spellings of the same two types; a node
        # carrying more than one would otherwise be counted twice.
        if node.get("id") in seen_hosts:
            continue
        seen_hosts.add(node.get("id"))
        host_rows.append({
            "host": node.get("nodeLabel") or "",
            "node_type": (node.get("nodeType") or "").lower(),
            "risk_score": _int(props.get("nessus_risk_score")),
            "critical": _int(props.get("nessus_critical_count")),
            "high": _int(props.get("nessus_high_count")),
            "medium": _int(props.get("nessus_medium_count")),
            "low": _int(props.get("nessus_low_count")),
            "cve_exposure": _int(props.get("nessus_cve_exposure")),
            "exploitable_findings": _int(props.get("nessus_exploitable_findings")),
            "os": str(props.get("nessus_os") or ""),
            "scan_date": str(props.get("nessus_scan_date") or ""),
            "top_findings": _json_prop(props.get("nessus_top_findings")),
        })
    host_rows.sort(key=lambda h: (-h["risk_score"], -h["critical"], -h["high"]))
    out["total_hosts"] = len(host_rows)
    out["top_hosts"] = host_rows[:top_n]

    # ── Empty-state diagnosis ─────────────────────────────────────────────────
    # An empty panel has three causes that need three different answers, and the
    # old message assumed the rarest one (unregistered type) for all of them —
    # sending an operator to register a type that is already registered when the
    # real story was simply "the scan had no rated findings". The signals are all
    # in hand: how many Nessus-scanned hosts landed, and how many RATED findings
    # those hosts counted *at ingest* (nessus_parser writes the per-severity host
    # counts straight from the CSV, before any Vulnerability node is written — so
    # a non-zero count with zero nodes means the nodes were dropped, not that the
    # scan was clean). empty_kind is the machine-readable form; empty_reason is
    # what the panel shows.
    if not out["total_findings"]:
        rated_on_hosts = sum(h["critical"] + h["high"] + h["medium"] + h["low"]
                             for h in host_rows)
        if not out["total_hosts"]:
            out["empty_kind"] = "no_data"
            out["empty_reason"] = (
                "No Nessus data in this campaign yet — upload a Nessus CSV on the "
                "Ingest tab.")
        elif rated_on_hosts:
            out["empty_kind"] = "findings_dropped"
            out["empty_reason"] = (
                "%d Nessus-scanned host(s) recorded %d rated finding(s), but no "
                "Vulnerability nodes exist — the finding nodes were dropped on "
                "ingest. This almost always means the Vulnerability custom type is "
                "not registered: run scripts/register_nessus_type.py --apply and "
                "re-upload the report." % (out["total_hosts"], rated_on_hosts))
        else:
            out["empty_kind"] = "all_informational"
            out["empty_reason"] = (
                "A Nessus scan was ingested (%d host(s)) but it contained no rated "
                "findings — every plugin was informational (severity None). Host "
                "facts, OS and CPEs still landed; browse them on the Tech Intel "
                "tab. To keep informational plugins as Vulnerability nodes too, "
                "re-upload with SPOTTER_NESSUS_INCLUDE_INFO=1." % out["total_hosts"])
    return out


def _json_prop(raw: Any) -> List[Dict[str, Any]]:
    """Decode a JSON-encoded list property, tolerating an already-decoded one."""
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, str) and raw.strip().startswith("["):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return [r for r in parsed if isinstance(r, dict)]
    return []


# ── Orchestration ─────────────────────────────────────────────────────────────

def run(sketch_id: str = "", limit: Optional[int] = None, dry_run: bool = False,
        include_nvd: bool = False) -> Dict[str, Any]:
    """Both passes plus the summary, as one result. What WF25 calls."""
    sid = sketch_id or fc.resolve_campaign_sketch()
    steps: Dict[str, Any] = {}

    ctx = contextualize_vulnerabilities(
        sketch_id=sid, limit=limit, dry_run=dry_run, include_nvd=include_nvd)
    steps["contextualize"] = {k: v for k, v in ctx.items() if k != "cve_ids"}

    roll = rollup_hosts(sketch_id=sid, dry_run=dry_run)
    steps["rollup"] = roll

    errors = list(ctx.get("errors") or []) + list(roll.get("errors") or [])
    out: Dict[str, Any] = {
        "ok": not errors,
        "sketch_id": sid,
        "dry_run": dry_run,
        "steps": steps,
        "cve_ids": ctx.get("cve_ids") or [],
        "errors": errors,
    }

    mirror = ctx.get("poc_mirror") or {}
    out["summary"] = (
        "%s of %s findings contextualized; %s with public exploit code; "
        "%s hosts rolled up"
        % (ctx.get("nodes_enriched", 0), ctx.get("nodes_seen", 0),
           ctx.get("nodes_with_exploits", 0), roll.get("hosts_updated", 0))
    )
    if not ctx.get("nodes_seen"):
        out["summary"] += (
            " | no Vulnerability nodes in this sketch — ingest a Nessus CSV on "
            "the Ingest tab first, and check scripts/register_nessus_type.py "
            "has been applied"
        )
    if mirror.get("stale"):
        out["summary"] += (
            " | WARNING: PoC mirror is stale (age %s d) — run "
            "scripts/sync_poc_mirror.py; absence of exploit code is not "
            "evidence none exists" % mirror.get("age_days")
        )
    elif mirror.get("available") is False:
        out["summary"] += (
            " | WARNING: PoC mirror is not present — every finding will read as "
            "'no public exploit', which is not the same as there being none. "
            "Run scripts/sync_poc_mirror.py on the host."
        )
    return out


def verify_context(sketch_id: str = "", sample: int = 5) -> Dict[str, Any]:
    """
    Read contextualized nodes back out of the graph.

    Exists because edit_node reports success whether or not the keys landed
    somewhere a reader looks: the only proof the namespace was right is a
    read-back through the same path the UI and the LLM tool use.
    """
    sid = sketch_id or fc.resolve_campaign_sketch()
    nodes = fc.get_nodes_by_type(
        VULN_LABELS, sketch_id=sid,
        properties=["plugin_id", "severity", "poc_count", "exploit_available",
                    "priority_score", "context_enriched_at"],
    )
    enriched = [n for n in nodes
                if (n.get("nodeProperties") or {}).get("context_enriched_at")]
    hosts = fc.get_nodes_by_type(
        HOST_LABELS, sketch_id=sid,
        properties=["nessus_risk_score", "nessus_cve_exposure",
                    "nessus_context_at"],
    )
    rolled = [h for h in hosts
              if (h.get("nodeProperties") or {}).get("nessus_context_at")]
    return {
        "sketch_id": sid,
        "vulnerability_nodes": len(nodes),
        "contextualized_nodes": len(enriched),
        "hosts_rolled_up": len(rolled),
        "sample": [n.get("nodeProperties") for n in enriched[:sample]],
        "host_sample": [h.get("nodeProperties") for h in rolled[:sample]],
    }


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sketch", default="",
                    help="sketch id (default: resolve_campaign_sketch)")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--with-nvd", action="store_true",
                    help="also look each finding's first CVE up at NVD "
                         "(network; publishes which CVEs interest you)")
    ap.add_argument("--summary", action="store_true",
                    help="print the campaign vulnerability summary and exit")
    ap.add_argument("--verify", action="store_true",
                    help="read contextualized nodes back and exit")
    args = ap.parse_args()

    if args.summary:
        print(json.dumps(summarise(args.sketch), indent=2, default=str))
        return 0
    if args.verify:
        print(json.dumps(verify_context(args.sketch), indent=2, default=str))
        return 0

    out = run(sketch_id=args.sketch, limit=args.limit, dry_run=args.dry_run,
              include_nvd=args.with_nvd)
    print(json.dumps(out, indent=2, default=str))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
