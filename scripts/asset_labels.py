#!/usr/bin/env python3
"""
asset_labels.py — Canonical node-label, edge-label and property vocabulary for
SPOTTER's asset layer.

WHY THIS EXISTS
---------------
Six independent copies of the same technology/service label set had to be kept in
sync by hand:

    scripts/tech_enricher.py                      TECH_LABELS / READ_PROPS
    n8n-workflows/04-attack-path-analyzer.json    Fetch Full Graph, Score Attack Paths
    n8n-workflows/12-tech-inventory.json          Build Tech Inventory + Narratives
    llm/tools/attack_path_tool.py                 the exploit-index Cypher
    llm/tools/tech_context_tool.py                get_attack_surface_for_host
    llm/tools/technology_tool.py                  the inventory subsets
    scripts/smoke_workflow04.py                   a hand-copy of all three lists

They had already drifted twice, and neither failure raises — both return clean
zeros, which reads as "no exploits exist":

  * WF12's fetch list omitted 'Technology' (PascalCase), so every Technology node
    written by fc.add_node — WF01, WF21, WF28 and now WF13's perimeter recon —
    was invisible to the Tech Intel tab, leaving its CVE-count and
    vulnerable-tech blocks dead.
  * llm/tools/attack_path_tool.py filtered `nodeType IN ['Technology','Service']`
    with no toLower(). On a graph holding 141 lowercase `technology` nodes and 38
    PascalCase `Service` nodes it saw 3 of the 65 exploit-bearing nodes, so the
    chat tool and WF04 disagreed about the same path's score.

scripts/high_value_tech.py is the precedent: one definition, mirrored only where a
different runtime needs it, and a CI check that fails if anything re-declares it
inline. check_asset_label_catalog() in scripts/check_workflow_regressions.py is
this module's equivalent.

CASING
------
Built-in Flowsint types are lowercase ("technology", "service", "individual");
SPOTTER's registered custom types are PascalCase ("Technology", "Service",
"CloudAsset", "WebAsset", "Subdomain"). Which spelling a node ends up with is
decided by its WRITER, not its type: fc.add_node preserves the case it is given,
while batch_import writes through /api/import/execute, which lowercases the type.
Neo4j labels are case-sensitive and get_nodes_by_type interpolates the label
straight into `MATCH (n:{label} ...)`, so a graph assembled from several ingest
paths genuinely carries both. A reader that drops one halves its own coverage and
reports success.

IMPORTING THIS FROM AN n8n CODE NODE
------------------------------------
`asset_labels` MUST be listed in N8N_RUNNERS_EXTERNAL_ALLOW in the `env-overrides`
of the python runner in deployment/n8n-task-runners.json, or `import asset_labels`
fails the WHOLE node with a security violation before line 1 runs. That is the trap
WF12 documents around its cobalt_normalizer import: the module defining
PROCESS_TECH_MAP was not allowlisted, so WF12 reaches the identical callable
through a module that was. Do not repeat that indirection here — allowlist it.

The allowlist is read from the file bind-mounted at /etc/n8n-task-runners.json.
Two copies exist on this host; confirm which is mounted with
`docker inspect spotter-n8n-runners` before trusting an edit, and confirm the value
reached the runner PROCESS (/proc/<pid>/environ) rather than only the file — see
check_runner_config_mount_is_pinned.

The runner's sandbox restrictions apply to a code node's own source, not to an
allowlisted module: a code node cannot call getattr()/hasattr(), but this module
runs as ordinary Python in the runner's venv, so the comprehensions below are fine.
high_value_tech.py already does the same in production.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Tuple


# ── The exploit-carrier layer ────────────────────────────────────────────────

# The canonical lowercase spellings, for readers that need the string itself
# rather than a membership test.
TECHNOLOGY_TYPE = "technology"
SERVICE_TYPE = "service"

TECHNOLOGY_LABELS: Tuple[str, ...] = (TECHNOLOGY_TYPE, "Technology")
SERVICE_LABELS: Tuple[str, ...] = (SERVICE_TYPE, "Service")

# Kept as one ordered tuple because get_nodes_by_type returns labels in list
# order, and callers that slice the result (tech_enricher's nodes[:limit]) depend
# on that order being stable.
TECH_LABELS: Tuple[str, ...] = TECHNOLOGY_LABELS + SERVICE_LABELS

# For readers that dispatch on (nodeType or '').lower() rather than fetching by
# label. WF12 genuinely needs the two apart — it keeps technology_nodes and
# service_nodes as separate dicts and tags its output rows with which one a
# component came from.
TECHNOLOGY_TYPES_LOWER = frozenset(t.lower() for t in TECHNOLOGY_LABELS)
SERVICE_TYPES_LOWER = frozenset(t.lower() for t in SERVICE_LABELS)
TECH_TYPES_LOWER = TECHNOLOGY_TYPES_LOWER | SERVICE_TYPES_LOWER

# Edges that mean "this asset RUNS or EXPOSES that software".
#
# MANAGES is deliberately absent, and so is HAS_CLOUD_ASSET.
#
# Ownership is not hosting: WF13 links an apex WebAsset to whoever's whois email
# or name matches it, and every CDN edge node answering for that domain hangs off
# that same asset, so inheriting exploit facts across MANAGES would charge a
# person with Akamai's and CloudFlare's CVEs. See issues.md, "Confirmed
# limitations" item 2.
#
# HAS_CLOUD_ASSET is out because a public bucket is not a CVE, and routing it
# through the carrier graph would spend NVD quota keyword-matching bucket names.
# Cloud exposure is its own bounded term in WF04.
#
# Both exclusions used to be pinned by a require_absent() against WF04's own
# source. Centralizing moved the literal out of that file, so the text pin would
# keep passing while guarding nothing — check_asset_label_catalog now asserts
# them on these VALUES instead, which is strictly stronger.
TECH_EDGES: Tuple[str, ...] = (
    "USES_TECH", "EXPOSES_SERVICE", "EXPOSES", "IMPLEMENTED_IN",
)
CARRIER_LABELS = frozenset(TECH_EDGES)

# Projected so a wide label does not ship properties the caller will discard.
#
# TECH_READ_PROPS is the ENRICHMENT projection (scripts/tech_enricher.py): what
# you need in order to FIND CVEs. Both `cpe` (singular, written by
# upload_router._parse_nmap) and `cpes` (a JSON array, written by WF13's
# domain-recon Service nodes) are read — two writers' spellings of one idea, and
# reading only one halves precise-match coverage.
TECH_READ_PROPS: Tuple[str, ...] = (
    "name", "product", "vendor", "version", "cpe", "cpes", "category",
    "is_high_value", "source", "vulns",
)

# TECH_SCORING_PROPS is the SCORING projection (WF04's Fetch Full Graph and
# llm/tools/attack_path_tool.py): what you need in order to WEIGH CVEs already
# found.
#
# These two lists are NOT interchangeable. Passing the enrichment projection to
# WF04 drops exploit_available / cves / cve_match_basis, so every exploit bonus
# silently becomes 0 — indistinguishable from an estate with no public exploits.
# check_asset_label_catalog asserts they stay distinct.
TECH_SCORING_PROPS: Tuple[str, ...] = (
    "name", "product", "version", "exploit_available", "poc_count",
    "cve_count", "cves", "cve_match_basis", "top_pocs", "source",
)


# ── The cloud-exposure layer ─────────────────────────────────────────────────
# Written by WF13's domain recon (passive CNAME/hostname match, then the
# anonymous list-check probe upserting the same node in place) and by
# scripts/cloudschism_parser.py. Both casings for the reason in the module
# docstring: WF13 writes through fc.add_node (PascalCase), cloudschism_parser
# through batch_import (lowercased).

CLOUD_LABELS: Tuple[str, ...] = ("CloudAsset", "cloudasset")
CLOUD_TYPES_LOWER = frozenset(t.lower() for t in CLOUD_LABELS)

# HAS_CLOUD_ASSET is the only edge here, and it is NOT a carrier — see TECH_EDGES.
# WebAsset -> CloudAsset (WF13) and Organization -> CloudAsset (cloudschism).
CLOUD_EDGES: Tuple[str, ...] = ("HAS_CLOUD_ASSET",)

# WF13 writes the first group; cloudschism_parser writes the second. A reader that
# knows only one shape is silently zero on the other source — the same fail-green
# scripts/spotter_notify.py guards against by reading several exposure keys.
#
# NOTE: WF13 writes `public` and `listable`. It has never written `is_open`,
# whatever a reader may hope for.
CLOUD_PROPS: Tuple[str, ...] = (
    "provider", "service", "bucket", "endpoint", "hostname", "url", "domain",
    "region", "access", "public", "listable", "object_count", "total_size",
    "exposure_score", "sensitive_categories", "sensitive_hits",
    "discovery_method", "source",
    # cloudschism_parser shapes
    "anonymous_reachable", "allow_blob_public_access", "public_network_access",
    "authentication_state", "exposure_type", "resource_id", "account_id",
)


# ── The external web layer ───────────────────────────────────────────────────
# The apex WebAsset and its subdomains. Present so readers that want "every label
# the asset layer can present" have one list; deliberately NOT in TECH_LABELS,
# because a WebAsset must stay outside the carrier layer so it TERMINATES WF04's
# two-hop walk instead of relaying a CDN's CVEs onward.
WEB_LABELS: Tuple[str, ...] = ("WebAsset", "Subdomain")
WEB_TYPES_LOWER = frozenset(t.lower() for t in WEB_LABELS)

ASSET_LABELS: Tuple[str, ...] = TECH_LABELS + CLOUD_LABELS + WEB_LABELS


# ── Helpers ──────────────────────────────────────────────────────────────────

def is_tech_type(node_type: str) -> bool:
    """True for a Technology or Service node, whatever its casing."""
    return str(node_type or "").strip().lower() in TECH_TYPES_LOWER


def is_technology_type(node_type: str) -> bool:
    """True for a Technology node only (not a Service), whatever its casing."""
    return str(node_type or "").strip().lower() in TECHNOLOGY_TYPES_LOWER


def is_service_type(node_type: str) -> bool:
    """True for a Service node only (not a Technology), whatever its casing."""
    return str(node_type or "").strip().lower() in SERVICE_TYPES_LOWER


def is_cloud_type(node_type: str) -> bool:
    """True for a CloudAsset node, whatever its casing."""
    return str(node_type or "").strip().lower() in CLOUD_TYPES_LOWER


# Same shape flowsint_client._LABEL_RE enforces, for the same reason.
_REL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def rel_pattern(edges: Iterable[str] = TECH_EDGES) -> str:
    """`USES_TECH|EXPOSES_SERVICE|...` for a Cypher relationship pattern.

    Relationship types cannot be parameterized in Cypher, so this is the one
    place the vocabulary gets interpolated into a query. Validated on shape
    anyway — the way flowsint_client._quote_label does — so a future edge name
    carrying a backtick or a quote fails loudly here rather than becoming an
    injection point.
    """
    out: List[str] = []
    for edge in edges:
        name = str(edge or "").strip()
        if not _REL_RE.match(name):
            raise ValueError(f"Unsafe Neo4j relationship type: {edge!r}")
        out.append(name)
    if not out:
        raise ValueError("rel_pattern() needs at least one relationship type")
    return "|".join(out)
