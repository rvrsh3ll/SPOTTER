"""
nessus_parser.py — Tenable Nessus vulnerability scan report parser.

Turns a Nessus **CSV export** or the **.nessus XML export** into SPOTTER's
canonical entity / relationship lists — the same shape `sharphound_parser.py`
and `pingcastle_parser.py` produce — so scan findings land on the *same* graph
nodes the AD and network data already created instead of duplicating them.

Accepted inputs
───────────────
    Nessus Professional / Essentials   Export → CSV, or the .nessus XML export
    Tenable Security Center (.sc)      vulnerability export CSV
    Tenable Vulnerability Management   findings export CSV

The three CSV dialects are the same table under different column names; see
COLUMN_ALIASES. A header is matched by *meaning*, not position, so a report
exported with a subset of columns still parses — only `Plugin ID` and a host
column are structurally required.

The .nessus XML export carries the same findings as the CSV, just un-flattened:
one ``<ReportItem>`` is exactly one CSV row (plugin × host × port). `_nessus_xml_
reader` streams it (ElementTree.iterparse, clearing each element as it closes so
a multi-gigabyte export does not have to fit in RAM as a tree) and re-presents
each ReportItem as a canonical CSV-column row, which then flows through the
*identical* accumulation logic. XML and CSV of the same scan yield the same graph.

Not accepted (reported as a parse error rather than silently ingesting nothing):

    report.html/pdf   the human report, no structured data to lift
    .db / .nessusdb   scanner-internal, not an export format

Why a plugin is a node and a host-finding is an edge
────────────────────────────────────────────────────
A Nessus row is (plugin × host × port). A 500-host scan easily runs to 100k
rows, so one node per row would swamp the graph with objects that all say the
same thing. A plugin *is* the finding — its severity, CVEs, synopsis and fix
are identical wherever it fires — so this parser emits:

    one Vulnerability node per plugin        (deduped across the whole report)
    one HAS_VULNERABILITY edge per host      (carrying that host's ports/output)

which is the same shape PingCastle's ADRisk uses (one node per rule, AFFECTS
edges to the objects that triggered it). Rows for the same host and plugin on
several ports are folded into ONE edge carrying a `ports` list — emitting two
edges would let Neo4j's MERGE collapse them and lose the port data silently.

Merging with SharpHound / PingCastle / nmap
───────────────────────────────────────────
Flowsint MERGEs on ``(node_type, nodeLabel, sketch_id)``, so a host merges with
an existing node only if its label matches *exactly*:

    named host   DC01.CORP.LOCAL   Device, uppercase — SharpHound/PingCastle's
                                   convention, which is the only reason the
                                   three tools share one node
    bare address 10.10.0.11        Ip, verbatim — nmap's convention

When a row carries both an address and a name, both nodes are created and
joined ``Device -[RESOLVES_TO]-> Ip`` (the label and direction nmap already
uses for name → address). Findings attach to the **named** node in that case,
never to both, so a host is never counted twice.

Because Neo4j applies ``SET n += $props``, a value written here *overwrites* the
same key on an already-ingested node. Everything scanner-specific is therefore
namespaced ``nessus_*``. The one bare key this parser will write is
``operating_system``, and only on an ``Ip`` node — a host with no AD identity,
where there is no SharpHound value to clobber. On a Device the OS goes to
``nessus_os`` alone: SharpHound reads the real attribute off the computer
object, a scanner fingerprints it from the outside, and the authoritative one
must win.

Entities produced
─────────────────
    Device         each scanned host known by name
    Ip             each scanned host known by address
    Vulnerability  each plugin that fired   ← custom Flowsint type, see below
    Technology     each CPE the scan resolved (plugin 45590)

Relationships produced
──────────────────────
    Device | Ip  -[HAS_VULNERABILITY]->  Vulnerability
    Device       -[RESOLVES_TO]->        Ip
    Device | Ip  -[USES_TECH]->          Technology

**Vulnerability must be registered in Flowsint before ingesting** — an
unresolvable nodeType makes ``GET /api/sketches/{id}/graph`` return HTTP 500 for
the *whole* sketch, not just that node. Run
``scripts/register_nessus_type.py --apply`` once per install; `upload_router`
refuses to write vulnerability nodes until it is, and imports the hosts and
technologies anyway.

Informational findings
──────────────────────
Roughly two-thirds of a Nessus report is severity `None` — service banners,
enumeration, "SSL certificate information". Those are not findings and ingesting
them buries the ones that are, so they are **skipped by default** and the count
is reported in `rows_skipped_info` rather than quietly dropped. Set
`include_info=True` (or SPOTTER_NESSUS_INCLUDE_INFO=1) to keep them.

A short allowlist of informational plugins is mined for *host facts* regardless
of that setting — OS identification and CPE enumeration are how a scan tells you
what a host runs, and CPEs are what `tech_context_engine.map_cpe_to_cves()` needs
to look a product up precisely instead of guessing from its name.

Secrets policy: Nessus plugin output can contain recovered credentials (default
password checks, SNMP community strings). By design this
parser truncates plugin output and never promotes anything out of it into a
Credential node. Feed such a report to WF11's Titus scan if you want the
credentials extracted deliberately.

Usage:
    python3 scripts/nessus_parser.py scan.csv           # summary to stdout
    python3 scripts/nessus_parser.py scan.nessus        # the XML export, too
    python3 scripts/nessus_parser.py scan.csv --json    # full summary as JSON

    from nessus_parser import parse_bytes, parse_file
    result = parse_bytes(open("scan.csv", "rb").read())  # CSV or .nessus bytes
    result = parse_file("scan.nessus")                   # streams a large .nessus
    nodes, edges = result.to_flowsint_batch()
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# ── Safety limits ─────────────────────────────────────────────────────────────
# An enterprise scan is genuinely large: 5k hosts × 40 findings is 200k rows.
# These caps bound one upload; every one of them reports what it dropped rather
# than truncating silently.

MAX_ROWS = int(os.environ.get("SPOTTER_NESSUS_MAX_ROWS", "300000"))
MAX_HOSTS = int(os.environ.get("SPOTTER_NESSUS_MAX_HOSTS", "20000"))
MAX_PLUGINS = int(os.environ.get("SPOTTER_NESSUS_MAX_PLUGINS", "5000"))
MAX_TECH = int(os.environ.get("SPOTTER_NESSUS_MAX_TECH", "2000"))


def _cap(name: str, fallback: int) -> int:
    """
    Resolve a cap when the parse runs, not when the module is imported.

    The constants above are fixed the first time the n8n task runner imports this
    file and never move again — the runner process is long-lived. A Configuration
    panel override (which WF06/WF25 publish into os.environ before parsing, the
    same way WF14 does for the POC_* knobs) would therefore silently do nothing.
    Reading through here is what makes the panel value actually apply.
    """
    try:
        return max(1, int(str(os.environ.get(name) or fallback).strip()))
    except (TypeError, ValueError):
        return fallback


# Plugin output is free text and can run to tens of kilobytes per row (a full
# certificate chain, a directory listing). It is kept for context, not evidence.
MAX_OUTPUT_CHARS = int(os.environ.get("SPOTTER_NESSUS_MAX_OUTPUT_CHARS", "800"))
MAX_TEXT_CHARS = int(os.environ.get("SPOTTER_NESSUS_MAX_TEXT_CHARS", "2000"))
MAX_CVES_PER_HOST = 300
# Per-host observations embedded on a Vulnerability node. They have to live on the
# node because edge properties do not survive the import (see the host_details
# block in parse_bytes), so this is what bounds one node's size: a plugin firing
# on 500 hosts would otherwise carry half a megabyte of plugin output.
MAX_HOST_DETAILS = int(os.environ.get("SPOTTER_NESSUS_MAX_HOST_DETAILS", "50"))

# Nessus severity `None` rows are informational. Off by default — see the module
# docstring. "1"/"true"/"yes" turn them into first-class Vulnerability nodes.
INCLUDE_INFO_DEFAULT = str(
    os.environ.get("SPOTTER_NESSUS_INCLUDE_INFO", "0")
).strip().lower() in ("1", "true", "yes", "on")

# Node type name registered via scripts/register_nessus_type.py
VULN_NODE_TYPE = "Vulnerability"

SOURCE = "nessus"

# Worse is higher, matching how the rest of SPOTTER bands risk.
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

# Per-finding contribution to a host's nessus_risk_score. Deliberately steep:
# ten mediums are not one critical, and a flat count would say they were.
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}

# Base of the 0-100 priority score. See _priority().
SEVERITY_PRIORITY = {"critical": 80, "high": 60, "medium": 35, "low": 15, "info": 0}

_SEVERITY_NAMES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "low": "low",
    "none": "info",
    "info": "info",
    "informational": "info",
    "information": "info",
}
# Tenable's numeric severity, used by the .sc and Vulnerability Management
# exports in place of a risk word.
_SEVERITY_NUM = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}

# Exploitability columns. Each is "true"/"false" in the Nessus CSV and names a
# framework that ships a working exploit — a materially different proposition
# from a CVE with no public code, and the reason _priority() weights it.
_EXPLOIT_COLUMNS = (
    ("metasploit", "Metasploit"),
    ("core_impact", "Core Impact"),
    ("canvas", "CANVAS"),
    ("elliot", "Elliot"),
    ("d2_elliot", "D2 Elliot"),
)

_TRUE_WORDS = frozenset({"true", "yes", "1", "y"})

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]+\.)+[A-Za-z]{2,}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
# One CPE line from plugin 45590, with its optional human title:
#   cpe:/a:openbsd:openssh:7.4 -> OpenBSD OpenSSH 7.4
#   cpe:2.3:o:microsoft:windows_server_2016
_CPE_LINE_RE = re.compile(
    r"^(cpe:(?:/|2\.3:)[aoh]:[^\s]+?)\s*(?:->\s*(.+?))?\s*$", re.IGNORECASE
)
# "cvss v2.0 base score" / "cvssv3 base score" / "cvss base score" (implicitly v2)
_CVSS_HEADER_RE = re.compile(r"^cvss\s*v?\.?\s*(\d)?(?:\.\d+)?\s*base\s*score$")

# Informational plugins mined for host facts even when info rows are skipped.
PLUGIN_OS_IDENTIFICATION = "11936"
PLUGIN_CPE = "45590"
PLUGIN_HOST_FQDN = "12053"
PLUGIN_NETBIOS = "10150"
FACT_PLUGINS = frozenset({
    PLUGIN_OS_IDENTIFICATION, PLUGIN_CPE, PLUGIN_HOST_FQDN, PLUGIN_NETBIOS,
})


# ── Header mapping ────────────────────────────────────────────────────────────
#
# Canonical field → the header spellings that mean it, normalised (lowercase,
# whitespace collapsed, surrounding quotes stripped). Nessus Pro, Tenable.sc and
# Tenable VM each name these differently; matching on meaning rather than
# position is what lets one parser read all three, and lets a report exported
# with a subset of columns still work.
COLUMN_ALIASES: Dict[str, Tuple[str, ...]] = {
    # Deliberately no bare "id": an inventory CSV with id/host/name columns would
    # otherwise map onto this parser and be read as a scan report.
    "plugin_id":   ("plugin id", "pluginid", "plugin", "plugin_id"),
    "name":        ("name", "plugin name", "pluginname", "vulnerability",
                    "plugin_name", "title"),
    "family":      ("family", "plugin family", "pluginfamily", "plugin_family"),
    "severity":    ("risk", "risk factor", "severity", "risk_factor"),
    # Address-shaped host column.
    "host":        ("host", "ip address", "ipv4 address", "ip", "host ip",
                    "ip_address", "ipv4", "asset ipv4 addresses"),
    # Name-shaped host column.
    "dns_name":    ("dns name", "fqdn", "hostname", "host name", "asset name",
                    "dns_name", "host fqdn"),
    "netbios":     ("netbios name", "netbios", "netbios_name"),
    "mac":         ("mac address", "mac", "mac_address"),
    "protocol":    ("protocol", "proto"),
    "port":        ("port",),
    "cve":         ("cve", "cves", "cve id", "cve_id"),
    "vpr":         ("vpr score", "vpr", "vpr_score"),
    "epss":        ("epss score", "epss", "epss_score"),
    "synopsis":    ("synopsis",),
    "description": ("description",),
    "solution":    ("solution", "steps to remediate"),
    "see_also":    ("see also", "see_also", "cross references", "xref", "xrefs"),
    "output":      ("plugin output", "output", "plugin_output", "plugin text"),
    "state":       ("state", "status", "vulnerability state"),
    "stig":        ("stig severity", "stig_severity"),
    "exploit":     ("exploit?", "exploit", "exploit available",
                    "exploitable", "exploit_available"),
    "exploit_ease": ("exploit ease", "exploitability ease", "exploit_ease"),
    "metasploit":  ("metasploit", "metasploit exploit framework", "in metasploit"),
    "core_impact": ("core impact", "core impact exploit framework"),
    "canvas":      ("canvas", "canvas exploit framework"),
    "elliot":      ("elliot", "elliot exploit framework"),
    "d2_elliot":   ("d2 elliot", "d2elliot"),
    "first_seen":  ("first discovered", "first seen", "first_seen",
                    "first found", "discovery date"),
    "last_seen":   ("last observed", "last seen", "last_seen", "last found"),
    "plugin_date": ("plugin publication date", "plugin modification date"),
    "vuln_date":   ("vuln publication date", "vulnerability publication date"),
}

# A column may only claim one canonical slot, and only the first column that
# claims it wins — Tenable.sc ships both "Plugin" (the id) and "Plugin Name",
# and without this the second would overwrite the first.
_ALIAS_LOOKUP: Dict[str, str] = {}
for _canon, _spellings in COLUMN_ALIASES.items():
    for _sp in _spellings:
        _ALIAS_LOOKUP.setdefault(_sp, _canon)


# ── Value coercion ────────────────────────────────────────────────────────────

def _decode_text(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode("utf-8", errors="replace")


def _norm_header(value: str) -> str:
    """Normalise one header cell to its comparison form."""
    # A BOM survives when the file is UTF-16, or when a tool re-joined a split
    # export, and an invisible character on the first header cell is exactly the
    # kind of thing that makes "Plugin ID" quietly stop matching.
    text = str(value or "").replace("﻿", "").strip().strip('"').strip("'")
    return re.sub(r"\s+", " ", text).lower()


def _clean(value: Any) -> str:
    """Collapse a CSV cell to a single-line string."""
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def _trim(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _float(value: Any) -> Optional[float]:
    try:
        num = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    # Nessus writes an empty cell rather than 0.0 for "no score"; a literal 0.0
    # is meaningful (an informational plugin), so it is kept.
    return num


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in _TRUE_WORDS


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _severity_of(raw: str, cvss: Optional[float]) -> str:
    """
    Normalise a report's severity word / number to SPOTTER's five bands.

    Falls back to the CVSS base score when the export carries no risk column at
    all — some Tenable VM exports do exactly that, and defaulting the whole
    report to "info" would silently discard every finding in it.
    """
    key = str(raw or "").strip().lower()
    if key in _SEVERITY_NAMES:
        return _SEVERITY_NAMES[key]
    if key in _SEVERITY_NUM:
        return _SEVERITY_NUM[key]
    if cvss is None:
        return "info"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _cves_in(value: str) -> List[str]:
    """Every CVE id in a cell, uppercased and de-duplicated in place order."""
    out: List[str] = []
    for match in _CVE_RE.findall(str(value or "")):
        cve = match.upper()
        if cve not in out:
            out.append(cve)
    return out


def _priority(severity: str, host_count: int, exploit_frameworks: List[str],
              poc_count: int = 0) -> int:
    """
    A 0-100 "fix / use this first" score.

    Severity sets the band; breadth, weaponisation and public exploit code move
    within it. Bounded so no single term can dominate: a plugin on 400 hosts is
    not more urgent than one that is remotely exploitable, and 400 PoC repos for
    Log4Shell must not outrank the severity that made it matter.

    `poc_count` is 0 here — the parser has no exploit mirror. scripts/
    nessus_context.py recomputes this with the PoC data attached, which is what
    makes the score move after contextualization.
    """
    score = SEVERITY_PRIORITY.get(severity, 0)
    if score == 0:
        return 0
    score += min(host_count, 20)                 # breadth,        max +20
    if exploit_frameworks:
        score += 15                              # weaponised,     flat +15
    score += min(poc_count * 2, 10)              # public PoC code, max +10
    return min(score, 100)


def _priority_tier(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# Public aliases. scripts/nessus_context.py recomputes the score once the exploit
# mirror has been consulted and MUST use this function, not a second copy of the
# weights — two scoring formulas that drift apart is how a "priority" number
# stops meaning anything.
compute_priority = _priority
priority_tier = _priority_tier


# ── Output dataclasses (mirrors pingcastle_parser / sharphound_parser) ─────────

@dataclass
class ParsedEntity:
    entity_type: str          # Device | Ip | Vulnerability | Technology
    label: str                # display name — also the Flowsint MERGE key
    properties: Dict[str, Any] = field(default_factory=dict)
    temp_id: str = ""         # stitching key before Flowsint IDs are known


@dataclass
class ParsedRelationship:
    source_temp_id: str
    target_temp_id: str
    label: str                # HAS_VULNERABILITY | RESOLVES_TO | USES_TECH
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NessusResult:
    entities: List[ParsedEntity] = field(default_factory=list)
    relationships: List[ParsedRelationship] = field(default_factory=list)
    source_format: str = "csv"
    report_date: str = ""
    rows_total: int = 0
    rows_parsed: int = 0
    rows_skipped_info: int = 0
    rows_skipped_bad: int = 0
    # Scanned hosts, counted from the rows. NOT derived from the entity types: a
    # host known by both name and address gets a Device *and* a companion Ip node
    # joined by RESOLVES_TO, so Device+Ip would report an estate half again as
    # large as the one that was actually scanned.
    hosts_scanned: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    cve_ids: List[str] = field(default_factory=list)
    top_findings: List[Dict[str, Any]] = field(default_factory=list)
    top_hosts: List[Dict[str, Any]] = field(default_factory=list)
    columns_seen: List[str] = field(default_factory=list)
    columns_unmapped: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_flowsint_batch(self) -> Tuple[List[dict], List[dict]]:
        """Convert to the nodes/edges format flowsint_client.batch_import() takes."""
        nodes = []
        for ent in self.entities:
            nodes.append({
                "id": ent.temp_id,
                "entity_type": ent.entity_type,
                "nodeLabel": ent.label,
                # nodeLabel must also sit in data: the Pydantic model carries it and
                # the serializer derives the Neo4j MERGE key from entity.nodeLabel.
                # import_ref = temp_id so batch_import's cross-chunk edge resolver can
                # find this node by the same id its edges reference (from_id/to_id).
                # A large ingest imports nodes in 300-node chunks; an edge whose
                # endpoints straddle two chunks is resolved by nodeProperties.sid /
                # device_id / import_ref, none of which a Nessus node otherwise
                # carries — so without this, every cross-chunk finding edge was
                # silently skipped ("endpoint SID not in graph"). NOT `sid`: that
                # would clobber a merged SharpHound host's real AD SID.
                "data": {**ent.properties, "nodeLabel": ent.label,
                         "label": ent.label, "type": ent.entity_type,
                         "import_ref": ent.temp_id},
                "include": True,
                # node_id must equal id so nodes_mapping_indices resolves edges.
                "node_id": ent.temp_id,
            })
        edges = []
        for rel in self.relationships:
            edges.append({
                "from_id": rel.source_temp_id,
                "to_id": rel.target_temp_id,
                "label": rel.label,
                "data": rel.data,
            })
        return nodes, edges

    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for ent in self.entities:
            by_type[ent.entity_type] = by_type.get(ent.entity_type, 0) + 1
        findings = sum(1 for r in self.relationships
                       if r.label == "HAS_VULNERABILITY")
        return {
            "scanner": SOURCE,
            "source_format": self.source_format,
            "report_date": self.report_date,
            "rows_total": self.rows_total,
            "rows_parsed": self.rows_parsed,
            "rows_skipped_info": self.rows_skipped_info,
            "rows_skipped_bad": self.rows_skipped_bad,
            "hosts": self.hosts_scanned,
            "plugins": by_type.get(VULN_NODE_TYPE, 0),
            "technologies": by_type.get("Technology", 0),
            "findings": findings,
            "severity_counts": dict(self.severity_counts),
            "cve_count": len(self.cve_ids),
            "exploitable_findings": sum(
                1 for f in self.top_findings if f.get("exploit_frameworks")),
            "top_findings": self.top_findings[:20],
            "top_hosts": self.top_hosts[:20],
            "entities": len(self.entities),
            "entities_by_type": by_type,
            "relationships": len(self.relationships),
            "columns_unmapped": self.columns_unmapped,
            "errors": self.errors,
        }


# ── Entity accumulator ────────────────────────────────────────────────────────

class _Builder:
    """Collects entities/relationships, de-duplicating on temp_id."""

    def __init__(self) -> None:
        self.by_tid: Dict[str, ParsedEntity] = {}
        self.order: List[str] = []
        self.relationships: List[ParsedRelationship] = []
        self.errors: List[str] = []

    def upsert(self, entity_type: str, label: str, temp_id: str,
               properties: Dict[str, Any]) -> str:
        props = {k: v for k, v in properties.items() if v not in ("", None, [])}
        existing = self.by_tid.get(temp_id)
        if existing is None:
            self.by_tid[temp_id] = ParsedEntity(entity_type, label, props, temp_id)
            self.order.append(temp_id)
        else:
            for key, val in props.items():
                if isinstance(val, list) and isinstance(existing.properties.get(key), list):
                    merged = list(existing.properties[key])
                    merged.extend(v for v in val if v not in merged)
                    existing.properties[key] = merged
                else:
                    existing.properties[key] = val
        return temp_id

    def relate(self, source: str, target: str, label: str,
               data: Optional[Dict[str, Any]] = None) -> None:
        if source and target and source != target:
            self.relationships.append(
                ParsedRelationship(source, target, label, data or {})
            )

    def entities(self) -> List[ParsedEntity]:
        return [self.by_tid[tid] for tid in self.order]


# ── Report detection ──────────────────────────────────────────────────────────

def is_nessus_xml(data: bytes, filename: str = "") -> bool:
    """True for the .nessus XML export, which this parser does NOT ingest."""
    name = os.path.basename(str(filename or "")).lower()
    if name.endswith(".nessus"):
        return True
    head = _decode_text(data[:4096]).lower()
    return "<nessusclientdata" in head


def header_matches(data: bytes, strict: bool = True) -> bool:
    """
    Does the first row look like a Nessus export header?

    Deliberately structural rather than name-based: an operator renames the
    export far more often than Tenable renames a column, and "nessus" in a
    filename is not evidence of anything.

    strict=True (detection) needs a plugin identifier *and* a host identifier
    *and* one of the columns no other CSV in this pipeline has — synopsis,
    solution, plugin output, a risk column, a family or a CVE list. Two of the
    three is not enough: "plugin,host" alone would swallow unrelated inventory
    CSVs and feed them to this parser.

    strict=False (hint corroboration) drops the third test. The operator has
    already said in the Context field that this is a vulnerability scan, so a
    report exported with a trimmed column set should be taken at their word —
    but a file with no plugin column at all still cannot be one.
    """
    if not data:
        return False
    head = _decode_text(data[:65536])
    line = ""
    for candidate in head.splitlines():
        if candidate.strip():
            line = candidate
            break
    if not line or "," not in line:
        return False

    try:
        cells = next(csv.reader(io.StringIO(line)))
    except (csv.Error, StopIteration):
        return False

    mapped = {_ALIAS_LOOKUP.get(_norm_header(c), "") for c in cells}
    mapped.discard("")
    if "plugin_id" not in mapped or not (mapped & {"host", "dns_name"}):
        return False
    if not strict:
        return True
    return bool(mapped & {"synopsis", "solution", "output", "severity",
                          "family", "cve"})


def is_nessus(data: bytes, filename: str = "") -> bool:
    """Cheap sniff used by upload_router.detect_format()."""
    if is_nessus_xml(data, filename):
        # Detected on purpose so parse_bytes can say *why* it failed rather than
        # letting the file fall through to the plain-text LLM branch and be
        # "extracted" into nonsense.
        return True
    return header_matches(data, strict=True)


# ── .nessus XML adapter ───────────────────────────────────────────────────────
#
# The XML export is the CSV un-flattened: one <ReportItem> is exactly one CSV row
# (plugin × host × port). Rather than teach the accumulation loop a second input
# shape, this adapter re-presents each ReportItem as a row in the canonical CSV
# column vocabulary, so XML and CSV of the same scan flow through the identical
# logic and produce the identical graph.
#
# Header display names are chosen so _norm_header + _ALIAS_LOOKUP (and, for the
# CVSS columns, _CVSS_HEADER_RE) map them onto the right canonical slots — the
# same table a real CSV header is matched against. Row cells are emitted in this
# order; _index_columns keys off position, so the two must stay aligned.
_XML_COLUMNS: Tuple[Tuple[str, str], ...] = (
    ("Plugin ID", "plugin_id"),
    ("Name", "name"),
    ("Family", "family"),
    ("Severity", "severity"),
    ("Host", "host"),
    ("DNS Name", "dns_name"),
    ("NetBIOS Name", "netbios"),
    ("MAC Address", "mac"),
    ("Protocol", "protocol"),
    ("Port", "port"),
    ("CVE", "cve"),
    ("VPR Score", "vpr"),
    ("EPSS Score", "epss"),
    ("CVSS v2.0 Base Score", "cvss2"),
    ("CVSS v3.0 Base Score", "cvss3"),
    ("CVSS v4.0 Base Score", "cvss4"),
    ("Synopsis", "synopsis"),
    ("Description", "description"),
    ("Solution", "solution"),
    ("See Also", "see_also"),
    ("Plugin Output", "output"),
    ("STIG Severity", "stig"),
    ("Exploit?", "exploit"),
    ("Exploit Ease", "exploit_ease"),
    ("Metasploit", "metasploit"),
    ("Core Impact", "core_impact"),
    ("CANVAS", "canvas"),
    ("Elliot", "elliot"),
    ("D2 Elliot", "d2_elliot"),
    ("Vuln Publication Date", "vuln_date"),
)

# canonical field → the ReportItem child element that carries it. Attributes
# (pluginID, pluginName, pluginFamily, protocol, port, severity) and the host
# columns are handled separately in _row_from_report_item.
_XML_ITEM_CHILDREN: Dict[str, str] = {
    "cvss2": "cvss_base_score",
    "cvss3": "cvss3_base_score",
    "cvss4": "cvss4_base_score",
    "vpr": "vpr_score",
    "epss": "epss_score",
    "synopsis": "synopsis",
    "description": "description",
    "solution": "solution",
    "output": "plugin_output",
    "stig": "stig_severity",
    "exploit": "exploit_available",
    "exploit_ease": "exploitability_ease",
    "metasploit": "exploit_framework_metasploit",
    "core_impact": "exploit_framework_core",
    "canvas": "exploit_framework_canvas",
    "elliot": "exploit_framework_elliot",
    "d2_elliot": "exploit_framework_d2_elliot",
    "vuln_date": "vuln_publication_date",
}

_XML_COL_ORDER: Tuple[str, ...] = tuple(canon for _disp, canon in _XML_COLUMNS)


def _local(tag: Any) -> str:
    """Element tag without its XML namespace (`{ns}ReportItem` → `ReportItem`)."""
    text = str(tag or "")
    return text.rsplit("}", 1)[-1]


def _first_line(value: str) -> str:
    """First non-empty line — a HostProperties mac-address tag can list several."""
    for line in str(value or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _row_from_report_item(
    item: ET.Element, host_name: str, host_props: Dict[str, str]
) -> List[str]:
    """Flatten one <ReportItem> into a canonical CSV-column row (in _XML_COLUMNS order)."""
    # Group children once: a ReportItem repeats <cve> (one per CVE) and may repeat
    # <see_also>/<xref>, so a positional first()/join() over a prebuilt dict beats
    # re-scanning the child list per field.
    kids: Dict[str, List[str]] = {}
    for child in item:
        kids.setdefault(_local(child.tag), []).append(child.text or "")

    def first(name: str) -> str:
        vals = kids.get(name)
        return vals[0] if vals else ""

    vals: Dict[str, str] = {}
    vals["plugin_id"] = item.get("pluginID", "")
    vals["name"] = item.get("pluginName", "")
    vals["family"] = item.get("pluginFamily", "")
    vals["protocol"] = item.get("protocol", "")
    vals["port"] = item.get("port", "")
    # risk_factor is the CSV's "Risk" word (Critical/High/…/None); fall back to the
    # numeric severity attribute, which _severity_of also understands.
    vals["severity"] = first("risk_factor") or item.get("severity", "")

    # Host identity from HostProperties, with the ReportHost @name as the fallback
    # for whichever of address/name the tags omit. _host_identity re-classifies by
    # shape regardless, so a name landing in "host" is still resolved correctly.
    ip = host_props.get("host-ip", "")
    fqdn = host_props.get("host-fqdn", "") or host_props.get("host-rdns", "")
    if not ip and _is_ip(host_name):
        ip = host_name
    if not fqdn and host_name and not _is_ip(host_name):
        fqdn = host_name
    vals["host"] = ip
    vals["dns_name"] = fqdn
    vals["netbios"] = host_props.get("netbios-name", "")
    vals["mac"] = _first_line(host_props.get("mac-address", ""))

    # Every <cve> child, comma-joined so _cves_in lifts them exactly as it does the
    # CSV's multi-CVE cell. see_also folds in <xref> the same way the CSV does.
    vals["cve"] = ", ".join(c for c in kids.get("cve", []) if c.strip())
    see_also = [s for s in (kids.get("see_also", []) + kids.get("xref", [])) if s.strip()]
    vals["see_also"] = "\n".join(see_also)

    for canon, child_name in _XML_ITEM_CHILDREN.items():
        if canon in ("see_also",):
            continue
        vals.setdefault(canon, first(child_name))

    return [vals.get(canon, "") for canon in _XML_COL_ORDER]


def _nessus_xml_reader(
    source: Any, result: "NessusResult"
) -> Tuple[List[str], Iterator[List[str]]]:
    """
    Present a .nessus XML export as (header, row-iterator) like csv.reader does.

    `source` is any binary file-like (an in-memory BytesIO from the webhook path,
    or an open file handle for a large host-side ingest). iterparse streams the
    document and every element is cleared as it closes, so peak memory tracks the
    accumulating graph rather than the size of the file — an AD-scale .nessus does
    not have to be held as a DOM tree.

    A malformed / truncated document is reported on `result` and the rows parsed so
    far are still yielded, matching this parser's "say what was dropped rather than
    fail silent" contract.
    """
    header = [disp for disp, _canon in _XML_COLUMNS]

    def _rows() -> Iterator[List[str]]:
        host_name = ""
        host_props: Dict[str, str] = {}
        try:
            for event, elem in ET.iterparse(source, events=("start", "end")):
                tag = _local(elem.tag)
                if event == "start":
                    if tag == "ReportHost":
                        host_name = elem.get("name", "") or ""
                        host_props = {}
                    continue
                if tag == "HostProperties":
                    for child in elem:
                        if _local(child.tag) == "tag":
                            host_props[child.get("name", "")] = child.text or ""
                    elem.clear()
                elif tag == "ReportItem":
                    row = _row_from_report_item(elem, host_name, host_props)
                    elem.clear()
                    yield row
                elif tag == "ReportHost":
                    host_name = ""
                    host_props = {}
                    elem.clear()
        except ET.ParseError as exc:
            result.errors.append(
                f"The .nessus XML is malformed and could not be read to the end "
                f"({exc}). Only the findings before the break were ingested — "
                f"re-export the scan and re-upload."
            )

    return header, _rows()


# ── Row model ─────────────────────────────────────────────────────────────────

def _index_columns(header: List[str]) -> Tuple[Dict[str, int], List[str], List[str]]:
    """Map canonical field → column index. Returns (index, seen, unmapped)."""
    index: Dict[str, int] = {}
    seen: List[str] = []
    unmapped: List[str] = []
    for pos, cell in enumerate(header):
        norm = _norm_header(cell)
        if not norm:
            continue
        seen.append(norm)
        canon = _ALIAS_LOOKUP.get(norm, "")
        if not canon:
            # CVSS columns vary too much for an alias table (v2.0 / v3 / v4,
            # with and without the dot, base and temporal). Match the shape.
            m = _CVSS_HEADER_RE.match(norm)
            if m:
                canon = "cvss%s" % (m.group(1) or "2")
            else:
                unmapped.append(norm)
                continue
        # First column to claim a slot keeps it.
        index.setdefault(canon, pos)
    return index, seen, unmapped


def _cell(row: List[str], index: Dict[str, int], key: str) -> str:
    pos = index.get(key)
    if pos is None or pos >= len(row):
        return ""
    return _clean(row[pos])


# ── Host resolution ───────────────────────────────────────────────────────────

def _host_identity(row: List[str], index: Dict[str, int]) -> Dict[str, str]:
    """
    Work out what the row's host node should be.

    Returns {'ip', 'fqdn', 'netbios'}. The Host column is whatever the scan was
    pointed at — an address on a subnet scan, a name on a credentialed one — so
    it is classified by shape, not by which column it came from.
    """
    raw_host = _cell(row, index, "host")
    dns = _cell(row, index, "dns_name")
    netbios = _cell(row, index, "netbios")

    ip = ""
    fqdn = ""

    for candidate in (raw_host, dns):
        if not candidate:
            continue
        if _is_ip(candidate):
            ip = ip or candidate
        elif _DOMAIN_RE.match(candidate) or _HOSTNAME_RE.match(candidate):
            fqdn = fqdn or candidate

    if not fqdn and netbios and not _is_ip(netbios):
        fqdn = netbios
    return {"ip": ip, "fqdn": fqdn, "netbios": netbios}


# ── Informational fact plugins ────────────────────────────────────────────────

def _os_from_output(output: str) -> str:
    """
    Lift the OS string out of plugin 11936's output.

    Format:
        Remote operating system : Microsoft Windows Server 2016 Standard
        Confidence level : 95
        Method : SMB

    When the fingerprint does not converge the plugin lists every candidate on
    its own line under the same heading. Taking the first would assert a build
    the scanner explicitly declined to commit to — and this value can be written
    onto the host — so an ambiguous answer yields nothing at all.
    """
    m = re.search(
        r"remote operating system\s*:\s*(.*?)"
        r"(?:\n\s*(?:confidence level|method|the remote host)\s*:|\Z)",
        str(output or ""), re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return ""
    lines = [ln.strip() for ln in m.group(1).splitlines() if ln.strip()]
    if len(lines) != 1:
        return ""
    return _trim(_clean(lines[0]), 200)


def _cpes_from_output(output: str) -> List[Tuple[str, str]]:
    """
    Lift (cpe, human title) pairs out of plugin 45590's output.

    Format:
        The remote operating system matched the following CPE :
          cpe:/o:microsoft:windows_server_2016 -> Microsoft Windows Server 2016
        Following application CPE's matched on the remote system :
          cpe:/a:openbsd:openssh:7.4 -> OpenBSD OpenSSH 7.4

    The title is optional — older plugin revisions emit the bare CPE.
    """
    out: List[Tuple[str, str]] = []
    seen: set = set()
    for raw_line in str(output or "").splitlines():
        line = raw_line.strip()
        if not line.lower().startswith("cpe:"):
            continue
        m = _CPE_LINE_RE.match(line)
        if not m:
            continue
        cpe = m.group(1).strip().rstrip(",;")
        title = _clean(m.group(2) or "")
        if cpe.lower() in seen:
            continue
        seen.add(cpe.lower())
        out.append((cpe, title))
    return out


def _tech_from_cpe(cpe: str, title: str) -> Dict[str, str]:
    """
    Derive a Technology node's name and version from a CPE.

    The human title is preferred for `name` because that is what an operator
    reads on the card; the CPE is kept whole in `cpe`, which is what
    tech_context_engine.map_cpe_to_cves() needs for a precise NVD match instead
    of a product-name keyword search that attributes other products' CVEs.

    `name` carries the product WITHOUT its version, and `version` carries the
    version — the same split `upload_router._parse_nmap` uses. This is not
    cosmetic: Flowsint composes a Technology node's nodeLabel from name+version
    server-side, so a title left as "OpenBSD OpenSSH 7.4" (which is how plugin
    45590 prints it) lands in the graph as "OpenBSD OpenSSH 7.4 7.4" — and, worse,
    stops matching the node nmap would create for the same product.
    """
    body = cpe.split(":", 1)[1] if ":" in cpe else cpe
    parts = [p for p in body.replace("/", "").split(":") if p]
    # cpe:/a:vendor:product:version   → ['a', 'vendor', 'product', 'version']
    # cpe:2.3:a:vendor:product:ver:.. → ['2.3', 'a', 'vendor', 'product', ...]
    if parts and parts[0] == "2.3":
        parts = parts[1:]
    part = parts[0] if parts else ""          # 'a' application, 'o' OS, 'h' hardware
    vendor = parts[1] if len(parts) > 1 else ""
    product = parts[2] if len(parts) > 2 else ""
    version = parts[3] if len(parts) > 3 else ""
    if version in ("*", "-"):
        version = ""

    name = title or " ".join(p for p in (vendor, product) if p).replace("_", " ")
    if version and name.endswith(version):
        name = name[: -len(version)].strip(" -_") or name
    label = f"{name} {version}".strip() if version else name
    return {
        "name": _trim(name, 200),
        "label": _trim(label, 200),
        "vendor": vendor.replace("_", " "),
        "version": version,
        "part": part,
        "cpe": cpe,
    }


# ── Main parse ────────────────────────────────────────────────────────────────

def parse_bytes(
    data: bytes,
    filename: str = "",
    allow_vuln_nodes: bool = True,
    include_info: Optional[bool] = None,
) -> NessusResult:
    """
    Parse a Nessus CSV export or .nessus XML export into entities/relationships.

    The XML export is detected and streamed through _nessus_xml_reader, then fed
    through the same accumulation core as the CSV, so the two produce the same
    graph. A large .nessus that will not fit the webhook body limit should go
    through parse_stream / scripts/ingest_nessus_large.py instead, which never
    holds the whole file in memory.

    allow_vuln_nodes=False drops the Vulnerability nodes (and their edges) while
    keeping hosts and technologies — the degraded mode upload_router uses when
    the custom type is not registered, because a single unresolvable nodeType
    makes GET /graph 500 for the entire sketch.

    include_info=None reads SPOTTER_NESSUS_INCLUDE_INFO; see the module docstring.
    """
    result = NessusResult()

    if not data:
        result.errors.append("Nessus upload is empty.")
        return result

    if is_nessus_xml(data, filename):
        result.source_format = "nessus-xml"
        header, reader = _nessus_xml_reader(io.BytesIO(data), result)
        return _ingest_rows(result, header, reader,
                            allow_vuln_nodes=allow_vuln_nodes,
                            include_info=include_info)

    text = _decode_text(data)
    if not text.strip():
        result.errors.append("Nessus CSV contains no rows.")
        return result

    # Plugin output routinely exceeds csv's 128 KB default field limit; without
    # this the reader raises partway through and the rest of the report is lost.
    try:
        if csv.field_size_limit() < 4 * 1024 * 1024:
            csv.field_size_limit(4 * 1024 * 1024)
    except (OverflowError, ValueError):        # platform-dependent ceiling
        pass

    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        result.errors.append("Nessus CSV has no header row.")
        return result
    except csv.Error as exc:
        result.errors.append(f"Nessus CSV is malformed: {exc}")
        return result

    return _ingest_rows(result, header, reader,
                        allow_vuln_nodes=allow_vuln_nodes,
                        include_info=include_info)


def parse_stream(
    source: Any,
    filename: str = "",
    allow_vuln_nodes: bool = True,
    include_info: Optional[bool] = None,
) -> NessusResult:
    """
    Parse a .nessus XML export straight from a binary file handle.

    The path scripts/ingest_nessus_large.py uses: iterparse streams the file and
    clears each element as it closes, so a multi-gigabyte export that could never
    fit the 90 MB webhook cap (or a DOM tree) still ingests on the host. Only the
    XML export streams this way — route CSV bytes through parse_bytes.
    """
    result = NessusResult()
    result.source_format = "nessus-xml"
    header, reader = _nessus_xml_reader(source, result)
    return _ingest_rows(result, header, reader,
                        allow_vuln_nodes=allow_vuln_nodes,
                        include_info=include_info)


def _ingest_rows(
    result: NessusResult,
    header: List[str],
    reader: Iterable[List[str]],
    *,
    allow_vuln_nodes: bool = True,
    include_info: Optional[bool] = None,
) -> NessusResult:
    """
    Accumulate canonical column rows into entities/relationships.

    Format-agnostic: `reader` yields row lists aligned to `header`, whether from
    csv.reader or _nessus_xml_reader. Everything scan-specific — host resolution,
    per-plugin folding, severity scoring, OS/CPE mining, the caps — lives here, so
    the CSV and XML inputs cannot drift apart.
    """
    # Resolved per call — see _cap(). INCLUDE_INFO_DEFAULT is only the value the
    # process started with.
    max_rows = _cap("SPOTTER_NESSUS_MAX_ROWS", MAX_ROWS)
    max_hosts = _cap("SPOTTER_NESSUS_MAX_HOSTS", MAX_HOSTS)
    max_plugins = _cap("SPOTTER_NESSUS_MAX_PLUGINS", MAX_PLUGINS)
    max_tech = _cap("SPOTTER_NESSUS_MAX_TECH", MAX_TECH)
    max_host_details = _cap("SPOTTER_NESSUS_MAX_HOST_DETAILS", MAX_HOST_DETAILS)
    if include_info is None:
        raw_flag = str(os.environ.get("SPOTTER_NESSUS_INCLUDE_INFO", "")).strip().lower()
        include_info = (raw_flag in ("1", "true", "yes", "on")
                        if raw_flag else INCLUDE_INFO_DEFAULT)

    index, seen, unmapped = _index_columns(header)
    result.columns_seen = seen
    result.columns_unmapped = unmapped

    if "plugin_id" not in index:
        result.errors.append(
            "No Plugin ID column found — this does not look like a Nessus export. "
            f"Columns seen: {', '.join(seen[:12]) or '(none)'}"
        )
        return result
    if not (index.keys() & {"host", "dns_name"}):
        result.errors.append(
            "No Host / IP Address column found — findings cannot be attached to "
            "anything. Re-export with the Host column included."
        )
        return result

    builder = _Builder()

    # Accumulators keyed by plugin id and by host temp_id.
    plugins: Dict[str, Dict[str, Any]] = {}
    hosts: Dict[str, Dict[str, Any]] = {}
    # (host_tid, plugin_id) → the single folded finding edge
    findings: Dict[Tuple[str, str], Dict[str, Any]] = {}
    # cpe (lowercased) → the human title plugin 45590 printed beside it, so the
    # Technology node can be named "OpenBSD OpenSSH 7.4" rather than
    # "openbsd openssh". Collected here because the build pass below walks hosts,
    # by which point the plugin output is long gone.
    cpe_titles: Dict[str, str] = {}
    # Order-preserving, but membership-tested against the set: a 100k-row report
    # can carry 30k distinct CVEs, and `cve not in all_cves` on a list turns the
    # row loop quadratic.
    all_cves: List[str] = []
    all_cve_set: set = set()
    # Only ISO-8601 observation dates are considered: Tenable also emits
    # "Aug 14, 2026 09:12:03 UTC", and a lexicographic max over that format
    # would confidently report the wrong month as the scan date.
    latest_seen = ""
    severity_counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    capped_rows = capped_hosts = capped_plugins = capped_tech = 0

    for raw_row in reader:
        if not raw_row or not any(str(c).strip() for c in raw_row):
            continue
        result.rows_total += 1
        if result.rows_total > max_rows:
            capped_rows += 1
            continue

        plugin_id = _cell(raw_row, index, "plugin_id")
        if not plugin_id:
            result.rows_skipped_bad += 1
            continue

        ident = _host_identity(raw_row, index)
        if not ident["ip"] and not ident["fqdn"]:
            result.rows_skipped_bad += 1
            continue

        # ── host node(s) ──────────────────────────────────────────────────────
        # Uppercase because that is BloodHound's convention and therefore the
        # only spelling that merges with SharpHound / PingCastle rather than
        # creating a parallel host.
        ip_tid = f"nessus:ip:{ident['ip']}" if ident["ip"] else ""
        dev_label = ident["fqdn"].upper() if ident["fqdn"] else ""
        dev_tid = f"nessus:host:{dev_label}" if dev_label else ""
        host_tid = dev_tid or ip_tid

        if host_tid not in hosts:
            if len(hosts) >= max_hosts:
                capped_hosts += 1
                continue
            hosts[host_tid] = {
                "ip": ident["ip"],
                "fqdn": ident["fqdn"],
                "netbios": ident["netbios"],
                "mac": _cell(raw_row, index, "mac"),
                "label": dev_label or ident["ip"],
                "is_device": bool(dev_label),
                "ip_tid": ip_tid,
                "dev_tid": dev_tid,
                "counts": {s: 0 for s in SEVERITY_ORDER},
                "score": 0,
                "cves": [],
                "exploitable": 0,
                "os": "",
                "cpes": [],
            }
        host = hosts[host_tid]
        # A later row may carry an identifier the first one lacked.
        if not host["mac"]:
            host["mac"] = _cell(raw_row, index, "mac")
        if not host["ip"] and ident["ip"]:
            host["ip"] = ident["ip"]
            host["ip_tid"] = ip_tid

        # ── severity ──────────────────────────────────────────────────────────
        cvss3 = _float(_cell(raw_row, index, "cvss3"))
        cvss2 = _float(_cell(raw_row, index, "cvss2"))
        cvss4 = _float(_cell(raw_row, index, "cvss4"))
        best_cvss = cvss4 if cvss4 is not None else (
            cvss3 if cvss3 is not None else cvss2)
        severity = _severity_of(_cell(raw_row, index, "severity"), best_cvss)
        output = ""
        pos = index.get("output")
        if pos is not None and pos < len(raw_row):
            output = str(raw_row[pos] or "")     # NOT _clean: line structure matters

        # ── informational rows: mined for facts, not ingested as findings ─────
        if severity == "info" and not include_info:
            result.rows_skipped_info += 1
            # Counted on the host as "informational rows seen" (nessus_info_count),
            # NOT into severity_counts: that is per plugin node, and a skipped
            # informational row never becomes one. rows_skipped_info is the total.
            host["counts"]["info"] += 1
            if plugin_id == PLUGIN_OS_IDENTIFICATION and not host["os"]:
                host["os"] = _os_from_output(output)
            elif plugin_id == PLUGIN_CPE:
                for cpe, title in _cpes_from_output(output):
                    if cpe not in host["cpes"]:
                        host["cpes"].append(cpe)
                    if title:
                        cpe_titles.setdefault(cpe.lower(), title)
            continue

        # Rows are counted here; severity counts and the host risk score are NOT.
        # Those are per FINDING — see the finding block below — because the same
        # plugin on three ports of one host is one thing to fix, and counting it
        # three times would inflate that host's risk by however many ports it
        # happened to expose.
        result.rows_parsed += 1

        # OS/CPE facts also arrive on non-informational rows in some exports.
        if plugin_id == PLUGIN_OS_IDENTIFICATION and not host["os"]:
            host["os"] = _os_from_output(output)
        elif plugin_id == PLUGIN_CPE:
            for cpe, title in _cpes_from_output(output):
                if cpe not in host["cpes"]:
                    host["cpes"].append(cpe)
                if title:
                    cpe_titles.setdefault(cpe.lower(), title)

        # ── plugin (Vulnerability) accumulator ────────────────────────────────
        cves = _cves_in(_cell(raw_row, index, "cve"))
        exploit_frameworks = [
            label for key, label in _EXPLOIT_COLUMNS
            if _truthy(_cell(raw_row, index, key))
        ]
        # Tenable.sc collapses the framework columns into one "Exploit?" flag.
        if not exploit_frameworks and _truthy(_cell(raw_row, index, "exploit")):
            exploit_frameworks = ["exploit available"]

        plugin = plugins.get(plugin_id)
        if plugin is None:
            if len(plugins) >= max_plugins:
                capped_plugins += 1
                continue
            plugin = {
                "plugin_id": plugin_id,
                "name": _cell(raw_row, index, "name") or f"Nessus plugin {plugin_id}",
                "family": _cell(raw_row, index, "family"),
                "severity": severity,
                "cvss2": cvss2,
                "cvss3": cvss3,
                "cvss4": cvss4,
                "vpr": _float(_cell(raw_row, index, "vpr")),
                "epss": _float(_cell(raw_row, index, "epss")),
                "synopsis": _trim(_cell(raw_row, index, "synopsis"), MAX_TEXT_CHARS),
                "description": _trim(_cell(raw_row, index, "description"), MAX_TEXT_CHARS),
                "solution": _trim(_cell(raw_row, index, "solution"), MAX_TEXT_CHARS),
                "see_also": _trim(_cell(raw_row, index, "see_also"), 500),
                "exploit_ease": _cell(raw_row, index, "exploit_ease"),
                "stig": _cell(raw_row, index, "stig"),
                "vuln_date": _cell(raw_row, index, "vuln_date"),
                "cves": [],
                "exploit_frameworks": [],
                "hosts": set(),
                "ports": set(),
            }
            plugins[plugin_id] = plugin

        # Keep the worst severity seen for a plugin: an export that carries a
        # per-host severity override must not let one low-rated host downgrade
        # the finding everywhere else.
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(plugin["severity"], 0):
            plugin["severity"] = severity
        for cve in cves:
            if cve not in plugin["cves"]:
                plugin["cves"].append(cve)
            if cve not in all_cve_set:
                all_cve_set.add(cve)
                all_cves.append(cve)
            if len(host["cves"]) < MAX_CVES_PER_HOST and cve not in host["cves"]:
                host["cves"].append(cve)
        for fw in exploit_frameworks:
            if fw not in plugin["exploit_frameworks"]:
                plugin["exploit_frameworks"].append(fw)
        plugin["hosts"].add(host_tid)

        # ── finding edge, folded per (host, plugin) ───────────────────────────
        port = _cell(raw_row, index, "port")
        proto = (_cell(raw_row, index, "protocol") or "").lower()
        port_label = ""
        if port and port not in ("0", ""):
            port_label = f"{port}/{proto}" if proto else str(port)
            plugin["ports"].add(port_label)

        last_seen = _cell(raw_row, index, "last_seen")
        if re.match(r"^\d{4}-\d{2}-\d{2}", last_seen) and last_seen > latest_seen:
            latest_seen = last_seen

        key = (host_tid, plugin_id)
        finding = findings.get(key)
        if finding is None:
            # First time this host has seen this plugin: this is the unit the
            # host's severity counts and risk score are measured in.
            host["counts"][severity] += 1
            host["score"] += SEVERITY_WEIGHT.get(severity, 0)
            if exploit_frameworks:
                host["exploitable"] += 1
            finding = {
                "severity": severity,
                "ports": [],
                "output": _trim(_clean(output), MAX_OUTPUT_CHARS),
                "first_seen": _cell(raw_row, index, "first_seen"),
                "last_seen": last_seen,
                "state": _cell(raw_row, index, "state"),
            }
            findings[key] = finding
        if port_label and port_label not in finding["ports"]:
            finding["ports"].append(port_label)
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(finding["severity"], 0):
            # A later row rated this finding worse. Move it between the buckets
            # rather than leaving the host's counts describing the first row seen.
            host["counts"][finding["severity"]] -= 1
            host["counts"][severity] += 1
            host["score"] += (SEVERITY_WEIGHT.get(severity, 0)
                              - SEVERITY_WEIGHT.get(finding["severity"], 0))
            finding["severity"] = severity

    # ── build host nodes ──────────────────────────────────────────────────────
    for host_tid, host in hosts.items():
        counts = host["counts"]
        props: Dict[str, Any] = {
            "source": SOURCE,
            "nessus_scanned": True,
            "nessus_finding_count": sum(counts[s] for s in SEVERITY_ORDER
                                        if s != "info"),
            "nessus_critical_count": counts["critical"],
            "nessus_high_count": counts["high"],
            "nessus_medium_count": counts["medium"],
            "nessus_low_count": counts["low"],
            "nessus_info_count": counts["info"],
            "nessus_risk_score": host["score"],
            # Compatible names for tech_context_engine.compute_composite_risk(),
            # which already takes cve_exposure / exploitable_cve_count.
            "nessus_cve_exposure": len(host["cves"]),
            "nessus_exploitable_findings": host["exploitable"],
            "nessus_cves": host["cves"][:MAX_CVES_PER_HOST],
            "nessus_cpes": host["cpes"][:100],
        }
        if latest_seen:
            props["nessus_scan_date"] = latest_seen
        if host["os"]:
            props["nessus_os"] = host["os"]
        if host["mac"]:
            props["mac_address"] = host["mac"]
        if host["netbios"]:
            props["nessus_netbios_name"] = host["netbios"]

        if host["is_device"]:
            label = host["label"]
            builder.upsert("Device", label, host_tid, {
                # `device_id` is Device's REQUIRED primary field. A built-in node
                # missing it is dropped by the importer without a word, and the
                # FQDN is the only stable identifier a scan report carries.
                "device_id": label,
                "hostname": label,
                "ip": host["ip"],
                # NOT `operating_system`: SharpHound reads the real attribute off
                # the computer object, this is an outside-in fingerprint, and
                # SET n += would let the guess overwrite the fact.
                **props,
            })
            # The address gets its own node so nmap/Shodan data still merges, and
            # is joined by the label nmap already uses for name → address.
            if host["ip"] and host["ip_tid"]:
                builder.upsert("Ip", host["ip"], host["ip_tid"], {
                    "address": host["ip"],      # REQUIRED primary field for Ip
                    "ip": host["ip"],
                    "source": SOURCE,
                    # Deliberately NOT `nessus_scanned`: the findings hang off the
                    # Device, and every reader that counts scanned hosts filters
                    # on that flag. Marking the companion address would report an
                    # estate half again as large as the one that was scanned.
                    "nessus_seen_as_address": True,
                })
                builder.relate(host_tid, host["ip_tid"], "RESOLVES_TO",
                               {"source": SOURCE})
        else:
            ip_props = dict(props)
            # Safe here and only here: an address-only host has no AD identity,
            # so there is no authoritative operating_system to overwrite.
            if host["os"]:
                ip_props["operating_system"] = host["os"]
            builder.upsert("Ip", host["label"], host_tid, {
                "address": host["label"],       # REQUIRED primary field for Ip
                "ip": host["label"],
                **ip_props,
            })

    # ── build Technology nodes from resolved CPEs ─────────────────────────────
    tech_tids: Dict[str, str] = {}
    for host_tid, host in hosts.items():
        for cpe in host["cpes"]:
            key = cpe.lower()
            if key not in tech_tids and len(tech_tids) >= max_tech:
                capped_tech += 1
                continue
            tech = _tech_from_cpe(cpe, cpe_titles.get(key, ""))
            if not tech["name"]:
                continue
            tech_tid = tech_tids.setdefault(key, f"nessus:tech:{key}")
            tech_label = tech["label"]
            builder.upsert("Technology", tech_label, tech_tid, {
                # `name` is REQUIRED on the built-in Technology type. A name-less
                # Technology node makes GET /graph 500 for the ENTIRE sketch.
                "name": tech["name"],
                "vendor": tech["vendor"],
                "version": tech["version"],
                "cpe": cpe,
                # From the parsed part letter, not a substring test on the whole
                # CPE: "cpe:/o:microsoft:..." contains ":/o:", never ":o:", so the
                # substring form labelled every operating system an Application.
                "category": {"o": "OS", "h": "Hardware"}.get(tech["part"],
                                                             "Application"),
                "source": SOURCE,
                # A CPE from a credentialed scan is an identification, not a
                # guess from a banner.
                "confidence": "high",
                # `is_high_value` is deliberately NOT written. It is derived from
                # HIGH_VALUE_TECH by the technology enricher and WF12, and a
                # blanket False here would `SET n +=` over a True they had
                # already established for the same product.
            })
            builder.relate(host_tid, tech_tid, "USES_TECH", {"source": SOURCE})

    # ── build Vulnerability nodes ─────────────────────────────────────────────
    # severity_counts is per PLUGIN, deliberately, and matches what
    # nessus_context.summarise() counts off the graph — two numbers labelled the
    # same thing that disagree is worse than either. The host×plugin count is
    # reported separately as `findings`, and the informational rows this parser
    # skipped are in `rows_skipped_info`. Counted here rather than in the row loop
    # so a plugin whose severity was upgraded mid-report lands in one bucket only.
    ranked: List[Dict[str, Any]] = []
    for plugin in plugins.values():
        severity_counts[plugin["severity"]] += 1
    for plugin_id, plugin in plugins.items():
        host_count = len(plugin["hosts"])
        priority = _priority(plugin["severity"], host_count,
                             plugin["exploit_frameworks"])
        record = {
            "plugin_id": plugin_id,
            "name": plugin["name"],
            "severity": plugin["severity"],
            "hosts": host_count,
            "cves": plugin["cves"][:20],
            "exploit_frameworks": plugin["exploit_frameworks"],
            "priority_score": priority,
            "cvss": plugin["cvss3"] if plugin["cvss3"] is not None else plugin["cvss2"],
        }
        ranked.append(record)

        if not allow_vuln_nodes:
            continue

        # The plugin id alone would be a stable but unreadable label; the name
        # alone is not unique. Together they read well in the graph and dedupe
        # correctly. A plugin renamed between scanner releases yields a second
        # node — visible and rare, unlike a silent merge onto the wrong finding.
        label = _trim(f"{plugin_id}: {plugin['name']}", 200)
        tid = f"nessus:vuln:{plugin_id}"

        # Which host saw this plugin, on which ports, with what output. Worst
        # hosts first so a truncated list keeps the ones that matter.
        host_details: List[Dict[str, Any]] = []
        for host_tid in plugin["hosts"]:
            finding = findings.get((host_tid, plugin_id))
            host = hosts.get(host_tid)
            if not finding or not host:
                continue
            host_details.append({
                "host": host["label"],
                "ports": finding["ports"],
                "severity": finding["severity"],
                "output": finding["output"],
                "first_seen": finding["first_seen"],
                "last_seen": finding["last_seen"],
                "state": finding["state"],
            })
        host_details.sort(key=lambda d: (-SEVERITY_RANK.get(d["severity"], 0),
                                         d["host"]))
        details_truncated = len(host_details) > max_host_details
        host_details = host_details[:max_host_details]
        props: Dict[str, Any] = {
            # ── declared in REGISTERED_SCHEMA: must be strings ────────────────
            "plugin_id": plugin_id,
            "name": plugin["name"],
            "family": plugin["family"],
            "severity": plugin["severity"],
            "synopsis": plugin["synopsis"],
            "description": plugin["description"],
            "solution": plugin["solution"],
            "see_also": plugin["see_also"],
            "exploit_ease": plugin["exploit_ease"],
            "stig_severity": plugin["stig"],
            "vuln_publication_date": plugin["vuln_date"],
            "scanner": SOURCE,
            "source": SOURCE,
            "priority_tier": _priority_tier(priority),
            # ── undeclared: keep their native Neo4j type so Cypher predicates
            #    like `WHERE v.priority_score > 70` keep working. A DB-registered
            #    custom type rebuilds every DECLARED property as Optional[str],
            #    and Pydantic v2 will not coerce an int into one, so declaring
            #    these would silently drop them. Keep in sync with
            #    scripts/register_nessus_type.py :: VULNERABILITY_SCHEMA.
            "cve_ids": plugin["cves"],
            "cve_count": len(plugin["cves"]),
            "cvss_base_score": plugin["cvss2"],
            "cvss3_base_score": plugin["cvss3"],
            "cvss4_base_score": plugin["cvss4"],
            "vpr_score": plugin["vpr"],
            "epss_score": plugin["epss"],
            "affected_host_count": host_count,
            "ports": sorted(plugin["ports"])[:50],
            "exploit_frameworks": plugin["exploit_frameworks"],
            "exploit_framework_available": bool(plugin["exploit_frameworks"]),
            "priority_score": priority,
            "severity_rank": SEVERITY_RANK.get(plugin["severity"], 0),
            # Per-host detail lives HERE, not on the HAS_VULNERABILITY edge.
            # batch_import drops edge properties on every path it has: the bulk
            # Neo4j writer sends only (from, to, label), and so does the _add_edge
            # REST fallback. Confirmed against the live graph — every relationship
            # in it carries exactly from_element_id / rel_label / sketch_id /
            # to_element_id and nothing else. Putting ports and plugin output on
            # the edge lost them silently.
            "host_details": json.dumps(host_details),
            "host_details_truncated": details_truncated,
        }
        builder.upsert(VULN_NODE_TYPE, label, tid, props)

    # ── finding edges ─────────────────────────────────────────────────────────
    if allow_vuln_nodes:
        for (host_tid, plugin_id), finding in findings.items():
            if plugin_id not in plugins:
                continue                      # dropped by the plugin cap
            # Deliberately no edge data: it would not survive the import (see
            # host_details above). The edge carries the association and nothing
            # more, which is all Neo4j will keep anyway.
            builder.relate(host_tid, f"nessus:vuln:{plugin_id}", "HAS_VULNERABILITY")

    # ── caps, reported rather than silently applied ───────────────────────────
    # A truncated scan that says nothing reads as "the estate is this clean",
    # which is the most expensive way for this parser to be wrong.
    if capped_rows:
        result.errors.append(
            f"Row cap reached: {capped_rows} of {result.rows_total} rows were not "
            f"read (SPOTTER_NESSUS_MAX_ROWS={max_rows}). This report is INCOMPLETE "
            f"— split the export by host range, or raise the cap."
        )
    if capped_hosts:
        result.errors.append(
            f"Host cap reached: {capped_hosts} rows belonged to hosts beyond the "
            f"first {max_hosts} and were skipped (SPOTTER_NESSUS_MAX_HOSTS)."
        )
    if capped_plugins:
        result.errors.append(
            f"Plugin cap reached: {capped_plugins} rows referenced plugins beyond "
            f"the first {max_plugins} and were skipped (SPOTTER_NESSUS_MAX_PLUGINS)."
        )
    if capped_tech:
        result.errors.append(
            f"Technology cap reached: {capped_tech} CPE references beyond the "
            f"first {max_tech} distinct products were skipped "
            f"(SPOTTER_NESSUS_MAX_TECH)."
        )

    # ── analysis ──────────────────────────────────────────────────────────────
    ranked.sort(key=lambda r: (-r["priority_score"],
                               -SEVERITY_RANK.get(r["severity"], 0),
                               -r["hosts"]))
    result.top_findings = ranked

    host_rows = []
    for host_tid, host in hosts.items():
        counts = host["counts"]
        host_rows.append({
            "host": host["label"],
            "ip": host["ip"],
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "risk_score": host["score"],
            "cve_count": len(host["cves"]),
            "exploitable_findings": host["exploitable"],
            "os": host["os"],
        })
    host_rows.sort(key=lambda h: (-h["risk_score"], -h["critical"], -h["high"]))
    result.top_hosts = host_rows
    result.hosts_scanned = len(hosts)

    result.entities = builder.entities()
    result.relationships = builder.relationships
    result.severity_counts = severity_counts
    result.cve_ids = all_cves
    result.report_date = latest_seen
    result.errors.extend(builder.errors)

    # A report that produced no findings is indistinguishable from a clean estate
    # unless it says which of the two it was. Checked against rows_parsed rather
    # than `not errors`, so a capped run still gets this explanation as well.
    if not result.rows_parsed:
        if result.rows_skipped_info:
            result.errors.append(
                f"All {result.rows_skipped_info} rows in this report are "
                f"informational (severity None) — nothing was ingested as a "
                f"finding. Host facts and CPEs were still lifted. Set "
                f"SPOTTER_NESSUS_INCLUDE_INFO=1 and re-upload to keep "
                f"informational plugins as nodes."
            )
        elif result.rows_total:
            result.errors.append(
                f"No usable rows: all {result.rows_total} rows were missing a "
                f"Plugin ID or a host column value."
            )
        else:
            result.errors.append(
                "The .nessus XML has no <ReportItem> findings."
                if result.source_format == "nessus-xml"
                else "Nessus CSV has a header but no data rows."
            )
    return result


def parse_file(path: str, allow_vuln_nodes: bool = True,
               include_info: Optional[bool] = None) -> NessusResult:
    name = os.path.basename(path)
    with open(path, "rb") as fh:
        # A .nessus XML is streamed from the handle so a multi-gigabyte export is
        # never read into memory whole; a CSV has no streamable structure, so it
        # is read and handed to parse_bytes as before.
        if is_nessus_xml(fh.read(4096), name):
            fh.seek(0)
            return parse_stream(fh, filename=name,
                                allow_vuln_nodes=allow_vuln_nodes,
                                include_info=include_info)
        fh.seek(0)
        return parse_bytes(fh.read(), filename=name,
                           allow_vuln_nodes=allow_vuln_nodes,
                           include_info=include_info)


# ── CLI entry point ───────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in args
    include_info = "--include-info" in args
    positional = [a for a in args if not a.startswith("--")]
    if not positional:
        print("usage: python3 scripts/nessus_parser.py <scan.csv> [--json] "
              "[--include-info]", file=sys.stderr)
        return 2

    result = parse_file(positional[0], include_info=include_info or None)
    summary = result.summary()
    if as_json:
        print(json.dumps(summary, indent=2, default=str))
        return 1 if result.errors else 0

    print(f"Nessus report: {positional[0]}")
    print(f"  rows       : {summary['rows_total']} total, "
          f"{summary['rows_parsed']} findings, "
          f"{summary['rows_skipped_info']} informational, "
          f"{summary['rows_skipped_bad']} unusable")
    print(f"  hosts      : {summary['hosts']}")
    print(f"  plugins    : {summary['plugins']}")
    print(f"  findings   : {summary['findings']}")
    print(f"  CVEs       : {summary['cve_count']}")
    counts = summary["severity_counts"]
    print("  severity   : " + ", ".join(
        f"{s}={counts.get(s, 0)}" for s in reversed(SEVERITY_ORDER)))
    if summary["top_findings"]:
        print("\n  Top findings by priority:")
        for row in summary["top_findings"][:10]:
            fw = ("  [" + ", ".join(row["exploit_frameworks"]) + "]"
                  if row["exploit_frameworks"] else "")
            print(f"    {row['priority_score']:>3}  {row['severity']:<8} "
                  f"{row['hosts']:>4} host(s)  {row['plugin_id']}: "
                  f"{row['name'][:60]}{fw}")
    if summary["top_hosts"]:
        print("\n  Worst hosts:")
        for row in summary["top_hosts"][:10]:
            print(f"    {row['risk_score']:>5}  {row['host'][:40]:<40} "
                  f"C{row['critical']} H{row['high']} M{row['medium']} L{row['low']}")
    for err in result.errors:
        print(f"  ! {err}")
    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
