"""
upload_router.py — Multi-format recon data detector and ingestion dispatcher.

Accepts a file path or raw bytes, detects the data format, normalises it into
SPOTTER's canonical entity/relationship lists, and optionally ingests directly
into Flowsint via flowsint_client.

Supported formats (all from authorized lab / engagement sources):
  SharpHound ZIP     — BloodHound CE (v2) or legacy SharpHound (v3)
  CloudSchism output — zipped scan directory, or one of its JSON exports
  PingCastle report  — ad_hc_<domain>.xml / .json AD health check
  Nessus CSV         — Nessus / Tenable.sc / Tenable VM vulnerability export
  nmap XML           — Service scan output (-oX)
  Amass output       — amass enum text output (FQDN --> IP / FQDN)
    ShareACL output    — [shareacl] JSON-lines from the authorized share scanner
  CSV                — Username / email / IP / domain lists
  Cobalt Strike log  — CS team server export or beacon log
  Raw JSON           — Generic entity dict or list
    Plain text         — LLM-assisted entity extraction via the configured backend

Usage:
    python upload_router.py <file-or-stdin>

Usage from n8n Code node (after reading file bytes):
    import base64, sys
    sys.path.insert(0, '/data/scripts')
    from upload_router import route_bytes
    result = route_bytes(base64.b64decode(file_b64), filename="scan.xml")
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import sys
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ── Safety limits ─────────────────────────────────────────────────────────────

MAX_UPLOAD_BYTES = int(os.environ.get("SPOTTER_UPLOAD_MAX_BYTES", str(32 * 1024 * 1024)))
MAX_CSV_ROWS = int(os.environ.get("SPOTTER_UPLOAD_MAX_CSV_ROWS", "10000"))
MAX_JSON_ITEMS = int(os.environ.get("SPOTTER_UPLOAD_MAX_JSON_ITEMS", "20000"))
LLM_TEXT_PREVIEW_MODES = {"preview", "quarantine", "dry-run", "dryrun", "review"}


def _llm_text_ingest_mode() -> str:
    return (os.environ.get("SPOTTER_LLM_TEXT_INGEST_MODE") or "ingest").strip().lower()


def _decode_text(data: bytes) -> str:
    """Decode bytes without dropping characters silently."""
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def zip_encryption(data: bytes) -> Tuple[int, int]:
    """
    (encrypted_members, total_members) for a zip, counting files only.

    A password-protected zip is invisible to every format test we run: member
    NAMES live in the central directory in the clear, so detect_format() reads
    "cloudschism" (or "sharphound") off an archive whose every artifact is
    unreadable. The parser then finds nothing, returns zero nodes, and the
    upload reports success having imported nothing at all.

    Returns (0, 0) for anything that is not a readable zip.
    """
    if data[:2] != b"PK":
        return (0, 0)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return _zip_encryption_members(zf)
    except Exception:
        return (0, 0)


def zip_encryption_path(path: str) -> Tuple[int, int]:
    """Same as zip_encryption(), but from a path. Reads the central directory only."""
    try:
        with zipfile.ZipFile(path) as zf:
            return _zip_encryption_members(zf)
    except Exception:
        return (0, 0)


def _zip_encryption_members(zf: zipfile.ZipFile) -> Tuple[int, int]:
    members = [i for i in zf.infolist() if not i.is_dir()]
    # Bit 0 of the general-purpose flag marks a member as encrypted.
    return (sum(1 for i in members if i.flag_bits & 0x1), len(members))


def _format_from_zip_names(raw_names: List[str]) -> str:
    """Classify a zip from member names. Shared by the byte path and the staged path."""
    names = [os.path.basename(n).lower() for n in raw_names]
    _bh_stems = ("users.json", "computers.json", "groups.json",
                 "domains.json", "gpos.json", "ous.json",
                 "containers.json", "sessions.json")
    _bh_pfx = tuple(s[:-5] + "_" for s in _bh_stems)  # "users_", "computers_", …
    if any(
        n in _bh_stems
        or any(n.endswith("_" + s) for s in _bh_stems)   # timestamp-first
        or any(n.startswith(p) for p in _bh_pfx)          # type-first
        for n in names
    ):
        return "sharphound"
    from cloudschism_parser import _names_are_cloudschism
    if _names_are_cloudschism(raw_names):
        return "cloudschism"
    for n in raw_names:
        base = os.path.basename(n).lower()
        if base in ("ew.db", "requests.csv"):
            return "eyewitness"
        norm = n.replace("\\", "/").lower()
        if "screens/" in norm and norm.endswith(".png"):
            return "eyewitness"
    return "zip_unknown"


# ── Format detection ──────────────────────────────────────────────────────────

def detect_format(data: bytes, filename: str = "") -> str:
    """
    Return a format string:
    sharphound | cloudschism | pingcastle | nessus | nmap | amass | shareacl |
        csv | cobalt | subdomain_jsonl | json | text
    """
    fname = (filename or "").lower()

    # ShareACL output is line-oriented text with an explicit prefix. Detect it
    # before the generic text/CSV branches so malformed records are reported by
    # the dedicated parser instead of falling through to LLM extraction.
    if b"[shareacl]" in data[:1024 * 1024]:
        try:
            shareacl_text = data[:1024 * 1024].decode("utf-8", errors="replace")
            if re.search(r"^\s*\[shareacl\]\s+\{", shareacl_text, re.MULTILINE):
                return "shareacl"
        except Exception:
            pass

    # SharpHound — ZIP magic bytes. Member names only: a staged file uses the
    # same classifier via detect_format_path(), so the two paths cannot drift.
    if data[:2] == b"PK" and zipfile.is_zipfile(io.BytesIO(data)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                return _format_from_zip_names(zf.namelist())
        except Exception:
            return "zip_unknown"

    # PingCastle health check — must precede both the nmap XML sniff (both are
    # <?xml ...>) and the JSON branch (ad_hc_<domain>.json is valid JSON).
    from pingcastle_parser import is_pingcastle
    if is_pingcastle(data, filename):
        return "pingcastle"

    # CloudSchism structured export uploaded on its own (CloudSchism-report.json,
    # findings.json, attack-graph.json…). Must precede the generic JSON branch,
    # which would otherwise collapse the whole document into one Phrase node.
    #
    # is_cloudschism() parses the document to confirm, so it is gated behind a
    # bounded head scan: a 30 MB unrelated JSON should cost a substring search,
    # not a full parse it will only fail.
    _cs_name = os.path.basename(fname)
    if _cs_name.startswith("cloudschism-") or _cs_name in (
        "findings.json", "attack-graph.json", "public-endpoints.json",
        "external-exposures.json", "attack-paths.json",
    ):
        from cloudschism_parser import is_cloudschism
        if is_cloudschism(data, filename):
            return "cloudschism"
    elif data[:512].lstrip()[:1] == b"{" and b'"metadata"' in data[:65536]:
        from cloudschism_parser import is_cloudschism
        if is_cloudschism(data, filename):
            return "cloudschism"

    # nmap XML
    head = _decode_text(data[:512])
    if "<?xml" in head and "<nmaprun" in head:
        return "nmap"

    if _looks_like_subdomain_jsonl(data, filename):
        return "subdomain_jsonl"

    # JSON
    stripped = data.lstrip()
    if stripped.startswith((b"{", b"[")):
        try:
            json.loads(data)
            obj = json.loads(data)
            
            # Distinguish Cobalt Strike JSON export
            sample = obj if isinstance(obj, dict) else (obj[0] if obj else {})
            if any(k in sample for k in ("bid", "computer", "internal", "external")):
                return "cobalt"
            
            # Distinguish SharpHound v2 JSON (users.json, computers.json, etc.)
            # SharpHound format: either {"data": [...], "meta": {...}} or array of objects
            # with "ObjectIdentifier", "Properties", "Aces"
            data_array = obj.get("data") if isinstance(obj, dict) else (obj if isinstance(obj, list) else [])
            if data_array and len(data_array) > 0:
                first_item = data_array[0] if isinstance(data_array, list) else {}
                if isinstance(first_item, dict) and all(
                    k in first_item for k in ("ObjectIdentifier", "Properties")
                ):
                    # Check filename to disambiguate (users.json, computers.json, etc.)
                    bh_files = ("users", "computers", "groups", "domains", "gpos", "ous", "containers", "sessions")
                    if any(bh in fname for bh in bh_files):
                        return "sharphound"
            
            return "json"
        except json.JSONDecodeError:
            pass

    # Nessus / Tenable vulnerability export. MUST precede the generic CSV branch:
    # that branch matches on a substring, and "description" contains "ip", so a
    # Nessus header line satisfies it and the whole report would be read as a
    # list of people. is_nessus() reads the header row only.
    from nessus_parser import is_nessus
    if is_nessus(data, filename):
        return "nessus"

    # CSV — check for known header columns
    try:
        text = _decode_text(data)
        first_line = text.splitlines()[0].lower() if text.strip() else ""
        csv_headers = {"username", "email", "domain", "ip", "hash",
                       "hostname", "sam", "samaccountname", "password", "ntlm"}
        if "," in first_line and any(h in first_line for h in csv_headers):
            return "csv"
    except Exception:
        pass

    # Amass text output — "sub.example.com --> 1.2.3.4" or "sub.example.com"
    text = _decode_text(data)
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if lines and all(
        re.match(r"[\w\-\.]+\.\w{2,}(\s*-->\s*\S+)?$", l) for l in lines[:10]
    ):
        return "amass"

    # Cobalt Strike plain log (look for CS-specific terms)
    if any(term in text.lower() for term in ("cobalt strike", "[beacon]", "bid =", "tasked beacon")):
        return "cobalt_log"

    return "text"


# ── Analyst-context format hinting ────────────────────────────────────────────
#
# detect_format() reads bytes only. Formless output that carries no magic number
# and no recognisable structure — a pasted process listing being the case that
# prompted this — lands on "text" and gets whatever the LLM fallback can make of
# it. The Ingest tab's Context field is the operator saying what the payload
# actually is, so map that prose onto a format.
#
# Prose never beats bytes. Callers reach this only for the weak detections
# (text / json / zip_unknown), and a hint must still be corroborated by the
# payload, so a mislabelled paste keeps its sniffed format instead of being
# force-fed to the wrong parser.

# First pattern that matches the operator's words wins — most specific first.
_CONTEXT_HINTS: List[Tuple[str, str]] = [
    (r"tasklist|get-?process|\bps\s+(?:aux|-ef)\b|process\s*(?:list|listing|dump|table)"
     r"|proclist|running\s+process", "process_list"),
    (r"\bnmap\b|port\s*scan|service\s*scan", "nmap"),
    (r"\bamass\b|subdomain\s*(?:enum|list)|dns\s*enum", "amass"),
    (r"\bpingcastle\b|ad\s*health\s*check", "pingcastle"),
    (r"\bnessus\b|\btenable\b|vuln(?:erability)?\s*scan|vuln\s*(?:export|report)"
     r"|credentialed\s*scan", "nessus"),
    (r"cloud\s*schism|cloudschism|cloud\s*(?:posture|scan|assessment)"
     r"|\b(?:aws|azure|gcp|m365)\s*scan\b", "cloudschism"),
    (r"sharphound|bloodhound", "sharphound"),
    (r"cobalt\s*strike|\bbeacon\b|\bteamserver\b", "cobalt_log"),
    (r"credential|password|\bntlm\b|hash\s*dump|user\s*list|account\s*list", "csv"),
]

# Weak detect_format() verdicts — the only ones a hint is allowed to replace.
WEAK_FORMATS = ("text", "json", "zip_unknown", "")


def _hint_corroborated(fmt: str, data: bytes) -> bool:
    """
    True when the payload itself is consistent with the hinted format.

    Without this a wrong or stale Context line silently redirects a parse: an
    nmap paste described as "process list" would produce zero technologies and
    lose the hosts it did contain. Declining the hint costs nothing — the caller
    keeps the sniffed format and the existing behaviour.
    """
    if fmt == "process_list":
        return bool(_extract_process_hosts(_decode_text(data))[1])
    text = _decode_text(data[:4096])
    if fmt == "nmap":
        return "<nmaprun" in text
    if fmt == "amass":
        return any(_DOMAIN_RE.match(l.strip().split()[0])
                   for l in text.splitlines()[:20] if l.strip())
    if fmt == "pingcastle":
        from pingcastle_parser import is_pingcastle
        return is_pingcastle(data, "")
    if fmt == "nessus":
        # Looser than detection: the operator has said this is a vulnerability
        # scan, so a report exported with a trimmed column set is taken at their
        # word. A file with no plugin-id column at all is still refused.
        from nessus_parser import header_matches, is_nessus_xml
        return is_nessus_xml(data, "") or header_matches(data, strict=False)
    if fmt == "sharphound":
        # A bare PK check is deliberately NOT enough: every zip starts with PK, so
        # "bloodhound" typed over a CloudSchism or a random archive would hand it
        # to the SharpHound parser. Confirm the member names instead.
        if data[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    names = [os.path.basename(n).lower() for n in zf.namelist()]
                return any(n.endswith(("users.json", "computers.json", "groups.json",
                                       "domains.json", "sessions.json"))
                           for n in names)
            except Exception:
                return False
        return "ObjectIdentifier" in text
    if fmt == "cloudschism":
        from cloudschism_parser import is_cloudschism
        return is_cloudschism(data, "")
    if fmt == "cobalt_log":
        low = text.lower()
        return any(t in low for t in ("beacon", "bid", "teamserver", "checkin", "check-in"))
    if fmt == "csv":
        lines = [l for l in text.splitlines() if l.strip()]
        return len(lines) >= 2 and "," in lines[0]
    return False


def hint_format(context: str, data: bytes, current: str = "text") -> str:
    """
    Re-route a weakly-detected upload using the analyst's description of it.

    Returns `current` unchanged when the context says nothing recognisable, or
    when it names a format the payload does not corroborate.
    """
    if not context or not data:
        return current
    ctx = context.lower()
    for pattern, fmt in _CONTEXT_HINTS:
        if not re.search(pattern, ctx):
            continue
        if fmt == current:
            return current
        try:
            if _hint_corroborated(fmt, data):
                return fmt
        except Exception as e:
            print(f"[upload_router] hint corroboration failed for '{fmt}': {e}",
                  file=sys.stderr)
        return current
    return current


# ── Format-specific parsers ────────────────────────────────────────────────────

def _parse_sharphound(data: bytes, filename: str = "") -> Tuple[List[dict], List[dict]]:
    """Parse SharpHound ZIP or standalone JSON (users.json, computers.json, etc.)."""
    from sharphound_parser import parse_zip_bytes, parse_standalone_json
    
    # Check if it's a ZIP
    if data[:2] == b"PK" and zipfile.is_zipfile(io.BytesIO(data)):
        result = parse_zip_bytes(data)
    else:
        # Assume standalone JSON
        result = parse_standalone_json(data, filename)
    
    return result.to_flowsint_batch()


def _parse_pingcastle(
    data: bytes,
    filename: str = "",
    ingest: bool = False,
) -> Tuple[List[dict], List[dict], List[str], Dict[str, Any]]:
    """
    Parse a PingCastle health check report (ad_hc_<domain>.xml / .json).

    Returns (nodes, edges, errors, report_summary).

    ADRisk is a custom Flowsint type. When it is not registered, importing even
    one such node makes GET /graph return HTTP 500 for the entire sketch, so the
    risk nodes are dropped and the rest of the report still ingests. The check
    only runs when we are actually about to write (ingest=True) — a dry parse
    should not need the API to be reachable.
    """
    from pingcastle_parser import RISK_NODE_TYPE, parse_bytes as parse_pingcastle_bytes

    allow_risk_nodes = True
    guard_error = ""
    if ingest:
        try:
            import flowsint_client as fc
            allow_risk_nodes = fc.is_type_registered(RISK_NODE_TYPE)
        except Exception as exc:
            allow_risk_nodes = False
            guard_error = f"custom type check failed ({exc})"
        if not allow_risk_nodes:
            guard_error = guard_error or f"custom type '{RISK_NODE_TYPE}' is not registered"
            guard_error = (
                f"PingCastle risk rules NOT ingested: {guard_error}. "
                f"Run scripts/register_pingcastle_type.py --apply, then re-upload. "
                f"Domain, DC, trust and privileged-account data was still imported."
            )

    result = parse_pingcastle_bytes(data, filename=filename,
                                    allow_risk_nodes=allow_risk_nodes)
    nodes, edges = result.to_flowsint_batch()
    errors = list(result.errors)
    if guard_error:
        errors.append(guard_error)

    summary = result.summary()
    summary["risk_nodes_ingested"] = allow_risk_nodes
    summary["high_risk_rules_detail"] = result.high_risk_rules[:20]
    return nodes, edges, errors, summary


def _parse_nessus(
    data: bytes,
    filename: str = "",
    ingest: bool = False,
) -> Tuple[List[dict], List[dict], List[str], Dict[str, Any]]:
    """
    Parse a Nessus / Tenable vulnerability export CSV.

    Returns (nodes, edges, errors, report_summary).

    Vulnerability is a custom Flowsint type. When it is not registered,
    importing even one such node makes GET /graph return HTTP 500 for the entire
    sketch, so the vulnerability nodes AND their finding edges are dropped and
    the rest of the report — the scanned hosts, their OS/CPE technologies, the
    per-host severity counts and risk score — still ingests. The check only runs
    when we are actually about to write (ingest=True); a dry parse should not
    need the API to be reachable.

    The analysis in `report` is computed either way, so an operator whose install
    is missing the type still gets the severity breakdown, the ranked findings
    and the worst-hosts list back from the upload.
    """
    from nessus_parser import VULN_NODE_TYPE, parse_bytes as parse_nessus_bytes

    allow_vuln_nodes = True
    guard_error = ""
    if ingest:
        try:
            import flowsint_client as fc
            allow_vuln_nodes = fc.is_type_registered(VULN_NODE_TYPE)
        except Exception as exc:
            allow_vuln_nodes = False
            guard_error = f"custom type check failed ({exc})"
        if not allow_vuln_nodes:
            guard_error = guard_error or f"custom type '{VULN_NODE_TYPE}' is not registered"
            guard_error = (
                f"Nessus findings NOT ingested: {guard_error}. "
                f"Run scripts/register_nessus_type.py --apply, then re-upload. "
                f"Scanned hosts, their technologies and the per-host severity "
                f"counts were still imported, and the report summary below is "
                f"complete either way."
            )

    result = parse_nessus_bytes(data, filename=filename,
                                allow_vuln_nodes=allow_vuln_nodes)
    nodes, edges = result.to_flowsint_batch()
    errors = list(result.errors)
    if guard_error:
        errors.append(guard_error)

    summary = result.summary()
    summary["vuln_nodes_ingested"] = allow_vuln_nodes
    return nodes, edges, errors, summary


# Where captured screenshots are written. This is the runner's RW bind-mount, which
# nginx serves (auth-gated) at /screenshots/. Overridable by env for the host CLI;
# in the runner the env var is not on the allowlist, so it resolves to the default
# mount path — which is exactly what we want.
SCREENSHOTS_DIR = os.environ.get("SPOTTER_SCREENSHOTS_DIR", "/data/screenshots")


def _parse_eyewitness(
    data: bytes,
    filename: str = "",
    ingest: bool = False,
    sketch_id: Optional[str] = None,
) -> Tuple[List[dict], List[dict], List[str], Dict[str, Any]]:
    """
    Parse an EyeWitness web-recon output zip into Website (+ Ip) nodes and copy each
    screenshot to the served directory.

    Returns (nodes, edges, errors, report). Website is a built-in Flowsint type, so
    unlike the Nessus/CloudSchism/PingCastle custom-type parsers there is no
    registration guard to run — a Website node cannot 500 the sketch as long as its
    required `url` is present and valid, which the parser enforces.

    Screenshots are written whenever a writable dir is resolvable, independent of
    `ingest`, because the image bytes only exist here in the uploaded zip. `ingest`
    is accepted for signature symmetry with the other parsers.
    """
    from eyewitness_parser import parse_bytes as parse_ew_bytes

    result = parse_ew_bytes(data, sketch_id=sketch_id, screenshots_dir=SCREENSHOTS_DIR)
    nodes, edges = result.to_flowsint_batch()
    return nodes, edges, list(result.errors), result.summary()


def _parse_cloudschism(
    data: bytes,
    filename: str = "",
    ingest: bool = False,
) -> Tuple[List[dict], List[dict], List[str], Dict[str, Any]]:
    """
    Parse CloudSchism output — a zipped scan directory, or one of its JSON exports.

    Returns (nodes, edges, errors, scan_summary).

    CloudFinding and CloudAttackPath are custom Flowsint types. When one is not
    registered, importing even a single such node makes GET /graph return HTTP 500
    for the entire sketch, so those nodes are dropped and the rest of the scan still
    ingests — the same guard PingCastle's ADRisk nodes get. They are gated
    independently, so a half-registered install still gets whichever type it has.
    The check only runs when we are actually about to write (ingest=True); a dry
    parse should not need the API to be reachable.
    """
    from cloudschism_parser import (
        ATTACK_PATH_NODE_TYPE, FINDING_NODE_TYPE, parse_bytes as parse_cs_bytes,
    )

    allow_findings = allow_paths = True
    guard_errors: List[str] = []
    if ingest:
        registered: List[str] = []
        check_failed = ""
        try:
            import flowsint_client as fc
            # One registry read for both types rather than a round trip each.
            registered = [t.lower() for t in fc.registered_custom_types()]
        except Exception as exc:
            check_failed = f"custom type check failed ({exc})"
        if not check_failed and not registered:
            # registered_custom_types() swallows transport errors and returns []
            # (fail closed), so an empty registry is indistinguishable from an
            # unreachable one — except that a working SPOTTER install has ~15
            # custom types. Say so rather than asserting "not registered".
            check_failed = ("the custom type registry came back empty — it is "
                            "either unreachable or nothing is registered")

        for type_name, attr in ((FINDING_NODE_TYPE, "findings"),
                                (ATTACK_PATH_NODE_TYPE, "attack paths")):
            ok = (not check_failed) and type_name.lower() in registered
            if attr == "findings":
                allow_findings = ok
            else:
                allow_paths = ok
            if not ok:
                guard_errors.append(
                    f"CloudSchism {attr} NOT ingested: "
                    f"{check_failed or f'custom type {type_name!r} is not registered'}. "
                    f"Run scripts/register_cloudschism_type.py --apply, then re-upload. "
                    f"Public endpoints, cloud assets and identities were still imported."
                )

    result = parse_cs_bytes(data, filename=filename,
                            allow_finding_nodes=allow_findings,
                            allow_attack_path_nodes=allow_paths)
    nodes, edges = result.to_flowsint_batch()
    errors = list(result.errors) + guard_errors

    summary = result.summary()
    summary["findings_ingested"] = allow_findings
    summary["attack_paths_ingested"] = allow_paths
    return nodes, edges, errors, summary


def _parse_nmap(data: bytes) -> Tuple[List[dict], List[dict]]:
    """Parse nmap XML (-oX) into IP / Domain / Service nodes."""
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        raise RuntimeError("xml.etree.ElementTree not available")

    root = ET.fromstring(data.decode("utf-8", errors="ignore"))
    nodes: List[dict] = []
    edges: List[dict] = []
    seen: set = set()

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # IP address
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        ip_str = addr_el.get("addr", "")
        host_id = f"ip:{ip_str}"

        # Hostname
        hostnames_el = host.find("hostnames")
        hostname = ""
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                if hn.get("type") == "PTR":
                    hostname = hn.get("name", "")
                    break
            if not hostname:
                hn_el = hostnames_el.find("hostname")
                if hn_el is not None:
                    hostname = hn_el.get("name", "")

        ip_node: Dict[str, Any] = {
            "id": host_id,
            "entity_type": "IP",
            "nodeLabel": ip_str,
            # `address` is Ip's required primary field — without it the node fails
            # validation and the importer drops it silently. `ip` is kept because
            # llm/tools/tech_context_tool.py searches on nodeProperties.ip.
            "data": {"label": ip_str, "type": "IP", "address": ip_str,
                     "ip": ip_str, "source": "nmap"},
            "include": True,
            "node_id": host_id,
        }
        nodes.append(ip_node)

        if hostname:
            dn_id = f"domain:{hostname}"
            if dn_id not in seen:
                seen.add(dn_id)
                nodes.append({
                    "id": dn_id,
                    "entity_type": "Domain",
                    "nodeLabel": hostname,
                    "data": {"label": hostname, "type": "Domain", "domain": hostname, "source": "nmap"},
                    "include": True,
                    "node_id": dn_id,
                })
            edges.append({"from_id": dn_id, "to_id": host_id, "label": "RESOLVES_TO"})

        # Open ports / services
        open_ports = []
        services = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portnum = port.get("portid", "")
                proto   = port.get("protocol", "tcp")
                svc_el  = port.find("service")
                svc_name = svc_el.get("name", "") if svc_el is not None else ""
                prod     = svc_el.get("product", "") if svc_el is not None else ""
                ver      = svc_el.get("version", "") if svc_el is not None else ""
                extra    = svc_el.get("extrainfo", "") if svc_el is not None else ""
                cpe      = svc_el.get("cpe", "") if svc_el is not None else ""

                open_ports.append(f"{portnum}/{proto}")
                svc_display = f"{portnum}/{proto} ({svc_name} {prod} {ver})".strip()
                services.append(svc_display)

                # Create a first-class Service node
                service_id = f"service:{host_id}:{portnum}:{proto}"
                service_node = {
                    "id": service_id,
                    "entity_type": "Service",
                    "nodeLabel": svc_display,
                    "data": {
                        "label": svc_display,
                        "type": "Service",
                        "host_id": host_id,
                        "port": int(portnum) if portnum.isdigit() else portnum,
                        "protocol": proto,
                        "state": "open",
                        "name": svc_name,
                        "product": prod,
                        "version": ver,
                        "extrainfo": extra,
                        "cpe": cpe,
                        "source": "nmap",
                        "confidence": "high" if (prod and ver) else ("medium" if prod else "low"),
                    },
                    "include": True,
                    "node_id": service_id,
                }
                nodes.append(service_node)
                edges.append({"from_id": host_id, "to_id": service_id, "label": "EXPOSES_SERVICE"})

                # Optionally create a Technology node for the identified product
                if prod:
                    tech_name = prod
                    tech_version = ver or None
                    tech_id = f"technology:{tech_name.lower().replace(' ', '_')}:{tech_version or ''}"
                    tech_label = f"{tech_name} {tech_version}".strip() if tech_version else tech_name
                    if tech_id not in seen:
                        seen.add(tech_id)
                        nodes.append({
                            "id": tech_id,
                            "entity_type": "Technology",
                            "nodeLabel": tech_label,
                            "data": {
                                "label": tech_label,
                                "type": "Technology",
                                "name": tech_name,
                                "version": tech_version,
                                "vendor": None,
                                "category": "Service",
                                "source": "nmap",
                                "confidence": "high" if ver else "medium",
                                "is_high_value": False,
                                "cpe": cpe,
                            },
                            "include": True,
                            "node_id": tech_id,
                        })
                    edges.append({"from_id": service_id, "to_id": tech_id, "label": "IMPLEMENTED_IN"})

        # Patch port data into the IP node
        ip_node["data"]["open_ports"] = open_ports
        ip_node["data"]["services"]   = services

    return nodes, edges


def _parse_shareacl(data: bytes) -> Tuple[List[dict], List[dict], List[str]]:
    """Parse ShareACL console output into the existing batch-import shape."""
    from shareacl_normalizer import parse_bof_output_detailed, to_flowsint_batch

    text = data.decode("utf-8", errors="replace")
    records, errors = parse_bof_output_detailed(text)
    if not records and not errors:
        errors.append("ShareACL output contained no share records")
        return [], [], errors
    nodes, edges = to_flowsint_batch(records)
    return nodes, edges, errors


def _parse_amass(data: bytes) -> Tuple[List[dict], List[dict]]:
    """
    Parse amass enum output.

    Supported formats:
      sub.example.com
      sub.example.com --> 1.2.3.4
      sub.example.com --> other.example.com
    """
    nodes: List[dict] = []
    edges: List[dict] = []
    seen: set = set()

    for line in data.decode("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        if "-->" in line:
            src, _, dst = line.partition("-->")
            src = src.strip(); dst = dst.strip()
        else:
            src = line; dst = None

        def add_domain(fqdn: str) -> str:
            nid = f"domain:{fqdn}"
            if nid not in seen:
                seen.add(nid)
                nodes.append({
                    "id": nid,
                    "entity_type": "Domain",
                    "nodeLabel": fqdn,
                    # `domain` is Domain's required primary field (see _parse_nmap).
                    "data": {"label": fqdn, "type": "Domain", "domain": fqdn,
                             "source": "amass"},
                    "include": True,
                    "node_id": nid,
                })
            return nid

        def add_ip(ip: str) -> str:
            nid = f"ip:{ip}"
            if nid not in seen:
                seen.add(nid)
                nodes.append({
                    "id": nid,
                    "entity_type": "IP",
                    "nodeLabel": ip,
                    # `address` is Ip's required primary field (see _parse_nmap).
                    "data": {"label": ip, "type": "IP", "address": ip,
                             "ip": ip, "source": "amass"},
                    "include": True,
                    "node_id": nid,
                })
            return nid

        def add_dns_record(name: str, record_type: str, value: str) -> str:
            nid = f"dns:{name}:{record_type}:{value}"
            if nid not in seen:
                seen.add(nid)
                nodes.append({
                    "id": nid,
                    "entity_type": "DNSRecord",
                    "nodeLabel": f"{record_type} {name}",
                    "data": {
                        "label": f"{record_type} {name}",
                        "type": "DNSRecord",
                        "name": name,
                        "record_type": record_type,
                        "value": value,
                        "source": "amass",
                    },
                    "include": True,
                    "node_id": nid,
                })
            return nid

        src_id = add_domain(src)
        if dst:
            try:
                ipaddress.ip_address(dst)
                dst_id = add_ip(dst)
                edge_label = "RESOLVES_TO"
                record_type = "A"
            except ValueError:
                dst_id = add_domain(dst)
                edge_label = "CNAME_TO"
                record_type = "CNAME"
            edges.append({"from_id": src_id, "to_id": dst_id, "label": edge_label})

            # Create a DNSRecord node and link it to the source domain
            rec_id = add_dns_record(src, record_type, dst)
            edges.append({"from_id": src_id, "to_id": rec_id, "label": "HAS_RECORD"})

    return nodes, edges


def _normalise_fqdn(value: Any) -> str:
    """Return a lower-case FQDN from a host-ish value, or ''."""
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.hostname or ""
    else:
        text = text.split("/", 1)[0]
        if text.startswith("[") and "]" in text:
            text = text[1:text.index("]")]
        elif ":" in text and text.count(":") == 1:
            text = text.rsplit(":", 1)[0]
    text = text.strip().strip(".").lower()
    if text.startswith("*."):
        text = text[2:]
    if not text or not _DOMAIN_RE.match(text):
        return ""
    try:
        ipaddress.ip_address(text)
        return ""
    except ValueError:
        return text


def _subdomain_parent(fqdn: str) -> str:
    parts = [p for p in fqdn.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else ""


def _subdomain_jsonl_host(item: Dict[str, Any]) -> str:
    for key in ("host", "input", "fqdn", "domain", "name"):
        fqdn = _normalise_fqdn(item.get(key))
        if fqdn:
            return fqdn
    return _normalise_fqdn(item.get("url"))


def _iter_jsonl_objects(data: bytes, max_lines: int = MAX_JSON_ITEMS):
    text = _decode_text(data)
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if line_no > max_lines:
            raise ValueError(
                f"JSON-lines item limit exceeded ({max_lines}). "
                "Split the upload into smaller files."
            )
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON object on line {line_no}: {exc.msg}") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"line {line_no} is JSON but not an object")
        yield line_no, obj


def _looks_like_subdomain_jsonl(data: bytes, filename: str = "") -> bool:
    """Recognise subfinder/httpx object-per-line output before weak fallbacks."""
    fname = os.path.basename(filename or "").lower()
    name_hint = any(h in fname for h in ("subfinder", "httpx", "subdomains"))
    text = _decode_text(data[:65536])
    lines = [l.strip() for l in text.splitlines() if l.strip()][:25]
    if not lines or not all(l.startswith("{") for l in lines):
        return False

    parsed = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return name_hint
        if not isinstance(obj, dict):
            return False
        parsed.append(obj)
    host_hits = sum(1 for obj in parsed if _subdomain_jsonl_host(obj))
    if not host_hits:
        return False
    if len(parsed) > 1:
        return True
    return name_hint


def _parse_subdomain_jsonl(data: bytes) -> Tuple[List[dict], List[dict]]:
    """Parse subfinder -oJ / httpx JSON-lines into first-class Subdomain nodes."""
    nodes: List[dict] = []
    seen: set = set()
    parsed_lines = 0

    for line_no, item in _iter_jsonl_objects(data):
        parsed_lines += 1
        fqdn = _subdomain_jsonl_host(item)
        if not fqdn:
            continue
        node_id = f"subdomain:{fqdn}"
        if node_id in seen:
            continue
        seen.add(node_id)
        props: Dict[str, Any] = {
            "fqdn": fqdn,
            "parent_domain": _subdomain_parent(fqdn),
            "discovery_source": item.get("source") or item.get("sources") or "",
            "line": line_no,
        }
        for key in ("url", "scheme", "port", "status_code", "title", "webserver",
                    "tech", "technologies", "ip", "ips", "cdn", "cdn_name"):
            value = item.get(key)
            if value not in (None, "", [], {}):
                props[key] = value
        nodes.append(_typed_node(node_id, "Subdomain", fqdn, props, "subfinder_jsonl"))

    if parsed_lines and not nodes:
        raise ValueError("JSON-lines upload contained no usable subdomain host fields")
    return nodes, []


def _parse_csv(data: bytes) -> Tuple[List[dict], List[dict]]:
    """
    Parse a CSV file of targets.

    Auto-detects column semantics from header row.
    Supported columns: username, sam, samaccountname, email, domain, ip,
                        hostname, hash, ntlm, password, name, fullname
    """
    text = _decode_text(data)
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return [], []

    # Normalise header names
    headers = {h.strip().lower(): h for h in (reader.fieldnames or [])}

    def col(*candidates: str) -> Optional[str]:
        for c in candidates:
            if c in headers:
                return headers[c]
        return None

    nodes: List[dict] = []
    edges: List[dict] = []
    seen: set = set()

    for i, row in enumerate(reader):
        if i >= MAX_CSV_ROWS:
            raise ValueError(
                f"CSV row limit exceeded ({MAX_CSV_ROWS}). "
                "Split the upload into smaller files."
            )

        # Normalise row keys
        row_n = {k.strip().lower(): v.strip() for k, v in row.items() if v}

        username = row_n.get("username") or row_n.get("sam") or row_n.get("samaccountname", "")
        email    = row_n.get("email", "")
        ip_str   = row_n.get("ip", "")
        domain   = row_n.get("domain", "")
        hostname = row_n.get("hostname", "")
        name     = row_n.get("name") or row_n.get("fullname", "")
        passwd   = row_n.get("password", "")
        ntlm     = row_n.get("hash") or row_n.get("ntlm", "")

        if username or email or name:
            label = name or email or username
            nid   = f"individual:{username or email or str(i)}"
            if nid not in seen:
                seen.add(nid)
                nodes.append({
                    "id": nid,
                    "entity_type": "Individual",
                    "nodeLabel": label,
                    "data": {
                        "label": label, "type": "Individual",
                        "username": username, "email": email,
                        "password_hash": ntlm,
                        "cleartext_password": passwd,
                        "source": "csv_upload",
                    },
                    "include": True,
                    "node_id": nid,
                })

        if ip_str:
            ip_id = f"ip:{ip_str}"
            if ip_id not in seen:
                seen.add(ip_id)
                nodes.append({
                    "id": ip_id, "entity_type": "IP", "nodeLabel": ip_str,
                    # `address` is Ip's required primary field (see _parse_nmap).
                    "data": {"label": ip_str, "type": "IP", "address": ip_str,
                             "ip": ip_str, "source": "csv_upload"},
                    "include": True, "node_id": ip_id,
                })

        if domain:
            d_id = f"domain:{domain}"
            if d_id not in seen:
                seen.add(d_id)
                nodes.append({
                    "id": d_id, "entity_type": "Domain", "nodeLabel": domain,
                    # `domain` is Domain's required primary field (see _parse_nmap).
                    "data": {"label": domain, "type": "Domain", "domain": domain,
                             "source": "csv_upload"},
                    "include": True, "node_id": d_id,
                })

    return nodes, edges


# ── Process listings ──────────────────────────────────────────────────────────
#
# Ported from the frontend's parsePastedProcesses(), which used to run in the
# browser on the Ingest tab's Analyst Context box and send bare process names to
# WF12 for the request's lifetime only. Extraction now happens here, once, so the
# names resolve to first-class Technology nodes that persist in the graph — and
# so there is a single implementation to keep correct.

MAX_PROC_HOSTS = int(os.environ.get("SPOTTER_UPLOAD_MAX_PROC_HOSTS", "200"))
MAX_PROC_NAMES = int(os.environ.get("SPOTTER_UPLOAD_MAX_PROC_NAMES", "2000"))

_PROC_HOST_RE = re.compile(
    r"^\s*(?:host(?:name)?|computer(?:name)?|beacon|target)\s*[:=]\s*([A-Za-z0-9._-]+)", re.I)
_PROC_PROMPT_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]{1,60})\s*[>:]\s*$")
_PROC_GP_HDR_RE = re.compile(r"Handles\s+NPM\(K\)", re.I)
# Any .exe token anywhere on the line. This one rule covers tasklist (table and
# /fo csv), beacon/badger ps, wmic and bare lists, and it will not fire on prose.
_PROC_EXE_RE = re.compile(r"[A-Za-z0-9_.+()\[\]-]+\.exe\b", re.I)
# ps aux / ps -ef: the command follows the TIME column (0:14, 00:00:14).
_PROC_TIME_RE = re.compile(r"^\d{1,4}:\d{2}(?::\d{2})?$")
_PROC_NAME_RE = re.compile(r"^[\w.+()\[\]-]{2,60}$")
_PROC_TASKLIST_HDR_RE = re.compile(r"^image\s+name\s", re.I)
_PROC_SEP_RE = re.compile(r"^[-=\s]+$")

# "tasklist from WS-014", "ps output on srv01.corp.local"
_CTX_HOST_RE = re.compile(
    r"\b(?:on|from|for|host|hostname|computer|beacon|target)\s+(?:host\s+)?"
    r"([A-Za-z0-9][A-Za-z0-9._-]{1,60})", re.I)
_CTX_HOST_STOPWORDS = frozenset({
    "the", "a", "an", "this", "that", "my", "our", "their", "one", "some",
    "host", "hostname", "machine", "box", "system", "server", "workstation",
    "target", "beacon", "computer", "domain", "network", "client", "lab",
})


def _hostname_from_context(context: str) -> str:
    """
    Pull a hostname out of the analyst's description of the paste.

    A listing with no host header ("tasklist from WS-014" over bare output) would
    otherwise produce technologies attached to nothing. Only host-shaped tokens
    qualify — a digit, a hyphen, a dot, or all-caps — so ordinary prose
    ("processes from the jump box") yields nothing rather than a node named "the".
    """
    for m in _CTX_HOST_RE.finditer(context or ""):
        cand = m.group(1).strip(".,;:")
        if not cand or cand.lower() in _CTX_HOST_STOPWORDS:
            continue
        if any(c.isdigit() for c in cand) or "-" in cand or "." in cand or cand.isupper():
            return cand
    return ""


def _extract_process_hosts(text: str) -> Tuple[List[Tuple[str, List[str]]], int]:
    """
    Group process names by host. Returns ([(host, [names]), ...], total_names).

    `host` is "" for names found before any host marker. Order is preserved so
    the caller's node ids stay stable across re-uploads of the same listing.
    """
    sections: Dict[str, List[str]] = {}
    seen_per_host: Dict[str, set] = {}
    current = ""
    in_get_process = False
    total = 0

    def add(proc: str) -> None:
        nonlocal total
        if not proc or total >= MAX_PROC_NAMES:
            return
        if current not in sections:
            if len(sections) >= MAX_PROC_HOSTS:
                return
            sections[current] = []
            seen_per_host[current] = set()
        key = proc.lower()
        if key not in seen_per_host[current]:
            seen_per_host[current].add(key)
            sections[current].append(proc)
            total += 1

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        host_m = _PROC_HOST_RE.match(line) or _PROC_PROMPT_RE.match(line)
        if host_m:
            current = host_m.group(1)
            in_get_process = False
            continue

        if _PROC_GP_HDR_RE.search(line):
            in_get_process = True
            continue
        if _PROC_SEP_RE.match(line):            # ==== / ---- separator rules
            continue
        if _PROC_TASKLIST_HDR_RE.match(line):   # tasklist header
            continue

        exe_matches = _PROC_EXE_RE.findall(line)
        if exe_matches:
            for m in exe_matches:
                add(re.split(r"[\\/]", m)[-1].strip())
            continue

        cols = line.split()

        # Get-Process: after its header the LAST field is the name, minus .exe.
        if in_get_process:
            if (len(cols) >= 5 and _PROC_NAME_RE.match(cols[-1])
                    and not _PROC_TIME_RE.match(cols[-1])):
                add(cols[-1] + ".exe")
            continue

        # Unix ps. Anchored on a numeric PID in column 2 AND a TIME column, so a
        # sentence of prose cannot satisfy it: the command is the token after TIME.
        if len(cols) >= 8 and cols[1].isdigit():
            # The LAST time-shaped column, not the first: ps aux has START before
            # TIME (Jul22 / 10:02, then 0:14) and ps -ef has STIME before TIME.
            t = -1
            for i in range(len(cols) - 2, 0, -1):
                if _PROC_TIME_RE.match(cols[i]):
                    t = i
                    break
            if t > 0 and t + 1 < len(cols):
                cmd = re.split(r"[\\/]", cols[t + 1])[-1].rstrip(":,;.")
                if cmd and _PROC_NAME_RE.match(cmd) and not cmd.isdigit():
                    add(cmd)

    return list(sections.items()), total


def _parse_process_list(
    data: bytes, context: str = ""
) -> Tuple[List[dict], List[dict], List[str]]:
    """
    Parse any process listing (tasklist, Get-Process, beacon/badger ps, ps aux)
    into Device + Technology nodes joined by USES_TECH.

    Process name → technology comes from c2_common.PROCESS_TECH_MAP, reached via
    cobalt_normalizer's re-export — the same route WF12 uses. Never re-derive
    those ~180 patterns here.
    """
    from cobalt_normalizer import (
        categorize_tech_stack,
        get_high_value_tech,
        infer_tech_stack,
    )

    hosts, total = _extract_process_hosts(_decode_text(data))
    errors: List[str] = []
    if not total:
        return [], [], ["No process names found in the upload."]

    ctx_host = _hostname_from_context(context)
    nodes: List[dict] = []
    edges: List[dict] = []
    seen_tech: Dict[str, str] = {}   # tech name (lower) → node id

    for host, procs in hosts:
        hostname = host or ctx_host
        tech_stack = infer_tech_stack(procs)
        hv_tech = set(get_high_value_tech(tech_stack))
        categories = categorize_tech_stack(tech_stack)
        tech_category = {t: cat for cat, techs in categories.items() for t in techs}

        device_id = ""
        if hostname:
            device_id = f"device:{hostname.lower()}"
            nodes.append({
                "id": device_id,
                "entity_type": "Device",
                "nodeLabel": hostname,
                "data": {
                    "label": hostname,
                    "type": "Device",
                    # `device_id` is Device's REQUIRED primary field. A built-in
                    # node missing its required field is dropped by the importer
                    # without a word (see ENTITY_PRIMARY_FIELD).
                    "device_id": hostname,
                    "hostname": hostname,
                    # JSON strings, matching how WF12 already reads process_list
                    # and tech_stack off beacon/individual props.
                    "process_list": json.dumps(procs),
                    "tech_stack": json.dumps(tech_stack),
                    "process_count": len(procs),
                    "source": "process_list",
                    # WF12's "hosts in use" filter prunes any device with no
                    # activity evidence, and on an AD-sized sketch it runs in
                    # strict mode — so a host known only from a process listing
                    # would be dropped from the whole inventory as stale. A
                    # listing IS the observation: we saw these processes running
                    # now. Stamp it so the host reads as seen, the same shape
                    # backfill_device_activity.py writes.
                    "last_activity_ts": int(time.time()),
                    "activity_source": "process_list",
                },
                "include": True,
                "node_id": device_id,
            })
        elif tech_stack:
            errors.append(
                f"{len(procs)} process names had no host: no host header in the "
                f"listing and none named in the context. Technologies imported "
                f"unattached — add \"from <hostname>\" to the Context field to link them."
            )

        for tech in tech_stack:
            if not tech:
                continue
            key = tech.lower()
            tech_id = seen_tech.get(key)
            if not tech_id:
                tech_id = f"technology:{key.replace(' ', '_')}"
                seen_tech[key] = tech_id
                nodes.append({
                    "id": tech_id,
                    "entity_type": "Technology",
                    "nodeLabel": tech,
                    "data": {
                        "label": tech,
                        "type": "Technology",
                        # `name` is REQUIRED on the built-in Technology type. A
                        # name-less Technology node makes GET /graph return 500
                        # for the ENTIRE sketch, not just that node.
                        "name": tech,
                        "category": tech_category.get(tech, ""),
                        "source": "process_list",
                        "confidence": "medium",
                        "is_high_value": tech in hv_tech,
                    },
                    "include": True,
                    "node_id": tech_id,
                })
            if device_id:
                # USES_TECH is the label WF01/WF21 already write for this
                # relationship. Do not coin a variant.
                edges.append({"from_id": device_id, "to_id": tech_id, "label": "USES_TECH"})

    return nodes, edges, errors


# ── Entity typing ─────────────────────────────────────────────────────────────
#
# Flowsint resolves a node's entity_type against its type registry and RAISES on
# an unknown one. The importer catches that per node, so an unresolvable type is
# not an error the caller sees — the node is simply never created. Emitting
# "Unknown" (as this module used to for every raw-JSON upload) therefore meant a
# silent 100% drop rate.
#
# Each type also has a REQUIRED primary field. A node that resolves but omits it
# fails Pydantic validation and is dropped just as quietly, so the primary field
# is filled here rather than left to the caller.

ENTITY_PRIMARY_FIELD: Dict[str, str] = {
    # Built-in flowsint_types (name → its required primary field).
    # Individual maps to "" on purpose: it is the one type with no required field,
    # and force-filling full_name with an email or a sAMAccountName would put a
    # value in the graph that is not a person's name.
    "Individual":     "",
    "Organization":   "name",
    "Device":         "device_id",
    "Domain":         "domain",
    "Ip":             "address",
    "Email":          "email",
    "Username":       "value",
    "Phone":          "number",
    "Website":        "url",
    "Technology":     "name",
    "Credential":     "username",
    "Port":           "number",
    "File":           "filename",
    "Document":       "title",
    "Breach":         "name",
    "Leak":           "name",
    "Malware":        "name",
    "Alias":          "alias",
    "Phrase":         "text",
}

# SPOTTER's own registered types, and the field that identifies each one. These
# are DB-registered custom types, which Flowsint rebuilds with every declared
# property as Optional[str] — so none of them has a *required* field and a node
# missing one still imports. The field is filled anyway to keep the node useful;
# it just is not a correctness requirement the way the built-ins above are.
CUSTOM_ENTITY_FIELD: Dict[str, str] = {
    "Service":        "name",
    "Subdomain":      "fqdn",
    "WebAsset":       "url",
    "CloudAsset":     "bucket",
    "DomainBreach":   "domain",
    "FlareBreach":    "breach_id",
    "SocialProfile":  "profile_url",
    "FileShare":      "share_path",
    "CertTemplate":   "name",
    "EnterpriseCA":   "name",
    "ADRisk":         "risk_id",
    "GPO":            "sid",
    "C2Session":      "session_key",
    "Vulnerability":  "plugin_id",
}

# Accepted spellings for an explicit "type" field, mapped to the canonical name.
# Matching is case-insensitive; "IP" and "DNSRecord" are the spellings the other
# parsers in this module already emit.
_TYPE_ALIASES: Dict[str, str] = {
    "ip": "Ip", "ipaddress": "Ip", "ip_address": "Ip", "ipv4": "Ip", "ipv6": "Ip",
    "person": "Individual", "user": "Individual", "individual": "Individual",
    "org": "Organization", "company": "Organization", "group": "Organization",
    "computer": "Device", "host": "Device", "machine": "Device",
    "fqdn": "Domain", "hostname": "Domain", "dnsrecord": "DNSRecord",
    "url": "Website", "site": "Website", "web": "Website",
    "mail": "Email", "email_address": "Email",
    "tech": "Technology", "product": "Technology", "software": "Technology",
}

# Registered types this module can emit or accept but never needs to key.
_EXTRA_TYPES = ("DNSRecord", "Port", "SocialAccount", "SSLCertificate", "Session")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_URL_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]+\.)+[A-Za-z]{2,}$")

# Field names that mark an item as being ABOUT a person. Checked before the
# address-shaped keys so {"username": ..., "email": ...} becomes one Individual
# carrying an email, exactly as the CSV parser treats the same columns.
_PERSON_KEYS = ("username", "sam", "samaccountname", "email", "full_name",
                "fullname", "first_name", "last_name", "displayname",
                "display_name", "upn", "userprincipalname")
_DEVICE_KEYS = ("device_id", "hostname", "dnshostname", "mac_address",
                "operating_system", "operatingsystem", "os")
_ORG_KEYS = ("organization", "org", "company", "group_name")


def canonical_entity_type(name: str) -> str:
    """Map a user-supplied type name to a canonical Flowsint type, or '' if unknown."""
    key = str(name or "").strip().lower().replace(" ", "").replace("-", "")
    if not key:
        return ""
    if key in _TYPE_ALIASES:
        return _TYPE_ALIASES[key]
    for canonical in (*ENTITY_PRIMARY_FIELD, *CUSTOM_ENTITY_FIELD, *_EXTRA_TYPES):
        if canonical.lower() == key:
            return canonical
    return ""


def identifying_field(entity_type: str) -> str:
    """The field that keys `entity_type`, whether it is built-in or custom."""
    return (ENTITY_PRIMARY_FIELD.get(entity_type)
            or CUSTOM_ENTITY_FIELD.get(entity_type, ""))


# Email's EmailStr rejects special-use TLDs, so ops@corp.local — the normal shape
# of an internal AD address — cannot be stored as an Email node at all. Engagements
# live in exactly those domains, so a bare address is inferred as the Individual it
# identifies (carrying `email`), which is also how the CSV parser treats the column.
_SPECIAL_USE_TLDS = frozenset({"local", "localhost", "test", "invalid", "example",
                               "lan", "home", "internal", "corp", "intranet"})


def email_is_storable(address: str) -> bool:
    """False when Flowsint's Email type would reject the address outright."""
    tld = str(address).rsplit("@", 1)[-1].rsplit(".", 1)[-1].strip().lower()
    return bool(tld) and tld not in _SPECIAL_USE_TLDS


def _sniff_scalar(value: Any) -> Tuple[str, str, Dict[str, Any]]:
    """
    Classify a bare scalar.

    Returns (canonical_type, primary_value, extra_properties); Phrase when nothing
    matches, so an unrecognised value still lands instead of being dropped.
    """
    text = str(value).strip()
    if not text:
        return "Phrase", text, {}
    if _EMAIL_RE.match(text):
        if email_is_storable(text):
            return "Email", text, {}
        return "Individual", text, {"email": text}
    if _URL_RE.match(text):
        return "Website", text, {}
    try:
        ipaddress.ip_address(text)
        return "Ip", text, {}
    except ValueError:
        pass
    if _DOMAIN_RE.match(text):
        return "Domain", text, {}
    return "Phrase", text, {}


def infer_entity_type(item: Dict[str, Any]) -> Tuple[str, str]:
    """
    Work out what a raw JSON object describes.

    Returns (canonical_type, primary_value). Falls back to Phrase — a real
    registered type — so an item that matches nothing still lands in the graph
    instead of being silently discarded.
    """
    keys = {str(k).strip().lower(): v for k, v in item.items()
            if v not in (None, "", [], {})}

    def first(*names: str) -> str:
        for n in names:
            val = keys.get(n)
            if isinstance(val, (str, int, float)) and str(val).strip():
                return str(val).strip()
        return ""

    if any(k in keys for k in _PERSON_KEYS):
        label = first("full_name", "fullname", "display_name", "displayname",
                      "name", "email", "username", "sam", "samaccountname", "upn")
        return "Individual", label
    # Device before Ip: a record carrying a hostname or an OS *plus* an address is
    # a machine with an IP, not an IP that happens to have a name.
    if any(k in keys for k in _DEVICE_KEYS):
        return "Device", first("device_id", "hostname", "dnshostname", "name")
    ip_val = first("ip", "address", "ip_address", "ipaddress")
    if ip_val:
        try:
            ipaddress.ip_address(ip_val)
            return "Ip", ip_val
        except ValueError:
            pass
    url_val = first("url", "link")
    if url_val:
        return "Website", url_val
    domain_val = first("domain", "fqdn", "dns_name")
    if domain_val:
        return "Domain", domain_val
    if any(k in keys for k in _ORG_KEYS):
        return "Organization", first("organization", "org", "company", "group_name", "name")
    phone_val = first("phone", "phone_number", "mobile", "telephone")
    if phone_val:
        return "Phone", phone_val
    if "technology" in keys or "product" in keys:
        return "Technology", first("technology", "product", "name")

    # No recognised key. A single scalar field is worth sniffing on its value.
    scalars = [v for v in keys.values() if isinstance(v, (str, int, float))]
    if len(scalars) == 1:
        entity_type, primary, _extra = _sniff_scalar(scalars[0])
        return entity_type, primary
    return "Phrase", json.dumps(item, sort_keys=True, default=str)[:500]


def _typed_node(node_id: str, entity_type: str, primary_value: str,
                properties: Dict[str, Any], source: str) -> dict:
    """Build one import-ready node with its type's required primary field filled."""
    primary_field = identifying_field(entity_type)
    label = str(primary_value or properties.get("label") or node_id)
    data: Dict[str, Any] = {
        **properties,
        "label": label,
        "nodeLabel": label,
        "type": entity_type,
        "source": properties.get("source") or source,
    }
    if primary_field and not data.get(primary_field):
        data[primary_field] = primary_value or label
    return {
        "id": node_id,
        "entity_type": entity_type,
        "nodeLabel": label,
        "data": data,
        "include": True,
        "node_id": node_id,
    }


def _parse_json_generic(data: bytes) -> Tuple[List[dict], List[dict]]:
    """
    Accept a raw JSON dict, list of dicts, or list of scalars and normalise it to
    SPOTTER entity format.

    An explicit "type"/"entity_type" is honoured when it names a real Flowsint
    type; otherwise the object's fields decide (see infer_entity_type). Nothing
    is ever emitted as "Unknown" — that resolves to no type at all and the
    importer drops it without creating a node.
    """
    obj = json.loads(data)
    if isinstance(obj, dict):
        # {"nodes": [...]} / {"data": [...]} / {"results": [...]} wrappers
        for wrapper in ("nodes", "entities", "data", "results", "items"):
            inner = obj.get(wrapper)
            if isinstance(inner, list):
                obj = inner
                break
        else:
            obj = [obj]

    if not isinstance(obj, list):
        obj = [obj]

    if len(obj) > MAX_JSON_ITEMS:
        raise ValueError(
            f"JSON entity count exceeds limit ({MAX_JSON_ITEMS}). "
            "Split the payload into smaller batches."
        )

    nodes: List[dict] = []
    for i, item in enumerate(obj):
        nid = f"json:{i}"

        if not isinstance(item, dict):
            entity_type, primary, extra = _sniff_scalar(item)
            nodes.append(_typed_node(nid, entity_type, primary, extra, "json_upload"))
            continue

        item = dict(item)  # never mutate the caller's payload
        declared = item.pop("type", None) or item.pop("entity_type", None)
        label = item.pop("label", None) or item.pop("nodeLabel", None)

        entity_type = canonical_entity_type(declared) if declared else ""
        if entity_type:
            primary_field = identifying_field(entity_type)
            primary = str(item.get(primary_field) or label or item.get("name") or "")
            if entity_type == "Email" and primary and not email_is_storable(primary):
                # Honouring the declared type here would mean losing the row.
                entity_type = "Individual"
                item.setdefault("email", primary)
                item["declared_type"] = "Email"
            if not primary:
                # Declared type we cannot key — infer instead of emitting a node
                # that would fail validation and vanish.
                entity_type, primary = infer_entity_type(item)
        else:
            entity_type, primary = infer_entity_type(item)
            if declared:
                # Keep the caller's word for it without letting it break the import.
                item["declared_type"] = str(declared)

        if label and not primary:
            primary = str(label)
        if label:
            item.setdefault("original_label", str(label))

        nodes.append(_typed_node(nid, entity_type, primary, item, "json_upload"))

    return nodes, []


def _parse_text_via_llm(text: str, context: str = "") -> Tuple[List[dict], List[dict]]:
    """
    Use the configured LLM backend to extract entities from unstructured text.
    Falls back to empty lists if the backend is not reachable.

    `context` is the analyst's own description of the payload, from the Ingest
    tab's Context field. It is prepended to the prompt so the model knows what it
    is looking at — an unlabelled column of names is a very different extraction
    depending on whether the operator called it a user list or a host list.
    """
    backend = os.environ.get("SPOTTER_LLM_BACKEND", "vllm").strip().lower()
    model = os.environ.get("EXTRACTION_LLM_MODEL", "Qwen/Qwen3.8-27B-FP8")
    ctx_line = (
        "The analyst describes this data as: "
        + " ".join((context or "").split())[:500] + "\n"
    ) if context else ""
    prompt = (
        "You are a cybersecurity data extraction assistant. "
        + ctx_line +
        "Extract all named entities from the following text and return a JSON array. "
        # Device and Technology are in the list because the analyst's context can
        # identify hosts and software that the type sniffer alone cannot; without
        # them the model has nowhere to put a hostname and drops it.
        "Each item must have: {\"type\": \"IP|Domain|Individual|Email|URL|Device|Technology\", "
        "\"label\": \"...\", \"raw\": \"...\"}. "
        "Return ONLY valid JSON, no explanation.\n\nText:\n" + text[:4000]
    )
    try:
        import requests as _req
        if backend == "vllm":
            base_url = os.environ.get("VLLM_URL", "http://vllm:8000/v1").rstrip("/")
            # No hardcoded fallback: signing with a credential published in
            # this repo would let a dropped secret pass unnoticed. Same guard as
            # llm_client._vllm_api_key(), inlined because the two modules are
            # loaded independently by the runner.
            _vk = (os.environ.get("VLLM_API_KEY") or "").strip()
            if not _vk:
                raise RuntimeError(
                    "VLLM_API_KEY is unset -- refusing to call the vLLM backend "
                    "with a default credential. Check .env and the Python runner's "
                    "allowed-env list in deployment/n8n-task-runners.json."
                )
            headers = {"Authorization": f"Bearer {_vk}"}
            resp = _req.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json={
                    "model": os.environ.get("VLLM_MODEL", model),
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "temperature": 0,
                },
                timeout=30,
            )
        else:
            resp = _req.post(
                f"{os.environ.get('OLLAMA_URL', 'http://llm-gateway:8080').rstrip('/')}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=30,
            )
        resp.raise_for_status()
        response_data = resp.json()
        if backend == "vllm":
            choices = response_data.get("choices") or []
            message = choices[0].get("message") if choices and isinstance(choices[0], dict) else {}
            raw_response = message.get("content", "[]") if isinstance(message, dict) else "[]"
        else:
            raw_response = response_data.get("response", "[]")
        entities = json.loads(raw_response)
        nodes = []
        for i, ent in enumerate(entities):
            if not isinstance(ent, dict):
                continue
            label = str(ent.get("label", "")).strip()
            if not label:
                continue
            # The model is asked for a type but is free to invent one, and an
            # unresolvable entity_type is dropped by the importer without a word.
            # Canonicalise it; sniff the label itself when it does not map.
            entity_type = canonical_entity_type(ent.get("type", ""))
            extra: Dict[str, Any] = {}
            if not entity_type or entity_type == "Email":
                entity_type, label, extra = _sniff_scalar(label)
            nodes.append(_typed_node(
                f"llm:{i}", entity_type, label,
                {**extra, "raw": ent.get("raw", ""),
                 "declared_type": str(ent.get("type", "")),
                 "confidence": "low",
                 "review_status": "needs_review",
                 "extraction_method": "llm_text"},
                "llm_extraction",
            ))
        return nodes, []
    except Exception as e:
        print(f"[upload_router] LLM extraction failed: {e}", file=sys.stderr)
        return [], []


# ── Node normalisation ────────────────────────────────────────────────────────

def _ensure_node_labels(nodes: List[dict]) -> int:
    """
    Mirror each node's top-level `nodeLabel` into its `data` dict.

    Flowsint MERGEs on the *Pydantic model's* nodeLabel field, which is populated
    from `data` — the top-level key is only used for import error messages. A node
    whose `data` carries `label` but not `nodeLabel` therefore imports with an
    empty MERGE key, so **every such node of the same type collapses into one
    blank-labelled node**. Observed 2026-08-06: a two-row CSV upload landed as a
    single `individual` with nodeLabel ''.

    Types whose model derives nodeLabel from a primary field (Domain, Ip, …) hid
    the bug; Individual and the other label-less models did not.

    Returns the number of nodes repaired. Idempotent: parsers that already set
    data['nodeLabel'] (sharphound_parser, pingcastle_parser) are left untouched.
    """
    repaired = 0
    for node in nodes:
        data = node.get("data")
        if not isinstance(data, dict):
            continue
        if data.get("nodeLabel"):
            continue
        label = node.get("nodeLabel") or data.get("label") or ""
        if label:
            data["nodeLabel"] = label
            repaired += 1
    return repaired


# ── Main router ───────────────────────────────────────────────────────────────

def detect_format_path(path: str, filename: str = "", max_read: Optional[int] = None) -> str:
    """Classify a file on disk without putting its bytes on an n8n item.

    Zips are classified from the central directory. A non-zip at or under
    `max_read` is read in full so JSON formats stay correct. A larger non-zip
    is sniffed from the first 1 MB — the caller is about to refuse it rather
    than parse it.
    """
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if magic[:2] == b"PK":
        try:
            with zipfile.ZipFile(path) as zf:
                return _format_from_zip_names(zf.namelist())
        except Exception:
            return "zip_unknown"
    ceiling = size if max_read is None else int(max_read)
    if size <= ceiling:
        with open(path, "rb") as fh:
            return detect_format(fh.read(), filename)
    with open(path, "rb") as fh:
        return detect_format(fh.read(1024 * 1024), filename)


def route_bytes(
    data: bytes,
    filename: str = "",
    ingest: bool = False,
    sketch_id: Optional[str] = None,
    context: str = "",
    max_bytes: Optional[int] = None,
    source_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Detect format, parse, and optionally ingest into Flowsint.

    `context` is the analyst's free-text description of the payload from the
    Ingest tab's Context field. It re-routes a weakly-detected upload (see
    hint_format), steers LLM extraction of formless text, and is stamped onto
    every parsed node as provenance.

    Returns:
      {
        "format": str,
        "nodes": [...],
        "edges": [...],
        "nodes_count": int,
        "edges_count": int,
        "ingestion": {...} | None,
        "errors": [...],
        "report": {...},      # format-specific summary (PingCastle scores/risks,
                              # Nessus severity counts + ranked findings)
      }
    """
    # Default stays the JSON-body cap. A staged file passes the runner cap
    # explicitly; raising the default would let a one-shot body skip Detect Format.
    limit = MAX_UPLOAD_BYTES if max_bytes is None else int(max_bytes)
    if len(data) > limit:
        return {
            "format": "oversize",
            "nodes": [],
            "edges": [],
            "nodes_count": 0,
            "edges_count": 0,
            "ingestion": None,
            "errors": [
                f"Upload is too large ({len(data)} bytes). "
                f"Max allowed is {limit} bytes."
            ],
            "ingest_ok": False,
        }

    fmt = detect_format(data, filename)
    # Bytes first, prose second: only the weak verdicts are open to a hint, and
    # the hint must be corroborated by the payload. Applied here rather than in
    # WF06 alone so the CLI and route_file() reach the same decision.
    if context and fmt in WEAK_FORMATS:
        fmt = hint_format(context, data, fmt)

    # A password-protected archive parses to nothing. Detection still succeeds
    # (member names are stored in the clear), so without this the upload runs
    # the full pipeline and reports a zero-node success -- indistinguishable
    # from a scan that genuinely found nothing. Fail loudly instead.
    enc_members, total_members = zip_encryption(data)
    if total_members and enc_members == total_members:
        return {
            "format": fmt,
            "nodes": [],
            "edges": [],
            "nodes_count": 0,
            "edges_count": 0,
            "ingestion": None,
            "errors": [
                f"Archive is password-protected: all {total_members} files inside "
                f"are encrypted, so nothing could be read. Detected as {fmt!r} from "
                f"the member names only. Re-upload the scan output zipped WITHOUT "
                f"a password (the artifacts themselves are what SPOTTER parses)."
            ],
            "ingest_ok": False,
        }

    errors: List[str] = []
    nodes: List[dict] = []
    edges: List[dict] = []
    report: Optional[Dict[str, Any]] = None

    # Partially encrypted: the readable members still parse, but say what was
    # skipped rather than letting the shortfall read as "the scan found less".
    if enc_members:
        errors.append(
            f"{enc_members} of {total_members} files in this archive are "
            f"password-protected and were skipped. Only the readable members "
            f"were parsed."
        )

    try:
        if fmt == "sharphound":
            nodes, edges = _parse_sharphound(data, filename)
        elif fmt == "shareacl":
            nodes, edges, shareacl_errors = _parse_shareacl(data)
            errors.extend(shareacl_errors)
        elif fmt == "cloudschism":
            nodes, edges, cs_errors, report = _parse_cloudschism(data, filename, ingest)
            errors.extend(cs_errors)
        elif fmt == "pingcastle":
            nodes, edges, pc_errors, report = _parse_pingcastle(data, filename, ingest)
            errors.extend(pc_errors)
        elif fmt == "nessus":
            nodes, edges, ns_errors, report = _parse_nessus(data, filename, ingest)
            errors.extend(ns_errors)
        elif fmt == "eyewitness":
            nodes, edges, ew_errors, report = _parse_eyewitness(
                data, filename, ingest, sketch_id)
            errors.extend(ew_errors)
        elif fmt == "nmap":
            nodes, edges = _parse_nmap(data)
        elif fmt == "amass":
            nodes, edges = _parse_amass(data)
        elif fmt == "subdomain_jsonl":
            nodes, edges = _parse_subdomain_jsonl(data)
        elif fmt == "csv":
            nodes, edges = _parse_csv(data)
        elif fmt in ("cobalt", "cobalt_log"):
            # Delegate to cobalt_normalizer
            import cobalt_normalizer as cn
            if fmt == "cobalt":
                raw_beacons = json.loads(data)
                if isinstance(raw_beacons, dict):
                    raw_beacons = raw_beacons.get("beacons", [raw_beacons])
            else:
                raw_beacons = []  # log-format parsing is complex; return empty for now
                errors.append("Cobalt Strike plain log parsing not yet implemented; upload JSON export instead.")
            for i, b in enumerate(raw_beacons):
                norm = cn.normalise_beacon(b)
                nid = f"beacon:{norm['session_id'] or i}"
                nodes.append({
                    "id": nid,
                    "entity_type": "C2Session",
                    "nodeLabel": f"Beacon@{norm['hostname']}",
                    "data": {**norm, "label": norm["hostname"], "type": "C2Session"},
                    "include": True,
                    "node_id": nid,
                })
        elif fmt == "json":
            nodes, edges = _parse_json_generic(data)
        elif fmt == "process_list":
            nodes, edges, proc_errors = _parse_process_list(data, context)
            errors.extend(proc_errors)
        elif fmt == "zip_unknown":
            errors.append(
                "Archive format was not recognized. Nothing was ingested; re-upload a "
                "supported scanner export or add a parser for this archive type."
            )
        else:
            # Plain text → LLM extraction
            nodes, edges = _parse_text_via_llm(
                data.decode("utf-8", errors="ignore"), context=context)
            fmt = "text_llm"
            report = {
                "extraction_method": "llm_text",
                "review_required": True,
                "review_status": "needs_review",
                "ingest_mode": _llm_text_ingest_mode(),
                "note": (
                    "Plain-text LLM extraction is low-confidence. Review these "
                    "entities before treating them as scanner-backed facts."
                ),
            }
    except Exception as e:
        errors.append(f"Parse error for format '{fmt}': {e}")

    # Applies to every format, so a parser that forgets data['nodeLabel'] cannot
    # silently collapse its whole output into one blank node.
    _ensure_node_labels(nodes)

    # Provenance: which upload, and what the analyst said it was. Answers "where
    # did this node come from" months later without a separate audit store.
    if context:
        _ctx = " ".join(context.split())[:2000]
        for _n in nodes:
            if isinstance(_n.get("data"), dict):
                _n["data"].setdefault("ingest_context", _ctx)

    result: Dict[str, Any] = {
        "format":       fmt,
        "nodes":        nodes,
        "edges":        edges,
        "nodes_count":  len(nodes),
        "edges_count":  len(edges),
        "ingestion":    None,
        "errors":       errors,
    }
    if report is not None:
        # Scores / risk summary the dossier and alerting paths surface without
        # having to re-read the graph.
        result["report"] = report

    if ingest and fmt == "text_llm" and _llm_text_ingest_mode() in LLM_TEXT_PREVIEW_MODES:
        result["ingestion"] = {
            "skipped": True,
            "reason": "SPOTTER_LLM_TEXT_INGEST_MODE is set to preview/quarantine",
        }
        result["ingest_ok"] = False
        return result

    if ingest and nodes:
        try:
            import flowsint_client as fc
            ingestion = fc.batch_import(nodes, edges, sketch_id=sketch_id)
            result["ingestion"] = ingestion
            created = ingestion.get("nodes_created", 0)
            # Loud failure signal: parsed nodes but none landed → import was rejected.
            # Callers (WF06 / frontend) use ingest_ok to avoid reporting a silent success
            # and to skip firing enrichment against an empty graph.
            result["ingest_ok"] = created > 0
            if created == 0:
                result["errors"].append(
                    f"Ingest produced 0 nodes from {len(nodes)} parsed entities — "
                    f"import rejected; graph NOT updated. See ingestion.errors for detail."
                )
        except Exception as e:
            result["ingest_ok"] = False
            result["errors"].append(f"Ingestion error: {e}")
    elif ingest:
        result["ingest_ok"] = False

    # A staged file is deleted only after a successful import. A failure leaves
    # it on disk so the operator can retry without uploading it again. Paths
    # outside the staging root are ignored. This must not be an elif of the
    # import branch: a normal JSON upload has no source_path, and attaching
    # the elif there cleared ingest_ok on every successful import.
    if source_path and result.get("ingest_ok"):
        try:
            from ingest_staging import release_staged
            release_staged(source_path)
        except Exception:
            pass

    return result


def route_file(
    path: str,
    ingest: bool = False,
    sketch_id: Optional[str] = None,
    context: str = "",
) -> Dict[str, Any]:
    with open(path, "rb") as f:
        data = f.read()
    return route_bytes(data, filename=os.path.basename(path),
                       ingest=ingest, sketch_id=sketch_id, context=context)


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    # --context "tasklist from WS-014" — same hint the Ingest tab's field supplies.
    # Consumed here rather than filtered on "--" so its value is not mistaken for
    # the file path.
    ingest_flag = "--ingest" in sys.argv
    cli_context = ""
    positional: List[str] = []
    _rest = sys.argv[1:]
    while _rest:
        _a = _rest.pop(0)
        if _a == "--context":
            cli_context = _rest.pop(0) if _rest else ""
        elif _a.startswith("--context="):
            cli_context = _a.split("=", 1)[1]
        elif not _a.startswith("--"):
            positional.append(_a)
    path = positional[0] if positional else None

    if path:
        res = route_file(path, ingest=ingest_flag, context=cli_context)
    else:
        data = sys.stdin.buffer.read()
        res = route_bytes(data, ingest=ingest_flag, context=cli_context)

    print(json.dumps({k: v for k, v in res.items() if k != "nodes" and k != "edges"}, indent=2))
    print(f"Nodes: {res['nodes_count']}, Edges: {res['edges_count']}")
    if res["errors"]:
        print("Errors:", res["errors"])
