"""
pingcastle_parser.py — PingCastle Active Directory health-check report parser.

Turns a PingCastle **health check** report into SPOTTER's canonical entity /
relationship lists, the same shape `sharphound_parser.py` produces, so the two
data sets land on the *same* graph nodes instead of duplicating them.

Accepted inputs (PingCastle 2.x / 3.x, `PingCastle.exe --healthcheck`):

    ad_hc_<domain>.xml    machine-readable report  (XmlSerializer of HealthcheckData)
    ad_hc_<domain>.json   same data, JSON-serialised

Not accepted (reported as a parse error rather than silently ingesting nothing):

    ad_hc_<domain>.html   the human report — no structured data to lift
    encrypted reports     root element <EncryptedData>; decrypt before upload
    cloud / Azure AD reports, ad_carto_* cartography, consolidated reports

Merging with SharpHound
───────────────────────
Flowsint MERGEs on ``(node_type, nodeLabel, sketch_id)``, so a PingCastle entity
merges into an existing SharpHound entity only if its label matches *exactly*.
BloodHound labels everything uppercase, so this parser does too:

    domain            CORP.LOCAL                 (SharpHound: domains.json name)
    domain controller DC01.CORP.LOCAL            (PingCastle DCName is the short
                                                  sAMAccountName, so the domain
                                                  FQDN is appended)
    privileged group  DOMAIN ADMINS@CORP.LOCAL   (SharpHound: groups.json name)
    privileged member ADMINISTRATOR@CORP.LOCAL   (built from the member DN)

Because Neo4j applies ``SET n += $props``, a value written here *overwrites* the
same key on an already-ingested SharpHound node. Everything PingCastle-specific
is therefore namespaced ``pingcastle_*``; only keys that mean exactly the same
thing in both tools (sid, name, hostname, enabled, is_dc, …) are written bare,
and booleans that SharpHound also derives are written only when True so a
PingCastle "no" can never erase a SharpHound "yes".

Entities produced
─────────────────
    Organization  the domain itself, its trust partners, its privileged groups
    Device        each domain controller
    Individual    each privileged-group member
    ADRisk        each triggered risk rule  ← custom Flowsint type, see below

Relationships produced
──────────────────────
    Device       -[DC_OF]->      Organization (domain)
    Individual   -[MEMBER_OF]->  Organization (privileged group)
    Organization -[TrustedBy]->  Organization (trust partner)
    Organization -[HAS_RISK]->   ADRisk
    ADRisk       -[AFFECTS]->    Individual | Device | Organization

**ADRisk must be registered in Flowsint before ingesting** — an unresolvable
nodeType makes `GET /api/sketches/{id}/graph` return HTTP 500 for the *whole*
sketch, not just that node. Run `scripts/register_pingcastle_type.py --apply`
once per install; `upload_router` refuses to ingest risk nodes until it is.

Secrets policy: PingCastle recovers cleartext GPP passwords from SYSVOL. By
design this parser records the *account* and the GPO the
credential came from and never the credential value.

Usage:
    python pingcastle_parser.py ad_hc_corp.local.xml        # summary to stdout

    from pingcastle_parser import parse_bytes
    result = parse_bytes(open("ad_hc_corp.local.xml", "rb").read())
    nodes, edges = result.to_flowsint_batch()
"""

from __future__ import annotations

import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ── Safety limits ─────────────────────────────────────────────────────────────
# A health check of a large forest carries tens of thousands of detail strings;
# these caps keep one upload from turning into a million-property import.

MAX_RISK_DETAILS = int(os.environ.get("SPOTTER_PINGCASTLE_MAX_DETAILS", "50"))
MAX_AFFECTS_EDGES = int(os.environ.get("SPOTTER_PINGCASTLE_MAX_AFFECTS", "500"))
MAX_MEMBERS = int(os.environ.get("SPOTTER_PINGCASTLE_MAX_MEMBERS", "10000"))
MAX_GPP_ACCOUNTS = int(os.environ.get("SPOTTER_PINGCASTLE_MAX_GPP", "200"))

# Node type name registered via scripts/register_pingcastle_type.py
RISK_NODE_TYPE = "ADRisk"

RULES_REFERENCE_URL = "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"

# PingCastle risk points are "worse is higher"; these bands drive severity and
# the is_high_risk flag the dossier / alerting paths key off.
SEVERITY_BANDS = ((30, "critical"), (15, "high"), (5, "medium"))

# msDS-Behavior-Version → readable domain/forest functional level.
FUNCTIONAL_LEVELS = {
    0: "Windows 2000",
    1: "Windows Server 2003 interim",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016",
    10: "Windows Server 2025",
}

TRUST_DIRECTIONS = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}
TRUST_TYPES = {1: "downlevel (NT4)", 2: "uplevel (AD)", 3: "MIT/Kerberos realm", 4: "DCE"}
# msDS-TrustAttributes bit flags (MS-ADTS 6.1.6.7.9).
TRUST_ATTRIBUTES = (
    (0x00000001, "non_transitive"),
    (0x00000002, "uplevel_only"),
    (0x00000004, "quarantined_sid_filtering"),
    (0x00000008, "forest_transitive"),
    (0x00000010, "cross_organization"),
    (0x00000020, "within_forest"),
    (0x00000040, "treat_as_external"),
    (0x00000080, "uses_rc4_encryption"),
    (0x00000200, "no_tgt_delegation"),
    (0x00000800, "pim_trust"),
)

# PingCastle writes DateTime.MinValue for "never"; anything this old is noise.
_MIN_YEAR = 1700

_DN_CN_RE = re.compile(r"CN=([^,]+)", re.IGNORECASE)
_DN_DC_RE = re.compile(r"DC=([^,]+)", re.IGNORECASE)


# ── Value coercion ────────────────────────────────────────────────────────────

def _decode_text(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode("utf-8", errors="replace")


def _int(val: Any, default: int = 0) -> int:
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return default


def _bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ("true", "1", "yes")


def _date(val: Any) -> str:
    """Normalise a PingCastle DateTime to 'YYYY-MM-DDTHH:MM:SS', '' for never."""
    text = str(val or "").strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00").split(".")[0])
    except ValueError:
        return ""
    if parsed.year < _MIN_YEAR:
        return ""
    return parsed.replace(tzinfo=None).isoformat(timespec="seconds")


def _epoch(val: Any) -> Optional[int]:
    """Normalised date → Unix seconds, matching SharpHound's timestamp columns."""
    iso = _date(val)
    if not iso:
        return None
    try:
        return int(datetime.fromisoformat(iso).replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


def _severity(points: int) -> str:
    for threshold, label in SEVERITY_BANDS:
        if points >= threshold:
            return label
    return "low"


def _domain_from_dn(dn: str) -> str:
    """'CN=Bob,OU=Staff,DC=corp,DC=local' → 'CORP.LOCAL'."""
    parts = _DN_DC_RE.findall(dn or "")
    return ".".join(parts).upper() if parts else ""


def _cn_from_dn(dn: str) -> str:
    match = _DN_CN_RE.search(dn or "")
    return match.group(1).strip() if match else ""


# ── Uniform accessor over XML elements and JSON dicts ─────────────────────────
# The .xml and .json health-check reports carry identical field names, so one
# builder can walk either once both are wrapped in this interface.

def _localname(tag: str) -> str:
    return str(tag).rsplit("}", 1)[-1]


class _XmlNode:
    """Case-insensitive view of one XML element (attributes and child elements)."""

    __slots__ = ("_el", "_children", "_attrs")

    def __init__(self, el: ET.Element) -> None:
        self._el = el
        self._children: Dict[str, List[ET.Element]] = {}
        for child in el:
            self._children.setdefault(_localname(child.tag).lower(), []).append(child)
        self._attrs = {_localname(k).lower(): v for k, v in el.attrib.items()}

    def get(self, name: str, default: str = "") -> str:
        key = name.lower()
        if key in self._attrs:
            return self._attrs[key]
        els = self._children.get(key)
        if els:
            return (els[0].text or "").strip()
        return default

    def has(self, name: str) -> bool:
        key = name.lower()
        return key in self._attrs or key in self._children

    def child(self, name: str) -> Optional["_XmlNode"]:
        els = self._children.get(name.lower())
        return _XmlNode(els[0]) if els else None

    def list(self, name: str) -> List["_XmlNode"]:
        """Items of a `List<T>` container element."""
        return [
            _XmlNode(item)
            for el in self._children.get(name.lower(), [])
            for item in el
        ]

    def strlist(self, name: str) -> List[str]:
        """Items of a `List<string>` container element."""
        return [
            (item.text or "").strip()
            for el in self._children.get(name.lower(), [])
            for item in el
            if (item.text or "").strip()
        ]


class _JsonNode:
    """Same interface as _XmlNode over a decoded JSON object."""

    __slots__ = ("_obj",)

    def __init__(self, obj: Dict[str, Any]) -> None:
        self._obj = {str(k).lower(): v for k, v in (obj or {}).items()}

    def _raw(self, name: str) -> Any:
        return self._obj.get(name.lower())

    def get(self, name: str, default: str = "") -> str:
        val = self._raw(name)
        if val is None or isinstance(val, (dict, list)):
            return default
        if isinstance(val, bool):
            return "true" if val else "false"
        return str(val).strip()

    def has(self, name: str) -> bool:
        return name.lower() in self._obj

    def child(self, name: str) -> Optional["_JsonNode"]:
        val = self._raw(name)
        return _JsonNode(val) if isinstance(val, dict) else None

    def list(self, name: str) -> List["_JsonNode"]:
        val = self._raw(name)
        if not isinstance(val, list):
            return []
        return [_JsonNode(item) for item in val if isinstance(item, dict)]

    def strlist(self, name: str) -> List[str]:
        val = self._raw(name)
        if not isinstance(val, list):
            return []
        return [str(item).strip() for item in val if not isinstance(item, (dict, list)) and str(item).strip()]


_Node = Any  # _XmlNode | _JsonNode


# ── Output dataclasses (mirrors sharphound_parser) ────────────────────────────

@dataclass
class ParsedEntity:
    entity_type: str          # Organization | Device | Individual | ADRisk
    label: str                # display name — also the Flowsint MERGE key
    properties: Dict[str, Any] = field(default_factory=dict)
    temp_id: str = ""         # stitching key before Flowsint IDs are known


@dataclass
class ParsedRelationship:
    source_temp_id: str
    target_temp_id: str
    label: str                # DC_OF | MEMBER_OF | TrustedBy | HAS_RISK | AFFECTS
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParseResult:
    entities: List[ParsedEntity] = field(default_factory=list)
    relationships: List[ParsedRelationship] = field(default_factory=list)
    domain: str = ""
    report_date: str = ""
    engine_version: str = ""
    scores: Dict[str, int] = field(default_factory=dict)
    high_risk_rules: List[Dict[str, Any]] = field(default_factory=list)
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
                "data": {**ent.properties, "nodeLabel": ent.label,
                         "label": ent.label, "type": ent.entity_type},
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
        return {
            "domain": self.domain,
            "report_date": self.report_date,
            "engine_version": self.engine_version,
            "scores": self.scores,
            "entities": len(self.entities),
            "entities_by_type": by_type,
            "relationships": len(self.relationships),
            "high_risk_rules": len(self.high_risk_rules),
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
        # upper-cased name → temp_id, used to resolve risk-rule details to nodes
        self.index: Dict[str, str] = {}

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

    def alias(self, *names: str) -> None:
        """Register lookup aliases for the most recently upserted entity."""
        if not self.order:
            return
        temp_id = self.order[-1]
        for name in names:
            key = (name or "").strip().upper()
            # First writer wins: a DC's short name must not be stolen by a user.
            if key and len(key) > 2 and key not in self.index:
                self.index[key] = temp_id

    def relate(self, source: str, target: str, label: str,
               data: Optional[Dict[str, Any]] = None) -> None:
        if source and target and source != target:
            self.relationships.append(
                ParsedRelationship(source, target, label, data or {})
            )

    def entities(self) -> List[ParsedEntity]:
        return [self.by_tid[tid] for tid in self.order]


# ── Report detection ──────────────────────────────────────────────────────────

def is_pingcastle(data: bytes, filename: str = "") -> bool:
    """Cheap sniff used by upload_router.detect_format()."""
    name = os.path.basename(filename or "").lower()
    head = _decode_text(data[:4096])
    if "<healthcheckdata" in head.lower():
        return True
    if name.startswith("ad_hc_") and name.endswith((".xml", ".json")):
        # Also catches encrypted reports, so parse_bytes can say *why* it failed
        # instead of the file falling through to the nmap / plain-text branch.
        return True
    stripped = data.lstrip()[:1]
    if stripped in (b"{", b"["):
        try:
            obj = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        if isinstance(obj, dict):
            keys = {str(k).lower() for k in obj}
            return "domainfqdn" in keys and (
                "riskrules" in keys or "globalscore" in keys or "domainsid" in keys
            )
    return False


def _load_root(data: bytes, filename: str = "") -> Tuple[Optional[_Node], List[str]]:
    """Return (root node, errors). Root is None when the report is unusable."""
    text = _decode_text(data).lstrip()

    if text[:1] in ("{", "["):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            return None, [f"PingCastle JSON report is not valid JSON: {exc}"]
        if not isinstance(obj, dict):
            return None, ["PingCastle JSON report must be an object"]
        node = _JsonNode(obj)
        if not node.has("DomainFQDN"):
            return None, ["JSON has no DomainFQDN — not a PingCastle health check report"]
        return node, []

    try:
        # ElementTree does not expand external entities, so an XXE payload in an
        # uploaded report raises here rather than reading host files.
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        lowered = text[:4096].lower()
        if "<html" in lowered:
            return None, [
                "This is the PingCastle HTML report. Upload the machine-readable "
                "ad_hc_<domain>.xml (or .json) written alongside it."
            ]
        return None, [f"PingCastle XML is not well-formed: {exc}"]

    tag = _localname(root.tag)
    if tag.lower() == "html":
        return None, [
            "This is the PingCastle HTML report. Upload the machine-readable "
            "ad_hc_<domain>.xml (or .json) written alongside it."
        ]
    if tag == "EncryptedData":
        return None, [
            "PingCastle report is encrypted (<EncryptedData>). Re-export without "
            "--encrypt, or decrypt it with the private key, then upload."
        ]
    if tag != "HealthcheckData":
        return None, [
            f"Unsupported PingCastle report root <{tag}> — only health check "
            f"reports (ad_hc_<domain>.xml/.json) are ingested."
        ]
    return _XmlNode(root), []


# ── Section parsers ───────────────────────────────────────────────────────────

def _domain_properties(root: _Node, fqdn: str) -> Dict[str, Any]:
    users = root.child("UserAccountData")
    computers = root.child("ComputerAccountData")
    os_rows = [
        f"{row.get('OperatingSystem')}: {row.get('NumberOfOccurence')}"
        for row in root.list("OperatingSystem")
        if row.get("OperatingSystem")
    ]
    dfl = _int(root.get("DomainFunctionalLevel"), -1)
    ffl = _int(root.get("ForestFunctionalLevel"), -1)

    props: Dict[str, Any] = {
        "sid": root.get("DomainSid"),
        "name": fqdn,
        "is_domain": True,
        "is_high_value": True,
        "source": "pingcastle",
        "netbios_name": root.get("NetBIOSName").upper(),
        "forest": root.get("ForestFQDN").upper(),
        "pingcastle_report": True,
        "pingcastle_generated_at": _date(root.get("GenerationDate")),
        "pingcastle_engine_version": root.get("EngineVersion"),
        "pingcastle_domain_created": _date(root.get("DomainCreation")),
        "pingcastle_schema_version": _int(root.get("SchemaVersion")) or None,
        "pingcastle_dc_count": _int(root.get("NumberOfDC")) or None,
        "pingcastle_admin_account_name": root.get("AdminAccountName"),
        "pingcastle_admin_last_logon": _date(root.get("AdminLastLoginDate")),
        "pingcastle_krbtgt_last_change": _date(root.get("KrbtgtLastChangeDate")),
        "pingcastle_krbtgt_version": _int(root.get("KrbtgtLastVersion")) or None,
        "pingcastle_last_ad_backup": _date(root.get("LastADBackup")),
        "pingcastle_azure_ad_name": root.get("AzureADName"),
        "pingcastle_azure_ad_id": root.get("AzureADId"),
        "pingcastle_os_distribution": os_rows,
    }
    if dfl >= 0:
        props["pingcastle_domain_functional_level"] = FUNCTIONAL_LEVELS.get(dfl, f"level {dfl}")
    if ffl >= 0:
        props["pingcastle_forest_functional_level"] = FUNCTIONAL_LEVELS.get(ffl, f"level {ffl}")

    # Scores: PingCastle counts risk *points*, so 0 is a clean domain and 100 is
    # the worst possible. Keep 0 rather than dropping it as an empty value.
    for key, source_field in (
        ("pingcastle_global_score", "GlobalScore"),
        ("pingcastle_stale_objects_score", "StaleObjectsScore"),
        ("pingcastle_privileged_group_score", "PrivilegiedGroupScore"),  # sic
        ("pingcastle_trust_score", "TrustScore"),
        ("pingcastle_anomaly_score", "AnomalyScore"),
        ("pingcastle_maturity_level", "MaturityLevel"),
    ):
        if root.has(source_field):
            props[key] = _int(root.get(source_field))

    for key, source_field in (
        ("pingcastle_laps_installed", "LAPSInstalled"),
        ("pingcastle_laps_new_installed", "NewLAPSInstalled"),
    ):
        installed = _date(root.get(source_field))
        if installed:
            props[key] = installed

    for key, source_field in (
        ("pingcastle_guest_enabled", "GuestEnabled"),
        ("pingcastle_sidhistory_auditing_present", "SIDHistoryAuditingGroupPresent"),
        ("pingcastle_ntfrs_sysvol", "UsingNTFRSForSYSVOL"),
        ("pingcastle_exchange_privesc_vulnerable", "ExchangePrivEscVulnerable"),
        ("pingcastle_recycle_bin_enabled", "IsRecycleBinEnabled"),
    ):
        if root.has(source_field):
            props[key] = _bool(root.get(source_field))

    if root.has("MachineAccountQuota"):
        props["pingcastle_machine_account_quota"] = _int(root.get("MachineAccountQuota"))

    # Account-hygiene counters — the cheap version of what a SharpHound sweep
    # gives per object, and available even from a non-privileged health check.
    if users is not None:
        props.update({
            "pingcastle_user_count": _int(users.get("Number")),
            "pingcastle_users_enabled": _int(users.get("NumberEnabled")),
            "pingcastle_users_inactive": _int(users.get("NumberInactive")),
            "pingcastle_users_pwd_never_expires": _int(users.get("NumberPwdNeverExpires")),
            "pingcastle_users_pwd_not_required": _int(users.get("NumberPwdNotRequired")),
            "pingcastle_users_no_preauth": _int(users.get("NumberNoPreAuth")),
            "pingcastle_users_reversible_encryption": _int(users.get("NumberReversibleEncryption")),
            "pingcastle_users_des_enabled": _int(users.get("NumberDesEnabled")),
            "pingcastle_users_sid_history": _int(users.get("NumberSidHistory")),
        })
    if computers is not None:
        props.update({
            "pingcastle_computer_count": _int(computers.get("Number")),
            "pingcastle_computers_enabled": _int(computers.get("NumberEnabled")),
            "pingcastle_computers_inactive": _int(computers.get("NumberInactive")),
            "pingcastle_computers_laps": _int(computers.get("NumberLAPS")),
        })

    return props


def _parse_domain_controllers(root: _Node, builder: _Builder, fqdn: str,
                              domain_tid: str) -> None:
    for dc in root.list("DomainControllers"):
        name = dc.get("DCName").strip()
        if not name:
            continue
        label = name.upper() if "." in name else f"{name}.{fqdn}".upper()
        temp_id = f"pcdc:{label}"
        ips = [ip for ip in dc.strlist("IP") if ip]
        fsmo = dc.strlist("FSMO")

        props: Dict[str, Any] = {
            # SharpHound sets device_id to the machine SID; a health check never
            # reports it, so the FQDN stands in as the stable identifier. `sid`
            # is deliberately left untouched so SharpHound edge resolution and
            # backfill_device_activity keep working on a merged node.
            "device_id": label,
            "hostname": label,
            "domain": fqdn,
            "is_dc": True,
            "source": "pingcastle",
            "operating_system": dc.get("OperatingSystem"),
            "os_version": dc.get("OperatingSystemVersion"),
            "ip_addresses": ips,
            "pingcastle_report": True,
            "pingcastle_dc_short_name": name.upper(),
            "pingcastle_distinguished_name": dc.get("DistinguishedName"),
            "pingcastle_owner": dc.get("OwnerName") or dc.get("OwnerSID"),
            "pingcastle_creation_date": _date(dc.get("CreationDate")),
            "pingcastle_startup_time": _date(dc.get("StartupTime")),
            "pingcastle_last_logon": _date(dc.get("LastComputerLogonDate")),
            "pingcastle_pwd_last_set": _date(dc.get("PwdLastSet")),
            "pingcastle_fsmo_roles": fsmo,
            "pingcastle_ldaps_protocols": dc.strlist("LDAPSProtocols"),
            "pingcastle_registration_problem": dc.get("RegistrationProblem"),
        }
        if ips:
            props["ip"] = ips[0]
        pwd_epoch = _epoch(dc.get("PwdLastSet"))
        if pwd_epoch is not None:
            props["pwd_last_set"] = pwd_epoch
        logon_epoch = _epoch(dc.get("LastComputerLogonDate"))
        if logon_epoch is not None:
            props["last_logon_timestamp"] = logon_epoch

        # Coercion / relay surface. Written only when True: a False here must not
        # overwrite something a SharpHound or nmap pass already proved.
        for key, source_field in (
            ("pingcastle_smb1_enabled", "SupportSMB1"),
            ("pingcastle_null_session", "HasNullSession"),
            ("pingcastle_remote_spooler", "RemoteSpoolerDetected"),
            ("pingcastle_ldap_channel_binding_disabled", "ChannelBindingDisabled"),
            ("pingcastle_ldap_signing_not_required", "LdapServerSigningRequirementDisabled"),
            ("pingcastle_webclient_enabled", "WebClientEnabled"),
            ("pingcastle_sysvol_overwrite", "SYSVOLOverwrite"),
            ("pingcastle_azure_ad_kerberos", "AzureADKerberos"),
            ("pingcastle_rodc", "RODC"),
        ):
            if _bool(dc.get(source_field)):
                props[key] = True

        builder.upsert("Device", label, temp_id, props)
        builder.alias(label, name, f"{name}$")
        builder.relate(temp_id, domain_tid, "DC_OF", {"source": "pingcastle"})


def _member_entity(member: _Node, builder: _Builder, fqdn: str,
                   group_name: str = "") -> str:
    """Upsert one privileged-account member; returns its temp_id."""
    sid = member.get("Sid")
    dn = member.get("DistinguishedName")
    raw_name = member.get("Name").strip()
    sam = raw_name.split("\\")[-1] if raw_name else _cn_from_dn(dn)
    # A foreign-security-principal member is reported as "NETBIOS\account" with no
    # DN. Keep its own domain rather than filing it under the assessed one — the
    # label would otherwise claim an account exists in a domain it does not.
    netbios_prefix = raw_name.split("\\")[0].upper() if "\\" in raw_name else ""
    member_domain = _domain_from_dn(dn) or netbios_prefix or fqdn

    if "@" in raw_name:
        label = raw_name.upper()
    elif sam:
        label = f"{sam}@{member_domain}".upper()
    elif sid:
        label = sid.upper()
    else:
        return ""

    temp_id = f"pcsid:{sid}" if sid else f"pcuser:{label}"
    spns = member.strlist("ServicePrincipalNames")
    is_service = _bool(member.get("IsService")) or bool(spns)
    member_class = (member.get("Class") or "").lower()

    props: Dict[str, Any] = {
        "sid": sid,
        "sam_account_name": sam,
        "email": member.get("Email"),
        "is_admin": True,          # every member here sits in a privileged group
        "source": "pingcastle",
        "pingcastle_report": True,
        "pingcastle_distinguished_name": dn,
        "pingcastle_object_class": member_class or None,
        "pingcastle_created": _date(member.get("Created")),
        "pingcastle_pwd_last_set": _date(member.get("PwdLastSet")),
        "pingcastle_last_logon": _date(member.get("LastLogonTimestamp")),
        "pingcastle_privileged_groups": [group_name] if group_name else [],
    }
    if member.has("IsEnabled"):
        props["enabled"] = _bool(member.get("IsEnabled"))
    pwd_epoch = _epoch(member.get("PwdLastSet"))
    if pwd_epoch is not None:
        props["pwd_last_set"] = pwd_epoch
    logon_epoch = _epoch(member.get("LastLogonTimestamp"))
    if logon_epoch is not None:
        props["last_logon_timestamp"] = logon_epoch
    if spns:
        props["spn_count"] = len(spns)
        props["is_kerberoastable"] = True
    if is_service:
        props["pingcastle_is_service_account"] = True

    for key, source_field in (
        ("pingcastle_pwd_never_expires", "DoesPwdNeverExpires"),
        ("pingcastle_can_be_delegated", "CanBeDelegated"),
        ("pingcastle_smartcard_required", "SmartCardRequired"),
        ("pingcastle_in_protected_users", "IsInProtectedUser"),
        ("pingcastle_is_locked", "IsLocked"),
        ("pingcastle_is_external", "IsExternal"),
    ):
        if _bool(member.get(source_field)):
            props[key] = True
    if member.has("IsActive") and not _bool(member.get("IsActive")):
        props["pingcastle_is_inactive"] = True

    builder.upsert("Individual", label, temp_id, props)
    builder.alias(label, sam, dn)
    return temp_id


def _parse_privileged_groups(root: _Node, builder: _Builder, fqdn: str) -> int:
    members_seen = 0

    for group in root.list("PrivilegedGroups"):
        group_name = group.get("GroupName").strip()
        if not group_name:
            continue
        label = group_name.upper() if "@" in group_name else f"{group_name}@{fqdn}".upper()
        sid = group.get("Sid")
        temp_id = f"pcsid:{sid}" if sid else f"pcgroup:{label}"

        builder.upsert("Organization", label, temp_id, {
            "sid": sid,
            "name": label,
            "is_high_value": True,
            "admin_count": True,
            "source": "pingcastle",
            "pingcastle_report": True,
            "pingcastle_group_name": group_name,
            "pingcastle_distinguished_name": group.get("DistinguishedName"),
            "pingcastle_member_count": _int(group.get("NumberOfMember")),
            "pingcastle_members_enabled": _int(group.get("NumberOfMemberEnabled")),
            "pingcastle_members_disabled": _int(group.get("NumberOfMemberDisabled")),
            "pingcastle_members_inactive": _int(group.get("NumberOfMemberInactive")),
            "pingcastle_members_pwd_never_expires": _int(group.get("NumberOfMemberPwdNeverExpires")),
            "pingcastle_members_pwd_not_required": _int(group.get("NumberOfMemberPwdNotRequired")),
            "pingcastle_members_can_be_delegated": _int(group.get("NumberOfMemberCanBeDelegated")),
            "pingcastle_members_service_accounts": _int(group.get("NumberOfServiceAccount")),
            "pingcastle_members_external": _int(group.get("NumberOfExternalMember")),
            "pingcastle_members_in_protected_users": _int(group.get("NumberOfMemberInProtectedUsers")),
        })
        builder.alias(label, group_name)

        for member in group.list("Members"):
            if members_seen >= MAX_MEMBERS:
                break
            member_tid = _member_entity(member, builder, fqdn, group_name)
            members_seen += 1
            if member_tid:
                builder.relate(member_tid, temp_id, "MEMBER_OF", {
                    "group_name": group_name,
                    "is_high_value": True,
                    "source": "pingcastle",
                })

    # AllPrivilegedMembers is the flattened union (including nested groups), so it
    # catches accounts that never appear in a Members list of their own.
    for member in root.list("AllPrivilegedMembers"):
        if members_seen >= MAX_MEMBERS:
            break
        _member_entity(member, builder, fqdn)
        members_seen += 1

    return members_seen


def _parse_trusts(root: _Node, builder: _Builder, domain_tid: str) -> None:
    for trust in root.list("Trusts"):
        partner = trust.get("TrustPartner").strip()
        if not partner:
            continue
        label = partner.upper()
        sid = trust.get("SID")
        temp_id = f"pcsid:{sid}" if sid else f"pcdomain:{label}"

        builder.upsert("Organization", label, temp_id, {
            "sid": sid,
            "name": label,
            "is_domain": True,
            "source": "pingcastle",
            "pingcastle_report": True,
            "netbios_name": trust.get("NetBiosName").upper(),
            "pingcastle_trust_partner": True,
        })
        builder.alias(label, trust.get("NetBiosName"))

        attributes = _int(trust.get("TrustAttributes"))
        flags = [name for bit, name in TRUST_ATTRIBUTES if attributes & bit]
        direction = _int(trust.get("TrustDirection"))
        trust_type = _int(trust.get("TrustType"))
        builder.relate(domain_tid, temp_id, "TrustedBy", {
            "trust_direction": TRUST_DIRECTIONS.get(direction, str(direction)),
            "trust_type": TRUST_TYPES.get(trust_type, str(trust_type)),
            "trust_attributes": flags,
            # Quarantine (0x4) is what actually filters foreign SIDs on an
            # external trust — its absence is the SID-history escalation path.
            "sid_filtering": "quarantined_sid_filtering" in flags,
            "is_transitive": "non_transitive" not in flags,
            "is_forest_transitive": "forest_transitive" in flags,
            "uses_rc4": "uses_rc4_encryption" in flags,
            "is_active": _bool(trust.get("IsActive")),
            "creation_date": _date(trust.get("CreationDate")),
            "known_domains": len(trust.list("KnownDomains")),
            "source": "pingcastle",
        })


def _resolve_detail(detail: str, index: Dict[str, str]) -> Optional[str]:
    """Best-effort map of one risk-rule detail line onto an ingested entity."""
    text = (detail or "").strip()
    if not text or len(text) > 512:
        return None
    candidates = [text]
    if " (" in text:
        candidates.append(text.split(" (", 1)[0])
    if "\\" in text:
        candidates.append(text.rsplit("\\", 1)[-1])
    cn = _cn_from_dn(text)
    if cn:
        candidates.append(cn)
    for candidate in candidates:
        hit = index.get(candidate.strip().upper())
        if hit:
            return hit
    return None


def _parse_risk_rules(root: _Node, builder: _Builder, fqdn: str, domain_tid: str,
                      report_date: str, allow_risk_nodes: bool) -> List[Dict[str, Any]]:
    high_risk: List[Dict[str, Any]] = []
    affects_emitted = 0

    for rule in root.list("RiskRules"):
        risk_id = rule.get("RiskId").strip()
        if not risk_id:
            continue
        points = _int(rule.get("Points"))
        severity = _severity(points)
        details = rule.strlist("Details")
        rationale = rule.get("Rationale")
        category = rule.get("Category")

        record = {
            "risk_id": risk_id,
            "category": category,
            "model": rule.get("Model"),
            "points": points,
            "severity": severity,
            "rationale": rationale,
            "details_count": len(details),
            "domain": fqdn,
        }
        if severity in ("critical", "high"):
            high_risk.append(record)

        if not allow_risk_nodes:
            continue

        label = f"{risk_id}@{fqdn}"
        temp_id = f"pcrisk:{fqdn.lower()}:{risk_id}"
        builder.upsert(RISK_NODE_TYPE, label, temp_id, {
            # Declared string fields of the registered ADRisk schema. A custom
            # type resolves to a model whose declared fields are all Optional[str],
            # so a non-string here is silently dropped — see the type contract in
            # flowsint-custom/types/ad_risk.py.
            "risk_id": risk_id,
            "category": category,
            "model": rule.get("Model"),
            "severity": severity,
            "rationale": rationale,
            "domain": fqdn,
            "source": "pingcastle",
            "generated_at": report_date,
            "reference": RULES_REFERENCE_URL,
            # Undeclared extras keep their native type through the serializer,
            # which is what makes `WHERE r.points > 20` work in Cypher.
            "points": points,
            "details_count": len(details),
            "is_high_risk": severity in ("critical", "high"),
            "details": details[:MAX_RISK_DETAILS],
            "details_truncated": len(details) > MAX_RISK_DETAILS,
        })
        builder.relate(domain_tid, temp_id, "HAS_RISK", {
            "risk_id": risk_id,
            "points": points,
            "severity": severity,
            "category": category,
            "source": "pingcastle",
        })

        # Point the rule at the objects it names, when they are objects we ingested.
        linked = set()
        for detail in details:
            if affects_emitted >= MAX_AFFECTS_EDGES:
                break
            target = _resolve_detail(detail, builder.index)
            if target and target not in linked:
                linked.add(target)
                affects_emitted += 1
                builder.relate(temp_id, target, "AFFECTS", {
                    "risk_id": risk_id,
                    "severity": severity,
                    "source": "pingcastle",
                })

    return high_risk


def _parse_gpp_passwords(root: _Node) -> Tuple[List[str], int]:
    """
    Accounts whose cleartext password PingCastle recovered from SYSVOL.

    Only the account and the GPO are returned — never the credential value
    (SPOTTER's data-minimisation rule).
    """
    accounts: List[str] = []
    for entry in root.list("GPPPassword"):
        username = entry.get("UserName") or entry.get("Other")
        if not username:
            continue
        gpo = entry.get("GPOName")
        accounts.append(f"{username} ({gpo})" if gpo else username)
    total = len(accounts)
    return accounts[:MAX_GPP_ACCOUNTS], total


# ── Public API ────────────────────────────────────────────────────────────────

def parse_bytes(data: bytes, filename: str = "",
                allow_risk_nodes: bool = True) -> ParseResult:
    """
    Parse a PingCastle health check report.

    allow_risk_nodes=False suppresses the ADRisk nodes (and their edges) for
    installs where the custom type is not registered yet — the rest of the
    report still ingests, and the risk summary is still returned.
    """
    root, errors = _load_root(data, filename)
    if root is None:
        return ParseResult(errors=errors)

    fqdn = (root.get("DomainFQDN") or "").strip().upper()
    if not fqdn:
        return ParseResult(errors=["Report has no DomainFQDN — nothing to attach data to"])

    report_date = _date(root.get("GenerationDate"))
    builder = _Builder()

    domain_props = _domain_properties(root, fqdn)
    domain_sid = domain_props.get("sid") or ""
    domain_tid = f"pcsid:{domain_sid}" if domain_sid else f"pcdomain:{fqdn}"

    gpp_accounts, gpp_total = _parse_gpp_passwords(root)
    if gpp_total:
        # Credential *values* are deliberately not stored; the account and GPO are
        # what an operator needs to go collect them from SYSVOL themselves.
        domain_props["pingcastle_gpp_password_count"] = gpp_total
        domain_props["pingcastle_gpp_password_accounts"] = gpp_accounts

    builder.upsert("Organization", fqdn, domain_tid, domain_props)
    builder.alias(fqdn, root.get("NetBIOSName"))

    # DCs and privileged accounts first: the risk-rule pass resolves its detail
    # lines against the name index those two build.
    try:
        _parse_domain_controllers(root, builder, fqdn, domain_tid)
    except Exception as exc:                       # noqa: BLE001 - keep partial data
        builder.errors.append(f"domain controller section failed: {exc}")
    try:
        _parse_privileged_groups(root, builder, fqdn)
    except Exception as exc:                       # noqa: BLE001
        builder.errors.append(f"privileged group section failed: {exc}")
    try:
        _parse_trusts(root, builder, domain_tid)
    except Exception as exc:                       # noqa: BLE001
        builder.errors.append(f"trust section failed: {exc}")

    try:
        high_risk = _parse_risk_rules(root, builder, fqdn, domain_tid,
                                      report_date, allow_risk_nodes)
    except Exception as exc:                       # noqa: BLE001
        builder.errors.append(f"risk rule section failed: {exc}")
        high_risk = []

    rule_count = len(root.list("RiskRules"))
    domain_entity = builder.by_tid.get(domain_tid)
    if domain_entity is not None:
        domain_entity.properties["pingcastle_risk_rule_count"] = rule_count
        domain_entity.properties["pingcastle_high_risk_rule_count"] = len(high_risk)

    scores = {
        key: domain_props[full_key]
        for key, full_key in (
            ("global", "pingcastle_global_score"),
            ("stale_objects", "pingcastle_stale_objects_score"),
            ("privileged_groups", "pingcastle_privileged_group_score"),
            ("trusts", "pingcastle_trust_score"),
            ("anomalies", "pingcastle_anomaly_score"),
            ("maturity_level", "pingcastle_maturity_level"),
        )
        if full_key in domain_props
    }

    return ParseResult(
        entities=builder.entities(),
        relationships=builder.relationships,
        domain=fqdn,
        report_date=report_date,
        engine_version=root.get("EngineVersion"),
        scores=scores,
        high_risk_rules=sorted(high_risk, key=lambda r: r["points"], reverse=True),
        errors=errors + builder.errors,
    )


def parse_file(path: str, allow_risk_nodes: bool = True) -> ParseResult:
    with open(path, "rb") as handle:
        return parse_bytes(handle.read(), filename=os.path.basename(path),
                           allow_risk_nodes=allow_risk_nodes)


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1:
        result = parse_file(sys.argv[1])
    else:
        result = parse_bytes(sys.stdin.buffer.read())

    print(json.dumps(result.summary(), indent=2))
    if result.high_risk_rules:
        print("\nTop risk rules:")
        for rule in result.high_risk_rules[:10]:
            print(f"  [{rule['severity']:>8}] {rule['risk_id']:<28} "
                  f"{rule['points']:>3} pts  {rule['rationale'][:70]}")
    if result.errors:
        sys.exit(1)
