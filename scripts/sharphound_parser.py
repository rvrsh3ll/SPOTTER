"""
sharphound_parser.py — Parse SharpHound / BloodHound ZIP exports.

Supports both schema versions:
  v2  (BloodHound CE / SharpHound v2+) — files named computers.json,
      users.json, groups.json, domains.json, ous.json, gpos.json, containers.json
  v3  (legacy SharpHound 1.x)          — single file with a top-level 'meta'
      key or files prefixed with a timestamp

Output: normalised dicts ready for flowsint_client.batch_import()

Usage (standalone):
    python sharphound_parser.py /path/to/BloodHound_*.zip

Usage (in n8n Code node — base64 ZIP bytes):
    import base64, sys
    sys.path.insert(0, '/data/scripts')
    from sharphound_parser import parse_zip_bytes
    result = parse_zip_bytes(base64.b64decode(zip_b64))

All data here originates from authorized SharpHound collections inside
lab or engagement environments under proper Rules of Engagement.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import zipfile
import base64
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ── Sensitive target heuristics ────────────────────────────────────────────────

DC_PATTERNS = re.compile(r"\bDC\b|DOMAIN.CONTROLLER|DOMAINCONTROLLER", re.IGNORECASE)
DA_GROUPS   = re.compile(r"domain admins|enterprise admins|schema admins|administrators", re.IGNORECASE)

# ── DN / CN helpers ────────────────────────────────────────────────────────────

def _split_dn(dn: str) -> List[str]:
    """Split a Distinguished Name on commas that are NOT escaped with \\."""
    return re.split(r'(?<!\\),', dn)


def _parse_cn_name(dn: str) -> tuple:
    """
    Extract (first_name, last_name, full_name) from a Distinguished Name.

    AD stores names in the CN component.  Common formats:
      CN=LASTNAME\\, FIRSTNAME   →  ("Firstname", "Lastname", "Firstname Lastname")
      CN=FIRSTNAME LASTNAME       →  ("Firstname", "Lastname", "Firstname Lastname")
      CN=SINGLE                   →  ("", "Single", "Single")
    Returns ("", "", "") when the DN is absent or unparseable.
    """
    if not dn:
        return ("", "", "")
    parts = _split_dn(dn)
    if not parts:
        return ("", "", "")
    cn_part = parts[0]
    if not cn_part.upper().startswith("CN="):
        return ("", "", "")
    cn_val = cn_part[3:].replace("\\,", ",").strip()
    if not cn_val:
        return ("", "", "")

    if "," in cn_val:
        # "LASTNAME, FIRSTNAME" — standard AD format
        last, _, first = cn_val.partition(",")
        last  = last.strip().title()
        first = first.strip().title()
    else:
        # "FIRSTNAME LASTNAME" or single token
        tokens = cn_val.split()
        if len(tokens) >= 2:
            first = tokens[0].title()
            last  = " ".join(tokens[1:]).title()
        else:
            first = ""
            last  = cn_val.title()

    full = f"{first} {last}".strip() if first else last
    return (first, last, full)


def _parse_department(dn: str) -> str:
    """Return the first OU component of a DN as the department string."""
    for part in _split_dn(dn):
        if part.upper().startswith("OU="):
            return part[3:].strip().title()
    return ""

def _extract_email(props: dict, name: str = "") -> str:
    """
    Find the best email address from AD/BloodHound properties.

    BloodHound may export the address under any of several field names
    depending on which SharpHound version or collection method was used,
    and AD environments sometimes store it in the 'name' or UPN fields.
    Checks in preference order; returns lowercase or empty string.
    """
    for key in ("email", "mail", "emailaddress", "userprincipalname", "userPrincipalName"):
        val = str(props.get(key, "") or "").strip()
        if val and "@" in val:
            return val.lower()
    # Fall back to the node name itself when it is email-shaped (common in
    # environments where AD 'name' is set to the user's UPN / SMTP address).
    if name and "@" in name:
        return name.lower()
    return ""


def _thumbnail_to_data_url(props: dict) -> Optional[str]:
    """Convert a base64-encoded AD thumbnailPhoto property to a data URL."""
    raw = props.get("thumbnailphoto") or props.get("thumbnailPhoto") or props.get("jpegPhoto")
    if not raw:
        return None
    if isinstance(raw, bytes):
        b64 = base64.b64encode(raw).decode("ascii")
    elif isinstance(raw, str):
        # May already be base64, or may be raw binary string
        try:
            base64.b64decode(raw, validate=True)
            b64 = raw
        except Exception:
            b64 = base64.b64encode(raw.encode("latin-1")).decode("ascii")
    else:
        return None
    if not b64:
        return None
    return f"data:image/jpeg;base64,{b64}"


HIGH_VALUE_RIGHTS = {
    "GenericAll", "WriteDacl", "WriteOwner", "GenericWrite",
    "AllExtendedRights", "ForceChangePassword", "DCSync",
    "GetChangesAll", "AddMember", "ReadLAPSPassword",
    # ── ADCS / GPO takeover rights (Certipy / Certify / GPO abuse tradecraft) ──
    "ManageCA", "ManageCertificates", "WritePKIEnrollmentFlag",
    "WritePKINameFlag", "WriteGPLink",
}

# Right names that SharpHound exposes on cert templates / enterprise CAs and that
# we want preserved as queryable Neo4j edge types (ADCS abuse — see Certipy).
ADCS_ACE_RIGHTS = {
    "Enroll", "AutoEnroll", "ManageCA", "ManageCertificates",
    "WritePKIEnrollmentFlag", "WritePKINameFlag",
}


def _truthy(val: Any) -> bool:
    """BloodHound exports booleans as real bools but older data may use strings."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes")
    return bool(val)


def _epoch(val: Any) -> int:
    """
    Normalise a SharpHound timestamp to POSIX seconds, 0 when unknown.

    SharpHound emits epoch-seconds ints, but -1 (attribute never set) and 0 (no
    data) both appear in the wild, and some collectors leak raw Windows FILETIME
    (100 ns ticks since 1601).

    Returns 0 rather than None on purpose: Flowsint's graph serializer drops None
    and "" but keeps 0, so "assessed, no logon recorded" stays distinguishable
    from "never assessed" (which is an absent key). WF12's coverage gate depends
    on that distinction.
    """
    try:
        n = int(val)
    except (TypeError, ValueError):
        return 0
    if n <= 0:
        return 0
    if n > 100_000_000_000_000:          # Windows FILETIME → POSIX seconds
        n = (n - 116_444_736_000_000_000) // 10_000_000
    if n <= 0 or n > 4_102_444_800:      # sanity clamp: past year 2100 is garbage
        return 0
    return n


def _principal_sids(items: Any) -> List[str]:
    """
    Normalise a BloodHound typed-principal list to a list of SID strings.

    Handles both the CE shape ([{"ObjectIdentifier": "S-1-…", "ObjectType": "…"}])
    and the occasional bare-string list ([\"S-1-…\"]).
    """
    out: List[str] = []
    for item in items or []:
        if isinstance(item, dict):
            sid = item.get("ObjectIdentifier") or item.get("objectid") or ""
        elif isinstance(item, str):
            sid = item
        else:
            sid = ""
        if sid and sid.startswith("S-1"):
            out.append(sid)
    return out


# ── Output dataclasses ────────────────────────────────────────────────────────

@dataclass
class ParsedEntity:
    entity_type: str          # Individual | Group | Computer | Domain
    label: str                # display name
    properties: Dict[str, Any] = field(default_factory=dict)
    temp_id: str = ""         # used for relationship stitching before Flowsint IDs known

@dataclass
class ParsedRelationship:
    source_temp_id: str
    target_temp_id: str
    label: str                # HAS_SESSION | MEMBER_OF | HAS_PERMISSION
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ParseResult:
    entities: List[ParsedEntity]
    relationships: List[ParsedRelationship]
    schema_version: str
    errors: List[str] = field(default_factory=list)
    high_value_aces: List[Dict[str, Any]] = field(default_factory=list)

    def to_flowsint_batch(self) -> Tuple[List[dict], List[dict]]:
        """
        Convert to the nodes/edges format expected by flowsint_client.batch_import().
        Returns (nodes_list, edges_list).
        """
        nodes = []
        for ent in self.entities:
            nodes.append({
                "id": ent.temp_id,
                "entity_type": ent.entity_type,
                "nodeLabel": ent.label,
                # nodeLabel must be in data so Individual(**data) sets it on the Pydantic model;
                # the serializer derives the Neo4j MERGE key from entity.nodeLabel.
                "data": {**ent.properties, "nodeLabel": ent.label, "label": ent.label, "type": ent.entity_type},
                "include": True,
                # node_id must equal id so nodes_mapping_indices is populated for edge resolution.
                "node_id": ent.temp_id,
            })
        edges = []
        for rel in self.relationships:
            edges.append({
                # import_service._create_edges expects from_id/to_id, not source/target.
                "from_id": rel.source_temp_id,
                "to_id": rel.target_temp_id,
                "label": rel.label,
                "data": rel.data,
            })
        return nodes, edges


# ── Schema detection ──────────────────────────────────────────────────────────

def _detect_schema(zip_obj: zipfile.ZipFile) -> str:
    """Return 'v2' for BloodHound CE / SharpHound v2, 'v3' for SharpHound v1."""
    names = [n.lower() for n in zip_obj.namelist()]
    v2_files = {"users.json", "computers.json", "groups.json", "domains.json"}
    # Check basenames only (may be inside a subdirectory)
    # Accept exact, timestamp-first (20240101_users.json), and type-first (users_20240101.json)
    basenames = {os.path.basename(n) for n in names}
    _pfx = tuple(v[:-5] + "_" for v in v2_files)  # "users_", "computers_", …
    if (v2_files & basenames
            or any(b.endswith("_" + v) for b in basenames for v in v2_files)
            or any(b.startswith(p) for b in basenames for p in _pfx)):
        return "v2"
    return "v3"


# ── v2 parser (BloodHound CE / SharpHound 2+) ────────────────────────────────

def _parse_v2(zip_obj: zipfile.ZipFile) -> ParseResult:
    entities: List[ParsedEntity] = []
    relationships: List[ParsedRelationship] = []
    high_value_aces: List[Dict[str, Any]] = []
    errors: List[str] = []

    # Index: canonical type → list of zip paths (primary + shards).
    # SharpHound splits large collections into numbered shards:
    #   20260804_computers.json, 20260804_computers_01.json, …
    # All shards for a type are merged in load().
    shard_map: Dict[str, List[str]] = {}
    for name in zip_obj.namelist():
        base = os.path.basename(name).lower()
        canon = None
        # timestamp-prefixed: 20240101_users.json or 20240101_users_01.json
        m = re.match(r"^\d+_([a-z]+?)(?:_\d+)?\.json$", base)
        if m:
            canon = m.group(1) + ".json"
        # type-first: users_20240101.json
        if not canon:
            m2 = re.match(r"^([a-z]+)_[\d_]+\.json$", base)
            if m2:
                canon = m2.group(1) + ".json"
        # bare name: users.json
        if not canon:
            canon = base
        shard_map.setdefault(canon, []).append(name)
    # Sort shards so the base file comes before _01, _02, etc.
    for k in shard_map:
        shard_map[k].sort()

    def load(fname: str) -> Optional[List[dict]]:
        paths = shard_map.get(fname)
        if not paths:
            return None
        merged: List[dict] = []
        for path in paths:
            try:
                with zip_obj.open(path) as f:
                    data = json.load(f)
                if isinstance(data, dict) and "data" in data:
                    merged.extend(data["data"])
                elif isinstance(data, list):
                    merged.extend(data)
            except Exception as e:
                errors.append(f"Failed to load {path}: {e}")
        return merged or None

    # ── Users ────────────────────────────────────────────────────────────────
    for user in (load("users.json") or []):
        props = user.get("Properties", {})
        sid   = user.get("ObjectIdentifier", "")
        name  = props.get("name", sid)
        sam   = props.get("samaccountname", "")
        email = _extract_email(props, name)
        enabled = props.get("enabled", True)
        dn    = props.get("distinguishedname", "")

        # ── Name: prefer explicit AD attributes, fall back to CN in DN ────────
        first_ad = props.get("givenname", "") or props.get("firstname", "")
        last_ad  = props.get("sn", "") or props.get("surname", "") or props.get("lastname", "")
        if first_ad or last_ad:
            first_name = first_ad.title()
            last_name  = last_ad.title()
            full_name  = f"{first_name} {last_name}".strip()
        else:
            first_name, last_name, full_name = _parse_cn_name(dn)

        # Also extract username from UPN (JDOE@DOMAIN → jdoe)
        upn_user = name.split("@")[0].lower() if "@" in name else sam.lower()

        # Department from first OU component of DN
        department = _parse_department(dn)

        # Assemble address string from AD fields if any parts are present
        addr_parts = [
            props.get("streetaddress", ""),
            props.get("l", ""),           # city (locality)
            props.get("st", ""),          # state
            props.get("postalcode", ""),
            props.get("co", "") or props.get("c", ""),  # country
        ]
        addresses = [", ".join(p for p in addr_parts if p)] if any(addr_parts) else []

        # ── AD attack-surface attributes (Kerberos / delegation tradecraft) ──
        spns = props.get("serviceprincipalnames", []) or []
        if isinstance(spns, str):
            spns = [spns] if spns else []
        is_kerberoastable = _truthy(props.get("hasspn")) or bool(spns)
        is_asrep_roastable = _truthy(props.get("dontreqpreauth"))
        unconstrained = _truthy(props.get("unconstraineddelegation"))
        allowed_to_delegate = _principal_sids(user.get("AllowedToDelegate"))
        # RC4-only accounts make Kerberoast/AS-REP hashes far cheaper to crack.
        # supportedencryptiontypes bit 0x18 (24) = AES128+AES256; absence ⇒ RC4/DES.
        enc_types = props.get("supportedencryptiontypes")
        rc4_only = bool(is_kerberoastable) and (
            enc_types in (None, 0, 4, "0", "4") or not (isinstance(enc_types, int) and enc_types & 0x18)
        )

        ent = ParsedEntity(
            entity_type="Individual",
            label=name,
            temp_id=sid,
            properties={
                "sid":              sid,
                "sam_account_name": sam or upn_user,
                "email":            email,
                "enabled":          enabled,
                "display_name":     props.get("displayname", "") or full_name,
                "description":      props.get("description", ""),
                "title":            props.get("title", ""),
                "company":          props.get("company", ""),
                "manager":          props.get("manager", ""),
                "is_admin":         props.get("admincount", False),
                "last_logon":       props.get("lastlogon"),
                "pwd_last_set":     props.get("pwdlastset"),
                "source":           "sharphound",
                # ── AD attack surface (Kerberos / delegation) ─────────────
                "is_kerberoastable":       is_kerberoastable,
                "spn_count":               len(spns),
                "spns":                    spns,
                "is_asrep_roastable":      is_asrep_roastable,
                "unconstrained_delegation": unconstrained,
                "constrained_delegation":  _truthy(props.get("trustedtoauth")) or bool(allowed_to_delegate),
                "is_sensitive":            _truthy(props.get("sensitive")),
                "rc4_only":                rc4_only,
                # ── Identity ──────────────────────────────────────────────
                "first_name":       first_name,
                "last_name":        last_name,
                "full_name":        full_name,
                "middle_name":      props.get("middlename", ""),
                "username":         upn_user,
                "department":       department,
                # ── Contact ───────────────────────────────────────────────
                "phone":            props.get("telephonenumber", "") or props.get("telephone_number", ""),
                "mobile":           props.get("mobile", "") or props.get("mobiletelephonenumber", ""),
                "addresses":        addresses,
                # ── Photo ─────────────────────────────────────────────────
                "photo_url":        _thumbnail_to_data_url(props),
            },
        )
        entities.append(ent)

        # ACEs on this user
        for ace in user.get("Aces", []):
            _process_ace(ace, sid, "User", relationships, high_value_aces, errors)

        # Primary group membership (PrimaryGroupSid is a single SID string, not a list)
        primary_sid = user.get("PrimaryGroupSid", "")
        if isinstance(primary_sid, str) and primary_sid:
            relationships.append(ParsedRelationship(
                source_temp_id=sid,
                target_temp_id=primary_sid,
                label="MEMBER_OF",
                data={"primary_group": True},
            ))

        # Constrained delegation: this user can delegate to the target computer/SPN.
        for tgt_sid in allowed_to_delegate:
            relationships.append(ParsedRelationship(
                source_temp_id=sid, target_temp_id=tgt_sid,
                label="AllowedToDelegate", data={"delegation": "constrained"},
            ))
        # SID history: this principal inherits the rights of the historical SID.
        for old_sid in _principal_sids(user.get("HasSIDHistory")):
            relationships.append(ParsedRelationship(
                source_temp_id=sid, target_temp_id=old_sid,
                label="HasSIDHistory", data={},
            ))

    # ── Computers ────────────────────────────────────────────────────────────
    for computer in (load("computers.json") or []):
        props = computer.get("Properties", {})
        sid = computer.get("ObjectIdentifier", "")
        name = props.get("name", sid)
        is_dc = bool(DC_PATTERNS.search(name)) or props.get("isdc", False)
        unconstrained = _truthy(props.get("unconstraineddelegation"))
        allowed_to_delegate = _principal_sids(computer.get("AllowedToDelegate"))

        ent = ParsedEntity(
            entity_type="Device",
            label=name,
            temp_id=sid,
            properties={
                "device_id":      sid,
                "sid":            sid,
                "hostname":       name,
                # Canonical SAM key is sam_account_name across ALL node types
                # (individuals + devices). AD's raw attribute is 'samaccountname';
                # we normalise it here so a single graph key covers every SID.
                "sam_account_name": props.get("samaccountname", ""),
                "description":    props.get("description", ""),
                "managed_by":     props.get("managedby", "") or props.get("managedBy", ""),
                "dnshostname":    props.get("dnshostname", ""),
                "domain":         props.get("domain", ""),
                "operating_system": props.get("operatingsystem", ""),
                "is_dc":          is_dc,
                "enabled":        props.get("enabled", True),
                "source":         "sharphound",
                # ── AD attack surface (delegation / LAPS) ─────────────────
                "unconstrained_delegation": unconstrained,
                "constrained_delegation":   _truthy(props.get("trustedtoauth")) or bool(allowed_to_delegate),
                "has_laps":                 _truthy(props.get("haslaps")),
                # ── Activity / staleness (drives WF12's "hosts in use" filter) ──
                # Naming mirrors the Individual branch above (last_logon /
                # pwd_last_set) plus the two device-relevant extras. All POSIX
                # seconds, 0 = unknown.
                "last_logon":           _epoch(props.get("lastlogon")),
                "last_logon_timestamp": _epoch(props.get("lastlogontimestamp")),
                "pwd_last_set":         _epoch(props.get("pwdlastset")),
                "when_created":         _epoch(props.get("whencreated")),
                # Precomputed max so WF12, the UI and the backfill script can
                # never disagree on the tie-break. lastlogon is 0 on most objects
                # (it is not replicated between DCs); lastlogontimestamp is, but
                # only every 9-14 days — hence the 90-day default window. The
                # machine-account password rotates every 30 days by default, so
                # pwdlastset is a good third signal for a host that is powered on.
                "last_activity_ts":     max(_epoch(props.get("lastlogontimestamp")),
                                            _epoch(props.get("lastlogon")),
                                            _epoch(props.get("pwdlastset"))),
                "activity_source":      "sharphound",
            },
        )
        entities.append(ent)

        # Unconstrained-delegation hosts (and DCs) are coercion → TGT-capture
        # targets: coerce them (PetitPotam / PrinterBug / DFSCoerce) to auth to
        # an attacker-controlled host and capture/relay the TGT (krbrelayx).
        if unconstrained:
            relationships.append(ParsedRelationship(
                source_temp_id=sid, target_temp_id=sid,
                label="CoerceToTGT", data={"reason": "unconstrained_delegation"},
            ))

        # Resource-based constrained delegation (RBCD): principals listed in
        # msDS-AllowedToActOnBehalfOfOtherIdentity can impersonate to this host.
        for principal_sid in _principal_sids(computer.get("AllowedToAct")):
            relationships.append(ParsedRelationship(
                source_temp_id=principal_sid, target_temp_id=sid,
                label="AllowedToAct", data={"delegation": "rbcd"},
            ))
        # Constrained delegation targets configured on the computer object.
        for tgt_sid in allowed_to_delegate:
            relationships.append(ParsedRelationship(
                source_temp_id=sid, target_temp_id=tgt_sid,
                label="AllowedToDelegate", data={"delegation": "constrained"},
            ))
        for old_sid in _principal_sids(computer.get("HasSIDHistory")):
            relationships.append(ParsedRelationship(
                source_temp_id=sid, target_temp_id=old_sid,
                label="HasSIDHistory", data={},
            ))

        # Lateral-movement rights (BloodHound CE exposes these as separate keys,
        # each with a .Results principal list). Edge: principal -[right]-> host.
        for group_key, edge_label in (
            ("RemoteDesktopUsers", "CanRDP"),
            ("DcomUsers",          "ExecuteDCOM"),
            ("PSRemoteUsers",      "CanPSRemote"),
        ):
            for member in computer.get(group_key, {}).get("Results", []):
                member_sid = member.get("ObjectIdentifier", "")
                if member_sid:
                    relationships.append(ParsedRelationship(
                        source_temp_id=member_sid, target_temp_id=sid,
                        label=edge_label, data={"computer_name": name},
                    ))

        # Sessions: users logged into this computer
        for session in computer.get("Sessions", {}).get("Results", []):
            user_sid = session.get("UserSID", "")
            if user_sid:
                relationships.append(ParsedRelationship(
                    source_temp_id=user_sid,
                    target_temp_id=sid,
                    label="HAS_SESSION",
                    data={"computer_name": name, "is_dc": is_dc},
                ))

        # LocalAdmins
        for la in computer.get("LocalAdmins", {}).get("Results", []):
            member_sid = la.get("ObjectIdentifier", "")
            if member_sid:
                relationships.append(ParsedRelationship(
                    source_temp_id=member_sid,
                    target_temp_id=sid,
                    label="LOCAL_ADMIN",
                    data={"computer_name": name},
                ))

        # ACEs on this computer
        for ace in computer.get("Aces", []):
            _process_ace(ace, sid, "Computer", relationships, high_value_aces, errors)

    # ── Groups ───────────────────────────────────────────────────────────────
    for group in (load("groups.json") or []):
        props = group.get("Properties", {})
        sid = group.get("ObjectIdentifier", "")
        name = props.get("name", sid)
        is_high_value = bool(DA_GROUPS.search(name))

        ent = ParsedEntity(
            entity_type="Organization",
            label=name,
            temp_id=sid,
            properties={
                "sid": sid,
                "name": name,
                "managed_by": props.get("managedby", "") or props.get("managedBy", ""),
                "is_high_value": is_high_value,
                "admin_count": props.get("admincount", False),
                "source": "sharphound",
            },
        )
        entities.append(ent)

        for member in group.get("Members", []):
            member_sid = member.get("ObjectIdentifier", "")
            if member_sid:
                relationships.append(ParsedRelationship(
                    source_temp_id=member_sid,
                    target_temp_id=sid,
                    label="MEMBER_OF",
                    data={"group_name": name, "is_high_value": is_high_value},
                ))

        for ace in group.get("Aces", []):
            _process_ace(ace, sid, "Group", relationships, high_value_aces, errors)

        for old_sid in _principal_sids(group.get("HasSIDHistory")):
            relationships.append(ParsedRelationship(
                source_temp_id=sid, target_temp_id=old_sid,
                label="HasSIDHistory", data={},
            ))

    # ── Domains & trusts (child→root forest escalation tradecraft) ────────────
    for domain in (load("domains.json") or []):
        props = domain.get("Properties", {})
        sid = domain.get("ObjectIdentifier", "")
        name = props.get("name", sid)
        if not sid:
            continue
        entities.append(ParsedEntity(
            entity_type="Organization",
            label=name,
            temp_id=sid,
            properties={
                "sid": sid, "name": name, "is_domain": True,
                "functional_level": props.get("functionallevel", ""),
                "is_high_value": True, "source": "sharphound",
            },
        ))
        for ace in domain.get("Aces", []):
            _process_ace(ace, sid, "Domain", relationships, high_value_aces, errors)
        for trust in domain.get("Trusts", []):
            target_sid = trust.get("TargetDomainSid", "")
            if not target_sid:
                continue
            relationships.append(ParsedRelationship(
                source_temp_id=sid, target_temp_id=target_sid,
                label="TrustedBy",
                data={
                    "trust_direction":  trust.get("TrustDirection"),
                    "trust_type":       trust.get("TrustType"),
                    "is_transitive":    trust.get("IsTransitive"),
                    "sid_filtering":    trust.get("SidFilteringEnabled"),
                    "target_domain":    trust.get("TargetDomainName"),
                },
            ))
        _process_gplinks(domain.get("Links", []), sid, relationships)

    # ── GPOs (GPO-abuse / UNC-path hijack tradecraft) ─────────────────────────
    for gpo in (load("gpos.json") or []):
        props = gpo.get("Properties", {})
        sid = gpo.get("ObjectIdentifier", "")
        name = props.get("name", sid)
        if not sid:
            continue
        entities.append(ParsedEntity(
            entity_type="GPO",
            label=name,
            temp_id=sid,
            properties={
                "sid": sid, "name": name,
                "gpcpath": props.get("gpcpath", ""),
                "source": "sharphound",
            },
        ))
        # ACEs on a GPO surface WriteDacl/WriteOwner/GenericAll/WriteGPLink etc.
        for ace in gpo.get("Aces", []):
            _process_ace(ace, sid, "GPO", relationships, high_value_aces, errors)

    # ── OUs / containers (GpLink → who a GPO applies to) ──────────────────────
    for container_file in ("ous.json", "containers.json"):
        for ou in (load(container_file) or []):
            props = ou.get("Properties", {})
            sid = ou.get("ObjectIdentifier", "")
            name = props.get("name", sid)
            if not sid:
                continue
            entities.append(ParsedEntity(
                entity_type="Organization",
                label=name,
                temp_id=sid,
                properties={
                    "sid": sid, "name": name, "is_ou": True,
                    "source": "sharphound",
                },
            ))
            for ace in ou.get("Aces", []):
                _process_ace(ace, sid, "OU", relationships, high_value_aces, errors)
            _process_gplinks(ou.get("Links", []), sid, relationships)

    # ── ADCS: certificate templates & enterprise CAs (ESC1/ESC8 — Certipy) ────
    _parse_adcs(load, entities, relationships, high_value_aces, errors)

    return ParseResult(
        entities=entities,
        relationships=relationships,
        schema_version="v2",
        errors=errors,
        high_value_aces=high_value_aces,
    )


def _process_gplinks(
    links: List[dict], container_sid: str, relationships: List[ParsedRelationship]
) -> None:
    """Emit GpLink edges: GPO -[GpLink]-> OU/domain it is linked to."""
    for link in links or []:
        gpo_sid = link.get("GUID") or link.get("GPOIdentifier") or ""
        if gpo_sid:
            relationships.append(ParsedRelationship(
                source_temp_id=gpo_sid, target_temp_id=container_sid,
                label="GpLink", data={"enforced": link.get("IsEnforced")},
            ))


def _parse_adcs(
    load,
    entities: List[ParsedEntity],
    relationships: List[ParsedRelationship],
    high_value_aces: List[Dict[str, Any]],
    errors: List[str],
) -> None:
    """
    Parse SharpHound-CE ADCS objects into certtemplate / enterpriseca nodes and
    ADCS abuse edges. Degrades gracefully when the collection omits ADCS files.

    Modeled ESC conditions (first-cut; extend for ESC2–16):
      ESC1 — template allows enrollee-supplied subject + client-auth EKU +
             no manager approval, and a low-priv principal can Enroll.
      ESC8 — an enterprise CA exposes HTTP web enrollment (coerce + NTLM relay).
    """
    # Enterprise CAs
    for ca in (load("enterprisecas.json") or []):
        props = ca.get("Properties", {})
        sid = ca.get("ObjectIdentifier", "")
        name = props.get("name", sid)
        if not sid:
            continue
        web_enroll = (
            _truthy(props.get("webenrollment"))
            or bool(ca.get("HttpEnrollmentEndpoints"))
            or bool(props.get("HttpEnrollmentEndpoints"))
        )
        entities.append(ParsedEntity(
            entity_type="EnterpriseCA",
            label=name,
            temp_id=sid,
            properties={
                "sid": sid, "name": name,
                "dns_hostname": props.get("dnshostname", ""),
                "web_enrollment": web_enroll,
                "esc8": web_enroll,
                "user_specified_san": _truthy(props.get("userspecifiedsan")),
                "source": "sharphound",
            },
        ))
        for ace in ca.get("Aces", []):
            _process_ace(ace, sid, "EnterpriseCA", relationships, high_value_aces, errors)
        # Templates published to this CA are enrollable through it.
        for tmpl in ca.get("EnabledCertTemplates", []) or []:
            tmpl_sid = tmpl.get("ObjectIdentifier", "") if isinstance(tmpl, dict) else tmpl
            if tmpl_sid:
                relationships.append(ParsedRelationship(
                    source_temp_id=tmpl_sid, target_temp_id=sid,
                    label="PublishedTo", data={},
                ))

    # Certificate templates
    for tmpl in (load("certtemplates.json") or []):
        props = tmpl.get("Properties", {})
        sid = tmpl.get("ObjectIdentifier", "")
        name = props.get("name") or props.get("displayname") or sid
        if not sid:
            continue
        ekus = [str(e).lower() for e in (props.get("effectiveekus") or props.get("ekus") or [])]
        client_auth = _truthy(props.get("authenticationenabled")) or any(
            k in " ".join(ekus) for k in ("client authentication", "1.3.6.1.5.5.7.3.2",
                                           "smart card logon", "1.3.6.1.4.1.311.20.2.2",
                                           "any purpose", "2.5.29.37.0")
        )
        ess = _truthy(props.get("enrolleesuppliessubject"))
        no_approval = not _truthy(props.get("requiresmanagerapproval"))
        enabled = _truthy(props.get("enabled"))
        esc1 = enabled and ess and client_auth and no_approval
        esc_vulns = ["ESC1"] if esc1 else []
        entities.append(ParsedEntity(
            entity_type="CertTemplate",
            label=name,
            temp_id=sid,
            properties={
                "sid": sid, "name": name,
                "enabled": enabled,
                "client_auth_eku": client_auth,
                "enrollee_supplies_subject": ess,
                "requires_manager_approval": not no_approval,
                "esc1": esc1,
                "esc_vulnerabilities": esc_vulns,
                "source": "sharphound",
            },
        ))
        for ace in tmpl.get("Aces", []):
            _process_ace(ace, sid, "CertTemplate", relationships, high_value_aces, errors)


def _process_ace(
    ace: dict,
    object_sid: str,
    object_type: str,
    relationships: List[ParsedRelationship],
    high_value_aces: List[Dict[str, Any]],
    errors: List[str],
) -> None:
    """Process a single ACE entry and append to relationships / high_value_aces."""
    principal_sid = ace.get("PrincipalSID", "")
    right = ace.get("RightName", ace.get("right_name", ""))
    if not principal_sid or not right:
        return

    is_high_value_right = right in HIGH_VALUE_RIGHTS
    # Use the ACE right name as the relationship label so it is queryable in
    # Cypher via type(r).  The Flowsint Edge schema has no data/property field,
    # so encoding the right in the label is the only way to preserve it.
    relationships.append(ParsedRelationship(
        source_temp_id=principal_sid,
        target_temp_id=object_sid,
        label=right,
        data={},
    ))

    if is_high_value_right:
        high_value_aces.append({
            "source_sid": principal_sid,
            "target_sid": object_sid,
            "target_type": object_type,
            "right": right,
        })


# ── v3 parser (legacy SharpHound 1.x) ────────────────────────────────────────

def _parse_v3(zip_obj: zipfile.ZipFile) -> ParseResult:
    """
    SharpHound v1 may bundle everything into a single JSON file with a top-level
    'meta' key, or split across timestamped files.  This parser handles both.
    """
    entities: List[ParsedEntity] = []
    relationships: List[ParsedRelationship] = []
    errors: List[str] = []

    for name in zip_obj.namelist():
        if not name.lower().endswith(".json"):
            continue
        try:
            with zip_obj.open(name) as f:
                data = json.load(f)
        except Exception as e:
            errors.append(f"Failed to parse {name}: {e}")
            continue

        meta = data.get("meta", {})
        obj_type = meta.get("type", "").lower()
        items = data.get("Collection", data.get(obj_type, []))

        for item in items:
            props = item.get("Properties", {})
            sid = item.get("ObjectIdentifier", item.get("ObjectSID", ""))
            name_val = props.get("Name", props.get("name", sid))

            if obj_type in ("users", "user"):
                v1_spns = props.get("ServicePrincipalNames", []) or []
                if isinstance(v1_spns, str):
                    v1_spns = [v1_spns] if v1_spns else []
                ent = ParsedEntity(
                    entity_type="Individual",
                    label=name_val,
                    temp_id=sid,
                    properties={
                        "sid": sid,
                        "sam_account_name": props.get("SamAccountName", ""),
                        "email": _extract_email(props, name_val),
                        "enabled": props.get("Enabled", True),
                        "source": "sharphound_v1",
                        "is_kerberoastable":  _truthy(props.get("HasSPN")) or bool(v1_spns),
                        "spn_count":          len(v1_spns),
                        "is_asrep_roastable": _truthy(props.get("DontRequirePreAuth")),
                        "unconstrained_delegation": _truthy(props.get("UnconstrainedDelegation")),
                    },
                )
                entities.append(ent)
                for ace in item.get("Aces", []):
                    _process_ace(ace, sid, "User", relationships, [], errors)

            elif obj_type in ("computers", "computer"):
                ent = ParsedEntity(
                    entity_type="Computer",
                    label=name_val,
                    temp_id=sid,
                    properties={
                        "sid": sid,
                        "hostname": name_val,
                        "operating_system": props.get("OperatingSystem", ""),
                        "source": "sharphound_v1",
                        # Activity / staleness — see the v2 branch for the rationale.
                        # SharpHound v1 uses CamelCase and has no LastLogonTimestamp.
                        "last_logon":       _epoch(props.get("LastLogon")),
                        "pwd_last_set":     _epoch(props.get("PwdLastSet")),
                        "last_activity_ts": max(_epoch(props.get("LastLogon")),
                                                _epoch(props.get("PwdLastSet"))),
                        "activity_source":  "sharphound_v1",
                    },
                )
                entities.append(ent)

    return ParseResult(
        entities=entities,
        relationships=relationships,
        schema_version="v3",
        errors=errors,
        high_value_aces=[],
    )


# ── Public interface ──────────────────────────────────────────────────────────

def parse_zip_bytes(data: bytes) -> ParseResult:
    """Parse a SharpHound ZIP from raw bytes."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        version = _detect_schema(zf)
        if version == "v2":
            return _parse_v2(zf)
        return _parse_v3(zf)


def parse_zip_file(path: str) -> ParseResult:
    """Parse a SharpHound ZIP from a file path."""
    with zipfile.ZipFile(path) as zf:
        version = _detect_schema(zf)
        if version == "v2":
            return _parse_v2(zf)
        return _parse_v3(zf)


def parse_standalone_json(data: bytes, filename: str = "") -> ParseResult:
    """
    Parse a standalone SharpHound v2 JSON file (e.g., users.json, computers.json).
    
    Wraps the JSON in a temporary ZIP structure so _parse_v2 can handle it.
    Infers the filename from the provided parameter if not otherwise known.
    """
    # Ensure filename has appropriate extension
    fname = (filename or "users.json").lower()
    if not fname.endswith(".json"):
        fname += ".json"
    
    # Wrap JSON in a temporary ZIP
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr(fname, data)
    
    zip_buffer.seek(0)
    return parse_zip_bytes(zip_buffer.read())


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sharphound_parser.py <path-to-zip>")
        sys.exit(1)

    result = parse_zip_file(sys.argv[1])
    print(f"Schema version : {result.schema_version}")
    print(f"Entities       : {len(result.entities)}")
    print(f"Relationships  : {len(result.relationships)}")
    print(f"High-value ACEs: {len(result.high_value_aces)}")
    if result.errors:
        print("Errors:")
        for e in result.errors:
            print(f"  {e}")
    if result.high_value_aces:
        print("\nHigh-value ACEs found (alert!):")
        for ace in result.high_value_aces[:10]:
            print(f"  {ace['source_sid']} --[{ace['right']}]--> {ace['target_sid']} ({ace['target_type']})")
