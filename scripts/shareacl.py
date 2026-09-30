"""
shareacl.py - Cross-platform Python SMB share enumerator for SPOTTER.

This script emits SPOTTER-compatible lines:

    [shareacl] {"host":"FILESERVER",...}

It writes the exact same lines to shareacl_results.txt in the current working
directory.

Safe-use constraints:
  - Authorized red-team / penetration-test engagements only.
  - Read-only enumeration; no share or ACL modifications are made.
  - Requires explicit SMB authentication: username, password, and domain.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    from smb.SMBConnection import SMBConnection
    from smb.smb_structs import OperationFailure
except ImportError:
    SMBConnection = None

    class OperationFailure(Exception):
        pass

try:
    from ldap3 import BASE, DSA, NTLM, SUBTREE, Connection, Server
except ImportError:
    BASE = DSA = NTLM = SUBTREE = None
    Connection = Server = None


RESULT_FILE_NAME = "shareacl_results.txt"
PREFIX = "[shareacl] "

USAGE_BLOCK = """Usage:
    python3 scripts/shareacl.py <host> --username <user> --password <pass> --domain <domain>
    python3 scripts/shareacl.py \\\\server\\share --username <user> --password <pass> --domain <domain>
    python3 scripts/shareacl.py --computers --dc <domain-controller> --username <user> --password <pass> --domain <domain>
    python3 scripts/shareacl.py --computers --dc <domain-controller> --ldaps --username <user> --password <pass> --domain <domain>

Examples:
    python3 scripts/shareacl.py FILESERVER --username operator --password 'Secret123!' --domain CORP
    python3 scripts/shareacl.py \\\\FILESERVER\\Finance$ --username operator --password 'Secret123!' --domain CORP
    python3 scripts/shareacl.py --computers --dc dc01.corp.local --username operator --password 'Secret123!' --domain CORP
    python3 scripts/shareacl.py --computers --dc dc01.corp.local --ldaps --username operator --password 'Secret123!' --domain CORP
    python3 scripts/shareacl.py --computers --dc 10.0.0.5 --base-dn DC=corp,DC=local --username operator --password 'Secret123!' --domain corp.local
"""

FILE_GENERIC_READ = 0x00120089


@dataclass
class AuthConfig:
    username: str
    password: str
    domain: str


class ResultWriter:
    def __init__(self, path: str) -> None:
        self.path = path
        self._fp = None

    def open(self) -> bool:
        try:
            self._fp = open(self.path, "w", encoding="utf-8", newline="")
            return True
        except OSError:
            self._fp = None
            return False

    def write_line(self, text: str) -> None:
        if not self._fp:
            return
        self._fp.write(text)
        self._fp.write("\n")

    def close(self) -> None:
        if self._fp:
            self._fp.close()
            self._fp = None


def _emit(writer: ResultWriter, payload: Dict[str, Any]) -> None:
    line = PREFIX + json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    writer.write_line(line)


def _emit_event_start(writer: ResultWriter, host: str, target: str) -> None:
    _emit(writer, {"source": "shareacl_bof", "host": host, "target": target, "event": "start"})


def _emit_event_done(writer: ResultWriter, host: str, count: int) -> None:
    _emit(writer, {"source": "shareacl_bof", "host": host, "event": "done", "count": count})


def _emit_event_ad_found(writer: ResultWriter, count: int) -> None:
    _emit(writer, {"source": "shareacl_bof", "event": "ad_computers_found", "count": count})


def _emit_event_ad_done(writer: ResultWriter, count: int, processed: int) -> None:
    _emit(writer, {"source": "shareacl_bof", "event": "ad_computers_done", "count": count, "processed": processed})


def _icacls_perm(rights: List[str]) -> str:
    if not rights:
        return "(N)"
    if "FULL" in rights:
        return "(F)"
    has_r = "READ" in rights
    has_w = "WRITE" in rights
    has_x = "EXECUTE" in rights
    if has_r and has_w and has_x:
        return "(M)"
    if has_r and has_x:
        return "(RX)"
    if has_r:
        return "(R)"
    if has_w:
        return "(W)"
    if has_x:
        return "(X)"
    return "(" + ",".join(rights) + ")"


def _print_icacls(record: Dict[str, Any]) -> None:
    print(record["unc_path"])
    for ace in record.get("acls", []):
        if ace.get("ace_type") == "ACCESS_DENIED":
            print("    Access is denied.")
            continue
        name = ace.get("trustee_name", "")
        domain = ace.get("trustee_domain", "")
        if domain and name:
            principal = f"{domain}\\{name}"
        elif name:
            principal = name
        else:
            principal = ace.get("trustee_sid") or "Unknown"
        perm = _icacls_perm(ace.get("rights", []))
        print(f"    {principal}:{perm}")
    if not record.get("acls"):
        print("    No permissions available.")
    print()


def _share_type_name(share: Any) -> str:
    name = str(getattr(share, "type", "")).lower()
    if "disk" in name:
        return "DISK"
    if "print" in name:
        return "PRINT"
    if "ipc" in name:
        return "IPC"
    if "device" in name:
        return "DEVICE"
    return "UNKNOWN"


def _effective_access_for_share(conn: SMBConnection, share_name: str) -> Tuple[int, List[str], str, str, Optional[int]]:
    """
    Read-only access check for the authenticated principal on the share root.

    This does not modify remote state. It uses listPath('/') as a practical read
    probe and maps the result to the expected ACL output schema.
    """
    try:
        conn.listPath(share_name, "/")
        return FILE_GENERIC_READ, ["READ"], "ACCESS_ALLOWED", "READ", None
    except OperationFailure as exc:
        msg = str(exc).lower()
        if "access denied" in msg or "status_access_denied" in msg:
            return 0, [], "ACCESS_DENIED", "DENY", 5
        return 0, [], "ACCESS_DENIED", "DENY", 1
    except Exception:
        return 0, [], "ACCESS_DENIED", "DENY", 1


def _build_share_record(host: str, share: Any, auth: AuthConfig, conn: SMBConnection) -> Dict[str, Any]:
    share_name = str(getattr(share, "name", ""))
    unc = "\\\\" + host + "\\" + share_name

    mask, rights, ace_type, effective_access, probe_error = _effective_access_for_share(conn, share_name)

    ace = {
        "trustee_sid": None,
        "trustee_name": auth.username,
        "trustee_domain": auth.domain,
        "trustee_type": "User",
        "access_mask": mask,
        "access_mask_hex": f"0x{mask & 0xFFFFFFFF:08X}",
        "ace_type": ace_type,
        "rights": rights,
        "effective_access": effective_access,
    }

    return {
        "host": host,
        "share_name": share_name,
        "unc_path": unc,
        "is_hidden": share_name.endswith("$"),
        "share_type": _share_type_name(share),
        "source": "shareacl_bof",
        "error_code": probe_error,
        "acls": [ace],
    }


def _connect(host: str, auth: AuthConfig) -> SMBConnection:
    if SMBConnection is None:
        raise RuntimeError("pysmb is required. Install dependencies from requirements.txt")

    client_name = (socket.gethostname() or "spotter-client")[:15]
    target_ip = socket.gethostbyname(host)
    conn = SMBConnection(
        auth.username,
        auth.password,
        client_name,
        host,
        domain=auth.domain,
        use_ntlm_v2=True,
        is_direct_tcp=True,
    )

    if not conn.connect(target_ip, 445, timeout=15):
        raise RuntimeError("SMB connection failed")
    return conn


def _process_host(writer: ResultWriter, host: str, auth: AuthConfig) -> None:
    conn = _connect(host, auth)
    try:
        shares = conn.listShares(timeout=15)
        _emit_event_start(writer, host, host)
        count = 0
        for share in shares:
            share_name = str(getattr(share, "name", ""))
            if not share_name:
                continue
            payload = _build_share_record(host, share, auth, conn)
            _emit(writer, payload)
            _print_icacls(payload)
            count += 1
        _emit_event_done(writer, host, count)
        print(f"Successfully processed {count} shares on {host}.")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _parse_unc_target(target: str) -> Tuple[Optional[str], Optional[str]]:
    normalized = target.rstrip("\\")
    if not normalized.startswith("\\\\"):
        return None, None

    rest = normalized[2:]
    first = rest.find("\\")
    if first < 0:
        return None, None

    server = rest[:first]
    share_start = rest[first + 1 :]
    second = share_start.find("\\")
    share = share_start if second < 0 else share_start[:second]

    if not server or not share:
        return None, None
    return server, share


def _print_usage_block() -> None:
    print(USAGE_BLOCK, file=sys.stderr)


def _process_single_share(writer: ResultWriter, host: str, share_name: str, target: str, auth: AuthConfig) -> None:
    conn = _connect(host, auth)
    try:
        _emit_event_start(writer, host, target)
        share = type("Share", (), {"name": share_name, "type": "DISK"})
        payload = _build_share_record(host, share, auth, conn)
        _emit(writer, payload)
        _print_icacls(payload)
        _emit_event_done(writer, host, 1)
        print(f"Successfully processed 1 share on {host}.")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _ldap_bind_user(auth: AuthConfig) -> str:
    if "\\" in auth.username or "@" in auth.username:
        return auth.username
    return f"{auth.domain}\\{auth.username}"


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _first_naming_context(values: List[Any]) -> str:
    """Pick a domain-style naming context (DC=...) from a namingContexts list."""
    cleaned = [str(raw or "").strip() for raw in values]
    cleaned = [v for v in cleaned if v]
    for v in cleaned:
        # Skip the Configuration/Schema/DomainDnsZones partitions.
        if "DC=" in v.upper() and not v.upper().startswith("CN="):
            return v
    return cleaned[0] if cleaned else ""


def _ldap_result_text(conn: Connection) -> str:
    """Human-readable LDAP result for the last operation.

    ldap3 defaults to raise_exceptions=False: a rejected search returns False and
    leaves the reason here, which is why failures must be read rather than assumed.
    """
    result = getattr(conn, "result", None) or {}
    parts = [str(result.get(key)).strip() for key in ("description", "message") if result.get(key)]
    text = " - ".join(p for p in parts if p)
    return text or "no LDAP result returned"


def _dn_from_domain(domain: str) -> str:
    """corp.example.com -> DC=corp,DC=example,DC=com. Empty for single-label/NetBIOS names."""
    labels = [label for label in str(domain or "").strip().strip(".").split(".") if label]
    if len(labels) < 2:
        return ""
    return ",".join(f"DC={label}" for label in labels)


def _base_dn_from_rootdse_entry(entry: Any) -> str:
    dnc = getattr(entry, "defaultNamingContext", None)
    if dnc is not None:
        value = str(dnc.value or "").strip()
        if value:
            return value

    ncs = getattr(entry, "namingContexts", None)
    if ncs is not None:
        return _first_naming_context(list(ncs.values or []))
    return ""


def _resolve_base_dn(conn: Connection, auth: AuthConfig) -> str:
    """Resolve the directory base DN, naming the real reason when RootDSE lookups fail."""
    failures: List[str] = []

    # get_info=DSA means ldap3 already read RootDSE at bind time; use it before searching again.
    info = getattr(conn.server, "info", None)
    if info is not None:
        other = getattr(info, "other", None) or {}
        for key, value in other.items():
            if str(key).lower() == "defaultnamingcontext":
                for raw in _as_list(value):
                    dn = str(raw or "").strip()
                    if dn:
                        return dn
        dn = _first_naming_context(_as_list(getattr(info, "naming_contexts", None)))
        if dn:
            return dn
        failures.append("server.info held no naming context")
    else:
        failures.append("server.info empty (RootDSE not returned at bind)")

    for attrs in (["defaultNamingContext", "namingContexts"], ["*"]):
        label = "+".join(attrs)
        try:
            ok = conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=attrs,
                check_names=False,
            )
        except Exception as exc:
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
            continue

        if not ok:
            failures.append(f"{label}: {_ldap_result_text(conn)}")
            continue
        if not conn.entries:
            failures.append(f"{label}: search returned no RootDSE entry")
            continue

        dn = _base_dn_from_rootdse_entry(conn.entries[0])
        if dn:
            return dn
        present = ", ".join(sorted(conn.entries[0].entry_attributes)) or "none"
        failures.append(f"{label}: RootDSE entry carried no naming context (attributes: {present})")

    detail = "; ".join(failures)
    derived = _dn_from_domain(auth.domain)
    if derived:
        print(
            f"shareacl: RootDSE lookup failed ({detail}); "
            f"falling back to base DN derived from --domain: {derived}",
            file=sys.stderr,
        )
        return derived

    raise RuntimeError(
        "unable to determine directory naming context from RootDSE "
        f"({detail}); pass --base-dn to set it explicitly"
    )


def _entry_attr(entry: Any, name: str) -> str:
    """Read one attribute from an ldap3 Entry or a paged_search result dict."""
    if isinstance(entry, dict):
        attributes = entry.get("attributes") or {}
        for key, value in attributes.items():
            if str(key).lower() == name.lower():
                if isinstance(value, (list, tuple)):
                    value = value[0] if value else ""
                return str(value or "").strip()
        return ""

    attr = getattr(entry, name, None)
    if attr is None:
        return ""
    value = attr.value
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    return str(value or "").strip()


def _enumerate_ad_computers(
    writer: ResultWriter,
    auth: AuthConfig,
    dc: str,
    base_dn_override: Optional[str] = None,
    ldap_port: Optional[int] = None,
    use_ldaps: bool = False,
    timeout: int = 30,
) -> None:
    if Connection is None or Server is None:
        raise RuntimeError("ldap3 is required for --computers mode. Install dependencies from requirements.txt")

    # get_info=DSA reads only RootDSE. The ldap3 default (SCHEMA) drags the whole
    # AD schema across the wire first, which is slow-to-fatal through a SOCKS tunnel.
    server = Server(
        dc,
        port=ldap_port or (636 if use_ldaps else 389),
        use_ssl=use_ldaps,
        get_info=DSA,
        connect_timeout=timeout,
    )
    print(
        f"shareacl: LDAP transport {'LDAPS' if use_ldaps else 'LDAP'} on port {server.port}",
        file=sys.stderr,
    )
    bind_user = _ldap_bind_user(auth)
    conn = Connection(
        server,
        user=bind_user,
        password=auth.password,
        authentication=NTLM,
        auto_bind=True,
        receive_timeout=timeout,
    )

    try:
        base_dn = (base_dn_override or "").strip() or _resolve_base_dn(conn, auth)
        print(f"shareacl: LDAP base DN {base_dn}", file=sys.stderr)

        comp_filter = "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        # Paged: AD caps a plain search at MaxPageSize (1000 by default) and reports
        # sizeLimitExceeded in conn.result, which would silently truncate the sweep.
        raw = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=comp_filter,
            search_scope=SUBTREE,
            attributes=["dNSHostName", "name"],
            paged_size=500,
            generator=False,
        )
        entries = [e for e in (raw or []) if not isinstance(e, dict) or e.get("type") == "searchResEntry"]

        if not entries:
            failure = _ldap_result_text(conn)
            if "success" not in failure.lower():
                raise RuntimeError(f"AD computer search failed under {base_dn}: {failure}")

        count = len(entries)
        _emit_event_ad_found(writer, count)
        print(f"\n{count} enabled AD computers found.\n")

        processed = 0
        for entry in entries:
            host = _entry_attr(entry, "dNSHostName") or _entry_attr(entry, "name")
            if not host:
                continue

            try:
                _process_host(writer, host, auth)
            except Exception as exc:
                print(f"shareacl: host scan failed for {host}: {exc}", file=sys.stderr)
            finally:
                processed += 1

        _emit_event_ad_done(writer, count, processed)
        print(f"\nCompleted processing {processed}/{count} AD computers.")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enumerate SMB shares and emit SPOTTER-compatible JSON lines.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=USAGE_BLOCK,
    )
    parser.add_argument("target", nargs="?", help="Host name/IP or UNC share path (\\\\server\\share)")
    parser.add_argument("--username", required=True, help="SMB username")
    parser.add_argument("--password", required=True, help="SMB password")
    parser.add_argument("--domain", required=True, help="SMB domain")
    parser.add_argument("--computers", action="store_true", help="Enumerate enabled AD computers via LDAP and scan each one")
    parser.add_argument("--dc", help="Domain controller hostname/IP for --computers mode")
    parser.add_argument("--base-dn", help="LDAP search base (e.g. DC=corp,DC=example,DC=com); skips RootDSE lookup")
    parser.add_argument("--ldap-port", type=int, help="LDAP port (default 389, or 636 with --ldaps)")
    parser.add_argument(
        "--ldaps",
        "--secure-ldap",
        dest="ldaps",
        action="store_true",
        help="Use LDAPS (secure LDAP); needed when the DC requires signing/sealing",
    )
    parser.add_argument("--timeout", type=int, default=30, help="LDAP connect/receive timeout in seconds (default 30)")
    args = parser.parse_args(argv)

    computers_mode = bool(args.computers or args.target == "--computers")
    if computers_mode:
        if args.target and args.target != "--computers":
            print("shareacl: use either <target> or --computers, not both", file=sys.stderr)
            _print_usage_block()
            return 1
        if not args.dc:
            print("shareacl: --dc is required with --computers", file=sys.stderr)
            _print_usage_block()
            return 1
    elif not args.target:
        print("shareacl: target is required unless --computers is used", file=sys.stderr)
        _print_usage_block()
        return 1

    auth = AuthConfig(username=args.username, password=args.password, domain=args.domain)

    cwd = os.getcwd()
    results_path = os.path.join(cwd, RESULT_FILE_NAME)
    writer = ResultWriter(results_path)

    if not writer.open():
        print(f"shareacl: could not open output file {RESULT_FILE_NAME}; console output only", file=sys.stderr)
    else:
        print(f"shareacl: writing results to {results_path}")

    try:
        if computers_mode:
            _enumerate_ad_computers(
                writer,
                auth,
                args.dc,
                base_dn_override=args.base_dn,
                ldap_port=args.ldap_port,
                use_ldaps=args.ldaps,
                timeout=args.timeout,
            )
        else:
            server, share = _parse_unc_target(args.target)
            if server and share:
                _process_single_share(writer, server, share, args.target, auth)
            else:
                _process_host(writer, args.target, auth)
    except Exception as exc:
        print(f"shareacl: error: {exc}", file=sys.stderr)
        return 1
    finally:
        writer.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())