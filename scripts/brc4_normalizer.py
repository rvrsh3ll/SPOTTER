"""
brc4_normalizer.py — Normalise Brute Ratel C4 listener webhook payloads.

Brute Ratel has NO REST API. Per the BRc4 2.6 manual the ratel server is
WebSocket-driven and its API reference ships separately from the manual, so
SPOTTER ingests badgers the other documented way: listener **webhooks**, which
push to a host the operator controls (manual §WebHooks, p27-28).

Enable per listener in Commander: right-click listener → Webhook → Enable, set
the URL, tick "Badger's Initial Connection" and/or "Badger's Command Output".
Webhooks are per-LISTENER — a badger on a listener without it enabled is
invisible to SPOTTER.

Two payload shapes arrive on the same endpoint:

  initial connection
    {"badger":"b-2","badger_config":{"b_arch":"x64","b_bld":"19045",
      "b_c2":"https://172.16.219.1:443","b_c2_id":"primary-c2","b_cookie":"...",
      "b_h_name":"DESKTOP-G15FRLS","b_ip":"172.16.88.135","b_l_ip":"172.16.219.1",
      "b_p_name":"Z:\\\\documents\\\\badger.exe","b_pid":"2028",
      "b_seen":"08-20-2023 14:42:39","b_tid":"4780","b_uid":"vendetta",
      "b_wver":"x64/10.0","dead":false,"is_pvt":false,"pipeline":"Direct",
      "pvt_master":""}}

  command output
    {"badger":"b-2","badger_msg":"<base64>","main_cmd":"pwd"}

Both are dispatched by normalise_webhook(), which emits the canonical C2Session
dict documented in c2_common.py.

What BRc4 does NOT send, and the consequences:
  - no elevation flag  → is_admin stays None (unknown, not False). Backfilled
                         heuristically from userinfo/get_system output.
  - no process list    → tech_stack is empty until a pslist/ps output event.
  Both feed score_session(), so a fresh badger scores lower than an equivalent
  CS beacon. See the note in c2_common.score_session.

b_cookie is deliberately NOT carried into the graph: it is the badger's session
token, and the graph is exported into shareable campaign bundles (WF19).

Environment variables:
  BRC4_SERVER_TZ_OFFSET_HOURS — b_seen carries no timezone. Default is to read it
                                as UTC; set e.g. "-4" if the ratel server's clock
                                is local. A wrong offset silently breaks both the
                                +5 recency score and the enricher's 30-minute
                                "active session" threshold.

All badger data processed here originates from an authorized red team engagement
running under documented Rules of Engagement.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from c2_common import finalize_session, infer_tech_stack

C2_FRAMEWORK = "brute_ratel"

# b_seen is MM-DD-YYYY HH:MM:SS (US ordering, no timezone).
_SEEN_FORMAT = "%m-%d-%Y %H:%M:%S"

# Commands whose output is a process listing. Names per the BRc4 2.6 command
# reference; the badger has no single canonical "ps", so accept the family.
PROCESS_LIST_COMMANDS = {"ps", "pslist", "psgrep", "ps_ex"}

# Commands whose output may reveal elevation.
IDENTITY_COMMANDS = {"userinfo", "get_system", "grab_token", "impersonate",
                     "make_token", "addpriv", "whoami"}

# Deliberately format-agnostic: the manual documents no output layout for these
# commands (its examples are screenshots), so pull anything that looks like an
# executable name rather than fitting columns that may not exist.
_EXE_RE = re.compile(r"[A-Za-z0-9_.\-+]+\.exe", re.IGNORECASE)

# Lowercased markers that indicate an elevated token. Only ever used to set
# is_admin True — absence proves nothing, so it is never set False from output.
_ELEVATED_MARKERS = (
    r"nt authority\system",
    "sedebugprivilege",
    "setcbprivilege",
    "elevated: true",
    "is admin: true",
    "integrity: high",
    "integrity: system",
    "builtin\\administrators",
)


def _tz() -> timezone:
    """Timezone to read b_seen in — UTC unless BRC4_SERVER_TZ_OFFSET_HOURS says otherwise."""
    raw = (os.environ.get("BRC4_SERVER_TZ_OFFSET_HOURS") or "").strip()
    if not raw:
        return timezone.utc
    try:
        return timezone(timedelta(hours=float(raw)))
    except (ValueError, OverflowError):
        return timezone.utc


def parse_seen(value: Any) -> Optional[datetime]:
    """Parse BRc4's b_seen ('08-20-2023 14:42:39') into an aware UTC datetime."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        naive = datetime.strptime(text, _SEEN_FORMAT)
    except ValueError:
        # Tolerate an ISO-ish value in case a future release changes the format.
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=_tz())
    return naive.replace(tzinfo=_tz()).astimezone(timezone.utc)


def _os_version(cfg: Dict[str, Any]) -> str:
    """
    Compose an OS string from b_wver ('x64/10.0') and b_bld ('19045').

    b_wver packs arch and version together; only the version half is wanted here
    because arch is already reported separately in b_arch.
    """
    wver = str(cfg.get("b_wver") or "").strip()
    build = str(cfg.get("b_bld") or "").strip()
    version = wver.split("/")[-1].strip() if "/" in wver else wver
    if version and build:
        return f"Windows {version} (build {build})"
    if version:
        return f"Windows {version}"
    return f"build {build}" if build else ""


def _int_or_none(value: Any) -> Optional[int]:
    """BRc4 sends pid/tid as strings."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def decode_badger_msg(value: Any) -> str:
    """
    Decode a base64 badger_msg. Returns the raw string unchanged if it is not
    valid base64, so a future plaintext payload still surfaces its output.
    """
    text = str(value or "")
    if not text:
        return ""
    try:
        return base64.b64decode(text, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return text


def normalise_initial(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalise a "Badger's Initial Connection" webhook into a canonical C2Session.

    BRc4 → canonical mapping:
      badger              → session_id
      b_h_name            → hostname
      b_uid               → username
      b_ip                → internal_ip
      b_c2                → c2_server
      b_c2_id             → listener
      b_wver + b_bld      → os_version
      b_arch              → arch
      b_p_name            → process_name (full path, not a bare name)
      b_pid / b_tid       → pid / thread_id
      b_seen              → last_checkin
      dead                → is_dead
      is_pvt / pvt_master / pipeline → is_pivot / pivot_parent / pivot_channel

    b_l_ip is the LISTENER's address, not the victim's public IP — it is kept as
    listener_ip and deliberately not mapped to external_ip, which would otherwise
    read as the target's egress address in every dossier.
    """
    cfg = payload.get("badger_config") or {}
    if not isinstance(cfg, dict):
        cfg = {}

    last_checkin_dt = parse_seen(cfg.get("b_seen"))

    session = {
        "c2_framework":    C2_FRAMEWORK,
        "session_id":      str(payload.get("badger") or "").strip(),
        "c2_server":       str(cfg.get("b_c2") or "").strip(),
        "hostname":        str(cfg.get("b_h_name") or "unknown").strip(),
        "username":        str(cfg.get("b_uid") or "").strip(),
        "internal_ip":     str(cfg.get("b_ip") or "").strip(),
        # BRc4 reports no victim-side public IP.
        "external_ip":     "",
        "listener_ip":     str(cfg.get("b_l_ip") or "").strip(),
        "os_version":      _os_version(cfg),
        "arch":            str(cfg.get("b_arch") or "").strip(),
        "pid":             _int_or_none(cfg.get("b_pid")),
        "thread_id":       _int_or_none(cfg.get("b_tid")),
        "process_name":    str(cfg.get("b_p_name") or "").strip(),
        # Not reported by BRc4 — None means unknown, NOT non-admin.
        "is_admin":        None,
        "last_checkin":    last_checkin_dt.isoformat() if last_checkin_dt else None,
        "last_checkin_dt": last_checkin_dt,
        "sleep_seconds":   None,
        "jitter_pct":      None,
        "listener":        str(cfg.get("b_c2_id") or "").strip(),
        "note":            "",
        "process_list":    [],
        "is_dead":         bool(cfg.get("dead")),
        "is_pivot":        bool(cfg.get("is_pvt")),
        "pivot_parent":    str(cfg.get("pvt_master") or "").strip(),
        "pivot_channel":   str(cfg.get("pipeline") or "").strip(),
        "source":          C2_FRAMEWORK,
    }
    return finalize_session(session)


def extract_process_list(output: str) -> List[str]:
    """Pull executable names out of a process-listing command's output."""
    seen: Dict[str, None] = {}
    for match in _EXE_RE.findall(output or ""):
        name = os.path.basename(match.replace("\\", "/")).lower()
        seen.setdefault(name, None)
    return sorted(seen)


def looks_elevated(output: str) -> bool:
    """Conservative elevation heuristic over identity-command output."""
    low = (output or "").lower()
    return any(marker in low for marker in _ELEVATED_MARKERS)


def normalise_command_output(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalise a "Badger's Command Output" webhook.

    Returns a partial session update rather than a whole C2Session: this event
    carries no host metadata, only {badger, main_cmd, decoded output}. Fields the
    output can enrich (process_list, tech_stack, is_admin) are included when the
    command is one that reveals them.
    """
    command = str(payload.get("main_cmd") or "").strip()
    output = decode_badger_msg(payload.get("badger_msg"))
    base_cmd = command.split()[0].lower() if command else ""

    update: Dict[str, Any] = {
        "c2_framework": C2_FRAMEWORK,
        "session_id":   str(payload.get("badger") or "").strip(),
        "main_cmd":     command,
        "output":       output,
    }

    if base_cmd in PROCESS_LIST_COMMANDS:
        processes = extract_process_list(output)
        if processes:
            update["process_list"] = processes
            update["tech_stack"] = infer_tech_stack(processes)

    # Only ever promotes to True: no marker in the output is not evidence of a
    # low-privilege token, so is_admin is left absent rather than set False.
    if base_cmd in IDENTITY_COMMANDS and looks_elevated(output):
        update["is_admin"] = True

    return update


def normalise_webhook(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dispatch either webhook shape. Both arrive on the same endpoint, told apart by
    which key is present: badger_config (initial connection) vs badger_msg
    (command output).

    Returns {'event': 'initial'|'command'|'unknown', ...fields}. 'unknown' carries
    an 'error' rather than raising, so one malformed POST cannot take down the
    receiving workflow.
    """
    if not isinstance(payload, dict):
        return {"event": "unknown", "error": f"payload is {type(payload).__name__}, expected object"}

    if isinstance(payload.get("badger_config"), dict):
        return {"event": "initial", **normalise_initial(payload)}

    if "badger_msg" in payload:
        return {"event": "command", **normalise_command_output(payload)}

    return {
        "event": "unknown",
        "error": f"no badger_config or badger_msg in payload (keys: {sorted(payload)[:10]})",
        "session_id": str(payload.get("badger") or "").strip(),
    }


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json as _json
    import sys as _sys

    raw = open(_sys.argv[1]).read() if len(_sys.argv) > 1 else _sys.stdin.read()
    try:
        parsed = _json.loads(raw)
    except ValueError as exc:
        print(f"brc4_normalizer: not JSON: {exc}", file=_sys.stderr)
        raise SystemExit(1)

    for entry in (parsed if isinstance(parsed, list) else [parsed]):
        print(_json.dumps(normalise_webhook(entry), indent=2, default=str))
