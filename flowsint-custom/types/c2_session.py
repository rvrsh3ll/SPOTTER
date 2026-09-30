"""
C2Session — Flowsint custom node type.

Represents a single C2 session observed during an authorized red team engagement,
regardless of which framework produced it: a Cobalt Strike beacon, a Brute Ratel
badger, or anything added later. One C2Session node is linked to an Individual
node via a HAS_BEACON relationship.

Flowsint node label : C2Session
Neo4j nodeType      : c2session   (consumers lower-case before comparing)
Dedup key           : session_key = "<c2_framework>:<session_id>"

This replaces the framework-specific CobaltBeacon type. The edge stays HAS_BEACON
rather than becoming HAS_C2_SESSION: the graph already has HAS_SESSION for AD logon
sessions (individual → computer), and two relationship types one word apart is a
trap for the operator chat LLM, which has to pick edge names from a prompt.

Live graphs created before the generalisation hold nodeType='cobaltbeacon' with
nodeProperties.beacon_id / .cs_server. scripts/migrate_c2session.py relabels them;
readers should COALESCE the old and new property names until it has run.

IMPORTANT: registering this type in Flowsint is not optional. Flowsint's graph
serializer raises on a nodeType it cannot resolve and has no per-node try/except,
so a single node carrying an unregistered type makes
GET /api/sketches/{id}/graph return HTTP 500 for the WHOLE sketch. Register via
POST /api/custom-types (the migration script does this first, before it relabels
anything).
"""

from __future__ import annotations
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

# Operators think in framework-native nouns; used only for the display label.
# Mirrored by scripts/c2_common.py::SESSION_NOUN, which is what the n8n code nodes
# read (this directory is not mounted into any container). Change both together.
SESSION_NOUN = {
    "cobalt_strike": "Beacon",
    "brute_ratel":   "Badger",
    "adaptix":       "Agent",
}


class C2Session(BaseModel):
    # ── Framework identity ────────────────────────────────────────────────────
    c2_framework: str = Field(
        default="cobalt_strike",
        description="Framework that owns this session: cobalt_strike | brute_ratel | adaptix",
    )
    session_id: str = Field(
        description="Framework-assigned session id (CS beacon bid, BR badger id, Adaptix a_id)"
    )
    session_key: Optional[str] = Field(
        default=None,
        description=(
            "Dedup key '<c2_framework>:<session_id>'. Session ids are only unique "
            "within a framework, so the framework must be part of the key."
        ),
    )
    c2_server: str = Field(
        description="Team server / listener URL that controls this session"
    )

    # ── Host context ──────────────────────────────────────────────────────────
    hostname: str = Field(description="Compromised host NetBIOS / DNS name")
    internal_ip: str = Field(description="Internal (LAN) IP address of the host")
    external_ip: Optional[str] = Field(
        default=None,
        description="External / NAT'd IP seen by the C2. Brute Ratel does not report one.",
    )
    listener_ip: Optional[str] = Field(
        default=None,
        description=(
            "Address of the listener the session calls back to (BR b_l_ip). This is "
            "infrastructure-side — NOT the victim's egress IP."
        ),
    )
    os_version: Optional[str] = Field(
        default=None, description="OS version string from the session metadata"
    )
    arch: Optional[str] = Field(
        default=None, description="CPU architecture: x86 | x64 | aarch64"
    )

    # ── Session ───────────────────────────────────────────────────────────────
    username: str = Field(
        description="Windows user running the implant process (DOMAIN\\user)"
    )
    sam_account_name: Optional[str] = Field(
        default=None,
        description="Domain-stripped username, for dedup against AD Individual nodes",
    )
    process_name: Optional[str] = Field(
        default=None,
        description="Implant / sacrificial process. BR reports a full path, CS a bare name.",
    )
    pid: Optional[int] = Field(default=None, description="Process ID")
    thread_id: Optional[int] = Field(
        default=None, description="Implant thread ID (BR b_tid); CS does not report one"
    )
    is_admin: Optional[bool] = Field(
        default=None,
        description=(
            "True if the token has local admin or SYSTEM privilege. None means "
            "UNKNOWN, not unprivileged — Brute Ratel's webhook carries no elevation "
            "flag, so it stays None until command output reveals it."
        ),
    )

    # ── Timing ────────────────────────────────────────────────────────────────
    last_checkin: Optional[datetime] = Field(
        default=None, description="Timestamp of the most recent callback (UTC)"
    )
    sleep_seconds: Optional[int] = Field(
        default=None, description="Configured sleep interval in seconds (CS only)"
    )
    jitter_pct: Optional[int] = Field(
        default=None, description="Jitter percentage 0-99 (CS only)"
    )

    # ── Process snapshot ──────────────────────────────────────────────────────
    process_list: List[str] = Field(
        default_factory=list,
        description=(
            "Process names captured from a ps / pslist / tasklist run on this session. "
            "Used by the TechStack enricher to infer technologies in use. Empty for a "
            "fresh BR badger — its initial webhook carries no process list."
        ),
    )
    tech_stack: List[str] = Field(
        default_factory=list,
        description="Technology labels inferred from process_list",
    )
    priority_score: Optional[int] = Field(
        default=None,
        description=(
            "Operator-attention score from c2_common.score_session(). Comparable "
            "within a framework, not across: BR sessions cannot earn the is_admin or "
            "process-count points until command output backfills those fields."
        ),
    )

    # ── Pivot topology ────────────────────────────────────────────────────────
    is_pivot: Optional[bool] = Field(
        default=None, description="True if this session reaches the C2 through another session"
    )
    pivot_parent: Optional[str] = Field(
        default=None, description="session_id of the parent/pivot session (BR pvt_master)"
    )
    pivot_channel: Optional[str] = Field(
        default=None, description="Pivot transport: Direct | SMB | TCP (BR pipeline)"
    )
    is_dead: Optional[bool] = Field(
        default=None, description="True if the C2 reports the session as dead (BR dead)"
    )

    # ── Operator notes ────────────────────────────────────────────────────────
    note: Optional[str] = Field(
        default=None, description="Free-text operator note attached in the C2 UI"
    )
    listener: Optional[str] = Field(
        default=None, description="Listener name used by this session (BR b_c2_id)"
    )

    class Config:
        # Allow extra fields so a future C2 field does not break parsing
        extra = "allow"

    # ── Flowsint helpers ──────────────────────────────────────────────────────

    @property
    def display_label(self) -> str:
        """Graph display name, using the framework's own noun for the session."""
        noun = SESSION_NOUN.get((self.c2_framework or "").lower(), "Session")
        return f"{noun}:{self.session_id}@{self.hostname}"

    def to_flowsint_node(self) -> dict:
        """
        Return the dict expected by  POST /api/sketches/{id}/nodes/add
        (GraphNode schema).  'label' is the display name shown in the graph.
        """
        payload = self.model_dump(exclude_none=True)
        payload.setdefault(
            "session_key", f"{(self.c2_framework or '').lower()}:{self.session_id}"
        )
        return {
            "label": self.display_label,
            "type": "C2Session",
            **payload,
        }

    @classmethod
    def from_cs_beacon(cls, raw: dict) -> "C2Session":
        """
        Construct from a raw Cobalt Strike REST API beacon object.

        CS field mapping:
          id → session_id, computer → hostname, user → username,
          internal → internal_ip, external → external_ip, process → process_name,
          last → last_checkin (epoch seconds), sleep → sleep_seconds,
          jitter → jitter_pct, arch → arch, note → note, listener → listener
        """
        last_ts = raw.get("last")
        last_checkin = datetime.fromtimestamp(int(last_ts)) if last_ts else None
        session_id = str(raw.get("id", ""))
        return cls(
            c2_framework="cobalt_strike",
            session_id=session_id,
            session_key=f"cobalt_strike:{session_id}",
            c2_server=raw.get("_cs_server", "unknown"),
            hostname=raw.get("computer", "unknown"),
            username=raw.get("user", "unknown"),
            internal_ip=raw.get("internal", "0.0.0.0"),
            external_ip=raw.get("external"),
            os_version=raw.get("os"),
            arch=raw.get("arch"),
            pid=raw.get("pid"),
            process_name=raw.get("process"),
            is_admin=raw.get("admin", raw.get("elevated")),
            last_checkin=last_checkin,
            sleep_seconds=raw.get("sleep"),
            jitter_pct=raw.get("jitter"),
            note=raw.get("note"),
            listener=raw.get("listener"),
        )

    @classmethod
    def from_br_badger(cls, payload: dict) -> "C2Session":
        """
        Construct from a Brute Ratel "Badger's Initial Connection" webhook payload,
        i.e. {"badger": "...", "badger_config": {...}}.

        The authoritative mapping (including b_seen timezone handling and why
        b_l_ip is not external_ip) lives in scripts/brc4_normalizer.py; this mirrors
        it for callers holding a raw payload and wanting a validated model.
        """
        cfg = payload.get("badger_config") or {}
        session_id = str(payload.get("badger", ""))

        def _int(value):
            try:
                return int(str(value).strip())
            except (TypeError, ValueError):
                return None

        wver = str(cfg.get("b_wver") or "")
        version = wver.split("/")[-1] if "/" in wver else wver
        build = str(cfg.get("b_bld") or "")
        os_version = f"Windows {version} (build {build})" if version and build else (version or None)

        last_checkin = None
        seen = str(cfg.get("b_seen") or "").strip()
        if seen:
            try:
                last_checkin = datetime.strptime(seen, "%m-%d-%Y %H:%M:%S")
            except ValueError:
                last_checkin = None

        return cls(
            c2_framework="brute_ratel",
            session_id=session_id,
            session_key=f"brute_ratel:{session_id}",
            c2_server=str(cfg.get("b_c2", "unknown")),
            hostname=str(cfg.get("b_h_name", "unknown")),
            username=str(cfg.get("b_uid", "unknown")),
            internal_ip=str(cfg.get("b_ip", "0.0.0.0")),
            # BR reports no victim-side public IP; b_l_ip is the listener.
            external_ip=None,
            listener_ip=str(cfg.get("b_l_ip") or "") or None,
            os_version=os_version,
            arch=str(cfg.get("b_arch") or "") or None,
            pid=_int(cfg.get("b_pid")),
            thread_id=_int(cfg.get("b_tid")),
            process_name=str(cfg.get("b_p_name") or "") or None,
            # Not reported by BRc4 — unknown, not False.
            is_admin=None,
            last_checkin=last_checkin,
            listener=str(cfg.get("b_c2_id") or "") or None,
            is_dead=bool(cfg.get("dead")),
            is_pivot=bool(cfg.get("is_pvt")),
            pivot_parent=str(cfg.get("pvt_master") or "") or None,
            pivot_channel=str(cfg.get("pipeline") or "") or None,
        )
