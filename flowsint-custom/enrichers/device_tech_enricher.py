"""
DeviceTechEnricher — Flowsint plugin enricher for Device nodes.

Reads the operating_system property imported from SharpHound / BloodHound,
parses it into a structured OS profile (family, clean name, EOL date, risk
tier), and writes the result back to the Device node.

Additionally detects OS-level technologies that are always present for a given
platform (e.g. IIS on a Server 2019 box running w3wp.exe), exposing them as
device_tech_labels for the Tech Intel frontend tab.

Risk tiers (computed at enrichment time vs today's date):
  critical  — EOL > 3 years ago: no vendor patches, weaponised public exploits
  high      — EOL 1–3 years ago: unpatched, many public exploits available
  medium    — EOL < 1 year ago: recently unsupported, patch gap growing
  low       — EOL within 6 months: end-of-life approaching, plan migration
  supported — Still under mainstream or extended support

Installation: copy this file into the Flowsint container at
  /app/flowsint-enrichers/src/flowsint_enrichers/spotter/
and restart flowsint-api-prod and flowsint-celery-prod.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher

# ── Try to import from Flowsint built-in device type ─────────────────────────
try:
    from flowsint_types.device import Device as DeviceType  # type: ignore[import]
except ImportError:
    from flowsint_types.individual import Individual as DeviceType  # type: ignore[import]


# ── OS EOL database ───────────────────────────────────────────────────────────
# Keyed by lowercase substring that appears in the operating_system field.
# Each entry: (display_name, eol_date_str YYYY-MM-DD or None if supported,
#              os_family: workstation|server|unknown)
# Ordered from most-specific to least-specific so the first match wins.

_OS_EOL_DB: List[Tuple[str, str, Optional[str], str]] = [
    # ── Windows Workstation ──────────────────────────────────────────────────
    ("windows xp",              "Windows XP",                "2014-04-08",  "workstation"),
    ("windows vista",           "Windows Vista",             "2017-04-11",  "workstation"),
    ("windows 7",               "Windows 7",                 "2020-01-14",  "workstation"),
    ("windows 8.1",             "Windows 8.1",               "2023-01-10",  "workstation"),
    ("windows 8",               "Windows 8",                 "2016-01-12",  "workstation"),
    ("windows 10",              "Windows 10",                "2025-10-14",  "workstation"),
    ("windows 11",              "Windows 11",                None,          "workstation"),
    # ── Windows Server ──────────────────────────────────────────────────────
    ("windows server 2003 r2",  "Windows Server 2003 R2",    "2015-07-14",  "server"),
    ("windows server 2003",     "Windows Server 2003",       "2015-07-14",  "server"),
    ("windows server 2008 r2",  "Windows Server 2008 R2",    "2020-01-14",  "server"),
    ("windows server 2008",     "Windows Server 2008",       "2020-01-14",  "server"),
    ("windows server 2012 r2",  "Windows Server 2012 R2",    "2023-10-10",  "server"),
    ("windows server 2012",     "Windows Server 2012",       "2023-10-10",  "server"),
    ("windows server 2016",     "Windows Server 2016",       "2027-01-12",  "server"),
    ("windows server 2019",     "Windows Server 2019",       "2029-01-09",  "server"),
    ("windows server 2022",     "Windows Server 2022",       "2031-10-13",  "server"),
    ("windows server 2025",     "Windows Server 2025",       "2034-10-10",  "server"),
    # ── Linux (generic — EOL depends on distro version, treat as supported) ─
    ("ubuntu",                  "Ubuntu Linux",              None,          "server"),
    ("debian",                  "Debian Linux",              None,          "server"),
    ("centos",                  "CentOS Linux",              None,          "server"),
    ("red hat",                 "Red Hat Enterprise Linux",  None,          "server"),
    ("rhel",                    "Red Hat Enterprise Linux",  None,          "server"),
    ("oracle linux",            "Oracle Linux",              None,          "server"),
    ("linux",                   "Linux",                     None,          "server"),
    # ── macOS ────────────────────────────────────────────────────────────────
    ("macos",                   "macOS",                     None,          "workstation"),
    ("mac os x",                "macOS",                     None,          "workstation"),
]


def _parse_os(operating_system: str) -> Dict[str, Any]:
    """
    Parse a raw operating_system string from SharpHound into a structured dict.

    Returns:
        os_family       — "workstation" | "server" | "unknown"
        os_name         — clean display name
        os_eol_date     — ISO date string or None
        os_risk         — "critical" | "high" | "medium" | "low" | "supported" | "unknown"
        is_eol          — bool
        is_server       — bool
        is_workstation  — bool
    """
    raw = (operating_system or "").strip()
    if not raw:
        return {
            "os_family": "unknown", "os_name": "Unknown",
            "os_eol_date": None, "os_risk": "unknown",
            "is_eol": False, "is_server": False, "is_workstation": False,
        }

    raw_lower = raw.lower()
    today = date.today()

    matched_name  = raw          # fallback: use raw string
    eol_date_str  = None
    os_family     = "unknown"

    for key, display, eol_str, family in _OS_EOL_DB:
        if key in raw_lower:
            matched_name = display
            eol_date_str = eol_str
            os_family    = family
            break

    # Compute risk tier
    if eol_date_str is None:
        is_eol   = False
        risk     = "supported"
    else:
        eol_date = datetime.strptime(eol_date_str, "%Y-%m-%d").date()
        is_eol   = eol_date < today
        if not is_eol:
            days_left = (eol_date - today).days
            risk = "low" if days_left <= 180 else "supported"
        else:
            days_past = (today - eol_date).days
            if days_past > 3 * 365:
                risk = "critical"
            elif days_past > 365:
                risk = "high"
            else:
                risk = "medium"

    return {
        "os_family":     os_family,
        "os_name":       matched_name,
        "os_eol_date":   eol_date_str,
        "os_risk":       risk,
        "is_eol":        is_eol,
        "is_server":     os_family == "server",
        "is_workstation": os_family == "workstation",
    }


# ── Cypher templates ──────────────────────────────────────────────────────────

_CYPHER_READ = """
MATCH (n:device {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
RETURN n.`nodeProperties.operating_system` AS operating_system,
       n.`nodeProperties.is_dc`            AS is_dc
"""

_CYPHER_UPDATE = """
MATCH (n:device {nodeLabel: $label, sketch_id: $sketch_id})
WHERE n.deleted_at IS NULL
SET n.`nodeProperties.os_name`        = $os_name,
    n.`nodeProperties.os_family`       = $os_family,
    n.`nodeProperties.os_eol_date`     = $os_eol_date,
    n.`nodeProperties.os_risk`         = $os_risk,
    n.`nodeProperties.is_eol`          = $is_eol,
    n.`nodeProperties.os_tech_enriched` = true
"""


# ── Enricher ──────────────────────────────────────────────────────────────────

@flowsint_enricher
class DeviceTechEnricher(Enricher):
    """Parse OS version strings on Device nodes and write risk-rated OS metadata."""

    InputType  = DeviceType
    OutputType = DeviceType

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._updates: List[Dict[str, Any]] = []

    @classmethod
    def name(cls) -> str:
        return "device_tech_enricher"

    @classmethod
    def category(cls) -> str:
        return "Device"

    @classmethod
    def key(cls) -> str:
        return "nodeLabel"

    @classmethod
    def documentation(cls) -> str:
        return (
            "Parses operating_system strings from SharpHound Device nodes into "
            "structured OS metadata: clean name, EOL date, risk tier (critical/"
            "high/medium/low/supported), and family (workstation/server). "
            "Risk is computed at enrichment time relative to today's date."
        )

    async def scan(self, data: List[DeviceType]) -> List[DeviceType]:  # type: ignore[override]
        self._updates = []

        for device in data:
            label = getattr(device, "nodeLabel", None)
            if not label:
                continue

            rows = self._graph_service.query(_CYPHER_READ, {
                "label":     label,
                "sketch_id": self.sketch_id,
            })
            if not rows:
                continue

            row = rows[0]
            os_raw = row.get("operating_system") or ""
            is_dc  = bool(row.get("is_dc"))

            parsed = _parse_os(os_raw)

            self._updates.append({
                "label":      label,
                "os_name":    parsed["os_name"],
                "os_family":  parsed["os_family"],
                "os_eol_date": parsed["os_eol_date"],
                "os_risk":    parsed["os_risk"],
                "is_eol":     parsed["is_eol"],
                "is_dc":      is_dc,
            })

        return data

    def postprocess(
        self,
        results: List[DeviceType],
        original_input: List[DeviceType],
    ) -> List[DeviceType]:
        for upd in self._updates:
            self._graph_service.query(_CYPHER_UPDATE, {
                "label":      upd["label"],
                "sketch_id":  self.sketch_id,
                "os_name":    upd["os_name"],
                "os_family":  upd["os_family"],
                "os_eol_date": upd["os_eol_date"],
                "os_risk":    upd["os_risk"],
                "is_eol":     upd["is_eol"],
            })
            risk_flag = f" ⚠ EOL RISK={upd['os_risk'].upper()}" if upd["is_eol"] else ""
            self.log_graph_message(
                f"OS enriched: {upd['label']} → {upd['os_name']}{risk_flag}"
            )

        return results


InputType  = DeviceTechEnricher.InputType
OutputType = DeviceTechEnricher.OutputType
