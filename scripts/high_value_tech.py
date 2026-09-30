"""Canonical high-value technology labels used across SPOTTER."""

from __future__ import annotations

from typing import Iterable, List


HIGH_VALUE_TECH_LABELS = (
    "IBM iSeries Access for Windows (AS/400)",
    "IBM Personal Communications (Mainframe)",
    "TN3270 Mainframe Terminal Emulator",
    "TN5250 AS/400 Terminal Emulator",
    "Attachmate EXTRA! Terminal Emulator",
    "Micro Focus RUMBA Terminal Emulator",
    "Micro Focus Reflection Terminal Emulator",
    "Rocket BlueZone Mainframe Emulator",
    "IBM HATS (Host Access Transformation Services)",
    "SAP Logon (SAP GUI)",
    "SAP GUI",
    "Bloomberg Terminal",
    "Refinitiv / Reuters Eikon",
    "CyberArk PAM",
    "BeyondTrust PAM",
    "Thycotic Secret Server",
    "Delinea PAM",
    "KeePass Password Manager",
    "1Password",
    "LastPass",
    "Bitwarden",
    "Oracle SQL*Plus",
    "SQL Server Management Studio",
    "Citrix Workspace / ICA Client",
    # Internet-facing appliances and platforms, added with WF13's perimeter
    # technology writer. Everything above is endpoint software an operator sees
    # in a process listing; these are reached from outside the estate, so they
    # matter for a different reason -- and marking them high-value is what makes
    # them visible in Tech Intel BEFORE WF14 has had a chance to attach a CVE
    # (WF12 gates vulnerable_tech on cve_count or is_high_value or
    # exploit_available). Names must match the canonical spellings in WF13's
    # TECH_CANON table, or the membership test never fires.
    "Citrix NetScaler ADC",
    "Ivanti Connect Secure",
    "Fortinet FortiGate",
    "Palo Alto GlobalProtect",
    "Microsoft Exchange Server",
    "VMware Horizon",
    "Atlassian Confluence",
)

HIGH_VALUE_TECH = frozenset(HIGH_VALUE_TECH_LABELS)


def is_high_value_tech(tech_labels: Iterable[str]) -> bool:
    """Return True when any technology label is high-value."""
    return bool(set(tech_labels) & HIGH_VALUE_TECH)


def get_high_value_tech(tech_labels: Iterable[str]) -> List[str]:
    """Return the high-value subset of technology labels in stable order."""
    present = set(tech_labels)
    return [label for label in HIGH_VALUE_TECH_LABELS if label in present]
