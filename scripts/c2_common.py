"""
c2_common.py — Framework-agnostic C2 session helpers shared by every C2 normaliser.

SPOTTER ingests sessions from more than one C2 framework (Cobalt Strike beacons via
the team server REST API, Brute Ratel badgers via listener webhooks, Adaptix agents
via the teamserver Web API). Everything in this module is about the *host* a session
lands on, not the framework that produced it, so every normaliser imports from here
and emits the same canonical dict shape — the one that becomes a C2Session node in
the graph.

Canonical C2Session dict (what normalisers must produce):

    c2_framework      "cobalt_strike" | "brute_ratel" | "adaptix"   discriminator
    session_id        framework-assigned session id     CS bid / BR badger / AX a_id
    session_key       "<framework>:<session_id>"        dedup key, see session_key()
    c2_server         team server / listener URL
    hostname, internal_ip, external_ip, os_version, arch
    username, sam_account_name, process_name, pid, is_admin
    last_checkin (ISO str), last_checkin_dt (aware datetime)
    sleep_seconds, jitter_pct, listener, note
    process_list, tech_stack, priority_score
    is_dead, is_pivot, pivot_parent, pivot_channel

Safe-use constraints: all session data processed here originates from an authorized
red team engagement running under documented Rules of Engagement.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from high_value_tech import HIGH_VALUE_TECH, get_high_value_tech, is_high_value_tech

# ── Process → Technology mapping ─────────────────────────────────────────────
# Maps lowercase process name patterns to a human-readable technology label.
# Used to infer what software is installed / active on a compromised host.

PROCESS_TECH_MAP: Dict[str, str] = {
    # Development
    r"python\d*\.exe":          "Python",
    r"pythonw\d*\.exe":         "Python",
    r"node\.exe":               "Node.js",
    r"java\.exe":               "Java",
    r"javaw\.exe":              "Java",
    r"ruby\.exe":               "Ruby",
    r"perl\.exe":               "Perl",
    r"php\.exe":                "PHP",
    r"go\.exe":                 "Go",
    r"rustc\.exe":              "Rust",
    r"dotnet\.exe":             ".NET SDK",
    r"code\.exe":               "VS Code",
    r"devenv\.exe":             "Visual Studio",
    r"idea\d*\.exe":            "IntelliJ IDEA",
    r"pycharm\d*\.exe":         "PyCharm",
    r"git\.exe":                "Git",
    r"docker\.exe":             "Docker",
    r"kubectl\.exe":            "Kubernetes (kubectl)",
    r"terraform\.exe":          "Terraform",
    r"ansible.*\.exe":          "Ansible",

    # Office / productivity
    r"outlook\.exe":            "Microsoft Outlook",
    r"winword\.exe":            "Microsoft Word",
    r"excel\.exe":              "Microsoft Excel",
    r"powerpnt\.exe":           "Microsoft PowerPoint",
    r"onenote\.exe":            "Microsoft OneNote",
    r"teams\.exe":              "Microsoft Teams",
    r"slack\.exe":              "Slack",
    r"zoom\.exe":               "Zoom",
    r"discord\.exe":            "Discord",
    r"telegram\.exe":           "Telegram",
    r"signal\.exe":             "Signal",
    r"whatsapp\.exe":           "WhatsApp",

    # Database / admin
    r"ssms\.exe":               "SQL Server Management Studio",
    r"sqlservr\.exe":           "Microsoft SQL Server",
    r"mysql\.exe":              "MySQL",
    r"mysqld\.exe":             "MySQL Server",
    r"psql\.exe":               "PostgreSQL",
    r"postgres\.exe":           "PostgreSQL Server",
    r"mongod\.exe":             "MongoDB",
    r"redis-server\.exe":       "Redis",
    r"dbeaver\.exe":            "DBeaver",
    r"sqlplus\.exe":            "Oracle SQL*Plus",
    r"oracle.*\.exe":           "Oracle Database Client",

    # IT / sysadmin
    r"powershell\.exe":         "PowerShell",
    r"pwsh\.exe":               "PowerShell Core",
    r"cmd\.exe":                "Windows CMD",
    r"wscript\.exe":            "Windows Script Host",
    r"cscript\.exe":            "Windows Script Host",
    r"mmc\.exe":                "Microsoft Management Console",
    r"putty\.exe":              "PuTTY (SSH)",
    r"winscp\.exe":             "WinSCP",
    r"mstsc\.exe":              "Remote Desktop (RDP)",
    r"anydesk\.exe":            "AnyDesk",
    r"teamviewer\.exe":         "TeamViewer",
    r"vmware\.exe":             "VMware Workstation",
    r"vmwaretray\.exe":         "VMware Workstation",
    r"virtualbox\.exe":         "VirtualBox",
    r"securecrt\.exe":          "SecureCRT (SSH)",
    r"ttermpro\.exe":           "Tera Term (SSH)",
    r"filezilla\.exe":          "FileZilla (FTP/SFTP)",
    r"pageant\.exe":            "Pageant (SSH Key Agent)",

    # Security / AV / EDR
    r"msseces\.exe":            "Microsoft Security Essentials",
    r"msmpeng\.exe":            "Windows Defender",
    r"mbam\.exe":               "Malwarebytes",
    r"falconctl\.exe":          "CrowdStrike Falcon",
    r"falconagent.*\.exe":      "CrowdStrike Falcon",
    r"csagent\.exe":            "CrowdStrike Falcon",
    r"savservice\.exe":         "Sophos AV",
    r"ntrtscan\.exe":           "Trend Micro",
    r"cb\.exe":                 "CarbonBlack EDR",
    r"cbsensor\.exe":           "CarbonBlack EDR",
    r"cortex.*\.exe":           "Palo Alto Cortex XDR",
    r"cyserver\.exe":           "Cylance",
    r"qualys.*\.exe":           "Qualys Agent",
    r"nessus.*\.exe":           "Nessus Agent",
    r"tanium.*\.exe":           "Tanium Agent",
    r"sentinel.*\.exe":         "Microsoft Sentinel Agent",

    # Web / networking
    r"chrome\.exe":             "Google Chrome",
    r"firefox\.exe":            "Mozilla Firefox",
    r"msedge\.exe":             "Microsoft Edge",
    r"iexplore\.exe":           "Internet Explorer",
    r"curl\.exe":               "curl",
    r"wget\.exe":               "wget",
    r"nginx\.exe":              "nginx",
    r"httpd\.exe":              "Apache HTTP Server",
    r"w3wp\.exe":               "IIS (ASP.NET)",

    # VPN clients
    r"vpnui\.exe":              "Cisco AnyConnect VPN",
    r"vpnclient.*\.exe":        "Cisco AnyConnect VPN",
    r"forticlient.*\.exe":      "FortiClient VPN",
    r"fortissl.*\.exe":         "FortiClient VPN",
    r"pulsesecure.*\.exe":      "Pulse Secure VPN",
    r"iveagent.*\.exe":         "Pulse Secure VPN",
    r"globalprotect.*\.exe":    "Palo Alto GlobalProtect VPN",
    r"juniper.*\.exe":          "Juniper Network Connect VPN",
    r"openvpn.*\.exe":          "OpenVPN",
    r"wireguard\.exe":          "WireGuard VPN",

    # Password managers / PAM
    r"keepass.*\.exe":          "KeePass Password Manager",
    r"1password.*\.exe":        "1Password",
    r"lastpass.*\.exe":         "LastPass",
    r"bitwarden.*\.exe":        "Bitwarden",
    r"cyberark.*\.exe":         "CyberArk PAM",
    r"capm.*\.exe":             "CyberArk PAM",
    r"beyondtrust.*\.exe":      "BeyondTrust PAM",
    r"thycotic.*\.exe":         "Thycotic Secret Server",
    r"secretserver.*\.exe":     "Thycotic Secret Server",
    r"delinea.*\.exe":          "Delinea PAM",

    # Mainframe / IBM iSeries / AS400 terminal emulators
    r"cwbenvok\.exe":           "IBM iSeries Access for Windows (AS/400)",
    r"cwbunpack\.exe":          "IBM iSeries Access for Windows (AS/400)",
    r"cwbconn.*\.exe":          "IBM iSeries Access for Windows (AS/400)",
    r"cwbping\.exe":            "IBM iSeries Access for Windows (AS/400)",
    r"cwbsvrca\.exe":           "IBM iSeries Access for Windows (AS/400)",
    r"pcsws\.exe":              "IBM Personal Communications (Mainframe)",
    r"pcshell\.exe":            "IBM Personal Communications (Mainframe)",
    r"pcomm.*\.exe":            "IBM Personal Communications (Mainframe)",
    r"extra.*\.exe":            "Attachmate EXTRA! Terminal Emulator",
    r"rumba.*\.exe":            "Micro Focus RUMBA Terminal Emulator",
    r"reflections.*\.exe":      "Micro Focus Reflection Terminal Emulator",
    r"bluezone.*\.exe":         "Rocket BlueZone Mainframe Emulator",
    r"tn3270.*\.exe":           "TN3270 Mainframe Terminal Emulator",
    r"tn5250.*\.exe":           "TN5250 AS/400 Terminal Emulator",
    r"ibmiaccess.*\.exe":       "IBM iSeries Access for Windows (AS/400)",
    r"accessclient.*\.exe":     "IBM iSeries Access for Windows (AS/400)",
    r"hatsenv.*\.exe":          "IBM HATS (Host Access Transformation Services)",
    r"ehlapi.*\.exe":           "IBM EHLLAPI Terminal Interface",
    r"attachmate.*\.exe":       "Attachmate Terminal Emulator",

    # SAP
    r"saplogon\.exe":           "SAP Logon (SAP GUI)",
    r"sapgui\.exe":             "SAP GUI",
    r"saplgpad\.exe":           "SAP Logon Pad",
    r"sapmmc\.exe":             "SAP Management Console",
    r"sapstartsrv\.exe":        "SAP Start Service",

    # Citrix / Virtual Desktop
    r"wfica32\.exe":            "Citrix Workspace / ICA Client",
    r"wfcrun32\.exe":           "Citrix Receiver",
    r"concentr\.exe":           "Citrix Connection Manager",
    r"redirector\.exe":         "Citrix Redirector",
    r"selfservice.*\.exe":      "Citrix Self-Service",
    r"picapp\.exe":             "Citrix Published Application",
    r"vmwareview.*\.exe":       "VMware Horizon (VDI)",
    r"vmware-view.*\.exe":      "VMware Horizon (VDI)",
    r"horizonagent.*\.exe":     "VMware Horizon Agent",
    r"mstscax.*\.exe":          "Microsoft RemoteApp",

    # Financial / Trading terminals
    r"bloomberg.*\.exe":        "Bloomberg Terminal",
    r"blp.*\.exe":              "Bloomberg Terminal",
    r"reuters.*\.exe":          "Refinitiv / Reuters Eikon",
    r"eikon.*\.exe":            "Refinitiv / Reuters Eikon",
    r"fidessa.*\.exe":          "Fidessa Trading Platform",
    r"murex.*\.exe":            "Murex Trading Platform",

    # ERP / Line-of-business
    r"dynamics.*\.exe":         "Microsoft Dynamics",
    r"nav.*client.*\.exe":      "Microsoft Dynamics NAV",
    r"bc.*client.*\.exe":       "Microsoft Dynamics 365 BC",
    r"axapta.*\.exe":           "Microsoft Dynamics AX",
    r"epicor.*\.exe":           "Epicor ERP",
    r"jdedwards.*\.exe":        "Oracle JD Edwards ERP",
    r"lawson.*\.exe":           "Infor Lawson ERP",
    r"peoplesoft.*\.exe":       "Oracle PeopleSoft",
}

_COMPILED_MAP = [(re.compile(pat, re.IGNORECASE), tech)
                 for pat, tech in PROCESS_TECH_MAP.items()]

DC_PATTERNS = re.compile(r"\bDC\d*\b|DOMAINCONTROLLER", re.IGNORECASE)


TECH_CATEGORIES: Dict[str, str] = {
    "Python": "Development",
    "Node.js": "Development",
    "Java": "Development",
    "Ruby": "Development",
    "Perl": "Development",
    "PHP": "Development",
    "Go": "Development",
    "Rust": "Development",
    ".NET SDK": "Development",
    "VS Code": "Development",
    "Visual Studio": "Development",
    "IntelliJ IDEA": "Development",
    "PyCharm": "Development",
    "Git": "Development",
    "Docker": "Development",
    "Kubernetes (kubectl)": "Development",
    "Terraform": "Development",
    "Ansible": "Development",
    "Microsoft Outlook": "Office / Productivity",
    "Microsoft Word": "Office / Productivity",
    "Microsoft Excel": "Office / Productivity",
    "Microsoft PowerPoint": "Office / Productivity",
    "Microsoft OneNote": "Office / Productivity",
    "Microsoft Teams": "Office / Productivity",
    "Slack": "Office / Productivity",
    "Zoom": "Office / Productivity",
    "Discord": "Communication",
    "Telegram": "Communication",
    "Signal": "Communication",
    "WhatsApp": "Communication",
    "SQL Server Management Studio": "Database",
    "Microsoft SQL Server": "Database",
    "MySQL": "Database",
    "MySQL Server": "Database",
    "PostgreSQL": "Database",
    "PostgreSQL Server": "Database",
    "MongoDB": "Database",
    "Redis": "Database",
    "DBeaver": "Database",
    "Oracle SQL*Plus": "Database",
    "Oracle Database Client": "Database",
    "SAP Logon (SAP GUI)": "ERP",
    "SAP GUI": "ERP",
    "SAP Logon Pad": "ERP",
    "SAP Management Console": "ERP",
    "SAP Start Service": "ERP",
    "Microsoft Dynamics": "ERP",
    "Microsoft Dynamics NAV": "ERP",
    "Microsoft Dynamics 365 BC": "ERP",
    "Microsoft Dynamics AX": "ERP",
    "Epicor ERP": "ERP",
    "Oracle JD Edwards ERP": "ERP",
    "Infor Lawson ERP": "ERP",
    "Oracle PeopleSoft": "ERP",
    "IBM iSeries Access for Windows (AS/400)": "Legacy / Mainframe",
    "IBM Personal Communications (Mainframe)": "Legacy / Mainframe",
    "Attachmate EXTRA! Terminal Emulator": "Legacy / Mainframe",
    "Micro Focus RUMBA Terminal Emulator": "Legacy / Mainframe",
    "Micro Focus Reflection Terminal Emulator": "Legacy / Mainframe",
    "Rocket BlueZone Mainframe Emulator": "Legacy / Mainframe",
    "TN3270 Mainframe Terminal Emulator": "Legacy / Mainframe",
    "TN5250 AS/400 Terminal Emulator": "Legacy / Mainframe",
    "IBM HATS (Host Access Transformation Services)": "Legacy / Mainframe",
    "IBM EHLLAPI Terminal Interface": "Legacy / Mainframe",
    "Attachmate Terminal Emulator": "Legacy / Mainframe",
    "Bloomberg Terminal": "Financial / Trading",
    "Refinitiv / Reuters Eikon": "Financial / Trading",
    "Fidessa Trading Platform": "Financial / Trading",
    "Murex Trading Platform": "Financial / Trading",
    "PowerShell": "IT Admin",
    "PowerShell Core": "IT Admin",
    "Windows CMD": "IT Admin",
    "Windows Script Host": "IT Admin",
    "Microsoft Management Console": "IT Admin",
    "PuTTY (SSH)": "IT Admin",
    "WinSCP": "IT Admin",
    "SecureCRT (SSH)": "IT Admin",
    "Tera Term (SSH)": "IT Admin",
    "FileZilla (FTP/SFTP)": "IT Admin",
    "Pageant (SSH Key Agent)": "IT Admin",
    "Remote Desktop (RDP)": "IT Admin",
    "AnyDesk": "Remote Access",
    "TeamViewer": "Remote Access",
    "VMware Workstation": "Virtualization",
    "VirtualBox": "Virtualization",
    "VMware Horizon (VDI)": "Virtual Desktop",
    "VMware Horizon Agent": "Virtual Desktop",
    "Microsoft RemoteApp": "Virtual Desktop",
    "Citrix Workspace / ICA Client": "Virtual Desktop",
    "Citrix Receiver": "Virtual Desktop",
    "Citrix Connection Manager": "Virtual Desktop",
    "Citrix Redirector": "Virtual Desktop",
    "Citrix Self-Service": "Virtual Desktop",
    "Citrix Published Application": "Virtual Desktop",
    "Cisco AnyConnect VPN": "VPN",
    "FortiClient VPN": "VPN",
    "Pulse Secure VPN": "VPN",
    "Palo Alto GlobalProtect VPN": "VPN",
    "Juniper Network Connect VPN": "VPN",
    "OpenVPN": "VPN",
    "WireGuard VPN": "VPN",
    "KeePass Password Manager": "Password Manager",
    "1Password": "Password Manager",
    "LastPass": "Password Manager",
    "Bitwarden": "Password Manager",
    "CyberArk PAM": "PAM",
    "BeyondTrust PAM": "PAM",
    "Thycotic Secret Server": "PAM",
    "Delinea PAM": "PAM",
    "Microsoft Security Essentials": "Security / AV",
    "Windows Defender": "Security / AV",
    "Malwarebytes": "Security / AV",
    "CrowdStrike Falcon": "Security / EDR",
    "Sophos AV": "Security / AV",
    "Trend Micro": "Security / AV",
    "CarbonBlack EDR": "Security / EDR",
    "Palo Alto Cortex XDR": "Security / EDR",
    "Cylance": "Security / EDR",
    "Qualys Agent": "Security / Scanning",
    "Nessus Agent": "Security / Scanning",
    "Tanium Agent": "Security / Scanning",
    "Microsoft Sentinel Agent": "Security / SIEM",
    "Google Chrome": "Web Browser",
    "Mozilla Firefox": "Web Browser",
    "Microsoft Edge": "Web Browser",
    "Internet Explorer": "Web Browser",
    "curl": "Networking",
    "wget": "Networking",
    "nginx": "Web Server",
    "Apache HTTP Server": "Web Server",
    "IIS (ASP.NET)": "Web Server",
}

def infer_tech_stack(process_list: List[str]) -> List[str]:
    """
    Given a list of running process names, return deduplicated technology labels.

    Example:
        infer_tech_stack(["python3.exe", "outlook.exe", "ssms.exe"])
        → ["Python", "Microsoft Outlook", "SQL Server Management Studio"]
    """
    found: set = set()
    for proc in process_list:
        proc_name = os.path.basename(proc).strip()
        for pattern, tech in _COMPILED_MAP:
            if pattern.fullmatch(proc_name):
                found.add(tech)
                break
    return sorted(found)


def categorize_tech_stack(tech_labels: List[str]) -> Dict[str, List[str]]:
    """
    Group technology labels into categories.

    Returns a dict mapping category name → list of tech labels in that category.
    Unknown technologies go into 'Other'.
    """
    grouped: Dict[str, List[str]] = {}
    for tech in tech_labels:
        cat = TECH_CATEGORIES.get(tech, "Other")
        grouped.setdefault(cat, []).append(tech)
    return grouped


# ── Framework display vocabulary ─────────────────────────────────────────────
# Operators think in framework-native nouns, so anything user-facing says "Badger"
# rather than "Brute Ratel session". This lives here, in the module both normalisers
# already import, because the readers that need it (WF23's roster, the AGENTS tab)
# run inside n8n code nodes: flowsint-custom/types/ is not mounted into any
# container and c2_session is not on the runner's import allowlist, so importing
# the copy in c2_session.py::SESSION_NOUN is not an option. Keep the two in step.

SESSION_NOUN: Dict[str, str] = {
    "cobalt_strike": "Beacon",
    "brute_ratel":   "Badger",
    # Adaptix calls them "agents" throughout its UI and its API (/agent/list),
    # regardless of which implant family answered -- "beacon" and "gopher" are
    # agent *types* within Adaptix, not the operator-facing noun for a session.
    "adaptix":       "Agent",
}

FRAMEWORK_LABEL: Dict[str, str] = {
    "cobalt_strike": "Cobalt Strike",
    "brute_ratel":   "Brute Ratel",
    "adaptix":       "Adaptix C2",
}


def framework_display(c2_framework: str) -> Dict[str, str]:
    """
    Human-facing names for a framework discriminator: {"label", "noun"}.

    Unknown frameworks fall back to a title-cased version of the discriminator
    and the generic noun "Session" rather than silently reading as Cobalt Strike —
    a new C2 added later should look unfamiliar in the UI, not mislabelled.
    """
    fw = (c2_framework or "").strip().lower()
    return {
        "label": FRAMEWORK_LABEL.get(fw) or (fw.replace("_", " ").title() if fw else "Unknown"),
        "noun":  SESSION_NOUN.get(fw, "Session"),
    }


# ── Session identity ─────────────────────────────────────────────────────────

def session_key(c2_framework: str, session_id: str) -> str:
    """
    Stable dedup key for a C2 session: "<framework>:<session_id>".

    Session ids are only unique *within* a framework's server — Brute Ratel hands
    out "b-1", "b-2" while Cobalt Strike uses numeric bids, so the framework has to
    be part of the key or a badger and a beacon eventually collide on one node.
    The C2 server is deliberately NOT in the key: a badger that migrates to another
    listener keeps its id, and keying on the server would fork it into a second
    node. That assumes one server per framework per engagement, which is how
    SPOTTER is deployed (CS_API_URL / BRC4_* are single-valued).
    """
    fw = (c2_framework or "unknown").strip().lower()
    return f"{fw}:{(session_id or '').strip()}"


def score_session(session: Dict[str, Any]) -> int:
    """
    Compute a priority score for a C2 session. Higher = more operator attention.

      +10  admin / SYSTEM token
      +8   hostname matches a DC naming pattern
      +5   checked in within the last 10 minutes
      +3   process is an operator shell (powershell / cmd)
      +2   more than 50 processes captured
      -5   the C2 reports the session as dead

    Frameworks report different things. A Brute Ratel initial-connection webhook
    carries no elevation flag and no process list, so is_admin and process_list are
    *absent* rather than false and those checks never fire — a fresh BR badger tops
    out at 13 where an equivalent CS beacon reaches 25. Rank within a framework, or
    wait for a command-output event to backfill the missing fields.
    """
    score = 0

    if session.get("is_admin"):
        score += 10
    if DC_PATTERNS.search(session.get("hostname") or ""):
        score += 8

    last = session.get("last_checkin_dt")
    if isinstance(last, datetime):
        aware = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
        # total_seconds(), not .seconds: timedelta(hours=24, minutes=5).seconds is
        # 300, which would score a day-stale session as freshly active.
        age_minutes = (datetime.now(timezone.utc) - aware).total_seconds() / 60
        if 0 <= age_minutes < 10:
            score += 5

    # BR reports a full path ("Z:\\documents\\badger.exe"), CS a bare name.
    proc = os.path.basename((session.get("process_name") or "").replace("\\", "/")).lower()
    if "powershell" in proc or proc == "cmd.exe":
        score += 3

    if len(session.get("process_list") or []) > 50:
        score += 2
    if session.get("is_dead"):
        score -= 5

    return max(score, 0)


def finalize_session(session: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fill the derived fields every C2Session node needs, whatever the framework.

    Mutates and returns the dict: sam_account_name (domain-stripped for dedup
    against AD users), tech_stack (inferred from process_list when not already
    set), session_key, and priority_score.
    """
    username = session.get("username") or ""
    if not session.get("sam_account_name"):
        session["sam_account_name"] = username.split("\\")[-1] if "\\" in username else username

    if not session.get("tech_stack"):
        session["tech_stack"] = infer_tech_stack(session.get("process_list") or [])

    session["session_key"] = session_key(
        session.get("c2_framework", ""), session.get("session_id", "")
    )
    session["priority_score"] = score_session(session)
    return session
