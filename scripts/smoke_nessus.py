"""
smoke_nessus.py — Offline contract tests for the Nessus ingest path.

Runs against a synthetic Nessus CSV export, so it needs no live stack and no
real engagement data.

What it pins down (each of these is a way this path can be quietly wrong):
  * detection beats the generic CSV branch — a Nessus header contains "ip"
    inside "description", so the old substring test matched it and the whole
    report would have been read as a list of people
  * an ordinary user CSV still routes to `csv`, not to this parser
  * the .nessus XML export is detected and PARSED into the same graph as the
    equivalent CSV — one <ReportItem> is one CSV row, so the two must agree
    node-for-node, edge-for-edge, and score-for-score
  * one node per plugin, one edge per (host, plugin), ports folded onto the edge
    — two edges with the same endpoints MERGE in Neo4j and lose the port data
  * host labels match BloodHound's uppercase convention, which is the only
    reason a scan merges into SharpHound's Device instead of duplicating it
  * the scanned-host count is the number of hosts scanned, not Device+Ip (a host
    known by both name and address has two nodes)
  * severity-None rows are skipped but COUNTED, and still yield OS/CPE facts
  * every emitted node carries data['nodeLabel'] and its type's primary field
  * Vulnerability numeric fields stay out of the registered schema (a declared
    custom-type property is rebuilt as Optional[str] and a float would be
    silently dropped)
  * the unregistered-Vulnerability guard degrades to "no findings", not
    "no ingest" — hosts and technologies still land
  * a report that yields nothing says WHY, because "no findings" and "a clean
    estate" look identical otherwise

Usage:
    python3 scripts/smoke_nessus.py           # all scenarios
    python3 scripts/smoke_nessus.py --verbose
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

REPO_ROOT = Path(__file__).resolve().parents[1]

# ── Fixtures ──────────────────────────────────────────────────────────────────

HEADER = (
    "Plugin ID,CVE,CVSS v2.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,"
    "Description,Solution,See Also,Plugin Output,CVSS v3.0 Base Score,"
    "Metasploit,Core Impact,CANVAS,DNS Name,MAC Address\n"
)

OS_OUTPUT = (
    "Remote operating system : Microsoft Windows Server 2016 Standard\n"
    "Confidence level : 95\n"
    "Method : SMB"
)

CPE_OUTPUT = (
    "The remote operating system matched the following CPE :\n"
    "  cpe:/o:microsoft:windows_server_2016 -> Microsoft Windows Server 2016\n"
    "Following application CPE's matched on the remote system :\n"
    "  cpe:/a:openbsd:openssh:7.4 -> OpenBSD OpenSSH 7.4"
)

SAMPLE_CSV = HEADER + "".join([
    # Same plugin, same host, two ports — must fold into ONE edge with two ports.
    '12345,CVE-2021-44228,10.0,Critical,10.10.0.11,tcp,8080,'
    '"Apache Log4j Remote Code Execution","Remote service is vulnerable.",'
    '"A long description.","Upgrade to 2.17.0.",https://logging.apache.org/,'
    '"Port 8080 responded.",10.0,true,false,false,dc01.corp.local,00:11:22:33:44:55\n',

    '12345,CVE-2021-44228,10.0,Critical,10.10.0.11,tcp,8443,'
    '"Apache Log4j Remote Code Execution","Remote service is vulnerable.",'
    '"A long description.","Upgrade to 2.17.0.",https://logging.apache.org/,'
    '"Port 8443 responded.",10.0,true,false,false,dc01.corp.local,00:11:22:33:44:55\n',

    # Same plugin, a second host that has no DNS name — an Ip node.
    '12345,CVE-2021-44228,10.0,Critical,10.10.0.12,tcp,8080,'
    '"Apache Log4j Remote Code Execution","Remote service is vulnerable.",'
    '"A long description.","Upgrade to 2.17.0.",https://logging.apache.org/,'
    '"Port 8080 responded.",10.0,true,false,false,,\n',

    # A medium finding with no CVE and no exploit.
    '42873,,5.0,Medium,10.10.0.11,tcp,443,'
    '"SSL Medium Strength Cipher Suites Supported","Weak ciphers offered.",'
    '"The remote host supports 64-bit ciphers.","Reconfigure the service.",,'
    '"TLSv1 offered.",4.3,false,false,false,dc01.corp.local,00:11:22:33:44:55\n',

    # Informational: OS identification. Skipped as a finding, mined for the OS.
    '11936,,,None,10.10.0.11,tcp,0,"OS Identification",'
    '"It is possible to guess the remote operating system.",'
    '"Using a combination of remote probes.","n/a",,'
    '"' + OS_OUTPUT.replace('"', '""') + '",,false,false,false,'
    'dc01.corp.local,00:11:22:33:44:55\n',

    # Informational: CPE enumeration. Skipped as a finding, mined for products.
    '45590,,,None,10.10.0.11,tcp,0,"Common Platform Enumeration (CPE)",'
    '"It was possible to enumerate CPE names.","n/a","n/a",,'
    '"' + CPE_OUTPUT.replace('"', '""') + '",,false,false,false,'
    'dc01.corp.local,00:11:22:33:44:55\n',
])

# A Tenable Vulnerability Management-shaped export: different column names, a
# numeric severity, and no Risk column at all.
TENABLE_CSV = (
    "Plugin,Plugin Name,Family,Severity,IPv4 Address,DNS Name,Protocol,Port,"
    "CVE,CVSSv3 Base Score,Solution\n"
    '19506,"Nessus Scan Information",General,0,10.20.0.5,web01.corp.local,tcp,0,,,\n'
    '156032,"Apache Struts RCE","Web Servers",4,10.20.0.5,web01.corp.local,tcp,'
    '443,CVE-2023-50164,9.8,"Upgrade Struts."\n'
)

# The .nessus XML export of the SAME scan as SAMPLE_CSV — one <ReportItem> per
# CSV row. It must parse into the identical graph (scenario_xml_equivalence):
# log4j (12345) on dc01:8080 and dc01:8443 folding to one edge, the same plugin
# on the address-only 10.10.0.12, a CVE-less medium (42873) on dc01:443, and the
# two informational fact plugins (11936 OS, 45590 CPE) mined but not ingested.
SAMPLE_XML = b'''<?xml version="1.0" ?>
<NessusClientData_v2>
<Report name="scan">
<ReportHost name="10.10.0.11">
  <HostProperties>
    <tag name="host-ip">10.10.0.11</tag>
    <tag name="host-fqdn">dc01.corp.local</tag>
    <tag name="mac-address">00:11:22:33:44:55</tag>
  </HostProperties>
  <ReportItem port="8080" protocol="tcp" severity="4" pluginID="12345" pluginName="Apache Log4j Remote Code Execution" pluginFamily="Web Servers">
    <risk_factor>Critical</risk_factor><cvss_base_score>10.0</cvss_base_score><cvss3_base_score>10.0</cvss3_base_score>
    <cve>CVE-2021-44228</cve><synopsis>Remote service is vulnerable.</synopsis><description>A long description.</description>
    <solution>Upgrade to 2.17.0.</solution><see_also>https://logging.apache.org/</see_also>
    <exploit_framework_metasploit>true</exploit_framework_metasploit><plugin_output>Port 8080 responded.</plugin_output>
  </ReportItem>
  <ReportItem port="8443" protocol="tcp" severity="4" pluginID="12345" pluginName="Apache Log4j Remote Code Execution" pluginFamily="Web Servers">
    <risk_factor>Critical</risk_factor><cvss_base_score>10.0</cvss_base_score><cvss3_base_score>10.0</cvss3_base_score>
    <cve>CVE-2021-44228</cve><synopsis>Remote service is vulnerable.</synopsis><description>A long description.</description>
    <solution>Upgrade to 2.17.0.</solution><exploit_framework_metasploit>true</exploit_framework_metasploit>
    <plugin_output>Port 8443 responded.</plugin_output>
  </ReportItem>
  <ReportItem port="443" protocol="tcp" severity="2" pluginID="42873" pluginName="SSL Medium Strength Cipher Suites Supported" pluginFamily="General">
    <risk_factor>Medium</risk_factor><cvss_base_score>5.0</cvss_base_score><cvss3_base_score>4.3</cvss3_base_score>
    <synopsis>Weak ciphers offered.</synopsis><description>The remote host supports 64-bit ciphers.</description>
    <solution>Reconfigure the service.</solution><plugin_output>TLSv1 offered.</plugin_output>
  </ReportItem>
  <ReportItem port="0" protocol="tcp" severity="0" pluginID="11936" pluginName="OS Identification" pluginFamily="General">
    <risk_factor>None</risk_factor>
    <plugin_output>''' + OS_OUTPUT.encode() + b'''</plugin_output>
  </ReportItem>
  <ReportItem port="0" protocol="tcp" severity="0" pluginID="45590" pluginName="Common Platform Enumeration (CPE)" pluginFamily="General">
    <risk_factor>None</risk_factor>
    <plugin_output>''' + CPE_OUTPUT.encode() + b'''</plugin_output>
  </ReportItem>
</ReportHost>
<ReportHost name="10.10.0.12">
  <HostProperties><tag name="host-ip">10.10.0.12</tag></HostProperties>
  <ReportItem port="8080" protocol="tcp" severity="4" pluginID="12345" pluginName="Apache Log4j Remote Code Execution" pluginFamily="Web Servers">
    <risk_factor>Critical</risk_factor><cvss_base_score>10.0</cvss_base_score>
    <cve>CVE-2021-44228</cve><synopsis>Remote service is vulnerable.</synopsis>
    <exploit_framework_metasploit>true</exploit_framework_metasploit><plugin_output>Port 8080 responded.</plugin_output>
  </ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>
'''

# A well-formed but finding-less XML (a ReportHost with no ReportItem) — used to
# check the "no findings" explanation, not a refusal.
NESSUS_XML_EMPTY = (
    b'<?xml version="1.0" ?>\n<NessusClientData_v2>\n'
    b'<Report name="scan"><ReportHost name="10.10.0.11"/></Report>\n'
    b'</NessusClientData_v2>\n'
)

USER_CSV = b"username,email\nrjones,rjones@example.test\nkpatel,kpatel@example.test\n"

RESULTS: list = []


def check(name: str, condition: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(condition), detail))


# ── Scenarios ─────────────────────────────────────────────────────────────────

def scenario_detection() -> None:
    from upload_router import detect_format

    check("detect Nessus CSV as nessus",
          detect_format(SAMPLE_CSV.encode(), "scan.csv") == "nessus",
          detect_format(SAMPLE_CSV.encode(), "scan.csv"))
    check("detect Nessus CSV without a filename",
          detect_format(SAMPLE_CSV.encode(), "") == "nessus")
    check("detect a Tenable VM export as nessus",
          detect_format(TENABLE_CSV.encode(), "findings.csv") == "nessus",
          detect_format(TENABLE_CSV.encode(), "findings.csv"))
    check("detect the .nessus XML export as nessus (so the parser handles it)",
          detect_format(SAMPLE_XML, "scan.nessus") == "nessus")
    check("detect the .nessus XML by its bytes even when renamed",
          detect_format(SAMPLE_XML, "report.txt") == "nessus")
    # The generic CSV branch matches any header containing "ip" as a SUBSTRING,
    # and "description" contains one. Without the nessus check running first,
    # every Nessus report was read as a list of people.
    check("an ordinary user CSV still routes to csv",
          detect_format(USER_CSV, "users.csv") == "csv",
          detect_format(USER_CSV, "users.csv"))


def scenario_hint() -> None:
    from upload_router import hint_format

    # A report exported with a trimmed column set fails strict detection and
    # lands on text; the operator's Context line is allowed to rescue it.
    trimmed = b"Plugin ID,Host,Name\n12345,10.0.0.1,Something\n"
    check("a trimmed export is rescued by a 'nessus' context line",
          hint_format("nessus scan of the DMZ", trimmed, "text") == "nessus",
          hint_format("nessus scan of the DMZ", trimmed, "text"))
    # Prose never beats bytes: a payload that cannot be a scan keeps its format.
    check("a mislabelled paste is NOT force-fed to the nessus parser",
          hint_format("nessus export", b"just some prose about nothing", "text") == "text")


def scenario_parse() -> None:
    from nessus_parser import parse_bytes

    result = parse_bytes(SAMPLE_CSV.encode(), "scan.csv")
    check("CSV parses without errors", not result.errors, str(result.errors))

    labels = {e.label for e in result.entities}
    by_type = {}
    for e in result.entities:
        by_type.setdefault(e.entity_type, []).append(e)

    check("host known by name becomes an uppercase Device",
          "DC01.CORP.LOCAL" in labels, str(sorted(labels)))
    check("host known only by address becomes an Ip",
          "10.10.0.12" in labels, str(sorted(labels)))
    check("the named host also gets its address node",
          "10.10.0.11" in labels, str(sorted(labels)))
    # The companion address node must not count as a scanned host: every reader
    # that reports coverage filters on nessus_scanned.
    companion = next(e for e in result.entities if e.label == "10.10.0.11")
    check("the companion address node is not flagged as scanned",
          "nessus_scanned" not in companion.properties,
          str(sorted(companion.properties.keys())))
    check("one Vulnerability node per plugin (not per row)",
          len(by_type.get("Vulnerability", [])) == 2,
          str([e.label for e in by_type.get("Vulnerability", [])]))
    check("scanned-host count is hosts, not Device+Ip",
          result.summary()["hosts"] == 2, str(result.summary()["hosts"]))

    # Edge folding: three rows of plugin 12345 on two hosts → two edges, and the
    # DC's edge carries BOTH ports.
    findings = [r for r in result.relationships if r.label == "HAS_VULNERABILITY"]
    p12345 = [r for r in findings if r.target_temp_id.endswith("12345")]
    check("plugin 12345 produces one edge per host, not one per row",
          len(p12345) == 2, str(len(p12345)))
    check("the DC gets exactly one edge for the plugin, both ports folded",
          len([r for r in p12345 if "DC01" in r.source_temp_id]) == 1,
          str([r.source_temp_id for r in p12345]))

    check("Device -> Ip is joined by RESOLVES_TO",
          any(r.label == "RESOLVES_TO" for r in result.relationships))

    # Per-host detail must be on the NODE. batch_import drops edge properties on
    # every path it has — verified against the live graph, where every
    # relationship carries only from_element_id/rel_label/sketch_id/to_element_id
    # — so anything written to the edge is lost without a word.
    check("no finding edge carries data that would be dropped on import",
          all(not r.data for r in result.relationships
              if r.label == "HAS_VULNERABILITY"),
          str([r.data for r in result.relationships
               if r.label == "HAS_VULNERABILITY" and r.data][:2]))
    log4j_node = next(e for e in result.entities
                      if e.entity_type == "Vulnerability"
                      and e.properties["plugin_id"] == "12345")
    details = json.loads(log4j_node.properties["host_details"])
    check("per-host detail is carried on the Vulnerability node",
          len(details) == 2, str(details))
    dc_detail = next((d for d in details if d["host"] == "DC01.CORP.LOCAL"), None)
    check("the node's host detail keeps both ports",
          bool(dc_detail) and sorted(dc_detail["ports"]) == ["8080/tcp", "8443/tcp"],
          str(dc_detail))
    check("the node's host detail keeps the plugin output",
          bool(dc_detail) and "responded" in dc_detail["output"],
          str(dc_detail.get("output") if dc_detail else None))
    check("host detail is not marked truncated when it is complete",
          log4j_node.properties.get("host_details_truncated") is False,
          str(log4j_node.properties.get("host_details_truncated")))

    dc = next(e for e in result.entities if e.label == "DC01.CORP.LOCAL")

    # Counting: severity_counts is per PLUGIN and must match what
    # nessus_context.summarise() reads off the graph; `findings` is host×plugin.
    # Two rows of one plugin on one host is ONE critical, not two — otherwise a
    # host's risk scales with how many ports it happened to expose.
    check("severity_counts is per plugin, not per row",
          result.severity_counts["critical"] == 1
          and result.severity_counts["medium"] == 1,
          str(result.severity_counts))
    check("findings is host x plugin", result.summary()["findings"] == 3,
          str(result.summary()["findings"]))
    check("the DC's critical count is per finding, not per row",
          dc.properties["nessus_critical_count"] == 1,
          str(dc.properties.get("nessus_critical_count")))

    # Informational rows.
    check("informational rows are skipped as findings",
          result.rows_skipped_info == 2, str(result.rows_skipped_info))
    check("informational rows are counted, not lost",
          dc.properties["nessus_info_count"] == 2,
          str(dc.properties.get("nessus_info_count")))
    check("skipped informational rows stay out of severity_counts",
          result.severity_counts["info"] == 0, str(result.severity_counts))
    check("OS is lifted from plugin 11936",
          dc.properties.get("nessus_os") == "Microsoft Windows Server 2016 Standard",
          str(dc.properties.get("nessus_os")))
    # A scanner fingerprint must never overwrite SharpHound's real OS attribute.
    check("a Device does NOT get a bare operating_system",
          "operating_system" not in dc.properties,
          str(sorted(dc.properties.keys())))

    techs = by_type.get("Technology", [])
    check("CPEs from plugin 45590 become Technology nodes",
          len(techs) == 2, str([t.label for t in techs]))
    check("the human title names the Technology, and the version is not doubled",
          any(t.label == "OpenBSD OpenSSH 7.4" for t in techs),
          str([t.label for t in techs]))
    check("every Technology carries its CPE for precise CVE matching",
          all(t.properties.get("cpe") for t in techs))
    # name/version must be SPLIT, not merged into name. Flowsint composes a
    # Technology node's nodeLabel from name+version server-side, so a name that
    # already ends in the version lands as "OpenBSD OpenSSH 7.4 7.4" — and stops
    # matching the node nmap creates for the same product.
    ssh = next(t for t in techs if "OpenSSH" in t.label)
    check("the product name excludes the version",
          ssh.properties["name"] == "OpenBSD OpenSSH",
          str(ssh.properties.get("name")))
    check("the version is carried separately",
          ssh.properties["version"] == "7.4", str(ssh.properties.get("version")))
    # ':o:' is never a substring of 'cpe:/o:vendor:...' — it is ':/o:'.
    win = next(t for t in techs if "Windows" in t.label)
    check("an operating-system CPE is categorised as OS, not Application",
          win.properties["category"] == "OS", str(win.properties.get("category")))
    check("an application CPE is categorised as Application",
          ssh.properties["category"] == "Application",
          str(ssh.properties.get("category")))

    # Severity + exploitability.
    log4j = next(e for e in by_type["Vulnerability"] if e.properties["plugin_id"] == "12345")
    check("severity is normalised", log4j.properties["severity"] == "critical")
    check("CVEs are lifted", log4j.properties["cve_ids"] == ["CVE-2021-44228"],
          str(log4j.properties.get("cve_ids")))
    check("the Metasploit column becomes an exploit framework",
          log4j.properties["exploit_frameworks"] == ["Metasploit"],
          str(log4j.properties.get("exploit_frameworks")))
    check("affected host count is distinct hosts",
          log4j.properties["affected_host_count"] == 2,
          str(log4j.properties.get("affected_host_count")))
    check("a weaponised critical on two hosts scores in the critical band",
          log4j.properties["priority_score"] >= 80,
          str(log4j.properties.get("priority_score")))

    ssl = next(e for e in by_type["Vulnerability"] if e.properties["plugin_id"] == "42873")
    check("a medium with no exploit scores below the critical",
          ssl.properties["priority_score"] < log4j.properties["priority_score"],
          f"{ssl.properties.get('priority_score')} vs {log4j.properties.get('priority_score')}")

    # Per-host rollup written at ingest.
    check("the DC carries a severity-weighted risk score",
          dc.properties["nessus_risk_score"] > 0, str(dc.properties.get("nessus_risk_score")))
    check("the DC's CVE exposure is recorded under a compute_composite_risk-shaped key",
          dc.properties.get("nessus_cve_exposure") == 1,
          str(dc.properties.get("nessus_cve_exposure")))


def scenario_label_casing() -> None:
    """
    Every reader must find the findings whichever casing the importer used.

    batch_import writes through /api/import/execute, which LOWERCASES the node
    type: an ingested report is labelled `vulnerability`, not `Vulnerability`.
    Reading only the PascalCase spelling found zero nodes, so contextualization
    ran, reported success, and did nothing at all — and the LLM tool answered
    "no findings on this host" for a host full of them.
    """
    import nessus_context as nc

    check("the context pass reads BOTH label casings",
          set(nc.VULN_LABELS) == {"vulnerability", "Vulnerability"},
          str(nc.VULN_LABELS))
    check("the lowercase spelling — the one that actually lands — is read first",
          nc.VULN_LABELS[0] == "vulnerability", str(nc.VULN_LABELS))
    check("the host rollup reads both casings too",
          {"device", "ip"} <= set(nc.HOST_LABELS), str(nc.HOST_LABELS))

    tool = (REPO_ROOT / "llm" / "tools" / "vulnerability_tool.py").read_text()
    check("the LLM tool pins no PascalCase :Vulnerability label in Cypher",
          ":Vulnerability)" not in tool,
          "found a hardcoded (v:Vulnerability) pattern")
    check("the LLM tool filters on nodeType where it has no relationship to lean on",
          "toLower(coalesce(v.nodeType, '')) = 'vulnerability'" in tool)

    purge = (REPO_ROOT / "scripts" / "purge_nessus_data.py").read_text()
    check("the purge matches on nodeType, not on a label",
          "toLower(coalesce(n.nodeType,'')) = 'vulnerability'" in purge)


def scenario_tenable_variant() -> None:
    from nessus_parser import parse_bytes

    result = parse_bytes(TENABLE_CSV.encode(), "findings.csv")
    check("Tenable VM columns parse without errors", not result.errors, str(result.errors))
    vulns = [e for e in result.entities if e.entity_type == "Vulnerability"]
    check("numeric Severity 4 maps to critical",
          len(vulns) == 1 and vulns[0].properties["severity"] == "critical",
          str([(v.properties["plugin_id"], v.properties["severity"]) for v in vulns]))
    check("Severity 0 is treated as informational and skipped",
          result.rows_skipped_info == 1, str(result.rows_skipped_info))
    check("CVSSv3 Base Score is read under its Tenable spelling",
          vulns and vulns[0].properties.get("cvss3_base_score") == 9.8,
          str(vulns[0].properties.get("cvss3_base_score")) if vulns else "no vuln")


def scenario_node_contract() -> None:
    """Every node must survive the importer. Both ways it silently does not."""
    from nessus_parser import parse_bytes
    from upload_router import ENTITY_PRIMARY_FIELD, canonical_entity_type

    nodes, edges = parse_bytes(SAMPLE_CSV.encode(), "scan.csv").to_flowsint_batch()
    check("parse produced nodes", bool(nodes))

    missing_label = [n.get("nodeLabel", "?") for n in nodes
                     if not (n.get("data") or {}).get("nodeLabel")]
    check("every node carries data['nodeLabel']", not missing_label, str(missing_label[:3]))
    check("no two nodes share a nodeLabel",
          len({(n.get("data") or {}).get("nodeLabel") for n in nodes}) == len(nodes))

    unresolved, missing_primary = [], []
    for node in nodes:
        canonical = canonical_entity_type(node.get("entity_type", ""))
        if not canonical:
            unresolved.append(node.get("entity_type"))
            continue
        primary = ENTITY_PRIMARY_FIELD.get(canonical, "")
        if primary and not (node.get("data") or {}).get(primary):
            missing_primary.append((canonical, node.get("nodeLabel"), primary))
    check("every entity_type resolves to a Flowsint type", not unresolved, str(unresolved))
    check("every built-in node sets its required primary field",
          not missing_primary, str(missing_primary[:3]))

    node_ids = {n["node_id"] for n in nodes}
    dangling = [e for e in edges if e["from_id"] not in node_ids or e["to_id"] not in node_ids]
    check("no edge references a node that was not emitted", not dangling, str(dangling[:2]))

    # Every node must carry import_ref == node_id so batch_import's cross-chunk edge
    # resolver can find it: a large ingest imports nodes in chunks, and an edge whose
    # endpoints straddle two chunks is resolved by nodeProperties.sid / device_id /
    # import_ref — none of which a Nessus node otherwise has, so without this every
    # cross-chunk finding edge is silently dropped ("endpoint SID not in graph").
    bad_ref = [n["nodeLabel"] for n in nodes
               if (n.get("data") or {}).get("import_ref") != n["node_id"]]
    check("every node stamps import_ref == node_id (cross-chunk edge resolution)",
          not bad_ref, str(bad_ref[:3]))


def scenario_registered_schema_split() -> None:
    """A declared custom-type property is rebuilt as Optional[str]; a float dies."""
    from nessus_parser import parse_bytes
    from register_nessus_type import VULNERABILITY_SCHEMA

    declared = set(VULNERABILITY_SCHEMA["properties"])
    must_stay_native = {
        "cve_ids", "cve_count", "cvss_base_score", "cvss3_base_score",
        "cvss4_base_score", "vpr_score", "epss_score", "affected_host_count",
        "ports", "exploit_frameworks", "exploit_framework_available",
        "priority_score", "severity_rank",
    }
    leaked = must_stay_native & declared
    check("no numeric/list Vulnerability field is in the registered schema",
          not leaked, str(sorted(leaked)))

    result = parse_bytes(SAMPLE_CSV.encode(), "scan.csv")
    vuln = next(e for e in result.entities if e.entity_type == "Vulnerability")
    check("priority_score is written as an int, not a string",
          isinstance(vuln.properties.get("priority_score"), int),
          type(vuln.properties.get("priority_score")).__name__)
    check("cve_ids is written as a list, not a string",
          isinstance(vuln.properties.get("cve_ids"), list),
          type(vuln.properties.get("cve_ids")).__name__)

    # The other half of the contract: every declared property that the parser
    # writes must be a string, or the serializer drops it.
    non_str = [k for k in declared
               if k in vuln.properties and not isinstance(vuln.properties[k], str)]
    check("every declared property the parser writes is a string",
          not non_str, str(non_str))


def scenario_unregistered_guard() -> None:
    from nessus_parser import parse_bytes

    result = parse_bytes(SAMPLE_CSV.encode(), "scan.csv", allow_vuln_nodes=False)
    types = {e.entity_type for e in result.entities}
    check("no Vulnerability node when the type is unregistered",
          "Vulnerability" not in types, str(sorted(types)))
    check("hosts still ingest when the type is unregistered",
          "Device" in types and "Ip" in types, str(sorted(types)))
    check("technologies still ingest when the type is unregistered",
          "Technology" in types, str(sorted(types)))
    check("no dangling HAS_VULNERABILITY edge is emitted",
          not any(r.label == "HAS_VULNERABILITY" for r in result.relationships))
    # The analysis is computed either way, so the operator still gets the report.
    check("the report summary is still complete",
          result.summary()["plugins"] == 0 and len(result.top_findings) == 2,
          str(len(result.top_findings)))


def scenario_include_info() -> None:
    from nessus_parser import parse_bytes

    result = parse_bytes(SAMPLE_CSV.encode(), "scan.csv", include_info=True)
    plugins = {e.properties["plugin_id"] for e in result.entities
               if e.entity_type == "Vulnerability"}
    check("include_info promotes informational plugins to nodes",
          {"11936", "45590"} <= plugins, str(sorted(plugins)))
    check("include_info leaves nothing in rows_skipped_info",
          result.rows_skipped_info == 0, str(result.rows_skipped_info))


def scenario_priority_recompute() -> None:
    """nessus_context must move the score, and must use the parser's formula."""
    from nessus_parser import compute_priority, priority_tier

    base = compute_priority("high", 3, [])
    with_fw = compute_priority("high", 3, ["Metasploit"])
    with_poc = compute_priority("high", 3, ["Metasploit"], poc_count=5)
    check("a weaponised finding outranks the same finding without an exploit",
          with_fw > base, f"{with_fw} vs {base}")
    check("public PoC code raises the score further",
          with_poc > with_fw, f"{with_poc} vs {with_fw}")
    check("the score is bounded at 100", compute_priority("critical", 999,
                                                          ["Metasploit"], 999) == 100)
    check("an informational finding scores 0", compute_priority("info", 50, []) == 0)
    check("tiers band the score", priority_tier(85) == "critical"
          and priority_tier(0) == "info")


def scenario_xml_equivalence() -> None:
    """The .nessus XML and the equivalent CSV must produce the same graph."""
    from nessus_parser import parse_bytes

    csv = parse_bytes(SAMPLE_CSV.encode(), "scan.csv")
    xml = parse_bytes(SAMPLE_XML, "scan.nessus")

    check("the .nessus XML parses without error", not xml.errors, str(xml.errors))
    check("the source_format records it came from XML",
          xml.source_format == "nessus-xml", xml.source_format)

    cs, xs = csv.summary(), xml.summary()
    for key in ("hosts", "plugins", "findings", "technologies", "cve_count",
                "severity_counts", "entities_by_type", "relationships"):
        check(f"XML matches CSV on {key}", cs[key] == xs[key],
              f"csv={cs[key]!r} xml={xs[key]!r}")
    check("XML matches CSV on the top finding's priority score",
          cs["top_findings"][0]["priority_score"]
          == xs["top_findings"][0]["priority_score"])

    # The load-bearing specifics, checked on the XML output directly.
    xnodes, xedges = xml.to_flowsint_batch()
    labels = {n["nodeLabel"] for n in xnodes}
    check("the named host is an uppercase Device (merges with SharpHound)",
          "DC01.CORP.LOCAL" in labels, sorted(labels))
    log4j = next((n for n in xnodes
                  if n["data"].get("plugin_id") == "12345"), None)
    check("the log4j plugin folds its two ports onto one node",
          bool(log4j) and sorted(log4j["data"]["ports"]) == ["8080/tcp", "8443/tcp"],
          log4j and log4j["data"].get("ports"))
    check("the log4j plugin records both affected hosts",
          bool(log4j) and log4j["data"]["affected_host_count"] == 2)
    dc01 = next((n for n in xnodes if n["nodeLabel"] == "DC01.CORP.LOCAL"), None)
    check("the OS is mined from plugin 11936 onto the Device",
          bool(dc01) and "Windows Server 2016" in dc01["data"].get("nessus_os", ""),
          dc01 and dc01["data"].get("nessus_os"))
    check("CPEs from plugin 45590 become Technology nodes",
          {"Microsoft Windows Server 2016", "OpenBSD OpenSSH 7.4"} <= labels)


def scenario_bad_inputs() -> None:
    from nessus_parser import parse_bytes

    xml = parse_bytes(NESSUS_XML_EMPTY, "scan.nessus")
    check("a finding-less .nessus XML says so rather than reporting a clean estate",
          bool(xml.errors) and any("ReportItem" in e for e in xml.errors),
          str(xml.errors))
    check("...and nothing is ingested from it", not xml.entities)

    truncated = parse_bytes(
        b'<?xml version="1.0" ?>\n<NessusClientData_v2>\n<Report><ReportHost',
        "scan.nessus")
    check("a truncated .nessus XML reports the malformation",
          any("malformed" in e for e in truncated.errors), str(truncated.errors))

    empty = parse_bytes(b"", "scan.csv")
    check("an empty upload errors", bool(empty.errors), str(empty.errors))

    header_only = parse_bytes(HEADER.encode(), "scan.csv")
    check("a header with no rows says so, rather than reporting a clean estate",
          bool(header_only.errors), str(header_only.errors))

    wrong = parse_bytes(b"name,department\nAlice,IT\n", "people.csv")
    check("a CSV with no Plugin ID column errors",
          any("Plugin ID" in e for e in wrong.errors), str(wrong.errors))

    # An all-informational report is the case most likely to be misread as
    # "nothing found", so it has to explain itself.
    info_only = HEADER + (
        '11936,,,None,10.10.0.11,tcp,0,"OS Identification","syn","desc","n/a",,'
        '"nothing",,false,false,false,,\n')
    only = parse_bytes(info_only.encode(), "scan.csv")
    check("an all-informational report explains why it produced no findings",
          any("informational" in e for e in only.errors), str(only.errors))


def scenario_router_integration() -> None:
    from upload_router import route_bytes

    result = route_bytes(SAMPLE_CSV.encode(), filename="scan.csv", ingest=False)
    check("route_bytes routes the report to the nessus parser",
          result["format"] == "nessus", result["format"])
    check("route_bytes returns nodes", result["nodes_count"] > 0)
    check("route_bytes carries the report summary",
          bool(result.get("report", {}).get("severity_counts")),
          str(result.get("report", {}).keys()))
    check("the summary reports what was skipped",
          result["report"]["rows_skipped_info"] == 2,
          str(result["report"].get("rows_skipped_info")))
    # Provenance: the analyst's Context line lands on every node.
    ctx = route_bytes(SAMPLE_CSV.encode(), filename="scan.csv", ingest=False,
                      context="nessus credentialed scan of the DC subnet")
    check("the ingest context is stamped onto the nodes",
          all(n["data"].get("ingest_context") for n in ctx["nodes"]))

    # The .nessus XML export goes through the identical router path.
    xml = route_bytes(SAMPLE_XML, filename="scan.nessus", ingest=False)
    check("route_bytes routes the .nessus XML to the nessus parser",
          xml["format"] == "nessus", xml["format"])
    check("route_bytes ingests nodes from the .nessus XML",
          xml["nodes_count"] == result["nodes_count"],
          f'xml={xml["nodes_count"]} csv={result["nodes_count"]}')


# ── Runner ────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verbose", action="store_true",
                        help="print every passing check")
    args = parser.parse_args(argv)

    scenarios = (
        ("format detection", scenario_detection),
        ("context hinting", scenario_hint),
        ("report parsing", scenario_parse),
        ("graph label casing", scenario_label_casing),
        ("Tenable VM variant", scenario_tenable_variant),
        ("node import contract", scenario_node_contract),
        ("Vulnerability schema split", scenario_registered_schema_split),
        ("unregistered-type guard", scenario_unregistered_guard),
        ("informational passthrough", scenario_include_info),
        ("priority scoring", scenario_priority_recompute),
        ("xml equivalence", scenario_xml_equivalence),
        ("bad inputs", scenario_bad_inputs),
        ("router integration", scenario_router_integration),
    )

    for label, fn in scenarios:
        before = len(RESULTS)
        try:
            fn()
        except Exception as exc:                      # noqa: BLE001 - report, don't abort
            check(f"{label} raised", False, repr(exc))
        passed = sum(1 for _, ok, _ in RESULTS[before:] if ok)
        print(f"  {label:<30} {passed}/{len(RESULTS) - before} checks passed")

    failures = [(n, d) for n, ok, d in RESULTS if not ok]
    if args.verbose:
        for name, ok, detail in RESULTS:
            print(f"    {'ok  ' if ok else 'FAIL'} {name}"
                  + (f"  — {detail}" if detail and not ok else ""))

    print()
    if failures:
        print(f"smoke_nessus: {len(failures)} FAILED of {len(RESULTS)}")
        for name, detail in failures:
            print(f"  FAIL {name}" + (f"  — {detail}" if detail else ""))
        return 1
    print(f"smoke_nessus: all {len(RESULTS)} checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
