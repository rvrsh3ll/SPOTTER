"""
smoke_pingcastle.py — Offline contract tests for the PingCastle ingest path.

Runs against a synthetic ad_hc_<domain> report built from PingCastle's
HealthcheckData schema, so it needs no live stack and no real engagement data.

What it pins down (each of these has bitten this codebase before):
  * format detection wins over the nmap-XML and generic-JSON branches
  * .xml and .json reports produce the same graph
  * node labels match BloodHound's uppercase convention, which is the only
    reason PingCastle merges into SharpHound nodes instead of duplicating them
  * cleartext GPP passwords never reach the node payload
  * ADRisk numeric fields stay out of the registered schema (a declared custom-type
    property is rebuilt as Optional[str] and an int would be silently dropped)
  * the unregistered-ADRisk guard degrades to "no risk nodes", not "no ingest"
  * encrypted / HTML reports fail loudly with an actionable message

Usage:
    python3 scripts/smoke_pingcastle.py           # all scenarios
    python3 scripts/smoke_pingcastle.py --verbose
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SAMPLE_XML = """<?xml version="1.0" encoding="utf-8"?>
<HealthcheckData xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <EngineVersion>3.2.0.1</EngineVersion>
  <GenerationDate>2026-08-01T09:14:22.7654321</GenerationDate>
  <DomainFQDN>corp.local</DomainFQDN>
  <NetBIOSName>CORP</NetBIOSName>
  <ForestFQDN>corp.local</ForestFQDN>
  <DomainSid>S-1-5-21-1111111111-2222222222-3333333333</DomainSid>
  <DomainFunctionalLevel>6</DomainFunctionalLevel>
  <GlobalScore>75</GlobalScore>
  <StaleObjectsScore>40</StaleObjectsScore>
  <PrivilegiedGroupScore>75</PrivilegiedGroupScore>
  <TrustScore>20</TrustScore>
  <AnomalyScore>65</AnomalyScore>
  <MaturityLevel>2</MaturityLevel>
  <KrbtgtLastChangeDate>2015-06-02T11:31:00</KrbtgtLastChangeDate>
  <LAPSInstalled>0001-01-01T00:00:00</LAPSInstalled>
  <MachineAccountQuota>10</MachineAccountQuota>
  <UserAccountData>
    <Number>4213</Number>
    <NumberEnabled>3902</NumberEnabled>
    <NumberNoPreAuth>6</NumberNoPreAuth>
  </UserAccountData>
  <DomainControllers>
    <HealthcheckDomainController WebClientEnabled="true">
      <DCName>DC01</DCName>
      <OperatingSystem>Windows Server 2012 R2</OperatingSystem>
      <SupportSMB1>true</SupportSMB1>
      <RemoteSpoolerDetected>true</RemoteSpoolerDetected>
      <PwdLastSet>2026-07-25T04:00:00</PwdLastSet>
      <IP><string>10.10.0.11</string></IP>
      <FSMO><string>PDC</string></FSMO>
    </HealthcheckDomainController>
  </DomainControllers>
  <Trusts>
    <HealthCheckTrustData>
      <TrustPartner>partner.example</TrustPartner>
      <TrustAttributes>8</TrustAttributes>
      <TrustDirection>3</TrustDirection>
      <TrustType>2</TrustType>
      <IsActive>true</IsActive>
      <SID>S-1-5-21-9999999999-8888888888-7777777777</SID>
      <NetBiosName>PARTNER</NetBiosName>
    </HealthCheckTrustData>
  </Trusts>
  <PrivilegedGroups>
    <HealthCheckGroupData>
      <GroupName>Domain Admins</GroupName>
      <Sid>S-1-5-21-1111111111-2222222222-3333333333-512</Sid>
      <NumberOfMember>2</NumberOfMember>
      <Members>
        <HealthCheckGroupMemberData>
          <Name>Administrator</Name>
          <DistinguishedName>CN=Administrator,CN=Users,DC=corp,DC=local</DistinguishedName>
          <IsEnabled>true</IsEnabled>
          <PwdLastSet>2023-01-04T09:00:00</PwdLastSet>
          <Sid>S-1-5-21-1111111111-2222222222-3333333333-500</Sid>
        </HealthCheckGroupMemberData>
        <HealthCheckGroupMemberData>
          <Name>svc_backup</Name>
          <DistinguishedName>CN=svc_backup,OU=Service Accounts,DC=corp,DC=local</DistinguishedName>
          <IsEnabled>true</IsEnabled>
          <IsService>true</IsService>
          <ServicePrincipalNames><string>MSSQLSvc/sql01.corp.local:1433</string></ServicePrincipalNames>
          <Sid>S-1-5-21-1111111111-2222222222-3333333333-1104</Sid>
        </HealthCheckGroupMemberData>
      </Members>
    </HealthCheckGroupData>
  </PrivilegedGroups>
  <GPPPassword>
    <GPPPassword>
      <UserName>local_admin</UserName>
      <Password>SuperSecret123!</Password>
      <GPOName>Workstation Baseline</GPOName>
    </GPPPassword>
  </GPPPassword>
  <RiskRules>
    <HealthcheckRiskRule>
      <Points>50</Points>
      <Category>PrivilegedAccounts</Category>
      <Model>CredentialTheft</Model>
      <RiskId>P-Delegated</RiskId>
      <Rationale>Privileged accounts can be delegated</Rationale>
      <Details><string>svc_backup</string></Details>
    </HealthcheckRiskRule>
    <HealthcheckRiskRule>
      <Points>3</Points>
      <Category>Trusts</Category>
      <Model>TrustImpermeability</Model>
      <RiskId>T-SIDFiltering</RiskId>
      <Rationale>SID filtering is not enabled</Rationale>
      <Details><string>partner.example</string></Details>
    </HealthcheckRiskRule>
  </RiskRules>
</HealthcheckData>
"""

SAMPLE_JSON = {
    "EngineVersion": "3.2.0.1",
    "GenerationDate": "2026-08-01T09:14:22.7654321",
    "DomainFQDN": "corp.local",
    "NetBIOSName": "CORP",
    "DomainSid": "S-1-5-21-1111111111-2222222222-3333333333",
    "GlobalScore": 75,
    "MaturityLevel": 2,
    "DomainControllers": [{
        "DCName": "DC01",
        "OperatingSystem": "Windows Server 2012 R2",
        "SupportSMB1": True,
        "RemoteSpoolerDetected": True,
        "PwdLastSet": "2026-07-25T04:00:00",
        "IP": ["10.10.0.11"],
        "FSMO": ["PDC"],
    }],
    "Trusts": [{
        "TrustPartner": "partner.example", "TrustAttributes": 8, "TrustDirection": 3,
        "TrustType": 2, "IsActive": True,
        "SID": "S-1-5-21-9999999999-8888888888-7777777777", "NetBiosName": "PARTNER",
    }],
    "PrivilegedGroups": [{
        "GroupName": "Domain Admins",
        "Sid": "S-1-5-21-1111111111-2222222222-3333333333-512",
        "Members": [{
            "Name": "Administrator",
            "DistinguishedName": "CN=Administrator,CN=Users,DC=corp,DC=local",
            "IsEnabled": True,
            "Sid": "S-1-5-21-1111111111-2222222222-3333333333-500",
        }],
    }],
    "GPPPassword": [{"UserName": "local_admin", "Password": "SuperSecret123!",
                     "GPOName": "Workstation Baseline"}],
    "RiskRules": [{"Points": 50, "Category": "PrivilegedAccounts",
                   "Model": "CredentialTheft", "RiskId": "P-Delegated",
                   "Rationale": "Privileged accounts can be delegated",
                   "Details": ["Administrator"]}],
}

RESULTS: list = []


def check(name: str, condition: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(condition), detail))


def scenario_detection() -> None:
    from upload_router import detect_format

    xml = SAMPLE_XML.encode()
    check("detect .xml as pingcastle",
          detect_format(xml, "ad_hc_corp.local.xml") == "pingcastle")
    check("detect .xml without a filename",
          detect_format(xml, "") == "pingcastle")
    check("detect .json as pingcastle",
          detect_format(json.dumps(SAMPLE_JSON).encode(), "ad_hc_corp.local.json") == "pingcastle")

    nmap = (b'<?xml version="1.0"?><nmaprun scanner="nmap"><host>'
            b'<status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/></host></nmaprun>')
    check("nmap XML still routes to nmap", detect_format(nmap, "scan.xml") == "nmap")
    check("generic JSON still routes to json",
          detect_format(b'{"foo": "bar"}', "data.json") == "json")


def scenario_parse() -> None:
    from pingcastle_parser import parse_bytes

    result = parse_bytes(SAMPLE_XML.encode(), "ad_hc_corp.local.xml")
    check("XML parses without errors", not result.errors, str(result.errors))
    check("domain is uppercased", result.domain == "CORP.LOCAL", result.domain)
    check("scores lifted", result.scores.get("global") == 75, str(result.scores))

    nodes, edges = result.to_flowsint_batch()
    labels = {n["nodeLabel"] for n in nodes}
    types = {n["entity_type"] for n in nodes}
    edge_labels = {e["label"] for e in edges}

    # These exact strings are what make a PingCastle node MERGE into the
    # SharpHound node for the same object instead of creating a second one.
    for expected in ("CORP.LOCAL", "DC01.CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL",
                     "ADMINISTRATOR@CORP.LOCAL", "SVC_BACKUP@CORP.LOCAL",
                     "PARTNER.EXAMPLE", "P-Delegated@CORP.LOCAL"):
        check(f"label {expected!r} present", expected in labels, sorted(labels))

    check("entity types", types == {"Organization", "Device", "Individual", "ADRisk"}, sorted(types))
    check("edge types", edge_labels == {"DC_OF", "MEMBER_OF", "TrustedBy", "HAS_RISK", "AFFECTS"},
          sorted(edge_labels))

    by_label = {n["nodeLabel"]: n["data"] for n in nodes}

    dc = by_label["DC01.CORP.LOCAL"]
    check("DC flagged is_dc", dc.get("is_dc") is True)
    check("DC spooler flagged", dc.get("pingcastle_remote_spooler") is True)
    check("DC pwd_last_set is an epoch int", isinstance(dc.get("pwd_last_set"), int), dc.get("pwd_last_set"))
    check("DC has a device_id (required by the Device type)", bool(dc.get("device_id")))
    check("DC does not overwrite the SharpHound sid", "sid" not in dc)

    svc = by_label["SVC_BACKUP@CORP.LOCAL"]
    check("SPN account marked kerberoastable", svc.get("is_kerberoastable") is True)
    check("privileged member marked is_admin", svc.get("is_admin") is True)

    risk = by_label["P-Delegated@CORP.LOCAL"]
    check("risk points stay numeric", risk.get("points") == 50, risk.get("points"))
    check("risk severity derived", risk.get("severity") == "critical", risk.get("severity"))

    trust_edge = next(e for e in edges if e["label"] == "TrustedBy")
    check("forest-transitive trust decoded",
          trust_edge["data"].get("is_forest_transitive") is True, trust_edge["data"])
    check("missing SID filtering surfaced",
          trust_edge["data"].get("sid_filtering") is False, trust_edge["data"])

    # Data minimisation: recovered credential values are never stored.
    blob = json.dumps([nodes, edges])
    check("GPP password value not stored", "SuperSecret123" not in blob)
    check("GPP account recorded",
          "local_admin (Workstation Baseline)" in
          (by_label["CORP.LOCAL"].get("pingcastle_gpp_password_accounts") or []))


def scenario_json_matches_xml() -> None:
    from pingcastle_parser import parse_bytes

    result = parse_bytes(json.dumps(SAMPLE_JSON).encode(), "ad_hc_corp.local.json")
    check("JSON parses without errors", not result.errors, str(result.errors))
    labels = {e.label for e in result.entities}
    for expected in ("CORP.LOCAL", "DC01.CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL",
                     "ADMINISTRATOR@CORP.LOCAL", "PARTNER.EXAMPLE"):
        check(f"JSON label {expected!r} present", expected in labels, sorted(labels))
    dc = next(e for e in result.entities if e.label == "DC01.CORP.LOCAL")
    check("JSON booleans coerced", dc.properties.get("pingcastle_smb1_enabled") is True)
    check("JSON GPP value not stored",
          "SuperSecret123" not in json.dumps([e.properties for e in result.entities]))


def scenario_registered_schema_split() -> None:
    """
    A DB-registered custom type resolves to a model whose declared properties are
    all Optional[str]; Pydantic will not coerce an int/bool and the serializer
    drops fields that fail validation. So every numeric ADRisk field must stay
    OUT of the registered schema.
    """
    from register_pingcastle_type import ADRISK_SCHEMA
    from pingcastle_parser import parse_bytes

    declared = set(ADRISK_SCHEMA["properties"])
    nodes, _ = parse_bytes(SAMPLE_XML.encode()).to_flowsint_batch()
    risk = next(n["data"] for n in nodes if n["entity_type"] == "ADRisk")

    non_strings = {
        key for key, val in risk.items()
        if key in declared and not isinstance(val, str)
    }
    check("no declared ADRisk property carries a non-string", not non_strings, sorted(non_strings))
    check("points is undeclared (so it keeps its int type)", "points" not in declared)
    check("details is undeclared (so it keeps its list type)", "details" not in declared)


def scenario_unregistered_guard() -> None:
    """Without the ADRisk type registered the report must still ingest."""
    import flowsint_client as fc
    import upload_router

    original = fc.is_type_registered
    fc.is_type_registered = lambda name: False
    try:
        nodes, edges, errors, report = upload_router._parse_pingcastle(
            SAMPLE_XML.encode(), "ad_hc_corp.local.xml", ingest=True
        )
    finally:
        fc.is_type_registered = original

    types = {n["entity_type"] for n in nodes}
    check("guard drops ADRisk nodes", "ADRisk" not in types, sorted(types))
    check("guard keeps the rest of the report", {"Organization", "Device", "Individual"} <= types)
    check("guard drops risk edges",
          not any(e["label"] in ("HAS_RISK", "AFFECTS") for e in edges))
    check("guard reports why", any("register_pingcastle_type" in e for e in errors), errors)
    check("guard still summarises the rules", report["high_risk_rules"] >= 1)


def scenario_bad_inputs() -> None:
    from pingcastle_parser import parse_bytes

    encrypted = (b'<?xml version="1.0"?><EncryptedData '
                 b'xmlns="http://www.w3.org/2001/04/xmlenc#"><CipherData/></EncryptedData>')
    errors = parse_bytes(encrypted, "ad_hc_corp.local.xml").errors
    check("encrypted report rejected", any("encrypted" in e.lower() for e in errors), errors)

    html = b"<html><body><h1>PingCastle report</h1><p>unclosed"
    errors = parse_bytes(html, "ad_hc_corp.local.html").errors
    check("HTML report points at the XML", any("machine-readable" in e for e in errors), errors)

    errors = parse_bytes(b"not a report at all", "junk.txt").errors
    check("junk rejected", bool(errors), errors)

    errors = parse_bytes(b'{"DomainFQDN": ""}', "ad_hc_.json").errors
    check("report with no domain rejected", bool(errors), errors)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verbose", action="store_true", help="print every passing check")
    args = parser.parse_args(argv)

    scenarios = (
        ("format detection", scenario_detection),
        ("report parsing", scenario_parse),
        ("json parity", scenario_json_matches_xml),
        ("ADRisk schema split", scenario_registered_schema_split),
        ("unregistered-type guard", scenario_unregistered_guard),
        ("bad inputs", scenario_bad_inputs),
    )

    for label, fn in scenarios:
        before = len(RESULTS)
        try:
            fn()
        except Exception as exc:                      # noqa: BLE001 - report, don't abort
            check(f"{label} raised", False, repr(exc))
        passed = sum(1 for _, ok, _ in RESULTS[before:] if ok)
        print(f"  {label:<26} {passed}/{len(RESULTS) - before} checks passed")

    failures = [(n, d) for n, ok, d in RESULTS if not ok]
    if args.verbose:
        for name, ok, detail in RESULTS:
            print(f"    {'ok  ' if ok else 'FAIL'} {name}" + (f"  — {detail}" if detail and not ok else ""))

    print()
    if failures:
        print(f"smoke_pingcastle: {len(failures)} FAILED of {len(RESULTS)}")
        for name, detail in failures:
            print(f"  FAIL {name}" + (f"  — {detail}" if detail else ""))
        return 1
    print(f"smoke_pingcastle: all {len(RESULTS)} checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
