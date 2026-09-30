"""
smoke_cloudschism.py — Offline contract tests for the CloudSchism ingest path.

Runs against a synthetic CloudSchism output directory built in-process, so it needs
no live stack, no cloud credentials and no real engagement data.

What it pins down (each of these is a way this ingest path can fail silently):
  * a CloudSchism zip is detected as `cloudschism`, not `zip_unknown` — the old
    behaviour fed the zip's compressed bytes to the text/LLM branch
  * a SharpHound zip still routes to `sharphound`, and a generic zip still to
    `zip_unknown`, so the new sniff cannot shadow the existing ones
  * the DEFAULT `analyst` profile still yields findings and identities, recovered
    from CloudSchism-report.json — that profile omits findings.json entirely
  * no two nodes share a nodeLabel: Flowsint MERGEs on it, so a collision means
    the second node overwrites the first and the reported count is a lie
  * every built-in node carries its REQUIRED primary field (a missing one makes
    GET /graph return 500 for the whole sketch)
  * only registered or built-in entity types are emitted, for the same reason
  * the CloudFinding / CloudAttackPath schema splits keep numbers and booleans
    undeclared (a declared custom-type property is rebuilt as Optional[str], and an
    int or bool would be silently dropped)
  * the unregistered-type guards degrade to "no nodes of that type", not
    "no ingest", and the two types are gated independently
  * an attack path scoped only to an S3 ARN still resolves its account — that ARN
    shape (arn:aws:s3:::bucket) has empty account and region fields
  * a path citing a finding this export never produced makes no dangling edge
  * an html/ subtree, and the per-path attack-paths/ export dir, are ignored while
    the top-level attack-paths.json is still read

Usage:
    python3 scripts/smoke_cloudschism.py           # all scenarios
    python3 scripts/smoke_cloudschism.py --verbose
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ACCOUNT = "123456789012"
BUCKET_ARN = "arn:aws:s3:::example-public-backups"
INSTANCE_ARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123"

PUBLIC_ENDPOINTS = [
    {"value": "example-public-backups.s3.amazonaws.com", "type": "dns",
     "url": "https://example-public-backups.s3.amazonaws.com", "provider": "aws",
     "account_id": ACCOUNT, "region": "us-east-1",
     "source_resource_id": BUCKET_ARN, "source_resource_type": "AWS::S3::Bucket",
     "endpoint_role": "data_endpoint", "authentication_state": "unauthenticated",
     "reachability_state": "configuration_confirmed_anonymous", "confidence": "high",
     "publicly_accessible_inferred": True},
    {"value": "203.0.113.48", "type": "ip", "provider": "aws", "account_id": ACCOUNT,
     "region": "us-east-1", "source_resource_id": INSTANCE_ARN,
     "source_resource_type": "AWS::EC2::Instance", "endpoint_role": "network_address",
     "authentication_state": "authentication_required"},
]

EXTERNAL_EXPOSURES = [
    {"id": "exp-1", "exposure_type": "vm_public_ip", "resource_id": INSTANCE_ARN,
     "resource_type": "AWS::EC2::Instance", "provider": "aws", "account_id": ACCOUNT,
     "region": "us-east-1", "public_endpoints": ["203.0.113.48"],
     "open_management_ports": [22, 3389], "ports": [443], "protocols": ["tcp"],
     "authentication_state": "authentication_required",
     "reachability_state": "configuration_confirmed_routable",
     "reasoning": "Public IP with 0.0.0.0/0 on 22 and 3389."},
]

FINDINGS = [
    {"id": "s3_bucket_public_read", "control_id": "s3_bucket_public_read",
     "finding_instance_id": "aws:123456789012:s3_bucket_public_read:example-public-backups",
     "severity": "critical", "title": "S3 bucket allows anonymous read",
     "provider": "aws", "service": "s3", "provider_scope": ACCOUNT,
     "region": "us-east-1", "resource_id": BUCKET_ARN,
     "finding_class": "exploitable", "exploitability": "direct",
     "attack_path_relevance": True, "evidence_state": "data_access_confirmed",
     "confidence": "high", "flagged_reason": "Bucket policy grants s3:GetObject to '*'.",
     "recommendation": "Remove the wildcard principal.", "suppressed": False,
     "related_techniques": ["T1530"]},
    {"id": "ec2_management_port_open", "control_id": "ec2_management_port_open",
     "finding_instance_id": "aws:123456789012:ec2_management_port_open:i-0abc123",
     "severity": "high", "title": "Management port open to the internet",
     "provider": "aws", "service": "ec2", "provider_scope": ACCOUNT,
     "resource_id": INSTANCE_ARN, "finding_class": "high_risk_configuration",
     "exploitability": "chainable", "confidence": "high"},
]

ATTACK_GRAPH = {
    "nodes": [
        {"id": "resource::" + BUCKET_ARN, "kind": "resource",
         "label": "example-public-backups", "provider": "aws", "resource_id": BUCKET_ARN,
         "metadata": {"type": "AWS::S3::Bucket", "account_id": ACCOUNT}},
        {"id": "endpoint::example-public-backups.s3.amazonaws.com", "kind": "public_endpoint",
         "label": "example-public-backups.s3.amazonaws.com", "provider": "aws",
         "metadata": {"account_id": ACCOUNT}},
        {"id": "identity::AIDAEXAMPLE", "kind": "identity",
         "label": "jane.doe@example.com", "provider": "aws",
         "resource_id": "AIDAEXAMPLE", "metadata": {"type": "user"}},
        {"id": "account::" + ACCOUNT, "kind": "cloud_account", "label": "example-prod",
         "provider": "aws", "resource_id": ACCOUNT},
        # Same finding as findings.json[0], without the instance id — must dedupe.
        {"id": "finding::s3_bucket_public_read", "kind": "finding",
         "label": "S3 bucket allows anonymous read", "provider": "aws",
         "resource_id": "s3_bucket_public_read",
         "metadata": {"severity": "critical", "control_id": "s3_bucket_public_read",
                      "provider_scope": ACCOUNT}},
        # Same path as attack-paths.json[0] — must dedupe, not duplicate.
        {"id": "path::ap-s3-cred-exfil", "kind": "attack_path",
         "label": "Anonymous S3 read leads to credential exfil", "provider": "aws",
         "resource_id": "ap-s3-cred-exfil",
         "metadata": {"severity": "critical", "affected_resource_ids": [BUCKET_ARN]}},
        # Kinds SPOTTER models no entity for — must be skipped, not invented.
        {"id": "region::us-east-1", "kind": "region", "label": "us-east-1"},
        {"id": "primitive::p1", "kind": "attack_primitive", "label": "AssumeRole"},
    ],
    "edges": [
        {"source": "endpoint::example-public-backups.s3.amazonaws.com",
         "target": "resource::" + BUCKET_ARN,
         "relationship_type": "endpoint_exposes_resource", "provider": "aws"},
        {"source": "finding::s3_bucket_public_read", "target": "resource::" + BUCKET_ARN,
         "relationship_type": "finding_affects_resource", "provider": "aws"},
        {"source": "identity::AIDAEXAMPLE", "target": "resource::" + BUCKET_ARN,
         "relationship_type": "has_permission", "provider": "aws"},
        {"source": "path::ap-s3-cred-exfil", "target": "resource::" + BUCKET_ARN,
         "relationship_type": "attack_path_affects_resource", "provider": "aws"},
        {"source": "path::ap-s3-cred-exfil", "target": "finding::s3_bucket_public_read",
         "relationship_type": "attack_path_uses_finding", "provider": "aws"},
        {"source": "region::us-east-1", "target": "resource::" + BUCKET_ARN,
         "relationship_type": "contains", "provider": "aws"},
    ],
}

# attack-paths.json is written through attack_path_export_record(), which adds
# path_type / trust_state / entry_points on top of the raw AttackPathRecord.
ATTACK_PATHS = [
    {"id": "ap-s3-cred-exfil", "title": "Anonymous S3 read leads to credential exfil",
     "provider": "aws", "severity": "critical", "rule_id": "rule-s3-anon-cred",
     "path_type": "deterministic_rule_backed", "rule_confidence": "high",
     # trust_state values come from attack_path_trust_state(); "confirmed" and
     # "contradicted" are two of the real ones.
     "trust_state": "confirmed", "evidence_state": "data_access_confirmed",
     "evidence_confidence": "high", "attack_path_completeness": "confirmed",
     "confidence_score": 88, "severity_ceiling_applied": False,
     "tactic_chain": ["Initial Access", "Collection"],
     "entry_points": ["example-public-backups.s3.amazonaws.com"],
     "affected_resource_ids": [BUCKET_ARN],
     # Cites both a finding that exists and one that does not — the second must
     # not become a dangling edge.
     "finding_ids": ["s3_bucket_public_read", "iam_role_never_collected"],
     "public_endpoints": ["example-public-backups.s3.amazonaws.com"],
     "contradictions": [], "missing_prerequisites": [],
     "reasoning": "The bucket is anonymously readable and holds CI credentials.",
     "remediation": "Block public access and rotate the exposed keys."},
    {"id": "ap-ec2-mgmt", "title": "Exposed management port on a public instance",
     "provider": "aws", "severity": "high", "rule_id": "",
     "path_type": "manual_review_required",
     "attack_path_completeness": "potential", "confidence_score": 41,
     "affected_resource_ids": [INSTANCE_ARN],
     "finding_ids": ["ec2_management_port_open"],
     "public_endpoints": ["203.0.113.48"],
     "contradictions": ["Security group may be restricted by a NACL"],
     "reasoning": "Instance exposes 22/3389 to the internet.",
     "remediation": "Restrict the security group to known source ranges."},
]

IDENTITIES = [
    {"id": "u-1", "displayName": "Jane Doe",
     "userPrincipalName": "jane.doe@example.com",
     "mail": "jane.doe@example.com",
     "@odata.type": "#microsoft.graph.user", "accountEnabled": True},
    {"id": "u-2", "displayName": "John Smith",
     "userPrincipalName": "john.s@example.com", "mail": "john.s@example.com",
     "@odata.type": "#microsoft.graph.user", "accountEnabled": True},
    {"id": "sp-1", "displayName": "terraform-deployer", "appId": "app-123",
     "@odata.type": "#microsoft.graph.servicePrincipal"},
]

REPORT = {
    "metadata": {"provider": "aws", "scan_id": "scan-abc", "tool_version": "2.6.0",
                 "account_type": "aws"},
    "public_endpoints": PUBLIC_ENDPOINTS,
    "external_exposures": EXTERNAL_EXPOSURES,
    "identities": IDENTITIES,
    "findings": FINDINGS,
    "attack_paths": ATTACK_PATHS,
    "entra": {"users": IDENTITIES[:2], "service_principals": IDENTITIES[2:]},
    "resource_type_index": {"AWS::S3::Bucket": 1},
    "collector_status": [],
}

PROVENANCE = {
    "schema_version": "1.0", "tool": "CloudSchism", "tool_version": "2.6.0",
    "generated_at": "2026-08-11T09:30:00Z",
    "report": {"scan_id": "scan-abc", "provider": "aws", "output_profile": "analyst",
               "redaction_mode": "none", "completed_at": "2026-08-11T09:29:00Z"},
}


def build_zip(profile: str = "integration") -> bytes:
    """A CloudSchism output directory, zipped the way an analyst would zip it."""
    members = {
        "public-endpoints.json": PUBLIC_ENDPOINTS,
        "external-exposures.json": EXTERNAL_EXPOSURES,
        "attack-graph.json": ATTACK_GRAPH,
        "provider-artifacts.json": {"schema_version": "1.0", "artifacts": []},
        "generation-provenance.json": PROVENANCE,
        "CloudSchism-report.json": REPORT,
        # Per-path exports live under attack-paths/ — that directory must be
        # skipped while the top-level attack-paths.json is still read.
        "attack-paths/ap-s3-cred-exfil.json": {"id": "decoy-per-path-export"},
        # Noise: a decoy findings.json nested under html/ must never shadow the
        # top-level export, and the html tree must not be walked for content.
        "html/index.html": None,
        "html/risk/exports/findings.json": [{"decoy": True}],
    }
    if profile != "analyst":
        # The default `analyst` profile deliberately omits both of these.
        members["findings.json"] = FINDINGS
        members["attack-paths.json"] = ATTACK_PATHS
        members["aws-inventory.json"] = {"aws_iam": {"users": [
            {"UserName": "svc-backup", "Arn": "arn:aws:iam::123456789012:user/svc-backup"},
        ]}}

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in members.items():
            path = f"example-aws-scan-out/{name}"
            if body is None:
                zf.writestr(path, "<html><body>report</body></html>")
            else:
                zf.writestr(path, json.dumps(body))
    return buf.getvalue()


RESULTS: list = []


def check(name: str, condition: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(condition), detail))


# ── Scenarios ─────────────────────────────────────────────────────────────────

def scenario_detection() -> None:
    from upload_router import detect_format

    check("CloudSchism zip detected", detect_format(build_zip(), "scan-out.zip") == "cloudschism",
          detect_format(build_zip(), "scan-out.zip"))
    check("analyst-profile zip detected",
          detect_format(build_zip("analyst"), "out.zip") == "cloudschism")

    # A SharpHound zip must still win — both are zips, and SharpHound is checked first.
    sh = io.BytesIO()
    with zipfile.ZipFile(sh, "w") as zf:
        zf.writestr("20260811_users.json", json.dumps(
            {"data": [{"ObjectIdentifier": "S-1-5-21-1", "Properties": {"name": "A@CORP"}}],
             "meta": {"type": "users"}}))
        zf.writestr("20260811_computers.json", json.dumps({"data": [], "meta": {}}))
    check("SharpHound zip still routes to sharphound",
          detect_format(sh.getvalue(), "bh.zip") == "sharphound",
          detect_format(sh.getvalue(), "bh.zip"))

    # An unrelated zip must stay zip_unknown, not be claimed by the new sniff.
    other = io.BytesIO()
    with zipfile.ZipFile(other, "w") as zf:
        zf.writestr("notes.txt", "hello")
    check("unrelated zip stays zip_unknown",
          detect_format(other.getvalue(), "x.zip") == "zip_unknown")

    # Single exports.
    check("CloudSchism-report.json on its own",
          detect_format(json.dumps(REPORT).encode(), "CloudSchism-report.json") == "cloudschism")
    check("bare findings.json on its own",
          detect_format(json.dumps(FINDINGS).encode(), "findings.json") == "cloudschism")
    check("another tool's findings.json is NOT claimed",
          detect_format(json.dumps([{"id": "x", "name": "y"}]).encode(),
                        "findings.json") == "json")
    check("generic JSON still routes to json",
          detect_format(b'{"foo": "bar"}', "data.json") == "json")


def scenario_analyst_profile() -> None:
    """The default profile writes no findings.json — findings must still land."""
    from cloudschism_parser import parse_zip_bytes

    res = parse_zip_bytes(build_zip("analyst"))
    types = {}
    for ent in res.entities:
        types[ent.entity_type] = types.get(ent.entity_type, 0) + 1

    check("analyst profile falls back to the report",
          "cloudschism-report.json" in res.sources, str(res.sources))
    check("findings recovered under analyst profile",
          types.get("CloudFinding", 0) == 2, str(types))
    check("identities recovered under analyst profile",
          types.get("Individual", 0) == 2, str(types))
    check("service principal is NOT an Individual",
          not any(e.entity_type == "Individual" and "terraform" in e.label.lower()
                  for e in res.entities))
    check("scan provenance read from generation-provenance.json",
          res.scan.get("output_profile") == "analyst", str(res.scan))


def scenario_graph_shape() -> None:
    from cloudschism_parser import parse_zip_bytes

    res = parse_zip_bytes(build_zip())
    nodes, edges = res.to_flowsint_batch()
    labels = [n["nodeLabel"] for n in nodes]

    check("no parse errors", not res.errors, str(res.errors))
    check("nodes produced", len(nodes) >= 12, str(len(nodes)))

    # THE invariant: Flowsint MERGEs on nodeLabel, so duplicates silently collapse.
    dupes = {lab for lab in labels if labels.count(lab) > 1}
    check("no duplicate nodeLabels", not dupes, str(dupes))

    # The same finding arrives from findings.json and attack-graph.json.
    findings = [n for n in nodes if n["entity_type"] == "CloudFinding"]
    check("duplicate finding deduped across artifacts", len(findings) == 2,
          str([n["nodeLabel"] for n in findings]))

    # Ports on one host must not collapse into a single shared Service node.
    services = [n for n in nodes if n["entity_type"] == "Service"]
    check("each exposed port is its own Service", len(services) == 3,
          str([n["nodeLabel"] for n in services]))
    check("Service labels are host-qualified",
          all("@" in n["nodeLabel"] for n in services),
          str([n["nodeLabel"] for n in services]))

    # Bucket labels match WF13's `<service>:<bucket>` so the two sources converge.
    check("bucket uses WF13's label shape",
          any(n["nodeLabel"] == "s3:example-public-backups" for n in nodes),
          str(labels))

    check("html/ decoy findings.json ignored",
          not any(n["entity_type"] == "CloudFinding" and "decoy" in json.dumps(n["data"])
                  for n in nodes))
    check("unmodelled graph kinds skipped",
          not any("us-east-1" == n["nodeLabel"] for n in nodes), str(labels))

    edge_labels = {e["label"] for e in edges}
    check("reuses the existing edge vocabulary",
          {"EXPOSES", "AFFECTS", "HAS_CLOUD_ASSET", "EXPOSES_SERVICE"} <= edge_labels,
          str(sorted(edge_labels)))
    check("identity permission edge mapped",
          "HAS_PERMISSION" in edge_labels, str(sorted(edge_labels)))

    ids = {n["node_id"] for n in nodes}
    check("no edge references a dropped node",
          all(e["from_id"] in ids and e["to_id"] in ids for e in edges))


def scenario_attack_paths() -> None:
    from cloudschism_parser import parse_zip_bytes

    res = parse_zip_bytes(build_zip())
    nodes, edges = res.to_flowsint_batch()
    paths = [n for n in nodes if n["entity_type"] == "CloudAttackPath"]
    ids = {n["node_id"] for n in nodes}

    check("attack paths imported", len(paths) == 2,
          str([n["nodeLabel"] for n in paths]))
    check("path deduped against the attack graph's copy",
          len({n["nodeLabel"] for n in paths}) == 2,
          str([n["nodeLabel"] for n in paths]))
    check("path label is account-scoped",
          all("@" in n["nodeLabel"] for n in paths),
          str([n["nodeLabel"] for n in paths]))

    by_label = {n["nodeLabel"]: n for n in paths}
    exfil = by_label.get(f"ap-s3-cred-exfil@{ACCOUNT}")
    check("account parsed out of the affected resource ARN", exfil is not None,
          str(sorted(by_label)))
    if exfil:
        check("confidence_score stays an int",
              exfil["data"].get("confidence_score") == 88,
              repr(exfil["data"].get("confidence_score")))
        check("severity_ceiling_applied stays a bool",
              exfil["data"].get("severity_ceiling_applied") is False)
        check("richer export record wins over the graph's thin copy",
              exfil["data"].get("rule_id") == "rule-s3-anon-cred",
              repr(exfil["data"].get("rule_id")))
        check("contradiction flag derived",
              by_label[f"ap-ec2-mgmt@{ACCOUNT}"]["data"].get("has_contradictions") is True)

    labels = {e["label"] for e in edges}
    check("path links to the findings it chains", "USES_FINDING" in labels, str(sorted(labels)))
    check("path links to its entry point", "ENTRY_POINT" in labels, str(sorted(labels)))

    # The fixture cites a finding CloudSchism never exported. It must not become
    # an edge to a node that does not exist.
    uses = [e for e in edges if e["label"] == "USES_FINDING"]
    check("cited-but-absent finding produces no dangling edge",
          all(e["to_id"] in ids for e in uses), str([e["to_id"] for e in uses]))
    check("only the real finding is linked", len(uses) == 2, str(len(uses)))

    check("per-path attack-paths/ export dir ignored",
          not any("decoy-per-path-export" in json.dumps(n["data"]) for n in nodes))

    # Registration gating is independent: no paths, but findings survive.
    res2 = parse_zip_bytes(build_zip(), allow_attack_path_nodes=False)
    nodes2, edges2 = res2.to_flowsint_batch()
    ids2 = {n["node_id"] for n in nodes2}
    check("attack paths dropped when unregistered",
          not any(n["entity_type"] == "CloudAttackPath" for n in nodes2))
    check("findings survive an unregistered path type",
          any(n["entity_type"] == "CloudFinding" for n in nodes2))
    check("no dangling edge after dropping paths",
          all(e["from_id"] in ids2 and e["to_id"] in ids2 for e in edges2))


def scenario_type_safety() -> None:
    """
    Every emitted type must resolve, and every built-in must carry its required
    primary field — either failure 500s GET /graph for the ENTIRE sketch.
    """
    from cloudschism_parser import parse_zip_bytes
    from upload_router import ENTITY_PRIMARY_FIELD, CUSTOM_ENTITY_FIELD

    # Custom types confirmed published in this install, plus the one this path adds.
    registered = {"C2Session", "ADRisk", "GPO", "EnterpriseCA", "CertTemplate",
                  "Subdomain", "Service", "CloudAsset", "WebAsset", "ADPermission",
                  "FileShare", "SocialProfile", "CobaltBeacon", "FlareBreach",
                  "DomainBreach", "CloudFinding", "CloudAttackPath"}
    builtin = set(ENTITY_PRIMARY_FIELD)

    nodes, _edges = parse_zip_bytes(build_zip()).to_flowsint_batch()
    unknown = {n["entity_type"] for n in nodes} - builtin - registered - set(CUSTOM_ENTITY_FIELD)
    check("only resolvable entity types emitted", not unknown, str(unknown))

    missing = []
    for node in nodes:
        required = ENTITY_PRIMARY_FIELD.get(node["entity_type"])
        if required and not node["data"].get(required):
            missing.append((node["entity_type"], node["nodeLabel"], required))
    check("built-in nodes carry their required primary field", not missing, str(missing))

    check("nodeLabel mirrored into data (MERGE key)",
          all(n["data"].get("nodeLabel") for n in nodes))
    check("node_id equals id (edge resolution)",
          all(n["node_id"] == n["id"] for n in nodes))


def scenario_registered_schema_split() -> None:
    """Declared custom-type properties are rebuilt as Optional[str]; a bool would vanish."""
    from register_cloudschism_type import CLOUDATTACKPATH_SCHEMA, CLOUDFINDING_SCHEMA
    from cloudschism_parser import parse_zip_bytes

    declared = set(CLOUDFINDING_SCHEMA["properties"])
    path_declared = set(CLOUDATTACKPATH_SCHEMA["properties"])
    for label, schema in (("CloudFinding", CLOUDFINDING_SCHEMA),
                          ("CloudAttackPath", CLOUDATTACKPATH_SCHEMA)):
        check(f"every declared {label} property is a string",
              all(spec.get("type") == "string" for spec in schema["properties"].values()))
    for field in ("attack_path_relevance", "suppressed", "related_techniques"):
        check(f"{field} stays undeclared", field not in declared)
    for field in ("confidence_score", "severity_ceiling_applied", "has_contradictions",
                  "affected_resource_count", "finding_count"):
        check(f"{field} stays undeclared on CloudAttackPath", field not in path_declared)

    # Loaded by path, NOT by `from types.cloud_finding import …`: stdlib `types` is
    # already in sys.modules, so that import can only ever raise — which would make
    # this parity check quietly pass without comparing anything.
    import importlib.util
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for filename, cls_name, schema in (
        ("cloud_finding.py", "CloudFinding", CLOUDFINDING_SCHEMA),
        ("cloud_attack_path.py", "CloudAttackPath", CLOUDATTACKPATH_SCHEMA),
    ):
        type_file = os.path.join(root, "flowsint-custom", "types", filename)
        spec = importlib.util.spec_from_file_location(f"spotter_{cls_name}", type_file)
        check(f"flowsint-custom/{filename} exists", spec is not None, type_file)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            check(f"{cls_name} registration schema matches the type definition",
                  getattr(module, cls_name).REGISTERED_SCHEMA == schema,
                  f"flowsint-custom/types/{filename} and "
                  f"scripts/register_cloudschism_type.py have drifted")

    nodes, _ = parse_zip_bytes(build_zip()).to_flowsint_batch()
    finding = next((n for n in nodes if n["entity_type"] == "CloudFinding"
                    and n["data"].get("attack_path_relevance")), None)
    check("boolean reaches the payload as a real bool",
          finding is not None and finding["data"]["attack_path_relevance"] is True)

    # The same assertion PingCastle's smoke test makes: a declared property that
    # arrives as a non-string is dropped by the serializer without an error.
    non_strings = set()
    for node in nodes:
        if node["entity_type"] != "CloudFinding":
            continue
        non_strings |= {k for k, v in node["data"].items()
                        if k in declared and not isinstance(v, str)}
    check("no declared CloudFinding property carries a non-string",
          not non_strings, str(sorted(non_strings)))


def scenario_unregistered_guard() -> None:
    """An unregistered CloudFinding must cost the findings, not the whole ingest."""
    from cloudschism_parser import parse_zip_bytes

    res = parse_zip_bytes(build_zip(), allow_finding_nodes=False)
    nodes, edges = res.to_flowsint_batch()
    check("no CloudFinding nodes when unregistered",
          not any(n["entity_type"] == "CloudFinding" for n in nodes))
    check("everything else still ingests", len(nodes) >= 10, str(len(nodes)))
    check("no dangling edge to a dropped finding",
          all(e["from_id"] in {n["node_id"] for n in nodes}
              and e["to_id"] in {n["node_id"] for n in nodes} for e in edges))


def scenario_bad_inputs() -> None:
    from cloudschism_parser import parse_bytes, parse_zip_bytes

    res = parse_zip_bytes(b"PK\x03\x04not-a-zip")
    check("truncated zip fails loudly", bool(res.errors) and not res.entities,
          str(res.errors))

    empty = io.BytesIO()
    with zipfile.ZipFile(empty, "w") as zf:
        zf.writestr("readme.txt", "nothing here")
    res = parse_zip_bytes(empty.getvalue())
    check("zip with no CloudSchism artifacts explains itself",
          any("No readable CloudSchism artifacts" in e for e in res.errors),
          str(res.errors))

    res = parse_bytes(b'{"metadata": {}}', "CloudSchism-report.json")
    check("empty report does not crash", isinstance(res.entities, list))


def scenario_route_bytes() -> None:
    """The full upload_router path, without ingesting."""
    from upload_router import route_bytes, hint_format

    res = route_bytes(build_zip(), filename="example-aws-scan-out.zip")
    check("route_bytes reports the cloudschism format", res["format"] == "cloudschism",
          res["format"])
    check("route_bytes returns nodes", res["nodes_count"] > 10, str(res["nodes_count"]))
    check("report summary surfaced", isinstance(res.get("report"), dict),
          str(type(res.get("report"))))
    check("summary names the artifacts read",
          "public-endpoints.json" in (res.get("report") or {}).get("sources", []),
          str((res.get("report") or {}).get("sources")))

    # A context hint may re-route a weak verdict, but only with corroboration —
    # and "bloodhound" over a CloudSchism zip must NOT reach the SharpHound parser.
    check("bloodhound context cannot hijack a CloudSchism zip",
          hint_format("bloodhound collection", build_zip(), "zip_unknown") != "sharphound",
          hint_format("bloodhound collection", build_zip(), "zip_unknown"))
    check("cloud context corroborates on a real CloudSchism zip",
          hint_format("cloudschism aws scan", build_zip(), "zip_unknown") == "cloudschism")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verbose", action="store_true", help="print every passing check")
    args = parser.parse_args(argv)

    scenarios = (
        ("format detection", scenario_detection),
        ("analyst profile fallback", scenario_analyst_profile),
        ("graph shape", scenario_graph_shape),
        ("attack paths", scenario_attack_paths),
        ("type safety", scenario_type_safety),
        ("CloudFinding schema split", scenario_registered_schema_split),
        ("unregistered-type guard", scenario_unregistered_guard),
        ("bad inputs", scenario_bad_inputs),
        ("upload_router route", scenario_route_bytes),
    )

    for label, fn in scenarios:
        before = len(RESULTS)
        try:
            fn()
        except Exception as exc:                      # noqa: BLE001 - report, don't abort
            check(f"{label} raised", False, repr(exc))
        passed = sum(1 for _, ok, _ in RESULTS[before:] if ok)
        print(f"  {label:<28} {passed}/{len(RESULTS) - before} checks passed")

    failures = [(n, d) for n, ok, d in RESULTS if not ok]
    if args.verbose:
        for name, ok, detail in RESULTS:
            print(f"    {'ok  ' if ok else 'FAIL'} {name}" + (f"  — {detail}" if detail and not ok else ""))

    print()
    if failures:
        print(f"smoke_cloudschism: {len(failures)} FAILED of {len(RESULTS)}")
        for name, detail in failures:
            print(f"  FAIL {name}" + (f"  — {detail}" if detail else ""))
        return 1
    print(f"smoke_cloudschism: all {len(RESULTS)} checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
