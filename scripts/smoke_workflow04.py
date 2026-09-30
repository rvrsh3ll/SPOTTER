#!/usr/bin/env python3
"""
Smoke scenarios for workflow 04 (Attack Path Analyzer), specifically the exploit
weighting added on 2026-08-18.

Runs WF04's embedded `Score Attack Paths` node on the host, skipping the n8n
import-and-restart cycle (same approach as smoke_workflow12.py / _23.py).

WHY THIS EXISTS
---------------
Scoring used to be 100% AD ACEs, so a host running software with working public
exploit code ranked identically to one without. The join now runs through an
`exploit_index` built from the Technology/Service nodes WF14 enriches, and every
part of it fails quietly if it breaks: a wrong property name, a boolean arriving
as the string 'False', or an id namespace mismatch all yield "no bonus", which
looks exactly like "no exploits exist".

Modes:

  (default)   Synthetic fixtures. No stack needed. Each pins one property of the
              weighting that is silent when lost:

                fixture             what it pins down
                ------------------  --------------------------------------------
                clean_path          the feature is inert without exploit data
                exploitable_target  an exploitable hop outscores an equal one
                max_not_sum         two exploitable products != double the bonus
                keyword_discount    an NVD name match is worth half a CPE match
                service_chain       host -> Service -> Technology, two hops
                bonus_cap           trust+critical+internet is capped, not 10
                own_asset_only      no ACE path at all still reaches a dossier
                own_asset_ignored   a bonus that did not move the score is not
                                    claimed as part of it
                string_false        exploit_available='False' grants nothing
                manages_excluded    ownership edges never carry exploit facts
                knob_zero           EXPLOIT_PATH_MAX_BONUS=0 restores AD-only

  --live      Reads the real exploit layer for the resolved campaign sketch with
              the same two calls the Fetch node makes, and scores a synthetic AD
              slice against it. This is what proves the elementId namespaces of
              get_nodes_by_type / get_edges_by_type / get_graph agree -- an
              assumption no fixture can test. It never calls get_graph(), which
              takes 117s and truncates at 100k nodes.

Neither mode covers the deployed artifact. For that: seed a throwaway sketch,
POST /webhook/attack-path-analyze with its sketch_id, read `attack_score` back
out of Neo4j, then fc.delete_sketch(). Never aim it at a live campaign.

Usage:
    python3 scripts/smoke_workflow04.py
    python3 scripts/smoke_workflow04.py --only keyword_discount
    NEO4J_HTTP_URL=http://127.0.0.1:7474 python3 scripts/smoke_workflow04.py --live
    NEO4J_HTTP_URL=http://127.0.0.1:7474 python3 scripts/smoke_workflow04.py --live --sketch <id>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / "n8n-workflows" / "04-attack-path-analyzer.json"
CODE_NODE = "Score Attack Paths"

# The code node does sys.path.insert(0, '/data/scripts'), which does not exist on
# the host, so the real scripts/ directory has to be ahead of it for
# `import spotter_settings` to resolve.
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def load_code_node(name: str, path: Path = WORKFLOW_PATH) -> str:
    obj = json.loads(path.read_text())
    for node in obj.get("nodes", []):
        if node.get("name") == name:
            return node["parameters"]["pythonCode"]
    raise SystemExit(f"code node {name!r} not found in {path}")


def run_code_node(code: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute the node body the way n8n does: `_items` in scope, top-level
    `return`. exec() rejects a bare return, so wrap it in a function first --
    which also makes this a real syntax check, unlike ast.parse()."""
    wrapper = "def __node(_items):\n" + "".join(
        "    " + line + "\n" for line in code.splitlines()
    )
    ns: Dict[str, Any] = {}
    exec(compile(wrapper, "<wf04>", "exec"), ns)
    return ns["__node"]([{"json": payload}])


def scored_by_label(code: str, payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out = run_code_node(code, payload)
    return {r["json"]["ind_label"]: r["json"] for r in out if r["json"].get("ind_id")}


# ── Synthetic graph ──────────────────────────────────────────────────────────

def _n(nid: str, ntype: str, label: str, **props: Any) -> Dict[str, Any]:
    return {"id": nid, "nodeType": ntype, "nodeLabel": label, "nodeProperties": props}


def _e(src: str, tgt: str, label: str) -> Dict[str, Any]:
    return {"id": f"e:{src}->{tgt}:{label}", "label": label, "source": src, "target": tgt}


def _cves(*specs: Any) -> str:
    """(cve_id, base_score, exploit_available) tuples -> the JSON string
    tech_enricher writes. Stored as a string on purpose: that is what the reader
    has to cope with."""
    return json.dumps([
        {"cve_id": c, "severity": "CRITICAL", "base_score": b,
         "exploit_available": e, "poc_count": 2 if e else 0, "match": "keyword"}
        for c, b, e in specs
    ])


def _pocs(trust: str) -> str:
    return json.dumps([{"full_name": "owner/poc", "trust": trust, "trust_score": 11.0,
                        "stars": 40, "unvetted": True}])


# nginx: cpe-matched, high trust, one CVSS 9.8 -> (6 + 2) * 1.0 = 8
TECH_CPE = _n("t-cpe", "technology", "nginx 1.18", name="nginx", version="1.18",
              exploit_available=True, poc_count=9, cve_count=4,
              cve_match_basis="cpe", source="nmap",
              cves=_cves(("CVE-2024-0001", 9.8, True)), top_pocs=_pocs("high"))
# Same trust and CVSS, keyword-matched -> halved to 4. This is the Ivanti-on-Apache
# case: the CVE text merely names the product.
TECH_KEYWORD = _n("t-kw", "technology", "Apache httpd", name="Apache httpd",
                  exploit_available=True, poc_count=3, cve_count=10,
                  cve_match_basis="keyword", source="process_list",
                  cves=_cves(("CVE-2023-38035", 9.8, True)), top_pocs=_pocs("high"))
# medium trust, cpe, no critical CVE, not internet-facing -> 4
TECH_OWN = _n("t-own", "technology", "KeePass", name="KeePass Password Manager",
              exploit_available=True, poc_count=1, cve_count=2,
              cve_match_basis="cpe", source="process_list",
              cves=_cves(("CVE-2023-32784", 7.5, True)), top_pocs=_pocs("medium"))
# The coercion trap: a declared boolean handed back as the STRING 'False', which
# is truthy in Python and JS alike.
TECH_STRFALSE = _n("t-str", "technology", "Notepad++", name="Notepad++",
                   exploit_available="False", poc_count=0, cve_count=1,
                   cve_match_basis="cpe", source="process_list",
                   cves=_cves(("CVE-2023-40031", 7.8, False)), top_pocs="[]")
# shodan basis, high trust, critical, internet-facing -> 6+2+2 = 10, capped to 8
TECH_DEEP = _n("t-deep", "technology", "Tomcat 9", name="Apache Tomcat", version="9",
               exploit_available=True, poc_count=6, cve_count=3,
               cve_match_basis="shodan", source="domain-recon",
               cves=_cves(("CVE-2020-1938", 9.8, True)), top_pocs=_pocs("high"))
SERVICE_BARE = _n("s-bare", "Service", "10.0.0.9 (1 ports)", product="", source="nmap")
WEB_ASSET = _n("w-apex", "WebAsset", "example.test (web)", url="https://example.test")

TECH_NODES = [TECH_CPE, TECH_KEYWORD, TECH_OWN, TECH_STRFALSE, TECH_DEEP,
              SERVICE_BARE, WEB_ASSET]

# ── Cloud exposure layer ─────────────────────────────────────────────────────
# Scored at the ASSET. With MANAGES excluded from scoring and HAS_CLOUD_ASSET not
# a carrier edge, a CloudAsset has no path to an Individual at all, so the
# load-bearing fixture below is the one proving no attack_score moves.
#
# Expected bonuses use BANKER'S ROUNDING, the same as _exploit_bonus: int(round())
# takes 4.5 to 4 and 2.5 to 2, so assert the actual values, not the intuitive ones.
_CATS_PII = json.dumps(["pii", "backup"])

# listable + pii(3) + 12048 objs(2) = 9, dns tier 1.0 -> 9, capped to 8
CLOUD_DNS = _n("c-dns", "CloudAsset", "s3:example-payroll", endpoint="example-payroll.s3.amazonaws.com",
               provider="aws", service="s3", bucket="example-payroll", listable=True,
               object_count=12048, exposure_score=64, sensitive_categories=_CATS_PII,
               hostname="files.example.test", source="domain-recon")
# identical exposure facts, no hostname, third-party index -> 9 * 0.5 = 4.5 -> 4
CLOUD_IDX = _n("c-idx", "CloudAsset", "s3:example-archive", endpoint="example-archive.s3.amazonaws.com",
               provider="aws", service="s3", bucket="example-archive", listable=True,
               object_count=12048, exposure_score=64, sensitive_categories=_CATS_PII,
               discovery_method="grayhatwarfare", source="domain-recon")
# listable only, 3 objects, name-guess -> 4 * 0.75 = 3.0 -> 3
CLOUD_GUESS = _n("c-guess", "CloudAsset", "s3:example-tmp", endpoint="example-tmp.s3.amazonaws.com",
                 provider="aws", service="s3", bucket="example-tmp", listable=True,
                 object_count=3, exposure_score=30, sensitive_categories="[]",
                 discovery_method="name-guess", source="domain-recon")
# listable + 400k objects(2), no categories, index tier -> 6 * 0.5 = 3.0 -> 3
CLOUD_VOL = _n("c-vol", "CloudAsset", "s3:example-logs", endpoint="example-logs.s3.amazonaws.com",
               provider="aws", service="s3", bucket="example-logs", listable=True,
               object_count=400000, exposure_score=50, sensitive_categories="[]",
               discovery_method="grayhatwarfare", source="domain-recon")
# not public at all -> absent
CLOUD_PRIVATE = _n("c-private", "CloudAsset", "s3:example-private",
                   endpoint="example-private.s3.amazonaws.com", provider="aws", service="s3",
                   bucket="example-private", listable=False, public=False, object_count=900,
                   exposure_score=0, sensitive_categories="[]", source="domain-recon")
# the coercion trap again, on this node type
CLOUD_STRFALSE = _n("c-strfalse", "CloudAsset", "s3:example-str",
                    endpoint="example-str.s3.amazonaws.com", provider="aws", service="s3",
                    bucket="example-str", listable="False", public="False", object_count=5000,
                    exposure_score=40, sensitive_categories=_CATS_PII, source="domain-recon")
# A CloudSchism-shaped node: no listable/exposure_score at all, a real list rather
# than a JSON string, and an authenticated posture scan for attribution.
CLOUD_SCHISM = _n("c-cs", "cloudasset", "blob:example-sa", endpoint="examplesa.blob.core.windows.net",
                  provider="azure", service="blob", bucket="examplesa",
                  anonymous_reachable=True, sensitive_categories=["config"],
                  source="cloudschism")

CLOUD_NODES = [CLOUD_DNS, CLOUD_IDX, CLOUD_GUESS, CLOUD_VOL, CLOUD_PRIVATE,
               CLOUD_STRFALSE, CLOUD_SCHISM]
# The apex is the only thing a CloudAsset hangs off. w-apex also carries EXPOSES
# to t-deep, which is what makes the apex_overlap join non-empty.
CLOUD_EDGE_ROWS = [
    {"id": f"e:w-apex->{c['id']}", "label": "HAS_CLOUD_ASSET", "source": "w-apex",
     "target": c["id"], "source_type": "WebAsset", "source_label": "example.test (web)",
     "target_type": c["nodeType"], "target_label": c["nodeLabel"]}
    for c in CLOUD_NODES
]
# Ownership, not hosting -- the same row TECH fixtures carry, on a bucket. i-mgr
# must gain nothing from it.
CLOUD_EDGE_ROWS.append(
    {"id": "e:i-mgr->c-dns", "label": "MANAGES", "source": "i-mgr", "target": "c-dns",
     "source_type": "individual", "source_label": "MGR@CORP",
     "target_type": "CloudAsset", "target_label": "s3:example-payroll"})

# WF13's asset-SCOPED ownership evidence: somebody holds AD control over the
# device serving this asset, or a cloud IAM permission on the resource itself.
# This is the only ownership evidence WF04 will score, and only when
# CLOUD_OWNER_MAX_BONUS is raised above its default of 0.
#
# The label was MANAGES_NAMED until the name-token match that wrote it was
# removed -- it attributed every asset on a domain to every identity WF13 had
# promoted from a breach email on that domain, because such an identity's
# nodeLabel IS an address on the domain. OWNS_ASSET is its asset-scoped successor
# and HAS_ACCESS, the weaker tier, is deliberately not read here: WF04 scores
# control only.
#
# i-named has no AD edge at all, so any score it gains comes from this alone --
# which is what makes "inert by default" testable rather than assumed.
OWNER_EDGE_ROWS = [
    {"id": "e:i-named->c-dns", "label": "OWNS_ASSET", "source": "i-named",
     "target": "c-dns", "source_type": "individual", "source_label": "NAMED@CORP",
     "target_type": "CloudAsset", "target_label": "s3:example-payroll"},
    # A second, weaker bucket for the same owner: the credit is a MAX over their
    # assets, not a sum. Owning three leaky buckets is one finding.
    {"id": "e:i-named->c-tmp", "label": "OWNS_ASSET", "source": "i-named",
     "target": "c-guess", "source_type": "individual", "source_label": "NAMED@CORP",
     "target_type": "CloudAsset", "target_label": "s3:example-tmp"},
    # Same bucket, but this owner also has a real AD path worth more.
    {"id": "e:i-cboth->c-dns", "label": "OWNS_ASSET", "source": "i-cboth",
     "target": "c-dns", "source_type": "individual", "source_label": "CBOTH@CORP",
     "target_type": "CloudAsset", "target_label": "s3:example-payroll"},
]

AD_NODES = [
    _n("i-plain", "individual", "PLAIN@CORP"),
    _n("i-exp", "individual", "EXP@CORP"),
    _n("i-own", "individual", "OWN@CORP"),
    _n("i-both", "individual", "BOTH@CORP"),
    _n("i-chain", "individual", "CHAIN@CORP"),
    _n("i-str", "individual", "STR@CORP"),
    _n("i-mgr", "individual", "MGR@CORP"),
    _n("i-named", "individual", "NAMED@CORP"),
    _n("i-cboth", "individual", "CBOTH@CORP"),
    _n("d-clean", "device", "CLEAN01"),
    _n("d-exp", "device", "EXPHOST01"),
    _n("d-chain", "device", "CHAINHOST01"),
    _n("d-str", "device", "STRHOST01"),
]
AD_EDGES = [
    _e("i-plain", "d-clean", "GenericAll"),      # 10, nothing exploitable
    _e("i-exp", "d-exp", "GenericAll"),          # 10 + best of {8, 4}
    _e("i-both", "d-clean", "DCSync"),           # 10, plus a weaker own asset
    _e("i-chain", "d-chain", "GenericAll"),      # 10 + 8 through a Service
    _e("i-str", "d-str", "GenericAll"),          # 10, string 'False'
    # An AD path AND a named bucket: the DA-style path must win and the cloud
    # credit must not be claimed, the same way own_asset_ignored works.
    _e("i-cboth", "d-clean", "GenericAll"),      # 10, plus a 4-capped bucket
]
CARRIER_EDGES = [
    _e("d-exp", "t-cpe", "USES_TECH"),
    _e("d-exp", "t-kw", "USES_TECH"),
    _e("i-own", "t-own", "USES_TECH"),
    _e("i-both", "t-own", "USES_TECH"),
    _e("d-str", "t-str", "USES_TECH"),
    _e("d-chain", "s-bare", "EXPOSES_SERVICE"),
    _e("s-bare", "t-deep", "IMPLEMENTED_IN"),
    _e("w-apex", "t-deep", "EXPOSES"),
    # Ownership, not hosting. The Fetch node never reads MANAGES; this row is here
    # so the fixture would catch it if someone added it to TECH_EDGES.
    _e("i-mgr", "w-apex", "MANAGES"),
]


def payload(with_exploit: bool = True, sketch: str = "smoke",
            with_cloud: bool = True) -> Dict[str, Any]:
    return {
        "sketch_id": sketch,
        "nds": AD_NODES + TECH_NODES,
        "rls": AD_EDGES,
        "tech": TECH_NODES if with_exploit else [],
        "tech_rls": CARRIER_EDGES if with_exploit else [],
        "cloud": CLOUD_NODES if with_cloud else [],
        "cloud_rls": CLOUD_EDGE_ROWS if with_cloud else [],
        "owner_rls": OWNER_EDGE_ROWS if with_cloud else [],
    }


def cloud_block(code: str, pl: Dict[str, Any]) -> Dict[str, Any]:
    """The cloud_exposure item. It carries no ind_id, so scored_by_label drops it."""
    for r in run_code_node(code, pl):
        if r["json"].get("kind") == "cloud_exposure":
            return r["json"]["cloud_exposure"]
    return {}


def cloud_writes(code: str, pl: Dict[str, Any]) -> List[Dict[str, Any]]:
    for r in run_code_node(code, pl):
        if r["json"].get("kind") == "cloud_exposure":
            return r["json"].get("cloud_writes") or []
    return []


def _bonus(rec: Dict[str, Any]) -> int:
    return int(rec.get("exploit_bonus") or 0)


def _exploit(rec: Dict[str, Any]) -> Dict[str, Any]:
    return (rec.get("attack_summary") or {}).get("exploit") or {}


FIXTURES: Dict[str, Callable[[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]], bool]] = {
    # (scored_with_exploit_layer, scored_without) -> bool
    "clean_path": lambda r, b: (
        r["PLAIN@CORP"]["max_score"] == b["PLAIN@CORP"]["max_score"] == 10
        and not _exploit(r["PLAIN@CORP"]) and _bonus(r["PLAIN@CORP"]) == 0
    ),
    "exploitable_target": lambda r, b: (
        r["EXP@CORP"]["max_score"] == 18 and b["EXP@CORP"]["max_score"] == 10
        and _exploit(r["EXP@CORP"])["from"] == "path"
        and _exploit(r["EXP@CORP"])["unvetted"] is True
        and "UNVETTED" in _exploit(r["EXP@CORP"])["note"]
    ),
    "max_not_sum": lambda r, b: _bonus(r["EXP@CORP"]) == 8,          # not 8 + 4
    "keyword_discount": lambda r, b: (
        # Both attached to d-exp with identical trust and CVSS; only the basis
        # differs, so the cpe one must win and the keyword one must not add.
        [a["match"] for a in _exploit(r["EXP@CORP"])["assets"]] == ["cpe"]
    ),
    "service_chain": lambda r, b: (
        r["CHAIN@CORP"]["max_score"] == 18 and b["CHAIN@CORP"]["max_score"] == 10
        and _exploit(r["CHAIN@CORP"])["assets"][0]["asset"] == "Apache Tomcat 9"
    ),
    "bonus_cap": lambda r, b: _bonus(r["CHAIN@CORP"]) == 8,           # 6+2+2 capped
    "own_asset_only": lambda r, b: (
        "OWN@CORP" in r and "OWN@CORP" not in b
        and r["OWN@CORP"]["max_score"] == 4
        and r["OWN@CORP"]["attack_summary"]["total_paths"] == 0
        and _exploit(r["OWN@CORP"])["from"] == "own_asset"
        # 4 < the default threshold of 15: exploitable software alone is not an alert.
        and r["OWN@CORP"]["is_high_value"] is False
    ),
    "own_asset_ignored": lambda r, b: (
        # DCSync (10) beats the KeePass bonus (4), so the score must not move and
        # the bonus must not be claimed -- but the asset is still recorded.
        r["BOTH@CORP"]["max_score"] == b["BOTH@CORP"]["max_score"] == 10
        and _bonus(r["BOTH@CORP"]) == 0
        and "bonus" not in _exploit(r["BOTH@CORP"])
        and _exploit(r["BOTH@CORP"])["own_asset"]["asset"] == "KeePass Password Manager"
    ),
    "string_false": lambda r, b: (
        r["STR@CORP"]["max_score"] == b["STR@CORP"]["max_score"] == 10
        and _bonus(r["STR@CORP"]) == 0
    ),
    "manages_excluded": lambda r, b: "MGR@CORP" not in r and "MGR@CORP" not in b,
}


def _by_asset(blk: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {r["asset"]: r for r in (blk.get("top") or [])}


# (cloud_block, scored_with_cloud, scored_without_cloud) -> bool
CLOUD_FIXTURES: Dict[str, Callable[..., bool]] = {
    # Ranking, and the exact banker's-rounded values. int(round(4.5)) is 4, not 5 --
    # the same behaviour _exploit_bonus has, so assert the real numbers.
    "cloud_ranked": lambda c, r, b: (
        [x["asset"] for x in c["top"]][:2] == ["s3:example-payroll", "blob:example-sa"]
        and _by_asset(c)["s3:example-payroll"]["bonus"] == 8       # 4+3+2=9, capped
        and _by_asset(c)["s3:example-archive"]["bonus"] == 4       # 9*0.5=4.5 -> 4
        and _by_asset(c)["s3:example-tmp"]["bonus"] == 3           # 4*0.75 -> 3
        and _by_asset(c)["s3:example-logs"]["bonus"] == 3          # 6*0.5 -> 3
        and "s3:example-private" not in _by_asset(c)
        and c["assets_seen"] == 7 and c["exposed"] == 5
    ),
    # c-dns and c-idx carry IDENTICAL exposure facts; only attribution differs, so
    # the whole gap must come from CLOUD_ATTRIB_SCALE.
    "cloud_attrib_discount": lambda c, r, b: (
        _by_asset(c)["s3:example-payroll"]["attrib"] == "dns"
        and _by_asset(c)["s3:example-archive"]["attrib"] == "grayhatwarfare"
        and _by_asset(c)["s3:example-payroll"]["object_count"]
            == _by_asset(c)["s3:example-archive"]["object_count"]
        and _by_asset(c)["s3:example-payroll"]["categories"]
            == _by_asset(c)["s3:example-archive"]["categories"]
        and _by_asset(c)["s3:example-payroll"]["bonus"]
            > _by_asset(c)["s3:example-archive"]["bonus"]
    ),
    # A declared boolean handed back as the STRING 'False' must grant nothing.
    "cloud_string_false": lambda c, r, b: "s3:example-str" not in _by_asset(c),
    # THE LOAD-BEARING ONE. Cloud exposure must never reach an attack_score: MANAGES
    # is excluded from scoring and HAS_CLOUD_ASSET is not a carrier, so a CloudAsset
    # has no path to an Individual. Every identity must be identical with and
    # without the entire cloud layer.
    "cloud_not_a_carrier": lambda c, r, b: (
        set(r) == set(b)
        and all(r[k]["max_score"] == b[k]["max_score"] for k in b)
        and all(_bonus(r[k]) == _bonus(b[k]) for k in b)
        and all("cloud" not in (r[k].get("attack_summary") or {}) for k in r)
        and c.get("unattributed") is True
    ),
    # Distinct from manages_excluded, which covers the tech layer.
    "cloud_manages_ignored": lambda c, r, b: (
        "MGR@CORP" not in r
        # And an ownership edge must never be RENDERED as the asset's hosting apex:
        # that would present a person's name as hosting provenance, the exact
        # conflation the MANAGES exclusion exists to prevent.
        and all(x["apex"] != "MGR@CORP" for x in c["top"])
    ),
    # A CloudSchism-shaped node carries no listable/exposure_score and a real list
    # rather than a JSON string. A reader that knows only WF13's shape scores it 0.
    "cloud_schism_shape": lambda c, r, b: (
        _by_asset(c)["blob:example-sa"]["bonus"] == 6
        and _by_asset(c)["blob:example-sa"]["attrib"] == "account"
        and _by_asset(c)["blob:example-sa"]["categories"] == ["config"]
    ),
    # sensitive_categories arrives from WF13 as a JSON STRING. Handed straight to a
    # membership test it would match single CHARACTERS.
    "cloud_categories_parsed": lambda c, r, b: (
        _by_asset(c)["s3:example-payroll"]["categories"] == ["pii", "backup"]
    ),
    # The join WF13 structurally cannot make: an apex both leaking a bucket and
    # running software with public exploit code.
    "cloud_apex_overlap": lambda c, r, b: (
        len(c["apex_overlap"]) == 5
        and all(x["apex"] == "example.test (web)" for x in c["apex_overlap"])
    ),
    # Provenance must be legible enough to act on, and must carry the caveat.
    "cloud_provenance_shape": lambda c, r, b: (
        all(k in c["top"][0] for k in ("bonus", "attrib", "exposure_score",
                                       "object_count", "categories", "apex",
                                       "provider", "service", "endpoint"))
        and "MANAGES" in c["note"] and "no attack_score" in c["note"]
    ),
}


def run_cloud_fixtures(code: str, only: Optional[str] = None) -> int:
    blk = cloud_block(code, payload(True))
    with_cloud = scored_by_label(code, payload(True))
    without_cloud = scored_by_label(code, payload(True, with_cloud=False))
    failures = 0
    for name, expect in CLOUD_FIXTURES.items():
        if only and name != only:
            continue
        try:
            ok, detail = bool(expect(blk, with_cloud, without_cloud)), ""
        except Exception as exc:                                     # noqa: BLE001
            ok, detail = False, f" ({type(exc).__name__}: {exc})"
        print(f"  {'ok  ' if ok else 'FAIL'} {name}{detail}")
        failures += 0 if ok else 1

    if not only or only == "cloud_writeback_bounded":
        # Update Dossier Notes drops any item without ind_id, and the cloud item has
        # none -- so if this list is empty or its entries lack ids, the whole term
        # computes a number nothing persists.
        writes = cloud_writes(code, payload(True))
        ok = (bool(writes) and len(writes) <= 100
              and all(w.get("id") for w in writes)
              and [w["asset"] for w in writes]
                  == [x["asset"] for x in blk["top"]][:len(writes)])
        print(f"  {'ok  ' if ok else 'FAIL'} cloud_writeback_bounded")
        failures += 0 if ok else 1

    if not only or only == "cloud_owner_off_by_default":
        # THE OTHER LOAD-BEARING ONE. Crediting an owner reverses the standing
        # "ownership is not hosting" decision, so it must ship INERT: with the knob
        # unset, an OWNS_ASSET edge onto the highest-scoring bucket must leave
        # every score untouched and NAMED@CORP out of the results entirely.
        ok = ("NAMED@CORP" not in with_cloud
              and all("cloud" not in (with_cloud[k].get("attack_summary") or {})
                      for k in with_cloud)
              and all(int(with_cloud[k].get("cloud_bonus") or 0) == 0
                      for k in with_cloud))
        print(f"  {'ok  ' if ok else 'FAIL'} cloud_owner_off_by_default")
        failures += 0 if ok else 1

    if not only or only == "cloud_owner_credit":
        prev = os.environ.get("CLOUD_OWNER_MAX_BONUS")
        os.environ["CLOUD_OWNER_MAX_BONUS"] = "4"
        try:
            on = scored_by_label(code, payload(True))
        finally:
            if prev is None:
                os.environ.pop("CLOUD_OWNER_MAX_BONUS", None)
            else:
                os.environ["CLOUD_OWNER_MAX_BONUS"] = prev
        rec = on.get("NAMED@CORP") or {}
        cl = (rec.get("attack_summary") or {}).get("cloud") or {}
        ok = (
            # No AD path of its own, so the whole score is the capped credit:
            # the bucket scores 8, the knob allows 4.
            rec.get("max_score") == 4
            and rec.get("attack_summary", {}).get("total_paths") == 0
            and cl.get("bonus") == 4
            and cl.get("from") == "owned_asset"
            and cl.get("evidence") == "name-in-asset"
            # unattributed flips to False here: this credit IS inside a score.
            and cl.get("unattributed") is False
            # MAX over the owner's assets, not a sum: 8 and 3 -> the 8, capped to 4,
            # never 11.
            and cl["assets"][0]["asset"] == "s3:example-payroll"
            and len(cl["assets"]) == 1
            # The bonus is only reported when it is actually inside max_score.
            and int(rec.get("cloud_bonus") or 0) == 4
            # 4 < the default threshold of 15: a leaky bucket alone is not an alert.
            and rec.get("is_high_value") is False
            # And the plain-MANAGES owner still gains nothing at any setting.
            and "MGR@CORP" not in on
            # Every other identity is unmoved.
            and all(on[k]["max_score"] == with_cloud[k]["max_score"]
                    for k in with_cloud)
        )
        print(f"  {'ok  ' if ok else 'FAIL'} cloud_owner_credit")
        failures += 0 if ok else 1

    if not only or only == "cloud_owner_ignored":
        # An identity with BOTH an AD path (10) and a named bucket (8, capped to 4
        # by the knob). The path must win, the credit must NOT be claimed, and no
        # cloud block may be attached -- the same contract own_asset_ignored holds
        # for the exploit bonus. Without this, nothing covers the branch that zeroes
        # a credit that did not move the score, nor a credit summed into a path.
        prev = os.environ.get("CLOUD_OWNER_MAX_BONUS")
        os.environ["CLOUD_OWNER_MAX_BONUS"] = "4"
        try:
            on = scored_by_label(code, payload(True))
        finally:
            if prev is None:
                os.environ.pop("CLOUD_OWNER_MAX_BONUS", None)
            else:
                os.environ["CLOUD_OWNER_MAX_BONUS"] = prev
        rec = on.get("CBOTH@CORP") or {}
        ok = (rec.get("max_score") == 10                     # not 14, not 4
              and int(rec.get("cloud_bonus") or 0) == 0
              and "cloud" not in (rec.get("attack_summary") or {}))
        print(f"  {'ok  ' if ok else 'FAIL'} cloud_owner_ignored")
        failures += 0 if ok else 1

    if not only or only == "cloud_knob_zero":
        prev = os.environ.get("CLOUD_EXPOSURE_MAX_BONUS")
        os.environ["CLOUD_EXPOSURE_MAX_BONUS"] = "0"
        try:
            off_blk = cloud_block(code, payload(True))
            off_scored = scored_by_label(code, payload(True))
        finally:
            if prev is None:
                os.environ.pop("CLOUD_EXPOSURE_MAX_BONUS", None)
            else:
                os.environ["CLOUD_EXPOSURE_MAX_BONUS"] = prev
        ok = (off_blk.get("exposed") == 0 and not off_blk.get("top")
              and all(off_scored[k]["max_score"] == with_cloud[k]["max_score"]
                      for k in with_cloud))
        print(f"  {'ok  ' if ok else 'FAIL'} cloud_knob_zero")
        failures += 0 if ok else 1

    return failures


def run_fixtures(code: str, only: Optional[str] = None) -> int:
    with_layer = scored_by_label(code, payload(True))
    without = scored_by_label(code, payload(False))
    failures = 0
    for name, expect in FIXTURES.items():
        if only and name != only:
            continue
        try:
            ok = bool(expect(with_layer, without))
            detail = ""
        except Exception as exc:                                     # noqa: BLE001
            ok, detail = False, f" ({type(exc).__name__}: {exc})"
        print(f"  {'ok  ' if ok else 'FAIL'} {name}{detail}")
        failures += 0 if ok else 1

    if not only or only == "knob_zero":
        # The Configuration-panel knob, resolved through spotter_settings' env
        # tier. 0 must remove exploit availability from the ranking entirely.
        prev = os.environ.get("EXPLOIT_PATH_MAX_BONUS")
        os.environ["EXPLOIT_PATH_MAX_BONUS"] = "0"
        try:
            off = scored_by_label(code, payload(True))
        finally:
            if prev is None:
                os.environ.pop("EXPLOIT_PATH_MAX_BONUS", None)
            else:
                os.environ["EXPLOIT_PATH_MAX_BONUS"] = prev
        ok = (all(off[k]["max_score"] == without[k]["max_score"] for k in without)
              and "OWN@CORP" not in off)
        print(f"  {'ok  ' if ok else 'FAIL'} knob_zero")
        failures += 0 if ok else 1

    return failures


# ── Live exploit layer ───────────────────────────────────────────────────────
# The same vocabulary the Fetch node reads, from the same module, so --live cannot
# drift from production the way this hand-copy used to.
from asset_labels import TECH_EDGES, TECH_LABELS  # noqa: E402
from asset_labels import TECH_SCORING_PROPS as TECH_PROPS  # noqa: E402


def run_live(code: str, sketch: str = "") -> int:
    import flowsint_client as fc

    # Both this harness and the Fetch node now import the vocabulary from
    # scripts/asset_labels.py, so there is nothing left to drift -- but assert the
    # node still imports it, because a local re-declaration there would shadow the
    # shared value and put --live back to testing something production does not.
    fetch = load_code_node("Fetch Full Graph")
    if "from asset_labels import" not in fetch:
        print("  warn --live: the Fetch node no longer imports asset_labels")

    sketch = sketch or fc.resolve_campaign_sketch()
    tech = fc.get_nodes_by_type(TECH_LABELS, sketch_id=sketch, properties=TECH_PROPS)
    edges = fc.get_edges_by_type(TECH_EDGES, sketch_id=sketch,
                                 resolve_endpoints=True, timeout=300)
    exploitable = [n for n in tech
                   if str((n.get("nodeProperties") or {}).get("exploit_available")
                          ).strip().lower() in ("true", "1", "yes")]
    print(f"  sketch {sketch}: {len(tech)} tech/service nodes "
          f"({len(exploitable)} exploitable), {len(edges)} carrier edges")

    # Score the synthetic AD slice against the REAL layer. The point is the id
    # namespace: get_graph, get_nodes_by_type and get_edges_by_type must agree,
    # and only real elementIds can show that.
    live_payload = payload(True, sketch=sketch)
    live_payload["nds"] = AD_NODES + TECH_NODES + tech
    live_payload["tech"] = TECH_NODES + tech
    live_payload["tech_rls"] = CARRIER_EDGES + edges
    scored = scored_by_label(code, live_payload)
    if scored.get("EXP@CORP", {}).get("max_score") != 18:
        print("  FAIL live: real layer perturbed the synthetic scores")
        return 1
    print("  ok   live: real exploit layer read and scored without perturbing fixtures")

    # Every asset the live layer actually credits, so a real run is inspectable.
    for label, rec in sorted(scored.items()):
        ex = _exploit(rec)
        if ex.get("bonus") and any(a.get("asset") for a in ex.get("assets", [])):
            names = ", ".join(a["asset"] for a in ex["assets"])
            print(f"       {label}: +{ex['bonus']} ({names})")
    json.dumps(scored)
    print("  ok   live: output is JSON-serialisable")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true",
                    help="also read the real exploit layer (needs NEO4J_HTTP_URL reachable)")
    ap.add_argument("--only", help="run a single fixture by name")
    ap.add_argument("--sketch", default="",
                    help="explicit sketch for --live (default: resolve_campaign_sketch, "
                         "which is the most recent campaign and may not be the enriched one)")
    args = ap.parse_args()

    code = load_code_node(CODE_NODE)
    print(f"WF04 {CODE_NODE}: {len(code.splitlines())} lines")

    print("fixtures:")
    failures = run_fixtures(code, args.only)

    print("cloud exposure fixtures:")
    failures += run_cloud_fixtures(code, args.only)

    if args.live:
        print("live exploit layer:")
        failures += run_live(code, args.sketch)

    print("FAILED" if failures else "PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
