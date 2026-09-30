#!/usr/bin/env python3
"""
Offline smoke test for workflow 13's domain-recon code node.

This executes the embedded `Run Domain OSINT + Breach Correlation` Python with
fake HTTP, settings, and Flowsint modules. It pins the ip.thc.org path that was
previously added but not executable-tested: THC subdomains, CNAMEs, rDNS metadata,
proxy use, ISO-2 country normalization, source mixing, and graph import for
THC-only subdomains.

Usage:
    python3 scripts/smoke_workflow13.py
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import textwrap
import types
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
# The node does sys.path.insert(0, '/data/scripts'), which only exists inside the
# runner container. On the host, put this directory there instead so the modules
# the node imports by bare name (job_titles) resolve to the repo copies.
sys.path.insert(0, str(Path(__file__).resolve().parent))
WORKFLOW_PATH = REPO_ROOT / "n8n-workflows" / "13-domain-recon.json"
CODE_NODE = "Run Domain OSINT + Breach Correlation"


def load_code_node() -> str:
    workflow = json.loads(WORKFLOW_PATH.read_text())
    for node in workflow.get("nodes", []):
        if node.get("name") == CODE_NODE:
            return node["parameters"]["pythonCode"]
    raise SystemExit(f"code node {CODE_NODE!r} not found in {WORKFLOW_PATH}")


def run_n8n_python_code(code: str, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    wrapped = "def __n8n_exec(_items):\n" + textwrap.indent(code, "    ")
    ns: Dict[str, Any] = {}
    exec(compile(wrapped, "<wf13>", "exec"), ns, ns)
    return ns["__n8n_exec"](items)


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.ok = 200 <= status_code < 300

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if not self.ok:
            raise RuntimeError(f"HTTP {self.status_code}")


# Which fields each simulated FOFA account tier refuses. 'normal' is an entitled
# account; 'forbidden_tier0' mimics the real key on this host, which rejects the
# richest tier only; 'forbidden_all' rejects every tier the workflow will try.
_FOFA_DENIED: Dict[str, set] = {
    "normal": set(),
    "forbidden_tier0": {"icp"},
    "forbidden_all": {"host"},
}


def build_fake_requests(thc_mode: str = "normal",
                        flare_creds: int = 0,
                        fofa_mode: str = "normal",
                        shodan_mode: str = "normal") -> Tuple[types.ModuleType, Dict[str, Any]]:
    state: Dict[str, Any] = {"gets": [], "posts": [], "fofa_fields": []}
    fake = types.ModuleType("requests")

    def get(url: str, **kwargs: Any) -> FakeResponse:
        state["gets"].append({"url": url, "kwargs": kwargs})
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        if parsed.netloc in {"dns.google", "cloudflare-dns.com"}:
            qtype = (query.get("type") or [""])[0]
            if qtype == "A":
                return FakeResponse(payload={"Answer": [{"data": "203.0.113.10"}]})
            if qtype == "MX":
                # Two hosts, ONE platform: the fixture for the fold assertion.
                return FakeResponse(payload={"Answer": [
                    {"data": "0 example-com.mail.protection.outlook.com."},
                    {"data": "10 example-com.mail.eo.outlook.com."}]})
            if qtype == "NS":
                # 'awsdns' sits MID-LABEL here, not as a suffix, so this pins the
                # DNS-label boundary matcher rather than an endswith() shortcut.
                return FakeResponse(payload={"Answer": [
                    {"data": "ns-1234.awsdns-56.org."},
                    {"data": "ns-99.awsdns-12.co.uk."}]})
            if qtype == "CNAME":
                return FakeResponse(payload={"Answer": [
                    {"data": "example-com.cdn.cloudflare.net."}]})
            return FakeResponse(payload={"Answer": []})

        if parsed.netloc == "ipinfo.io":
            # 'Example Transit' is in no ASN table: an unrecognised hosting network
            # is not a technology finding, and the assertions below pin that.
            return FakeResponse(payload={"org": "AS64500 Example Transit"})

        if parsed.netloc == "internetdb.shodan.io":
            if shodan_mode == "idb_429":
                return FakeResponse(status_code=429, text="rate limited")
            return FakeResponse(payload={
                "ports": [443],
                "vulns": ["CVE-2024-0001"],
                "cpes": ["cpe:/a:nginx:nginx:1.18"],
                "hostnames": ["www.example.com"],
            })

        if parsed.netloc == "fofa.info":
            # Field-aware, because WF13 walks a ladder of field sets: the rows it
            # gets back must be positional in the fields IT asked for, or a
            # narrower tier would silently shift every column.
            fields = str((kwargs.get("params") or {}).get("fields") or "")
            cols = [c for c in fields.split(",") if c]
            state["fofa_fields"].append(fields)

            # An account tier that forbids a field rejects the WHOLE query with
            # HTTP 200 + error, naming one offending field.
            denied = _FOFA_DENIED.get(fofa_mode) or set()
            for bad in denied:
                if bad in cols:
                    return FakeResponse(payload={
                        "error": True,
                        "errmsg": "[820001] 没有权限搜索"
                                  + bad + "字段",
                    })

            rows = [{
                "host": "www.example.com", "ip": "203.0.113.12", "port": "80",
                "protocol": "http", "title": "Example",
                "server": "Microsoft-IIS/10.0", "product": "Microsoft-IIS/10.0",
                "os": "windows", "country": "US", "region": "Virginia",
                "city": "Ashburn", "link": "http://203.0.113.12",
                "domain": "example.com", "icp": "",
            }, {
                # A product string that canonicalises to nothing: bare dotted
                # digits are stripped as a version tail, leaving an empty name.
                # It must yield NO Technology node rather than a name-less one.
                "host": "bad.example.com", "ip": "203.0.113.13", "port": "80",
                "protocol": "http", "title": "Junk",
                "server": "2.4", "product": "2.4",
                "os": "linux", "country": "US", "region": "Virginia",
                "city": "Ashburn", "link": "http://203.0.113.13",
                "domain": "example.com", "icp": "",
            }]
            return FakeResponse(payload={
                "size": len(rows),
                "results": [[rec.get(c, "") for c in cols] for rec in rows],
            })

        if parsed.netloc == "api.shodan.io":
            if shodan_mode == "429":
                return FakeResponse(status_code=429, text="rate limited")
            if shodan_mode == "empty":
                return FakeResponse(payload={"matches": []})
            return FakeResponse(payload={"matches": [{
                "ip_str": "203.0.113.11",
                "port": 8443,
                "vulns": {"CVE-2024-0002": {}},
                "cpes": ["cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"],
                "product": "Apache httpd",
                "version": "2.4.58",
                "org": "Example Hosting",
            }, {
                # A perimeter appliance, reported under a banner spelling that is
                # NOT the canonical name. Exercises both the canon fold and the
                # HIGH_VALUE_TECH membership test.
                "ip_str": "203.0.113.14",
                "port": 443,
                "vulns": {},
                "cpes": [],
                "product": "NetScaler",
                "version": "13.1",
                "org": "Example Hosting",
            }, {
                # The SAME product on a second address. It folds onto one
                # canonical Technology -- correctly, the node is the software --
                # but the response used to ship only the first observation, so it
                # could say "Apache is on the perimeter" and not "on these two
                # hosts". The dashboard has nothing but this response to answer
                # "which host?" from.
                "ip_str": "203.0.113.15",
                "port": 443,
                "vulns": {},
                "cpes": [],
                "product": "Apache httpd",
                "version": "2.4.58",
                "hostnames": ["shop.example.com"],
                "org": "Example Hosting",
            }]})

        if parsed.netloc == "ip.thc.org":
            if thc_mode == "429":
                return FakeResponse(status_code=429, text="rate limited")
            if parsed.path.startswith("/sb/"):
                if thc_mode == "low_budget":
                    return FakeResponse(text=";;Rate Limit: You can make 4 requests (Replenishes at 0.50/sec)\nexample.com\n")
                return FakeResponse(text=";;Rate Limit: You can make 249 requests (Replenishes at 0.50/sec)\nexample.com\nalpha.example.com\n")
            if parsed.path.startswith("/cn/"):
                return FakeResponse(text=";;Rate Limit: You can make 248 requests (Replenishes at 0.50/sec)\ncdn-thirdparty.example.net\n")
            if parsed.path == "/203.0.113.10":
                return FakeResponse(text=";IP: 203.0.113.10\n;ASN: 64500\n;Organization: Example Transit\n;City: Boulder\n;Country: United States\nwww.example.com\n")

        if parsed.netloc == "example.com":
            return FakeResponse(text="<html><head><title>Example Domain</title></head></html>")

        if parsed.netloc in {"rdap.verisign.com", "rdap.org"}:
            return FakeResponse(payload={})

        return FakeResponse(payload={})

    def post(url: str, **kwargs: Any) -> FakeResponse:
        state["posts"].append({"url": url, "kwargs": kwargs})
        if url == "https://ct.certkit.io/search":
            return FakeResponse(payload={"results": [], "totalCount": 0})
        if url == "https://api.flare.io/tokens/generate":
            return FakeResponse(payload={"token": "fake-flare-token"})
        if url == "https://api.flare.io/astp/v2/credentials/_search":
            # One page, no cursor: this case is about the response cap, not paging.
            # `hash` carries the credential and hash_type is 'unknown' — the real
            # ASTP shape (see flare-astp-credential-shape).
            return FakeResponse(payload={"items": [{
                "id": f"cred-{i}",
                "identity_name": f"user{i}@example.com",
                "source_id": "stealer_logs",
                "hash": f"pw{i}",
                "hash_type": "unknown",
            } for i in range(flare_creds)], "next": None})
        return FakeResponse(payload={})

    fake.get = get  # type: ignore[attr-defined]
    fake.post = post  # type: ignore[attr-defined]
    return fake, state


def build_fake_flowsint(seed_tech: bool = False,
                        individuals: int = 0,
                        titled_people: bool = False,
                        ownership: str = "",
                        ) -> Tuple[types.ModuleType, Dict[str, Any]]:
    """Fake Flowsint graph.

    `ownership` seeds the AD/cloud evidence WF13's owners_for() now reads, one
    scenario per value: "direct" (a real person holds LOCAL_ADMIN on the device
    serving the apex), "access" (CanRDP only), "group" (a small team holds
    GenericAll), "da" (Domain Admins holds LOCAL_ADMIN -- must NOT attribute),
    "provisional" (a Flare-promoted email-labelled identity, the regression case
    for the retired name-token branch), "cloud" (a CloudSchism IAM permission).
    """
    state: Dict[str, Any] = {"nodes": [], "edges": [], "edits": []}
    fake = types.ModuleType("flowsint_client")

    existing_nodes = [
        {
            "id": "dev-1",
            "nodeType": "device",
            "nodeLabel": "WWW01",
            "nodeProperties": {
                "hostname": "WWW01",
                "dnshostname": "www.example.com",
                "ip": "203.0.113.10",
            },
        },
        {
            "id": "ip-1",
            "nodeType": "ip",
            "nodeLabel": "203.0.113.10",
            "nodeProperties": {"ip": "203.0.113.10"},
        },
    ]

    existing_edges: List[Dict[str, Any]] = []

    if seed_tech:
        # Lowercase 'technology' on purpose: that is how batch_import writes it
        # (the nmap, Nessus and process-list ingest paths), while fc.add_node
        # preserves PascalCase. WF13's dedup lookup is an exact string test, so
        # without an explicit case fold this node is invisible and gets duplicated.
        # The nodeLabel carries a version the canonical key must ignore.
        existing_nodes.append({
            "id": "tech-1",
            "nodeType": "technology",
            "nodeLabel": "Apache httpd 2.4.49",
            "nodeProperties": {"name": "Apache httpd", "source": "nmap",
                               "version": "2.4.49", "cve_count": 7},
        })

    # Individuals whose email matches a Flare breach record, for the
    # credential-match cap case. Two are admins and the rest carry descending
    # breach counts, which is exactly the sort key the cap relies on — so the
    # assertion that the kept slice is the high-value one is a real assertion.
    for i in range(individuals):
        existing_nodes.append({
            "id": f"ind-{i}",
            "nodeType": "individual",
            "nodeLabel": f"EXAMPLE\\user{i}",
            "nodeProperties": {
                "email": f"user{i}@example.com",
                "is_admin": i < 2,
                "breach_count": individuals - i,
            },
        })

    if titled_people:
        # Two people whose titles reach WF13 by the two different routes the
        # org block has to cover: one written straight onto the Individual by
        # WF03's write-back, one only on a linked SocialProfile. Both are in
        # English while the vacancies they must match are in Russian, which is
        # the whole reason the match goes through derive_specialty().
        existing_nodes.append({
            "id": "ind-titled", "nodeType": "individual", "nodeLabel": "Ivan Ivanov",
            "nodeProperties": {"full_name": "Ivan Ivanov",
                               "linkedin_job_title": "Senior Systems Administrator"},
        })
        existing_nodes.append({
            "id": "ind-sp", "nodeType": "individual", "nodeLabel": "Olga Petrova",
            "nodeProperties": {"full_name": "Olga Petrova"},
        })
        existing_nodes.append({
            "id": "sp-1", "nodeType": "socialprofile", "nodeLabel": "Linkedin:opetrova",
            "nodeProperties": {"platform": "linkedin", "job_title": "Financial Analyst"},
        })
        existing_edges.append({"source": "ind-sp", "target": "sp-1", "label": "HAS_PROFILE"})

    # ── Ownership evidence fixtures ──────────────────────────────────────────
    # dev-1 is WWW01, dnshostname www.example.com, ip 203.0.113.10 — which is
    # what devices_for_asset() joins the apex and its subdomains onto.
    if ownership:
        # An identity WF13 itself promoted from an unmatched Flare breach email:
        # nodeLabel IS the address, `provisional` set. Present in EVERY ownership
        # scenario, because the retired name-token branch matched it against every
        # asset on the domain and nothing must resurrect that.
        existing_nodes.append({
            "id": "ind-prov", "nodeType": "individual",
            "nodeLabel": "jd@example.com",
            "nodeProperties": {"email": "jd@example.com", "provisional": True,
                               "source": "flare_domain", "source_domain": "example.com"},
        })
        # A right pointing AT the serving device from the provisional identity.
        # Contrived, but it is the only way to exercise the property guard rather
        # than merely re-observing that the name-token branch is gone: without
        # this edge the identity can never be attributed however the guard behaves.
        existing_edges.append({"source": "ind-prov", "target": "dev-1",
                               "label": "LOCAL_ADMIN"})
    if ownership in ("direct", "access", "provisional"):
        existing_nodes.append({
            # SharpHound labels an Individual from Properties.name, which
            # BloodHound populates as SAM@DOMAIN.LOCAL -- so a REAL AD user is
            # email-shaped too. Using a "Carol Ops" label here would let a filter
            # that excludes every email-shaped label pass this suite while
            # zeroing the whole AD ownership layer on real data.
            "id": "ind-ops", "nodeType": "individual", "nodeLabel": "COPS@EXAMPLE.COM",
            "nodeProperties": {"full_name": "Carol Ops", "sam_account_name": "cops",
                               "source": "sharphound"},
        })
        right = "CanRDP" if ownership == "access" else "LOCAL_ADMIN"
        existing_edges.append({"source": "ind-ops", "target": "dev-1", "label": right})
    if ownership == "group":
        existing_nodes.append({
            "id": "grp-web", "nodeType": "organization", "nodeLabel": "Web Team",
            "nodeProperties": {"name": "Web Team"},
        })
        existing_nodes.append({
            "id": "ind-team", "nodeType": "individual", "nodeLabel": "DWEB@EXAMPLE.COM",
            "nodeProperties": {"full_name": "Dave Web", "source": "sharphound"},
        })
        existing_edges.append({"source": "grp-web", "target": "dev-1", "label": "GenericAll"})
        existing_edges.append({"source": "ind-team", "target": "grp-web", "label": "MEMBER_OF"})
    if ownership == "bulk":
        # A group that is neither built-in nor flagged high-value, but is an org
        # unit rather than a team: "All Staff" with more members than
        # MAX_GROUP_MEMBERS. Its rights say nothing asset-specific, and without
        # the size guard every member would own the host.
        existing_nodes.append({
            "id": "grp-all", "nodeType": "organization", "nodeLabel": "All Staff",
            "nodeProperties": {"name": "All Staff"},
        })
        existing_edges.append({"source": "grp-all", "target": "dev-1", "label": "GenericAll"})
        for i in range(60):
            existing_nodes.append({
                "id": f"ind-bulk-{i}", "nodeType": "individual",
                "nodeLabel": f"BULK{i}@EXAMPLE.COM",
                "nodeProperties": {"full_name": f"Bulk User {i}", "source": "sharphound"},
            })
            existing_edges.append({"source": f"ind-bulk-{i}", "target": "grp-all",
                                   "label": "MEMBER_OF"})

    if ownership == "da":
        # The guard that stops this fix reproducing the bug it replaces. Domain
        # Admins holds LOCAL_ADMIN on every host; attributing that to its members
        # would charge the whole estate to every DA.
        existing_nodes.append({
            "id": "grp-da", "nodeType": "organization", "nodeLabel": "Domain Admins",
            "nodeProperties": {"name": "Domain Admins", "is_high_value": True},
        })
        existing_nodes.append({
            "id": "ind-da", "nodeType": "individual", "nodeLabel": "EADMIN@EXAMPLE.COM",
            "nodeProperties": {"full_name": "Erin Admin", "source": "sharphound"},
        })
        existing_edges.append({"source": "grp-da", "target": "dev-1", "label": "LOCAL_ADMIN"})
        existing_edges.append({"source": "ind-da", "target": "grp-da", "label": "MEMBER_OF"})

    def get_nodes_by_type(node_type: Any, **_kwargs: Any) -> List[Dict[str, Any]]:
        wanted = {node_type} if isinstance(node_type, str) else set(node_type)
        return [n for n in existing_nodes if n["nodeType"] in wanted]

    def get_edges_by_type(edge_type: Any, **kwargs: Any) -> Any:
        """Honours the real client's shaping kwargs.

        group_by_target and resolve_endpoints are NOT decoration: WF13 reads the
        AD rights grouped, so a fake that always returns a flat list makes the
        node's own `.items()` raise into its try/except and the whole ownership
        layer silently returns nothing while the test still passes. That is the
        fail-green pattern this repo keeps getting bitten by, so it is modelled
        here rather than assumed away.
        """
        wanted = {edge_type} if isinstance(edge_type, str) else set(edge_type)
        if "RESOLVES_TO" in wanted:
            rows = [{"id": "rel-1", "source": "dev-1", "target": "ip-1", "label": "RESOLVES_TO"}]
        else:
            rows = [dict(e) for e in existing_edges if e["label"] in wanted]

        by_id = {n["id"]: n for n in existing_nodes}
        # Endpoint labels anchor the query in the real client; a fake that
        # ignores them would let a reader walk an edge the wrong way round and
        # still pass.
        for key, side in (("source_label", "source"), ("target_label", "target")):
            want = kwargs.get(key)
            if want:
                rows = [r for r in rows
                        if (by_id.get(r[side], {}).get("nodeType") or "") == want]
        if kwargs.get("resolve_endpoints"):
            for r in rows:
                for side in ("source", "target"):
                    n = by_id.get(r[side], {})
                    r[side + "_type"] = n.get("nodeType", "")
                    r[side + "_label"] = n.get("nodeLabel", "")
        if kwargs.get("group_by_target"):
            lim = kwargs.get("per_target_limit")
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for r in rows:
                item = {"label": r["label"], "source": r["source"]}
                if kwargs.get("resolve_endpoints"):
                    item["source_type"] = r.get("source_type", "")
                    item["source_label"] = r.get("source_label", "")
                grouped.setdefault(r["target"], []).append(item)
            if lim:
                grouped = {k: v[:lim] for k, v in grouped.items()}
            return grouped
        return rows

    def add_node(label: str, node_type: str, properties: Dict[str, Any], **_kwargs: Any) -> Dict[str, Any]:
        node_id = f"node-{len(state['nodes']) + 1}"
        state["nodes"].append({"id": node_id, "label": label, "node_type": node_type, "properties": properties})
        return {"id": node_id}

    def edit_node(node_id: str, updates: Dict[str, Any], **_kwargs: Any) -> Dict[str, Any]:
        state["edits"].append({"id": node_id, "updates": updates})
        return {"id": node_id}

    def create_edge(src_id: str, tgt_id: str, label: str, sketch_id: str = "") -> Dict[str, Any]:
        edge_id = f"edge-{len(state['edges']) + 1}"
        state["edges"].append({"id": edge_id, "source": src_id, "target": tgt_id, "label": label, "sketch_id": sketch_id})
        return {"id": edge_id}

    fake.get_nodes_by_type = get_nodes_by_type  # type: ignore[attr-defined]
    fake.get_edges_by_type = get_edges_by_type  # type: ignore[attr-defined]
    fake.add_node = add_node  # type: ignore[attr-defined]
    fake.edit_node = edit_node  # type: ignore[attr-defined]
    fake.create_edge = create_edge  # type: ignore[attr-defined]
    return fake, state


def build_fake_tavily(fail: bool = False, matched: bool = True,
                      ) -> Tuple[types.ModuleType, Dict[str, Any]]:
    """Stand-in for scripts/tavily_client.

    The real client's transports, query shapes and parsers are covered by
    scripts/smoke_tavily_client.py. What this fake exists to test is WF13's
    half: that Tavily records its own provider row, that it WINS the linkedin_*
    keys over SerpAPI when both matched, and -- the one that actually bites --
    that a person BOTH providers returned lands in org_people exactly once.

    Dana Webb is deliberately shared with build_fake_serp's roster at the same
    profile URL, and deliberately arrives here with employer='' -- the real
    limitation, because Tavily's snippet is its own extraction and often lacks
    the `Experience:` run a Google-rendered snippet carries. The merge must
    therefore keep ONE row and fill the employer in from whichever provider
    had it.
    """
    state: Dict[str, Any] = {"queries": [], "ctor": {}, "identities": []}
    fake = types.ModuleType("tavily_client")

    class TavilyError(Exception):
        pass

    class TavilyClient:
        def __init__(self, **kwargs: Any) -> None:
            state["ctor"] = kwargs
            self._searches = 3
            self.credits_spent = 3
            self.errors: list = []

        def organization_profile(self, name: str, role_keywords: Any = None,
                                 identity: Any = None, match_min: Any = None,
                                 ) -> Dict[str, Any]:
            state["queries"].append(name)
            state["identities"].append(identity)
            if fail:
                raise TavilyError("Tavily returned HTTP 503")
            if not matched:
                return {"matched": False, "source": "tavily", "reliable": True,
                        "query": name, "profile": {}, "related": [], "people": [],
                        "mentions": [], "rejected": [], "match_reason": "",
                        "errors": []}
            return {
                "matched": True, "source": "tavily", "reliable": True, "query": name,
                "profile": {"id": "example-fixture", "name": "Example Corp",
                            "industries": [], "description": "Example Corp via Tavily",
                            "site": "", "area": "", "address": "", "country": "",
                            "size_category": "",
                            "profile_url": "https://www.linkedin.com/company/example-fixture-tavily/"},
                "related": [{"name": "Example Cloud", "kind": "unit",
                             "url": "https://www.linkedin.com/company/example-cloud/"}],
                "mentions": [],
                "people": [
                    # SHARED with the SERP fake, and without an employer.
                    {"name": "Dana Webb", "job_title": "", "employer": "",
                     "employer_source": "", "location": "Denver", "education": "",
                     "technologies": [],
                     "url": "https://www.linkedin.com/in/dana-webb-example/"},
                    {"name": "Robin Tavily", "job_title": "Cloud Architect",
                     "employer": "Example Corp", "employer_source": "title",
                     "location": "", "education": "", "technologies": ["AWS"],
                     "url": "https://www.linkedin.com/in/robin-tavily/"},
                ],
                "rejected": [], "match_reason": "", "errors": [],
            }

    fake.TavilyError = TavilyError
    fake.TavilyClient = TavilyClient
    return fake, state


def build_fake_serp(fail: bool = False, unreliable: bool = False,
                    jobs: bool = True,
                    ) -> Tuple[types.ModuleType, Dict[str, Any]]:
    """Stand-in for scripts/serp_client.

    The real client's transports and parsers are covered by
    scripts/smoke_serp_client.py against captured SerpAPI payloads. What this
    fake exists to test is WF13's half: that the provider is recorded in
    org_sources, that its people reach org_people and the graph, and that an
    unreliable transport is labelled rather than read as "no presence".
    """
    state: Dict[str, Any] = {"queries": [], "ctor": {}, "jobs_calls": []}
    fake = types.ModuleType("serp_client")

    class SerpError(Exception):
        pass

    class SerpClient:
        def __init__(self, **kwargs: Any) -> None:
            state["ctor"] = kwargs

        def organization_profile(self, name: str, role_keywords: Any = None,
                                 identity: Any = None, match_min: Any = None,
                                 ) -> Dict[str, Any]:
            state["queries"].append(name)
            state.setdefault("identities", []).append(identity)
            if fail:
                raise SerpError("SerpAPI returned HTTP 503")
            if unreliable:
                return {"matched": False, "source": "bing", "reliable": False,
                        "query": name, "profile": {}, "related": [], "people": [],
                        "mentions": [], "errors": ["Bing returned no parseable results"]}
            return {
                "matched": True, "source": "serpapi", "reliable": True, "query": name,
                "profile": {"id": "example-fixture", "name": "Example Corp",
                            "industries": [], "description": "Example Corp | 4200 followers",
                            "site": "", "area": "", "address": "", "country": "",
                            "size_category": "",
                            "profile_url": "https://www.linkedin.com/company/example-fixture/"},
                "related": [{"name": "Example Cloud", "kind": "unit",
                             "url": "https://www.linkedin.com/company/example-cloud/"}],
                "mentions": [{"name": "Reseller Ltd", "kind": "mention", "url": ""}],
                "people": [
                    {"name": "Dana Webb", "job_title": "Senior Systems Administrator",
                     "employer": "Example Corp", "location": "Denver",
                     "education": "", "technologies": ["Active Directory", "Azure"],
                     "url": "https://www.linkedin.com/in/dana-webb-example/"},
                    {"name": "Sam Ortiz", "job_title": "Security Engineer",
                     "employer": "Example Corp", "location": "", "education": "",
                     "technologies": [], "url": "https://www.linkedin.com/in/sam-ortiz-example/"},
                    # The two shapes that made "People & Positions (34)" wrong.
                    # A quoted company-name search returns both, and neither is
                    # an employee: one works somewhere else, one named nobody.
                    {"name": "Pat Vendor", "job_title": "Account Executive",
                     "employer": "Globex Industries", "location": "", "education": "",
                     "technologies": [], "url": "https://www.linkedin.com/in/pat-vendor/"},
                    {"name": "Chris Noise", "job_title": "Recruiter",
                     "employer": "", "location": "", "education": "",
                     "technologies": [], "url": "https://www.linkedin.com/in/chris-noise/"},
                ],
                "errors": [],
            }

        def jobs(self, company: str, identity: Any = None, country: str = "",
                 max_rows: int = 60) -> Dict[str, Any]:
            """The open-roles leg. Already employer-gated by the real client."""
            state["jobs_calls"].append({"company": company, "country": country,
                                        "identity": identity, "max_rows": max_rows})
            if not jobs:
                return {"rows": [], "refused": [], "transport": "", "errors": []}
            return {
                "transport": "google_jobs",
                "rows": [
                    {"title": "Senior Systems Administrator", "company": "Example Corp",
                     "location": "Denver, CO", "via": "LinkedIn", "posted": "3 days ago",
                     "url": "https://example.test/j/1", "employer_score": 100},
                    {"title": "Security Engineer", "company": "Example Corporation",
                     "location": "Remote", "via": "Indeed", "posted": "",
                     "url": "https://example.test/j/2", "employer_score": 95},
                ],
                # Kept and surfaced, never dropped: a card full of refusals is
                # how an operator sees the target was identified wrongly.
                "refused": [
                    {"title": "Java Developer", "company": "Globex Industries",
                     "location": "Austin, TX", "via": "Glassdoor", "posted": "",
                     "url": "", "employer_score": 0, "verdict": "other"},
                ],
                "errors": [],
            }

    fake.SerpError = SerpError      # type: ignore[attr-defined]
    fake.SerpClient = SerpClient    # type: ignore[attr-defined]
    return fake, state


# What site_rag returns when the campaign egress cannot reach the target at all:
# no HTTP response ever arrived. Kept verbatim-ish rather than referencing the
# real module, because this file stubs site_rag out -- the wording itself is
# pinned by scripts/smoke_site_rag.py. WF13's job is to carry the distinction
# through instead of flattening it into 'no_match'.
SITE_UNREACHABLE_MESSAGE = (
    "Nothing was fetched: every request to example.com over the campaign proxy "
    "(socks5h://proxy.local:1080) failed at the transport layer -- a connect or "
    "read timeout, with no HTTP response at all. The site was NOT REACHED, "
    "which is not the same as the site having nothing on it.")


def build_fake_site(fail: bool = False, unreachable: bool = False
                    ) -> Tuple[types.ModuleType, Dict[str, Any]]:
    """Stand-in for scripts/site_rag. The crawler itself is covered by
    scripts/smoke_site_rag.py against a synthetic site."""
    state: Dict[str, Any] = {"calls": []}
    fake = types.ModuleType("site_rag")

    def crawl_and_index(domain: str, **kwargs: Any) -> Dict[str, Any]:
        state["calls"].append({"domain": domain, **kwargs})
        if fail:
            raise RuntimeError("crawl exploded")
        if unreachable:
            return {
                "matched": False, "source": "website", "domain": domain,
                "profile": {}, "people": [], "technologies": [], "partners": [],
                "units": [], "offices": [],
                "pages_crawled": 0, "pages_refused": 0, "refused_sample": [],
                "chunks_indexed": 0, "collection": "company_site__smoke-sketch",
                "blocked": False, "unreachable": True,
                "empty_kind": "site_unreachable",
                "empty_message": SITE_UNREACHABLE_MESSAGE,
                "errors": ["egress preflight failed for https://example.com/: "
                           "no response within 10s"],
            }
        return {
            "matched": True, "source": "website", "domain": domain,
            "profile": {"name": "Example Corp", "description": "We make widgets.",
                        "industry": "Manufacturing", "address": "1 Main St, Denver"},
            "people": [
                {"name": "Jane Roe", "job_title": "Chief Technology Officer",
                 "specialty": "Executive", "source": "website",
                 "site_named": True, "site_evidence": "jsonld"},
                # Also returned by the SERP provider -- must not duplicate, and
                # must UPGRADE that row rather than being skipped: being named on
                # the company's own site is the strongest non-AD evidence there is.
                {"name": "Dana Webb", "job_title": "Sysadmin", "source": "website",
                 "site_named": True, "site_evidence": "llm"},
            ],
            "technologies": ["Terraform", "Linux"],
            "partners": ["Globex"],
            "units": ["Widget Division"],
            "offices": ["Denver, CO"],
            "pages_crawled": 7, "pages_refused": 3,
            "refused_sample": ["https://offsite.example.net/x"],
            "chunks_indexed": 41, "collection": "company_site__smoke-sketch",
            "errors": [],
        }

    fake.crawl_and_index = crawl_and_index   # type: ignore[attr-defined]
    return fake, state


def build_fake_edgar(matched: bool = True, fail: bool = False
                     ) -> Tuple[types.ModuleType, Dict[str, Any]]:
    """Stand-in for scripts/edgar_client.

    The client's scoring, Exhibit 21 parsing and refusal logic are covered by
    scripts/smoke_edgar_client.py. What this tests is WF13's half: that EDGAR
    OVERWRITES the fields it is authoritative about, that its filed
    subsidiaries join org_related, and that a no_match is not an error.
    """
    state: Dict[str, Any] = {"queries": [], "ctor": {}}
    fake = types.ModuleType("edgar_client")

    class EdgarError(Exception):
        pass

    class EdgarClient:
        def __init__(self, **kwargs: Any) -> None:
            state["ctor"] = kwargs

        def organization_profile(self, name: str, aliases: Any = None) -> Dict[str, Any]:
            state["queries"].append(name)
            state.setdefault("aliases", []).append(list(aliases or []))
            if fail:
                raise EdgarError("SEC returned 403")
            if not matched:
                return {"matched": False, "source": "sec-edgar", "query": name,
                        "profile": {}, "related": [],
                        "candidates": [{"cik": "0000000002", "name": "EXAMPLE HARBOR CORP",
                                        "ticker": "EXHB", "score": 64, "via": "company_tickers"}],
                        "filing": {},
                        "errors": ["closest SEC registrant 'EXAMPLE HARBOR CORP' (CIK "
                                   "0000000002) scored 64, below the 72 match floor "
                                   "\u2014 not adopted. Set Primary Target to the exact "
                                   "legal name if this is the right company."]}
            return {
                "matched": True, "source": "sec-edgar", "query": name,
                "profile": {
                    "cik": "0009999999", "name": "EXAMPLE HOLDING CORP",
                    "sic": "7372", "industry": "Services-Prepackaged Software",
                    "entity_type": "operating", "state_of_incorporation": "DE",
                    "tickers": ["EXHC"], "exchanges": ["Nasdaq"],
                    "former_names": ["EXAMPLE WIDGETS INC"],
                    "address": "1 Main St, Denver, CO, 80202", "phone": "303-555-0100",
                    "ein": "001234567", "fiscal_year_end": "1231",
                    "profile_url": "https://www.sec.gov/cgi-bin/browse-edgar?CIK=0009999999",
                    "match_score": 95,
                },
                "related": [
                    {"name": "Example Ireland Ltd", "jurisdiction": "Ireland",
                     "kind": "subsidiary", "source": "sec-edgar"},
                    # Also returned by hh.ru -- must not duplicate.
                    {"name": "Example Delivery", "jurisdiction": "Delaware",
                     "kind": "subsidiary", "source": "sec-edgar"},
                ],
                "candidates": [{"cik": "0009999999", "name": "EXAMPLE HOLDING CORP",
                                "ticker": "EXHC", "score": 95, "via": "company_tickers"}],
                "filing": {"form": "10-K", "accession": "0000000000-26-000001",
                           "date": "2026-07-29",
                           "document": "https://www.sec.gov/Archives/edgar/data/9999999/x/ex21.htm"},
                "errors": [],
            }

    fake.EdgarError = EdgarError        # type: ignore[attr-defined]
    fake.EdgarClient = EdgarClient      # type: ignore[attr-defined]
    return fake, state


def build_fake_settings() -> types.ModuleType:
    fake = types.ModuleType("spotter_settings")

    def resolve_many(_names: List[str]) -> Dict[str, int]:
        return {
            "BUCKET_PROBE_MAX_CANDIDATES": 0,
            "BUCKET_PROBE_CONCURRENCY": 1,
            "BUCKET_PROBE_TIMEOUT": 1,
            "BUCKET_PROBE_MAX_SECONDS": 5,
            "BUCKET_ALERT_MIN_SCORE": 60,
            "THC_SUBDOMAIN_LIMIT": 5,
            "THC_RDNS_MAX_IPS": 1,
            "THC_TIMEOUT": 2,
            "FLARE_DOMAIN_MAX_CREDS": 100,
            "FLARE_DOMAIN_PAGE_SIZE": 100,
            "FLARE_DOMAIN_LIST_CAP": 50,
            # Deliberately tiny so the cap is crossed by a fixture small enough to
            # read. Production default is 500.
            "FLARE_DOMAIN_MATCH_CAP": 3,
            "FLARE_DOMAIN_PROMOTE": 0,
            "HH_MAX_EMPLOYERS": 25,
            "HH_MAX_VACANCIES": 100,
            "HH_MAX_VACANCY_DETAILS": 5,
            "HH_TIMEOUT": 20,
            "SERP_MAX_SEARCHES": 8,
            "SERP_TIMEOUT": 20,
            "SITE_MAX_PAGES": 60,
            "SITE_MAX_SECONDS": 180,
            "EDGAR_MAX_REQUESTS": 12,
            "EDGAR_TIMEOUT": 20,
        }

    fake.resolve_many = resolve_many  # type: ignore[attr-defined]
    return fake


def build_fake_hh(fail: bool = False) -> Tuple[types.ModuleType, Dict[str, Any]]:
    """Stand-in for scripts/hh_client.

    The real client's HTTP and state-blob parsing are covered by
    scripts/smoke_hh_client.py against captured hh.ru pages. What this fake
    exists to test is the half that lives in WF13: the company-name seed, the
    aggregation into org_* keys, the region gate, and the Company graph writes.
    """
    state: Dict[str, Any] = {"queries": [], "ctor": {}, "vacancies": []}
    fake = types.ModuleType("hh_client")

    class HHError(Exception):
        pass

    class HHClient:
        def __init__(self, **kwargs: Any) -> None:
            state["ctor"] = kwargs

        def organization_profile(self, name: str, max_vacancies: Any = None,
                                 max_details: Any = None, identity: Any = None,
                                 match_min: Any = None, max_probes: Any = None,
                                 ) -> Dict[str, Any]:
            # `identity` and `match_min` are recorded, not just tolerated: WF13
            # wiring them is the whole fix, and a stub that silently swallowed
            # them would let a regression that stops passing them pass here.
            state["queries"].append({"name": name, "max_vacancies": max_vacancies,
                                     "max_details": max_details,
                                     "identity": identity, "match_min": match_min})
            if fail:
                return {"matched": False, "source": "hh.ru-scrape", "profile": {},
                        "related": [], "vacancies": [], "facets": {}, "details": [],
                        "errors": ["hh.ru found no employer matching %r" % name]}
            out = {
                "matched": True,
                "source": "hh.ru-scrape",
                "profile": {
                    "id": "100001", "name": "Example Holding",
                    "industries": ["Information Technology"],
                    "description": "An example holding company.",
                    "site": "https://example.com", "area": "Moscow",
                    "address": "Moscow, Primernaya ulitsa 1", "country": "RU",
                    "size_category": "MORE_THAN_5000", "it_accredited": True,
                    "trusted": True, "has_divisions": True, "rating": 4.4,
                    "open_vacancies": 350,
                    "profile_url": "https://hh.ru/employer/100001",
                },
                "related": [
                    {"id": "2", "name": "Example Delivery", "vacancies_open": 80,
                     "url": "https://hh.ru/employer/2"},
                ],
                "vacancies": [
                    {"id": "10", "title": "Системный администратор",
                     "department": "Example Infrastructure", "division": "1",
                     "area": "Moscow", "experience": "between1And3",
                     "address": {"label": "Moscow, Primernaya ulitsa 1", "city": "Moscow",
                                 "metro": "Primernaya"},
                     "roles": ["96"], "url": "https://hh.ru/vacancy/10"},
                    {"id": "11", "title": "Финансовый аналитик",
                     "department": "Fintech", "division": "2", "area": "Moscow",
                     "experience": "between3And6",
                     "address": {"label": "Moscow, Primernaya ulitsa 1", "city": "Moscow"},
                     "roles": ["145"], "url": "https://hh.ru/vacancy/11"},
                ],
                "facets": {
                    "roles": [{"name": "Программист, разработчик", "count": 28},
                              {"name": "Системный администратор", "count": 12}],
                    "areas": [{"name": "Moscow", "count": 169}],
                },
                "details": [
                    {"id": "10", "title": "Системный администратор",
                     "url": "https://hh.ru/vacancy/10",
                     "description": "Active Directory experience required.",
                     "key_skills": ["Active Directory", "VMware"],
                     "contacts": {"hidden": False, "name": "Petr Petrov",
                                  "email": "hr@example.ru", "phones": ["74951234567"]}},
                    {"id": "11", "title": "Финансовый аналитик",
                     "url": "https://hh.ru/vacancy/11", "description": "",
                     "key_skills": ["Excel"],
                     "contacts": {"hidden": True, "name": "", "email": "", "phones": []}},
                ],
                "errors": [],
            }
            # Recorded so an assertion can tell a REAL vacancy title from a
            # roster job title that merely looks like one. The facet vocabulary
            # flattens these away, so org_roles alone is not the whole set.
            state["vacancies"] = out["vacancies"]
            return out

    fake.HHError = HHError            # type: ignore[attr-defined]
    fake.HHClient = HHClient          # type: ignore[attr-defined]
    return fake, state


@contextmanager
def patched_modules(modules: Dict[str, types.ModuleType]):
    old = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        yield
    finally:
        for name, value in old.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


@contextmanager
def patched_env(values: Dict[str, str]):
    old = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def assert_true(condition: bool, message: str, detail: Any = None) -> None:
    if not condition:
        suffix = f": {detail!r}" if detail is not None else ""
        raise AssertionError(message + suffix)


def run_smoke_case(code: str, payload: Dict[str, Any], thc_mode: str = "normal",
                   seed_tech: bool = False, flare_creds: int = 0,
                   individuals: int = 0,
                   extra_env: Dict[str, str] | None = None,
                   fofa_mode: str = "normal",
                   shodan_mode: str = "normal",
                   hh_fail: bool = False,
                   serp_fail: bool = False,
                   serp_unreliable: bool = False,
                   serp_jobs: bool = True,
                   site_fail: bool = False,
                   site_unreachable: bool = False,
                   edgar_matched: bool = True,
                   edgar_fail: bool = False,
                   titled_people: bool = False,
                   ownership: str = "",
                   hh_state_out: Dict[str, Any] | None = None,
                   tavily_fail: bool = False,
                   tavily_matched: bool = True,
                   tavily_key: bool = True,
                   ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    fake_requests, request_state = build_fake_requests(
        thc_mode, flare_creds, fofa_mode, shodan_mode)
    # certcreep talks to crt.sh via urllib, not requests. Leave it unstubbed and
    # every case in this offline test waits on a live CT dump.
    fake_certcreep = types.ModuleType("certcreep")
    import certcreep as real_certcreep
    fake_certcreep.source_for_domain = real_certcreep.source_for_domain
    certcreep_calls: list[dict[str, Any]] = []

    def _collect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        certcreep_calls.append({"args": args, "kwargs": kwargs})
        return {"records": [], "count": 0, "errors": []}

    fake_certcreep.collect = _collect
    fake_flowsint, flowsint_state = build_fake_flowsint(seed_tech, individuals,
                                                        titled_people, ownership)
    fake_settings = build_fake_settings()
    fake_hh, hh_state = build_fake_hh(hh_fail)
    fake_serp, serp_state = build_fake_serp(serp_fail, serp_unreliable, serp_jobs)
    fake_site, site_state = build_fake_site(site_fail, site_unreachable)
    fake_edgar, edgar_state = build_fake_edgar(edgar_matched, edgar_fail)
    fake_tavily, tavily_state = build_fake_tavily(tavily_fail, tavily_matched)
    if hh_state_out is not None:
        hh_state_out.clear()
        hh_state_out.update({"_ref": hh_state, "_serp": serp_state,
                             "_site": site_state, "_edgar": edgar_state,
                             "_tavily": tavily_state})
    env = {"FLOWSINT_SKETCH_ID": "fallback-sketch", "THC_IP_BASE_URL": "https://ip.thc.org",
           "SHODAN_API_KEY": "fake-key", "FOFA_API_KEY": "fake-fofa-key",
           # The open-roles leg reads this directly to decide whether to run at
           # all -- it is a secret, so it is not a Configuration-panel key and
           # never reaches the settings bag.
           "SERP_API_KEY": "fake-serp-key"}
    # Same reasoning as SERP_API_KEY: read straight from the environment by the
    # provider gate, because it is a secret and never a Configuration-panel key.
    if tavily_key:
        env["TAVILY_API_KEY"] = "fake-tavily-key"
    env.update(extra_env or {})
    with patched_modules({
        "requests": fake_requests,
        "flowsint_client": fake_flowsint,
        "spotter_settings": fake_settings,
        "hh_client": fake_hh,
        "serp_client": fake_serp,
        "site_rag": fake_site,
        "edgar_client": fake_edgar,
        "tavily_client": fake_tavily,
        "certcreep": fake_certcreep,
        # job_titles is a pure-function module with no I/O -- use the real one so
        # a change to the specialty table breaks this test rather than sliding by.
        "job_titles": importlib.import_module("job_titles"),
    }):
        with patched_env(env):
            out = run_n8n_python_code(code, [{"json": {"body": payload}}])
    assert_true(len(out) == 1, "WF13 should return one item", out)
    result = out[0]["json"]
    assert_true(not result.get("error"), "WF13 returned an error", result.get("error"))
    request_state["certcreep_calls"] = certcreep_calls
    return result, request_state, flowsint_state


def main() -> None:
    code = load_code_node()
    payload = {
        "domain": "example.com",
        "campaign_id": "smoke-campaign",
        "sketch_id": "smoke-sketch",
        "sources": ["assets", "shodan"],
        "proxy": {"enabled": True, "type": "socks5", "socks_url": "socks5h://proxy.local:1080"},
        "opsec": {"user_agent": "SPOTTER-Smoke/1.0", "dns_resolvers": ["https://dns.google/resolve"]},
    }

    result, request_state, flowsint_state = run_smoke_case(code, payload)
    cc_calls = request_state.get("certcreep_calls") or []
    assert_true(cc_calls and cc_calls[0]["kwargs"].get("source") == "both",
                "a non-.ru domain must query CertCreep with both CT sources", cc_calls)
    ru_result, ru_state, _ru_graph = run_smoke_case(code, {**payload, "domain": "example.ru"})
    ru_calls = ru_state.get("certcreep_calls") or []
    assert_true(ru_calls and ru_calls[0]["kwargs"].get("source") == "precert",
                "a .ru TLD must query CertCreep with --source precert only", ru_calls)
    assert_true(not any(str(err).startswith("CertCreep") for err in (ru_result.get("errors") or [])),
                "the .ru CertCreep call must not fail closed", ru_result.get("errors"))
    assert_true(result.get("country") == "US", "THC fallback country should be ISO-2", result.get("country"))
    assert_true(result.get("asn") == "AS64500", "THC ASN should be normalized with AS prefix", result.get("asn"))
    assert_true(result.get("thc_budget_remaining") == 248, "latest THC budget should be retained", result.get("thc_budget_remaining"))
    assert_true(result.get("thc_cnames") == ["cdn-thirdparty.example.net"], "THC CNAME rows should be retained", result.get("thc_cnames"))
    assert_true("alpha.example.com" in result.get("subdomains", []), "THC-only subdomain should enter capped subdomain list", result.get("subdomains"))
    assert_true(result.get("subdomain_mix", {}).get("selected_counts", {}).get("thc", 0) >= 1,
                "subdomain_mix should record THC contribution", result.get("subdomain_mix"))

    subdomain_nodes = [n for n in flowsint_state["nodes"] if n["node_type"] == "Subdomain"]
    assert_true(subdomain_nodes, "graph import should create Subdomain nodes", flowsint_state["nodes"])
    assert_true(any(n["properties"].get("fqdn") == "alpha.example.com" and n["properties"].get("parent_domain") == "example.com"
                    for n in subdomain_nodes),
                "THC-only Subdomain node should carry required graph properties", subdomain_nodes)
    assert_true(any(e["label"] == "HAS_SUBDOMAIN" for e in flowsint_state["edges"]),
                "graph import should link subdomains to apex WebAsset", flowsint_state["edges"])
    service_nodes = [n for n in flowsint_state["nodes"] if n["node_type"] == "Service"]
    assert_true(service_nodes, "graph import should create a Service node from Shodan", flowsint_state["nodes"])
    service_by_ip = {n["properties"].get("ip"): n for n in service_nodes}
    assert_true(service_by_ip.get("203.0.113.10", {}).get("properties", {}).get("host_id") == "dev-1",
                "Service should prefer the matched AD device as host_id", service_by_ip.get("203.0.113.10"))
    assert_true(service_by_ip.get("203.0.113.10", {}).get("properties", {}).get("cpe") == "cpe:/a:nginx:nginx:1.18",
                "InternetDB Service should carry a primary CPE", service_by_ip.get("203.0.113.10"))
    assert_true("cpe:/a:nginx:nginx:1.18" in json.loads(service_by_ip.get("203.0.113.10", {}).get("properties", {}).get("cpes", "[]")),
                "InternetDB Service should carry the full CPE list", service_by_ip.get("203.0.113.10"))
    assert_true(service_by_ip.get("203.0.113.11", {}).get("properties", {}).get("cpe") == "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
                "Full Shodan Service should preserve Shodan CPEs", service_by_ip.get("203.0.113.11"))
    assert_true(any(e["source"] == "dev-1" and e["target"] == service_nodes[0]["id"] and e["label"] == "EXPOSES_SERVICE"
                    for e in flowsint_state["edges"]),
                "matched AD device should link to external Service with EXPOSES_SERVICE", flowsint_state["edges"])
    assert_true(result.get("graph_import", {}).get("service_device_links") == 1,
                "graph_import should count Service-to-device correlations", result.get("graph_import"))

    # ── Perimeter technologies ────────────────────────────────────────────────
    # Before this, every product string and CPE Shodan and FOFA returned died in a
    # JSON blob on the Service node: WF12, WF14 and WF04 all key on Technology, so
    # the whole external estate was invisible to Tech Intel and to attack-path
    # scoring.
    tech_nodes = [n for n in flowsint_state["nodes"] if n["node_type"] == "Technology"]
    assert_true(tech_nodes, "graph import should create Technology nodes", flowsint_state["nodes"])
    # A Technology node without a non-empty name makes GET /graph return 500 for
    # the ENTIRE sketch: the serializer strips '' BEFORE validating, so the
    # retry-without-invalid-fields path cannot recover a MISSING required field.
    # check_required_builtin_props cannot catch this in WF13 -- every write here
    # goes through upsert(properties=props), so its regex finds no literal
    # node_type= and skips the call. This assertion is the guard.
    assert_true(all((n["properties"].get("name") or "").strip() for n in tech_nodes),
                "every Technology node must carry a non-empty name", tech_nodes)
    # WF04's EXPLOIT_INTERNET_BONUS is derived from this exact string.
    assert_true(all(n["properties"].get("source") == "domain-recon" for n in tech_nodes),
                "Technology nodes must carry source='domain-recon'", tech_nodes)
    tech_by_name = {n["properties"]["name"]: n for n in tech_nodes}

    # Product/CPE half.
    assert_true("Apache httpd" in tech_by_name,
                "the paid-Shodan product banner should become a Technology", sorted(tech_by_name))
    _ap = tech_by_name["Apache httpd"]
    assert_true(_ap["properties"].get("version") == "2.4.58",
                "Apache Technology should carry the observed version", _ap)
    # nodeLabel is the server-side MERGE key (label, nodeLabel, sketch_id), so a
    # version in it forks the node on every new banner string.
    assert_true(_ap["label"] == "Apache httpd",
                "Technology nodeLabel must be the version-free canonical name", _ap["label"])
    # InternetDB supplies a CPE and no product at all, so the name has to come
    # from the CPE -- and 'cpe:/a:nginx:nginx' must NOT become 'nginx nginx'.
    assert_true("nginx" in tech_by_name,
                "a CPE-only observation should still yield a named Technology", sorted(tech_by_name))
    assert_true(tech_by_name["nginx"]["properties"].get("confidence") == "high",
                "a CPE-derived Technology is high confidence", tech_by_name["nginx"])
    assert_true(tech_by_name["nginx"]["properties"].get("cpe") == "cpe:/a:nginx:nginx:1.18",
                "a CPE-derived Technology must keep the CPE, or WF14 falls back to "
                "keyword search and WF04 halves the score", tech_by_name["nginx"])

    # Carrier edges.
    _svc_ids = {n["id"] for n in service_nodes}
    _tech_ids = {n["id"] for n in tech_nodes}
    _edges = flowsint_state["edges"]
    assert_true(any(e["label"] == "IMPLEMENTED_IN" and e["source"] in _svc_ids
                    and e["target"] in _tech_ids for e in _edges),
                "Service should link to Technology with IMPLEMENTED_IN "
                "(the nmap shape, upload_router._parse_nmap)", _edges)
    # dev-1 matches 203.0.113.10 (the InternetDB/nginx host) and does NOT match
    # 203.0.113.11, so USES_TECH must reach nginx and not Apache.
    assert_true(any(e["label"] == "USES_TECH" and e["source"] == "dev-1"
                    and e["target"] == tech_by_name["nginx"]["id"] for e in _edges),
                "a matched AD device should link to its Technology with USES_TECH "
                "(the only tech edge WF12's single-hop host loop can see)", _edges)
    assert_true(not any(e["label"] == "USES_TECH" and e["source"] == "dev-1"
                        and e["target"] == _ap["id"] for e in _edges),
                "an unmatched host's Technology must NOT be linked to an AD device", _edges)
    # MANAGES is ownership, not hosting. WF04 excludes it from CARRIER_LABELS and
    # pins that exclusion; a MANAGES edge onto a Technology would reintroduce the
    # "charge a person with Akamai's CVEs" failure by another route.
    assert_true(not any(e["target"] in _tech_ids and e["label"] == "MANAGES" for e in _edges),
                "Technology nodes must never receive ownership edges", _edges)
    # Several observations fold onto one canonical Technology (a banner and a CPE
    # for the same software), and each used to re-write the same edge.
    _te = [(e["label"], e["source"], e["target"]) for e in _edges
           if e["label"] in ("USES_TECH", "IMPLEMENTED_IN")]
    assert_true(len(_te) == len(set(_te)),
                "technology carrier edges must not be written twice", _te)

    # DNS-inferred platform half.
    assert_true("Microsoft 365 Exchange Online" in tech_by_name,
                "MX should infer the mail platform", sorted(tech_by_name))
    assert_true(sum(1 for n in tech_nodes
                    if n["properties"]["name"] == "Microsoft 365 Exchange Online") == 1,
                "two MX hosts for one platform must fold into ONE Technology node", tech_nodes)
    assert_true("Cloudflare CDN and WAF" in tech_by_name,
                "the apex CNAME should infer the CDN/WAF", sorted(tech_by_name))
    assert_true("Amazon Route 53" in tech_by_name,
                "NS should infer the DNS platform even though 'awsdns' is mid-label, "
                "which an endswith() match would miss", sorted(tech_by_name))
    # 'Example Transit' is in no ASN table, and an unrecognised hosting network is
    # not a technology finding.
    assert_true(not any("Transit" in k for k in tech_by_name),
                "an unrecognised asn_org must not mint a Technology", sorted(tech_by_name))
    _plat = tech_by_name["Cloudflare CDN and WAF"]
    assert_true(not _plat["properties"].get("cpe"),
                "a DNS-inferred platform must not invent a CPE -- it can only ever "
                "keyword-match, and WF04 halves that basis", _plat)
    # Platform tech hangs off the apex WebAsset. A Service edge would put a CDN's
    # CVEs exactly two carrier hops from an AD device, which is the failure the
    # MANAGES exclusion exists to prevent arriving through a carrier instead.
    assert_true(any(e["label"] == "USES_TECH" and e["target"] == _plat["id"]
                    and e["source"] not in _svc_ids for e in _edges),
                "platform Technology should attach to the apex WebAsset", _edges)
    assert_true(not any(e["target"] == _plat["id"] and e["source"] in _svc_ids
                        for e in _edges),
                "platform Technology must NOT attach to a Service node", _edges)

    # Response contract.
    assert_true(result.get("graph_import", {}).get("technologies", 0) >= 4,
                "graph_import should count created Technology nodes", result.get("graph_import"))
    assert_true(result.get("graph_import", {}).get("tech_edges", 0) >= 2,
                "graph_import should count new technology edges", result.get("graph_import"))
    assert_true(any(t.get("basis") == "cpe" for t in result.get("technologies", [])),
                "technologies[] must record how each product was identified",
                result.get("technologies"))

    # ── Which host is this product ON? ───────────────────────────────────────
    # Every observation writes its own carrier edges, so the GRAPH always knew.
    # The response did not: observations fold onto one canonical row and only the
    # first one reached technologies[], which is the only thing the operator
    # dashboard can render the perimeter from.
    _tech_row = {t["name"]: t for t in result.get("technologies", [])}
    _ap_row = _tech_row.get("Apache httpd", {})
    assert_true({h.get("ip") for h in _ap_row.get("hosts", [])}
                == {"203.0.113.11", "203.0.113.15"},
                "one product on two addresses must ship BOTH hosts, not just the "
                "first observation", _ap_row)
    assert_true(_ap_row.get("host_count") == 2,
                "host_count must state how many distinct (ip, port) pairs were "
                "seen, so a capped list is never read as the population", _ap_row)
    # The flat keys predate hosts[] and several readers still use them.
    assert_true(_ap_row.get("ip") == "203.0.113.11" and _ap_row.get("port") == 8443,
                "the flat ip/port keys must keep the first observation", _ap_row)
    _ng_row = _tech_row.get("nginx", {})
    assert_true([h.get("hostnames") for h in _ng_row.get("hosts", [])]
                == [["www.example.com"]],
                "a host ships the name its source reported for it -- an operator "
                "recognises www.example.com, not 203.0.113.10", _ng_row)
    assert_true([h.get("devices") for h in _ng_row.get("hosts", [])] == [["WWW01"]],
                "a host that matched an AD device names it, so the perimeter "
                "product and the internal host read as one system", _ng_row)
    assert_true(all(h.get("devices") == [] for h in _ap_row.get("hosts", [])),
                "an unmatched address must not borrow another host's AD device",
                _ap_row)
    assert_true(any(t.get("basis") == "mx" for t in result.get("platform_tech", [])),
                "platform_tech[] must record which DNS record inferred it",
                result.get("platform_tech"))
    assert_true(all(t.get("cve_match_limit") for t in result.get("platform_tech", [])),
                "platform_tech[] must declare that it can only keyword-match",
                result.get("platform_tech"))

    thc_gets = [g for g in request_state["gets"] if urlparse(g["url"]).netloc == "ip.thc.org"]
    assert_true(len(thc_gets) == 3, "expected subdomain, CNAME, and one rDNS THC lookup", thc_gets)
    assert_true(all(g["kwargs"].get("proxies", {}).get("https") == "socks5h://proxy.local:1080" for g in thc_gets),
                "THC lookups should use the OPSEC proxy envelope", thc_gets)
    doh_gets = [g for g in request_state["gets"] if urlparse(g["url"]).netloc == "dns.google"]
    assert_true(doh_gets and all(g["kwargs"].get("proxies", {}).get("https") == "socks5h://proxy.local:1080" for g in doh_gets),
                "DoH lookups should use the same proxy envelope", doh_gets)
    shodan_gets = [g for g in request_state["gets"]
                   if urlparse(g["url"]).netloc in {"api.shodan.io", "internetdb.shodan.io"}]
    assert_true(any(urlparse(g["url"]).netloc == "api.shodan.io" for g in shodan_gets)
                and any(urlparse(g["url"]).netloc == "internetdb.shodan.io" for g in shodan_gets),
                "a shodan run must call both the paid API and InternetDB", shodan_gets)
    assert_true(all(g["kwargs"].get("proxies", {}).get("https") == "socks5h://proxy.local:1080"
                    for g in shodan_gets),
                "Shodan lookups must use the campaign proxy", shodan_gets)
    assert_true(all((g["kwargs"].get("headers") or {}).get("User-Agent") == "SPOTTER-Smoke/1.0"
                    for g in shodan_gets),
                "Shodan lookups must send the campaign user-agent", shodan_gets)
    assert_true((result.get("shodan_api_status") or {}).get("state") == "ok",
                "a shodan run with matches must record state ok",
                result.get("shodan_api_status"))

    # ── Perimeter technology dedup against a pre-existing node ───────────────
    seeded, _, seeded_state = run_smoke_case(code, payload, seed_tech=True)
    _seeded_tech = [n for n in seeded_state["nodes"] if n["node_type"] == "Technology"]
    assert_true(not any(n["properties"].get("name") == "Apache httpd" for n in _seeded_tech),
                "an existing lowercase 'technology' Apache node must be UPDATED, not "
                "re-created -- the dedup lookup is an exact string test, so the case "
                "fold is what prevents a duplicate", _seeded_tech)
    _edits = [e for e in seeded_state["edits"] if e["id"] == "tech-1"]
    assert_true(_edits, "the existing Technology should be patched via edit_node",
                seeded_state["edits"])
    # An unprefixed key writes to a dead top-level namespace that no reader looks
    # at, and every layer still reports success.
    assert_true(all(k.startswith("nodeProperties.") for e in _edits for k in e["updates"]),
                "every Technology patch key must be nodeProperties.-prefixed", _edits)
    # edit_node is SET n += $props, so a blank genuinely overwrites a good value.
    assert_true(all(v not in ("", None) for e in _edits for v in e["updates"].values()),
                "a Technology patch must never blank an existing value", _edits)
    # Relabelling nmap's source would make WF04 read internal software as
    # internet-facing (it derives that from source == 'domain-recon').
    assert_true(all("nodeProperties.source" not in e["updates"] for e in _edits),
                "must not overwrite another writer's source", _edits)
    assert_true(any(e["updates"].get("nodeProperties.is_internet_exposed") is True
                    for e in _edits),
                "an existing Technology now seen from the internet must be flagged", _edits)
    assert_true(any(e["updates"].get("nodeProperties.also_seen_by") == "domain-recon"
                    for e in _edits),
                "provenance must record that domain-recon also saw it", _edits)
    assert_true(seeded.get("graph_import", {}).get("technologies", 99) <
                result.get("graph_import", {}).get("technologies", 0),
                "an updated node must not be counted as created", seeded.get("graph_import"))

    # A perimeter appliance must fold onto its canonical name and be flagged
    # high-value, which is what puts it in Tech Intel's Vulnerable Technology panel
    # before WF14 has attached any CVE (WF12 gates that panel on
    # cve_count or is_high_value or exploit_available).
    assert_true("Citrix NetScaler ADC" in tech_by_name,
                "a 'NetScaler' banner must canonicalise to Citrix NetScaler ADC",
                sorted(tech_by_name))
    assert_true(tech_by_name["Citrix NetScaler ADC"]["properties"].get("is_high_value") is True,
                "a perimeter appliance must be flagged high-value, or it stays "
                "invisible in Tech Intel until WF14 runs",
                tech_by_name["Citrix NetScaler ADC"])
    assert_true(any(t["name"] == "Citrix NetScaler ADC" and t["is_high_value"]
                    for t in result.get("technologies", [])),
                "technologies[] must carry the high-value flag too",
                result.get("technologies"))

    # ── A product string that canonicalises to nothing ───────────────────────
    # The most dangerous failure in this feature: `name` is REQUIRED on the
    # built-in Technology type, the serializer strips '' BEFORE validating, and one
    # name-less node makes GET /graph return 500 for the ENTIRE sketch. WF01
    # shipped exactly that once. check_required_builtin_props cannot catch it here
    # because every write in this node goes through upsert(properties=props), so
    # its regex finds no literal node_type= and skips the call.
    #
    # FOFA reports '2.4' as a product for one host. Bare dotted digits are stripped
    # as a version tail, so the canonical name is empty and the observation must be
    # DROPPED rather than written with a blank name.
    fofa_run, fofa_reqs, fofa_state = run_smoke_case(code, dict(payload, sources=["shodan", "fofa"]))
    _ft = [n for n in fofa_state["nodes"] if n["node_type"] == "Technology"]
    assert_true(_ft, "the fofa case should still create Technology nodes", fofa_state["nodes"])
    assert_true(all((n["properties"].get("name") or "").strip() for n in _ft),
                "a product string that canonicalises to nothing must yield NO "
                "Technology node, never one with a blank name -- that 500s the "
                "whole sketch", _ft)
    assert_true(all(n["label"].strip() for n in _ft),
                "every Technology nodeLabel must be non-empty -- it is the "
                "server-side MERGE key", _ft)
    assert_true(any(t.get("basis") == "fofa" for t in fofa_run.get("technologies", [])),
                "a FOFA product banner should be recorded with basis 'fofa'",
                fofa_run.get("technologies"))
    assert_true(not any(t.get("name", "").strip() in ("", "2.4")
                        for t in fofa_run.get("technologies", [])),
                "the junk product must not reach the response either",
                fofa_run.get("technologies"))
    # The banner spelling and NVD's CPE product name for IIS differ; both must land
    # on ONE node, or the CPE-accurate half of the estate fragments away from the
    # banner-named half and WF14 spends a separate NVD search on each.
    assert_true("Microsoft IIS" in {t["name"] for t in fofa_run.get("technologies", [])},
                "a FOFA 'Microsoft-IIS/10.0' banner must canonicalise to Microsoft IIS",
                fofa_run.get("technologies"))

    # ── FOFA field entitlements ──────────────────────────────────────────────
    # The outage this pins: FOFA rejects the ENTIRE query, HTTP 200 + error, zero
    # rows, when any ONE requested field is above the account tier. WF13 asked for
    # product/as_organization/lastupdatetime for months, so FOFA never once
    # returned data and the card silently rendered nothing.
    _forbidden = {"product", "as_organization", "lastupdatetime", "country_name"}
    for _fields in fofa_reqs["fofa_fields"]:
        _asked = {c for c in _fields.split(",") if c}
        assert_true(not (_asked & _forbidden),
                    "WF13 must never request a FOFA field this account tier "
                    "forbids -- one of them rejects the whole query",
                    sorted(_asked & _forbidden))

    _fs = fofa_run.get("fofa_status") or {}
    assert_true(_fs.get("state") == "ok",
                "an entitled FOFA account should report state 'ok'", _fs)
    assert_true(_fs.get("attempts") == 1,
                "tier 0 answers an entitled account in ONE call -- more means the "
                "ladder is probing fields it should never ask for", _fs)
    assert_true(fofa_run.get("fofa_results"),
                "the FOFA case should return rows", fofa_run.get("fofa_results"))
    _fr0 = (fofa_run.get("fofa_results") or [{}])[0]
    for _k in ("protocol", "country", "city", "link"):
        assert_true(_fr0.get(_k),
                    f"fofa_results rows must carry '{_k}' -- the card renders it",
                    _fr0)

    # A thinner tier: the richest field set is refused, the ladder drops down and
    # still comes back with real data rather than an empty card.
    _tier0_bad, _t0_reqs, _ = run_smoke_case(
        code, dict(payload, sources=["fofa"]), fofa_mode="forbidden_tier0")
    _fs0 = _tier0_bad.get("fofa_status") or {}
    assert_true(_fs0.get("state") == "ok",
                "a forbidden top tier must fall back to a narrower field set, "
                "not fail the whole FOFA lookup", _fs0)
    assert_true(_fs0.get("attempts") == 2,
                "exactly one retry should be needed to clear one forbidden field",
                _fs0)
    assert_true(_tier0_bad.get("fofa_results"),
                "the fallback tier must still return rows",
                _tier0_bad.get("fofa_results"))

    # Every tier refused: the run must say WHY, because a silent empty card is
    # indistinguishable from a target with no external estate.
    _all_bad, _, _ = run_smoke_case(
        code, dict(payload, sources=["fofa"]), fofa_mode="forbidden_all")
    _fsa = _all_bad.get("fofa_status") or {}
    assert_true(_fsa.get("state") == "error",
                "an entirely refused FOFA must report state 'error'", _fsa)
    assert_true("820001" in str(_fsa.get("detail")),
                "the FOFA error detail must carry the API's own message so the "
                "operator can tell a permission problem from an empty result",
                _fsa)
    assert_true(_fsa.get("attempts") == 3,
                "the ladder should exhaust every tier before giving up", _fsa)
    assert_true(not _all_bad.get("fofa_results"),
                "a refused FOFA returns no rows", _all_bad.get("fofa_results"))

    # ── Source pruning, both directions ──────────────────────────────────────
    # The frontend merges recon records with a shallow spread, so a
    # present-but-empty key BEATS a good previous value. The product half must
    # disappear on a run that gathered none; the DNS half must survive, because
    # base recon always collects it.
    flare_only, _, _ = run_smoke_case(code, dict(payload, sources=["flare"]))
    assert_true("technologies" not in flare_only,
                "technologies must be pruned when neither shodan nor fofa ran",
                sorted(flare_only))
    assert_true(isinstance(flare_only.get("platform_tech"), list),
                "platform_tech must NEVER be pruned -- it comes from base recon DNS",
                sorted(flare_only))
    # fofa_status travels WITH the fofa_* keys. Left unpruned, a shodan-only
    # re-run would shallow-spread a stale status over good FOFA data and the card
    # would explain an emptiness that isn't there.
    assert_true("fofa_status" not in flare_only,
                "fofa_status must be pruned alongside the other fofa_* keys",
                sorted(flare_only))
    assert_true("shodan_api_status" not in flare_only,
                "shodan_api_status must be pruned alongside the other shodan_* keys",
                sorted(flare_only))
    assert_true("shodan_api_status" in result,
                "shodan_api_status must be present on a run that included Shodan",
                sorted(result))
    assert_true("fofa_status" in fofa_run,
                "fofa_status must be present on a run that included FOFA",
                sorted(fofa_run))

    shodan_limited, shodan_limited_reqs, _ = run_smoke_case(code, payload, shodan_mode="429")
    _sl = shodan_limited.get("shodan_api_status") or {}
    assert_true(_sl.get("state") == "rate_limited" and _sl.get("rate_limited") is True,
                "Shodan HTTP 429 must be a rate limit, not an empty result", _sl)
    assert_true(_sl.get("http_status") == 429,
                "the rate-limit status must carry the HTTP status", _sl)
    assert_true(any(urlparse(g["url"]).netloc == "internetdb.shodan.io"
                    for g in shodan_limited_reqs["gets"]),
                "InternetDB must still be queried when the paid API is rate-limited",
                shodan_limited_reqs["gets"])

    shodan_empty, _, _ = run_smoke_case(code, payload, shodan_mode="empty")
    _se = shodan_empty.get("shodan_api_status") or {}
    assert_true(_se.get("state") == "empty" and not _se.get("rate_limited"),
                "a 200 with zero matches is empty, not rate-limited", _se)

    shodan_idb, _, _ = run_smoke_case(code, payload, shodan_mode="idb_429")
    _si = shodan_idb.get("shodan_api_status") or {}
    assert_true(_si.get("rate_limited") is True,
                "an InternetDB 429 stays visible even when the paid API returns rows", _si)

    rate_limited, _, _ = run_smoke_case(code, payload, thc_mode="429")
    assert_true(rate_limited.get("thc_rate_limited") is True,
                "THC 429 should keep the compatibility aggregate true", rate_limited)
    assert_true(rate_limited.get("thc_service_429") is True,
                "THC 429 should set thc_service_429", rate_limited)
    assert_true(rate_limited.get("thc_incomplete_reason") == "service_429",
                "THC 429 should emit a specific incomplete reason", rate_limited)

    budget_stopped, budget_requests, _ = run_smoke_case(code, payload, thc_mode="low_budget")
    assert_true(budget_stopped.get("thc_rate_limited") is True,
                "THC budget guard should keep the compatibility aggregate true", budget_stopped)
    assert_true(budget_stopped.get("thc_budget_guard_stop") is True,
                "THC budget guard should set thc_budget_guard_stop", budget_stopped)
    assert_true(budget_stopped.get("thc_incomplete_reason") == "budget_guard_stop",
                "THC budget guard should emit a specific incomplete reason", budget_stopped)
    budget_thc_gets = [g for g in budget_requests["gets"] if urlparse(g["url"]).netloc == "ip.thc.org"]
    assert_true(len(budget_thc_gets) == 1,
                "THC budget guard should stop before the CNAME/rDNS calls", budget_thc_gets)

    # ── credential-match cap (FLARE_DOMAIN_MATCH_CAP) ────────────────────────
    # This list was uncapped until 2026-09-08, when a large domain's match list
    # helped push one cached recon record past the browser's ~5MB localStorage
    # budget -- which surfaced as "Ensure n8n is running and workflow 13 is
    # imported and active" on a run that had succeeded. The cap must bound the
    # RESPONSE without shrinking the graph import, so both halves are asserted.
    flare_payload = dict(payload, sources=["flare"])
    capped, _, cap_graph = run_smoke_case(
        code, flare_payload, flare_creds=8, individuals=8,
        extra_env={"FLARE_API_KEY": "fake-flare-key"})

    matches = capped.get("credential_matches")
    assert_true(isinstance(matches, list) and len(matches) == 3,
                "credential_matches should be capped to FLARE_DOMAIN_MATCH_CAP (3)", matches)
    assert_true(capped.get("credential_matches_total") == 8,
                "credential_matches_total should report the TRUE match count",
                capped.get("credential_matches_total"))
    assert_true(capped.get("credential_matches_truncated") is True,
                "credential_matches_truncated should flag the cap", capped)
    # Sorted admins-first then by breach count, so the cap keeps the ones that matter.
    assert_true(sum(1 for m in matches if m.get("is_admin")) == 2,
                "both admin matches must survive the cap", matches)
    assert_true([m["email"] for m in matches]
                == ["user0@example.com", "user1@example.com", "user2@example.com"],
                "the kept slice should be the highest-value matches, in sort order",
                [m["email"] for m in matches])

    # The graph import must still see every match: the DomainBreach node's
    # matched_users and one EXPOSED_IN_BREACH edge per matched individual.
    db_nodes = [n for n in cap_graph["nodes"] if n["node_type"] == "DomainBreach"]
    assert_true(len(db_nodes) == 1, "one DomainBreach node should be created", db_nodes)
    assert_true(db_nodes[0]["properties"]["matched_users"] == 8,
                "DomainBreach.matched_users must be the full count, NOT the capped one",
                db_nodes[0]["properties"])
    assert_true(db_nodes[0]["properties"]["admin_matches"] == 2,
                "DomainBreach.admin_matches must count every admin match",
                db_nodes[0]["properties"])
    exposed = [e for e in cap_graph["edges"] if e["label"] == "EXPOSED_IN_BREACH"]
    assert_true(len(exposed) == 8,
                "every matched individual must still get an EXPOSED_IN_BREACH edge, "
                "so the response cap cannot silently shrink the graph", len(exposed))

    # Under the cap the keys must still be present and honest.
    small, _, _ = run_smoke_case(
        code, flare_payload, flare_creds=2, individuals=2,
        extra_env={"FLARE_API_KEY": "fake-flare-key"})
    assert_true(len(small.get("credential_matches") or []) == 2,
                "an uncapped run returns every match", small.get("credential_matches"))
    assert_true(small.get("credential_matches_total") == 2,
                "the total equals the shown count when nothing was dropped", small)
    assert_true(small.get("credential_matches_truncated") is False,
                "the truncation flag stays false when nothing was dropped", small)

    # An explicit full export lifts the cap — the payload is transient and never
    # persisted, so bounding it there would only truncate the operator's export.
    exported, _, _ = run_smoke_case(
        code, dict(flare_payload, full_credentials=True, include_credentials=True),
        flare_creds=8, individuals=8,
        extra_env={"FLARE_API_KEY": "fake-flare-key"})
    assert_true(len(exported.get("credential_matches") or []) == 8,
                "a full_credentials export must carry every match, not the capped slice",
                len(exported.get("credential_matches") or []))
    assert_true(exported.get("credential_matches_truncated") is False,
                "a full export is not truncated", exported.get("credential_matches_truncated"))

    # A non-flare run must prune the companion keys with the list, or the
    # frontend's shallow-spread merge would let an empty total beat a good one.
    no_flare, _, _ = run_smoke_case(code, payload)
    for key in ("credential_matches", "credential_matches_total",
                "credential_matches_truncated"):
        assert_true(key not in no_flare,
                    f"{key} must be pruned when flare did not run", sorted(no_flare))

    # ── Organization source (Live Analysis > Organization) ────────────────────
    org_payload = {
        "domain": "example.com",
        "campaign_id": "smoke-campaign",
        "sketch_id": "smoke-sketch",
        "sources": ["org"],
        "social_regions": ["ru"],
        "proxy": {"enabled": True, "type": "socks5", "socks_url": "socks5h://proxy.local:1080"},
        "opsec": {"user_agent": "SPOTTER-Smoke/1.0"},
    }
    hh_ref: Dict[str, Any] = {}
    org, _, org_graph = run_smoke_case(code, org_payload, individuals=4,
                                       titled_people=True, hh_state_out=hh_ref)
    hh_state = hh_ref["_ref"]

    # org_source became a comma-joined summary of every provider that returned
    # data when the SERP and website providers landed. It is kept only so a
    # phase-1 record cached in a browser still renders; org_sources is the real
    # structure now.
    assert_true("hh.ru-scrape" in (org.get("org_source") or ""),
                "org_source still names the hh.ru transport", org.get("org_source"))
    assert_true(org.get("regions_run") == ["ru"],
                "WF13 must parse social_regions -- it received none until the org card",
                org.get("regions_run"))

    # The proxy/opsec envelope has to reach the client. WF13 honoured it for THC
    # and the bucket probe but each source wires it separately, so this is not
    # implied by the others passing.
    assert_true(hh_state["ctor"].get("proxy_url") == "socks5h://proxy.local:1080",
                "hh.ru client must receive the campaign proxy", hh_state["ctor"])
    assert_true(hh_state["ctor"].get("user_agent") == "SPOTTER-Smoke/1.0",
                "hh.ru client must receive the opsec user agent", hh_state["ctor"])

    # Vendors come from DNS/WHOIS, so they land with no regional provider at all.
    vendors = {v["name"]: v for v in org.get("org_vendors") or []}
    assert_true("outlook.com" in vendors,
                "MX records should fold into a mail vendor", sorted(vendors))
    assert_true("mail" in vendors["outlook.com"]["kinds"], "vendor kind", vendors["outlook.com"])
    assert_true("cloudflare.net" in vendors, "CNAME target should become a vendor", sorted(vendors))
    # 'awsdns-56.org' is the registrable base of ns-1234.awsdns-56.org.
    assert_true(any(v.get("kinds") == ["dns"] for v in vendors.values()),
                "NS records should become dns vendors", sorted(vendors))
    assert_true(not any(n == "example.com" for n in vendors),
                "the target's own domain is not its own vendor", sorted(vendors))

    # Org structure.
    depts = {d["name"]: d["count"] for d in org.get("org_departments") or []}
    assert_true(depts.get("Example Infrastructure") == 1 and depts.get("Fintech") == 1,
                "departments should aggregate across vacancies", depts)
    roles = org.get("org_roles") or []
    assert_true(roles and roles[0]["count"] == 28,
                "roles should come from the facet histogram, which counts every "
                "vacancy rather than only the page fetched", roles[:2])
    offices = org.get("org_offices") or []
    _hh_off = [o for o in offices if o["label"] == "Moscow, Primernaya ulitsa 1"]
    assert_true(len(_hh_off) == 1 and _hh_off[0]["count"] == 2,
                "identical vacancy addresses fold into one office with a count", offices)
    assert_true(_hh_off[0].get("metro") == "Primernaya",
                "office should keep the metro hint", _hh_off[0])
    assert_true(any(o["label"] == "Denver, CO" for o in offices),
                "a website-named office joins the hh.ru list", offices)

    # Contacts: the hidden count is the denominator that makes an empty list
    # readable as "withheld" instead of "this employer has no recruiters".
    assert_true(len(org.get("org_contacts") or []) == 1,
                "only published contacts are listed", org.get("org_contacts"))
    assert_true(org.get("org_contacts_hidden") == 1,
                "withheld contacts must be counted, not silently dropped",
                org.get("org_contacts_hidden"))
    assert_true((org.get("org_skills") or [{}])[0]["name"] in {"Active Directory", "Excel", "VMware"},
                "key skills should aggregate", org.get("org_skills"))

    # ── Job title match ──────────────────────────────────────────────────────
    # Both sides normalise through derive_specialty(), which is what lets a
    # Russian vacancy title meet an English LinkedIn title.
    title_rows = org.get("org_title_matches") or []
    matches = {m["specialty"] for m in title_rows}
    assert_true("Infrastructure / IT" in matches,
                "a seeded sysadmin should match the Russian sysadmin vacancy", matches)

    # Every chip on this card is a dossier link, so every person on it must have
    # a node to open. This used to be computed BEFORE the employment gate, over
    # the ungated candidate roster, so the card offered links for people the gate
    # had rejected -- and the click answered "No Individual matching: <name>".
    match_people = [p for m in title_rows for p in (m.get("people") or [])]
    assert_true(match_people, "the match should carry people", title_rows)
    assert_true(all((p.get("id") or "").strip() for p in match_people),
                "every matched person must carry a graph node id", match_people)
    held_names = {(p.get("name") or "") for p in org.get("org_people_unverified") or []}
    assert_true(held_names, "the fixture should hold somebody back", org.get("org_people_counts"))
    assert_true(not (held_names & {p.get("name") for p in match_people}),
                "a candidate the employment gate held must never reach the card",
                sorted(held_names & {p.get("name") for p in match_people}))
    assert_true(all(p.get("graph_id") for p in org.get("org_people") or []),
                "the write loop must record each person's node id",
                org.get("org_people"))

    # `open_roles` is VACANCIES, and every entry must be traceable to one.
    #
    # Feeding the roster's own job titles back in -- which is what this block
    # used to do -- makes every specialty match itself, turns open_role_count
    # into a count of people, and prints an unparseable LinkedIn headline
    # (usually a person's name) as an open role, because derive_specialty()
    # Title-Cases whatever it cannot classify.
    #
    # NOT "no offered role may equal an employee's job title": a company hiring
    # for the role somebody already holds is the pivot this card exists for, and
    # the fixture has exactly that. The invariant is provenance, not difference.
    offered = {r for m in title_rows for r in (m.get("open_roles") or [])}
    vacancy_titles = ({j.get("title") or "" for j in org.get("org_jobs") or []}
                      | {r.get("name") or "" for r in org.get("org_roles") or []}
                      # hh.ru also offers the titles of the vacancies it FETCHED,
                      # which the facet vocabulary flattens away. They are real
                      # vacancies; they just do not appear in org_roles.
                      | {v["title"] for v in hh_state["vacancies"]})
    assert_true(offered <= vacancy_titles,
                "every open role must come from a vacancy source, not the roster",
                sorted(offered - vacancy_titles))
    person_names = {(p.get("name") or "") for p in
                    (org.get("org_people") or []) + (org.get("org_people_unverified") or [])}
    assert_true(not (offered & person_names),
                "a person's name must never render as an open role",
                sorted(offered & person_names))
    assert_true(org.get("org_title_empty_kind") == "",
                "a populated match reports no empty kind", org.get("org_title_empty_kind"))

    # Company graph writes. fc.add_node preserves PascalCase; batch_import would
    # have lowercased the type and made every PascalCase read find zero.
    companies = [n for n in org_graph["nodes"] if n["node_type"] == "Company"]
    assert_true(companies, "org source should write Company nodes", org_graph["nodes"])
    by_rel: Dict[str, List[Dict[str, Any]]] = {}
    for n in companies:
        by_rel.setdefault(n["properties"].get("relationship", ""), []).append(n)
    assert_true(len(by_rel.get("target") or []) == 1, "exactly one target Company", by_rel)
    target = by_rel["target"][0]
    assert_true(target["properties"].get("name") == "Example Holding",
                "target Company name", target["properties"])
    # A Company node with no name is the Technology-node trap again: the
    # serializer strips '' before validating, so GET /graph 500s for the whole
    # sketch and the campaign goes dark in the UI.
    assert_true(all((n["properties"].get("name") or "").strip() for n in companies),
                "every Company node must carry a non-empty name", companies)
    # Numerics and booleans must stay native. A registered custom type retypes
    # every DECLARED property to Optional[str] and drops what will not coerce,
    # which is why these are undeclared in register_company_type.py.
    assert_true(target["properties"].get("open_vacancies") == 350,
                "open_vacancies must survive as an int", target["properties"].get("open_vacancies"))
    assert_true(target["properties"].get("it_accredited") is True,
                "boolean flags must survive as bools", target["properties"])
    assert_true(by_rel.get("subsidiary") and by_rel["subsidiary"][0]["properties"]["name"] == "Example Delivery",
                "related employers become subsidiary Companies", by_rel.get("subsidiary"))
    assert_true(by_rel.get("vendor"), "DNS-derived vendors become Companies", by_rel)
    edge_labels = {e["label"] for e in org_graph["edges"]}
    assert_true({"SUBSIDIARY_OF", "VENDOR_OF", "RECRUITS_FOR"} <= edge_labels,
                "org source should link subsidiaries, vendors and recruiters", sorted(edge_labels))
    assert_true(org.get("org_company_written") is True,
                "org_company_written should report the write", org.get("org_company_written"))

    # ── Multi-provider org_sources ───────────────────────────────────────────
    serp_state = hh_ref["_serp"]
    site_state = hh_ref["_site"]
    tavily_state = hh_ref["_tavily"]
    provs = {p["provider"]: p for p in org.get("org_sources") or []}
    assert_true(set(provs) == {"hh.ru", "linkedin-jobs", "linkedin-serp",
                               "linkedin-tavily",
                               "website", "sec-edgar"},
                "every provider records itself, run or not", sorted(provs))
    assert_true(provs["linkedin-serp"]["transport"] == "serpapi",
                "the SERP transport is named so the card can show it", provs["linkedin-serp"])
    assert_true(provs["website"]["status"] == "ok", "the website provider ran", provs["website"])
    assert_true(org.get("org_source") and "serpapi" in org["org_source"],
                "the derived scalar still exists for cached phase-1 records",
                org.get("org_source"))

    # The envelope has to reach BOTH new providers, each wired separately.
    assert_true(serp_state["ctor"].get("proxy_url") == "socks5h://proxy.local:1080",
                "SERP client receives the campaign proxy", serp_state["ctor"])
    assert_true(tavily_state["ctor"].get("proxy_url") == "socks5h://proxy.local:1080",
                "Tavily client receives the campaign proxy", tavily_state["ctor"])
    assert_true(tavily_state["ctor"].get("budget_credits") is not None,
                "Tavily client receives the shared credit ceiling",
                tavily_state["ctor"])
    assert_true(site_state["calls"][0].get("proxy_url") == "socks5h://proxy.local:1080",
                "site crawler receives the campaign proxy", site_state["calls"][0])
    assert_true(site_state["calls"][0].get("sketch_id") == "smoke-sketch",
                "the site corpus is namespaced to the campaign's sketch",
                site_state["calls"][0])

    # The four linkedin_* keys that had never held a value.
    #
    # TAVILY WINS when both providers matched. That precedence is carried by
    # block ORDER plus fill-if-empty merges rather than by a flag, so this
    # assertion is what stops a later edit reordering the blocks and silently
    # flipping it back.
    assert_true(org.get("linkedin_company_url", "").endswith("/company/example-fixture-tavily/"),
                "linkedin_company_url comes from Tavily when both matched",
                org.get("linkedin_company_url"))
    assert_true(org.get("linkedin_company_name") == "Example Corp",
                "linkedin_company_name is finally populated", org.get("linkedin_company_name"))

    # People, merged across providers, deduped, and then GATED. org_people is
    # what we can evidence; org_people_unverified is what the providers returned
    # with the reason it did not qualify.
    names = [p["name"] for p in org.get("org_people") or []]
    held_names = [p["name"] for p in org.get("org_people_unverified") or []]
    assert_true("Dana Webb" in names and "Sam Ortiz" in names and "Jane Roe" in names,
                "evidenced people from both providers land", names)
    assert_true(names.count("Dana Webb") == 1,
                "a person returned by both providers appears once", names)

    # The false positives the gate exists to remove. Neither may be counted and
    # neither may reach the graph.
    assert_true("Pat Vendor" in held_names,
                "a profile naming a DIFFERENT employer is held", held_names)
    assert_true("Chris Noise" in held_names,
                "a profile naming no employer at all is held", held_names)
    assert_true("Pat Vendor" not in names and "Chris Noise" not in names,
                "...and neither is counted as a person", names)
    pat = [p for p in org["org_people_unverified"] if p["name"] == "Pat Vendor"][0]
    assert_true(pat["tier"] == "contradicted" and pat["edge_label"] == "",
                "a contradicted row carries no edge label", pat)
    assert_true("Globex" in (pat.get("why") or ""),
                "...and the operator is told which company it named", pat.get("why"))
    chris = [p for p in org["org_people_unverified"] if p["name"] == "Chris Noise"][0]
    assert_true(chris["tier"] == "weak" and chris["edge_label"] == "",
                "a co-occurrence row is weak and carries no edge label", chris)

    dana = [p for p in org["org_people"] if p["name"] == "Dana Webb"][0]
    assert_true(dana["source"] == "linkedin-tavily",
                "the first provider to name a person owns the row", dana)
    # Dana is returned by Tavily, SerpAPI and the website crawl. Tavily names
    # her first but WITHOUT an employer, because its snippet is its own
    # extraction and often lacks the `Experience:` run a Google-rendered
    # snippet carries. The merge must therefore keep one row and UPGRADE it.
    assert_true(dana.get("employer") == "Example Corp",
                "a blank field is filled in from a later provider", dana)
    assert_true(dana.get("job_title") == "Senior Systems Administrator",
                "...including the job title the gate scores", dana)
    # THE REGRESSION. The website merge used to `continue` on a name the SERP had
    # already returned, so the company's own statement about its own staff was
    # silently thrown away and Dana was judged on a bare LinkedIn claim.
    assert_true(dana.get("site_named") is True,
                "being named on the company's own site survives the merge", dana)
    assert_true(dana["tier"] == "confirmed" and dana["edge_label"] == "WORKS_FOR",
                "...and that org-side evidence CONFIRMS employment", dana)
    sam = [p for p in org["org_people"] if p["name"] == "Sam Ortiz"][0]
    assert_true(sam["tier"] == "reported" and sam["edge_label"] == "CLAIMS_WORKS_FOR",
                "a profile-only claim is reported, never confirmed", sam)
    assert_true(dana["specialty"] == "Infrastructure / IT",
                "specialty is derived for SERP people too", dana)
    assert_true(dana["technologies"] == ["Active Directory", "Azure"],
                "named technologies survive", dana)

    counts = org.get("org_people_counts") or {}
    assert_true(counts.get("candidates") == len(names) + len(held_names),
                "the counters account for every candidate", counts)
    assert_true(counts.get("shown") == len(names) and counts.get("held") == len(held_names),
                "shown + held match the two lists", counts)
    assert_true(org.get("org_people_held") == len(held_names),
                "the held count is reported for the card", org.get("org_people_held"))

    units = [u["name"] for u in org.get("org_units") or []]
    assert_true("Example Cloud" in units and "Widget Division" in units,
                "org units merge across providers", units)
    assert_true(any(m["name"] == "Reseller Ltd" for m in org.get("org_mentions") or []),
                "a company that merely mentions the target stays a mention",
                org.get("org_mentions"))
    assert_true(any(v["name"] == "Globex" for v in org.get("org_vendors") or []),
                "a site-named partner joins the DNS-derived vendors",
                [v["name"] for v in org.get("org_vendors") or []])
    assert_true(org.get("org_site", {}).get("pages_refused") == 3,
                "the count of off-domain URLs the scope lock refused is surfaced",
                org.get("org_site"))

    # ── open roles, and the employer gate on them ────────────────────────────
    # The second vacancy source, and the first that is not region-gated.
    jobs_prov = provs["linkedin-jobs"]
    assert_true(jobs_prov["status"] == "ok" and jobs_prov["transport"] == "google_jobs",
                "the open-roles leg records its transport like every provider",
                jobs_prov)
    job_titles_ = [j["title"] for j in org.get("org_jobs") or []]
    assert_true("Senior Systems Administrator" in job_titles_,
                "open roles reach the card", org.get("org_jobs"))
    # google_jobs aggregates LinkedIn, Indeed and Glassdoor, so a company-name
    # query returns other companies' vacancies. An ungated list would feed a
    # competitor's roles into the match and they would match.
    refused_cos = {j["company"] for j in org.get("org_jobs_refused") or []}
    assert_true("Globex Industries" in refused_cos,
                "a posting belonging to another company is refused",
                org.get("org_jobs_refused"))
    assert_true("Java Developer" not in job_titles_,
                "...and never reaches the roles list", job_titles_)
    offered_all = {r for m in org.get("org_title_matches") or []
                   for r in (m.get("open_roles") or [])}
    assert_true("Java Developer" not in offered_all,
                "...nor the job title match", sorted(offered_all))
    # hh.ru ASSIGNS org_roles; the jobs leg must merge into it, not clobber it.
    role_names = [r["name"] for r in org.get("org_roles") or []]
    assert_true("Системный администратор" in role_names,
                "hh.ru's facet roles survive the merge", role_names)
    assert_true("Senior Systems Administrator" in role_names,
                "...and the LinkedIn roles join them", role_names)
    assert_true(org.get("org_roles_denominator") == "facets",
                "with hh.ru's facets present the denominator says so",
                org.get("org_roles_denominator"))
    # Card data only. A JobPosting nodeType would have to be registered, and an
    # unresolvable one makes GET /graph 500 for the WHOLE sketch.
    _job_labels = {str(n.get("label") or "") for n in org_graph["nodes"]}
    assert_true(not (_job_labels & set(job_titles_)),
                "no posting is ever written to the graph",
                sorted(_job_labels & set(job_titles_)))

    # ── a non-RU campaign, which is the ordinary case ────────────────────────
    # hh.ru is gated on the RU objective, so before the open-roles leg existed
    # this campaign shape had NOTHING to match against -- which is what drove
    # the old bug where the people roster was offered to itself as open roles.
    no_ru_payload = dict(org_payload)
    no_ru_payload["social_regions"] = []
    no_ru, _, _ = run_smoke_case(code, no_ru_payload, individuals=4, titled_people=True)
    assert_true(no_ru.get("org_title_matches"),
                "LinkedIn open roles carry the card without any Russian job board",
                no_ru.get("org_title_empty_message"))
    assert_true(no_ru.get("org_title_empty_kind") == "",
                "so it is not an empty card any more",
                no_ru.get("org_title_empty_kind"))
    assert_true(no_ru.get("org_roles_denominator") == "fetched",
                "and the histogram says it counted the postings fetched",
                no_ru.get("org_roles_denominator"))

    # ── no open-role source AT ALL: an honest empty, not a self-match ────────
    # Neither leg returned a vacancy. The card has to SAY which kind of empty
    # that is; the regression this pins is a full-looking card, not an empty one.
    none_, _, _ = run_smoke_case(code, no_ru_payload, individuals=4,
                                 titled_people=True, serp_jobs=False)
    assert_true(none_.get("org_title_matches") == [],
                "with no vacancy source there is nothing to match",
                none_.get("org_title_matches"))
    assert_true(none_.get("org_open_roles_offered") == 0,
                "...because no roles were offered at all",
                none_.get("org_open_roles_offered"))
    assert_true(none_.get("org_title_empty_kind") == "no_role_source",
                "the card must name which kind of empty it is",
                none_.get("org_title_empty_kind"))
    _msg = none_.get("org_title_empty_message") or ""
    assert_true("hh.ru" in _msg and "SerpAPI" in _msg,
                "and the message must name BOTH legs, not just the Russian one",
                _msg)
    # The people side is still read -- it lives outside the hh.ru branch now.
    # It used to be built INSIDE it, so on a non-RU campaign it was never built.
    assert_true((none_.get("org_people_with_titles") or 0) > 0,
                "the graph-side people read must not be gated on the RU objective",
                none_.get("org_people_with_titles"))

    # ── the operator's identifiers reach the providers ───────────────────────
    # The wrong-company bug was three separate holes, and each of these pins one
    # of them shut. Objectives held the target's name, its legal entity, a second
    # domain and a company email; WF13 read only the name, and every provider was
    # handed that one string and told to pick a winner from what came back.
    ident_payload = dict(org_payload,
                         target_type="organization",
                         company_name="Example Holding",
                         additional_ids="example.org, OOO Primer",
                         company_email="info@example.com")
    idref: Dict[str, Any] = {}
    ident_org, _, _ = run_smoke_case(code, ident_payload, individuals=4,
                                     titled_people=True, hh_state_out=idref)
    ident_state = idref["_ref"]

    identity = (ident_state["queries"][0] or {}).get("identity") or {}
    assert_true(bool(identity), "hh.ru must receive the identity, not a bare seed",
                ident_state["queries"][:1])
    assert_true("OOO Primer" in (identity.get("names") or []),
                "an Additional Identifier reaches the provider as a NAME to search",
                identity.get("names"))
    assert_true("example.org" in (identity.get("domains") or []),
                "a domain-shaped Additional Identifier reaches it as a DOMAIN",
                identity.get("domains"))
    assert_true("example.com" in (identity.get("domains") or []),
                "the Company Email Address contributes its domain -- it was sent by "
                "the frontend and never read at all",
                identity.get("domains"))
    assert_true((ident_state["queries"][0] or {}).get("match_min"),
                "a match floor is passed, so a provider cannot adopt an unmatched row",
                ident_state["queries"][0])
    edgar_aliases = (idref["_edgar"].get("aliases") or [[]])[0]
    assert_true("OOO Primer" in edgar_aliases,
                "EDGAR resolves every alias -- a registrant files under its LEGAL name",
                edgar_aliases)

    # The card has to be able to say what it searched for and on what basis it
    # believes the answer. An unexplained profile is what shipped the wrong one.
    card_ident = ident_org.get("org_identity") or {}
    assert_true(card_ident.get("operator_sourced") is True,
                "the card is told these identifiers came from Objectives", card_ident)
    assert_true("example.org" in (card_ident.get("operator_domains") or []),
                "...and which of them the operator typed", card_ident)
    assert_true(isinstance(ident_org.get("org_match"), dict)
                and isinstance(ident_org.get("org_rejected"), dict),
                "per-provider match provenance and refusals reach the card",
                [ident_org.get("org_match"), ident_org.get("org_rejected")])

    # The same identifiers must also widen the PEOPLE gate: someone whose
    # headline names the legal entity rather than the trading name was scored as
    # naming a different company and held.
    gate_aliases = (ident_org.get("org_people_counts") or {}).get("aliases") or []
    assert_true("OOO Primer" in gate_aliases,
                "the employment gate scores against the operator's identifiers too",
                gate_aliases)

    # Graph: the relational half.
    org_edges = {e["label"] for e in org_graph["edges"]}
    assert_true("WORKS_FOR" in org_edges, "confirmed people are linked to the company",
                sorted(org_edges))
    assert_true("CLAIMS_WORKS_FOR" in org_edges,
                "a self-reported claim gets its own weaker label", sorted(org_edges))
    assert_true("HAS_UNIT" in org_edges, "units are linked to the company", sorted(org_edges))
    assert_true("USES_TECH" in org_edges, "named technologies become edges", sorted(org_edges))
    people_nodes = [n for n in org_graph["nodes"] if n["node_type"] == "individual"]
    assert_true(any(n["properties"].get("full_name") == "Dana Webb" for n in people_nodes),
                "SERP people are written as Individuals", [n["label"] for n in people_nodes])
    dana_node = [n for n in people_nodes if n["properties"].get("full_name") == "Dana Webb"][0]
    # add_node MERGEs on the label, so writing an empty string here would erase a
    # richer value WF03/WF27 had already put on the node.
    assert_true("education" not in dana_node["properties"],
                "an empty field is omitted rather than written as ''", dana_node["properties"])
    assert_true(org.get("org_people_written", 0) == len(org.get("org_people") or []),
                "exactly the evidenced people are written",
                (org.get("org_people_written"), len(org.get("org_people") or [])))
    # No held person may reach the graph under ANY label.
    written_names = {n["properties"].get("full_name") for n in people_nodes}
    assert_true(not (written_names & {"Pat Vendor", "Chris Noise"}),
                "a held person is never written as an Individual", sorted(written_names))
    # employment_tier is the marker scripts/prune_org_people.py keys on: edge
    # `data` is dropped by the importer, node properties are not.
    assert_true(dana_node["properties"].get("employment_tier") == "confirmed",
                "the tier is stamped on the node for later cleanup",
                dana_node["properties"])
    assert_true(bool(dana_node["properties"].get("employment_evidence")),
                "...alongside the sentence explaining it", dana_node["properties"])

    # ── SEC EDGAR: the filing of record ──────────────────────────────────────
    edgar_state = hh_ref["_edgar"]
    assert_true(provs.get("sec-edgar", {}).get("status") == "ok",
                "EDGAR records itself as a provider", provs.get("sec-edgar"))
    ed = org.get("org_edgar") or {}
    assert_true(ed.get("cik") == "0009999999", "the CIK is carried", ed)
    assert_true(ed.get("legal_name") == "EXAMPLE HOLDING CORP", "the legal name is carried", ed)
    assert_true(ed.get("state_of_incorporation") == "DE", "state of incorporation", ed)
    assert_true(ed.get("match_score") == 95,
                "the match score travels so an operator can judge the match", ed)
    assert_true(ed.get("filing", {}).get("form") == "10-K",
                "the source filing is named", ed.get("filing"))
    assert_true(ed.get("subsidiary_count") == 2, "the subsidiary count", ed)

    # EDGAR is authoritative where it overlaps, so unlike the other providers it
    # OVERWRITES rather than only filling gaps.
    prof = org.get("org_profile") or {}
    assert_true(prof.get("legal_name") == "EXAMPLE HOLDING CORP",
                "the filed legal name is added to the profile", prof)
    assert_true(prof.get("address") == "1 Main St, Denver, CO, 80202",
                "the registered address overwrites an inferred one", prof.get("address"))
    assert_true(prof.get("state_of_incorporation") == "DE",
                "state of incorporation reaches the profile", prof)
    assert_true((prof.get("industries") or [])[0] == "Services-Prepackaged Software",
                "the SIC description leads the industry list", prof.get("industries"))

    rel_names = [r.get("name") for r in org.get("org_related") or []]
    assert_true("Example Ireland Ltd" in rel_names,
                "Exhibit 21 subsidiaries join org_related", rel_names)
    assert_true(rel_names.count("Example Delivery") == 1,
                "a subsidiary both hh.ru and EDGAR name appears once", rel_names)
    ireland = [r for r in org["org_related"] if r.get("name") == "Example Ireland Ltd"][0]
    assert_true(ireland.get("jurisdiction") == "Ireland",
                "a filed subsidiary keeps its jurisdiction", ireland)
    assert_true(ireland.get("source") == "sec-edgar",
                "...and its provenance", ireland)
    assert_true(edgar_state["ctor"].get("proxy_url") == "socks5h://proxy.local:1080",
                "EDGAR receives the campaign proxy", edgar_state["ctor"])

    # Provenance must survive into the graph. The writer hardcoded source='hh.ru'
    # for every subsidiary, which mislabelled the filed ones as job-board
    # guesses and dropped the jurisdiction that makes them authoritative.
    subs_nodes = [n for n in org_graph["nodes"]
                  if n["node_type"] == "Company"
                  and n["properties"].get("relationship") == "subsidiary"]
    filed = [n for n in subs_nodes if n["properties"].get("source") == "sec-edgar"]
    assert_true(filed, "EDGAR subsidiaries keep their own source in the graph",
                [(n["label"], n["properties"].get("source")) for n in subs_nodes])
    assert_true(all(n["properties"].get("jurisdiction") for n in filed),
                "...and their filed jurisdiction", [n["properties"] for n in filed])
    assert_true(all(n["properties"].get("filed") is True for n in filed),
                "...and are flagged as filed rather than inferred",
                [n["properties"] for n in filed])
    hh_subs = [n for n in subs_nodes if n["properties"].get("source") == "hh.ru"]
    assert_true(hh_subs and not any(n["properties"].get("filed") for n in hh_subs),
                "an inferred subsidiary is NOT flagged as filed",
                [n["properties"] for n in hh_subs])

    # ── A non-filer is no_match, not an error ────────────────────────────────
    nofile_ref: Dict[str, Any] = {}
    nofile, _, _ = run_smoke_case(code, org_payload, edgar_matched=False,
                                  hh_state_out=nofile_ref)
    np_ = {p["provider"]: p for p in nofile["org_sources"]}
    assert_true(np_["sec-edgar"]["status"] == "no_match",
                "a private company is a miss, not a failure", np_.get("sec-edgar"))
    assert_true("SEC filers only" in (np_["sec-edgar"]["note"] or ""),
                "...and the note says why that is normal", np_.get("sec-edgar"))
    assert_true((nofile.get("org_edgar") or {}).get("candidates"),
                "near-miss registrants are still offered to the operator",
                nofile.get("org_edgar"))
    assert_true(any("below the 72 match floor" in e for e in nofile.get("errors") or []),
                "the declined registrant is named", nofile.get("errors"))
    assert_true(nofile.get("org_profile", {}).get("name"),
                "the other providers still fill the profile", nofile.get("org_profile"))

    # ── An unreliable SERP transport is labelled, not silently empty ─────────
    unrel_ref: Dict[str, Any] = {}
    unrel, _, _ = run_smoke_case(code, org_payload, serp_unreliable=True,
                                 hh_state_out=unrel_ref)
    up = {p["provider"]: p for p in unrel["org_sources"]}
    assert_true(up["linkedin-serp"]["reliable"] is False,
                "an unreliable transport is flagged", up["linkedin-serp"])
    assert_true("SERP_API_KEY" in (up["linkedin-serp"]["note"] or ""),
                "...and the note names the fix", up["linkedin-serp"])

    # ── A crawl that never REACHED the site is not an empty site ─────────────
    # The 2026-09-21 defect, in the one place it was visible to an operator: the
    # target silently dropped the campaign's Tor egress, every fetch timed out,
    # and the provider row said "no match" -- the status that means we looked and
    # there was nothing there. Six consecutive runs read as completed crawls.
    unreach, _, _ = run_smoke_case(code, org_payload, site_unreachable=True)
    _uw = {p["provider"]: p for p in unreach["org_sources"]}["website"]
    assert_true(_uw["status"] == "unreachable",
                "an unreached site is its own status, never 'no_match'", _uw)
    assert_true("NOT REACHED" in (_uw["note"] or ""),
                "...and the note says so in the operator's words", _uw)
    assert_true("socks5h://proxy.local:1080" in (_uw["note"] or ""),
                "...naming the egress that could not reach it, which is the "
                "operator's next decision", _uw)
    _us = unreach.get("org_site") or {}
    assert_true(_us.get("unreachable") is True,
                "org_site carries the transport failure to the card", _us)
    assert_true(_us.get("blocked") is False,
                "a timeout is not a WAF refusal", _us)
    assert_true(_us.get("empty_kind") == "site_unreachable",
                "the empty_kind reaches the response", _us)
    assert_true(_us.get("empty_message") == SITE_UNREACHABLE_MESSAGE,
                "...with the message the card prints in place of the "
                "'Crawled the target\'s own site' boilerplate", _us)
    assert_true(unreach.get("org_profile", {}).get("name"),
                "the other providers still fill the profile",
                unreach.get("org_profile"))

    # ── The website-title probe must not touch the target off-proxy ──────────
    # It is the only req.* call in WF13 that contacts the TARGET rather than a
    # third-party API, and it went out direct on every run, from this host's
    # real IP, while the crawl beside it was proxied. The shape of the call is
    # pinned in scripts/check_workflow_regressions.py, which catches the next
    # such call site as well; what this checks is the one that leaked.
    _title_call = code.split("wr = req.get(", 1)[1].split(")", 1)[0]
    assert_true("proxies=THC_PROXIES" in _title_call,
                "the website-title probe rides the campaign proxy", _title_call)
    assert_true("THC_USER_AGENT" in _title_call,
                "...with the campaign's user agent, not a hardcoded one",
                _title_call)

    # ── One provider failing must not cost the others ────────────────────────
    broken, _, _ = run_smoke_case(code, org_payload, serp_fail=True, site_fail=True)
    bp = {p["provider"]: p for p in broken["org_sources"]}
    assert_true(bp["sec-edgar"]["status"] == "ok",
                "EDGAR still ran despite two siblings failing", bp)
    assert_true(bp["linkedin-serp"]["status"] == "error", "SERP failure recorded", bp)
    assert_true(bp["website"]["status"] == "error", "site failure recorded", bp)
    assert_true(bp["hh.ru"]["status"] == "ok",
                "hh.ru still ran despite both siblings failing", bp)
    assert_true(broken.get("org_profile", {}).get("name"),
                "the surviving provider's profile is kept", broken.get("org_profile"))
    assert_true(broken.get("org_vendors"),
                "DNS-derived vendors survive every provider failing", broken.get("org_vendors"))

    # ── The phantom endpoint is gone ─────────────────────────────────────────
    # The comment explaining WHY it was removed names the path, so check only
    # EXECUTABLE lines -- otherwise documenting the bug would fail the test.
    _live_lines = [ln for ln in code.splitlines() if not ln.lstrip().startswith("#")]
    assert_true(not any("search/company" in ln for ln in _live_lines),
                "WF13 no longer CALLS linkedin-api/search/company, which never existed",
                [ln.strip()[:70] for ln in _live_lines if "search/company" in ln])
    assert_true("search/company" in code,
                "...and the reason it was removed is still documented in the node")

    # ── The RU gate ───────────────────────────────────────────────────────────
    # Without the region ticked, hh.ru must not be contacted AT ALL, and the card
    # must be told why rather than shown an empty profile that reads as "nothing
    # found". Vendors still land, because they cost no egress.
    no_ru_ref: Dict[str, Any] = {}
    no_ru, _, _ = run_smoke_case(code, dict(org_payload, social_regions=[]),
                                 hh_state_out=no_ru_ref)
    assert_true(no_ru_ref["_ref"]["queries"] == [],
                "hh.ru must not be queried when RU is not selected", no_ru_ref["_ref"]["queries"])
    _no_ru_provs = {p["provider"]: p for p in no_ru.get("org_sources") or []}
    assert_true(_no_ru_provs["hh.ru"]["status"] == "skipped",
                "hh.ru records itself as skipped, not failed", _no_ru_provs.get("hh.ru"))
    assert_true("RU not selected" in (_no_ru_provs["hh.ru"]["note"] or ""),
                "an unticked region must be explained, not left blank",
                _no_ru_provs.get("hh.ru"))
    # The other two providers are not region-gated, so the card is NOT empty.
    assert_true(_no_ru_provs["linkedin-serp"]["status"] == "ok",
                "the SERP provider is not region-gated", _no_ru_provs.get("linkedin-serp"))
    assert_true(_no_ru_provs["website"]["status"] == "ok",
                "the website provider is not region-gated", _no_ru_provs.get("website"))
    assert_true(no_ru.get("org_profile"),
                "a profile still comes from the non-region-gated providers",
                no_ru.get("org_profile"))
    assert_true(no_ru.get("org_vendors"), "vendors do not depend on a region", no_ru.get("org_vendors"))

    # ── Company-name seed precedence ──────────────────────────────────────────
    seeded_ref: Dict[str, Any] = {}
    run_smoke_case(code, dict(org_payload, company_name="Explicit Corp"),
                   hh_state_out=seeded_ref)
    assert_true(seeded_ref["_ref"]["queries"][0]["name"] == "Explicit Corp",
                "an explicit company_name wins the seed", seeded_ref["_ref"]["queries"])
    assert_true(hh_state["queries"][0]["name"] == "example",
                "with no better source the seed falls back to the domain label",
                hh_state["queries"])

    # ── A failed lookup is reported, not fatal ────────────────────────────────
    failed, _, _ = run_smoke_case(code, org_payload, hh_fail=True)
    _fp = {p["provider"]: p for p in failed.get("org_sources") or []}
    assert_true(_fp["hh.ru"]["status"] == "no_match",
                "an hh.ru miss is recorded as a miss", _fp.get("hh.ru"))
    assert_true(any("hh.ru" in e for e in failed.get("errors") or []),
                "the miss is surfaced to the operator", failed.get("errors"))
    assert_true(failed.get("org_vendors"), "a hh.ru miss must not cost the vendor list", failed)
    # Phase 1 asserted an empty profile here. With three providers, one missing
    # no longer empties the card -- which is the whole reason the others exist.
    assert_true(failed.get("org_profile", {}).get("name") == "Example Corp",
                "another provider fills the profile when hh.ru misses",
                failed.get("org_profile"))

    # ── Pruning ───────────────────────────────────────────────────────────────
    # The frontend merges recon records with a shallow spread where a
    # present-but-empty key BEATS a good previous value, so a run without the org
    # source must carry no org_* keys at all.
    for key in ("org_source", "org_sources", "org_profile", "org_related",
                "org_departments", "org_roles", "org_offices", "org_contacts",
                "org_skills", "org_title_matches", "org_vendors",
                "org_company_written", "org_people", "org_units", "org_site",
                "org_mentions", "org_edgar"):
        assert_true(key not in no_flare,
                    f"{key} must be pruned when the org source did not run", sorted(no_flare))

    # ── Asset ownership evidence ─────────────────────────────────────────────
    # The retired branch matched the person's own name TOKENS against the asset
    # label. It is gone, and these cases pin why it cannot come back and what
    # replaced it. The fixture device dev-1 (WWW01 / www.example.com /
    # 203.0.113.10) is what devices_for_asset() joins the apex onto.
    own_payload = dict(payload, sources=["assets", "shodan"])

    def owner_rows(res, label=None):
        rows = res.get("asset_owners", []) or []
        return [r for r in rows if label is None or r.get("individual") == label]

    # 1. THE REGRESSION. An identity WF13 itself promoted from an unmatched Flare
    #    breach email is labelled with the address, so its tokens ARE the domain's
    #    tokens. This is the real-campaign false positive in miniature.
    prov, _, prov_graph = run_smoke_case(code, own_payload, ownership="provisional")
    assert_true(not owner_rows(prov, "jd@example.com"),
                "an email-labelled provisional identity must never own an asset",
                owner_rows(prov, "jd@example.com"))
    assert_true(not any(e["label"] == "MANAGES_NAMED" for e in prov_graph["edges"]),
                "the retired MANAGES_NAMED label must have no writer",
                [e["label"] for e in prov_graph["edges"]])
    # ...while the real rights-holder on the same run is still found, so the
    # assertion above is about the identity and not about ownership being dead.
    assert_true(owner_rows(prov, "COPS@EXAMPLE.COM"),
                "a real AD rights-holder is still attributed on the same run",
                prov.get("asset_owners"))

    # 2. Control: LOCAL_ADMIN on the device serving the apex.
    direct, _, direct_graph = run_smoke_case(code, own_payload, ownership="direct")
    own_rows = [r for r in owner_rows(direct, "COPS@EXAMPLE.COM")
                if r.get("relationship") == "OWNS_ASSET"]
    assert_true(own_rows, "LOCAL_ADMIN on the serving device must yield OWNS_ASSET",
                direct.get("asset_owners"))
    assert_true(any("local admin on WWW01" in (r.get("evidence") or "") for r in own_rows),
                "the evidence must name the intermediate host", own_rows)
    assert_true(any(e["label"] == "OWNS_ASSET" for e in direct_graph["edges"]),
                "an OWNS_ASSET edge reaches the graph",
                [e["label"] for e in direct_graph["edges"]])
    ev = direct.get("graph_import", {}).get("ownership_evidence", {})
    assert_true(ev.get("owns", 0) >= 1 and not ev.get("empty_kind"),
                "ownership_evidence counts the control tier and is not empty", ev)

    # 3. Reach without control must NOT be promoted to control.
    acc, _, _ = run_smoke_case(code, own_payload, ownership="access")
    acc_rows = owner_rows(acc, "COPS@EXAMPLE.COM")
    assert_true(acc_rows and all(r.get("relationship") == "HAS_ACCESS" for r in acc_rows),
                "CanRDP alone is HAS_ACCESS, never OWNS_ASSET", acc_rows)

    # 4. A small, non-privileged team's right reaches its members, and says so.
    grp, _, _ = run_smoke_case(code, own_payload, ownership="group")
    grp_rows = owner_rows(grp, "DWEB@EXAMPLE.COM")
    assert_true(grp_rows and all(r.get("relationship") == "OWNS_ASSET" for r in grp_rows),
                "a small team's GenericAll reaches its members", grp.get("asset_owners"))
    assert_true(any("via Web Team" in (r.get("evidence") or "") for r in grp_rows),
                "group-derived evidence names the group it came through", grp_rows)

    # 5. THE GUARD. Domain Admins holds LOCAL_ADMIN on every host in a real
    #    estate; expanding that to its members would attribute the whole estate to
    #    every DA -- a wider false positive than the one being fixed, wearing
    #    BloodHound's authority. WF10 already scores DA membership separately.
    da, _, da_graph = run_smoke_case(code, own_payload, ownership="da")
    assert_true(not owner_rows(da, "EADMIN@EXAMPLE.COM"),
                "a Domain Admin must not inherit ownership of every host",
                da.get("asset_owners"))
    assert_true(not any(e["label"] in ("OWNS_ASSET", "HAS_ACCESS") for e in da_graph["edges"]),
                "and no ownership edge is written for it",
                [e["label"] for e in da_graph["edges"]])

    # 5b. THE SIZE GUARD, separately from the name/flag guard. "All Staff" is not
    #     a built-in and carries no high-value flag, so only MAX_GROUP_MEMBERS
    #     stops its 60 members each claiming the host.
    bulk, _, bulk_graph = run_smoke_case(code, own_payload, ownership="bulk")
    assert_true(not owner_rows(bulk, "BULK0@EXAMPLE.COM"),
                "an oversized ordinary group must not confer ownership on its members",
                owner_rows(bulk, "BULK0@EXAMPLE.COM"))
    assert_true(not any(e["label"] in ("OWNS_ASSET", "HAS_ACCESS")
                        for e in bulk_graph["edges"]),
                "and writes no ownership edge",
                [e["label"] for e in bulk_graph["edges"]])

    # 6. No AD data at all is the COMMON case for an external estate, and it must
    #    report which kind of empty it is rather than looking like a regression.
    bare, _, _ = run_smoke_case(code, own_payload)
    bare_ev = bare.get("graph_import", {}).get("ownership_evidence", {})
    assert_true(bare_ev.get("empty_kind") == "no_ad_data",
                "a sketch with no AD rights reports no_ad_data", bare_ev)
    assert_true(bare_ev.get("owns") == 0 and bare_ev.get("access") == 0,
                "and claims no ownership", bare_ev)

    # ── Tavily as a peer provider ───────────────────────────────────────────
    tav_provs = {p["provider"]: p for p in org.get("org_sources") or []}
    assert_true(tav_provs["linkedin-tavily"]["status"] == "ok",
                "Tavily records itself as a provider", tav_provs.get("linkedin-tavily"))
    assert_true(tav_provs["linkedin-tavily"]["transport"] == "tavily",
                "and names its transport", tav_provs.get("linkedin-tavily"))

    # THE integration hazard. Both providers read the SAME LinkedIn profiles,
    # so a provider-local dedupe would gate Dana twice and write her twice.
    _all_rows = ((org.get("org_people") or [])
                 + (org.get("org_people_unverified") or []))
    _danas = [x for x in _all_rows if x.get("name") == "Dana Webb"]
    assert_true(len(_danas) == 1,
                "a person BOTH providers returned appears exactly once",
                [(x.get("source"), x.get("url")) for x in _danas])
    assert_true(_danas[0].get("employer") == "Example Corp",
                "and the employer is filled in from whichever provider had it",
                _danas[0])
    assert_true("Robin Tavily" in [x.get("name") for x in _all_rows],
                "a Tavily-only person still lands",
                [x.get("name") for x in _all_rows])
    _units = [u.get("name") for u in org.get("org_units") or []]
    assert_true(_units.count("Example Cloud") == 1,
                "a unit both providers returned is not duplicated", _units)

    _org_payload = {"domain": "example.com", "sources": ["org"],
                    "campaign": {"sketch_id": "smoke-sketch"}}

    # No key: a row that SAYS so, not a blank, and no silent fallback.
    nokey_org, _, _ = run_smoke_case(code, _org_payload, tavily_key=False)
    nokey = {p["provider"]: p for p in nokey_org.get("org_sources") or []}
    assert_true(nokey["linkedin-tavily"]["status"] == "skipped",
                "with no key the provider reports skipped", nokey.get("linkedin-tavily"))
    assert_true("TAVILY_API_KEY" in nokey["linkedin-tavily"]["note"],
                "and names the variable to set", nokey.get("linkedin-tavily"))

    # Tavily unmatched: SerpAPI must still fill the linkedin_* keys.
    unm_org, _, _ = run_smoke_case(code, _org_payload, tavily_matched=False)
    assert_true(unm_org.get("linkedin_company_url", "").endswith("/company/example-fixture/"),
                "SerpAPI still fills linkedin_company_url when Tavily found nothing",
                unm_org.get("linkedin_company_url"))

    # A Tavily crash must cost its own row and nothing else in the run.
    fail_org, _, _ = run_smoke_case(code, _org_payload, tavily_fail=True)
    fail_provs = {p["provider"]: p for p in fail_org.get("org_sources") or []}
    assert_true(fail_provs["linkedin-tavily"]["status"] == "error",
                "a Tavily failure is recorded as an error row",
                fail_provs.get("linkedin-tavily"))
    assert_true(fail_provs["linkedin-serp"]["status"] == "ok",
                "and does not cost the other providers in the run",
                fail_provs.get("linkedin-serp"))

    print("smoke_workflow13 passed")


if __name__ == "__main__":
    main()
