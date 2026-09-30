"""
cloudschism_parser.py — Parse CloudSchism cloud-posture output into Flowsint nodes.

CloudSchism writes a *directory* of artifacts, not a single file, so the unit an
analyst actually has to hand is either that directory or a zip of it. Both are
accepted here, plus a single structured export on its own.

Which artifacts exist depends on the scan's `--output-profile`, and the default
(`analyst`) deliberately OMITS `findings.json` — it keeps findings in the canonical
record store and the bounded HTML views instead. So findings are read from
`findings.json` when the profile wrote one (integration / forensic) and otherwise
recovered from the compatibility export `CloudSchism-report.json[.gz]`, which every
profile writes. Parsing only findings.json would silently return zero findings for
the most common scan there is.

Artifacts consumed (first source that exists wins; all are optional):
  public-endpoints.json    → Domain / Ip           the externally reachable surface
  external-exposures.json  → Service               open management ports + protocols
  findings.json            → CloudFinding          integration & forensic profiles only
  attack-paths.json        → CloudAttackPath       chains findings into an entry route
  attack-graph.json        → all of the above      resource/identity/finding topology
  storage-accounts.json    → CloudAsset            Azure storage + anonymous access
  CloudSchism-report.json[.gz]                     fallback for findings / paths /
                                                   endpoints / identities under the
                                                   analyst profile
  azure|aws|m365|gcp-inventory.json[.gz]           identity sections only

Read order matters: findings before attack paths (a path links to the findings it
chains, and an edge is only written when both endpoints exist), and the attack graph
last (it adds topology between things the dedicated exports already described in
richer form).

Output: normalised dicts ready for flowsint_client.batch_import(), via
CloudSchismResult.to_flowsint_batch() — the same contract sharphound_parser and
pingcastle_parser return.

Usage (standalone):
    python3 cloudschism_parser.py /path/to/aws-scan-out        # a directory
    python3 cloudschism_parser.py /path/to/scan-out.zip        # or a zip of one

Usage (from upload_router / an n8n Code node):
    from cloudschism_parser import parse_zip_bytes
    result = parse_zip_bytes(zip_bytes)

All data here originates from authorized cloud assessments under an engagement's
Rules of Engagement.

Node types
──────────
Everything below is a built-in Flowsint type or a *registered* custom type, with two
exceptions: CloudFinding and CloudAttackPath. Flowsint's graph serializer raises on a
nodeType it cannot resolve and has no per-node guard, so a single unregistered node
makes GET /api/sketches/{id}/graph return HTTP 500 for the WHOLE sketch. Both are
therefore gated behind `allow_finding_nodes` / `allow_attack_path_nodes` —
upload_router checks the registry and drops those nodes (keeping every other node)
rather than taking a campaign's graph offline. Run
scripts/register_cloudschism_type.py --apply once per install.

  Domain / Ip          public endpoints, keyed by the FQDN / address itself
  CloudAsset           cloud resources (registered custom type, shared with WF13)
  Service              exposed ports (registered custom type)
  Organization         cloud accounts / subscriptions / projects
  Individual           ONLY identities carrying an email-shaped principal (see
                       _identity_is_person) — WF06 fires Gravatar/breach/Maigret
                       enrichment across every Individual after an ingest, so
                       service principals and IAM roles are deliberately kept out
                       of that population and land as CloudAsset instead.
  CloudFinding         findings (custom, registration-gated — see above)
  CloudAttackPath      deterministic attack paths (custom, registration-gated)

Edges reuse SPOTTER's existing vocabulary wherever the semantics already exist —
EXPOSES, EXPOSES_SERVICE, AFFECTS, HAS_RISK, HAS_CLOUD_ASSET, HAS_PERMISSION — and
add two that had no equivalent: USES_FINDING (a path chains a finding) and
ENTRY_POINT (a path enters through a public endpoint).

nodeLabel is the MERGE key
──────────────────────────
Flowsint MERGEs on nodeLabel, so two nodes sharing a label are ONE node. Labels
here are built to be unique per real-world entity:

  * Storage buckets use `"<service>:<bucket>"` — deliberately the same label WF13's
    domain recon writes, so a bucket found by both sources converges on one node.
  * Every other resource uses `"<service>:<name>@<account>"`, which cannot collide
    with WF13's shape and keeps same-named resources in different accounts apart.
  * Service nodes are suffixed with their asset (`"22/tcp@ec2:web-01@1234"`). A bare
    `"22/tcp (ssh)"` would collapse every host's SSH port into a single node.
"""

from __future__ import annotations

import gzip
import io
import ipaddress
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# The custom types findings and attack paths land on. Kept in sync with
# flowsint-custom/types/cloud_finding.py, flowsint-custom/types/cloud_attack_path.py
# and scripts/register_cloudschism_type.py.
FINDING_NODE_TYPE = "CloudFinding"
ATTACK_PATH_NODE_TYPE = "CloudAttackPath"

# Both must be registered before nodes of those types are written — an
# unresolvable nodeType 500s GET /graph for the whole sketch.
REQUIRED_CUSTOM_TYPES = (FINDING_NODE_TYPE, ATTACK_PATH_NODE_TYPE)

SOURCE = "cloudschism"


# ── Bounds ────────────────────────────────────────────────────────────────────
#
# A large tenant scan carries tens of thousands of resources. Importing all of it
# would swamp the sketch and bury the engagement-relevant surface, so each category
# is capped and every truncation is reported in `errors` — a silent cap reads as
# "we covered everything" when it did not.

MAX_ENDPOINTS  = int(os.environ.get("SPOTTER_CS_MAX_ENDPOINTS", "5000"))
MAX_FINDINGS   = int(os.environ.get("SPOTTER_CS_MAX_FINDINGS", "5000"))
MAX_PATHS      = int(os.environ.get("SPOTTER_CS_MAX_PATHS", "2000"))
MAX_IDENTITIES = int(os.environ.get("SPOTTER_CS_MAX_IDENTITIES", "5000"))
MAX_ASSETS     = int(os.environ.get("SPOTTER_CS_MAX_ASSETS", "10000"))
MAX_SERVICES   = int(os.environ.get("SPOTTER_CS_MAX_SERVICES", "5000"))

# Guard against a zip bomb / a 2 GB canonical export: refuse to decompress a single
# member larger than this. The compatibility report is the one member that can get
# genuinely large, hence the generous default.
MAX_MEMBER_BYTES = int(os.environ.get("SPOTTER_CS_MAX_MEMBER_BYTES", str(512 * 1024 * 1024)))

# Directories inside an output dir that never carry ingestable structure. `html/`
# alone can be tens of thousands of files.
_SKIP_DIR_PARTS = (
    "html", "attack-paths", "visual-review", "collected-data", "customer-report",
    "delivery-audits", "logs", ".cloudschism-checkpoints", ".cloudschism-collection",
    ".attack-paths-rendering",
)

# Files whose presence identifies a directory / zip as CloudSchism output. Every
# generation profile writes all of these except the report projection, which is
# either plaintext or gzip.
_MANIFEST_MEMBERS = frozenset({
    "provider-artifacts.json",
    "cloudschism-report.json",
    "cloudschism-report.json.gz",
    "cloudschism-records.sqlite3",
    "cloudschism-scan-health.json",
    "output-profile.json",
    "generation-provenance.json",
})

# Members read for graph content, by basename.
_CONTENT_MEMBERS = (
    "public-endpoints.json",
    "external-exposures.json",
    "attack-graph.json",
    "attack-paths.json",
    "findings.json",
    "storage-accounts.json",
    "vulnerabilities.json",
    "cloudschism-report.json",
    "cloudschism-report.json.gz",
    "generation-provenance.json",
    "aws-inventory.json", "aws-inventory.json.gz",
    "azure-inventory.json", "azure-inventory.json.gz",
    "m365-inventory.json", "m365-inventory.json.gz",
    "gcp-inventory.json", "gcp-inventory.json.gz",
)

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_*-]+\.)+[A-Za-z]{2,}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


# ── Result containers ─────────────────────────────────────────────────────────

@dataclass
class Entity:
    temp_id: str
    entity_type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Relationship:
    source_temp_id: str
    target_temp_id: str
    label: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloudSchismResult:
    entities: List[Entity] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)
    scan: Dict[str, Any] = field(default_factory=dict)

    def to_flowsint_batch(self) -> Tuple[List[dict], List[dict]]:
        """Convert to the nodes/edges format flowsint_client.batch_import() expects."""
        nodes = []
        for ent in self.entities:
            nodes.append({
                "id": ent.temp_id,
                "entity_type": ent.entity_type,
                "nodeLabel": ent.label,
                # nodeLabel must live in `data` too: the Pydantic model is built from
                # `data`, and the serializer derives the Neo4j MERGE key from the
                # model's nodeLabel. A node carrying only `label` merges on ''.
                "data": {**ent.properties, "nodeLabel": ent.label,
                         "label": ent.label, "type": ent.entity_type},
                "include": True,
                # node_id must equal id so edge resolution can map temp ids.
                "node_id": ent.temp_id,
            })
        edges = [{
            "from_id": rel.source_temp_id,
            "to_id": rel.target_temp_id,
            "label": rel.label,
            "data": rel.data,
        } for rel in self.relationships]
        return nodes, edges

    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for ent in self.entities:
            by_type[ent.entity_type] = by_type.get(ent.entity_type, 0) + 1
        return {
            "sources": list(self.sources),
            "nodes_by_type": by_type,
            "edges": len(self.relationships),
            "counts": dict(self.counts),
            "scan": dict(self.scan),
        }


# ── Small helpers ─────────────────────────────────────────────────────────────

def _first(obj: Dict[str, Any], *names: str) -> str:
    """First non-empty scalar among `names`, matched case-insensitively."""
    if not isinstance(obj, dict):
        return ""
    lowered = {str(k).strip().lower(): v for k, v in obj.items()}
    for name in names:
        val = lowered.get(name.lower())
        if isinstance(val, (str, int, float)) and str(val).strip():
            return str(val).strip()
    return ""


def _clean(value: Any) -> Any:
    """
    Make a value safe to store as a Neo4j property.

    Lists and dicts are JSON-encoded — the same thing WF12/WF13 do for
    process_list, open_ports and manager_candidates. Scalars pass through with
    their native type, which matters: an undeclared int stays queryable as an int
    (see flowsint-custom-type-str-coercion).
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    try:
        return json.dumps(value, default=str)[:8000]
    except Exception:
        return str(value)[:8000]


def _props(**kwargs: Any) -> Dict[str, Any]:
    """Drop empty values so a node never carries a wall of null properties."""
    out: Dict[str, Any] = {}
    for key, val in kwargs.items():
        if val is None or val == "" or val == [] or val == {}:
            continue
        out[key] = _clean(val)
    return out


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _short(value: str, limit: int = 60) -> str:
    value = " ".join(str(value or "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _resource_name(resource_id: str) -> str:
    """
    Last meaningful segment of a cloud resource id.

    Covers an ARN (`arn:aws:s3:::bucket`, `.../function:name`), an Azure resource
    id (`/subscriptions/../providers/Microsoft.Web/sites/app`) and a GCP resource
    name (`//compute.googleapis.com/projects/p/zones/z/instances/i`).
    """
    raw = str(resource_id or "").strip().rstrip("/")
    if not raw:
        return ""
    for sep in ("/", ":"):
        if sep in raw:
            tail = raw.rsplit(sep, 1)[-1]
            if tail:
                raw = tail
                break
    return raw


def _account_from_resource_id(resource_id: str) -> str:
    """
    Pull the owning account / subscription / project out of a resource id.

    Attack paths carry no account field of their own, only the resources they
    touch, so this is what scopes a path label and links it to its Organization.
    Returns '' when the id carries no scope — the caller falls back to provider.
    """
    rid = str(resource_id or "").strip()
    if not rid:
        return ""
    if rid.startswith("arn:"):
        parts = rid.split(":")
        return parts[4] if len(parts) > 4 and parts[4] else ""
    segments = [s for s in rid.replace("\\", "/").split("/") if s]
    for marker in ("subscriptions", "projects", "folders", "organizations"):
        if marker in segments:
            idx = segments.index(marker)
            if idx + 1 < len(segments):
                return segments[idx + 1]
    return ""


def _service_of(resource_type: str, resource_id: str) -> str:
    """
    A short service token for a resource: 's3', 'ec2', 'microsoft.web/sites'…

    Used in the node label, so it is kept stable and lowercase rather than pretty.
    """
    rtype = str(resource_type or "").strip().lower()
    if rtype:
        # AWS "AWS::S3::Bucket" → s3 ; Azure "Microsoft.Web/sites" → web/sites
        if "::" in rtype:
            parts = [p for p in rtype.split("::") if p and p != "aws"]
            return parts[0] if parts else rtype
        if rtype.startswith("microsoft."):
            return rtype.split(".", 1)[1]
        return rtype
    rid = str(resource_id or "").lower()
    if rid.startswith("arn:"):
        parts = rid.split(":")
        if len(parts) > 2:
            return parts[2]
    return "resource"


# ── Graph builder ─────────────────────────────────────────────────────────────

class _Builder:
    """
    Accumulates entities and relationships with per-category caps and dedup.

    Dedup is on the temp id; the temp id is derived from the same value that goes
    into nodeLabel, so two artifacts describing the same endpoint or resource
    converge on one node instead of racing to overwrite each other.
    """

    def __init__(self) -> None:
        self.result = CloudSchismResult()
        self._seen: Dict[str, Entity] = {}
        self._edges: set = set()
        self._capped: Dict[str, int] = {}
        self._counts: Dict[str, int] = {}
        # resource id → the temp id of the CloudAsset created for it. Assets are
        # keyed differently for buckets than for everything else, so this is the
        # only reliable way to find one back by the id an attack path cites.
        self._asset_by_resource: Dict[str, str] = {}

    # -- capacity ------------------------------------------------------------

    # category → (cap, the env var that raises it). The env name is carried rather
    # than derived: pluralising "identity" by appending "S" told operators to set
    # SPOTTER_CS_MAX_IDENTITYS, which does nothing.
    _CAPS = {
        "endpoint": (MAX_ENDPOINTS, "SPOTTER_CS_MAX_ENDPOINTS"),
        "finding":  (MAX_FINDINGS, "SPOTTER_CS_MAX_FINDINGS"),
        "path":     (MAX_PATHS, "SPOTTER_CS_MAX_PATHS"),
        "identity": (MAX_IDENTITIES, "SPOTTER_CS_MAX_IDENTITIES"),
        "asset":    (MAX_ASSETS, "SPOTTER_CS_MAX_ASSETS"),
        "service":  (MAX_SERVICES, "SPOTTER_CS_MAX_SERVICES"),
    }

    def _take(self, category: str) -> bool:
        """Reserve one slot in `category`; False once its cap is reached."""
        cap = (self._CAPS.get(category) or (None, ""))[0]
        used = self._counts.get(category, 0)
        if cap is not None and used >= cap:
            self._capped[category] = self._capped.get(category, 0) + 1
            return False
        self._counts[category] = used + 1
        return True

    # -- nodes ---------------------------------------------------------------

    def add(self, temp_id: str, entity_type: str, label: str,
            properties: Dict[str, Any], category: str) -> str:
        """
        Create or enrich one node. Returns its temp id, or '' when capped.

        A repeat id merges properties rather than replacing the node: the same
        resource is commonly described by an endpoint record, an exposure record
        and a finding, each knowing a different subset of its attributes.
        """
        if not temp_id or not label:
            return ""
        existing = self._seen.get(temp_id)
        if existing is not None:
            for key, val in properties.items():
                if val not in (None, "", [], {}) and not existing.properties.get(key):
                    existing.properties[key] = val
            return temp_id
        if not self._take(category):
            return ""
        entity = Entity(temp_id=temp_id, entity_type=entity_type,
                        label=_short(label), properties=properties)
        self._seen[temp_id] = entity
        self.result.entities.append(entity)
        return temp_id

    def link(self, src: str, dst: str, label: str,
             data: Optional[Dict[str, Any]] = None) -> None:
        """
        Join two nodes, but only if both actually exist.

        Attack paths reference findings and resources by id, and those ids may name
        something that was capped, dropped as an unregistered type, or simply not
        in this export. An edge to a node that was never created is a dangling
        reference the importer cannot resolve, so the check is enforced here rather
        than left to each caller to remember.
        """
        if not src or not dst or src == dst:
            return
        if src not in self._seen or dst not in self._seen:
            return
        key = (src, dst, label)
        if key in self._edges:
            return
        self._edges.add(key)
        self.result.relationships.append(
            Relationship(source_temp_id=src, target_temp_id=dst,
                         label=label, data=data or {}))

    def error(self, message: str) -> None:
        if message not in self.result.errors:
            self.result.errors.append(message)

    def finish(self) -> CloudSchismResult:
        for category, dropped in sorted(self._capped.items()):
            cap, env_name = self._CAPS.get(category, (None, ""))
            self.error(
                f"{dropped} {category} record(s) dropped: cap of {cap} reached. "
                f"Raise {env_name} to import more, or scan a narrower scope."
            )
        self.result.counts = dict(self._counts)
        return self.result

    # -- typed node constructors ---------------------------------------------

    def account(self, account_id: str, provider: str = "",
                name: str = "") -> str:
        """A cloud account / subscription / project, as an Organization."""
        ident = str(account_id or "").strip()
        if not ident:
            return ""
        label = name or ident
        return self.add(
            f"cs:account:{ident.lower()}", "Organization", label,
            # `name` is Organization's REQUIRED primary field; a built-in node
            # missing it fails validation and is dropped without a word.
            _props(name=label, account_id=ident, provider=provider,
                   source=SOURCE, org_kind="cloud_account"),
            "asset",
        )

    def asset(self, resource_id: str, resource_type: str = "", provider: str = "",
              account_id: str = "", region: str = "", name: str = "",
              **extra: Any) -> str:
        """
        A cloud resource, as a CloudAsset.

        Buckets keep WF13's `"<service>:<bucket>"` label so a bucket discovered by
        both domain recon and a posture scan lands on one node; everything else is
        account-qualified so same-named resources in different accounts stay apart.
        """
        rid = str(resource_id or "").strip()
        if not rid:
            return ""
        service = _service_of(resource_type, rid)
        display = name or _resource_name(rid)
        bucket = display if service in ("s3", "gcs", "blob", "storage", "buckets") else ""
        if bucket:
            label = f"{service}:{bucket}"
            temp_id = f"cs:asset:{service}:{bucket.lower()}"
        else:
            scope = str(account_id or "").strip()
            label = f"{service}:{display}" + (f"@{scope}" if scope else "")
            temp_id = f"cs:asset:{rid.lower()}"
        self._asset_by_resource.setdefault(rid.lower(), temp_id)
        return self.add(
            temp_id, "CloudAsset", label,
            _props(
                # Declared on the registered type → stored as strings.
                provider=provider, service=service, bucket=bucket,
                endpoint=extra.pop("endpoint", ""), hostname=extra.pop("hostname", ""),
                domain=extra.pop("domain", ""), source=SOURCE,
                # Undeclared → keep native types and stay queryable as such.
                resource_id=rid, resource_type=resource_type,
                account_id=account_id, region=region, resource_name=display,
                **extra,
            ),
            "asset",
        )

    def endpoint(self, value: str, provider: str = "", **extra: Any) -> str:
        """A public endpoint, as a Domain or an Ip depending on its shape."""
        val = str(value or "").strip().rstrip(".")
        if not val:
            return ""
        if _is_ip(val):
            # `address` is Ip's REQUIRED primary field.
            return self.add(f"cs:ip:{val}", "Ip", val,
                            _props(address=val, ip=val, provider=provider,
                                   source=SOURCE, **extra),
                            "endpoint")
        host = val.split("//")[-1].split("/")[0].split(":")[0]
        if not _DOMAIN_RE.match(host):
            return ""
        # `domain` is Domain's REQUIRED primary field.
        return self.add(f"cs:domain:{host.lower()}", "Domain", host,
                        _props(domain=host, provider=provider, source=SOURCE, **extra),
                        "endpoint")

    def service(self, asset_temp_id: str, asset_label: str, port: Any,
                protocol: str = "tcp", name: str = "", **extra: Any) -> str:
        """
        An exposed port on a cloud asset.

        The label carries the asset because nodeLabel is the MERGE key — a bare
        "22/tcp" would fuse every host's SSH into one node.
        """
        try:
            port_num = int(str(port).strip())
        except (TypeError, ValueError):
            return ""
        proto = (protocol or "tcp").lower()
        display = f"{port_num}/{proto}" + (f" ({name})" if name else "")
        label = f"{display}@{asset_label}" if asset_label else display
        temp_id = f"cs:service:{asset_temp_id or 'unbound'}:{port_num}:{proto}"
        sid = self.add(temp_id, "Service", label,
                       _props(name=name or display, port=port_num, protocol=proto,
                              state="open", source=SOURCE, **extra),
                       "service")
        if sid and asset_temp_id:
            self.link(asset_temp_id, sid, "EXPOSES_SERVICE")
        return sid

    def finding(self, record: Dict[str, Any], allow: bool) -> str:
        """
        One CloudSchism finding, as a CloudFinding.

        Returns '' when the custom type is not registered — the caller keeps every
        other node rather than 500-ing the sketch.
        """
        if not allow:
            return ""
        control = (_first(record, "control_id", "id", "finding_instance_id")
                   or "").strip()
        title = _first(record, "title", "queue_summary") or control
        if not control and not title:
            return ""
        scope = (_first(record, "provider_scope", "account_id", "subscription_id",
                        "provider") or "").strip()
        label = f"{control or title}" + (f"@{scope}" if scope else "")
        # Keyed on the label, NOT on finding_instance_id. The same finding arrives
        # from findings.json (with an instance id) and from attack-graph.json
        # (without one); keying on the instance id would emit two nodes that then
        # silently MERGE onto one another in Neo4j, overstating the import count.
        temp_id = f"cs:finding:{label.lower()}"
        return self.add(
            temp_id, FINDING_NODE_TYPE, label,
            _props(
                finding_id=_first(record, "finding_instance_id", "id"),
                control_id=control,
                title=title,
                severity=_first(record, "severity"),
                provider=_first(record, "provider"),
                service=_first(record, "service"),
                resource_id=_first(record, "resource_id"),
                region=_first(record, "region", "location"),
                account_id=scope,
                finding_class=_first(record, "finding_class"),
                exploitability=_first(record, "exploitability"),
                evidence_state=_first(record, "evidence_state"),
                confidence=_first(record, "confidence"),
                flagged_reason=_short(_first(record, "flagged_reason", "impact"), 500),
                remediation=_short(_first(record, "recommendation", "remediation_steps"), 500),
                source=SOURCE,
                # Undeclared → keep their real types for Cypher predicates.
                attack_path_relevance=bool(record.get("attack_path_relevance")),
                suppressed=bool(record.get("suppressed")),
                related_techniques=record.get("related_techniques") or [],
            ),
            "finding",
        )

    def scope_for(self, resource_ids: List[str], provider: str = "") -> str:
        """
        Work out which account a set of resources belongs to.

        Tried in order: parse it out of a resource id; then ask the CloudAsset
        already created for one of them. The second step matters — an S3 ARN is
        `arn:aws:s3:::bucket` with *empty* account and region fields, so a path
        that only touches buckets can never name its account from the ARN alone.
        The endpoint or finding record that created the asset did know it.

        Falls back to the provider, which keeps two providers' paths apart even
        when neither can be attributed to an account.
        """
        for rid in resource_ids:
            account = _account_from_resource_id(rid)
            if account:
                return account
        for rid in resource_ids:
            entity = self._seen.get(self._asset_by_resource.get(str(rid).lower(), ""))
            if entity and entity.properties.get("account_id"):
                return str(entity.properties["account_id"])
        return provider

    def finding_ref(self, control_id: str, scope: str) -> str:
        """
        The temp id a CloudFinding *would* have, for linking without creating one.

        Attack paths cite findings by control id, and `finding()` keys its node on
        "<control_id>@<scope>" — so a path can address a finding it did not create.
        link() drops the edge when that node is not present, which is the point:
        cited-but-absent findings must not become dangling references.
        """
        if not control_id:
            return ""
        label = f"{control_id}" + (f"@{scope}" if scope else "")
        return f"cs:finding:{label.lower()}"

    def attack_path(self, record: Dict[str, Any], allow: bool) -> str:
        """
        One deterministic attack path, as a CloudAttackPath.

        Handles both on-disk shapes: attack-paths.json is written through
        attack_path_export_record() (which adds path_type / trust_state /
        entry_points / target_impacts), while CloudSchism-report.json carries the
        raw AttackPathRecord dump without them. Missing keys are simply absent.
        """
        if not allow:
            return ""
        path_id = _first(record, "id", "rule_id")
        title = _first(record, "title") or path_id
        if not path_id and not title:
            return ""
        resources = [r for r in (record.get("affected_resource_ids") or []) if r]
        scope = self.scope_for(resources, _first(record, "provider"))
        label = f"{path_id or title}" + (f"@{scope}" if scope else "")
        return self.add(
            f"cs:path:{label.lower()}", ATTACK_PATH_NODE_TYPE, label,
            _props(
                # Declared on the registered type → stored as strings.
                path_id=path_id,
                title=title,
                severity=_first(record, "severity"),
                provider=_first(record, "provider"),
                rule_id=_first(record, "rule_id"),
                path_type=_first(record, "path_type"),
                trust_state=_first(record, "trust_state"),
                evidence_state=_first(record, "evidence_state"),
                evidence_confidence=_first(record, "evidence_confidence"),
                completeness=_first(record, "attack_path_completeness"),
                rule_confidence=_first(record, "rule_confidence"),
                account_id=scope,
                reasoning=_short(_first(record, "reasoning"), 800),
                remediation=_short(_first(record, "remediation", "remediation_guidance"), 500),
                tactic_chain=record.get("tactic_chain") or [],
                entry_points=record.get("entry_points") or record.get("public_endpoints") or [],
                missing_prerequisites=record.get("missing_prerequisites") or [],
                source=SOURCE,
                # Undeclared → keep their real types for Cypher predicates.
                confidence_score=record.get("confidence_score"),
                severity_ceiling_applied=bool(record.get("severity_ceiling_applied")),
                has_contradictions=bool(record.get("contradictions")),
                affected_resource_count=len(resources),
                finding_count=len([f for f in (record.get("finding_ids") or []) if f]),
            ),
            "path",
        )

    def identity(self, record: Dict[str, Any], provider: str = "") -> str:
        """
        One cloud identity.

        Only principals carrying an email-shaped identifier become Individual
        nodes: WF06 launches Gravatar / breach / Maigret enrichment over every
        Individual in the sketch after an ingest, so filling that population with
        service principals and IAM roles would fire per-person OSINT at machines.
        Everything else lands as a CloudAsset in the identity service.
        """
        object_id = _first(record, "id", "objectId", "object_id", "appId", "app_id",
                           "UserId", "user_id", "Arn", "name")
        display = _first(record, "displayName", "display_name", "userPrincipalName",
                         "UserName", "user_name", "mail", "email", "appDisplayName",
                         "name") or object_id
        if not display:
            return ""
        email = ""
        for candidate in (_first(record, "mail", "email", "emailAddress"),
                          _first(record, "userPrincipalName", "upn")):
            if candidate and _EMAIL_RE.match(candidate):
                email = candidate.lower()
                break
        kind = (_first(record, "@odata.type", "servicePrincipalType", "identity_type",
                       "type") or "").lower()

        if email and self._identity_is_person(kind):
            return self.add(
                f"cs:identity:{(email or object_id).lower()}", "Individual", display,
                # Individual is the one built-in with no required primary field, so
                # full_name is left to real name data rather than forced from an id.
                _props(username=_first(record, "userPrincipalName", "UserName", "upn"),
                       email=email, object_id=object_id, provider=provider,
                       identity_kind=kind or "user",
                       account_enabled=record.get("accountEnabled"),
                       source=SOURCE),
                "identity",
            )
        return self.add(
            f"cs:identity:{(object_id or display).lower()}", "CloudAsset",
            f"identity:{display}",
            _props(provider=provider, service="identity", source=SOURCE,
                   object_id=object_id, identity_kind=kind or "principal",
                   display_name=display, principal_email=email),
            "identity",
        )

    @staticmethod
    def _identity_is_person(kind: str) -> bool:
        """False for the identity kinds that are machines wearing a principal."""
        machine = ("serviceprincipal", "application", "managedidentity",
                   "managed_identity", "role", "serviceaccount", "service_account",
                   "group")
        return not any(token in kind for token in machine)


# ── Artifact readers ──────────────────────────────────────────────────────────

def _as_list(value: Any) -> List[dict]:
    """Coerce an artifact body to a list of records."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        for wrapper in ("items", "records", "data", "results", "findings", "nodes"):
            inner = value.get(wrapper)
            if isinstance(inner, list):
                return [v for v in inner if isinstance(v, dict)]
        return [value]
    return []


def _ingest_public_endpoints(builder: _Builder, body: Any) -> None:
    for rec in _as_list(body):
        value = _first(rec, "value")
        if not value:
            continue
        provider = _first(rec, "provider")
        account = _first(rec, "account_id", "subscription_id")
        eid = builder.endpoint(
            value, provider=provider,
            endpoint_role=_first(rec, "endpoint_role"),
            authentication_state=_first(rec, "authentication_state"),
            reachability_state=_first(rec, "reachability_state"),
            confidence=_first(rec, "confidence"),
            account_id=account,
            region=_first(rec, "region"),
            url=_first(rec, "url"),
            publicly_accessible_inferred=rec.get("publicly_accessible_inferred"),
        )
        if not eid:
            continue
        resource_id = _first(rec, "source_resource_id")
        aid = ""
        if resource_id:
            aid = builder.asset(
                resource_id,
                resource_type=_first(rec, "source_resource_type"),
                provider=provider, account_id=account,
                region=_first(rec, "region"), endpoint=value,
                hostname="" if _is_ip(value) else value,
            )
            builder.link(aid, eid, "EXPOSES")
        if account and aid:
            # Reuse the id from the call above rather than rebuilding it: asset()
            # derives its key from the resource *type*, so a second call without
            # that type would key an Azure resource differently and create a
            # duplicate node for the same thing.
            builder.link(builder.account(account, provider), aid, "HAS_CLOUD_ASSET")


def _ingest_external_exposures(builder: _Builder, body: Any) -> None:
    for rec in _as_list(body):
        resource_id = _first(rec, "resource_id")
        if not resource_id:
            continue
        provider = _first(rec, "provider")
        account = _first(rec, "account_id", "subscription_id")
        aid = builder.asset(
            resource_id, resource_type=_first(rec, "resource_type"),
            provider=provider, account_id=account, region=_first(rec, "region"),
            exposure_type=_first(rec, "exposure_type"),
            authentication_state=_first(rec, "authentication_state"),
            reachability_state=_first(rec, "reachability_state"),
            exposure_reasoning=_short(_first(rec, "reasoning"), 500),
        )
        if not aid:
            continue
        label = builder._seen[aid].label if aid in builder._seen else ""
        protocols = [p for p in (rec.get("protocols") or []) if p]
        proto = str(protocols[0]).lower() if protocols else "tcp"
        ports = list(rec.get("open_management_ports") or []) + list(rec.get("ports") or [])
        for port in dict.fromkeys(ports):
            builder.service(
                aid, label, port, protocol=proto,
                name="management" if port in (rec.get("open_management_ports") or []) else "",
                authentication_state=_first(rec, "authentication_state"),
            )
        for value in rec.get("public_endpoints") or []:
            eid = builder.endpoint(str(value), provider=provider)
            builder.link(aid, eid, "EXPOSES")
        if account:
            builder.link(builder.account(account, provider), aid, "HAS_CLOUD_ASSET")


def _ingest_findings(builder: _Builder, body: Any, allow_findings: bool) -> int:
    written = 0
    for rec in _as_list(body):
        fid = builder.finding(rec, allow_findings)
        if not fid:
            continue
        written += 1
        resource_id = _first(rec, "resource_id")
        provider = _first(rec, "provider")
        account = _first(rec, "provider_scope", "account_id", "subscription_id")
        if resource_id:
            aid = builder.asset(resource_id, provider=provider, account_id=account,
                                region=_first(rec, "region", "location"))
            # AFFECTS mirrors ADRisk -[AFFECTS]-> its subject, so cloud and AD
            # findings answer the same traversal.
            builder.link(fid, aid, "AFFECTS")
        if account:
            builder.link(builder.account(account, provider), fid, "HAS_RISK")
    return written


def _ingest_attack_paths(builder: _Builder, body: Any, allow_paths: bool,
                         allow_findings: bool) -> int:
    """
    Read attack-paths.json (or report.attack_paths) into CloudAttackPath nodes.

    A path is only worth a node because of what it connects, so the resources it
    reaches, the findings it chains and the endpoints it enters through are all
    linked. Every link goes through builder.link(), which drops edges to nodes this
    export never produced rather than emitting dangling references.
    """
    written = 0
    for rec in _as_list(body):
        pid = builder.attack_path(rec, allow_paths)
        if not pid:
            continue
        written += 1
        provider = _first(rec, "provider")
        resources = [r for r in (rec.get("affected_resource_ids") or []) if r]
        # Same resolution the node label used, so the path, its account link and
        # its finding links all agree on one scope.
        scope = builder.scope_for(resources, provider)

        for resource_id in resources:
            aid = builder.asset(resource_id, provider=provider,
                                account_id=_account_from_resource_id(resource_id) or scope)
            # AFFECTS is the label ADRisk and CloudFinding already use for
            # "this problem lands on that thing".
            builder.link(pid, aid, "AFFECTS")

        for control_id in (rec.get("finding_ids") or []):
            builder.link(pid, builder.finding_ref(str(control_id), scope),
                         "USES_FINDING")

        for value in (rec.get("entry_points") or rec.get("public_endpoints") or []):
            # entry_points falls back to sentinels like "initial_access" when the
            # path has no concrete endpoint; endpoint() rejects those on shape.
            builder.link(pid, builder.endpoint(str(value), provider=provider),
                         "ENTRY_POINT")

        if scope:
            builder.link(builder.account(scope, provider), pid, "HAS_RISK")
    if written and not allow_findings:
        builder.error(
            f"{written} attack path(s) imported without their finding links: "
            f"CloudFinding is not registered, so the findings they chain were dropped."
        )
    return written


def _ingest_storage_accounts(builder: _Builder, body: Any) -> None:
    for rec in _as_list(body):
        resource_id = _first(rec, "id")
        name = _first(rec, "name")
        if not resource_id and not name:
            continue
        containers = rec.get("containers") or []
        public_containers = [
            _first(c, "name") for c in containers
            if isinstance(c, dict) and str(c.get("public_access") or "").lower()
            not in ("", "none", "false")
        ]
        aid = builder.asset(
            resource_id or name, resource_type="storage", provider="azure",
            account_id=_first(rec, "subscription_id"), region=_first(rec, "location"),
            name=name,
            public_network_access=_first(rec, "public_network_access"),
            allow_blob_public_access=rec.get("allow_blob_public_access"),
            anonymous_reachable=rec.get("anonymous_reachable"),
            minimum_tls_version=_first(rec, "minimum_tls_version"),
            container_count=len(containers),
            public_containers=public_containers,
        )
        for endpoint in (rec.get("endpoints") or {}).values():
            if isinstance(endpoint, str) and endpoint:
                builder.link(aid, builder.endpoint(endpoint, provider="azure"), "EXPOSES")


# Attack-graph node kinds → how each is materialised. Kinds absent here carry no
# entity SPOTTER models (attack_path_rule, attack_primitive, network_path, region,
# location) and are skipped rather than invented.
_GRAPH_KIND_ASSET = ("resource", "cloud_account", "subscription", "organization",
                     "folder", "project")


def _ingest_attack_graph(builder: _Builder, body: Any, allow_findings: bool,
                         allow_paths: bool = True) -> None:
    """
    Read attack-graph.json — the one artifact carrying real topology.

    Its node ids are opaque (`resource::<id>`), so a map from graph id to the temp
    id we actually created is kept in order to translate the edge list.
    """
    if not isinstance(body, dict):
        return
    nodes = body.get("nodes") or []
    edges = body.get("edges") or []
    id_map: Dict[str, str] = {}

    for node in nodes:
        if not isinstance(node, dict):
            continue
        kind = str(node.get("kind") or "").lower()
        gid = str(node.get("id") or "")
        if not gid:
            continue
        label = _first(node, "label")
        provider = _first(node, "provider")
        resource_id = _first(node, "resource_id") or label
        meta = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}

        if kind in ("cloud_account", "subscription", "organization", "project", "folder"):
            temp = builder.account(resource_id or label, provider, name=label)
        elif kind == "resource":
            temp = builder.asset(resource_id, resource_type=_first(meta, "type", "resource_type"),
                                 provider=provider,
                                 account_id=_first(meta, "account_id", "subscription_id"),
                                 region=_first(meta, "region", "location"), name=label)
        elif kind == "public_endpoint":
            temp = builder.endpoint(
                label or resource_id, provider=provider,
                account_id=_first(meta, "account_id", "subscription_id"),
                region=_first(meta, "region"), confidence=_first(meta, "confidence"))
        elif kind == "identity":
            temp = builder.identity(
                {"id": resource_id, "displayName": label,
                 "userPrincipalName": label if _EMAIL_RE.match(label or "") else "",
                 "type": _first(meta, "type")},
                provider=provider)
        elif kind == "finding":
            temp = builder.finding({**meta, "id": resource_id or gid, "title": label,
                                    "provider": provider}, allow_findings)
        elif kind == "attack_path":
            temp = builder.attack_path({**meta, "id": resource_id or gid,
                                        "title": label, "provider": provider},
                                       allow_paths)
        else:
            continue
        if temp:
            id_map[gid] = temp

    # CloudSchism relationship_type → SPOTTER's existing edge vocabulary. Anything
    # unmapped keeps its own name upper-cased rather than being dropped, so a new
    # CloudSchism rule still shows up in the graph.
    rel_map = {
        "endpoint_exposes_resource": "EXPOSES",
        "exposes": "EXPOSES",
        "finding_affects_resource": "AFFECTS",
        "affects": "AFFECTS",
        "affected_by_finding": "AFFECTS",
        "has_permission": "HAS_PERMISSION",
        "permission_affects": "HAS_PERMISSION",
        "attack_path_affects_resource": "AFFECTS",
        "attack_path_uses_finding": "USES_FINDING",
        "attack_path_entrypoint": "ENTRY_POINT",
        "contains_folder": "HAS_CLOUD_ASSET",
        "contains_project": "HAS_CLOUD_ASSET",
        "resource_represents_resource": "HAS_CLOUD_ASSET",
    }
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        src = id_map.get(str(edge.get("source") or ""))
        dst = id_map.get(str(edge.get("target") or ""))
        if not src or not dst:
            continue
        rel = str(edge.get("relationship_type") or "related_to").lower()
        builder.link(src, dst, rel_map.get(rel, re.sub(r"[^A-Z0-9_]", "", rel.upper()) or "RELATED_TO"))


def _ingest_identities(builder: _Builder, body: Any, provider_hint: str = "") -> int:
    """
    Pull principals out of a report or an inventory projection.

    Identity records live in provider-shaped containers, so the known ones are
    walked by name rather than guessing from the whole document.
    """
    if not isinstance(body, dict):
        return 0
    written = 0
    containers: List[Tuple[str, Any]] = []
    if isinstance(body.get("identities"), list):
        containers.append((provider_hint or "azure", body["identities"]))
    for key, provider in (("entra", "azure"), ("m365", "m365"),
                          ("aws_iam", "aws"), ("gcp_iam", "gcp")):
        section = body.get(key)
        if not isinstance(section, dict):
            continue
        for sub in ("users", "guest_users", "service_principals",
                    "identity_center_users", "service_accounts"):
            if isinstance(section.get(sub), list):
                containers.append((provider, section[sub]))
    for provider, records in containers:
        for rec in records:
            if isinstance(rec, dict) and builder.identity(rec, provider):
                written += 1
    return written


# ── Member resolution ─────────────────────────────────────────────────────────

def _decode_json(raw: bytes, name: str) -> Any:
    """Parse a member, transparently handling the .gz projections."""
    if name.endswith(".gz") or raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return json.loads(raw.decode("utf-8-sig", errors="replace"))


def _relevant(name: str) -> bool:
    """True for a member worth opening: a content artifact outside the noisy dirs."""
    parts = [p.lower() for p in name.replace("\\", "/").split("/")]
    if any(p in _SKIP_DIR_PARTS for p in parts[:-1]):
        return False
    return parts[-1] in _CONTENT_MEMBERS


def _pick_shallowest(names: Iterable[str]) -> Dict[str, str]:
    """
    Map basename → the shallowest path carrying it.

    Zipping a folder yields `scan-out/findings.json`, and a packaged engagement can
    nest that again. Depth-ordering keeps the top-level artifact from being shadowed
    by a same-named file in a subdirectory.
    """
    best: Dict[str, str] = {}
    for name in names:
        clean = name.replace("\\", "/")
        if clean.endswith("/"):
            continue
        base = clean.rsplit("/", 1)[-1].lower()
        depth = clean.count("/")
        if base not in best or depth < best[base].count("/"):
            best[base] = clean
    return best


def _consume(builder: _Builder, members: Dict[str, str],
             read: Callable[[str], bytes], allow_findings: bool,
             allow_paths: bool = True) -> None:
    """
    Drive the readers over whatever artifacts this output profile actually wrote.

    Order matters: the dedicated exports are richer and cheaper than the
    compatibility report, so the report is only opened for what they did not cover.
    """
    result = builder.result

    def load(base: str) -> Any:
        path = members.get(base)
        if not path:
            return None
        try:
            raw = read(path)
        except Exception as exc:
            builder.error(f"{base}: could not read ({exc})")
            return None
        if len(raw) > MAX_MEMBER_BYTES:
            builder.error(
                f"{base}: {len(raw)} bytes exceeds the {MAX_MEMBER_BYTES}-byte member "
                f"limit and was skipped. Raise SPOTTER_CS_MAX_MEMBER_BYTES to read it."
            )
            return None
        try:
            body = _decode_json(raw, base)
        except Exception as exc:
            builder.error(f"{base}: not readable JSON ({exc})")
            return None
        result.sources.append(base)
        return body

    # Scan provenance, read first and from the tiny artifact rather than from the
    # compatibility report — the report can be hundreds of MB and is not always
    # opened, but every profile writes this one and it is a few hundred bytes.
    provenance = load("generation-provenance.json")
    if isinstance(provenance, dict):
        rep = provenance.get("report") if isinstance(provenance.get("report"), dict) else {}
        result.scan = _props(
            provider=_first(rep, "provider"),
            scan_id=_first(rep, "scan_id"),
            completed_at=_first(rep, "completed_at"),
            output_profile=_first(rep, "output_profile"),
            redaction_mode=_first(rep, "redaction_mode"),
            tool_version=_first(provenance, "tool_version"),
            generated_at=_first(provenance, "generated_at"),
        )

    endpoints = load("public-endpoints.json")
    if endpoints is not None:
        _ingest_public_endpoints(builder, endpoints)

    exposures = load("external-exposures.json")
    if exposures is not None:
        _ingest_external_exposures(builder, exposures)

    storage = load("storage-accounts.json")
    if storage is not None:
        _ingest_storage_accounts(builder, storage)

    findings_written = 0
    findings = load("findings.json")
    if findings is not None:
        findings_written = _ingest_findings(builder, findings, allow_findings)

    # After findings: an attack path links to the findings it chains, and link()
    # only writes an edge when both endpoints exist. Reading paths first would
    # silently drop every USES_FINDING edge.
    paths_written = 0
    paths = load("attack-paths.json")
    if paths is not None:
        paths_written = _ingest_attack_paths(builder, paths, allow_paths, allow_findings)

    # Last: the graph adds topology between things the dedicated exports already
    # described, and its finding/path records are the thinner of the two shapes.
    graph = load("attack-graph.json")
    if graph is not None:
        _ingest_attack_graph(builder, graph, allow_findings, allow_paths)

    identities_written = 0
    for base in ("azure-inventory.json", "azure-inventory.json.gz",
                 "m365-inventory.json", "m365-inventory.json.gz",
                 "aws-inventory.json", "aws-inventory.json.gz",
                 "gcp-inventory.json", "gcp-inventory.json.gz"):
        if base not in members:
            continue
        body = load(base)
        if body is not None:
            identities_written += _ingest_identities(
                builder, body, provider_hint=base.split("-", 1)[0])

    # The analyst profile — the default — writes neither findings.json nor the
    # provider inventories, so without this fallback the most common scan there is
    # would import an attack surface with no findings and no identities behind it.
    needs_report = (endpoints is None
                    or (findings is None and allow_findings)
                    or (paths is None and allow_paths)
                    or identities_written == 0)
    if needs_report:
        report = load("cloudschism-report.json") or load("cloudschism-report.json.gz")
        if isinstance(report, dict):
            if endpoints is None and report.get("public_endpoints"):
                _ingest_public_endpoints(builder, report["public_endpoints"])
            if exposures is None and report.get("external_exposures"):
                _ingest_external_exposures(builder, report["external_exposures"])
            if storage is None and report.get("storage_accounts"):
                _ingest_storage_accounts(builder, report["storage_accounts"])
            if findings is None and report.get("findings"):
                findings_written += _ingest_findings(builder, report["findings"],
                                                     allow_findings)
            if paths is None and report.get("attack_paths"):
                paths_written += _ingest_attack_paths(builder, report["attack_paths"],
                                                      allow_paths, allow_findings)
            identities_written += _ingest_identities(builder, report)
            meta = report.get("metadata")
            if isinstance(meta, dict) and not result.scan:
                result.scan = _props(
                    provider=_first(meta, "provider", "account_type"),
                    scan_id=_first(meta, "scan_id", "id"),
                    started_at=_first(meta, "started_at", "start_time", "timestamp"),
                    tool_version=_first(meta, "tool_version", "version"),
                )

    if not result.sources:
        builder.error(
            "No readable CloudSchism artifacts found. Expected at least one of "
            "public-endpoints.json, external-exposures.json, attack-graph.json, "
            "findings.json or CloudSchism-report.json[.gz]."
        )
    if allow_findings and findings_written == 0 and "findings.json" not in result.sources:
        builder.error(
            "No findings imported: this output has no findings.json (the default "
            "`analyst` profile omits it) and its CloudSchism-report.json carried none. "
            "Re-run the scan with --output-profile integration for a findings export."
        )


# ── Entry points ──────────────────────────────────────────────────────────────

def is_cloudschism_zip(data: bytes) -> bool:
    """True when these zip bytes are a CloudSchism output directory."""
    if data[:2] != b"PK":
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except Exception:
        return False
    return _names_are_cloudschism(names)


def _names_are_cloudschism(names: Iterable[str]) -> bool:
    bases = {n.replace("\\", "/").rsplit("/", 1)[-1].lower() for n in names}
    if bases & _MANIFEST_MEMBERS:
        return True
    # A hand-assembled zip of just the JSON exports is still CloudSchism output.
    exports = {"findings.json", "public-endpoints.json", "attack-graph.json",
               "external-exposures.json", "attack-paths.json"}
    return len(bases & exports) >= 2


# Record keys that identify a bare export as CloudSchism's rather than some other
# tool's findings.json. Checked per-record, so a list of two unrelated dicts that
# happen to have an "id" cannot pass.
_EXPORT_FINGERPRINTS = {
    "findings.json": ("control_id", "finding_instance_id", "evidence_state",
                      "finding_class", "exploitability", "flagged_reason"),
    "public-endpoints.json": ("endpoint_role", "reachability_state",
                              "publicly_accessible_inferred", "source_resource_id"),
    "external-exposures.json": ("exposure_type", "reachability_state",
                                "confirmation_basis", "open_management_ports"),
    "attack-paths.json": ("rule_id", "attack_path_completeness", "tactic_chain",
                          "required_findings"),
}


def is_cloudschism(data: bytes, filename: str = "") -> bool:
    """True for a CloudSchism zip, or one of its JSON exports on its own."""
    if data[:2] == b"PK":
        return is_cloudschism_zip(data)
    base = os.path.basename(str(filename or "")).lower()
    if base.startswith("cloudschism-") and base.endswith((".json", ".json.gz")):
        return True
    if data[:2] == b"\x1f\x8b":
        return False
    head = data[:4096].lstrip()
    if not head[:1] in (b"{", b"["):
        return False
    try:
        body = json.loads(data.decode("utf-8-sig", errors="replace"))
    except Exception:
        return False

    # The compatibility report / a whole-report projection.
    if isinstance(body, dict):
        meta = body.get("metadata")
        markers = ("public_endpoints", "external_exposures", "attack_paths",
                   "collector_status", "resource_type_index")
        if isinstance(meta, dict) and sum(1 for m in markers if m in body) >= 2:
            return True
        # attack-graph.json is a bare {nodes, edges, projection}.
        if base == "attack-graph.json" and isinstance(body.get("nodes"), list):
            return any(isinstance(n, dict) and "kind" in n for n in body["nodes"][:20])
        return False

    # A bare array export — identified by its filename plus its record shape, so a
    # findings.json from an unrelated scanner is not force-fed to this parser.
    fingerprint = _EXPORT_FINGERPRINTS.get(base)
    if not fingerprint or not isinstance(body, list):
        return False
    records = [r for r in body[:20] if isinstance(r, dict)]
    if not records:
        return False
    return any(sum(1 for key in fingerprint if key in rec) >= 2 for rec in records)


def parse_zip_bytes(data: bytes, allow_finding_nodes: bool = True,
                    allow_attack_path_nodes: bool = True) -> CloudSchismResult:
    """Parse a zipped CloudSchism output directory."""
    builder = _Builder()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [n for n in zf.namelist() if _relevant(n)]
            members = _pick_shallowest(names)
            _consume(builder, members, lambda p: zf.read(p),
                     allow_finding_nodes, allow_attack_path_nodes)
    except zipfile.BadZipFile as exc:
        builder.error(f"Not a readable ZIP: {exc}")
    return builder.finish()


def parse_directory(path: str, allow_finding_nodes: bool = True,
                    allow_attack_path_nodes: bool = True) -> CloudSchismResult:
    """
    Parse an unpacked CloudSchism output directory.

    This is the path for output too large to move through the browser upload —
    members are read from disk one at a time instead of holding the whole archive
    in memory (see scripts/ingest_cloudschism.py).
    """
    builder = _Builder()
    root = os.path.abspath(path)
    collected: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_DIR_PARTS]
        for name in filenames:
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            if _relevant(rel):
                collected.append(rel.replace("\\", "/"))
    members = _pick_shallowest(collected)

    def read(rel: str) -> bytes:
        with open(os.path.join(root, rel), "rb") as fh:
            return fh.read()

    _consume(builder, members, read, allow_finding_nodes, allow_attack_path_nodes)
    return builder.finish()


def parse_bytes(data: bytes, filename: str = "",
                allow_finding_nodes: bool = True,
                allow_attack_path_nodes: bool = True) -> CloudSchismResult:
    """Parse a zip, or a single structured export uploaded on its own."""
    if data[:2] == b"PK":
        return parse_zip_bytes(data, allow_finding_nodes, allow_attack_path_nodes)

    builder = _Builder()
    base = os.path.basename(str(filename or "")).lower() or "cloudschism-report.json"
    if base.endswith(".gz") or data[:2] == b"\x1f\x8b":
        base = base if base.endswith(".gz") else base + ".gz"
    # A lone file is handed to the same reader set, keyed by its own name, so the
    # zip and single-file paths cannot drift apart.
    if base not in _CONTENT_MEMBERS:
        base = "cloudschism-report.json.gz" if base.endswith(".gz") else "cloudschism-report.json"
    _consume(builder, {base: base}, lambda _p: data,
             allow_finding_nodes, allow_attack_path_nodes)
    return builder.finish()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__.strip().splitlines()[0])
        print("usage: python3 cloudschism_parser.py <output-dir|output.zip|export.json>")
        raise SystemExit(2)

    target = sys.argv[1]
    if os.path.isdir(target):
        res = parse_directory(target)
    else:
        with open(target, "rb") as fh:
            payload = fh.read()
        res = parse_bytes(payload, filename=os.path.basename(target))

    nodes, edges = res.to_flowsint_batch()
    print(json.dumps(res.summary(), indent=2))
    print(f"Nodes: {len(nodes)}, Edges: {len(edges)}")
    for err in res.errors:
        print("  !", err)
