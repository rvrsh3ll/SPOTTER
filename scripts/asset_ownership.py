#!/usr/bin/env python3
"""
asset_ownership.py — Canonical evidence vocabulary for "who owns this asset".

WHY THIS EXISTS
---------------
WF13's `owners_for()` used to answer that question with a name-token match: split
the individual's graph label into tokens of length >= 4 and require the first two
to appear in the asset's own label. On a real campaign that
attributed `https://primer-avia.test` and `autoconfig.primer-avia.test` to the identity
`jd@primer-avia.test`.

That is not a tuning problem, it is a structural one. WF13's own Flare promotion
block creates provisional individuals whose **nodeLabel is the email address**
(`provisional: True`, `source: 'flare_domain'`), because the address is all we
know about them. Tokenising `jd@primer-avia.test` at length >= 4 yields
`['primer', 'avia', 'test']` -- `jd` is too short to count -- and the apex
`https://primer-avia.test` tokenises to `{https, primer, avia, test}`. The match is
guaranteed by construction, for every promoted identity against every asset on
the domain. Token boundaries and the shared-CDN exclusion, the two tightenings
that branch already carried, cannot help: the tokens genuinely match.

So ownership is now asserted only from evidence that describes control over the
SPECIFIC asset -- Active Directory rights over the host serving it, or a cloud
IAM permission on the resource itself -- and the strength of that evidence is
carried in the EDGE LABEL.

WHY THE EDGE LABEL CARRIES THE TIER
-----------------------------------
Flowsint's importer drops edge `data` before it reaches Neo4j (see issues.md,
"Flowsint import drops edge props"). An edge therefore cannot carry an
`evidence` string or a confidence number into the graph; the relationship type is
the only durable channel. That is also why the previous `MANAGES_NAMED` rollout
could not be applied retroactively -- nothing recorded which branch had produced
an existing edge -- and why `scripts/prune_named_ownership.py` has to infer
intent from the SOURCE NODE instead.

Three of the four labels below were already read by WF10's `OWN_LABELS` and
written by nobody. They are used here rather than inventing new ones.

CASING IS NOT DECORATIVE
------------------------
AD ACE edges carry BloodHound's own spelling, because `sharphound_parser`
uses the right name AS the relationship type ("the Flowsint Edge schema has no
data/property field, so encoding the right in the label is the only way to
preserve it"). So `GenericAll` and `CanRDP` are PascalCase while `LOCAL_ADMIN`,
`HAS_SESSION` and `MEMBER_OF` -- which the parser renames -- are SCREAMING_SNAKE.
There is no rule to derive one from the other; both spellings below are literal.

AD *nodes*, separately, are lowercase (`individual`, `device`, `organization`)
because SharpHound ingests through `batch_import`, which lowercases nodeType.
`fc.get_nodes_by_type` interpolates the label straight into `MATCH (n:{label})`
and Neo4j labels are case-sensitive, so a reader that guesses PascalCase here
finds nothing and reports success. See `scripts/asset_labels.py` for the longer
version of that trap.

IMPORTING THIS FROM AN n8n CODE NODE
------------------------------------
`asset_ownership` MUST be listed in N8N_RUNNERS_EXTERNAL_ALLOW in the
`env-overrides` of the python runner in `deployment/n8n-task-runners.json`, or
`import asset_ownership` fails the WHOLE node with a security violation before
line 1 runs. Two copies of that file exist on this host; confirm which is mounted
with `docker inspect spotter-n8n-runners`, and confirm the value reached the
runner PROCESS (`/proc/<pid>/environ`) rather than only the file.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


# ── The four ownership labels ────────────────────────────────────────────────
#
# OWNS_ASSET   the person demonstrably controls the thing serving this asset.
# HAS_ACCESS   the person can reach it, but control is not established.
# MANAGES      the apex WHOIS registrant / DNS TXT address. A fact about the
#              DOMAIN, not about any one asset: it attaches uniformly to the
#              apex, to every subdomain and to every bucket in a sweep. Kept
#              because an operator wants to see it; weighted 0 because a
#              registrant on a 40-subdomain estate would otherwise accumulate
#              40 x 8 and peg the score.
# LIKELY_MANAGES  reserved, and deliberately UNWRITTEN. Role/job-title inference
#              stays a `manager_candidates` node property -- WF13's standing
#              policy comment ("Role-based 'likely manager' guesses are stored as
#              a node property, not edges") is correct and this module does not
#              reverse it. The label exists so a future writer has a slot with a
#              weight already pinned at 0.

OWNS_ASSET = "OWNS_ASSET"
HAS_ACCESS = "HAS_ACCESS"
MANAGES = "MANAGES"
LIKELY_MANAGES = "LIKELY_MANAGES"

# The retired label. WF13's name-token branch was its only writer; nothing writes
# it now. Kept as a named constant so the cleanup script and the regression
# guards can refer to it without re-typing a string that must not come back.
RETIRED_LABELS: Tuple[str, ...] = ("MANAGES_NAMED",)

# Every label a reader should treat as an ownership assertion. WF10 derives its
# OWN_LABELS from this rather than re-declaring the set.
OWNERSHIP_LABELS: Tuple[str, ...] = (OWNS_ASSET, HAS_ACCESS, MANAGES, LIKELY_MANAGES)

# What each label may contribute to a person's score, per owned asset.
#
# Only the asset-SCOPED tiers score. This is the same discrimination WF04 makes
# when it fetches OWNER_EDGES -- one label, not the whole set -- expressed once
# so WF10 stops adding a flat 8 for every label alike.
OWNERSHIP_WEIGHTS: Dict[str, int] = {
    OWNS_ASSET: 8,
    HAS_ACCESS: 5,
    MANAGES: 0,
    LIKELY_MANAGES: 0,
}

# Modifiers WF10 already applied, kept, but now reachable only from a tier that
# scores at all.
CLOUD_ASSET_BONUS = 6
VULNERABLE_ASSET_BONUS = 6

# Total ceiling on the ownership contribution to one person's score. Owning ten
# assets is not ten findings -- the same "MAX over an owner's assets, not a sum"
# reasoning WF04's cloud_owner_credit already documents. 20 sits between the
# has_beacon term (20) and the in_da term (25), so ownership can decide which
# target an operator picks first but never outranks reaching Domain Admin.
ASSET_BUMP_CAP = 20

# Only WF04's asset-scoped reader. Bare MANAGES must never appear here: it is the
# domain registrant and attaches to CDN endpoints too.
SCORING_OWNER_EDGES: Tuple[str, ...] = (OWNS_ASSET,)


# ── Active Directory evidence ────────────────────────────────────────────────
#
# Direction for every relationship type below is principal -> device, which is
# what `sharphound_parser` writes. A reader that walks it the other way finds
# nothing: `llm/tools/graph_query_tool.py` documents HAS_SESSION reversed, and
# the parser (source_temp_id=user_sid, target_temp_id=computer_sid) is the
# authority.

# Rights that mean "this principal can do what it likes to that computer
# object". Owns is AD's literal object-owner ACE; the four write primitives each
# convert to full control in one step; LOCAL_ADMIN is administrative control of
# the running host and is the strongest signal of the set for our purpose.
CONTROL_RIGHTS: Tuple[str, ...] = (
    "LOCAL_ADMIN",
    "Owns",
    "GenericAll",
    "WriteDacl",
    "WriteOwner",
    "GenericWrite",
    "AddKeyCredentialLink",
)

# Rights that mean "this principal can reach that host", without establishing
# control over it. HAS_SESSION is observational rather than granted -- somebody
# was logged in when SharpHound ran -- which is why it sits here and not above.
ACCESS_RIGHTS: Tuple[str, ...] = (
    "CanRDP",
    "CanPSRemote",
    "ExecuteDCOM",
    "HAS_SESSION",
)

# Everything WF13 fetches against target_label='device'. Deliberately much
# narrower than WF04's AD_EDGES: the ACE types that reach a GPO, a cert template
# or another principal say nothing about who owns a web asset, and each one is a
# separate relationship-type scan.
DEVICE_RIGHT_EDGES: Tuple[str, ...] = CONTROL_RIGHTS + ACCESS_RIGHTS

# AD group membership. Rights are usually held by a group rather than a person,
# so without this the AD tiers are near-empty on a real estate.
GROUP_EDGE = "MEMBER_OF"

# CloudSchism IAM. Low yield by design rather than by accident:
# `cloudschism_parser._identity_is_person` types roles, service principals,
# managed identities and service accounts as CloudAsset, so only an email-shaped
# HUMAN principal arrives as an `individual` and can reach this edge at all.
CLOUD_PERMISSION_EDGE = "HAS_PERMISSION"


# ── Guard: group-held rights must not fan out ────────────────────────────────
#
# This is the guard that stops the fix reproducing the bug it replaces, at
# greater cost. "Domain Admins" holds LOCAL_ADMIN on every host in the estate;
# expanding that to its members would attribute the entire estate to every
# Domain Admin -- a wider false positive than the name match ever produced, and
# one that would look authoritative because it came from BloodHound.
#
# Being a Domain Admin is not evidence that you own a particular host, and WF10
# already scores it separately (in_da, +25). So these groups are read for
# membership and then dropped as a source of asset ownership.
EXCLUDED_GROUP_PATTERNS: Tuple[str, ...] = (
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "domain computers",
    "domain users",
    "authenticated users",
    "everyone",
    "enterprise read-only domain controllers",
    "read-only domain controllers",
    "account operators",
    "server operators",
    "backup operators",
    "print operators",
)

# A group larger than this is an org unit, not a team that owns a box. Even a
# non-builtin group with 200 members tells you nothing asset-specific.
MAX_GROUP_MEMBERS = 40


def is_excluded_group(label: str, props: Optional[Mapping[str, Any]] = None) -> bool:
    """True when a group's rights must not be attributed to its members.

    Matches the built-in high-privilege and everyone-groups by name, and honours
    the `is_high_value` / `admin_count` flags SharpHound writes onto the
    `organization` node -- a renamed or non-English Domain Admins still carries
    those.
    """
    name = str(label or "").strip().lower()
    if any(p in name for p in EXCLUDED_GROUP_PATTERNS):
        return True
    if props:
        for flag in ("is_high_value", "admin_count", "highvalue"):
            if _truthy(props.get(flag)):
                return True
    return False


def _truthy(value: Any) -> bool:
    """Tolerant truth test for graph properties.

    A registered custom type coerces every declared field to str, so a boolean
    can arrive as "True", "true" or "1" depending on which writer produced it.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    return str(value or "").strip().lower() in ("true", "1", "yes")


# ── Guard: an identity we only know as an email address ──────────────────────

_EMAIL_LABEL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def is_provisional_identity(
    label: str, props: Optional[Mapping[str, Any]] = None
) -> bool:
    """True for an individual we know only as an address on the target domain.

    These are WF13's own Flare promotions: `fc.add_node(label=em, ...)` with
    `provisional: True` and `source: 'flare_domain'`, labelled with the email
    because the address is all we have. They are legitimate targets -- they carry
    real breach evidence and belong on the Targets tab -- but their LABEL is the
    domain, which is what made the retired name-token branch match every asset on
    that domain.

    THIS READS PROPERTIES, NOT THE LABEL SHAPE, AND THE DISTINCTION IS CRITICAL.
    An earlier draft treated any email-shaped nodeLabel as provisional. That is
    wrong in the worst available way: `sharphound_parser` labels every AD
    principal from `Properties.name`, which BloodHound populates as
    `SAMACCOUNTNAME@DOMAIN.LOCAL`. So EVERY REAL AD USER is email-shaped, and
    that draft silently excluded every genuine rights-holder -- the AD ownership
    tiers would have returned nothing on real data while every test built on
    "Carol Ops"-style labels passed. Use is_email_labelled() only where an
    email-shaped label is genuinely the signal, and always alongside this.
    """
    if not props:
        return False
    if _truthy(props.get("provisional")):
        return True
    for key in ("source", "discovered_by"):
        if str(props.get(key) or "").strip().lower() == "flare_domain":
            return True
    return False


def is_email_labelled(label: str) -> bool:
    """True when the node's own label is an email address.

    NOT a synonym for "provisional" -- see the warning above. Every SharpHound
    individual is email-shaped. This exists for `prune_named_ownership.py`, which
    combines it WITH `is_provisional_identity` and with the address's domain to
    decide that a legacy edge is definitely wrong.
    """
    return bool(_EMAIL_LABEL_RE.match(str(label or "").strip()))


# ── Evidence strings ─────────────────────────────────────────────────────────
#
# What the operator reads in the Asset Ownership panel and in the exported
# report's Evidence column. The edge label says how much it is worth; this says
# why, and it must name the intermediate host -- "OWNS_ASSET" on its own does not
# tell anyone that the claim came from WEB01.

# The renamed rights read badly as bare labels in a sentence: "AD LOCAL_ADMIN on
# WEB01" and "AD HAS_SESSION on WEB01" are the graph's spelling, not English. The
# PascalCase ACE names are left exactly as BloodHound spells them, because that
# is the string an operator will search for in BloodHound itself.
_RIGHT_PHRASING: Dict[str, str] = {
    "LOCAL_ADMIN": "local admin",
    "HAS_SESSION": "session",
}


def evidence_string(right: str, host: str, via_group: str = "") -> str:
    """Operator-facing evidence for one AD-derived ownership claim.

    >>> evidence_string('LOCAL_ADMIN', 'WEB01')
    'AD local admin on WEB01'
    >>> evidence_string('GenericAll', 'WEB01', via_group='Web Team')
    'AD GenericAll on WEB01 via Web Team'
    """
    name = str(right or "").strip()
    phrase = _RIGHT_PHRASING.get(name, name)
    text = ("AD " + phrase + " on " + str(host or "").strip()).strip()
    if via_group:
        text += " via " + str(via_group).strip()
    return text


def cloud_evidence_string(resource: str) -> str:
    """Operator-facing evidence for a CloudSchism IAM permission."""
    return "cloud IAM on " + str(resource or "").strip()


def label_for_right(right: str) -> str:
    """The ownership label an AD relationship type earns.

    Returns '' for a relationship type that is not ownership evidence, so a
    caller can use this as the membership test too.
    """
    name = str(right or "").strip()
    if name in CONTROL_RIGHTS:
        return OWNS_ASSET
    if name in ACCESS_RIGHTS:
        return HAS_ACCESS
    return ""


# ── Why a run produced no ownership rows ─────────────────────────────────────
#
# Most external assets genuinely resolve to no AD device: a public apex on a
# hosting provider's address is not a domain-joined computer. After this change
# the section will often be empty, and an empty section that used to be full
# reads as a regression unless it says which kind of empty it is. Same reasoning
# as the Nessus panel's empty_kind (all-informational vs no-data vs dropped).

EMPTY_NO_AD_DATA = "no_ad_data"        # no AD rights edges in this sketch at all
EMPTY_NO_DEVICE_MATCH = "no_device_match"  # AD exists, no asset resolved to a device
EMPTY_NO_RIGHTS = "no_rights"          # devices matched, nobody holds rights on them
EMPTY_KINDS: Tuple[str, ...] = (EMPTY_NO_AD_DATA, EMPTY_NO_DEVICE_MATCH, EMPTY_NO_RIGHTS)


def empty_kind(ad_edges_seen: int, devices_matched: int, owners_found: int) -> str:
    """Classify an empty ownership result. '' when it is not empty."""
    if owners_found:
        return ""
    if not ad_edges_seen:
        return EMPTY_NO_AD_DATA
    if not devices_matched:
        return EMPTY_NO_DEVICE_MATCH
    return EMPTY_NO_RIGHTS


# ── Scoring helper ───────────────────────────────────────────────────────────


def asset_bump(assets: Iterable[Mapping[str, Any]]) -> int:
    """Total ownership contribution to one person's score.

    `assets` is one mapping per owned asset carrying at least `relationship`, and
    optionally `type` and `has_vulns`. Weighted by evidence tier and capped, so a
    registrant attached to forty subdomains contributes 0 rather than 320, and an
    operator who genuinely admins six hosts contributes ASSET_BUMP_CAP rather
    than 48.
    """
    total = 0
    for asset in assets:
        weight = OWNERSHIP_WEIGHTS.get(str(asset.get("relationship") or ""), 0)
        if weight <= 0:
            continue
        total += weight
        if str(asset.get("type") or "").strip().lower() == "cloudasset":
            total += CLOUD_ASSET_BONUS
        if asset.get("has_vulns"):
            total += VULNERABLE_ASSET_BONUS
    return min(total, ASSET_BUMP_CAP)


def own_labels() -> List[str]:
    """Every label a renderer should treat as ownership, sorted for stability."""
    return sorted(OWNERSHIP_LABELS)
