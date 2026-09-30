#!/usr/bin/env python3
"""
sanitize_campaign.py — Replace one campaign's client-identifying strings with
consistent fictional ones, in place, across the whole Flowsint sketch.

WHAT THIS IS FOR
----------------
Turning a real engagement into course / demo / conference material. Every token
that names the client — company, domains, AD forest, NetBIOS name, adjacent
brands, and people's surnames — is swapped for a plausible invention, and the
swap is *consistent*: a person renamed in one field is renamed identically in
every other field, on every node, everywhere in the graph.

THERE IS NO BACKUP AND THIS IS IN PLACE
---------------------------------------
There is no Neo4j backup on this host (see purge_nessus_data.py's header) and
Flowsint MERGEs on (node_type, nodeLabel, sketch_id) — nodeLabel IS the node's
identity. Rewriting it is not reversible by re-running anything. Two mitigations
are built in and neither is optional:

  * dry-run by default. --apply is the only thing that writes.
  * the mapping sidecar is written BEFORE the first write. It is the only
    inverse that will ever exist. Copy it off-box, then shred it.

WHY THE STRING SURGERY HAPPENS IN PYTHON
----------------------------------------
migrate_c2session.py has to resolve every value in a WITH before any SET, so
that no SET item reads a value another SET item in the same clause has already
overwritten. This script sidesteps that hazard entirely: every new value is
computed in Python and pushed as a precomputed {elementId -> props} map, so
there is no read-after-write inside the statement at all.

WHY IT IS A FIXPOINT (AND WHY THAT MATTERS)
-------------------------------------------
Fake surnames are drawn from a generated corpus that is explicitly filtered
against every real token in the data, so a fake can never equal a real name, and
the replacement domains contain none of the source tokens. Therefore
rewrite(rewrite(s)) == rewrite(s). A crashed --apply can simply be re-run
without double-mangling anything. `plan` asserts this on a sample.

ORDER OF REPLACEMENT IS LOAD-BEARING
------------------------------------
  1. DN form        DC=AD,DC=EXAMPLE,DC=COM  (must precede 2, or 2 never sees it)
  2. FQDN suffixes  longest first, so ad.example.com beats example.com
  3. NetBIOS        EXAMPLE\\user
  4. Brand tokens   bounded (it_example) then glued (examplecorp, Example2)
  5. Surnames       LAST, and pre-filtered to exclude anything that is also a
                    brand or a DNS label — otherwise this stage would re-mangle
                    the output of stages 2-4.

SHORT SURNAMES ARE NOT SUBSTITUTED IN FREE TEXT
-----------------------------------------------
A large, mixed-language directory carries many very short surnames: li, ng,
wu, lee, kim, day, may. Word-bounded substitution of those inside a description
or a banner would wreck unrelated strings. Surnames shorter than
MIN_FREE_TEXT_SURNAME are applied only in structured identity fields (email
local-parts, username, the name keys), where the surrounding format tells us it
really is a person's name.

USAGE
-----
Runs from the host; Neo4j publishes on 127.0.0.1:7474. NEO4J_HTTP_URL in .env
names a container, which does not resolve here — this script falls back the same
way spotter_user.py does.

    S=scripts/sanitize_campaign.py
    python3 $S --list                                   # campaigns and sketch ids
    python3 $S --campaign DEMO-01 --phase discover      # what is in there
    python3 $S --campaign DEMO-01 --phase map           # write the sidecar
    python3 $S --campaign DEMO-01 --phase plan          # full dry-run report
    python3 $S --campaign DEMO-01 --scope graph --apply
    python3 $S --campaign DEMO-01 --phase verify

There is no fallback to the "most recent campaign". --campaign or --sketch is
required; purge_nessus_data.py's default would silently target the wrong graph.

Environment: NEO4J_HTTP_URL, NEO4J_USER, NEO4J_PASSWORD (CLI flags win).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

import requests

_PROP = "nodeProperties."

# ── Replacement configuration ────────────────────────────────────────────────
# Discovered from the live sketch, not guessed. `--phase discover` re-derives the
# apex list and reports anything present in the data that is NOT covered here, so
# a new domain cannot slip through unnoticed.

# The client tokens themselves live in a PROFILE FILE, not in this script.
# Putting a real "<client>" -> "<pseudonym>" pair in a tracked source file would
# publish the very mapping the sanitization exists to hide, permanently, in git
# history. The profile is written next to the mapping sidecar under the
# gitignored extracted_* prefix. --profile overrides the path.
#
# Shape:
#   {"domains":   {"ad.example.com": "ad.fake.test", ...},
#    "brands":    {"example": "fake", ...},
#    "netbios":   {"EXAMPLE": "FAKE"},
#    "org_names": {"Example Technologies, Inc.": "Fake Design, Inc"}}
DOMAIN_MAP: Dict[str, str] = {}
BRAND_MAP: Dict[str, str] = {}
NETBIOS_MAP: Dict[str, str] = {}
ORG_NAME_MAP: Dict[str, str] = {}


def load_profile(path: str) -> None:
    """Populate the module-level replacement maps from the campaign profile."""
    global DOMAIN_MAP, BRAND_MAP, NETBIOS_MAP, ORG_NAME_MAP
    with open(path, "r", encoding="utf-8") as fh:
        prof = json.load(fh)
    DOMAIN_MAP = {str(k).lower(): str(v) for k, v in prof.get("domains", {}).items()}
    BRAND_MAP = {str(k).lower(): str(v) for k, v in prof.get("brands", {}).items()}
    NETBIOS_MAP = {str(k): str(v) for k, v in prof.get("netbios", {}).items()}
    ORG_NAME_MAP = {str(k): str(v) for k, v in prof.get("org_names", {}).items()}
    if not DOMAIN_MAP and not BRAND_MAP:
        raise RuntimeError(f"profile {path} defines no domains or brands")


def default_profile_path(campaign_id: str) -> str:
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(repo, f"extracted_{campaign_id}-profile.json")


# Apexes that are third-party breach-corpus identifiers or public infrastructure,
# not target identity. Reported but never rewritten; they will show up in any
# naive grep for ".com" and that is fine.
PUBLIC_APEXES = frozenset({
    "amazonaws.com", "googleapis.com", "microsoft.com", "windows.com",
    "office.com", "outlook.com", "gmail.com", "localdomain", "local", "lan",
})

# Local-parts like it_admin@, it_support@, <region>_admin@ decompose exactly like
# first.last, but the trailing token is a role, not a family name. Mapping those
# would mangle every service account AND make the surname residue check
# permanently red, since "admin" and "support" legitimately appear everywhere.
ROLE_STOPWORDS = frozenset({
    "admin", "admins", "administrator", "support", "service", "services", "svc",
    "test", "tests", "testing", "info", "sales", "team", "teams", "group",
    "groups", "help", "helpdesk", "desk", "noreply", "no", "reply", "mail",
    "mailbox", "user", "users", "account", "accounts", "read", "write", "all",
    "dev", "devel", "prod", "qa", "lab", "labs", "it", "hr", "ops", "eng",
    "engineering", "finance", "legal", "marketing", "sys", "system", "systems",
    "root", "guest", "temp", "tmp", "backup", "archive", "report", "reports",
    "manager", "mgr", "lead", "owner", "contact", "office", "site", "local",
    "global", "main", "primary", "secondary", "shared", "common", "general",
    # geographies that show up as the trailing token of a regional role account
    "africa", "americas", "apac", "asia", "australia", "benelux", "brazil",
    "canada", "china", "emea", "europe", "france", "germany", "india", "israel",
    "italy", "japan", "korea", "latam", "malaysia", "mexico", "nordics",
    "oceania", "singapore", "spain", "sweden", "taiwan", "uk", "us", "usa",
    # common trailing tokens of a functional (non-person) account
    "build", "builder", "automation", "payroll", "compliance", "project",
    "security", "procurement", "logistics", "training", "quality", "facilities",
})

# Surnames shorter than this are applied only in structured identity fields.
MIN_FREE_TEXT_SURNAME = 4

# ── Key policy ───────────────────────────────────────────────────────────────

# Never touched. sid is handled separately (see _patch_sid): only a domain-prefixed
# SID has its prefix rewritten; a bare S-1-... body is the join key that
# flowsint_client._bulk_create_edges_neo4j resolves edges through.
FROZEN_KEYS = frozenset({
    "sketch_id", "created_at", "nodeMetadata.created_at", "updated_at",
    "x", "y", "nodeShape", "nodeType", "id", "deleted_at", "sanitize_rev",
    _PROP + "device_id",
    _PROP + "import_ref",
    _PROP + "breach_id",
    _PROP + "discovered_at",
    _PROP + "source",
    _PROP + "sid",
})

# Structured identity fields: the format around the value tells us it is a name,
# so short surnames are safe to substitute here.
IDENTITY_KEYS = frozenset({
    "nodeLabel",
    _PROP + "label", _PROP + "email", _PROP + "username",
    _PROP + "sam_account_name", _PROP + "full_name", _PROP + "display_name",
    _PROP + "first_name", _PROP + "last_name", _PROP + "middle_name",
    _PROP + "identity_name", _PROP + "personal_email", _PROP + "personal_emails",
    _PROP + "profile_emails", _PROP + "email_addresses", _PROP + "exposed_emails",
    _PROP + "name", _PROP + "principal_email", _PROP + "username_context",
    _PROP + "hostname", _PROP + "dnshostname", _PROP + "fqdn", _PROP + "domain",
    _PROP + "source_domain", _PROP + "parent_domain", _PROP + "netbios_name",
    _PROP + "forest", _PROP + "url", _PROP + "endpoint", _PROP + "bucket",
})

# Where a value is structurally "<initials><surname><digits>" — the fields that
# hold a login or a person's name, as opposed to a hostname or a group name.
LOGIN_KEYS = frozenset({
    "nodeLabel",
    _PROP + "label", _PROP + "email", _PROP + "username",
    _PROP + "sam_account_name", _PROP + "full_name", _PROP + "display_name",
    _PROP + "first_name", _PROP + "last_name", _PROP + "middle_name",
    _PROP + "identity_name", _PROP + "personal_email", _PROP + "personal_emails",
    _PROP + "profile_emails", _PROP + "email_addresses", _PROP + "exposed_emails",
})

# Well-known AD principals. Their names are protocol constants, and WF04's
# DA_PATTERN ('domain admins', 'enterprise admins', 'schema admins',
# 'administrators') matches them against node labels — mirroring DA_GROUPS in
# sharphound_parser.py. Rename one and attack-path scoring silently finds zero
# high-value targets. These nodes get domain + brand rewriting only.
WELL_KNOWN_PRINCIPALS = frozenset({
    "nt authority", "everyone", "authenticated users", "interactive", "network",
    "batch", "service", "self", "creator owner", "anonymous logon", "builtin",
    "enterprise domain controllers", "domain computers", "domain controllers",
    "domain users", "domain guests", "domain admins", "enterprise admins",
    "schema admins", "administrators", "users", "guests", "account operators",
    "server operators", "print operators", "backup operators", "replicator",
    "remote desktop users", "network configuration operators",
    "performance monitor users", "performance log users", "distributed com users",
    "iis_iusrs", "cryptographic operators", "event log readers",
    "certificate service dcom access", "rds remote access servers",
    "rds endpoint servers", "rds management servers", "hyper-v administrators",
    "access control assistance operators", "remote management users",
    "storage replica administrators", "pre-windows 2000 compatible access",
    "windows authorization access group", "terminal server license servers",
    "incoming forest trust builders", "krbtgt", "guest", "administrator",
    "defaultaccount", "protected users", "cloneable domain controllers",
    "dnsadmins", "dnsupdateproxy", "key admins", "enterprise key admins",
    "ras and ias servers", "group policy creator owners", "cert publishers",
    "allowed rodc password replication group",
    "denied rodc password replication group", "read-only domain controllers",
})

_SERVICE_RE = re.compile(r"^(svc|sa|srv|adm)[_.\-]|_svc|^\$|"
                         r"^(healthmailbox|systemmailbox|discoverysearchmailbox|sm_[0-9a-f]{8,})",
                         re.I)
# A "run" is what the old per-surname boundary (?<![A-Za-z0-9]) ... (?![A-Za-z0-9])
# used to delimit, extended to keep hyphenated surnames (smith-jones) whole.
_TOKEN_RUN = re.compile(r"[A-Za-z0-9]+(?:[-'][A-Za-z0-9]+)*")
# What may follow a surname inside one login token: anything containing a digit,
# or a recognised account-type suffix. Capped at 8 characters so a compound
# word cannot masquerade as one.
_ACCT_SUFFIX = re.compile(r"^(?=.{1,8}$)(?:.*\d.*|adm|admin|svc|ext|tmp|old"
                          r"|new|test|o365|jr|sr)$")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")

_DOMSID_RE = re.compile(r"^(?P<dom>[A-Za-z0-9.\-]+)-(?P<sid>S-1-\d.*)$")


# Node types whose identity fields hold a person even though the node is not an
# `individual` — FlareBreach.identity_name is an email address, and so on.
_IDENTITY_TYPES = frozenset({"flarebreach", "domainbreach", "socialprofile",
                             "credential"})


class Kind:
    BUILTIN = "builtin"
    MACHINE = "machine"
    SERVICE = "service"
    GROUP = "group"
    PERSON = "person"
    OPAQUE = "opaque"
    RESOURCE = "resource"


# ── Neo4j ────────────────────────────────────────────────────────────────────

class Neo4jHTTP:
    """Minimal Neo4j HTTP transactional client — same shape WF19/WF20 use."""

    def __init__(self, url: str, user: str, password: str) -> None:
        self.url = url.rstrip("/")
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {auth}",
                        "Content-Type": "application/json"}

    def query(self, statement: str, parameters: Optional[Dict[str, Any]] = None,
              timeout: int = 600) -> List[List[Any]]:
        resp = requests.post(
            f"{self.url}/db/neo4j/tx/commit", headers=self.headers,
            json={"statements": [{"statement": statement,
                                  "parameters": parameters or {}}]},
            timeout=timeout)
        resp.raise_for_status()
        body = resp.json()
        if body.get("errors"):
            raise RuntimeError(str(body["errors"])[:600])
        return [row["row"] for row in body["results"][0]["data"]]

    def scalar(self, statement: str, parameters: Optional[Dict[str, Any]] = None) -> Any:
        rows = self.query(statement, parameters)
        return rows[0][0] if rows else None


def _env_file(key: str) -> str:
    """One key from config or the decrypted secret tiers.

    Kept under the old name so the call sites below read unchanged; it is no
    longer "the .env file", because NEO4J_PASSWORD now lives encrypted in
    secrets/machine.sops.env.
    """
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
    import spotter_env
    return spotter_env.get(key) or ""

def _neo4j_candidates(explicit: str = "") -> List[str]:
    """
    Ordered URLs to try. The .env value names `flowsint-neo4j-prod`, which only
    resolves on the docker network — from the host it just fails to connect.
    spotter_user.py does the same fallback.
    """
    if explicit:
        return [explicit]
    out: List[str] = []
    env = os.environ.get("NEO4J_HTTP_URL") or _env_file("NEO4J_HTTP_URL")
    if env:
        out.append(env)
    for fallback in ("http://127.0.0.1:7474", "http://localhost:7474"):
        if fallback not in out:
            out.append(fallback)
    return out


def connect(url: str = "", user: str = "", password: str = "") -> Neo4jHTTP:
    user = user or os.environ.get("NEO4J_USER") or _env_file("NEO4J_USER") or "neo4j"
    password = (password or os.environ.get("NEO4J_PASSWORD")
                or _env_file("NEO4J_PASSWORD"))
    if not password:
        raise RuntimeError("NEO4J_PASSWORD is not set and is not in .env")
    last: Optional[Exception] = None
    for candidate in _neo4j_candidates(url):
        neo = Neo4jHTTP(candidate, user, password)
        try:
            neo.query("RETURN 1", timeout=15)
            return neo
        except Exception as exc:                      # noqa: BLE001 - try the next
            last = exc
    raise RuntimeError(f"could not reach Neo4j on any of "
                       f"{_neo4j_candidates(url)}: {last}")


# ── Fake-name corpus ─────────────────────────────────────────────────────────

_ONSET = ["b", "br", "c", "ch", "cl", "cr", "d", "dr", "f", "fl", "fr", "g",
          "gl", "gr", "h", "j", "k", "kr", "l", "m", "n", "p", "pl", "pr", "q",
          "r", "s", "sc", "sh", "sk", "sl", "sm", "sn", "sp", "st", "str", "t",
          "th", "tr", "v", "w", "wh", "y", "z", ""]
_NUC = ["a", "e", "i", "o", "u", "ai", "ea", "ee", "ie", "oa", "oo", "ou",
        "ay", "ey", "au"]
_CODA = ["", "b", "ck", "d", "dge", "ft", "g", "ld", "lk", "ll", "lt", "m", "n",
         "nd", "ng", "nt", "p", "r", "rd", "rk", "rn", "rt", "s", "sh", "sk",
         "ss", "st", "t", "th", "x"]
_TAIL = ["", "ley", "son", "ton", "ford", "wood", "field", "worth", "man",
         "berg", "dale", "well", "stone", "brook", "mont", "wick", "shaw"]


class Corpus:
    """
    Deterministic, index-addressable surname space — 45*15*30*17 = 344,250
    candidates, generated rather than shipped so this stays dependency-free.
    Built lazily as a mixed-radix index so nothing materialises 344k strings.
    """

    def __init__(self) -> None:
        self._sizes = (len(_ONSET), len(_NUC), len(_CODA), len(_TAIL))
        self.size = 1
        for s in self._sizes:
            self.size *= s

    def __len__(self) -> int:
        return self.size

    def __getitem__(self, i: int) -> str:
        i %= self.size
        i, t = divmod(i, self._sizes[3])
        i, c = divmod(i, self._sizes[2])
        o, n = divmod(i, self._sizes[1])
        word = _ONSET[o % self._sizes[0]] + _NUC[n] + _CODA[c] + _TAIL[t]
        return word[:1].upper() + word[1:]


def _probe_index(seed: bytes, token: str, probe: int) -> int:
    msg = token.lower().encode() if probe == 0 else f"{token.lower()}#{probe}".encode()
    return int.from_bytes(hmac.new(seed, msg, hashlib.sha256).digest()[:8], "big")


def assign(seed: bytes, token: str, corpus: Corpus, used: Set[str],
           taken: Dict[str, str]) -> str:
    """
    Injective by construction: salted-HMAC linear re-probe until a free name is
    found. `used` is pre-seeded with every real token in the data, so a generated
    fake can never collide with a real name — which is what makes the whole
    rewrite a fixpoint.
    """
    key = token.lower()
    if key in taken:
        return taken[key]
    for probe in range(4096):
        cand = corpus[_probe_index(seed, token, probe)]
        if len(cand) < 4:
            continue
        if cand.lower() in used:
            continue
        used.add(cand.lower())
        taken[key] = cand
        return cand
    raise RuntimeError(f"corpus exhausted assigning a pseudonym for {token!r}")


# ── Discovery ────────────────────────────────────────────────────────────────

_LOCAL_SPLIT = re.compile(r"[._]")
_NAME_TOKEN = re.compile(r"^[a-z][a-z'\-]*$")
_TRAILING_DIGITS = re.compile(r"\d+$")


@dataclass
class Discovery:
    sketch_id: str
    node_total: int = 0
    edge_total: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    edge_types: Dict[str, int] = field(default_factory=dict)
    apexes: Dict[str, int] = field(default_factory=dict)
    unmapped_apexes: Dict[str, int] = field(default_factory=dict)
    surnames: Dict[str, int] = field(default_factory=dict)
    first_names: Set[str] = field(default_factory=set)
    kinds: Dict[str, int] = field(default_factory=dict)
    residue: List[Tuple[str, str, str, int]] = field(default_factory=list)


def _apex_of(host: str) -> str:
    parts = [p for p in host.lower().split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else ""


# The leading label of a domain is only a usable residue term when it is
# distinctive. "ad.example.com" yields "ad", which matches half the English
# language — including the replacement domain — so verify could never go green.
_GENERIC_LABELS = frozenset({"ad", "com", "net", "org", "lab", "local", "lan",
                             "corp", "int", "dev", "www", "mail", "s3"})


def residue_terms(brands: Dict[str, str], domains: Dict[str, str],
                  netbios: Optional[Dict[str, str]] = None) -> List[str]:
    """Lowercase tokens whose presence anywhere means the pass is not finished."""
    terms = {b.lower() for b in brands}
    for dom in domains:
        terms.add(dom.lower())
        head = dom.split(".")[0].lower()
        # A short head produces false positives against ordinary words: a head
        # like "nova" (from nova.lab) matches SUPERNOVA. Distinctive heads only;
        # anything shorter is already covered as a brand token if it matters.
        if len(head) >= 6 and head not in _GENERIC_LABELS:
            terms.add(head)
    for nb in (netbios or {}):
        if len(nb) >= 4 and nb.lower() not in _GENERIC_LABELS:
            terms.add(nb.lower())
    return sorted(terms)


def discover(neo: Neo4jHTTP, sketch_id: str) -> Discovery:
    d = Discovery(sketch_id=sketch_id)
    p = {"sid": sketch_id}

    d.node_total = int(neo.scalar(
        "MATCH (n {sketch_id:$sid}) WHERE n.deleted_at IS NULL RETURN count(n)", p) or 0)
    d.edge_total = int(neo.scalar(
        "MATCH ()-[r {sketch_id:$sid}]->() RETURN count(r)", p) or 0)
    for t, c in neo.query(
            "MATCH (n {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
            "RETURN n.nodeType AS t, count(*) AS c ORDER BY c DESC", p):
        d.by_type[str(t)] = int(c)
    for t, c in neo.query(
            "MATCH ()-[r {sketch_id:$sid}]->() "
            "RETURN type(r) AS t, count(*) AS c ORDER BY c DESC", p):
        d.edge_types[str(t)] = int(c)

    # Which property keys carry the client name today. This table is the
    # acceptance list: every row must read zero after --apply.
    for term in residue_terms(BRAND_MAP, DOMAIN_MAP):
        for k, t, c in neo.query(
                "MATCH (n {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
                "UNWIND keys(n) AS k WITH n.nodeType AS t, k, n[k] AS v "
                "WHERE v IS NOT NULL AND toLower(toString(v)) CONTAINS $term "
                "RETURN k, t, count(*) AS c ORDER BY c DESC",
                {"sid": sketch_id, "term": term}):
            d.residue.append((term, str(t), str(k), int(c)))

    # Apex inventory, so a domain that is in the data but not in DOMAIN_MAP is
    # reported instead of silently surviving.
    host_keys = [_PROP + k for k in ("domain", "source_domain", "parent_domain",
                                     "fqdn", "hostname", "dnshostname", "email",
                                     "identity_name", "endpoint", "url")]
    for host, c in neo.query(
            "MATCH (n {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
            "UNWIND [k IN keys(n) WHERE k IN $keys] AS k "
            "WITH toLower(toString(n[k])) AS v WHERE v CONTAINS '.' "
            "WITH CASE WHEN v CONTAINS '@' THEN split(v,'@')[1] ELSE v END AS h "
            "RETURN h AS host, count(*) AS c",
            {"sid": sketch_id, "keys": host_keys}):
        apex = _apex_of(str(host).split("/")[0].split(":")[0])
        if apex:
            d.apexes[apex] = d.apexes.get(apex, 0) + int(c)
    for apex, c in d.apexes.items():
        if apex in DOMAIN_MAP or apex in PUBLIC_APEXES:
            continue
        if any(apex == k or apex.endswith("." + k) for k in DOMAIN_MAP):
            continue
        d.unmapped_apexes[apex] = c

    # Real surnames: the only population with a parseable First/Last structure is
    # the Flare-promoted set, whose nodeLabel IS the email address.
    for (email,) in neo.query(
            "MATCH (n:individual {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
            "AND n.`" + _PROP + "source_domain` IS NOT NULL "
            "RETURN n.`" + _PROP + "email` AS e", p):
        first, last = split_person_local(str(email or ""))
        if last and last not in ROLE_STOPWORDS and last not in BRAND_MAP:
            d.surnames[last] = d.surnames.get(last, 0) + 1
            if first:
                d.first_names.add(first)

    # Surnames also appear as the last token of a genuine "First Last" display
    # name. The SharpHound population is NOT that: its last_name is a copy of the
    # whole single-token login (Jdoe, Asmith, Ex-100042), and harvesting those
    # would both inflate the map many times over and rename the opaque logins
    # the operator asked to keep. Require a real multi-token alphabetic name
    # whose final token is the recorded surname.
    for (full, last) in neo.query(
            "MATCH (n:individual {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
            "AND n.`" + _PROP + "last_name` IS NOT NULL "
            "RETURN n.`" + _PROP + "full_name` AS f, n.`" + _PROP + "last_name` AS l", p):
        first, surname = split_display_name(str(full or ""), str(last or ""))
        if surname and surname not in ROLE_STOPWORDS and surname not in BRAND_MAP:
            d.surnames[surname] = d.surnames.get(surname, 0) + 1
            if first:
                d.first_names.add(first)

    return d


def split_person_local(email: str) -> Tuple[str, str]:
    """
    ('jane', 'doe') from jane.doe@example.com. Returns ('','') when the
    local-part has no person structure (the tens of thousands of SharpHound
    logins, numeric payroll ids, and the handful of labels with a URL glued on
    the front).
    """
    if not email or "@" not in email:
        return "", ""
    local = email.split("@")[0].strip().lower()
    local = local.split()[-1] if " " in local else local
    core = _TRAILING_DIGITS.sub("", local)
    parts = [p for p in _LOCAL_SPLIT.split(core) if p]
    if len(parts) < 2:
        return "", ""
    if not all(_NAME_TOKEN.match(p) for p in parts):
        return "", ""
    return parts[0], parts[-1]



def split_display_name(full_name: str, last_name: str) -> Tuple[str, str]:
    """
    ('jane', 'doe') from full_name "Jane Doe" / last_name "Doe".
    Returns ('','') unless the display name is genuinely multi-token, every token
    is alphabetic, and the final token matches the recorded surname — which is
    what separates a real person from a SharpHound login echoed into last_name.
    """
    tokens = [t for t in re.split(r"\s+", full_name.strip()) if t]
    if len(tokens) < 2:
        return "", ""
    lowered = [t.lower() for t in tokens]
    if not all(_NAME_TOKEN.match(t) for t in lowered):
        return "", ""
    surname = last_name.strip().lower()
    if not surname or surname != lowered[-1]:
        return "", ""
    return lowered[0], surname

def classify(node_type: str, props: Dict[str, Any]) -> str:
    """Population of a node, for the report and to gate surname substitution."""
    nt = (node_type or "").lower()
    sid = str(props.get(_PROP + "sid") or "")
    label = str(props.get("nodeLabel") or props.get(_PROP + "label") or "")
    principal = label.split("@")[0].split("\\")[-1].strip().lower()

    if _DOMSID_RE.match(sid) or principal in WELL_KNOWN_PRINCIPALS:
        return Kind.BUILTIN
    sam = str(props.get(_PROP + "sam_account_name") or "")
    if nt == "device" or sam.endswith("$"):
        return Kind.MACHINE
    if nt == "organization":
        return Kind.GROUP
    if nt == "individual":
        login = str(props.get(_PROP + "username") or sam or "")
        if _SERVICE_RE.search(login):
            return Kind.SERVICE
        email = str(props.get(_PROP + "email") or "")
        if split_person_local(email)[1]:
            return Kind.PERSON
        if split_person_local(label)[1]:
            return Kind.PERSON
        return Kind.OPAQUE
    return Kind.RESOURCE


# ── Mapping ──────────────────────────────────────────────────────────────────

@dataclass
class Mapping:
    version: int = 1
    created: str = ""
    sketch_id: str = ""
    campaign_id: str = ""
    seed_sha256: str = ""
    fingerprint: str = ""
    domains: Dict[str, str] = field(default_factory=dict)
    netbios: Dict[str, str] = field(default_factory=dict)
    brands: Dict[str, str] = field(default_factory=dict)
    org_names: Dict[str, str] = field(default_factory=dict)
    surnames: Dict[str, str] = field(default_factory=dict)
    # Pairs that were issued and written to the graph, then withdrawn from active
    # substitution (a harvested token that turned out to be a role word, not a
    # family name). Their pseudonyms are already IN the graph, so they must stay
    # protected from re-harvesting forever; they simply stop being applied to
    # anything new. Dropping them outright makes the graph re-pseudonymize its
    # own output on the next run.
    retired: Dict[str, str] = field(default_factory=dict)
    extra_phrases: Dict[str, str] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        return {
            "version": self.version, "created": self.created,
            "sketch_id": self.sketch_id, "campaign_id": self.campaign_id,
            "seed_sha256": self.seed_sha256, "fingerprint": self.fingerprint,
            "domains": self.domains, "netbios": self.netbios,
            "brands": self.brands, "org_names": self.org_names,
            "surnames": self.surnames, "retired": self.retired,
            "extra_phrases": self.extra_phrases,
        }

    @classmethod
    def from_json(cls, obj: Dict[str, Any]) -> "Mapping":
        m = cls()
        for k in ("version", "created", "sketch_id", "campaign_id",
                  "seed_sha256", "fingerprint"):
            if k in obj:
                setattr(m, k, obj[k])
        for k in ("domains", "netbios", "brands", "org_names", "surnames",
                  "retired", "extra_phrases"):
            if isinstance(obj.get(k), dict):
                setattr(m, k, dict(obj[k]))
        return m


def _fingerprint(m: Mapping) -> str:
    blob = json.dumps({"d": m.domains, "n": m.netbios, "b": m.brands,
                       "o": m.org_names, "s": m.surnames, "r": m.retired,
                       "e": m.extra_phrases},
                      sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def build_mapping(disc: Discovery, seed: bytes, existing: Optional[Mapping],
                  campaign_id: str, extra: Optional[Dict[str, str]] = None) -> Mapping:
    """
    Append-only: an assignment already in the sidecar is never reissued, so a
    second run after new data arrives extends the map instead of reshuffling it.
    """
    m = existing or Mapping()
    m.sketch_id = disc.sketch_id
    m.campaign_id = campaign_id
    m.seed_sha256 = hashlib.sha256(seed).hexdigest()
    m.created = m.created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for src, dst in DOMAIN_MAP.items():
        m.domains.setdefault(src, dst)
    for src, dst in NETBIOS_MAP.items():
        m.netbios.setdefault(src, dst)
    for src, dst in BRAND_MAP.items():
        m.brands.setdefault(src, dst)
    for src, dst in ORG_NAME_MAP.items():
        m.org_names.setdefault(src, dst)
    for src, dst in (extra or {}).items():
        m.extra_phrases[src] = dst

    # Everything a generated fake must never equal: real surnames, real first
    # names (we keep those, so a fake surname colliding with one would look
    # absurd), every DNS label in play, and every brand token.
    used: Set[str] = set()
    used |= {s.lower() for s in disc.surnames}
    used |= {f.lower() for f in disc.first_names}
    used |= {b.lower() for b in m.brands}
    used |= {v.lower() for v in m.brands.values()}
    for dom in list(m.domains) + list(m.domains.values()):
        used |= {part.lower() for part in dom.split(".")}
    used |= {v.lower() for v in m.surnames.values()}
    used |= {v.lower() for v in m.retired.values()}
    used |= {k.lower() for k in m.retired}
    used |= {v.lower() for v in m.netbios.values()}
    for dom in m.domains.values():
        used |= {part.lower() for part in dom.split(".")}

    # Pseudonyms this mapping has already issued. After a first --apply the graph
    # contains them instead of the real names, so a re-harvest would pick them up
    # as brand-new "real" surnames and map fake -> fake', destroying the property
    # that one person has one pseudonym. (The fixpoint assertion in `plan` is
    # what catches this if the filter is ever lost.)
    issued = {v.lower() for v in m.surnames.values()}
    issued |= {v.lower() for v in m.retired.values()}
    issued |= {k.lower() for k in m.retired}
    # Replacement vocabulary, built from the replacements ALONE. An earlier
    # version subtracted the harvested names from `used`, which let "novabrand"
    # (a brand substitute that now appears in local-parts such as
    # sales_novabrand@) be harvested as a real surname and given a pseudonym of
    # its own — the map poisoning itself with its own output.
    protected = {v.lower() for v in m.brands.values()}
    protected |= {v.lower() for v in m.netbios.values()}
    for dom in m.domains.values():
        protected |= {part.lower() for part in dom.split(".")}

    corpus = Corpus()
    # Deterministic order so the same seed yields the same map regardless of the
    # order Neo4j happened to return rows in.
    for surname in sorted(disc.surnames):
        if surname in m.surnames or surname in issued or surname in protected:
            continue
        m.surnames[surname] = assign(seed, surname, corpus, used, m.surnames)

    m.fingerprint = _fingerprint(m)
    return m


# ── The rewrite engine ───────────────────────────────────────────────────────

def _match_case(src: str, dst: str) -> str:
    if src.isupper():
        return dst.upper()
    if src.islower():
        return dst.lower()
    if src[:1].isupper() and src[1:].islower():
        return dst[:1].upper() + dst[1:].lower()
    # Multi-word title case ("Example Labs"), which none of the above catch.
    if src == src.title():
        return dst.title()
    return dst


class Rewriter:
    """
    One ordered replacement pass applied to every string value in the graph.
    Stage order is load-bearing — see the module docstring.
    """

    def __init__(self, mapping: Mapping) -> None:
        self.m = mapping
        self._dn = re.compile(r"(?i)(?:DC=[A-Za-z0-9_\-]+)(?:\s*,\s*DC=[A-Za-z0-9_\-]+)+")

        # 2. FQDN suffixes, longest first so ad.example.com beats example.com.
        doms = sorted(mapping.domains.items(), key=lambda kv: -len(kv[0]))
        self._domain_rules = [
            (re.compile(r"(?i)(?<![A-Za-z0-9.\-])((?:[A-Za-z0-9_\-]+\.)*)"
                        + re.escape(src) + r"(?![A-Za-z0-9\-])"), src, dst)
            for src, dst in doms
        ]
        # 3. NetBIOS, both DOMAIN\user and the isolated all-caps word.
        self._netbios_rules = [
            (re.compile(r"(?i)\b" + re.escape(src) + r"(?=\\)"), dst)
            for src, dst in mapping.netbios.items()
        ]
        # 4. Brand tokens: bounded first, then glued.
        brands = sorted(mapping.brands.items(), key=lambda kv: -len(kv[0]))
        self._brand_bounded = [
            (re.compile(r"(?i)(?<![A-Za-z0-9])" + re.escape(src) + r"(?![A-Za-z0-9])"), dst)
            for src, dst in brands
        ]
        self._brand_glued = [
            (re.compile(r"(?i)" + re.escape(src)), dst) for src, dst in brands
        ]
        # 0. Literal phrases the operator supplied, applied before everything.
        self._phrases = [
            (re.compile(r"(?i)" + re.escape(src)), dst)
            for src, dst in sorted(mapping.extra_phrases.items(), key=lambda kv: -len(kv[0]))
        ]
        # Whole org names, before the brand stage can chew them up piecemeal.
        self._org_rules = [
            (re.compile(r"(?i)" + re.escape(src)), dst)
            for src, dst in sorted(mapping.org_names.items(), key=lambda kv: -len(kv[0]))
        ]
        # 5. Surnames, LAST, pre-filtered against brands and DNS labels so this
        #    stage cannot re-mangle the output of stages 2-4.
        reserved = {b.lower() for b in mapping.brands}
        reserved |= {v.lower() for v in mapping.brands.values()}
        for dom in list(mapping.domains) + list(mapping.domains.values()):
            reserved |= {part.lower() for part in dom.split(".")}
        #    Held as dicts, not as ~2k individual patterns: one compiled
        #    pattern per surname would mean ~2k regex passes over every one of
        #    the millions of property values in a large sketch (billions of
        #    operations, hours).
        #    A single tokenizing pass with a dict lookup is the same semantics —
        #    "this whole alphanumeric run is a surname" — in one scan.
        # Replacement tokens must never be fed back into the surname matcher:
        # a replacement domain label must not be decomposed into surname+suffix.
        self._protected: Set[str] = set()
        for dom in mapping.domains.values():
            self._protected |= {part.lower() for part in dom.split(".")}
        self._protected |= {v.lower() for v in mapping.brands.values()}
        self._protected |= {v.lower() for v in mapping.netbios.values()}
        self._protected |= {v.lower() for v in mapping.surnames.values()}
        self._protected |= {v.lower() for v in mapping.retired.values()}
        # Generated pseudonyms are built from real-sounding tails (-wick, -worth,
        # -berg), and some of those tails ARE real surnames in a real corpus. So
        # "Eastworth" (a pseudonym) contains "worth" (a real surname), and the
        # embedded matcher would happily re-split its own output. One regex over
        # every issued pseudonym lets _embedded refuse any token that already
        # contains sanitized text.
        issued = sorted((set(mapping.surnames.values())
                         | set(mapping.retired.values())),
                        key=len, reverse=True)
        self._pseudo_rx = (re.compile("|".join(re.escape(v.lower()) for v in issued))
                           if issued else None)

        self._sur_all: Dict[str, str] = {}
        self._sur_long: Dict[str, str] = {}
        retired = {k.lower() for k in mapping.retired}
        for src, dst in mapping.surnames.items():
            key = src.lower()
            if key in reserved or key in retired:
                continue
            self._sur_all[key] = dst
            if len(key) >= MIN_FREE_TEXT_SURNAME:
                self._sur_long[key] = dst

    # -- stages ------------------------------------------------------------

    def _sub_domains(self, s: str) -> str:
        for rx, src, dst in self._domain_rules:
            def repl(mo: "re.Match[str]", _src=src, _dst=dst) -> str:
                return mo.group(1) + _match_case(mo.group(0)[len(mo.group(1)):], _dst)
            s = rx.sub(repl, s)
        return s

    def _sub_dn(self, s: str) -> str:
        if "DC=" not in s and "dc=" not in s:
            return s

        def repl(mo: "re.Match[str]") -> str:
            raw = mo.group(0)
            comps = [c.strip() for c in raw.split(",")]
            labels = [c.split("=", 1)[1] for c in comps]
            new = self._sub_domains(".".join(labels)).split(".")
            # Preserve each component's original case and the original spacing.
            out = []
            for i, lab in enumerate(new):
                src = labels[i] if i < len(labels) else lab
                prefix = comps[i].split("=", 1)[0] if i < len(comps) else "DC"
                out.append(f"{prefix}={_match_case(src, lab)}")
            sep = ", " if ", " in raw else ","
            return sep.join(out)

        return self._dn.sub(repl, s)

    def _sub_surnames(self, s: str, identity: bool,
                      embedded: bool = False) -> str:
        # identity=True also allows the short surnames (li, ng, lee, day), which
        # are only safe where the surrounding format says the value is a name.
        table = self._sur_all if identity else self._sur_long
        if not table:
            return s

        def swap(word: str) -> Optional[str]:
            """Whole run, or surname + trailing digits. None when no match."""
            lw = word.lower()
            if lw in self._protected:
                return None
            hit = table.get(lw)
            if hit:
                return _match_case(word, hit)
            # A disambiguating numeric suffix: DOE0015, SMITH011, JONES25,
            # jane.roe1 — the largest class of real-name residue in an AD
            # corpus, and a plain whole-run lookup misses every one of them.
            core = lw.rstrip("0123456789")
            if core != lw and len(core) >= 3 and core not in self._protected:
                hit = table.get(core)
                if hit:
                    return _match_case(word[:len(core)], hit) + word[len(core):]
            return None

        def part(mo: "re.Match[str]") -> str:
            return swap(mo.group(0)) or mo.group(0)

        def sub_part(mo: "re.Match[str]") -> str:
            word = mo.group(0)
            got = swap(word)
            if got is not None:
                return got
            if embedded:
                got = self._embedded(word)
                if got is not None:
                    return got
            return word

        def run(mo: "re.Match[str]") -> str:
            whole = mo.group(0)
            got = swap(whole)
            if got is not None:
                return got
            # A hyphenated run that is not itself a surname may still contain
            # one, matching the boundary semantics where a hyphen is a word
            # break. JDOE_OPS-EXAMPLESON2 arrives here as the run OPS-EXAMPLESON2.
            # Descend to the sub-parts BEFORE trying an embedded match on the
            # joined run: "da-whierwick" must be seen as "da" + the pseudonym
            # "whierwick", not as something ending in the real surname "wick".
            if "-" in whole or "'" in whole:
                return _ALNUM_RUN.sub(sub_part, whole)
            if embedded:
                got = self._embedded(whole)
                if got is not None:
                    return got
            return whole

        return _TOKEN_RUN.sub(run, s)

    def _embedded(self, word: str) -> Optional[str]:
        """
        <initials><surname><digits> and <surname><non-name suffix>, for login
        tokens only. The trailing-suffix form requires the leftover to contain a
        digit or be a known account suffix, so SMITHFIELD is left alone while
        SMITH1ADM and JONES007O365 are not.
        """
        lw = word.lower()
        if lw in self._protected:
            return None
        if self._pseudo_rx is not None and self._pseudo_rx.search(lw):
            return None
        core = lw.rstrip("0123456789")
        stem, digits = word[:len(core)], word[len(core):]
        n = len(core)
        if n < 6 or core in self._protected:
            return None
        for cut in range(1, n - 3):                  # longest trailing surname
            tail = core[cut:]
            if len(tail) >= 4 and tail in self._sur_long:
                return (stem[:cut]
                        + _match_case(stem[cut:], self._sur_long[tail]) + digits)
        for cut in range(n - 1, 3, -1):              # longest leading surname
            head, rest = core[:cut], core[cut:]
            if head in self._sur_long and _ACCT_SUFFIX.match(rest):
                return (_match_case(stem[:cut], self._sur_long[head])
                        + stem[cut:] + digits)
        return None

    def rewrite(self, s: str, *, identity: bool = False,
                surnames: bool = True, embedded: bool = False) -> str:
        if not s:
            return s
        for rx, dst in self._phrases:
            s = rx.sub(lambda mo, _d=dst: _match_case(mo.group(0), _d), s)
        for rx, dst in self._org_rules:
            s = rx.sub(dst, s)
        s = self._sub_dn(s)
        s = self._sub_domains(s)
        for rx, dst in self._netbios_rules:
            s = rx.sub(lambda mo, _d=dst: _match_case(mo.group(0), _d), s)
        for rx, dst in self._brand_bounded:
            s = rx.sub(lambda mo, _d=dst: _match_case(mo.group(0), _d), s)
        for rx, dst in self._brand_glued:
            s = rx.sub(lambda mo, _d=dst: _match_case(mo.group(0), _d), s)
        if surnames:
            s = self._sub_surnames(s, identity, embedded)
        return s

    def rewrite_value(self, v: Any, *, identity: bool = False,
                      surnames: bool = True, embedded: bool = False) -> Any:
        if isinstance(v, str):
            stripped = v.lstrip()
            if stripped[:1] in "{[":
                try:
                    obj = json.loads(v)
                except (ValueError, TypeError):
                    return self.rewrite(v, identity=identity, surnames=surnames,
                                        embedded=embedded)
                new = self.rewrite_json(obj, identity=identity, surnames=surnames,
                                        embedded=embedded)
                if new == obj:
                    return v
                return json.dumps(new, ensure_ascii=False)
            return self.rewrite(v, identity=identity, surnames=surnames,
                                embedded=embedded)
        if isinstance(v, list):
            return [self.rewrite_value(x, identity=identity, surnames=surnames,
                                       embedded=embedded)
                    for x in v]
        return v

    def rewrite_json(self, obj: Any, *, identity: bool = False,
                     surnames: bool = True, embedded: bool = False) -> Any:
        """Values only — a JSON key is schema, not data."""
        if isinstance(obj, dict):
            return {k: self.rewrite_json(v, identity=identity,
                                         surnames=surnames, embedded=embedded)
                    for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.rewrite_json(v, identity=identity, surnames=surnames,
                                      embedded=embedded)
                    for v in obj]
        if isinstance(obj, str):
            return self.rewrite(obj, identity=True, surnames=surnames,
                                embedded=embedded)
        return obj


# ── Node patching ────────────────────────────────────────────────────────────

def patch_props(props: Dict[str, Any], rw: Rewriter, node_type: str,
                credentials: str = "rewrite",
                rename_hosts: bool = False) -> Dict[str, Any]:
    """Return only the keys whose value actually changes."""
    kind = classify(node_type, props)
    # Embedded-surname decomposition is confined to login/name fields on
    # person-ish nodes. Turned loose on group names it would chew up ordinary
    # words (an "-ADMIN" suffix, a compound department name); here the
    # surrounding format really is "<initials><surname><digits>".
    # Nodes whose identity fields really do hold a person: individuals, and the
    # breach/profile/credential types whose "identity_name" is literally an email
    # address. Organizations are excluded on purpose — their label is a group
    # name, where a 3-letter surname match means "COE" (Center of Excellence)
    # becomes a person, and an embedded match chews up ordinary words.
    person_like = (kind in (Kind.PERSON, Kind.OPAQUE, Kind.SERVICE)
                   or (node_type or "").lower() in _IDENTITY_TYPES)
    # Workstations are often named after the person who uses them
    # (LTJSMITH01). Opt-in, because the same decomposition also chews through
    # machine naming schemes that merely look like names — BLUEBERRY2024
    # becomes BLUEGAUMWOOD2024, and LIVESTOCK01 loses "stock". Typically a small
    # share of device names; the dry run prints the count either way.
    if rename_hosts and kind == Kind.MACHINE:
        person_like = True
    # A built-in principal's NAME is a protocol constant WF04 matches on; it gets
    # domain and brand rewriting but never surname substitution.
    allow_surnames = kind != Kind.BUILTIN
    changes: Dict[str, Any] = {}

    for key, val in props.items():
        if key in FROZEN_KEYS or val is None:
            continue
        if not isinstance(val, (str, list)):
            continue

        if key == _PROP + "credential_value":
            if credentials == "keep":
                continue
            if credentials == "redact":
                if val != "[REDACTED]":
                    changes[key] = "[REDACTED]"
                continue
            # 'rewrite': brand-map it AND surname-map it. A password like
            # "Smith6!" or "JANE1985doe" carries a real family name that the
            # rest of the pass has erased everywhere else; leaving it would
            # re-identify the person from their own credential. The finding —
            # "users pick a name as their password" — survives intact.
            new = rw.rewrite_value(val, identity=True, surnames=True,
                                   embedded=True)
        else:
            new = rw.rewrite_value(val,
                                   identity=(person_like and key in IDENTITY_KEYS),
                                   surnames=allow_surnames,
                                   embedded=(person_like and key in LOGIN_KEYS))
        if new != val:
            changes[key] = new

    # sid is frozen except for the domain-prefixed form (AD.EXAMPLE.COM-S-1-5-32-544),
    # where only the prefix is rewritten. The bare S-1-... body is the join key
    # flowsint_client._bulk_create_edges_neo4j resolves cross-chunk edges through.
    sid = props.get(_PROP + "sid")
    if isinstance(sid, str):
        mo = _DOMSID_RE.match(sid)
        if mo:
            new_dom = rw.rewrite(mo.group("dom"), identity=True,
                                 surnames=allow_surnames)
            if new_dom != mo.group("dom"):
                changes[_PROP + "sid"] = f"{new_dom}-{mo.group('sid')}"

    return changes


# ── Read / write ─────────────────────────────────────────────────────────────

_READ_UNSTAMPED = """
MATCH (n {sketch_id:$sid})
WHERE n.deleted_at IS NULL AND coalesce(n.sanitize_rev,'') <> $rev
RETURN elementId(n) AS eid, n.nodeType AS t, properties(n) AS p
LIMIT $lim
"""

_READ_PAGE = """
MATCH (n {sketch_id:$sid})
WHERE n.deleted_at IS NULL
RETURN elementId(n) AS eid, n.nodeType AS t, properties(n) AS p
ORDER BY elementId(n) SKIP $skip LIMIT $lim
"""

# Every value is precomputed in Python, so unlike migrate_c2session.py's
# WITH-then-SET dance there is no read-after-write hazard inside this statement.
_WRITE = """
UNWIND $rows AS row
MATCH (n) WHERE elementId(n) = row.eid
SET n += row.props, n.sanitize_rev = $rev
RETURN count(n) AS c
"""


def iter_nodes(neo: Neo4jHTTP, sketch_id: str, rev: str, page: int,
               unstamped_only: bool) -> Iterator[List[List[Any]]]:
    """
    Yield pages of nodes. When unstamped_only, re-query the head of the
    unprocessed set each time — nodes drop out as they are stamped, which makes
    the loop naturally restartable and avoids SKIP drifting under our own writes.
    """
    if unstamped_only:
        while True:
            rows = neo.query(_READ_UNSTAMPED,
                             {"sid": sketch_id, "rev": rev, "lim": page})
            if not rows:
                return
            yield rows
    else:
        skip = 0
        while True:
            rows = neo.query(_READ_PAGE,
                             {"sid": sketch_id, "skip": skip, "lim": page})
            if not rows:
                return
            yield rows
            skip += len(rows)


def write_batch(neo: Neo4jHTTP, rows: List[Dict[str, Any]], rev: str) -> int:
    if not rows:
        return 0
    return int(neo.query(_WRITE, {"rows": rows, "rev": rev})[0][0])


# ── Collision detection ──────────────────────────────────────────────────────

def find_collisions(planned: Dict[str, Tuple[str, str]],
                    unchanged: Dict[str, Tuple[str, str]]) -> List[Dict[str, Any]]:
    """
    Flowsint MERGEs on (node_type, nodeLabel, sketch_id) and NO uniqueness
    constraint exists on sketch nodes, so two labels fusing would not error here
    — it would silently merge two nodes into one on the NEXT import. Detect it
    now or plant a data-loss bomb for later.
    """
    buckets: Dict[Tuple[str, str], List[str]] = {}
    for eid, (ntype, label) in list(unchanged.items()) + list(planned.items()):
        buckets.setdefault((ntype, label), []).append(eid)
    out = []
    for (ntype, label), eids in buckets.items():
        if len(eids) > 1:
            out.append({"node_type": ntype, "new_label": label,
                        "count": len(eids), "eids": eids[:5]})
    return out


# ── Graph phases ─────────────────────────────────────────────────────────────

def plan_graph(neo: Neo4jHTTP, sketch_id: str, rw: Rewriter, rev: str,
               page: int, credentials: str, rename_hosts: bool = False,
               sample_limit: int = 6) -> Dict[str, Any]:
    kinds: Dict[str, int] = {}
    key_counts: Dict[str, int] = {}
    samples: Dict[str, List[Dict[str, str]]] = {}
    planned_labels: Dict[str, Tuple[str, str]] = {}
    unchanged_labels: Dict[str, Tuple[str, str]] = {}
    nodes_changed = 0
    props_changed = 0
    fixpoint_failures: List[str] = []
    checked = 0

    for rows in iter_nodes(neo, sketch_id, rev, page, unstamped_only=False):
        for eid, ntype, props in rows:
            ntype = str(ntype or "")
            kinds[classify(ntype, props)] = kinds.get(classify(ntype, props), 0) + 1
            changes = patch_props(props, rw, ntype, credentials, rename_hosts)

            label = changes.get("nodeLabel", props.get("nodeLabel"))
            if label is not None:
                (planned_labels if "nodeLabel" in changes
                 else unchanged_labels)[eid] = (ntype, str(label))

            if not changes:
                continue
            nodes_changed += 1
            props_changed += len(changes)
            for k in changes:
                key_counts[k] = key_counts.get(k, 0) + 1

            # Fixpoint assertion on a sample: rewriting the output again must be
            # a no-op, or a re-run after a crash would double-mangle the data.
            if checked < 1000:
                for k, v in changes.items():
                    if isinstance(v, str):
                        again = rw.rewrite_value(v, identity=(k in IDENTITY_KEYS))
                        if again != v:
                            fixpoint_failures.append(f"{k}: {v!r} -> {again!r}")
                        checked += 1
                        break

            bucket = samples.setdefault(ntype, [])
            if len(bucket) < sample_limit:
                k, v = next(iter(changes.items()))
                bucket.append({"key": k, "before": str(props.get(k))[:110],
                               "after": str(v)[:110]})

    return {
        "nodes_changed": nodes_changed,
        "props_changed": props_changed,
        "kinds": kinds,
        "key_counts": dict(sorted(key_counts.items(), key=lambda kv: -kv[1])),
        "samples": samples,
        "collisions": find_collisions(planned_labels, unchanged_labels),
        "fixpoint_failures": fixpoint_failures[:10],
    }


def apply_graph(neo: Neo4jHTTP, sketch_id: str, rw: Rewriter, rev: str,
                page: int, batch: int, credentials: str,
                rename_hosts: bool = False) -> Dict[str, Any]:
    written = 0
    stamped = 0
    errors: List[str] = []
    pending: List[Dict[str, Any]] = []

    def flush() -> None:
        nonlocal written, stamped, pending
        if not pending:
            return
        try:
            stamped += write_batch(neo, pending, rev)
            written += sum(1 for r in pending if r["props"])
        except Exception as exc:                       # noqa: BLE001 - keep going
            errors.append(f"{pending[0]['eid']}..{pending[-1]['eid']}: {exc}")
        pending = []

    for rows in iter_nodes(neo, sketch_id, rev, page, unstamped_only=True):
        for eid, ntype, props in rows:
            changes = patch_props(props, rw, str(ntype or ""), credentials,
                                  rename_hosts)
            pending.append({"eid": eid, "props": changes})
            if len(pending) >= batch:
                flush()
        flush()

    return {"nodes_written": written, "nodes_stamped": stamped, "errors": errors}


def verify_graph(neo: Neo4jHTTP, sketch_id: str, mapping: Mapping,
                 rw: "Rewriter", rev: str, page: int,
                 credentials: str, rename_hosts: bool = False) -> Dict[str, Any]:
    """
    Two gates plus one advisory.

    GATE 1 — literal residue. No configured brand, domain or NetBIOS token may
    appear anywhere in the sketch. Policy-independent: this must be zero.

    GATE 2 — policy residue. Re-plan the whole sketch; if the rewriter would
    still change anything, the pass is not finished. This is stronger and more
    honest than grepping for names, because it measures exactly what the tool
    would still do rather than what a human guessed to look for.

    ADVISORY — real surnames still present somewhere. Some of these are
    deliberate: "west" inside the group TEAM-OPS3WEST-C is a direction, and the
    policy does not surname-map group names. Reported so an operator can judge,
    never failed on, or the scan could never go green.
    """
    terms = residue_terms(mapping.brands, mapping.domains, mapping.netbios)
    hits = []
    for term, t, k, c in neo.query(
            "MATCH (n {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
            "UNWIND keys(n) AS k "
            "WITH n.nodeType AS t, k, toLower(toString(n[k])) AS v WHERE v <> '' "
            "UNWIND $terms AS term WITH t, k, term, v WHERE v CONTAINS term "
            "RETURN term, t, k, count(*) AS c ORDER BY c DESC LIMIT 100",
            {"sid": sketch_id, "terms": terms}):
        hits.append({"term": str(term), "node_type": str(t), "key": str(k),
                     "count": int(c)})

    rep = plan_graph(neo, sketch_id, rw, rev, page, credentials, rename_hosts)

    # Advisory: an UNWIND of ~2k terms over millions of values is not viable
    # in Cypher, so tokenize in Python and test set membership instead.
    real = {k.lower() for k in mapping.surnames if len(k) >= MIN_FREE_TEXT_SURNAME}
    tok = re.compile(r"[a-z]{%d,}" % MIN_FREE_TEXT_SURNAME)
    sur: Dict[str, int] = {}
    for rows in iter_nodes(neo, sketch_id, "", page, unstamped_only=False):
        for _eid, _t, props in rows:
            for k, v in props.items():
                if k in FROZEN_KEYS or not isinstance(v, str):
                    continue
                for t in tok.findall(v.lower()):
                    if t in real:
                        sur[t] = sur.get(t, 0) + 1

    return {
        "literal_hits": hits,
        "policy_residue_nodes": rep["nodes_changed"],
        "policy_residue_props": rep["props_changed"],
        "collisions": rep["collisions"],
        "surname_advisory": dict(sorted(sur.items(), key=lambda kv: -kv[1])[:25]),
        "clean": not hits and rep["nodes_changed"] == 0,
    }


def parity(neo: Neo4jHTTP, sketch_id: str) -> Dict[str, Any]:
    p = {"sid": sketch_id}
    by_type = {str(t): int(c) for t, c in neo.query(
        "MATCH (n {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
        "RETURN n.nodeType AS t, count(*) AS c", p)}
    distinct = {str(t): int(c) for t, c in neo.query(
        "MATCH (n {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
        "RETURN n.nodeType AS t, count(DISTINCT n.nodeLabel) AS c", p)}
    return {
        "nodes": int(neo.scalar("MATCH (n {sketch_id:$sid}) "
                                "WHERE n.deleted_at IS NULL RETURN count(n)", p) or 0),
        "edges": int(neo.scalar("MATCH ()-[r {sketch_id:$sid}]->() "
                                "RETURN count(r)", p) or 0),
        "by_type": by_type,
        "distinct_labels": distinct,
    }


# ── Registry and notifications ───────────────────────────────────────────────

_REG_READ = "MATCH (m:SpotterMeta {key:'campaigns'}) RETURN m.data AS d"
# Compare-and-swap. write_campaigns() in spotter_campaign_acl.py is a blind
# whole-array overwrite; all the merge safety lives in merge_save(), which only
# WF18 applies. A CAS is what keeps a concurrent UI save from being lost.
_REG_CAS = """
MATCH (m:SpotterMeta {key:'campaigns'}) WHERE m.data = $expected
SET m.data = $new, m.updated_at = timestamp()
RETURN count(m) AS updated
"""

# objectives.missionStatement is deliberately absent: the operator hand-edits the
# prose, because a machine rewrite cannot catch phrasing, employee counts or
# market sector, and silently half-sanitized prose is worse than untouched prose.
REGISTRY_FIELDS = ("targetName", "companyEmail", "additionalIds")


def rewrite_registry(neo: Neo4jHTTP, rw: Rewriter, campaign_id: str,
                     apply: bool) -> Dict[str, Any]:
    rows = neo.query(_REG_READ)
    if not rows or not rows[0][0]:
        return {"error": "campaign registry not found"}
    raw = rows[0][0]
    camps = json.loads(raw)

    changes: List[Dict[str, str]] = []
    prose_left: List[str] = []
    for camp in camps:
        if not isinstance(camp, dict) or camp.get("id") != campaign_id:
            continue
        obj = camp.get("objectives")
        if not isinstance(obj, dict):
            continue
        for fld in REGISTRY_FIELDS:
            old = obj.get(fld)
            if not isinstance(old, str) or not old:
                continue
            new = rw.rewrite(old, identity=True)
            if new != old:
                changes.append({"field": fld, "before": old, "after": new})
                obj[fld] = new
        mission = obj.get("missionStatement")
        if isinstance(mission, str) and mission:
            probe = rw.rewrite(mission, identity=True)
            if probe != mission:
                prose_left.append(
                    "objectives.missionStatement still contains client tokens — "
                    "hand-edit it in the UI (Objectives tab).")
    result: Dict[str, Any] = {"changes": changes, "manual": prose_left}

    if apply and changes:
        new_raw = json.dumps(camps, ensure_ascii=False)
        updated = int(neo.query(_REG_CAS,
                                {"expected": raw, "new": new_raw})[0][0])
        if updated != 1:
            result["error"] = ("registry changed underneath us — re-run "
                               "(nothing was written)")
        else:
            result["written"] = True
    return result


_NOTIF_COUNT = """
MATCH (n:SpotterNotification {campaign_id:$camp}) RETURN count(n) AS c
"""
_NOTIF_DELETE = """
MATCH (n:SpotterNotification {campaign_id:$camp})
WITH n LIMIT $lim DETACH DELETE n RETURN count(*) AS c
"""
# notify_agents holds {"agents": {}, "baselined": true}. Leaving it makes the next
# sweep re-emit up to NOTIFY_MAX_PER_SWEEP findings as visible ticker spam;
# deleting it makes sweep() re-baseline silently off the sanitized graph.
_NOTIF_META = """
MATCH (m:SpotterMeta) WHERE m.key IN $keys DETACH DELETE m RETURN count(*) AS c
"""


def purge_notifications(neo: Neo4jHTTP, campaign_id: str,
                        apply: bool) -> Dict[str, Any]:
    n = int(neo.scalar(_NOTIF_COUNT, {"camp": campaign_id}) or 0)
    keys = [f"notify_sweep:{campaign_id}", f"notify_agents:{campaign_id}"]
    meta = [str(k) for (k,) in neo.query(
        "MATCH (m:SpotterMeta) WHERE m.key STARTS WITH $p RETURN m.key",
        {"p": f"notify_read:{campaign_id}:"})]
    keys.extend(meta)
    out = {"notifications": n, "meta_keys": keys, "deleted": 0, "meta_deleted": 0}
    if not apply:
        return out
    deleted = 0
    while True:
        c = int(neo.query(_NOTIF_DELETE,
                          {"camp": campaign_id, "lim": 5000})[0][0])
        deleted += c
        if c == 0:
            break
    out["deleted"] = deleted
    out["meta_deleted"] = int(neo.query(_NOTIF_META, {"keys": keys})[0][0])
    return out


# ── Sidecar ──────────────────────────────────────────────────────────────────

def default_mapping_path(campaign_id: str) -> str:
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(repo, f"extracted_{campaign_id}-namemap.json")


def load_mapping(path: str) -> Optional[Mapping]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return Mapping.from_json(json.load(fh))
    except FileNotFoundError:
        return None


def save_mapping(m: Mapping, path: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(m.to_json(), fh, indent=2, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ── Reporting ────────────────────────────────────────────────────────────────

def _fmt_int(n: int) -> str:
    return f"{n:,}"


def print_discovery(d: Discovery) -> None:
    print(f"  nodes {_fmt_int(d.node_total)}   edges {_fmt_int(d.edge_total)} "
          f"({len(d.edge_types)} types)")
    print("  by type   " + " · ".join(f"{t} {_fmt_int(c)}"
                                      for t, c in d.by_type.items()))
    print(f"  real surnames discovered   {_fmt_int(len(d.surnames))} "
          f"(first names kept: {_fmt_int(len(d.first_names))})")
    if d.unmapped_apexes:
        print("  !! domains present in the data with NO replacement configured:")
        for apex, c in sorted(d.unmapped_apexes.items(), key=lambda kv: -kv[1]):
            print(f"       {apex:<32} {_fmt_int(c)}")
        print("     add them to DOMAIN_MAP or accept that they survive the pass.")
    if d.residue:
        print("  client tokens by property key (this is the acceptance list —")
        print("  every row here must read zero after --apply):")
        for term, t, k, c in sorted(d.residue, key=lambda r: -r[3])[:18]:
            print(f"       {term:<12} {t:<14} {k:<34} {_fmt_int(c)}")


def print_plan(rep: Dict[str, Any]) -> None:
    print(f"  nodes to change {_fmt_int(rep['nodes_changed'])}   "
          f"properties to change {_fmt_int(rep['props_changed'])}")
    print("  population   " + " · ".join(f"{k} {_fmt_int(v)}"
                                         for k, v in sorted(rep["kinds"].items())))
    opaque = rep["kinds"].get(Kind.OPAQUE, 0)
    if opaque:
        print(f"     !! {_fmt_int(opaque)} accounts have no inferable name "
              f"structure. Their logins are kept as-is;")
        print("        only an embedded real surname or the domain is rewritten.")
    print("  top changed keys")
    for k, c in list(rep["key_counts"].items())[:10]:
        print(f"       {k:<40} {_fmt_int(c)}")
    if rep["fixpoint_failures"]:
        print("  !! FIXPOINT VIOLATION — rewriting the output again changes it.")
        print("     A re-run after a crash would double-mangle. Do not apply.")
        for f in rep["fixpoint_failures"]:
            print(f"       {f}")
    if rep["collisions"]:
        print(f"  !! {len(rep['collisions'])} LABEL COLLISIONS — two nodes would "
              f"share (node_type, nodeLabel).")
        print("     No constraint catches this; they would fuse on the next import.")
        for c in rep["collisions"][:10]:
            print(f"       {c['node_type']:<14} {c['new_label'][:60]:<60} "
                  f"x{c['count']}")
    else:
        print("  label collisions 0")
    print("  samples")
    for ntype, rows in rep["samples"].items():
        for r in rows[:2]:
            print(f"       {ntype:<14} {r['key']}")
            print(f"           - {r['before']}")
            print(f"           + {r['after']}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def resolve_target(neo: Neo4jHTTP, campaign: str,
                   sketch: str) -> Tuple[str, str]:
    """
    No fallback to the most recent campaign. purge_nessus_data.py defaults to
    fc.resolve_campaign_sketch(), which would silently target a different graph
    — and this script rewrites node identities.
    """
    camps: List[Dict[str, Any]] = []
    rows = neo.query(_REG_READ)
    if rows and rows[0][0]:
        try:
            camps = [c for c in json.loads(rows[0][0]) if isinstance(c, dict)]
        except ValueError:
            camps = []
    if campaign:
        match = [c for c in camps if str(c.get("id")) == campaign]
        if not match:
            raise SystemExit(f"error: campaign {campaign!r} is not in the registry")
        resolved = str(match[0].get("sketchId") or "")
        if not resolved:
            raise SystemExit(f"error: campaign {campaign!r} has no sketchId")
        if sketch and sketch != resolved:
            raise SystemExit(f"error: --sketch {sketch} does not match campaign "
                             f"{campaign}'s sketchId {resolved}")
        return campaign, resolved
    match = [c for c in camps if str(c.get("sketchId")) == sketch]
    return (str(match[0].get("id")) if match else ""), sketch


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--campaign", default="", help="campaign id, e.g. DEMO-01")
    ap.add_argument("--sketch", default="", help="sketch id (cross-checked)")
    ap.add_argument("--mapping", default="", help="path to the mapping sidecar")
    ap.add_argument("--profile", default="",
                    help="campaign replacement profile (client tokens); default "
                         "extracted_<campaign>-profile.json")
    ap.add_argument("--seed", default="", help="or $SANITIZE_SEED; else random")
    ap.add_argument("--extra-map", default="",
                    help="JSON {literal: replacement} applied before every stage")
    ap.add_argument("--apply", action="store_true",
                    help="actually write. Without it, nothing is written.")
    ap.add_argument("--phase", default="all",
                    choices=["discover", "map", "plan", "apply", "verify", "all"])
    ap.add_argument("--scope", default="all",
                    choices=["graph", "registry", "notifications", "all"])
    ap.add_argument("--credentials", default="rewrite",
                    choices=["rewrite", "redact", "keep"])
    ap.add_argument("--on-collision", default="abort", choices=["abort", "suffix"])
    ap.add_argument("--rename-hosts", action="store_true",
                    help="also decompose device short names, catching hosts "
                         "named after their user (LTJSMITH01). Off by "
                         "default: it also mangles machine naming schemes.")
    ap.add_argument("--forget", action="store_true",
                    help="clear sanitize_rev stamps and exit")
    ap.add_argument("--list", action="store_true",
                    help="list campaigns and sketch ids, then exit")
    ap.add_argument("--json", action="store_true", help="machine-readable report")
    ap.add_argument("--batch", type=int, default=2000, help="write batch size")
    ap.add_argument("--page", type=int, default=5000, help="read page size")
    ap.add_argument("--neo4j-url", default="")
    ap.add_argument("--neo4j-user", default="")
    ap.add_argument("--neo4j-password", default="")
    args = ap.parse_args(argv)

    try:
        neo = connect(args.neo4j_url, args.neo4j_user, args.neo4j_password)
    except Exception as exc:                            # noqa: BLE001 - operator-facing
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.list:
        rows = neo.query(_REG_READ)
        camps = json.loads(rows[0][0]) if rows and rows[0][0] else []
        for c in camps:
            if isinstance(c, dict):
                print(f"  {str(c.get('sketchId') or '(no sketch)'):<40} "
                      f"{c.get('id') or '?':<24} {c.get('name') or ''}")
        return 0

    if not args.campaign and not args.sketch:
        print("error: --campaign or --sketch is required. This script rewrites "
              "node identities in place; it will not guess which graph you "
              "meant.", file=sys.stderr)
        return 2

    campaign_id, sketch_id = resolve_target(neo, args.campaign, args.sketch)
    map_path = args.mapping or default_mapping_path(campaign_id or "sketch")
    profile_path = args.profile or default_profile_path(campaign_id or "sketch")
    try:
        load_profile(profile_path)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: could not load the replacement profile {profile_path}: "
              f"{exc}\n       The client tokens live there, not in this script.",
              file=sys.stderr)
        return 2

    if args.forget:
        n = 0
        while True:
            c = int(neo.query(
                "MATCH (n {sketch_id:$sid}) WHERE n.sanitize_rev IS NOT NULL "
                "WITH n LIMIT 20000 REMOVE n.sanitize_rev RETURN count(*) AS c",
                {"sid": sketch_id})[0][0])
            n += c
            if c == 0:
                break
        print(f"cleared sanitize_rev on {_fmt_int(n)} nodes")
        return 0

    extra: Dict[str, str] = {}
    if args.extra_map:
        with open(args.extra_map, "r", encoding="utf-8") as fh:
            extra = {str(k): str(v) for k, v in json.load(fh).items()}

    report: Dict[str, Any] = {"campaign": campaign_id, "sketch": sketch_id,
                              "apply": bool(args.apply)}
    mode = "APPLY" if args.apply else "DRY-RUN"
    if not args.json:
        print(f"sanitize_campaign  {mode}   campaign {campaign_id or '(none)'}   "
              f"sketch {sketch_id}")

    want = {"discover": {"discover"}, "map": {"discover", "map"},
            "plan": {"discover", "map", "plan"},
            "apply": {"discover", "map", "apply"},
            "verify": {"verify"},
            "all": {"discover", "map", "plan", "apply", "verify"}}[args.phase]
    graph_scope = args.scope in ("graph", "all")

    mapping = load_mapping(map_path)

    # -- discover ----------------------------------------------------------
    disc: Optional[Discovery] = None
    if "discover" in want or "verify" in want:
        disc = discover(neo, sketch_id)
        report["discover"] = {
            "nodes": disc.node_total, "edges": disc.edge_total,
            "by_type": disc.by_type, "surnames": len(disc.surnames),
            "unmapped_apexes": disc.unmapped_apexes,
            "residue": [{"term": t, "node_type": nt, "key": k, "count": c}
                        for t, nt, k, c in disc.residue],
        }
        if not args.json:
            print("\ndiscover")
            print_discovery(disc)

    # -- map ---------------------------------------------------------------
    if "map" in want:
        seed_str = args.seed or os.environ.get("SANITIZE_SEED", "")
        if seed_str:
            seed = hashlib.sha256(seed_str.encode()).digest()
        elif mapping and mapping.seed_sha256:
            # Reuse is only meaningful for NEW tokens; existing assignments are
            # already frozen in the sidecar, so a fresh seed cannot reshuffle them.
            seed = secrets.token_bytes(32)
        else:
            seed = secrets.token_bytes(32)
            if not args.json:
                print(f"\n  no --seed given; generated one. To reproduce this "
                      f"mapping later:\n    --seed {seed.hex()}")
        assert disc is not None
        mapping = build_mapping(disc, seed, mapping, campaign_id, extra)
        report["mapping"] = {"path": map_path, "surnames": len(mapping.surnames),
                             "fingerprint": mapping.fingerprint}
        if args.apply or args.phase in ("map", "all"):
            save_mapping(mapping, map_path)
            if not args.json:
                print(f"\nmap\n  sidecar {map_path}")
                print(f"  {_fmt_int(len(mapping.surnames))} surnames, "
                      f"fingerprint {mapping.fingerprint}")
                print("  This file is the ONLY inverse of the rewrite and is a "
                      "complete\n  de-anonymization table. Copy it off-box, then "
                      "shred it.")

    if mapping is None:
        print("error: no mapping sidecar. Run --phase map first.", file=sys.stderr)
        return 2
    rw = Rewriter(mapping)
    rev = mapping.fingerprint

    # -- plan --------------------------------------------------------------
    if "plan" in want and graph_scope:
        rep = plan_graph(neo, sketch_id, rw, rev, args.page, args.credentials,
                         args.rename_hosts)
        report["plan"] = rep
        if not args.json:
            print("\nplan")
            print_plan(rep)
        if rep["fixpoint_failures"]:
            print("\nrefusing to continue: the rewrite is not a fixpoint.",
                  file=sys.stderr)
            return 3
        if rep["collisions"] and args.on_collision == "abort":
            print("\nrefusing to continue: label collisions. Resolve them with "
                  "--extra-map, or pass --on-collision suffix.", file=sys.stderr)
            return 3

    # -- apply -------------------------------------------------------------
    if "apply" in want and args.apply:
        if graph_scope:
            res = apply_graph(neo, sketch_id, rw, rev, args.page, args.batch,
                              args.credentials, args.rename_hosts)
            report["apply_graph"] = res
            if not args.json:
                print(f"\napply (graph)\n  nodes written {_fmt_int(res['nodes_written'])}"
                      f"   stamped {_fmt_int(res['nodes_stamped'])}")
                for e in res["errors"]:
                    print(f"  !! {e}")
        if args.scope in ("notifications", "all") and campaign_id:
            res = purge_notifications(neo, campaign_id, True)
            report["apply_notifications"] = res
            if not args.json:
                print(f"\napply (notifications)\n  deleted "
                      f"{_fmt_int(res['deleted'])} notifications, "
                      f"{res['meta_deleted']} meta keys")
        if args.scope in ("registry", "all") and campaign_id:
            res = rewrite_registry(neo, rw, campaign_id, True)
            report["apply_registry"] = res
            if not args.json:
                print("\napply (registry)")
                for c in res.get("changes", []):
                    print(f"  {c['field']}\n    - {c['before'][:150]}"
                          f"\n    + {c['after'][:150]}")
                for m in res.get("manual", []):
                    print(f"  !! {m}")
                if res.get("error"):
                    print(f"  !! {res['error']}")
    elif "apply" in want and not args.apply:
        if args.scope in ("registry", "all") and campaign_id:
            res = rewrite_registry(neo, rw, campaign_id, False)
            report["registry"] = res
            if not args.json:
                print("\nregistry (dry run)")
                for c in res.get("changes", []):
                    print(f"  {c['field']}\n    - {c['before'][:150]}"
                          f"\n    + {c['after'][:150]}")
                for m in res.get("manual", []):
                    print(f"  !! {m}")
        if args.scope in ("notifications", "all") and campaign_id:
            res = purge_notifications(neo, campaign_id, False)
            report["notifications"] = res
            if not args.json:
                print(f"\nnotifications (dry run)\n  would delete "
                      f"{_fmt_int(res['notifications'])} nodes and "
                      f"{len(res['meta_keys'])} meta keys")

    # -- verify ------------------------------------------------------------
    if "verify" in want and graph_scope:
        res = verify_graph(neo, sketch_id, mapping, rw, rev, args.page,
                           args.credentials, args.rename_hosts)
        res["parity"] = parity(neo, sketch_id)
        report["verify"] = res
        if not args.json:
            print("\nverify")
            print(f"  parity  nodes {_fmt_int(res['parity']['nodes'])}  "
                  f"edges {_fmt_int(res['parity']['edges'])}")
            if res["clean"]:
                print("  gate 1  literal residue 0 — no configured brand, domain "
                      "or NetBIOS token survives")
                print("  gate 2  policy residue 0 — a re-plan would change nothing")
            else:
                for h in res["literal_hits"][:20]:
                    print(f"  !! literal {h['term']:<12} {h['node_type']:<14} "
                          f"{h['key']:<30} {_fmt_int(h['count'])}")
                if res["policy_residue_nodes"]:
                    print(f"  !! policy residue: {_fmt_int(res['policy_residue_nodes'])}"
                          f" nodes would still change — re-run --apply")
            if res["surname_advisory"]:
                print("  advisory — real surnames still present (policy leaves "
                      "group names and free text alone):")
                for t, c in list(res["surname_advisory"].items())[:12]:
                    print(f"       {t:<20} {_fmt_int(c)}")

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    elif not args.apply:
        print("\nDRY RUN — nothing written. There is no Neo4j backup on this host.")
        print("Re-run with --apply to write.")

    if "verify" in want and graph_scope and not report.get("verify", {}).get("clean"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
