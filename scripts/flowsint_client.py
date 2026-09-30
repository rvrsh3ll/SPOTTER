"""
flowsint_client.py — Thin REST client for the Flowsint API.

All SPOTTER scripts and enrichers use this module to talk to Flowsint rather
than constructing raw HTTP calls individually.

API base   : FLOWSINT_API_URL env var  (default http://flowsint-api:5001)
Auth       : Bearer token via FLOWSINT_API_KEY env var
Sketch     : FLOWSINT_SKETCH_ID env var — all entities land in this sketch

Key endpoints used (verified against flowsint-api/app/api/routes/sketches.py):
  GET  /api/sketches/{id}/graph                 — full graph read
  POST /api/sketches/{id}/nodes/add             — add single node
  PUT  /api/sketches/{id}/nodes/edit            — patch node properties
  POST /api/sketches/{id}/import/execute        — batch import (nodes + edges)
  DELETE /api/sketches/{id}/nodes               — remove nodes by ID list
  DELETE /api/sketches/{id}/relationships       — remove relationships by ID list
"""

from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── Configuration (read from environment) ─────────────────────────────────────

API_URL   = os.environ.get("FLOWSINT_API_URL", "http://flowsint-api:5001")
API_KEY   = os.environ.get("FLOWSINT_API_KEY", "")
SKETCH_ID = os.environ.get("FLOWSINT_SKETCH_ID", "")

# Direct-Neo4j access — used only for the bulk edge fast-path (see batch_import).
# Flowsint's /graph endpoint reads straight from Neo4j, so relationships written
# here (same schema as flowsint-core's Neo4jGraphRepository) are read back intact.
# When these are unset the importer falls back to the per-edge REST path.
NEO4J_HTTP_URL = os.environ.get("NEO4J_HTTP_URL", "")
NEO4J_USER     = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")

# 30-second graph cache — keyed by sketch_id so multi-sketch callers stay isolated.
# Cleared and replaced on each cache miss, keeping memory bounded to one snapshot.
_graph_cache: Dict[str, Any] = {}


def _session() -> requests.Session:
    """Return a requests Session with retry logic and Bearer auth."""
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


def _url(path: str, sketch_id: Optional[str] = None) -> str:
    sid = sketch_id or SKETCH_ID
    base = f"{API_URL}/api/sketches/{sid}"
    return base + path


# ── Graph reads ───────────────────────────────────────────────────────────────
#
# GET /api/sketches/{id}/graph is unpaginated and deserializes every node through
# Pydantic, so it costs 110-235s (~0.5 GB) on an AD-sized sketch and silently
# truncates at the repository's LIMIT 100000. Prefer the targeted readers below,
# which seek the per-label (sketch_id) indexes in Neo4j directly and return the
# same node/edge shape. get_graph() is kept for callers that genuinely want
# everything, but it is the slow path.

_GRAPH_READ_TIMEOUT = 300   # get_graph had no timeout at all; bound it
_NEO4J_READ_TIMEOUT = 60


def get_graph(sketch_id: Optional[str] = None) -> Dict[str, Any]:
    """Return the full graph (nodes + edges) for the sketch, cached for 30 seconds."""
    sid = sketch_id or SKETCH_ID
    bucket = int(time.time()) // 30
    cache_key = f"{sid}:{bucket}"
    if cache_key in _graph_cache:
        return _graph_cache[cache_key]
    resp = _session().get(_url("/graph", sketch_id), timeout=_GRAPH_READ_TIMEOUT)
    resp.raise_for_status()
    raw = resp.json()
    # Normalize compact keys returned by the API (nds/rls → nodes/edges)
    result = {
        "nodes": raw.get("nodes") or raw.get("nds") or [],
        "edges": raw.get("edges") or raw.get("rls") or [],
    }
    _graph_cache.clear()
    _graph_cache[cache_key] = result
    return result


_LABEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PROP_PREFIX = "nodeProperties."


def _quote_label(label: str) -> str:
    """Backtick a Neo4j label after validating it — labels cannot be parameterized."""
    if not _LABEL_RE.match(label or ""):
        raise ValueError(f"Unsafe Neo4j label/relationship type: {label!r}")
    return f"`{label}`"


def _neo4j_rows(
    statement: str,
    parameters: Dict[str, Any],
    timeout: int = _NEO4J_READ_TIMEOUT,
) -> List[Dict[str, Any]]:
    """Run one read statement and return its rows as column->value dicts."""
    body = _neo4j_commit(statement, parameters, timeout=timeout)
    results = body.get("results") or []
    if not results:
        return []
    cols = results[0].get("columns") or []
    return [dict(zip(cols, row["row"])) for row in results[0].get("data", [])]


def _node_from_props(props: Dict[str, Any], element_id: str) -> Dict[str, Any]:
    """
    Rebuild the API's node shape from a raw Neo4j property map.

    Properties are stored flattened as dotted keys ("nodeProperties.email"), so
    the prefix is stripped back into a nested dict to match what
    GET /graph returns and what every workflow already consumes.
    """
    node_props = {
        k[len(_PROP_PREFIX):]: v
        for k, v in props.items()
        if k.startswith(_PROP_PREFIX)
    }
    return {
        "id": element_id,
        "nodeType": props.get("nodeType", ""),
        "nodeLabel": props.get("nodeLabel", ""),
        "nodeProperties": node_props,
    }


def get_nodes_by_type(
    labels: Any,
    sketch_id: Optional[str] = None,
    properties: Optional[List[str]] = None,
    timeout: int = _NEO4J_READ_TIMEOUT,
) -> List[Dict[str, Any]]:
    """
    Return nodes for the given Neo4j label(s), scoped to one sketch.

    This is the fast replacement for filtering a full get_graph() result. Each
    label is a separate index-backed seek on (sketch_id); on a 136k-node AD
    sketch the largest label returns in well under a second.

    labels     : a label string or list of labels. Case matters — built-in types
                 are lowercase ("individual", "device"), SPOTTER's custom types
                 are PascalCase ("WebAsset", "Subdomain", "C2Session").
    properties : optional whitelist of nodeProperties keys to project. Omit to
                 return every property (larger payload, same shape).

    Nodes come back in the API's shape: {id, nodeType, nodeLabel, nodeProperties}
    with `id` being the Neo4j elementId — the same identifier GET /graph emits,
    so results stay valid for edit_node() / create_edge().
    """
    sid = sketch_id or SKETCH_ID
    if isinstance(labels, str):
        labels = [labels]
    out: List[Dict[str, Any]] = []

    for label in labels:
        quoted = _quote_label(label)
        if properties is None:
            rows = _neo4j_rows(
                f"MATCH (n:{quoted} {{sketch_id: $sid}}) WHERE n.deleted_at IS NULL "
                f"RETURN elementId(n) AS eid, properties(n) AS p",
                {"sid": sid},
                timeout=timeout,
            )
            out.extend(_node_from_props(r["p"] or {}, r["eid"]) for r in rows)
        else:
            # Project only the requested keys so a wide label (individual carries
            # ~30 properties) does not ship megabytes the caller will discard.
            keys = [_PROP_PREFIX + p for p in properties]
            rows = _neo4j_rows(
                f"MATCH (n:{quoted} {{sketch_id: $sid}}) WHERE n.deleted_at IS NULL "
                f"RETURN elementId(n) AS eid, n.nodeType AS nt, n.nodeLabel AS nl, "
                f"[k IN $keys | n[k]] AS vals",
                {"sid": sid, "keys": keys},
                timeout=timeout,
            )
            for r in rows:
                vals = r.get("vals") or []
                out.append({
                    "id": r["eid"],
                    "nodeType": r.get("nt") or label,
                    "nodeLabel": r.get("nl") or "",
                    "nodeProperties": {
                        p: v for p, v in zip(properties, vals) if v is not None
                    },
                })
    return out


def get_edges_by_type(
    rel_types: Any,
    sketch_id: Optional[str] = None,
    source_label: Optional[str] = None,
    target_label: Optional[str] = None,
    resolve_endpoints: bool = False,
    per_target_limit: Optional[int] = None,
    group_by_target: bool = False,
    timeout: int = _NEO4J_READ_TIMEOUT,
) -> Any:
    """
    Return edges of the given relationship type(s) within one sketch.

    Edges come back as {id, label, source, target} — `label` mirrors the API's
    naming (Neo4j calls it the relationship type) and source/target are
    elementIds matching get_nodes_by_type() ids.

    source_label / target_label anchor the pattern on a labelled, indexed
    endpoint. Anchoring matters: AD ACE types run to hundreds of thousands of
    relationships each, and seeking (e.g.) :device by sketch_id and expanding
    inward is far cheaper than scanning the relationship type.

    resolve_endpoints additionally returns source_type/source_label and
    target_type/target_label. Use it when an endpoint may fall outside the
    labels you fetched — AD group principals ingest as `organization`, so
    without this they degrade to bare elementIds.

    per_target_limit caps how many edges are kept per target node, applied
    inside Neo4j. Use it when the caller only keeps the first N per node anyway
    (AD ACE types run to hundreds of thousands of edges) so the cap costs one
    aggregation instead of a several-hundred-megabyte transfer.

    group_by_target returns {target_element_id: [edge, ...]} with the target
    field dropped from each edge, and is what makes the AD case affordable:
    843,974 device ACEs are 320 MB as flat rows but ~60 MB grouped, because the
    target id and label stop repeating on every row.

    Relationship sketch scoping is done through the endpoints, not r.sketch_id:
    some edges (HAS_PROFILE, written by the enrichers) carry no properties at
    all, so a property filter would silently match nothing.
    """
    sid = sketch_id or SKETCH_ID
    if isinstance(rel_types, str):
        rel_types = [rel_types]
    if not rel_types:
        return []

    rel_pattern = "|".join(_quote_label(t) for t in rel_types)
    src_pat = f"(a:{_quote_label(source_label)} {{sketch_id: $sid}})" if source_label else "(a)"
    tgt_pat = f"(b:{_quote_label(target_label)} {{sketch_id: $sid}})" if target_label else "(b)"

    where = ["r.deleted_at IS NULL"]
    if not source_label:
        where.append("a.sketch_id = $sid")
    if not target_label:
        where.append("b.sketch_id = $sid")
    where.append("a.deleted_at IS NULL")
    where.append("b.deleted_at IS NULL")

    fields = ["elementId(r) AS eid", "type(r) AS l",
              "elementId(a) AS s", "elementId(b) AS t"]
    if resolve_endpoints:
        fields += ["labels(a)[0] AS stype", "a.nodeLabel AS slabel",
                   "labels(b)[0] AS ttype", "b.nodeLabel AS tlabel"]

    params: Dict[str, Any] = {"sid": sid}
    match = f"MATCH {src_pat}-[r:{rel_pattern}]->{tgt_pat} WHERE {' AND '.join(where)} "

    if group_by_target:
        # Group in Neo4j so the target id/label are sent once per node rather
        # than once per edge, and slice the list in the same aggregation.
        # No edge id here: at AD scale it is ~40 bytes on every one of hundreds of
        # thousands of rows, and adjacency consumers key off the endpoints.
        item = ("{label: type(r), source: elementId(a)"
                + (", source_type: labels(a)[0], source_label: a.nodeLabel" if resolve_endpoints else "")
                + "}")
        slice_ = "[..$lim]" if per_target_limit else ""
        if per_target_limit:
            params["lim"] = int(per_target_limit)
        rows = _neo4j_rows(
            match + f"WITH b, collect({item}){slice_} AS es "
            "RETURN elementId(b) AS tid, es",
            params,
            timeout=timeout,
        )
        return {r["tid"]: r["es"] for r in rows}

    if per_target_limit:
        # Collect per target and slice inside Neo4j, then flatten back to the
        # same row shape so the caller sees an ordinary edge list either way.
        params["lim"] = int(per_target_limit)
        aliases = [f.split(" AS ")[1] for f in fields]
        pairs = ", ".join(f"{a}: {f.split(' AS ')[0]}" for a, f in zip(aliases, fields))
        rows = _neo4j_rows(
            match
            + f"WITH b, collect({{{pairs}}})[..$lim] AS es "
            + "UNWIND es AS e RETURN "
            + ", ".join(f"e.{a} AS {a}" for a in aliases),
            params,
            timeout=timeout,
        )
    else:
        rows = _neo4j_rows(match + "RETURN " + ", ".join(fields), params, timeout=timeout)

    edges = []
    for r in rows:
        edge = {"id": r["eid"], "label": r["l"], "source": r["s"], "target": r["t"]}
        if resolve_endpoints:
            edge.update({
                "source_type": r.get("stype") or "",
                "source_label": r.get("slabel") or "",
                "target_type": r.get("ttype") or "",
                "target_label": r.get("tlabel") or "",
            })
        edges.append(edge)
    return edges


def search_nodes(
    query: str,
    node_type: Optional[str] = None,
    sketch_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Search nodes in the sketch graph by label or property substring.

    Flowsint exposes no sketch-level search endpoint. When Neo4j is reachable
    this matches server-side (index-seeking the sketch first); otherwise it
    falls back to a client-side filter over the full get_graph() result.
    """
    query_l = query.lower()

    if _neo4j_enabled():
        sid = sketch_id or SKETCH_ID
        labels = [node_type] if node_type else [
            r["l"] for r in _neo4j_rows("CALL db.labels() YIELD label AS l RETURN l", {})
        ]
        results = []
        for label in labels:
            try:
                quoted = _quote_label(label)
            except ValueError:
                continue
            rows = _neo4j_rows(
                f"MATCH (n:{quoted} {{sketch_id: $sid}}) WHERE n.deleted_at IS NULL AND ("
                f"toLower(coalesce(n.nodeLabel, '')) CONTAINS $q OR "
                f"any(k IN keys(n) WHERE k STARTS WITH '{_PROP_PREFIX}' "
                f"AND toLower(toString(n[k])) CONTAINS $q)) "
                f"RETURN elementId(n) AS eid, properties(n) AS p",
                {"sid": sid, "q": query_l},
            )
            results.extend(_node_from_props(r["p"] or {}, r["eid"]) for r in rows)
        return results

    graph = get_graph(sketch_id)
    nodes: List[Dict[str, Any]] = graph.get("nodes", [])
    results = []
    for node in nodes:
        label: str = str(node.get("nodeLabel", "")).lower()
        ntype: str = str(node.get("nodeType", "")).lower()
        # Match query against label and any string property in nodeProperties
        node_props = node.get("nodeProperties") or {}
        if isinstance(node_props, dict):
            props = " ".join(str(v) for v in node_props.values() if isinstance(v, str)).lower()
        else:
            props = str(node_props).lower()
        if query_l in label or query_l in props:
            if node_type is None or ntype == node_type.lower():
                results.append(node)
    return results


def get_node_by_id(
    node_id: str,
    sketch_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return a single node by its Flowsint node ID (Neo4j elementId), or None."""
    if _neo4j_enabled():
        rows = _neo4j_rows(
            "MATCH (n) WHERE elementId(n) = $nid AND n.sketch_id = $sid "
            "AND n.deleted_at IS NULL "
            "RETURN elementId(n) AS eid, properties(n) AS p",
            {"nid": node_id, "sid": sketch_id or SKETCH_ID},
        )
        return _node_from_props(rows[0]["p"] or {}, rows[0]["eid"]) if rows else None

    graph = get_graph(sketch_id)
    for node in graph.get("nodes", []):
        if node.get("id") == node_id:
            return node
    return None


def get_neighbors(
    node_id: str,
    sketch_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return all nodes and edges directly connected to a given node.

    Uses get_graph() and filters locally.
    """
    graph = get_graph(sketch_id)
    edges = graph.get("edges", [])
    nodes = {n["id"]: n for n in graph.get("nodes", [])}

    connected_ids = set()
    connected_edges = []
    for edge in edges:
        src = edge.get("source")
        tgt = edge.get("target")
        if src == node_id or tgt == node_id:
            connected_ids.add(src)
            connected_ids.add(tgt)
            connected_edges.append(edge)

    return {
        "center": nodes.get(node_id),
        "neighbors": [nodes[nid] for nid in connected_ids if nid in nodes and nid != node_id],
        "edges": connected_edges,
    }


# ── Node writes ───────────────────────────────────────────────────────────────

def add_node(
    label: str,
    node_type: str,
    properties: Optional[Dict[str, Any]] = None,
    sketch_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a single node in the sketch.

    POST /api/sketches/{id}/nodes/add
    Body: GraphNode  { id, nodeLabel, nodeType, nodeMetadata, nodeProperties }
    Returns the inner node object so callers can read node.get('id').
    """
    payload = {
        "id": None,
        "nodeLabel": label,
        "nodeType": node_type,
        "nodeMetadata": {},
        "nodeProperties": properties or {},
    }
    resp = _session().post(_url("/nodes/add", sketch_id), json=payload)
    resp.raise_for_status()
    data = resp.json()
    return data.get("node", data)


def create_edge(
    source_id: str,
    target_id: str,
    label: str,
    sketch_id: Optional[str] = None,
) -> None:
    """Create a directed edge between two existing nodes by their Flowsint UUIDs."""
    _add_edge(source_id, target_id, label, sketch_id)


def edit_node(
    node_id: str,
    updates: Dict[str, Any],
    sketch_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Patch properties on an existing node.

    PUT /api/sketches/{id}/nodes/edit
    Body: NodeEditInput  { nodeId, updates }
    """
    payload = {"nodeId": node_id, "updates": updates}
    resp = _session().put(_url("/nodes/edit", sketch_id), json=payload)
    resp.raise_for_status()
    return resp.json()


# ── Batch import ──────────────────────────────────────────────────────────────

_IMPORT_CHUNK = 300        # max nodes per import/execute call
# The server rejects an import/execute part over 1024 KB ("Part exceeded maximum
# size"). 300 small AD nodes sit well under that, but a few hundred Nessus
# Vulnerability nodes — each carrying a host_details blob up to ~50 KB — blow past
# it, and a rejected chunk drops every node AND edge in it. So a chunk is now
# capped by BYTES as well as count: whichever limit is hit first ends the chunk.
_IMPORT_MAX_BYTES = 750 * 1024   # node-JSON budget per chunk, headroom under 1024 KB
_EDGE_CHUNK   = 500        # edges per add_edge batch

# Above this many cross-chunk edges, skip the per-edge REST loop (~100 edges/s,
# which times out the n8n runner on large AD graphs) and bulk-write straight to
# Neo4j (~40k edges/s). SharpHound zips routinely exceed a million edges.
_EDGE_BULK_MIN    = 2000
_NEO4J_EDGE_BATCH = 20000  # edges per Neo4j UNWIND CREATE transaction


# ── Direct-Neo4j bulk edge writer ─────────────────────────────────────────────

def _neo4j_enabled() -> bool:
    """True when Neo4j creds are present so the bulk edge fast-path can run."""
    return bool(NEO4J_HTTP_URL and NEO4J_PASSWORD)


def _neo4j_commit(statement: str, parameters: Dict[str, Any], timeout: int = 600) -> Dict[str, Any]:
    """Run one Cypher statement via the Neo4j HTTP transaction endpoint."""
    url = NEO4J_HTTP_URL.rstrip("/") + "/db/neo4j/tx/commit"
    # Bare requests.post (not _session()) so we send HTTP Basic auth and let
    # requests set application/json — the shared session carries a Bearer header.
    resp = requests.post(
        url,
        json={"statements": [{"statement": statement, "parameters": parameters}]},
        auth=(NEO4J_USER, NEO4J_PASSWORD),
        timeout=timeout,
    )
    resp.raise_for_status()
    body = resp.json()
    if body.get("errors"):
        raise RuntimeError(f"Neo4j error: {body['errors']}")
    return body


def _bulk_create_edges_neo4j(
    edges: List[Dict[str, Any]],
    sketch_id: Optional[str],
) -> Dict[str, Any]:
    """
    Create relationships directly in Neo4j in batched UNWIND transactions.

    ~400x faster than the per-edge REST path on large AD graphs. Endpoints are
    resolved SID → Neo4j elementId (SharpHound edges reference nodes by SID,
    stored on nodes as nodeProperties.sid / nodeProperties.device_id). Edges are
    grouped by label because Neo4j relationship types cannot be parameterized.

    Relationship props mirror flowsint-core (sketch_id, rel_label,
    from_element_id, to_element_id) so Flowsint's /graph reads them back, and
    WF07's sketch-scoped purge (MATCH ()-[r {sketch_id}]->()) still finds them.

    Idempotent: pre-existing edges (and intra-run duplicates) are skipped, so a
    partial import can be safely completed by re-running.
    """
    sid = sketch_id or SKETCH_ID

    # 1. SID → elementId for every alive node in the sketch.
    # SharpHound references endpoints by AD SID (nodeProperties.sid) and PingCastle
    # by device_id; a parser whose temp-id is neither (Nessus's nessus:vuln:<id>,
    # EyeWitness's website/ip ids) stamps that temp-id into nodeProperties.import_ref
    # so its cross-chunk edges resolve here too — without overloading `sid`, which
    # would clobber a merged SharpHound node's real AD SID. Purely additive: a node
    # with no import_ref is unaffected.
    body = _neo4j_commit(
        "MATCH (n {sketch_id:$s}) WHERE n.deleted_at IS NULL "
        "RETURN elementId(n) AS eid, n.`nodeProperties.sid` AS sid, "
        "n.`nodeProperties.device_id` AS did, n.`nodeProperties.import_ref` AS ref",
        {"s": sid},
    )
    sid_to_eid: Dict[str, str] = {}
    for row in body["results"][0]["data"]:
        eid, node_sid, node_did, node_ref = row["row"]
        if node_sid:
            sid_to_eid[node_sid] = eid
        if node_did:
            sid_to_eid[node_did] = eid
        if node_ref:
            sid_to_eid[node_ref] = eid
    known_eids = set(sid_to_eid.values())

    # 2. Resolve endpoints and group by relationship label.
    by_label: Dict[str, List[tuple]] = {}
    skipped = 0
    for e in edges:
        from_ref = e.get("from_id", "")
        to_ref   = e.get("to_id", "")
        f = from_ref if from_ref in known_eids else sid_to_eid.get(from_ref)
        t = to_ref if to_ref in known_eids else sid_to_eid.get(to_ref)
        if not f or not t:
            skipped += 1
            continue
        by_label.setdefault(e.get("label") or "RELATED_TO", []).append((f, t))

    # 3. Existing edges for this sketch → dedup key (from_eid, to_eid, type).
    ex_body = _neo4j_commit(
        "MATCH (a)-[r]->(b) WHERE r.sketch_id=$s "
        "RETURN elementId(a) AS f, elementId(b) AS t, type(r) AS ty",
        {"s": sid},
    )
    existing = {
        (row["row"][0], row["row"][1], row["row"][2])
        for row in ex_body["results"][0]["data"]
    }

    # 4. CREATE per label in batches (elementId match → no index scan needed).
    created = 0
    errors: List[str] = []
    for label, pairs in by_label.items():
        rel_type = label.replace("`", "")  # backtick-safe Neo4j relationship type
        # dedup within this run AND against pre-existing edges
        rows = [
            {"f": f, "t": t}
            for (f, t) in set(pairs)
            if (f, t, rel_type) not in existing
        ]
        query = (
            "UNWIND $rows AS row "
            "MATCH (a) WHERE elementId(a)=row.f "
            "MATCH (b) WHERE elementId(b)=row.t "
            f"CREATE (a)-[r:`{rel_type}`]->(b) "
            "SET r.sketch_id=$s, r.rel_label=$lbl, "
            "r.from_element_id=row.f, r.to_element_id=row.t"
        )
        for i in range(0, len(rows), _NEO4J_EDGE_BATCH):
            chunk = rows[i : i + _NEO4J_EDGE_BATCH]
            try:
                _neo4j_commit(query, {"rows": chunk, "s": sid, "lbl": label})
                created += len(chunk)
            except Exception as exc:
                errors.append(
                    f"Neo4j edge batch ({label} {i}-{i + len(chunk)}) failed: {exc}"
                )

    if skipped:
        errors.append(f"{skipped} edges skipped — endpoint SID not in graph")
    return {"edges_created": created, "errors": errors}


def _import_execute(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    sketch_id: Optional[str],
) -> Dict[str, Any]:
    """Single import/execute call. Payload must be < ~1 MB."""
    payload = json.dumps({"nodes": nodes, "edges": edges})
    # Flowsint expects multipart/form-data with field entity_mappings_json.
    # The session has Content-Type: application/json; we must clear it so
    # requests can set the multipart boundary header instead.
    resp = _session().post(
        _url("/import/execute", sketch_id),
        files={"entity_mappings_json": (None, payload, "text/plain")},
        headers={"Content-Type": None},
    )
    # Surface the server's rejection reason — raise_for_status() discards the body,
    # which made import failures opaque (HTTP 400 with no diagnosable detail).
    if resp.status_code >= 400:
        raise RuntimeError(f"import/execute HTTP {resp.status_code}: {resp.text[:600]}")
    return resp.json()


def _add_edge(
    source_id: str,
    target_id: str,
    label: str,
    sketch_id: Optional[str],
) -> None:
    """Create one edge via POST /api/sketches/{id}/relations/add."""
    resp = _session().post(
        _url("/relations/add", sketch_id),
        json={"source": source_id, "target": target_id, "label": label, "type": "one-way"},
    )
    resp.raise_for_status()


def _size_chunks(nodes: List[Dict[str, Any]]) -> "Iterator[List[Dict[str, Any]]]":
    """
    Yield node chunks bounded by BOTH _IMPORT_CHUNK (count) and _IMPORT_MAX_BYTES
    (serialized size), whichever is reached first.

    A fixed node count assumes every node is small; a Nessus Vulnerability node can
    be ~50 KB (its host_details blob), so a few hundred of them exceed the server's
    1024 KB part limit and the whole chunk is rejected. A single node larger than
    the budget still ships alone (it is far under 1024 KB on its own).
    """
    chunk: List[Dict[str, Any]] = []
    size = 0
    for node in nodes:
        nb = len(json.dumps(node))
        if chunk and (len(chunk) >= _IMPORT_CHUNK or size + nb > _IMPORT_MAX_BYTES):
            yield chunk
            chunk, size = [], 0
        chunk.append(node)
        size += nb
    if chunk:
        yield chunk


def batch_import(
    nodes: List[Dict[str, Any]],
    edges: Optional[List[Dict[str, Any]]] = None,
    sketch_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Bulk-create nodes and edges, splitting large payloads automatically.

    Nodes are imported in chunks of _IMPORT_CHUNK to stay under the server's
    ~1 MB form-field limit.  Edges that reference nodes already in the graph
    (from a prior call or a previous import) are created after all nodes are
    imported by resolving SID → Flowsint UUID via the graph API.

    Each node dict must have at minimum:
      { "id": "<temp-id>", "node_id": "<temp-id>", "entity_type": "...",
        "nodeLabel": "...", "data": {...}, "include": True }

    Edge dicts:
      { "from_id": "<temp-id>", "to_id": "<temp-id>", "label": "MEMBER_OF" }

    Returns { status, nodes_created, nodes_skipped, edges_created, errors }
    """
    edges = edges or []

    # Strict edge schema: callers must use from_id/to_id. Accepting source/target
    # silently caused dropped relationships and hard-to-debug partial imports.
    for idx, edge in enumerate(edges):
        if not isinstance(edge, dict):
            raise ValueError(f"Edge at index {idx} must be a dict, got {type(edge).__name__}")

        has_from_to = ("from_id" in edge) or ("to_id" in edge)
        has_source_target = ("source" in edge) or ("target" in edge)

        if has_source_target and not has_from_to:
            raise ValueError(
                "Invalid edge schema at index "
                f"{idx}: use from_id/to_id (source/target is not supported)"
            )

        src = edge.get("from_id")
        tgt = edge.get("to_id")
        if not src or not tgt:
            raise ValueError(
                f"Invalid edge schema at index {idx}: both from_id and to_id are required"
            )

    total_nodes_created = 0
    total_nodes_skipped = 0
    all_errors: List[str] = []

    # ── 1. Import nodes in chunks, bundling co-located edges ──────────────────
    # For each chunk of nodes, also bundle any edge whose BOTH endpoints are in
    # that chunk (avoids a second pass for the common same-chunk case). Chunks are
    # bounded by both node count and serialized byte size (see _IMPORT_MAX_BYTES).
    remaining_edges = list(edges)

    for chunk in _size_chunks(nodes):
        chunk_sids = {n.get("node_id") for n in chunk}
        in_chunk: List[Dict[str, Any]] = []
        still_remaining: List[Dict[str, Any]] = []
        for e in remaining_edges:
            if e.get("from_id") in chunk_sids and e.get("to_id") in chunk_sids:
                in_chunk.append(e)
            else:
                still_remaining.append(e)
        remaining_edges = still_remaining

        # A single chunk's rejection must NOT abort the whole ingest (previously an
        # unguarded raise here meant one HTTP 400 dropped every remaining node/edge,
        # leaving a freshly-cleared graph empty and silent). Record and continue;
        # push this chunk's edges back so they can still be created via SID resolution.
        try:
            result = _import_execute(chunk, in_chunk, sketch_id)
            total_nodes_created += result.get("nodes_created", 0)
            total_nodes_skipped += result.get("nodes_skipped", 0)
            all_errors.extend(result.get("errors", []))
        except Exception as exc:
            labels = ", ".join(sorted({str(n.get("nodeLabel", ""))[:40] for n in chunk[:3]}))
            all_errors.append(
                f"Node chunk of {len(chunk)} import failed (e.g. {labels}): {exc}")
            remaining_edges.extend(in_chunk)

    # ── 2. Cross-chunk edges ──────────────────────────────────────────────────
    edges_created = 0
    _MAX_WORKERS = 32   # parallel threads for edge creation

    # Fast path: bulk-write straight to Neo4j. The per-edge REST loop below runs
    # at ~100 edges/s and times out the n8n runner on large AD graphs (a 2M-edge
    # SharpHound zip needs >5 h); the bulk path does the same at ~40k edges/s.
    if remaining_edges and _neo4j_enabled() and len(remaining_edges) >= _EDGE_BULK_MIN:
        bulk = _bulk_create_edges_neo4j(remaining_edges, sketch_id)
        edges_created += bulk["edges_created"]
        all_errors.extend(bulk["errors"])
        remaining_edges = []

    # ── 2b. REST fallback: resolve SIDs → Flowsint UUIDs via graph API ────────
    if remaining_edges:
        _graph_cache.clear()
        graph = get_graph(sketch_id)
        nds = graph.get("nodes", [])  # get_graph() normalizes nds→nodes
        known_node_ids = {n.get("id") for n in nds if n.get("id")}
        # Build SID → flowsint_uuid from nodeProperties.sid / device_id / import_ref
        # (import_ref is the neutral cross-chunk key non-SID parsers stamp — see
        # _bulk_create_edges_neo4j).
        sid_to_id: Dict[str, str] = {}
        for n in nds:
            props = n.get("nodeProperties", {})
            sid = props.get("sid") or props.get("device_id") or props.get("import_ref")
            if sid:
                sid_to_id[sid] = n["id"]

        # Resolve and partition into creatable vs unresolvable
        to_create = []
        for e in remaining_edges:
            src_ref = e.get("from_id", "")
            tgt_ref = e.get("to_id", "")

            src_uuid = src_ref if src_ref in known_node_ids else sid_to_id.get(src_ref)
            tgt_uuid = tgt_ref if tgt_ref in known_node_ids else sid_to_id.get(tgt_ref)

            if not src_uuid or not tgt_uuid:
                all_errors.append(
                    f"Edge skipped — SID not found: {e.get('from_id')} → {e.get('to_id')}"
                )
            else:
                to_create.append((src_uuid, tgt_uuid, e.get("label", "RELATED_TO")))

        # Create edges in parallel using a thread pool
        def _create(args: tuple) -> Optional[str]:
            src, tgt, lbl = args
            try:
                _add_edge(src, tgt, lbl, sketch_id)
                return None
            except Exception as exc:
                return str(exc)

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {pool.submit(_create, args): args for args in to_create}
            for future in as_completed(futures):
                err = future.result()
                if err:
                    all_errors.append(f"Edge create failed: {err}")
                else:
                    edges_created += 1

    status = "completed" if not all_errors else "completed_with_errors"
    return {
        "status":          status,
        "nodes_created":   total_nodes_created,
        "nodes_skipped":   total_nodes_skipped,
        "edges_created":   edges_created,
        "errors":          all_errors[:50],
    }


# ── Delete nodes / relationships ─────────────────────────────────────────────

def delete_nodes(
    node_ids: List[str],
    sketch_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Remove nodes by ID list from the sketch.

    DELETE /api/sketches/{id}/nodes
    Body: {"nodeIds": ["<node_id>", ...]}

    The key is nodeIds, not ids: the API validates the body with a Pydantic model
    and answers a plain "ids" with 422 {"loc": ["body","nodeIds"], "missing"} --
    which clear_sketch swallowed into its errors list, so a caller saw a
    deleted_nodes count equal to what it MEANT to delete and nothing removed.
    """
    resp = _session().delete(
        _url("/nodes", sketch_id),
        json={"nodeIds": node_ids},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json() if resp.text.strip() else {}


def delete_relationships(
    rel_ids: List[str],
    sketch_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Remove relationships by ID list from the sketch.

    DELETE /api/sketches/{id}/relationships
    Body: {"relationshipIds": ["<rel_id>", ...]}

    relationshipIds, not ids -- same 422 trap as delete_nodes above.
    """
    resp = _session().delete(
        _url("/relationships", sketch_id),
        json={"relationshipIds": rel_ids},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json() if resp.text.strip() else {}


def clear_sketch(sketch_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Delete every node and relationship in the sketch.

    Deletes relationships first (avoids orphan edge errors), then nodes.
    Returns {"deleted_nodes": N, "deleted_relationships": M, "errors": []}.
    """
    graph = get_graph(sketch_id)
    nds = graph.get("nodes", [])
    rls = graph.get("edges", [])

    node_ids = [n["id"] for n in nds if n.get("id")]
    rel_ids  = [r["id"] for r in rls if r.get("id")]

    errors = []

    if rel_ids:
        try:
            delete_relationships(rel_ids, sketch_id)
        except Exception as exc:
            errors.append(f"delete_relationships: {exc}")

    if node_ids:
        try:
            delete_nodes(node_ids, sketch_id)
        except Exception as exc:
            errors.append(f"delete_nodes: {exc}")

    # Invalidate the graph cache so subsequent reads see the empty sketch
    _graph_cache.clear()

    return {
        "deleted_nodes":         len(node_ids),
        "deleted_relationships": len(rel_ids),
        "errors":                errors,
    }


# ── Convenience: upsert Individual ────────────────────────────────────────────

def upsert_individual(
    name: str,
    properties: Dict[str, Any],
    dedup_field: str = "username",
    sketch_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Find an existing Individual node by dedup_field value or create a new one.

    Returns the node dict from Flowsint (includes its 'id' for relationship creation).
    """
    dedup_value = properties.get(dedup_field, "")
    if dedup_value:
        existing = search_nodes(dedup_value, node_type="Individual", sketch_id=sketch_id)
        for node in existing:
            node_props = node.get("nodeProperties") or node.get("data") or {}
            if str(node_props.get(dedup_field, "")).lower() == str(dedup_value).lower():
                # Node exists — patch any new properties
                edit_node(node["id"], properties, sketch_id=sketch_id)
                return node

    # Create new
    return add_node(
        label=name,
        node_type="Individual",
        properties=properties,
        sketch_id=sketch_id,
    )


# ── Enricher trigger ──────────────────────────────────────────────────────────

def trigger_enricher(
    flow_id: str,
    entity_ids: List[str],
    sketch_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Trigger a Flowsint enricher flow against a list of entity node IDs.

    POST /api/flows/{flow_id}/run
    (See flowsint-api/app/api/routes/flows.py)
    """
    sid = sketch_id or SKETCH_ID
    payload = {
        "sketch_id": sid,
        "entities": [{"id": eid} for eid in entity_ids],
    }
    resp = _session().post(f"{API_URL}/api/flows/{flow_id}/run", json=payload)
    resp.raise_for_status()
    return resp.json()


# ── Type registry ─────────────────────────────────────────────────────────────

def registered_custom_types() -> List[str]:
    """
    Names of the published custom node types this API key can resolve.

    Importing a node whose entity_type is not resolvable does not fail that node
    in isolation: the graph serializer raises with no per-node guard, so
    GET /api/sketches/{id}/graph then returns HTTP 500 for the whole sketch.
    Callers that emit custom types (PingCastle → ADRisk) check here first and
    drop those nodes rather than take a campaign's graph offline.

    Returns [] if the registry cannot be read, so callers fail closed.
    """
    try:
        resp = _session().get(f"{API_URL}/api/custom-types", timeout=30)
        resp.raise_for_status()
        body = resp.json()
    except Exception:
        return []
    if not isinstance(body, list):
        return []
    return [
        t["name"]
        for t in body
        if isinstance(t, dict) and t.get("name") and t.get("status") == "published"
    ]


def is_type_registered(type_name: str) -> bool:
    """True if `type_name` is a built-in or published custom Flowsint type."""
    builtin = {
        "individual", "organization", "device", "domain", "ip", "email", "phone",
        "username", "website", "credential", "session", "technology", "service",
        "file", "document", "breach", "leak", "malware", "address", "asn", "cidr",
        "dns_record", "port", "social_account", "ssl_certificate", "phrase",
    }
    name = (type_name or "").strip()
    if name.lower() in builtin:
        return True
    return any(name.lower() == t.lower() for t in registered_custom_types())


# ── Investigations & sketch provisioning ──────────────────────────────────────

def list_campaigns() -> List[Dict[str, Any]]:
    """
    Read the shared campaign registry.

    SPOTTER keeps it in one global Neo4j node, (:SpotterMeta {key:'campaigns'}),
    holding a JSON array in `data` — the same record WF17/WF18 read and write.
    It deliberately carries no sketch_id so it is visible to every campaign, and
    WF07's orphan sweep excludes :SpotterMeta so it is never purged.

    Returns [] when Neo4j is unreachable or the registry has not been written.
    """
    if not _neo4j_enabled():
        return []
    try:
        rows = _neo4j_rows(
            "MATCH (m:SpotterMeta {key:'campaigns'}) RETURN m.data AS data LIMIT 1", {}
        )
    except Exception:
        return []
    if not rows:
        return []
    try:
        camps = json.loads(rows[0].get("data") or "[]")
    except Exception:
        return []
    return camps if isinstance(camps, list) else []


def resolve_campaign_sketch(explicit: str = "") -> str:
    """
    Best sketch id for a workflow that has no request body to read one from.

    Schedule- and push-triggered workflows (WF01's 5-minute sweep, WF02's drop
    folder, WF21's C2 callback) cannot be handed a sketch_id the way a webhook
    from the UI can, so they used to fall straight back to FLOWSINT_SKETCH_ID.
    That env value points at a throwaway default sketch by design, so everything
    they ingested landed somewhere no campaign ever reads — silently, because
    writing to an empty sketch succeeds.

    Resolution order:
      1. `explicit` — a sketch id the caller genuinely received.
      2. Most recently created campaign in the shared registry that has a
         sketchId. This mirrors the frontend's own auto-adopt rule in
         syncCampaignsOnBoot(), so a headless run lands on the same campaign a
         fresh operator's browser would.
      3. FLOWSINT_SKETCH_ID.

    There is intentionally no server-side "active campaign": operators may each
    be viewing a different one, so most-recent is the only shared answer.
    """
    if explicit:
        return explicit
    try:
        camps = [c for c in list_campaigns()
                 if isinstance(c, dict) and c.get("sketchId")]
    except Exception:
        camps = []
    if camps:
        camps.sort(key=lambda c: str(c.get("created") or ""), reverse=True)
        return camps[0]["sketchId"]
    return SKETCH_ID


def list_investigations() -> List[Dict[str, Any]]:
    resp = _session().get(f"{API_URL}/api/investigations")
    resp.raise_for_status()
    return resp.json()


def list_sketches() -> List[Dict[str, Any]]:
    resp = _session().get(f"{API_URL}/api/sketches")
    resp.raise_for_status()
    return resp.json()


def create_investigation(name: str, description: str = "") -> Dict[str, Any]:
    """
    Create an investigation (the container that groups per-campaign sketches).

    POST /api/investigations/create  Body: {name, description} → {id, ...}
    Mirrors scripts/create_flowsint_investigation_and_sketch.sh.
    """
    resp = _session().post(
        f"{API_URL}/api/investigations/create",
        json={"name": name, "description": description},
    )
    resp.raise_for_status()
    return resp.json()


def create_sketch(
    title: str,
    investigation_id: str,
    description: str = "",
) -> Dict[str, Any]:
    """
    Create a new sketch (one per SPOTTER campaign) inside an investigation.

    POST /api/sketches/create  Body: {title, description, investigation_id} → {id, ...}
    Returns the created sketch object; caller reads sketch['id'].
    """
    resp = _session().post(
        f"{API_URL}/api/sketches/create",
        json={
            "title": title,
            "description": description,
            "investigation_id": investigation_id,
        },
    )
    resp.raise_for_status()
    return resp.json()


def delete_sketch(sketch_id: str) -> Dict[str, Any]:
    """
    Permanently delete a sketch and its contents (used when a campaign is deleted).

    DELETE /api/sketches/{id}
    Note: the Flowsint delete may leave Neo4j orphans (see clear-graph workflow);
    callers that need a durable wipe should also issue a sketch-scoped Neo4j
    DETACH DELETE. Every Neo4j node/relationship carries a `sketch_id` property,
    so `MATCH (n {sketch_id:$sid}) DETACH DELETE n` cleanly scopes the purge.
    """
    resp = _session().delete(f"{API_URL}/api/sketches/{sketch_id}", timeout=60)
    resp.raise_for_status()
    return resp.json() if resp.text.strip() else {}
