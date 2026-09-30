"""Individual identifier resolution — the one contract.

Consumers, which must not grow a private CONTAINS chain:

  n8n-workflows/05-dossier-exporter.json   Fetch Full Graph, Compile Dossier
  n8n-workflows/08-llm-query-gateway.json  get_dossier, get_attack_paths
  llm/tools/dossier_tool.py
  llm/tools/attack_path_tool.py
  llm/tools/technology_tool.py

Normalization is strip + lower, not str.casefold(). Cypher only has toLower(),
and the in-memory predicate has to agree with the query or a hit in one path
is a miss in the other. 'ß'.casefold() is 'ss'; toLower('ß') is not, so a
casefold() here would resolve names the graph query cannot.

Match is case-insensitive CONTAINS on nodeLabel, label, display_name,
full_name, sid, sam_account_name, username, email, and email_addresses, plus
case-insensitive equality on the node id (elementId). display_name is required
because sharphound_parser labels AD principals SAM@DOMAIN.LOCAL and puts the
human name in display_name — a click carrying that name otherwise resolves
nothing.

email_addresses is a list in the Flowsint schema and a string in some writers.
Cypher uses toString so toLower() is never applied to a list. The in-memory
matcher walks a list and a dict item's address/email/value.

Tie-break: shortest label, then label, LIMIT 1. Sketch scope and
deleted_at IS NULL are part of the clause. An empty query matches nothing.
Each caller's not-found envelope stays its own.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Optional, Sequence


IDENTIFIER_FIELDS: Sequence[str] = (
    "nodeLabel",
    "label",
    "display_name",
    "full_name",
    "sid",
    "sam_account_name",
    "username",
    "email",
    "email_addresses",
)

# Nested props only. nodeLabel is a top-level property, not nodeProperties.*.
_PROP_FIELDS: Sequence[str] = tuple(f for f in IDENTIFIER_FIELDS if f != "nodeLabel")


def normalize_identifier(raw: Any) -> str:
    """Strip + lower. See the module docstring for why this is not Unicode case folding."""
    return str(raw or "").strip().lower()


def _prop_expr(var: str, field: str) -> str:
    if field == "nodeLabel":
        return f"{var}.nodeLabel"
    return f"{var}['nodeProperties.{field}']"


def individual_match_predicate(var: str = "u", param: str = "$q") -> str:
    """Parenthesized OR predicate. ``param`` is a Cypher parameter reference."""
    parts: List[str] = []
    for field in IDENTIFIER_FIELDS:
        expr = _prop_expr(var, field)
        if field == "email_addresses":
            parts.append(f"toLower(coalesce(toString({expr}), '')) CONTAINS {param}")
        else:
            parts.append(f"toLower(coalesce({expr}, '')) CONTAINS {param}")
    parts.append(f"toLower(elementId({var})) = {param}")
    return "(" + " OR ".join(parts) + ")"


def individual_resolve_query(
    *,
    var: str = "u",
    sketch_param: str = "$sketch_id",
    q_param: str = "$q",
    label_expr: Optional[str] = None,
    return_clause: str,
) -> str:
    """One MATCH. Caller supplies the RETURN list and the parameter names.

    ``return_clause`` must not include ORDER BY — the tie-break is appended.
    ``label`` is bound for that ORDER BY and may be selected by the RETURN.
    Pass an already-normalized query as ``q_param``. An empty query matches
    nothing (``$q <> ''``), matching identifier_matches().
    """
    if not return_clause or not str(return_clause).strip():
        raise ValueError("return_clause is required")
    label_expr = label_expr or (
        f"coalesce({var}.nodeLabel, {var}['nodeProperties.label'], '')"
    )
    pred = individual_match_predicate(var, q_param)
    return (
        f"MATCH ({var}:individual) WHERE {var}.sketch_id = {sketch_param} "
        f"AND {var}.deleted_at IS NULL AND {q_param} <> '' AND {pred} "
        f"WITH {var}, {label_expr} AS label "
        f"{return_clause.strip()} "
        f"ORDER BY size(label) ASC, label ASC LIMIT 1"
    )


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(_as_text(v) for v in value)
    if isinstance(value, dict):
        bits = [value.get("address"), value.get("email"), value.get("value")]
        return " ".join(str(b) for b in bits if b)
    return str(value)


def identifier_matches(node_label: Any, props: Any, node_id: Any, query: Any) -> bool:
    """Same predicate as the Cypher clause, for an already-fetched node.

    ``props`` is the nested nodeProperties dict, not Neo4j's flat dotted keys.
    Node id is equality, not CONTAINS, so a short query cannot hit a substring
    of an elementId.
    """
    q = normalize_identifier(query)
    if not q:
        return False
    if node_id is not None and q == normalize_identifier(node_id):
        return True
    props = props or {}
    hay = [node_label or ""]
    for field in _PROP_FIELDS:
        hay.append(_as_text(props.get(field)))
    blob = " ".join(str(x) for x in hay if x).lower()
    return q in blob


def tiebreak_label(node_label: Any, props: Any) -> str:
    props = props or {}
    return str(node_label or props.get("label") or "")


def best_individual_match(nodes: Iterable[dict], query: Any) -> Optional[dict]:
    """Shortest label, then label. None when the query is empty or nothing hits.

    Only nodes whose nodeType is ``individual`` (any case) are considered.
    Use this when the subject has not already been chosen. A neighbourhood that
    starts with the Cypher-selected subject should take the first
    identifier_matches() hit instead — a shorter-label neighbour must not
    steal the dossier.
    """
    q = normalize_identifier(query)
    if not q:
        return None
    hits: List[dict] = []
    for node in nodes or []:
        if str((node or {}).get("nodeType") or "").lower() != "individual":
            continue
        props = node.get("nodeProperties") or {}
        if identifier_matches(node.get("nodeLabel"), props, node.get("id"), q):
            hits.append(node)
    if not hits:
        return None
    hits.sort(key=lambda n: (
        len(tiebreak_label(n.get("nodeLabel"), n.get("nodeProperties"))),
        tiebreak_label(n.get("nodeLabel"), n.get("nodeProperties")).lower(),
    ))
    return hits[0]
