#!/usr/bin/env python3
"""Offline tests for the shared individual-identifier contract.

Covers label, display name, SID, username, string email, and list
email_addresses, plus strip/lower (not casefold), node-id equality, and the
shortest-label tie-break. No Neo4j.

    python3 scripts/smoke_individual_lookup.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import individual_lookup as il


failures = 0
checks = 0


def ok(cond, label, extra=None):
    global failures, checks
    checks += 1
    if cond:
        print(f"  ok    {label}")
        return
    failures += 1
    tail = "" if extra is None else f"\n        got: {extra!r}"
    print(f"  FAIL  {label}{tail}")


def node(label, props, node_id="4:abc:1", node_type="individual"):
    return {
        "id": node_id,
        "nodeType": node_type,
        "nodeLabel": label,
        "nodeProperties": props,
    }


def section(title):
    print(f"\n── {title}")


section("normalization agrees with toLower, not casefold")
ok(il.normalize_identifier("  Alice  ") == "alice", "strip + lower")
ok(il.normalize_identifier("Straße") == "straße", "does not expand ß the way casefold does",
   il.normalize_identifier("Straße"))
ok("casefold" not in Path(il.__file__).read_text().split('"""', 2)[-1],
   "the implementation does not call casefold")
ok(il.normalize_identifier(None) == "", "None is an empty query")
ok(il.identifier_matches("Alice", {}, "4:abc:1", "   ") is False,
   "a whitespace query matches nothing")

section("the five forms, plus the list email the schema actually stores")
ok(il.identifier_matches("alice@CORP.LOCAL", {}, "4:abc:1", "ALICE@corp.local"),
   "label, case-insensitive")
ok(il.identifier_matches("ASMITH@CORP.LOCAL", {"display_name": "Alice Smith"}, "4:abc:1", "alice smith"),
   "display name")
ok(il.identifier_matches("ASMITH@CORP.LOCAL", {"sid": "S-1-5-21-1001"}, "4:abc:1", "s-1-5-21-1001"),
   "SID")
ok(il.identifier_matches("ASMITH@CORP.LOCAL", {"username": "asmith"}, "4:abc:1", "asmith"),
   "username")
ok(il.identifier_matches("ASMITH@CORP.LOCAL", {"sam_account_name": "asmith"}, "4:abc:1", "asmith"),
   "sam_account_name")
ok(il.identifier_matches("ASMITH@CORP.LOCAL", {"email": "Alice@Corp.local"}, "4:abc:1", "alice@corp.local"),
   "string email")
ok(il.identifier_matches(
    "ASMITH@CORP.LOCAL",
    {"email_addresses": ["other@corp.local", "alice@corp.local"]},
    "4:abc:1", "alice@corp.local"),
   "email_addresses list")
ok(il.identifier_matches(
    "ASMITH@CORP.LOCAL",
    {"email_addresses": [{"address": "alice@corp.local"}]},
    "4:abc:1", "alice@corp.local"),
   "email_addresses list of address dicts")
ok(il.identifier_matches("bob", {}, "4:AbC:9", "4:abc:9"),
   "node id is case-insensitive equality")
ok(il.identifier_matches("bob", {}, "4:abc:9", "abc") is False,
   "node id is not a substring match", )

section("shortest label wins, and only individuals are considered")
longer = node("Alice Smith", {"display_name": "Alice Smith"}, "4:long:1")
shorter = node("Alice", {"display_name": "Alice"}, "4:short:1")
device = node("Alice", {}, "4:dev:1", node_type="device")
picked = il.best_individual_match([longer, device, shorter], "alice")
ok(picked is shorter, "shortest label wins over first-hit and over a device",
   None if picked is None else picked.get("id"))
ok(il.best_individual_match([longer], "") is None, "empty query does not match everyone")
ok(il.best_individual_match([longer], "nobody") is None, "a miss is None")

section("the Cypher clause is the same predicate")
q = il.individual_resolve_query(
    var="n",
    sketch_param="$sid",
    return_clause="RETURN elementId(n) AS eid, properties(n) AS p",
)
for field in il.IDENTIFIER_FIELDS:
    ok(field in q, f"query mentions {field}")
ok("toLower(coalesce(toString(n['nodeProperties.email_addresses']), '')) CONTAINS $q" in q,
   "email_addresses is toString'd before toLower")
ok("toLower(elementId(n)) = $q" in q, "node id is equality on toLower(elementId)")
ok("elementId(n) = $qraw" not in q, "raw elementId compare is gone")
ok("CONTAINS $q" in q and "toLower(elementId(n)) CONTAINS" not in q,
   "elementId is not a CONTAINS")
ok("n.sketch_id = $sid" in q and "n.deleted_at IS NULL" in q, "sketch scope and deleted_at")
ok("$q <> ''" in q, "an empty query matches nothing in Cypher too")
ok("ORDER BY size(label) ASC, label ASC LIMIT 1" in q, "shortest-label tie-break")
ok(q.index("WITH n,") < q.index("RETURN") < q.index("ORDER BY"),
   "WITH, then the caller's RETURN, then the tie-break")

try:
    il.individual_resolve_query(return_clause="  ")
    ok(False, "a blank RETURN is rejected")
except ValueError:
    ok(True, "a blank RETURN is rejected")

print(f"\n{'FAILED' if failures else 'PASSED'} — {checks - failures}/{checks} checks")
sys.exit(1 if failures else 0)
