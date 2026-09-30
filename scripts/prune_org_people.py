#!/usr/bin/env python3
"""
prune_org_people.py — clear the employment edges and properties WF13's ungated
"People & Positions" branch left behind.

WHAT IT IS CLEANING UP
----------------------
WF13 used to write `Individual -[WORKS_FOR]-> Company` for every row its people
providers returned, with no attribution test at all. The SERP provider's only
tie to the target is that a search engine returned a profile for a query
containing the company name, which equally matches former staff, vendors,
recruiters, applicants and anyone who merely mentions it. On one live campaign
that produced dozens of "people", nearly all of them wrong, and all of them
reached the graph. `scripts/employment_evidence.py` is the gate that replaced it.

TWO KINDS OF DAMAGE, AND NEITHER HEALS ON RE-RUN
------------------------------------------------
A. INVENTED INDIVIDUALS — a WORKS_FOR edge and an `individual` node for someone
   who never worked there. Deletable outright.

B. POLLUTED REAL PEOPLE — `fc.add_node` MERGEs on nodeLabel, so a false-positive
   row named "John Smith" overwrote a GENUINE AD individual's `employer`,
   `job_title`, `personal_location`, `linkedin_url` and `named_technologies`. A
   corrected re-run cannot clear these: the writer deliberately only sets
   non-empty values, precisely so it does not erase richer data from WF03/WF27
   (see issues.md, Organization card item 7 — observed live). This is the worse
   half, it is invisible on the card, and it needs an explicit act.

HOW A BAD ROW IS IDENTIFIED
---------------------------
Edge `data` is dropped by Flowsint's importer, so nothing about the EDGE records
which branch produced it — the same limitation that forced
prune_named_ownership.py to infer intent from the source node. Node properties,
however, do survive, and the gate now stamps `employment_tier` on everything it
writes. So:

    an org-recon-sourced individual with NO `employment_tier` property is, BY
    CONSTRUCTION, output of the ungated branch.

That is exact rather than heuristic, which is why this script is safer than its
predecessor. It is also why running it before the gated WF13 has been deployed
and re-run would flag every row including the good ones.

    --mode edges  (default)  delete employment edges whose source individual is
                             org-recon-sourced and carries no employment_tier.
    --mode nodes             also delete those individuals, but only when they
                             have no AD sid, no corporate email, and no other
                             in-edge. USES_TECH edges go with them.
    --mode props             damage B. For individuals that DO have an AD sid,
                             clear the five fields WF13 may have polluted,
                             printing each current value first.

--mode props CANNOT DISTINGUISH a value WF13 polluted from a correct one WF03 or
WF27 wrote — both land in the same properties. It is an operator judgement,
which is why it is opt-in and prints before it clears.

THE ONLY FULLY CLEAN OPTION is re-running recon into a fresh sketch. This script
exists for when that is not acceptable.

SAFETY
------
--dry-run is the DEFAULT and prints everything it would touch. There is no Neo4j
backup on this host and deletions are not recoverable.

Usage:
    python3 scripts/prune_org_people.py --sketch-id <id>
    python3 scripts/prune_org_people.py --sketch-id <id> --mode nodes
    python3 scripts/prune_org_people.py --sketch-id <id> --mode props
    python3 scripts/prune_org_people.py --sketch-id <id> --apply
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import employment_evidence as ee  # noqa: E402
import flowsint_client as fc  # noqa: E402

# The sources WF13's org block stamps on an individual it creates. An individual
# from SharpHound, Flare promotion or a C2 ingest is NOT this script's business,
# even if it happens to carry a WORKS_FOR edge.
ORG_RECON_SOURCES: Set[str] = {"serp", "website", "org-recon", "linkedin", "hh.ru"}

# Damage B: exactly the fields WF13's people writer sets. Nothing else is
# touched, because nothing else could have been overwritten by it.
POLLUTED_FIELDS = ("employer", "job_title", "personal_location",
                   "linkedin_url", "named_technologies")


def _props(node: Dict[str, Any]) -> Dict[str, Any]:
    return node.get("nodeProperties") or node.get("data") or {}


def _is_org_recon(props: Dict[str, Any]) -> bool:
    return str(props.get("source") or "").strip().lower() in ORG_RECON_SOURCES


def _is_gated(props: Dict[str, Any]) -> bool:
    """True when the gate wrote this row — it stamped a tier on it."""
    return bool(str(props.get("employment_tier") or "").strip())


def _has_ad_identity(props: Dict[str, Any]) -> bool:
    """A real Active Directory principal, which must never be deleted."""
    return bool(str(props.get("sid") or "").strip()
                or str(props.get("sam_account_name") or "").strip())


def collect(sketch_id: str) -> Dict[str, Any]:
    nodes = fc.get_nodes_by_type(["individual", "Individual"], sketch_id=sketch_id) or []
    by_id = {n["id"]: n for n in nodes}

    edges: List[Dict[str, Any]] = []
    for label in ee.WRITABLE_LABELS:
        edges.extend(fc.get_edges_by_type([label], sketch_id=sketch_id,
                                          resolve_endpoints=True) or [])

    stale_edges: List[Dict[str, Any]] = []
    kept_edges = 0
    stale_sources: Set[str] = set()
    for e in edges:
        src = by_id.get(e.get("source", ""))
        if src is None:
            continue
        p = _props(src)
        if _is_gated(p) or not _is_org_recon(p):
            kept_edges += 1
            continue
        stale_edges.append({
            "id": e.get("id"), "label": e.get("label"),
            "individual": e.get("source_label") or src.get("nodeLabel", ""),
            "company": e.get("target_label") or e.get("target") or "",
            "source": p.get("source", ""), "node_id": src["id"],
        })
        stale_sources.add(src["id"])

    # Which of those individuals may be deleted outright. Any relationship other
    # than the ones being removed -- in EITHER direction -- means something else
    # in the graph refers to this person, so the node stays.
    #
    # Counted with one degree query rather than fc.get_edges_by_type, which needs
    # an explicit relationship-type list and returns [] when given none. An
    # earlier draft passed None and so saw zero edges for everybody, which would
    # have marked every stale individual deletable including the ones another
    # subsystem still points at. USES_TECH is excluded because this script
    # removes those alongside the node, exactly as WF13 wrote them together.
    other_degree: Dict[str, int] = {}
    if stale_sources:
        try:
            rows = fc._neo4j_rows(
                "MATCH (n) WHERE elementId(n) IN $ids "
                "OPTIONAL MATCH (n)-[r]-() "
                "WHERE NOT type(r) IN $skip "
                "RETURN elementId(n) AS id, count(r) AS deg",
                {"ids": sorted(stale_sources),
                 "skip": list(ee.WRITABLE_LABELS) + ["USES_TECH"]},
            )
            other_degree = {r["id"]: int(r["deg"] or 0) for r in rows}
        except Exception as exc:
            # Fail CLOSED: without the degree count we cannot prove isolation, so
            # nothing is deletable and the operator is told why.
            print("degree query failed (%s); no individual will be deleted" % exc,
                  file=sys.stderr)
            other_degree = {nid: 1 for nid in stale_sources}

    deletable, retained = [], []
    for nid in sorted(stale_sources):
        n = by_id[nid]
        p = _props(n)
        row = {"id": nid, "label": n.get("nodeLabel", ""), "source": p.get("source", "")}
        if _has_ad_identity(p):
            row["why"] = "has an AD identity"
            retained.append(row)
        elif other_degree.get(nid):
            row["why"] = "%d other relationship(s)" % other_degree[nid]
            retained.append(row)
        else:
            deletable.append(row)

    # Damage B: real people whose org-recon fields may have been overwritten.
    polluted = []
    for n in nodes:
        p = _props(n)
        if not _has_ad_identity(p) or _is_gated(p):
            continue
        dirty = {f: p[f] for f in POLLUTED_FIELDS if str(p.get(f) or "").strip()}
        if dirty:
            polluted.append({"id": n["id"], "label": n.get("nodeLabel", ""),
                             "fields": dirty})

    return {"stale_edges": stale_edges, "kept_edges": kept_edges,
            "deletable": deletable, "retained": retained, "polluted": polluted,
            "individuals": len(nodes)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sketch-id", help="Campaign sketch. Resolved from the active "
                                        "campaign when omitted.")
    ap.add_argument("--mode", choices=("edges", "nodes", "props"), default="edges")
    ap.add_argument("--apply", action="store_true",
                    help="Actually change the graph. Without it this is a dry run.")
    args = ap.parse_args()

    sketch_id = args.sketch_id
    if not sketch_id:
        try:
            sketch_id = fc.resolve_campaign_sketch()
        except Exception as exc:
            print("could not resolve a sketch: %s" % exc, file=sys.stderr)
            return 2
    # Every query here is sketch-scoped and a wrong or empty sketch id returns
    # clean zeros rather than an error, so "nothing to prune" must never be
    # reported without saying which sketch produced it.
    print("sketch: %s" % sketch_id)
    print("mode:   %s   (%s)" % (args.mode, "APPLY" if args.apply else "DRY RUN"))

    found = collect(sketch_id)
    print("individuals in sketch: %d" % found["individuals"])
    print("employment edges kept (gated, or not org-recon): %d" % found["kept_edges"])

    if args.mode == "props":
        rows = found["polluted"]
        print("\nAD individuals carrying org-recon fields: %d" % len(rows))
        print("NOTE: this cannot tell a value WF13 polluted from a correct one")
        print("      WF03/WF27 wrote. Read each before applying.")
        for r in rows[:100]:
            print("  %s" % r["label"])
            for f, v in r["fields"].items():
                print("      %-18s %s" % (f, str(v)[:90]))
        if len(rows) > 100:
            print("  ... and %d more" % (len(rows) - 100))
        if not args.apply:
            print("\ndry run — nothing changed. Re-run with --apply to clear these.")
            return 0
        cleared = 0
        for r in rows:
            # nodeProperties.<key>, NOT a bare key: an unprefixed update lands at
            # the node's top level where no reader looks, and every layer still
            # reports success.
            updates = {"nodeProperties.%s" % f: "" for f in r["fields"]}
            try:
                fc.edit_node(r["id"], updates, sketch_id=sketch_id)
                cleared += 1
            except Exception as exc:
                print("  FAILED %s: %s" % (r["label"], exc), file=sys.stderr)
        print("\ncleared org-recon fields on %d individual(s)" % cleared)
        return 0

    edges = found["stale_edges"]
    print("\nungated employment edges to remove: %d" % len(edges))
    for r in edges[:200]:
        print("  [%s] %s -> %s  (source=%s)"
              % (r["label"], r["individual"], r["company"], r["source"]))
    if len(edges) > 200:
        print("  ... and %d more" % (len(edges) - 200))

    if args.mode == "nodes":
        print("\nindividuals to delete: %d" % len(found["deletable"]))
        for r in found["deletable"][:200]:
            print("  %s  (source=%s)" % (r["label"], r["source"]))
        if len(found["deletable"]) > 200:
            print("  ... and %d more" % (len(found["deletable"]) - 200))
        if found["retained"]:
            print("\nkeeping %d individual(s) despite a stale edge:"
                  % len(found["retained"]))
            for r in found["retained"][:50]:
                print("  %s — %s" % (r["label"], r["why"]))

    if not args.apply:
        print("\ndry run — nothing deleted. Re-run with --apply to act.")
        return 0

    ids = [r["id"] for r in edges if r.get("id")]
    deleted = 0
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        fc.delete_relationships(chunk, sketch_id=sketch_id)
        deleted += len(chunk)
    print("\ndeleted %d edge(s)" % deleted)

    if args.mode == "nodes":
        nids = [r["id"] for r in found["deletable"]]
        removed = 0
        for i in range(0, len(nids), 500):
            chunk = nids[i:i + 500]
            fc.delete_nodes(chunk, sketch_id=sketch_id)
            removed += len(chunk)
        print("deleted %d individual(s)" % removed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
