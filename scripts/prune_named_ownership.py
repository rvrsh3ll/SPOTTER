#!/usr/bin/env python3
"""
prune_named_ownership.py — clear the ownership edges WF13's retired name-token
match left behind.

WHAT IT IS CLEANING UP
----------------------
WF13 used to infer asset ownership by matching an individual's own name TOKENS
against the asset's label, writing a `MANAGES_NAMED` edge. On a real
campaign that attributed `https://primer-avia.test` and
`autoconfig.primer-avia.test` to `jd@primer-avia.test`.

It was structurally broken, not merely imprecise. WF13's own Flare promotion
creates individuals whose nodeLabel IS an email address on the target domain --
the address is all it knows about them -- so tokenising the label yields the
domain's own tokens and the match is guaranteed for every promoted identity
against every asset on that domain. That branch is gone; `MANAGES_NAMED` now has
no writer anywhere in the repo.

WHY THIS CANNOT JUST READ THE EDGE
----------------------------------
Flowsint drops edge `data` before it reaches Neo4j, so nothing records which
branch produced an existing edge -- the same limitation that stopped
`MANAGES_NAMED` being applied retroactively when it was introduced. Intent has to
be inferred from the SOURCE NODE instead, which is what --mode does.

    --mode provisional  (default) delete only edges whose source individual is a
                        Flare-promoted provisional identity: `provisional` set,
                        or source/discovered_by == 'flare_domain'. These are
                        definitely wrong, because such an identity has no AD
                        presence and cannot own anything.
    --mode all          delete every MANAGES_NAMED edge in the sketch. Defensible
                        now that the label has no writer: what remains is all
                        legacy output of a branch that no longer exists.

A NOTE ON is_provisional_identity
---------------------------------
It reads node PROPERTIES, never the label's shape, and that distinction is load
bearing here. `sharphound_parser` labels every AD principal from
`Properties.name`, which BloodHound populates as `SAMACCOUNTNAME@DOMAIN.LOCAL` --
so every genuine AD user is email-shaped too. Treating an email-shaped label as
provisional would delete real principals' edges under --mode provisional and,
worse, silently exclude every real rights-holder from the replacement inference.

SAFETY
------
--dry-run is the DEFAULT and prints every edge it would remove. There is no Neo4j
backup on this host, and `clear_graph` on a bare sketch_id is not a dry run
either -- deletions here are not recoverable.

Usage:
    python3 scripts/prune_named_ownership.py --sketch-id <id>
    python3 scripts/prune_named_ownership.py --sketch-id <id> --mode all
    python3 scripts/prune_named_ownership.py --sketch-id <id> --apply
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import asset_ownership as ao  # noqa: E402
import flowsint_client as fc  # noqa: E402


def collect(sketch_id: str, mode: str) -> Dict[str, Any]:
    """Return the edges to remove, those kept, and why."""
    out: Dict[str, Any] = {"remove": [], "keep": [], "labels": {}}

    # Index the individuals once: the edge rows carry labels, not properties, and
    # the property flags are the only reliable provisional signal.
    props_by_id: Dict[str, Dict[str, Any]] = {}
    for n in fc.get_nodes_by_type(["individual", "Individual"], sketch_id=sketch_id):
        props_by_id[n["id"]] = n.get("nodeProperties") or {}

    for label in ao.RETIRED_LABELS:
        edges = fc.get_edges_by_type([label], sketch_id=sketch_id,
                                     resolve_endpoints=True) or []
        out["labels"][label] = len(edges)
        for e in edges:
            src_label = e.get("source_label") or e.get("source") or ""
            props = props_by_id.get(e.get("source", ""), {})
            provisional = ao.is_provisional_identity(src_label, props)
            row = {
                "id": e.get("id"),
                "label": e.get("label"),
                "individual": src_label,
                "asset": e.get("target_label") or e.get("target") or "",
                "provisional": provisional,
                # Recorded for the operator's judgement under --mode provisional,
                # never used as the decision itself -- see the module docstring.
                "email_labelled": ao.is_email_labelled(src_label),
            }
            if mode == "all" or provisional:
                out["remove"].append(row)
            else:
                out["keep"].append(row)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sketch-id", help="Campaign sketch. Resolved from the active "
                                        "campaign when omitted.")
    ap.add_argument("--mode", choices=("provisional", "all"), default="provisional")
    ap.add_argument("--apply", action="store_true",
                    help="Actually delete. Without it this is a dry run.")
    args = ap.parse_args()

    sketch_id = args.sketch_id
    if not sketch_id:
        try:
            sketch_id = fc.resolve_campaign_sketch()
        except Exception as exc:
            print(f"could not resolve a sketch: {exc}", file=sys.stderr)
            return 2
    # Every query in this stack is sketch-scoped, and a wrong or empty sketch id
    # returns clean zeros rather than an error -- so "nothing to prune" must not
    # be reported without saying which sketch produced it.
    print(f"sketch: {sketch_id}")
    print(f"mode:   {args.mode}   ({'APPLY' if args.apply else 'dry run'})")

    found = collect(sketch_id, args.mode)
    for label, count in found["labels"].items():
        print(f"{label}: {count} edge(s) in this sketch")

    if not found["remove"] and not found["keep"]:
        print("nothing to do — no retired ownership edges in this sketch")
        return 0

    print(f"\nwould remove {len(found['remove'])}:")
    for row in found["remove"][:200]:
        flag = "provisional" if row["provisional"] else "legacy"
        print(f"  [{flag}] {row['individual']} -> {row['asset']}")
    if len(found["remove"]) > 200:
        print(f"  ... and {len(found['remove']) - 200} more")

    if found["keep"]:
        print(f"\nkeeping {len(found['keep'])} (source is not a provisional "
              f"identity; use --mode all to remove these too):")
        for row in found["keep"][:50]:
            print(f"  {row['individual']} -> {row['asset']}")
        if len(found["keep"]) > 50:
            print(f"  ... and {len(found['keep']) - 50} more")

    if not args.apply:
        print("\ndry run — nothing deleted. Re-run with --apply to remove them.")
        return 0

    ids: List[str] = [r["id"] for r in found["remove"] if r.get("id")]
    if not ids:
        print("\nnothing to delete")
        return 0
    # Chunked: the delete endpoint takes an id list, and a sketch with thousands
    # of these would otherwise go in one request.
    deleted = 0
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        fc.delete_relationships(chunk, sketch_id=sketch_id)
        deleted += len(chunk)
    print(f"\ndeleted {deleted} edge(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
