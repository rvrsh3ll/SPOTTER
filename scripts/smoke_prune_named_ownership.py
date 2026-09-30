#!/usr/bin/env python3
"""
Offline smoke test for scripts/prune_named_ownership.py.

Runs the cleanup against a fake Flowsint graph, so the selection logic is tested
without touching a campaign. There is no Neo4j backup on this host and these
deletions are not recoverable, so "I ran it and it looked right" is not a
substitute for pinning which rows it picks.

    fixture               what it pins down
    --------------------  --------------------------------------------------
    provisional_removed   the rows from the original bug report are selected
    ad_principal_kept     an email-shaped REAL AD user is not selected
    mode_all              --mode all takes every legacy edge
    dry_run_default       a run without --apply deletes nothing
    apply_deletes         a run with --apply deletes exactly the selection

Usage:
    python3 scripts/smoke_prune_named_ownership.py
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def build_fake_client(deleted: List[str]) -> types.ModuleType:
    """A graph holding both kinds of source individual.

    The AD principal's nodeLabel is COPS@CORP.LOCAL on purpose. SharpHound labels
    an Individual from Properties.name, which BloodHound populates as
    SAMACCOUNTNAME@DOMAIN.LOCAL -- so a REAL AD user is email-shaped, exactly
    like the Flare promotion. A fixture using "Carol Ops" would let a
    label-shape selection pass this test while deleting real principals' edges.
    """
    nodes = [
        {"id": "i-prov", "nodeType": "individual", "nodeLabel": "jd@primer-avia.test",
         "nodeProperties": {"provisional": True, "source": "flare_domain"}},
        {"id": "i-flare2", "nodeType": "individual", "nodeLabel": "ops@primer-avia.test",
         # No `provisional` key, only the source -- both writers' spellings must work.
         "nodeProperties": {"discovered_by": "flare_domain"}},
        {"id": "i-ad", "nodeType": "individual", "nodeLabel": "COPS@CORP.LOCAL",
         "nodeProperties": {"source": "sharphound", "sam_account_name": "cops"}},
    ]
    edges = [
        {"id": "e1", "label": "MANAGES_NAMED", "source": "i-prov", "target": "a1",
         "source_label": "jd@primer-avia.test", "target_label": "https://primer-avia.test"},
        {"id": "e2", "label": "MANAGES_NAMED", "source": "i-prov", "target": "a2",
         "source_label": "jd@primer-avia.test", "target_label": "autoconfig.primer-avia.test"},
        {"id": "e3", "label": "MANAGES_NAMED", "source": "i-flare2", "target": "a1",
         "source_label": "ops@primer-avia.test", "target_label": "https://primer-avia.test"},
        {"id": "e4", "label": "MANAGES_NAMED", "source": "i-ad", "target": "a1",
         "source_label": "COPS@CORP.LOCAL", "target_label": "https://primer-avia.test"},
    ]
    fake = types.ModuleType("flowsint_client")
    fake.get_nodes_by_type = lambda labels, **k: [n for n in nodes if n["nodeType"] in labels]
    fake.get_edges_by_type = lambda rels, **k: [dict(e) for e in edges if e["label"] in rels]
    fake.delete_relationships = lambda ids, **k: deleted.extend(ids)
    fake.resolve_campaign_sketch = lambda: "resolved-sketch"
    return fake


def main() -> None:
    deleted: List[str] = []
    sys.modules["flowsint_client"] = build_fake_client(deleted)
    import prune_named_ownership as p

    failures = 0

    def check(name: str, ok: bool, detail: Any = None) -> None:
        nonlocal failures
        print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f"  {detail!r}"))
        failures += 0 if ok else 1

    print("prune_named_ownership fixtures:")

    prov = p.collect("smoke-sketch", "provisional")
    removed = {(r["individual"], r["asset"]) for r in prov["remove"]}
    # The two rows from the actual bug report, plus the source-only-flagged one.
    check("provisional_removed",
          removed == {("jd@primer-avia.test", "https://primer-avia.test"),
                      ("jd@primer-avia.test", "autoconfig.primer-avia.test"),
                      ("ops@primer-avia.test", "https://primer-avia.test")},
          removed)

    kept = prov["keep"]
    # THE LOAD-BEARING ONE. The AD principal is email-shaped too; only the
    # property flags distinguish it, and getting this wrong deletes real data.
    check("ad_principal_kept",
          len(kept) == 1
          and kept[0]["individual"] == "COPS@CORP.LOCAL"
          and kept[0]["email_labelled"] is True      # it IS email-shaped
          and kept[0]["provisional"] is False,       # ...and still not provisional
          kept)

    allm = p.collect("smoke-sketch", "all")
    check("mode_all", len(allm["remove"]) == 4 and not allm["keep"], allm)

    # The CLI's dry-run default. Argv is the contract an operator actually types.
    saved_argv = sys.argv
    try:
        sys.argv = ["prune", "--sketch-id", "smoke-sketch"]
        p.main()
        check("dry_run_default", deleted == [], deleted)

        sys.argv = ["prune", "--sketch-id", "smoke-sketch", "--apply"]
        p.main()
        check("apply_deletes", sorted(deleted) == ["e1", "e2", "e3"], deleted)
    finally:
        sys.argv = saved_argv

    if failures:
        print(f"FAILED ({failures})")
        raise SystemExit(1)
    print("PASSED")


if __name__ == "__main__":
    main()
