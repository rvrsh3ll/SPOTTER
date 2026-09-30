"""Persist WF10/WF12 model runs and operator corrections on the host.

The run input, model output, and WF29 correction records provide local data for
future triage evaluation or classifier research. This module does not train a
model. Browser localStorage remains the dashboard's presentation cache; these
records live separately and are not written to Neo4j.

Storage: $SPOTTER_CACHE_DIR/analysis_history/<sketch_id>/<workflow>/<run_id>.json
-- the same shared cache bind mount rag_indexer.py already uses, so this needs
no new service, container, or database. One JSON file per run holds:

    {run_id, sketch_id, workflow, created_at, input_state, model_output,
     corrections: [{item_path, corrected_value, corrected_by, corrected_at}, ...]}

Every write here is best-effort by design: WF10/WF12 call record_run() wrapped
in their own try/except, since a persistence failure must never affect the
response already computed for the operator.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional

from spotter_cache import ensure_cache_path

DEFAULT_CACHE_DIR = "./.spotter-cache"
_SUBDIR = "analysis_history"
ALLOWED_WORKFLOWS = {"wf10", "wf12"}


def _cache_root() -> str:
    return os.environ.get("SPOTTER_CACHE_DIR") or DEFAULT_CACHE_DIR


def _safe_slug(value: str, *, max_len: int = 120) -> str:
    """Sanitize an id for use as a path segment -- no separators, no traversal."""
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", str(value or "").strip())
    slug = slug.lstrip(".")
    return slug[:max_len] or "unknown"


def _run_dir(sketch_id: str, workflow: str) -> str:
    return os.path.join(_cache_root(), _SUBDIR, _safe_slug(sketch_id), _safe_slug(workflow))


def _run_path(sketch_id: str, workflow: str, run_id: str) -> str:
    return os.path.join(_run_dir(sketch_id, workflow), f"{_safe_slug(run_id)}.json")


def _write_json(path: str, record: Dict[str, Any]) -> None:
    ensure_cache_path(os.path.dirname(path), is_dir=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, separators=(",", ":"))
    # Shared cache bind mount, root maintenance scripts vs. uid/gid 1000 task
    # runner -- same permission trap _save_collection() in rag_indexer.py works
    # around; best-effort only, not owning the file only matters on rewrite.
    try:
        ensure_cache_path(path, is_dir=False)
    except OSError:
        pass


def record_run(
    sketch_id: str,
    workflow: str,
    input_state: Dict[str, Any],
    model_output: Dict[str, Any],
    *,
    run_id: Optional[str] = None,
) -> str:
    """Persist one WF10/WF12 run; returns the run_id."""
    workflow = workflow.lower()
    if workflow not in ALLOWED_WORKFLOWS:
        raise ValueError(f"unknown workflow {workflow!r}, expected one of {sorted(ALLOWED_WORKFLOWS)}")
    run_id = run_id or uuid.uuid4().hex
    record = {
        "run_id": run_id,
        "sketch_id": sketch_id,
        "workflow": workflow,
        "created_at": time.time(),
        "input_state": input_state,
        "model_output": model_output,
        "corrections": [],
    }
    _write_json(_run_path(sketch_id, workflow, run_id), record)
    return run_id


def get_run(sketch_id: str, workflow: str, run_id: str) -> Optional[Dict[str, Any]]:
    path = _run_path(sketch_id, workflow.lower(), run_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def record_correction(
    sketch_id: str,
    workflow: str,
    run_id: str,
    item_path: str,
    corrected_value: Any,
    corrected_by: str = "",
) -> bool:
    """Append an operator correction to an existing run. False if the run is gone
    (e.g. pruned, or never persisted) rather than raising."""
    workflow = workflow.lower()
    record = get_run(sketch_id, workflow, run_id)
    if record is None:
        return False
    record.setdefault("corrections", []).append({
        "item_path": str(item_path)[:500],
        "corrected_value": corrected_value,
        "corrected_by": str(corrected_by)[:200],
        "corrected_at": time.time(),
    })
    _write_json(_run_path(sketch_id, workflow, run_id), record)
    return True


def list_runs(sketch_id: str, workflow: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Newest-first run summaries (no input_state/model_output payload)."""
    workflows = [workflow.lower()] if workflow else sorted(ALLOWED_WORKFLOWS)
    out: List[Dict[str, Any]] = []
    for wf in workflows:
        d = _run_dir(sketch_id, wf)
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(d, fname), "r", encoding="utf-8") as f:
                    rec = json.load(f)
            except (OSError, ValueError):
                continue
            out.append({
                "run_id": rec.get("run_id"),
                "workflow": rec.get("workflow"),
                "created_at": rec.get("created_at"),
                "correction_count": len(rec.get("corrections") or []),
            })
    out.sort(key=lambda r: r.get("created_at") or 0, reverse=True)
    return out[: max(1, limit)]
