#!/usr/bin/env python3
"""Smoke tests for scripts/analysis_history.py (WF10/WF12 run persistence)."""

from __future__ import annotations

import os
import tempfile


def _ok(name: str) -> None:
    print(f"  ok    {name}")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SPOTTER_CACHE_DIR"] = tmp
        import analysis_history as ah

        run_id = ah.record_run(
            "sketch-abc", "wf10",
            {"campaign_id": "camp-1", "target_name": "example corp"},
            {"summary": "test summary", "scenarios": []},
        )
        assert run_id
        _ok("record_run returns a run_id")

        rec = ah.get_run("sketch-abc", "wf10", run_id)
        assert rec is not None
        assert rec["sketch_id"] == "sketch-abc"
        assert rec["model_output"]["summary"] == "test summary"
        assert rec["corrections"] == []
        _ok("get_run round-trips the persisted record")

        assert ah.get_run("sketch-abc", "wf10", "does-not-exist") is None
        _ok("get_run returns None for an unknown run_id")

        try:
            ah.record_run("sketch-abc", "wf99", {}, {})
            assert False, "expected ValueError for an unknown workflow"
        except ValueError:
            pass
        _ok("record_run rejects an unknown workflow name")

        ok = ah.record_correction("sketch-abc", "wf10", run_id, "scenarios[0].severity", "high", corrected_by="operator1")
        assert ok is True
        rec = ah.get_run("sketch-abc", "wf10", run_id)
        assert len(rec["corrections"]) == 1
        assert rec["corrections"][0]["corrected_value"] == "high"
        assert rec["corrections"][0]["corrected_by"] == "operator1"
        _ok("record_correction appends a correction to the persisted run")

        assert ah.record_correction("sketch-abc", "wf10", "does-not-exist", "x", "y") is False
        _ok("record_correction returns False for an unknown run_id instead of raising")

        # Path-traversal-shaped ids must not escape the sketch/workflow directory.
        evil_run_id = ah.record_run("../../etc", "wf10", {}, {})
        evil_path = ah._run_path("../../etc", "wf10", evil_run_id)
        assert os.path.abspath(evil_path).startswith(os.path.abspath(tmp))
        _ok("sketch_id/run_id path segments are sanitized against traversal")

        runs = ah.list_runs("sketch-abc")
        assert any(r["run_id"] == run_id and r["correction_count"] == 1 for r in runs)
        _ok("list_runs surfaces the run with its correction count")

    print("\nAll analysis_history smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
