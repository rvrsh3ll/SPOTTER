#!/usr/bin/env python3
"""
Deployed-artifact smoke for WF04 (Attack Path Analyzer).

This checks the production path that the offline scorer fixture cannot cover:
a body-less run resolves the active campaign sketch, reads the graph, writes
attack_score/attack_summary back to Individual nodes, and exits without using the
stale FLOWSINT_SKETCH_ID fallback.

The script creates a temporary investigation/sketch, makes that sketch the newest
campaign in the shared registry, triggers the deployed webhook with an empty body
so WF04 must resolve the active campaign itself, verifies the write-back, then
restores the campaign registry and cleans up the sketch.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ID = "spotter-workflow-04"
CAMPAIGN_ID = "wf04-deployed-smoke"
IND_LABEL = "WF04-SMOKE-EXP@CORP"
DEVICE_LABEL = "WF04-SMOKE-EXPHOST01"
TECH_LABEL = "WF04-SMOKE-nginx 1.18"


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(REPO_ROOT / ".env")
os.environ["FLOWSINT_API_URL"] = os.environ.get("FLOWSINT_API_URL_HOST", "http://127.0.0.1:5001")
os.environ["NEO4J_HTTP_URL"] = os.environ.get("NEO4J_HTTP_URL_HOST", "http://127.0.0.1:7474")

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import flowsint_client as fc  # noqa: E402


def _read_campaign_blob() -> str:
    rows = fc._neo4j_rows(
        "MATCH (m:SpotterMeta {key:'campaigns'}) RETURN m.data AS data LIMIT 1",
        {},
        timeout=60,
    )
    return rows[0].get("data") if rows else "[]"


def _write_campaign_blob(blob: str) -> None:
    fc._neo4j_rows(
        "MERGE (m:SpotterMeta {key:'campaigns'}) "
        "SET m.data = $data, m.updated_at = timestamp() "
        "RETURN m.data AS data",
        {"data": blob},
        timeout=60,
    )


def _replace_temp_campaign(original_blob: str, sketch_id: str) -> str:
    try:
        campaigns = json.loads(original_blob or "[]")
    except Exception:
        campaigns = []
    if not isinstance(campaigns, list):
        campaigns = []
    campaigns = [c for c in campaigns if not (isinstance(c, dict) and c.get("id") == CAMPAIGN_ID)]
    now = datetime.now(timezone.utc).isoformat()
    campaigns.append({
        "id": CAMPAIGN_ID,
        "name": "WF04 deployed smoke",
        "sketchId": sketch_id,
        "created": now,
        "updated": now,
        "owner": "smoke",
    })
    return json.dumps(campaigns, separators=(",", ":"))


def _j(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def _seed_graph(sketch_id: str) -> Dict[str, str]:
    ind = fc.add_node(IND_LABEL, "individual", {
        "sam_account_name": "WF04-SMOKE-EXP",
        "display_name": IND_LABEL,
    }, sketch_id=sketch_id)
    dev = fc.add_node(DEVICE_LABEL, "device", {
        "hostname": DEVICE_LABEL,
        "dnshostname": "wf04-smoke.example.test",
    }, sketch_id=sketch_id)
    tech = fc.add_node(TECH_LABEL, "technology", {
        "name": "nginx",
        "product": "nginx",
        "version": "1.18",
        "exploit_available": True,
        "poc_count": 2,
        "cve_count": 1,
        "cve_match_basis": "cpe",
        "source": "domain-recon",
        "cves": _j([{
            "cve_id": "CVE-2024-0001",
            "severity": "CRITICAL",
            "base_score": 9.8,
            "exploit_available": True,
            "poc_count": 2,
            "match": "cpe",
        }]),
        "top_pocs": _j([{
            "full_name": "owner/wf04-smoke-poc",
            "trust": "high",
            "trust_score": 12.0,
            "stars": 42,
            "unvetted": True,
        }]),
    }, sketch_id=sketch_id)
    fc.create_edge(ind["id"], dev["id"], "GenericAll", sketch_id=sketch_id)
    fc.create_edge(dev["id"], tech["id"], "USES_TECH", sketch_id=sketch_id)
    return {"individual": ind["id"], "device": dev["id"], "technology": tech["id"]}


def _trigger_webhook() -> str:
    try:
        return subprocess.check_output(
            ["docker", "exec", "spotter-n8n", "wget", "-qO-",
             "--header=Content-Type: application/json", "--post-data={}",
             "http://127.0.0.1:5678/webhook/attack-path-analyze"],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(exc.output[-4000:]) from exc


def _get_node(node_id: str, sketch_id: str) -> Dict[str, Any]:
    rows = fc._neo4j_rows(
        "MATCH (n {sketch_id:$sid}) WHERE elementId(n)=$id "
        "RETURN properties(n) AS props LIMIT 1",
        {"sid": sketch_id, "id": node_id},
        timeout=60,
    )
    return rows[0].get("props") if rows else {}


def _wait_for_score(node_id: str, sketch_id: str, timeout_seconds: int) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_props: Dict[str, Any] = {}
    while time.monotonic() < deadline:
        last_props = _get_node(node_id, sketch_id)
        if last_props.get("nodeProperties.attack_score") is not None:
            return last_props
        time.sleep(1)
    return last_props


def _cleanup_sketch(sketch_id: str) -> None:
    try:
        fc.delete_sketch(sketch_id)
    finally:
        fc._neo4j_rows(
            "MATCH (n {sketch_id: $sid}) DETACH DELETE n RETURN count(n) AS deleted",
            {"sid": sketch_id},
            timeout=60,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-sketch", action="store_true", help="leave the temporary sketch for inspection")
    parser.add_argument("--timeout", type=int, default=90, help="seconds to wait for async webhook write-back")
    args = parser.parse_args()

    original_blob = _read_campaign_blob()
    sketch_id = ""
    try:
        inv = fc.create_investigation("WF04 deployed smoke", "Temporary schedule-equivalent verification")
        inv_id = inv.get("id") or inv.get("investigation", {}).get("id")
        if not inv_id:
            raise RuntimeError(f"could not determine investigation id from {inv}")
        sketch = fc.create_sketch("WF04 deployed smoke", inv_id, "Temporary WF04 deployed smoke graph")
        sketch_id = sketch.get("id") or sketch.get("sketch", {}).get("id")
        if not sketch_id:
            raise RuntimeError(f"could not determine sketch id from {sketch}")

        ids = _seed_graph(sketch_id)
        temp_blob = _replace_temp_campaign(original_blob, sketch_id)
        _write_campaign_blob(temp_blob)
        resolved = fc.resolve_campaign_sketch()
        if resolved != sketch_id:
            raise RuntimeError(f"resolve_campaign_sketch returned {resolved}, expected {sketch_id}")

        output = _trigger_webhook()
        props = _wait_for_score(ids["individual"], sketch_id, args.timeout)
        score = props.get("nodeProperties.attack_score")
        summary_raw = props.get("nodeProperties.attack_summary")
        if int(score or 0) != 18:
            raise RuntimeError(json.dumps({
                "error": "unexpected attack_score",
                "score": score,
                "props": props,
                "n8n_output_tail": output[-1200:],
            }, indent=2))
        summary = json.loads(summary_raw or "{}")
        exploit = summary.get("exploit") or {}
        if exploit.get("bonus") != 8 or exploit.get("from") != "path":
            raise RuntimeError(json.dumps({
                "error": "missing exploit provenance",
                "attack_summary": summary,
                "n8n_output_tail": output[-1200:],
            }, indent=2))

        high_value = props.get("nodeProperties.is_high_value")
        print(json.dumps({
            "workflow_id": WORKFLOW_ID,
            "sketch_id": sketch_id,
            "resolved_schedule_sketch": resolved,
            "trigger_response": output.strip()[:200],
            "individual_id": ids["individual"],
            "attack_score": score,
            "is_high_value": high_value,
            "exploit_bonus": exploit.get("bonus"),
            "exploit_from": exploit.get("from"),
            "top_paths": summary.get("total_paths"),
        }, indent=2))
        return 0
    finally:
        try:
            _write_campaign_blob(original_blob)
        except Exception as exc:
            print(f"warning: failed to restore campaign registry: {exc}", file=sys.stderr)
        if sketch_id and not args.keep_sketch:
            try:
                _cleanup_sketch(sketch_id)
            except Exception as exc:
                print(f"warning: failed to clean sketch {sketch_id}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
