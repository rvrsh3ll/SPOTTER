"""Campaign ownership, sharing and quota rules for SPOTTER.

Single source of truth for who may see, edit or delete a campaign, imported by
the n8n code nodes in WF16 (create-sketch), WF17 (list-campaigns), WF18
(save-campaigns) and WF20 (import-campaign). The rules are security-relevant, so
they live here rather than being copy-pasted into four workflow JSONs where they
would inevitably drift.

Identity comes from the `X-Spotter-User` request header. That header is set by
nginx from the `auth_request` subrequest result and, because nginx uses
`proxy_set_header`, it unconditionally overwrites whatever the client sent — see
frontend/nginx.conf. It is therefore trustworthy *provided* n8n is not reachable
except through that proxy. If the n8n port is republished to the host, this
whole model reverts to advisory.

Ownership model
  owner == <username>   normal case: private to the owner plus anyone in
                        sharedWith; only the owner may edit, share or delete
  owner is None         legacy campaign created before authentication existed.
                        Visible and editable by everyone, and counted against
                        nobody's quota, so switching auth on cannot strand a
                        live engagement. Claim one with:
                            scripts/spotter_user.py adopt <campaign_id> <user>

NOTE for n8n: this module must be listed in N8N_RUNNERS_EXTERNAL_ALLOW
(deployment/docker-compose.n8n.yml) or the import fails at runtime with a bare
ModuleNotFoundError. The host-side node harness does NOT enforce that allowlist,
so a passing harness run is not proof the workflow will import it.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict, List, Optional, Tuple

import requests as req

DEFAULT_MAX_CAMPAIGNS = 3


def max_campaigns() -> int:
    """Per-user cap on owned campaigns.

    Set SPOTTER_MAX_CAMPAIGNS_PER_USER in .env, the task-runners `environment:`
    block AND the python runner's `allowed-env` list, or this silently keeps the
    default (a var missing from allowed-env never reaches the code node).
    """
    try:
        value = int(os.environ.get("SPOTTER_MAX_CAMPAIGNS_PER_USER") or DEFAULT_MAX_CAMPAIGNS)
    except (TypeError, ValueError):
        return DEFAULT_MAX_CAMPAIGNS
    return value if value > 0 else DEFAULT_MAX_CAMPAIGNS


# ── Caller identity ──────────────────────────────────────────────────────────

def caller(_items: Any) -> str:
    """Resolve the authenticated operator from the webhook node's item.

    n8n's Webhook node emits {headers, params, query, body}; Node lowercases all
    inbound header names. Returns '' when absent — callers must fail closed.
    """
    try:
        item = _items[0].get("json", {}) if _items else {}
    except (IndexError, AttributeError, TypeError):
        return ""
    headers = item.get("headers") or {}
    if not isinstance(headers, dict):
        return ""
    value = headers.get("x-spotter-user") or headers.get("X-Spotter-User") or ""
    return str(value).strip().lower()


def body_of(_items: Any) -> Dict[str, Any]:
    """Extract the JSON body from a webhook item (mirrors the existing nodes)."""
    item = _items[0].get("json", {}) if _items else {}
    if isinstance(item.get("body"), dict):
        return item["body"]
    return item if isinstance(item, dict) else {}


# ── Neo4j registry access ────────────────────────────────────────────────────
# The registry is one global node (:SpotterMeta {key:'campaigns'}) holding a JSON
# array in `data`. It deliberately carries no sketch_id so it is global to every
# campaign/operator; WF07's orphan sweep is guarded (AND NOT n:SpotterMeta) so it
# is never purged.

def _cypher(stmt: str, params: Optional[dict] = None) -> dict:
    neo_url = os.environ.get("NEO4J_HTTP_URL", "http://flowsint-neo4j-prod:7474").rstrip("/")
    neo_user = os.environ.get("NEO4J_USER", "neo4j")
    neo_pass = os.environ.get("NEO4J_PASSWORD", "")
    if not neo_pass:
        raise RuntimeError("NEO4J_PASSWORD not set")
    auth = base64.b64encode(f"{neo_user}:{neo_pass}".encode()).decode()
    r = req.post(
        f"{neo_url}/db/neo4j/tx/commit",
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        json={"statements": [{"statement": stmt, "parameters": params or {}}]},
        timeout=60,
    )
    r.raise_for_status()
    d = r.json()
    if d.get("errors"):
        raise RuntimeError(str(d["errors"])[:300])
    return d


def read_campaigns() -> List[dict]:
    d = _cypher("MATCH (m:SpotterMeta {key:'campaigns'}) RETURN m.data AS data LIMIT 1")
    rows = d["results"][0]["data"]
    raw = rows[0]["row"][0] if rows else None
    try:
        camps = json.loads(raw) if raw else []
    except (TypeError, ValueError):
        return []
    return camps if isinstance(camps, list) else []


def write_campaigns(camps: List[dict]) -> None:
    _cypher(
        "MERGE (m:SpotterMeta {key:'campaigns'}) SET m.data = $data, m.updated_at = timestamp()",
        {"data": json.dumps(camps)},
    )


# ── Access rules ─────────────────────────────────────────────────────────────

def owner_of(camp: dict) -> Optional[str]:
    owner = camp.get("owner")
    return str(owner).strip().lower() if owner else None


def shared_with(camp: dict) -> List[str]:
    raw = camp.get("sharedWith") or []
    if not isinstance(raw, list):
        return []
    return [str(u).strip().lower() for u in raw if str(u).strip()]


def can_read(camp: dict, user: str) -> bool:
    owner = owner_of(camp)
    return owner is None or owner == user or user in shared_with(camp)


def can_write(camp: dict, user: str) -> bool:
    """Edit/delete/share rights. Shared-in users get read access only."""
    owner = owner_of(camp)
    return owner is None or owner == user


def visible(camps: List[dict], user: str) -> List[dict]:
    return [c for c in camps if isinstance(c, dict) and can_read(c, user)]


def owned_count(camps: List[dict], user: str) -> int:
    """Campaigns counting against `user`'s quota.

    Shared-in and legacy unowned campaigns deliberately do not count — the cap
    is on what you create, not on what you can see.
    """
    return sum(1 for c in camps if isinstance(c, dict) and owner_of(c) == user)


def quota_state(camps: List[dict], user: str) -> Dict[str, int]:
    limit = max_campaigns()
    used = owned_count(camps, user)
    return {"used": used, "limit": limit, "remaining": max(0, limit - used)}


def can_access_sketch(camps: List[dict], sketch_id: str, user: str) -> bool:
    """May `user` write to the campaign graph behind `sketch_id`?

    Used by the destructive/writing webhooks (WF07 clear-graph, WF20 import) so
    that knowing another operator's sketch UUID is not sufficient to wipe or
    pollute their engagement.

    A sketch that belongs to NO campaign in the registry is allowed: sketches
    are also created out of band by scripts/ingest_sharphound_large.py and the
    admin tooling, and refusing those would break existing operational paths.
    The check therefore restricts what is known to be owned, rather than
    asserting ownership over everything.
    """
    if not sketch_id:
        return True
    for camp in camps:
        if not isinstance(camp, dict):
            continue
        if str(camp.get("sketchId") or "") == str(sketch_id):
            return can_write(camp, user)
    return True


# ── Merge / save ─────────────────────────────────────────────────────────────

def merge_save(current: List[dict], incoming: Optional[List[dict]],
               delete_id: Optional[str], user: str) -> Tuple[List[dict], Dict[str, Any]]:
    """Apply an authenticated save to the registry.

    Returns (merged_full_registry, info) where info carries what the UI needs to
    explain a partial write: `rejected`, `quota_exceeded` and `quota`.

    Invariants:
      * ids absent from the payload are never dropped, so a stale client cannot
        wipe campaigns — now including other operators' campaigns.
      * `owner` is always taken from the stored record, never from the payload,
        so a client cannot assign ownership to itself or anyone else.
      * a write to a campaign the caller cannot edit is skipped SILENTLY (listed
        in `rejected`) rather than failing the request, because the frontend
        pushes the whole visible array — including shared-in campaigns it does
        not own — on every save.
    """
    by_id: Dict[str, dict] = {}
    order: List[str] = []

    def _put(camp: dict) -> None:
        if isinstance(camp, dict) and camp.get("id"):
            cid = str(camp["id"])
            if cid not in by_id:
                order.append(cid)
            by_id[cid] = camp

    for camp in current:
        _put(camp)

    rejected: List[str] = []
    quota_exceeded = False

    if isinstance(incoming, list):
        for camp in incoming:
            if not isinstance(camp, dict) or not camp.get("id"):
                continue
            cid = str(camp["id"])
            existing = by_id.get(cid)

            if existing is None:
                # Creating: charge it to the caller's quota.
                if owned_count(list(by_id.values()), user) >= max_campaigns():
                    quota_exceeded = True
                    rejected.append(cid)
                    continue
                fresh = dict(camp)
                fresh["owner"] = user
                fresh["sharedWith"] = [u for u in shared_with(camp) if u != user]
                _put(fresh)
                continue

            if not can_write(existing, user):
                rejected.append(cid)
                continue

            merged = dict(camp)
            # Ownership is server-owned state; a legacy campaign stays unowned
            # until explicitly adopted via scripts/spotter_user.py.
            if existing.get("owner"):
                merged["owner"] = existing["owner"]
            else:
                merged.pop("owner", None)
            # Only a real owner may change the share list.
            if owner_of(existing) == user:
                merged["sharedWith"] = [u for u in shared_with(camp) if u != user]
            else:
                merged["sharedWith"] = shared_with(existing)
            _put(merged)

    if delete_id is not None:
        did = str(delete_id)
        target = by_id.get(did)
        if target is None:
            pass  # already gone; deleting is idempotent
        elif not can_write(target, user):
            rejected.append(did)
        else:
            by_id.pop(did, None)
            order = [x for x in order if x != did]

    merged_all = [by_id[cid] for cid in order if cid in by_id]
    info: Dict[str, Any] = {
        "rejected": rejected,
        "quota_exceeded": quota_exceeded,
        "quota": quota_state(merged_all, user),
    }
    return merged_all, info
