#!/usr/bin/env python3
"""Persistent notification feed behind the SPOTTER header ticker (workflow 24).

Why this exists
---------------
SPOTTER had no event store of any kind. There was no notification table, no
event log, and no timestamps on alerts: `nodeProperties.alert` is a
comma-separated tag list carrying no time information, the old Slack emitters
(WF01/02/04/09/13/14, since removed) were fire-and-forget with nothing
persisted, and n8n is configured to discard successful executions. "What
happened in the last hour" was therefore unanswerable from the graph, which is
exactly what a header ticker has to answer. This feed is now the only alerting
surface.

How the feed is produced
------------------------
Every signal an operator cares about already lands ON a graph node -- attack
scores on Individuals (WF04), `last_checkin` on C2Sessions (WF01/WF21),
FlareBreach nodes (WF09), alert tags (the enrichers), CloudAsset nodes (WF13).
So rather than tee six producer workflows into a new store, `sweep()` reads
those nodes on a rate-limited schedule, diffs them against what has already
been reported, and writes a notification for anything new. No producer workflow
is modified. The cost is latency bounded by the sweep interval rather than
instant push; any single source can be upgraded to push later by calling
emit() directly, with no change to storage or to the UI.

Four decisions here are load-bearing. Each has a cheaper-looking alternative
that is wrong:

1.  Notification nodes carry BOTH :SpotterMeta and :SpotterNotification.
    The label pair is not decoration. WF07's orphan sweep is

        MATCH (n) WHERE NOT coalesce(n.sketch_id, "") IN $live
                    AND NOT n:SpotterMeta ... DETACH DELETE n

    A node labelled only :SpotterNotification has no sketch_id, so
    coalesce(...,"") is never in $live and every campaign delete or orphan
    reconcile would silently delete the entire feed. Carrying :SpotterMeta
    inherits the existing guard and means WF07 needs no edit.

2.  They carry NO sketch_id, and are scoped by campaign_id instead. A node
    inside a sketch whose nodeType Flowsint cannot resolve returns 500 for
    reads of the WHOLE sketch, which would take the graph down for one
    cosmetic feature. Staying outside every sketch also means notifications
    survive a clear-graph, which is right for an audit trail; prune() drops
    rows whose campaign has left the registry.

3.  The notification nodes ARE the dedup state. "Have I already reported
    this?" is answered by whether a node with that dedup_key exists, not by a
    parallel state blob, which removes the read-modify-write race for four of
    the five sources. Only agent status transitions need stored prior state,
    because detecting a change requires the PREVIOUS status.

4.  sketch_id is derived from the campaign registry, never taken from the
    request body. WF23 trusts the body, but a feed that did so would let
    operator A sweep operator B's graph into A's ticker. This follows WF07's
    precedent instead: authorise the caller against the campaign, then take
    the sketch from the registry entry.

Reading never raises. The ticker polls this every 60 seconds from every open
browser; a sweep that fails while Neo4j restarts must degrade to "no new
notifications" rather than 500 the webhook and paint an error in the header of
every operator's dashboard. Every public entry point swallows its exception and
reports through an `errors` list, the same contract WF23's roster uses.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

# spotter_campaign_acl already owns the Neo4j HTTP transaction helper and the
# webhook identity helpers, and is on the runner's import allowlist. Reusing it
# keeps one Cypher path and one definition of "who is calling", exactly as
# spotter_settings does.
import spotter_campaign_acl as _acl
import spotter_settings as _settings

# Hard import, the same call WF23's roster makes, so the ticker and the AGENTS tab
# can never disagree about what a framework is called. c2_common is on the runner's
# import allowlist and mounted at /data/scripts, so a failure here is a real
# deployment fault -- a try/except with a local fallback map would silently relabel
# every framework as Cobalt Strike and look like it worked.
from c2_common import framework_display

# ── Storage keys ─────────────────────────────────────────────────────────────
# Every auxiliary blob is a plain (:SpotterMeta) node keyed by campaign, so two
# campaigns never contend and a per-user read mark never races another user.
_K_LEASE = "notify_sweep:{camp}"
_K_AGENTS = "notify_agents:{camp}"
_K_READ = "notify_read:{camp}:{user}"

_SEV_ORDER = {"critical": 0, "warn": 1, "info": 2}

# Alert tags the sweep turns into notifications, with severity and whether the
# ticker surfaces them. The disabled ones are deliberate, not oversights:
#   * CRITICAL_AD_RIGHTS / OVERPERMISSIVE_HIDDEN_SHARE belong to the AD-rights
#     source, which was not selected for the ticker.
#   * HIGH_VALUE_BEACON is already reported by the agent-status source; leaving
#     it on would double-report the same beacon under two different wordings.
# Flipping any flag to True is the whole change needed to surface it.
_ALERT_TAGS: Dict[str, Tuple[str, bool]] = {
    "STEALER_LOG_DETECTED":        ("critical", True),
    "CORP_BREACH_CRED_MATCH":      ("critical", True),
    "MULTIPLE_BREACHES":           ("warn",     True),
    "PASSWORD_REUSE":              ("warn",     True),
    "CRITICAL_AD_RIGHTS":          ("critical", False),
    "OVERPERMISSIVE_HIDDEN_SHARE": ("warn",     False),
    "HIGH_VALUE_BEACON":           ("warn",     False),
}

# Mirrors WF23's roster maths exactly. A beacon's liveness must not be computed
# two different ways in two places, or the Agents tab and the ticker will
# disagree about the same beacon in front of the operator.
_SKEW_MINUTES = 5


# ── Small helpers ────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _truthy(value: Any) -> bool:
    """Flowsint round-trips declared booleans as strings often enough that a
    bare `if value:` is wrong -- the string 'false' is truthy in Python."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "y")


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _parse_dt(value: Any) -> Optional[datetime]:
    """Parse the several timestamp shapes C2 nodes carry. Returns None, never
    raises: an unparseable check-in must read as 'unknown', not kill the sweep."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    for fmt in (None, "%m-%d-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = (datetime.fromisoformat(text.replace("Z", "+00:00"))
                  if fmt is None else datetime.strptime(text, fmt))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            continue
    return None


def _rows(result: dict) -> List[list]:
    try:
        return [r["row"] for r in result["results"][0]["data"]]
    except (KeyError, IndexError, TypeError):
        return []


def _meta_read(key: str) -> Dict[str, Any]:
    """A (:SpotterMeta) JSON blob, or {} on any failure."""
    try:
        rows = _rows(_acl._cypher(
            "MATCH (m:SpotterMeta {key:$k}) RETURN m.data AS data LIMIT 1", {"k": key}))
        raw = rows[0][0] if rows else None
        data = json.loads(raw) if raw else {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _meta_write(key: str, data: Dict[str, Any]) -> None:
    _acl._cypher(
        "MERGE (m:SpotterMeta {key:$k}) SET m.data = $data, m.updated_at = timestamp()",
        {"k": key, "data": json.dumps(data)},
    )


def _tunables() -> Dict[str, int]:
    """Runtime-tunable bounds, resolved through the Configuration panel."""
    try:
        return _settings.resolve_many([
            "NOTIFY_SWEEP_INTERVAL", "NOTIFY_RETENTION",
            "NOTIFY_MAX_PER_SWEEP", "NOTIFY_ACTIVE_MINUTES",
            # WF13's open-bucket exposure threshold. It used to gate WF13's own
            # (now removed) Slack alert; the feed is now its only consumer, so it
            # is resolved here and applied in _sweep_buckets.
            "BUCKET_ALERT_MIN_SCORE",
        ])
    except Exception:
        return {"NOTIFY_SWEEP_INTERVAL": 120, "NOTIFY_RETENTION": 500,
                "NOTIFY_MAX_PER_SWEEP": 25, "NOTIFY_ACTIVE_MINUTES": 30,
                "BUCKET_ALERT_MIN_SCORE": 40}


# ── Schema ───────────────────────────────────────────────────────────────────

_schema_ready = False


def ensure_schema() -> None:
    """Idempotent constraint + index creation, attempted once per process.

    The UNIQUE constraint on dedup_key is the real concurrency backstop. The
    sweep lease below serialises the common case, but a constraint is what makes
    a double-create IMPOSSIBLE rather than merely unlikely -- MERGE alone can
    race, and two operators refreshing at the same instant is the normal case,
    not the exotic one.

    The :SpotterMeta(key) index matters because notification nodes are
    dual-labelled: without it, every settings and campaign-registry lookup in
    the whole product degrades into a label scan over the entire feed as it
    grows. Adding the feed must not slow down code that predates it.
    """
    global _schema_ready
    if _schema_ready:
        return
    for stmt in (
        "CREATE CONSTRAINT spotter_notification_dedup IF NOT EXISTS "
        "FOR (n:SpotterNotification) REQUIRE n.dedup_key IS UNIQUE",
        "CREATE INDEX spotter_meta_key IF NOT EXISTS FOR (m:SpotterMeta) ON (m.key)",
    ):
        try:
            _acl._cypher(stmt)
        except Exception:
            # An older Neo4j, a read-only replica, or a constraint that already
            # exists under another name. The feed still works without either --
            # the constraint is defence in depth and the index is a speed-up.
            pass
    _schema_ready = True


# ── Emit ─────────────────────────────────────────────────────────────────────

def notification_id(dedup_key: str) -> str:
    """Stable id derived from the dedup key rather than a random UUID, so that
    re-emitting the same event keeps the id an operator may already have marked
    read."""
    return hashlib.sha1(dedup_key.encode("utf-8")).hexdigest()[:16]


def emit(
    campaign_id: str,
    kind: str,
    severity: str,
    title: str,
    dedup_key: str,
    detail: str = "",
    target_label: str = "",
    target_kind: str = "",
    target_id: str = "",
    baseline: bool = False,
    when: Optional[datetime] = None,
) -> bool:
    """Create one notification unless dedup_key has been seen. True if created.

    `baseline=True` records the dedup marker WITHOUT producing anything an
    operator sees. That is how the first sweep of a campaign avoids emptying
    the entire pre-existing backlog into the ticker at once, while still
    ensuring the same event is not re-reported as "new" a minute later.

    Single MERGE, so this is atomic and idempotent by construction: no read,
    no check, no window between them.

    NOTE: this MUST NOT write a `key` property. Neo4j carries a UNIQUENESS
    constraint `spotter_meta_key_unique` on :SpotterMeta(key) -- it is what
    keeps the singleton blobs ('campaigns', 'settings', each notify_* key)
    from ever being duplicated by two racing MERGEs, so it is correct and
    stays. Because notification nodes are deliberately dual-labelled, they are
    inside that constraint's scope: the original code set n.key='notification'
    on every one of them, so the FIRST notification ever created claimed the
    key and every later emit died with ConstraintValidationFailed. Uniqueness
    is not enforced against a missing property, so carrying no `key` at all is
    what lets the feed hold more than a single row. The :SpotterNotification
    label already identifies these nodes; the key property was never read.
    """
    dt = when or _now()
    # The _new flag is how "did this MERGE actually create something?" is
    # answered: ON CREATE sets it, the REMOVE clears it again in the same
    # statement, so a second call for the same dedup_key reports False. Without
    # it every re-observation would count as a new notification and the
    # `created` figure -- the one number that tells an operator the sweep is
    # working -- would be noise.
    rows = _rows(_acl._cypher(
        "MERGE (n:SpotterMeta:SpotterNotification {dedup_key:$dedup}) "
        "ON CREATE SET n.id = $id, "
        "  n.campaign_id = $camp, n.kind = $kind, n.severity = $sev, "
        "  n.title = $title, n.detail = $detail, n.target_label = $tlabel, "
        "  n.target_kind = $tkind, n.target_id = $tid, "
        "  n.ts = $ts, n.ts_ms = $ts_ms, n.baseline = $baseline, n._new = true "
        "WITH n, coalesce(n._new, false) AS created "
        "REMOVE n._new "
        "RETURN created",
        {
            "dedup": dedup_key, "id": notification_id(dedup_key),
            "camp": str(campaign_id or ""), "kind": kind,
            "sev": severity if severity in _SEV_ORDER else "info",
            "title": title[:300], "detail": (detail or "")[:500],
            "tlabel": (target_label or "")[:200], "tkind": target_kind or "",
            "tid": (target_id or "")[:200],
            "ts": _iso(dt), "ts_ms": _ms(dt), "baseline": bool(baseline),
        },
    ))
    return bool(rows and rows[0] and rows[0][0])


# ── Read marks ───────────────────────────────────────────────────────────────
# Read state is per operator and lives in its own (:SpotterMeta) node keyed by
# campaign AND user, so two operators reading the same feed can never overwrite
# each other's marks -- the one place a shared blob would genuinely race.
#
# Shape: {"read_ms": <watermark>, "ids": [<ids newer than the watermark>]}
# "Mark all read" moves the watermark and clears the id list, which is what
# keeps that list from growing without bound.

def _read_state(campaign_id: str, user: str) -> Dict[str, Any]:
    st = _meta_read(_K_READ.format(camp=campaign_id, user=user or "unknown"))
    return {"read_ms": _int(st.get("read_ms"), 0),
            "ids": [str(i) for i in (st.get("ids") or []) if i]}


def mark_read(campaign_id: str, user: str, ids: Optional[Iterable[str]] = None,
              mark_all: bool = False) -> Dict[str, Any]:
    key = _K_READ.format(camp=campaign_id, user=user or "unknown")
    st = _read_state(campaign_id, user)
    if mark_all:
        st = {"read_ms": _ms(_now()), "ids": []}
    else:
        st["ids"] = sorted(set(st["ids"]) | {str(i) for i in (ids or []) if i})
    _meta_write(key, st)
    return st


# ── List ─────────────────────────────────────────────────────────────────────

def list_for(campaign_id: str, user: str, limit: int = 25,
             since_ms: int = 0) -> Tuple[List[Dict[str, Any]], int]:
    """Newest-first notifications for one campaign, with per-user read state.

    Returns (rows, unread_total). `unread_total` counts the whole feed, not the
    returned page -- the badge must not say "3" because the page size is 3.
    """
    limit = max(1, min(200, _int(limit, 25)))
    st = _read_state(campaign_id, user)
    read_ms, read_ids = st["read_ms"], set(st["ids"])

    rows = _rows(_acl._cypher(
        "MATCH (n:SpotterNotification {campaign_id:$camp}) "
        "WHERE n.baseline = false AND n.ts_ms > $since "
        "RETURN n.id, n.ts, n.ts_ms, n.kind, n.severity, n.title, n.detail, "
        "       n.target_label, n.target_kind, n.target_id "
        "ORDER BY n.ts_ms DESC LIMIT $limit",
        {"camp": campaign_id, "since": _int(since_ms, 0), "limit": limit},
    ))

    out: List[Dict[str, Any]] = []
    for r in rows:
        nid, ts, ts_ms = r[0], r[1], _int(r[2], 0)
        out.append({
            "id": nid, "ts": ts, "kind": r[3], "severity": r[4] or "info",
            "title": r[5] or "", "detail": r[6] or "",
            "target_label": r[7] or "", "target_kind": r[8] or "",
            "target_id": r[9] or "", "campaign_id": campaign_id,
            "read": bool(ts_ms <= read_ms or nid in read_ids),
        })

    # Counted across the WHOLE feed, not the page above: the badge must not read
    # "3" merely because the caller asked for three rows.
    count_rows = _rows(_acl._cypher(
        "MATCH (n:SpotterNotification {campaign_id:$camp}) "
        "WHERE n.baseline = false AND NOT (n.ts_ms <= $read_ms OR n.id IN $ids) "
        "RETURN count(n)",
        {"camp": campaign_id, "read_ms": read_ms, "ids": sorted(read_ids)},
    ))
    unread = _int(count_rows[0][0] if count_rows else 0, 0)
    return out, unread


# ── Retention ────────────────────────────────────────────────────────────────

def prune(campaign_id: str, keep: int = 500,
          live_campaign_ids: Optional[List[str]] = None) -> int:
    """Trim one campaign's feed to `keep` rows, and drop feeds whose campaign
    has left the registry.

    Retention is applied to the two kinds of row SEPARATELY, and that split is
    load-bearing rather than tidiness. Baseline rows are not feed entries at
    all -- they are the dedup ledger, the only record that a finding has
    already been accounted for. Trimming them against the same bound as the
    visible feed means that as soon as `keep` is exceeded the OLDEST rows go
    first, which is precisely the baseline markers; the next sweep then finds
    those findings unaccounted for, re-stages them, and -- the campaign now
    being baselined -- emits them as VISIBLE. A first sweep that baselines 455
    breach records would start re-reporting 2019 breaches as fresh news after
    45 real notifications, and would keep oscillating forever. So the ledger is
    kept an order of magnitude longer than the feed, and never below the most
    rows a single sweep can possibly stage (the per-source LIMITs total ~6000).
    """
    removed = 0
    keep_visible = max(10, _int(keep, 500))
    keep_marker = max(10 * keep_visible, 10_000)
    for baseline, bound in ((False, keep_visible), (True, keep_marker)):
        try:
            rows = _rows(_acl._cypher(
                "MATCH (n:SpotterNotification {campaign_id:$camp}) "
                "WHERE coalesce(n.baseline, false) = $baseline "
                "WITH n ORDER BY n.ts_ms DESC SKIP $keep "
                "DETACH DELETE n RETURN count(*)",
                {"camp": campaign_id, "keep": bound, "baseline": baseline},
            ))
            removed += _int(rows[0][0] if rows else 0, 0)
        except Exception:
            pass
    if live_campaign_ids is not None:
        try:
            rows = _rows(_acl._cypher(
                "MATCH (n:SpotterNotification) "
                "WHERE NOT coalesce(n.campaign_id, '') IN $live "
                "WITH n LIMIT 5000 DETACH DELETE n RETURN count(*)",
                {"live": [str(c) for c in live_campaign_ids]},
            ))
            removed += _int(rows[0][0] if rows else 0, 0)
        except Exception:
            pass
    return removed


# ── Sweep ────────────────────────────────────────────────────────────────────

def _take_lease(campaign_id: str, interval_s: int) -> bool:
    """Atomic compare-and-set on the sweep lease. True if this caller may sweep.

    The `SET m._lock = timestamp()` line looks like dead code and is NOT --
    do not remove it. It forces Neo4j to take the node's write lock BEFORE the
    lease value is read in the following WITH, which serialises concurrent
    callers. Without it, two polls landing in the same tick both read the old
    value, both decide the lease is free, and both sweep -- and with N browsers
    open on a campaign, "the same tick" is the normal case.

    (Even if this were defeated, the UNIQUE constraint on dedup_key means the
    worst outcome is wasted work, never a duplicated notification.)
    """
    now = _now()
    cutoff = _ms(now - timedelta(seconds=max(15, interval_s)))
    rows = _rows(_acl._cypher(
        "MERGE (m:SpotterMeta {key:$k}) "
        "SET m._lock = timestamp() "
        "WITH m, coalesce(m.lease_ms, 0) AS prev "
        "WHERE prev <= $cutoff "
        "SET m.lease_ms = $now "
        "RETURN prev",
        {"k": _K_LEASE.format(camp=campaign_id), "cutoff": cutoff, "now": _ms(now)},
    ))
    return bool(rows)


def _q(sketch_id: str, stmt: str, cap: int) -> List[list]:
    return _rows(_acl._cypher(stmt, {"sid": sketch_id, "cap": cap}))


def sweep(campaign_id: str, sketch_id: str) -> Dict[str, Any]:
    """Derive new notifications for one campaign. Never raises.

    Returns {"swept": bool, "created": int, "errors": [...]}. A source that
    fails is reported and skipped; one broken source must not cost the operator
    the other four.
    """
    out: Dict[str, Any] = {"swept": False, "created": 0, "errors": []}
    if not campaign_id or not sketch_id:
        return out

    tun = _tunables()
    try:
        if not _take_lease(campaign_id, tun["NOTIFY_SWEEP_INTERVAL"]):
            return out
    except Exception as exc:
        out["errors"].append(f"lease: {exc}".replace("\n", " ")[:200])
        return out
    out["swept"] = True

    try:
        ensure_schema()
    except Exception:
        pass

    state = _meta_read(_K_AGENTS.format(camp=campaign_id))
    baselined = bool(state.get("baselined"))
    # The first sweep of a campaign records markers silently. Everything found
    # now predates the feature; showing it would open the ticker with a wall of
    # history and bury whatever happens next.
    budget = 10_000 if not baselined else max(1, _int(tun["NOTIFY_MAX_PER_SWEEP"], 25))
    created = 0
    pending: List[Dict[str, Any]] = []

    def stage(**kw: Any) -> None:
        pending.append(kw)

    for source in (_sweep_attack_paths, _sweep_agents, _sweep_breaches,
                   _sweep_alert_tags, _sweep_buckets):
        try:
            source(sketch_id, campaign_id, state, stage, tun)
        except Exception as exc:
            out["errors"].append(f"{source.__name__}: {exc}".replace("\n", " ")[:200])

    # Severity-first so that when the per-sweep cap bites, what gets dropped is
    # the least urgent thing rather than whatever happened to be read last.
    pending.sort(key=lambda p: _SEV_ORDER.get(p.get("severity", "info"), 3))

    # Drop everything already in the ledger BEFORE the cap is applied. What the
    # sources stage is "every finding in the graph", not "every new finding" --
    # a mature campaign re-stages its whole history on every single sweep. Cap
    # that list directly and two things go wrong, both of them permanent:
    # `dropped` becomes len(history) - 25 on every sweep, so the rollup fires
    # once a minute forever announcing findings that were reported weeks ago;
    # and the 25-item budget is spent re-MERGEing rows that already exist, so a
    # genuinely new finding sitting at position 26 is never reached and never
    # reported. Deduping here makes the budget and the rollup both count NEW
    # work, which is what they were always described as counting. One indexed
    # lookup against the UNIQUE dedup_key replaces up to `budget` no-op round
    # trips, so this is cheaper than what it replaces.
    fresh = pending
    try:
        keys = [str(p.get("dedup_key") or "") for p in pending]
        known = {r[0] for r in _rows(_acl._cypher(
            "MATCH (n:SpotterNotification) WHERE n.dedup_key IN $keys "
            "RETURN n.dedup_key", {"keys": keys}))}
        fresh = [p for p in pending if str(p.get("dedup_key") or "") not in known]
    except Exception as exc:
        # Fall back to the undeduped list: emit() is still idempotent, so the
        # cost is a noisy rollup for one sweep, not a duplicated notification.
        out["errors"].append(f"dedup: {exc}".replace("\n", " ")[:200])

    now = _now()
    for item in fresh[:budget]:
        try:
            if emit(campaign_id=campaign_id, baseline=not baselined, when=now, **item):
                created += 1
        except Exception as exc:
            out["errors"].append(f"emit: {exc}".replace("\n", " ")[:200])
    dropped = max(0, len(fresh) - budget)
    if dropped and baselined:
        # Never silently truncate: a capped sweep that says nothing reads as
        # "that was everything".
        try:
            emit(campaign_id=campaign_id, kind="rollup", severity="info",
                 title=f"+{dropped} more findings this sweep",
                 detail="Raised the per-sweep cap in Configuration to see them all.",
                 dedup_key=f"rollup:{campaign_id}:{_ms(now) // 60000}", when=now)
        except Exception:
            pass

    state["baselined"] = True
    try:
        _meta_write(_K_AGENTS.format(camp=campaign_id), state)
    except Exception as exc:
        out["errors"].append(f"state: {exc}".replace("\n", " ")[:200])

    try:
        prune(campaign_id, tun["NOTIFY_RETENTION"])
    except Exception:
        pass

    out["created"] = created
    return out


# ── Sweep sources ────────────────────────────────────────────────────────────
# Each reads with a LABEL-anchored query so Neo4j does a label scan rather than
# a full-graph property scan; on an AD-sized sketch the difference is the whole
# cost of the feature. A label that does not exist yields zero rows without
# error, which is what makes the CloudAsset source safe to ship unverified.

def _sweep_attack_paths(sid, camp, state, stage, tun) -> None:
    """WF04 writes attack_score / is_high_value back onto Individuals."""
    for label, score, hv, summary in _q(sid,
        "MATCH (n:individual {sketch_id:$sid}) "
        "WHERE n.deleted_at IS NULL AND n.`nodeProperties.attack_score` IS NOT NULL "
        "RETURN n.nodeLabel, n.`nodeProperties.attack_score`, "
        "       n.`nodeProperties.is_high_value`, n.`nodeProperties.attack_summary` "
        "ORDER BY n.`nodeProperties.attack_score` DESC LIMIT $cap", 500):
        if not label or not _truthy(hv):
            continue
        score_i = _int(score, 0)
        hops = ""
        exploit = ""
        try:
            parsed = json.loads(summary) or {}
            paths = parsed.get("total_paths")
            hops = f"{paths} paths" if paths else ""
            # How much of the score is public exploit code, and against what.
            # A path that ranks because somebody has already written the exploit
            # is a different call than one that ranks on ACEs alone, and the
            # ticker is where that difference gets acted on.
            ex = parsed.get("exploit") or {}
            if ex.get("bonus"):
                asset = (ex.get("assets") or [{}])[0]
                name = asset.get("asset") or "unnamed component"
                exploit = (f"exploit +{_int(ex['bonus'], 0)} ({name}, "
                           f"{asset.get('trust', '?')}-trust PoC)")
        except Exception:
            pass
        stage(kind="attack_path", severity="critical",
              title=f"High-value attack path — {label}",
              detail=" · ".join(x for x in (f"score {score_i}", hops, exploit) if x),
              target_label=label, target_kind="individual",
              # Score in the key, so a re-run at the same score is silent but a
              # RAISED score re-notifies -- that is the part worth knowing.
              dedup_key=f"path:{camp}:{label}:{score_i}")


def _sweep_agents(sid, camp, state, stage, tun) -> None:
    """C2 liveness. The one source needing prior state: a transition is only
    visible against the previous status."""
    active_minutes = max(1, _int(tun.get("NOTIFY_ACTIVE_MINUTES"), 30))
    now = _now()
    prev: Dict[str, str] = dict(state.get("agents") or {})
    seen: Dict[str, str] = {}

    # `c2_framework`, NOT `framework`. Nothing has ever written a bare `framework`
    # key -- every writer (WF01/WF21/WF28, upload_router, migrate_c2session) stores
    # c2_framework -- so this column returned null for every row and the framework
    # silently dropped out of the `who` detail line below. The property is
    # unresolvable rather than wrong, so Neo4j returned null instead of erroring and
    # the feed looked healthy. Same misspelling was in README's verification query.
    rows = _q(sid,
        "MATCH (n:C2Session {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
        "RETURN n.nodeLabel, n.`nodeProperties.session_id`, n.`nodeProperties.last_checkin`, "
        "       n.`nodeProperties.is_dead`, n.`nodeProperties.hostname`, "
        "       n.`nodeProperties.username`, n.`nodeProperties.c2_framework` LIMIT $cap "
        "UNION "
        "MATCH (n:CobaltBeacon {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
        "RETURN n.nodeLabel, n.`nodeProperties.session_id`, n.`nodeProperties.last_checkin`, "
        "       n.`nodeProperties.is_dead`, n.`nodeProperties.hostname`, "
        "       n.`nodeProperties.username`, n.`nodeProperties.c2_framework` LIMIT $cap", 1000)

    for label, session_id, last_checkin, is_dead, hostname, username, framework in rows:
        key = str(session_id or label or "").strip()
        if not key:
            continue
        dt = _parse_dt(last_checkin)
        age = (now - dt).total_seconds() / 60.0 if dt else None
        if _truthy(is_dead):
            status = "dead"
        elif age is None or age < -_SKEW_MINUTES:
            status = "unknown"
        elif age < active_minutes:
            status = "live"
        else:
            status = "stale"
        seen[key] = status

        was = prev.get(key)
        if was == status:
            continue
        # Legacy CobaltBeacon nodes predate the discriminator, so COALESCE the way
        # WF01/WF21/WF23 all do, then render the operator-facing label rather than
        # the raw key: this line is read in the header ticker, and "Adaptix C2"
        # belongs there, not "adaptix".
        fw = (framework or "cobalt_strike").strip().lower()
        fw_label = framework_display(fw)["label"]
        who = " · ".join(x for x in (hostname, username, fw_label) if x)
        if was is None:
            title, sev = f"New agent — {hostname or label}", "info"
        elif status == "dead":
            title, sev = f"Agent died — {hostname or label}", "warn"
        elif status == "stale":
            title, sev = f"Agent went stale — {hostname or label}", "warn"
        elif status == "live":
            title, sev = f"Agent returned — {hostname or label}", "info"
        else:
            continue
        stage(kind="agent_status", severity=sev, title=title, detail=who,
              target_label=label or key, target_kind="agent", target_id=key,
              # Hour bucket: a beacon flapping across the 30-minute threshold
              # must not produce a notification every single sweep.
              dedup_key=f"agent:{camp}:{key}:{status}:{_ms(now) // 3_600_000}")

    state["agents"] = seen


def _sweep_breaches(sid, camp, state, stage, tun) -> None:
    """Breach records come from FlareBreach nodes, NOT from the alert tag.

    The STEALER_LOG_DETECTED / MULTIPLE_BREACHES tags are written by
    flare_breach_enricher, a Flowsint-container plugin that only runs if it was
    installed and invoked -- and its stealer test is `event_type ==
    'stealer_log'` while ASTP-sourced records are built with
    event_type='leaked_credentials', so ASTP stealer logs never raise the tag
    at all. Traversing HAS_BREACH is what the dossier already relies on and
    needs no label on the breach node, whose casing is not guaranteed.

    The notification is stamped with sweep time, not the record's own
    `imported_at` -- that field is FLARE's timestamp, so a 2019 breach carries
    a 2019 date and would sort to the bottom of a feed of new findings.
    """
    for owner, breach_id, event_type, source, hash_type, pw in _q(sid,
        "MATCH (i:individual {sketch_id:$sid})-[:HAS_BREACH]->(b) "
        "WHERE i.deleted_at IS NULL AND b.deleted_at IS NULL AND b.sketch_id = $sid "
        "RETURN i.nodeLabel, coalesce(b.`nodeProperties.breach_id`, b.nodeLabel), "
        "       b.`nodeProperties.event_type`, b.`nodeProperties.source`, "
        "       b.`nodeProperties.hash_type`, b.`nodeProperties.password_exposed` "
        "LIMIT $cap", 2000):
        if not owner or not breach_id:
            continue
        etype = str(event_type or "").lower()
        stealer = "stealer" in etype or "stealer" in str(source or "").lower()
        exposed = _truthy(pw) or str(hash_type or "").lower() in ("plain", "plaintext", "")
        stage(kind="breach", severity="critical" if (stealer or exposed) else "warn",
              title=("Stealer log — " if stealer else "Breach record — ") + str(owner),
              detail=" · ".join(x for x in (event_type, source,
                                            "password exposed" if exposed else "") if x),
              target_label=str(owner), target_kind="individual",
              dedup_key=f"breach:{camp}:{breach_id}")


def _sweep_alert_tags(sid, camp, state, stage, tun) -> None:
    """The enricher-written tag list. Covers the credential half of the feed
    (PASSWORD_REUSE, CORP_BREACH_CRED_MATCH) plus a belt-and-braces path to the
    breach tags when the enricher HAS run."""
    for label, alert in _q(sid,
        "MATCH (n:individual {sketch_id:$sid}) "
        "WHERE n.deleted_at IS NULL AND n.`nodeProperties.alert` IS NOT NULL "
        "  AND n.`nodeProperties.alert` <> '' "
        "RETURN n.nodeLabel, n.`nodeProperties.alert` LIMIT $cap", 2000):
        if not label:
            continue
        for tag in [t.strip() for t in str(alert).split(",") if t.strip()]:
            sev, enabled = _ALERT_TAGS.get(tag, ("info", False))
            if not enabled:
                continue
            stage(kind="alert_tag", severity=sev,
                  title=f"{tag.replace('_', ' ').title()} — {label}",
                  detail=tag, target_label=label, target_kind="individual",
                  dedup_key=f"alert:{camp}:{label}:{tag}")


def _sweep_buckets(sid, camp, state, stage, tun) -> None:
    """Publicly listable cloud storage found by WF13.

    WF13 persists CloudAsset nodes with endpoint / exposure_score / provider /
    service / object_count and the public/listable exposure flags. Keep the
    legacy is_open read because older campaigns may still contain it; a label
    or property that does not exist yields NULL in Neo4j, not an error.
    """
    # Only surface exposures at or above the operator's configured minimum, the
    # same bar WF13's old Slack open-bucket alert used (BUCKET_ALERT_MIN_SCORE).
    min_score = _int(tun.get("BUCKET_ALERT_MIN_SCORE"), 40)
    for label, endpoint, score, provider, service, objects, is_open, public, listable in _q(sid,
        "MATCH (n:CloudAsset {sketch_id:$sid}) WHERE n.deleted_at IS NULL "
        "RETURN n.nodeLabel, n.`nodeProperties.endpoint`, "
        "       n.`nodeProperties.exposure_score`, n.`nodeProperties.provider`, "
        "       n.`nodeProperties.service`, n.`nodeProperties.object_count`, "
        "       n.`nodeProperties.is_open`, n.`nodeProperties.public`, "
        "       n.`nodeProperties.listable` LIMIT $cap", 500):
        score_i = _int(score, 0)
        open_confirmed = _truthy(is_open) or _truthy(public) or _truthy(listable)
        if score_i > 0:
            if score_i < min_score:
                continue          # scored, but below the operator's threshold
        elif not open_confirmed:
            continue              # no score and nothing marking it open/public
        # else: confirmed open but unscored -- surfaced rather than hidden, since a
        # missing score is unknown risk, not low risk.
        name = str(endpoint or label or "")
        stage(kind="cloud_bucket", severity="critical",
              title=f"Open cloud storage — {name}",
              detail=" · ".join(x for x in (
                  f"{provider or ''}/{service or ''}".strip("/"),
                  f"{_int(objects, 0)} objects" if objects else "",
                  f"score {_int(score, 0)}" if score else "") if x),
              target_label=name, target_kind="bucket",
              dedup_key=f"bucket:{camp}:{name}")


# ── Webhook entry point ──────────────────────────────────────────────────────

def handle(_items: Any) -> Dict[str, Any]:
    """The whole of WF24's code node. Never raises.

    Authorisation follows WF07's precedent rather than WF23's: the caller is
    resolved from the nginx-stamped header, checked against the campaign, and
    the sketch is then taken FROM THE REGISTRY. Trusting a sketch_id in the
    request body -- which WF23 does, harmlessly, for a roster -- would here let
    one operator sweep another operator's graph into their own ticker.
    """
    errors: List[str] = []
    body = _acl.body_of(_items) or {}
    user = _acl.caller(_items)
    action = str(body.get("action") or "list").strip().lower()
    campaign_id = str(body.get("campaign_id") or "").strip()

    if not user:
        return {"error": "unauthenticated", "notifications": [], "unread": 0,
                "errors": ["unauthenticated"]}
    if not campaign_id:
        # No campaign selected yet is a normal UI state on first load, not an
        # error worth painting red in the header.
        return {"notifications": [], "unread": 0, "errors": [],
                "generated_at": _iso(_now())}

    try:
        camps = _acl.read_campaigns()
    except Exception as exc:
        camps = []
        errors.append(f"registry: {exc}".replace("\n", " ")[:200])

    camp = next((c for c in camps
                 if isinstance(c, dict) and str(c.get("id") or "") == campaign_id), None)
    if camp is not None and not _acl.can_read(camp, user):
        return {"error": "not authorised for this campaign",
                "notifications": [], "unread": 0, "errors": []}
    sketch_id = str((camp or {}).get("sketchId") or "")

    if action == "mark_read":
        try:
            mark_read(campaign_id, user,
                      ids=body.get("ids") or [], mark_all=bool(body.get("all")))
        except Exception as exc:
            errors.append(f"mark_read: {exc}".replace("\n", " ")[:200])
        rows, unread = [], 0
        try:
            rows, unread = list_for(campaign_id, user, _int(body.get("limit"), 25))
        except Exception as exc:
            errors.append(f"list: {exc}".replace("\n", " ")[:200])
        return {"ok": True, "notifications": rows, "unread": unread,
                "errors": errors, "generated_at": _iso(_now())}

    swept = sweep(campaign_id, sketch_id)
    errors.extend(swept.get("errors") or [])
    try:
        rows, unread = list_for(campaign_id, user,
                                _int(body.get("limit"), 25),
                                _int(body.get("since"), 0))
    except Exception as exc:
        rows, unread = [], 0
        errors.append(f"list: {exc}".replace("\n", " ")[:200])

    return {"notifications": rows, "unread": unread,
            "swept": swept.get("swept", False), "created": swept.get("created", 0),
            "sketch_id": sketch_id, "campaign_id": campaign_id,
            "generated_at": _iso(_now()), "errors": errors}
