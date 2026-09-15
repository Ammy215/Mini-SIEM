from datetime import datetime, timedelta, timezone
from functools import reduce
from typing import Literal

from fastapi import APIRouter, Depends, Query

from auth.deps import CurrentUser, get_current_user
from database import get_pool
from detection.mitre import TACTIC_ORDER, TECHNIQUES, tactics_of
from detection.scorer import SEVERITY_ORDER, max_severity
from enrichment.ip import NON_PUBLIC_NETWORKS
from models.stats import (
    BreakdownResponse, DashboardStats, GeoCountry, GeoResponse, MitreCoverageResponse, MitreTacticOut,
    MitreTechniqueOut, NamedCount, TimelineBucket, TimelineResponse, TopAttacker, TopAttackersResponse,
)
from routers._timerange import BUCKET_ORIGIN, TimeRange, floor_to_bucket, time_range

router = APIRouter()

# When an alert's attack happened. Alerts written before event times were
# recorded fall back to when the alert was created.
_ALERT_START = "COALESCE(first_event_time, created_at)"
_ALERT_END = "COALESCE(last_event_time, created_at)"
_SOURCE_SLICES = 7
_TOP_ACTIONS = 8


@router.get("/api/stats/dashboard", response_model=DashboardStats)
async def dashboard_stats(
    tr: TimeRange = Depends(time_range),
    current_user: CurrentUser = Depends(get_current_user),
):
    pool = get_pool()
    async with pool.acquire() as conn:
        total_events = await conn.fetchval("SELECT COUNT(*) FROM events")
        events_last_24h = await conn.fetchval(
            "SELECT COUNT(*) FROM events WHERE event_time >= now() - interval '24 hours'"
        )
        events_in_range = await conn.fetchval(
            "SELECT COUNT(*) FROM events WHERE event_time >= $1 AND event_time < $2", tr.start, tr.end
        )
        alerts_in_range = await conn.fetchval(
            f"SELECT COUNT(*) FROM alerts WHERE {_ALERT_START} >= $1 AND {_ALERT_START} < $2", tr.start, tr.end
        )
        open_alerts = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE status = 'open'")
        open_incidents = await conn.fetchval("SELECT COUNT(*) FROM incidents WHERE status = 'open'")
        severity_rows = await conn.fetch(
            "SELECT severity, COUNT(*) AS cnt FROM alerts WHERE status = 'open' GROUP BY severity"
        )

    return DashboardStats(
        total_events=total_events, events_last_24h=events_last_24h,
        open_alerts=open_alerts, open_incidents=open_incidents,
        alerts_by_severity=_by_severity(severity_rows),
        events_in_range=events_in_range, alerts_in_range=alerts_in_range,
        range_start=tr.start, range_end=tr.end,
    )


@router.get("/api/stats/timeline", response_model=TimelineResponse)
async def timeline_stats(
    hours: int | None = Query(None, ge=1, le=168, description="Older form of range: the last N hours, hourly"),
    tr: TimeRange = Depends(time_range),
    current_user: CurrentUser = Depends(get_current_user),
):
    if hours is not None and tr.label == "default":
        end = datetime.now(timezone.utc)
        tr = TimeRange(end - timedelta(hours=hours), end, timedelta(hours=1), f"{hours}h")

    pool = get_pool()
    async with pool.acquire() as conn:
        event_rows = await conn.fetch(
            """
            SELECT date_bin($3::interval, event_time, $4::timestamptz) AS bucket, COUNT(*) AS cnt
            FROM events WHERE event_time >= $1 AND event_time < $2
            GROUP BY 1
            """,
            tr.start, tr.end, tr.bucket, BUCKET_ORIGIN,
        )
        alert_rows = await conn.fetch(
            f"""
            SELECT date_bin($3::interval, {_ALERT_START}, $4::timestamptz) AS bucket, COUNT(*) AS cnt
            FROM alerts WHERE {_ALERT_START} >= $1 AND {_ALERT_START} < $2
            GROUP BY 1
            """,
            tr.start, tr.end, tr.bucket, BUCKET_ORIGIN,
        )

    event_counts = {row["bucket"]: row["cnt"] for row in event_rows}
    alert_counts = {row["bucket"]: row["cnt"] for row in alert_rows}
    buckets = []
    bucket = floor_to_bucket(tr.start, tr.bucket)
    while bucket < tr.end:
        buckets.append(TimelineBucket(
            bucket=bucket, event_count=event_counts.get(bucket, 0), alert_count=alert_counts.get(bucket, 0),
        ))
        bucket += tr.bucket

    return TimelineResponse(
        buckets=buckets, bucket_seconds=int(tr.bucket.total_seconds()), start=tr.start, end=tr.end,
    )


@router.get("/api/stats/top-attackers", response_model=TopAttackersResponse)
async def top_attackers(
    limit: int = Query(10, ge=1, le=50),
    tr: TimeRange = Depends(time_range),
    current_user: CurrentUser = Depends(get_current_user),
):
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT source_ip, COUNT(*) AS cnt, array_agg(severity) AS severities, MAX({_ALERT_END}) AS last_seen
            FROM alerts
            WHERE source_ip IS NOT NULL AND {_ALERT_END} >= $2 AND {_ALERT_START} < $3
            GROUP BY source_ip
            ORDER BY cnt DESC, last_seen DESC
            LIMIT $1
            """,
            limit, tr.start, tr.end,
        )

    attackers = [
        TopAttacker(
            source_ip=str(r["source_ip"]), alert_count=r["cnt"],
            max_severity=reduce(max_severity, r["severities"]),
            last_seen=r["last_seen"],
        )
        for r in rows
    ]
    return TopAttackersResponse(attackers=attackers)


@router.get("/api/stats/breakdown", response_model=BreakdownResponse)
async def breakdown(
    tr: TimeRange = Depends(time_range),
    current_user: CurrentUser = Depends(get_current_user),
):
    pool = get_pool()
    async with pool.acquire() as conn:
        logins = await conn.fetchrow(
            """
            SELECT COUNT(*) FILTER (WHERE action = 'login_success') AS success,
                   COUNT(*) FILTER (WHERE action = 'login_failed') AS failed
            FROM events WHERE event_time >= $1 AND event_time < $2
            """,
            tr.start, tr.end,
        )
        source_rows = await conn.fetch(
            """
            SELECT source_type AS name, COUNT(*) AS cnt FROM events
            WHERE event_time >= $1 AND event_time < $2
            GROUP BY 1 ORDER BY 2 DESC, 1
            """,
            tr.start, tr.end,
        )
        severity_rows = await conn.fetch(
            f"""
            SELECT severity, COUNT(*) AS cnt FROM alerts
            WHERE {_ALERT_START} >= $1 AND {_ALERT_START} < $2
            GROUP BY severity
            """,
            tr.start, tr.end,
        )
        action_rows = await conn.fetch(
            """
            SELECT action AS name, COUNT(*) AS cnt FROM events
            WHERE event_time >= $1 AND event_time < $2 AND action IS NOT NULL
            GROUP BY 1 ORDER BY 2 DESC, 1
            LIMIT $3
            """,
            tr.start, tr.end, _TOP_ACTIONS,
        )

    sources = [NamedCount(name=row["name"], count=row["cnt"]) for row in source_rows[:_SOURCE_SLICES]]
    rest = sum(row["cnt"] for row in source_rows[_SOURCE_SLICES:])
    if rest:
        sources.append(NamedCount(name="other", count=rest))

    return BreakdownResponse(
        start=tr.start, end=tr.end,
        logins={"success": logins["success"], "failed": logins["failed"]},
        events_by_source=sources,
        alerts_by_severity=_by_severity(severity_rows),
        top_actions=[NamedCount(name=row["name"], count=row["cnt"]) for row in action_rows],
    )


@router.get("/api/stats/geo", response_model=GeoResponse)
async def geo_breakdown(
    metric: Literal["alerts", "events"] = Query("alerts"),
    tr: TimeRange = Depends(time_range),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Where alerts (or events) came from, by the cached location of their
    source IP. Private and reserved addresses are never located, so never counted."""
    pool = get_pool()
    async with pool.acquire() as conn:
        if metric == "alerts":
            rows = await conn.fetch(
                """
                SELECT g.country, COUNT(*) AS cnt, array_agg(a.severity) AS severities
                FROM alerts a JOIN ip_geo g ON g.ip = a.source_ip
                WHERE g.country IS NOT NULL
                  AND COALESCE(a.first_event_time, a.created_at) >= $1 AND COALESCE(a.first_event_time, a.created_at) < $2
                GROUP BY g.country ORDER BY cnt DESC, g.country
                """,
                tr.start, tr.end,
            )
            unlocated = await conn.fetchval(
                """
                SELECT COUNT(*) FROM alerts a LEFT JOIN ip_geo g ON g.ip = a.source_ip
                WHERE a.source_ip IS NOT NULL AND g.ip IS NULL AND NOT (a.source_ip <<= ANY($3::cidr[]))
                  AND COALESCE(a.first_event_time, a.created_at) >= $1 AND COALESCE(a.first_event_time, a.created_at) < $2
                """,
                tr.start, tr.end, NON_PUBLIC_NETWORKS,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT g.country, COUNT(*) AS cnt, NULL::text[] AS severities
                FROM events e JOIN ip_geo g ON g.ip = e.source_ip
                WHERE g.country IS NOT NULL AND e.event_time >= $1 AND e.event_time < $2
                GROUP BY g.country ORDER BY cnt DESC, g.country
                """,
                tr.start, tr.end,
            )
            unlocated = await conn.fetchval(
                """
                SELECT COUNT(*) FROM events e LEFT JOIN ip_geo g ON g.ip = e.source_ip
                WHERE e.source_ip IS NOT NULL AND g.ip IS NULL AND NOT (e.source_ip <<= ANY($3::cidr[]))
                  AND e.event_time >= $1 AND e.event_time < $2
                """,
                tr.start, tr.end, NON_PUBLIC_NETWORKS,
            )

    return GeoResponse(
        start=tr.start, end=tr.end, metric=metric, unlocated=unlocated,
        countries=[
            GeoCountry(
                country=row["country"], count=row["cnt"],
                max_severity=reduce(max_severity, row["severities"]) if row["severities"] else None,
            )
            for row in rows
        ],
    )


@router.get("/api/stats/mitre", response_model=MitreCoverageResponse)
async def mitre_coverage(
    tr: TimeRange = Depends(time_range),
    current_user: CurrentUser = Depends(get_current_user),
):
    """The ATT&CK techniques this SIEM knows, by tactic: how many alerts each
    raised in the range, and how many enabled rules can raise it."""
    pool = get_pool()
    async with pool.acquire() as conn:
        alert_rows = await conn.fetch(
            f"""
            SELECT mitre_technique, COUNT(*) AS cnt FROM alerts
            WHERE mitre_technique IS NOT NULL AND {_ALERT_START} >= $1 AND {_ALERT_START} < $2
            GROUP BY 1
            """,
            tr.start, tr.end,
        )
        rule_rows = await conn.fetch(
            "SELECT mitre_technique, COUNT(*) AS cnt FROM rules WHERE enabled AND mitre_technique IS NOT NULL GROUP BY 1"
        )

    alerts = {row["mitre_technique"]: row["cnt"] for row in alert_rows}
    rules = {row["mitre_technique"]: row["cnt"] for row in rule_rows}

    by_tactic: dict[str, list[MitreTechniqueOut]] = {}
    for technique_id in sorted(TECHNIQUES):
        technique = MitreTechniqueOut(
            id=technique_id, name=TECHNIQUES[technique_id]["name"], tactics=tactics_of(technique_id),
            alert_count=alerts.get(technique_id, 0), enabled_rules=rules.get(technique_id, 0),
        )
        for tactic in technique.tactics:
            by_tactic.setdefault(tactic, []).append(technique)

    ordered = [t for t in TACTIC_ORDER if t in by_tactic] + sorted(set(by_tactic) - set(TACTIC_ORDER))
    return MitreCoverageResponse(
        start=tr.start, end=tr.end,
        tactics=[MitreTacticOut(tactic=tactic, techniques=by_tactic[tactic]) for tactic in ordered],
        techniques_covered=sum(1 for technique_id in TECHNIQUES if rules.get(technique_id)),
        techniques_with_alerts=sum(1 for technique_id in TECHNIQUES if alerts.get(technique_id)),
    )


def _by_severity(rows) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for row in rows:
        if row["severity"] in counts:
            counts[row["severity"]] = row["cnt"]
    return counts
