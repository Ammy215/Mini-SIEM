from functools import reduce

from fastapi import APIRouter, Depends, Query

from auth.deps import CurrentUser, get_current_user
from database import get_pool
from detection.scorer import max_severity
from models.stats import DashboardStats, TimelineBucket, TimelineResponse, TopAttacker, TopAttackersResponse

router = APIRouter()


@router.get("/api/stats/dashboard", response_model=DashboardStats)
async def dashboard_stats(current_user: CurrentUser = Depends(get_current_user)):
    pool = get_pool()
    async with pool.acquire() as conn:
        total_events = await conn.fetchval("SELECT COUNT(*) FROM events")
        events_last_24h = await conn.fetchval(
            "SELECT COUNT(*) FROM events WHERE event_time >= now() - interval '24 hours'"
        )
        open_alerts = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE status = 'open'")
        open_incidents = await conn.fetchval("SELECT COUNT(*) FROM incidents WHERE status = 'open'")
        severity_rows = await conn.fetch(
            "SELECT severity, COUNT(*) AS cnt FROM alerts WHERE status = 'open' GROUP BY severity"
        )

    alerts_by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for row in severity_rows:
        if row["severity"] in alerts_by_severity:
            alerts_by_severity[row["severity"]] = row["cnt"]

    return DashboardStats(
        total_events=total_events, events_last_24h=events_last_24h,
        open_alerts=open_alerts, open_incidents=open_incidents,
        alerts_by_severity=alerts_by_severity,
    )


@router.get("/api/stats/timeline", response_model=TimelineResponse)
async def timeline_stats(
    hours: int = Query(24, ge=1, le=168),
    current_user: CurrentUser = Depends(get_current_user),
):
    pool = get_pool()
    async with pool.acquire() as conn:
        event_rows = await conn.fetch(
            """
            SELECT date_trunc('hour', event_time) AS bucket, COUNT(*) AS cnt
            FROM events WHERE event_time >= now() - make_interval(hours => $1)
            GROUP BY bucket
            """,
            hours,
        )
        alert_rows = await conn.fetch(
            """
            SELECT date_trunc('hour', created_at) AS bucket, COUNT(*) AS cnt
            FROM alerts WHERE created_at >= now() - make_interval(hours => $1)
            GROUP BY bucket
            """,
            hours,
        )

    event_counts = {r["bucket"]: r["cnt"] for r in event_rows}
    alert_counts = {r["bucket"]: r["cnt"] for r in alert_rows}
    all_buckets = sorted(set(event_counts) | set(alert_counts))

    buckets = [
        TimelineBucket(bucket=b, event_count=event_counts.get(b, 0), alert_count=alert_counts.get(b, 0))
        for b in all_buckets
    ]
    return TimelineResponse(buckets=buckets)


@router.get("/api/stats/top-attackers", response_model=TopAttackersResponse)
async def top_attackers(
    limit: int = Query(10, ge=1, le=50),
    current_user: CurrentUser = Depends(get_current_user),
):
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT source_ip, COUNT(*) AS cnt, array_agg(severity) AS severities, MAX(created_at) AS last_seen
            FROM alerts
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT $1
            """,
            limit,
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
