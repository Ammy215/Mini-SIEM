from fastapi import APIRouter, Depends, HTTPException, Query

from auth.deps import CurrentUser, get_current_user
from database import get_pool
from models.alerts import alert_summary_from_row
from models.incidents import IncidentDetail, IncidentListResponse, IncidentSummary

router = APIRouter()


@router.get("/api/incidents", response_model=IncidentListResponse)
async def list_incidents(
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: CurrentUser = Depends(get_current_user),
):
    pool = get_pool()
    where: list[str] = []
    params: list = []
    if status:
        params.append(status)
        where.append(f"status = ${len(params)}")
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    async with pool.acquire() as conn:
        total = await conn.fetchval(f"SELECT COUNT(*) FROM incidents {where_sql}", *params)
        rows = await conn.fetch(
            f"""
            SELECT id, title, source_ip, severity, status, alert_count, first_seen, last_seen, created_at
            FROM incidents {where_sql}
            ORDER BY last_seen DESC NULLS LAST, created_at DESC
            LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}
            """,
            *params, limit, offset,
        )

    incidents = [_to_incident_summary(r) for r in rows]
    return IncidentListResponse(incidents=incidents, total=total)


@router.get("/api/incidents/{incident_id}", response_model=IncidentDetail)
async def get_incident(incident_id: int, current_user: CurrentUser = Depends(get_current_user)):
    pool = get_pool()
    async with pool.acquire() as conn:
        incident = await conn.fetchrow(
            """
            SELECT id, title, source_ip, severity, status, alert_count, first_seen, last_seen, created_at
            FROM incidents WHERE id = $1
            """,
            incident_id,
        )
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        alert_rows = await conn.fetch(
            """
            SELECT id, rule_id, incident_id, title, severity, mitre_technique, source_ip, threat_score, status, created_at
            FROM alerts WHERE incident_id = $1 ORDER BY created_at ASC
            """,
            incident_id,
        )

    alerts = [alert_summary_from_row(r) for r in alert_rows]

    summary = _to_incident_summary(incident)
    return IncidentDetail(**summary.model_dump(), alerts=alerts)


def _to_incident_summary(row) -> IncidentSummary:
    return IncidentSummary(
        id=row["id"], title=row["title"],
        source_ip=str(row["source_ip"]) if row["source_ip"] else None,
        severity=row["severity"], status=row["status"], alert_count=row["alert_count"],
        first_seen=row["first_seen"], last_seen=row["last_seen"], created_at=row["created_at"],
    )
