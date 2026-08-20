import json

from fastapi import APIRouter, Depends, HTTPException, Query

from auth.deps import CurrentUser, get_current_user
from database import get_pool
from models.alerts import AlertDetail, AlertListResponse, alert_summary_from_row

router = APIRouter()


@router.get("/api/alerts", response_model=AlertListResponse)
async def list_alerts(
    status: str | None = Query(None),
    severity: str | None = Query(None),
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
    if severity:
        params.append(severity)
        where.append(f"severity = ${len(params)}")
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    async with pool.acquire() as conn:
        total = await conn.fetchval(f"SELECT COUNT(*) FROM alerts {where_sql}", *params)
        rows = await conn.fetch(
            f"""
            SELECT id, rule_id, incident_id, title, severity, mitre_technique, source_ip, threat_score, status, created_at
            FROM alerts {where_sql}
            ORDER BY created_at DESC
            LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}
            """,
            *params, limit, offset,
        )

    alerts = [alert_summary_from_row(r) for r in rows]
    return AlertListResponse(alerts=alerts, total=total)


@router.get("/api/alerts/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: int, current_user: CurrentUser = Depends(get_current_user)):
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, rule_id, incident_id, title, severity, mitre_technique, source_ip,
                   threat_score, status, evidence, acknowledged_by, acknowledged_at, created_at
            FROM alerts WHERE id = $1
            """,
            alert_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Alert not found")

    return AlertDetail(
        id=row["id"], rule_id=row["rule_id"], incident_id=row["incident_id"],
        title=row["title"], severity=row["severity"], mitre_technique=row["mitre_technique"],
        source_ip=str(row["source_ip"]) if row["source_ip"] else None,
        threat_score=row["threat_score"], status=row["status"],
        evidence=json.loads(row["evidence"]) if row["evidence"] else {},
        acknowledged_by=str(row["acknowledged_by"]) if row["acknowledged_by"] else None,
        acknowledged_at=row["acknowledged_at"], created_at=row["created_at"],
    )
