import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from auth.audit import log_action
from auth.deps import CurrentUser, get_current_user
from auth.rbac import require_role
from database import get_pool
from models.alerts import AlertDetail, AlertListResponse, AlertUpdate, alert_summary_from_row

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


@router.put("/api/alerts/{alert_id}", response_model=AlertDetail)
async def update_alert(
    alert_id: int,
    body: AlertUpdate,
    request: Request,
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    pool = get_pool()
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT id, status FROM alerts WHERE id = $1", alert_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Alert not found")

        if body.status == "acknowledged":
            row = await conn.fetchrow(
                """
                UPDATE alerts
                SET status = $2, acknowledged_by = $3, acknowledged_at = now()
                WHERE id = $1
                RETURNING id, rule_id, incident_id, title, severity, mitre_technique, source_ip,
                          threat_score, status, evidence, acknowledged_by, acknowledged_at, created_at
                """,
                alert_id, body.status, current_user.id,
            )
        else:
            row = await conn.fetchrow(
                """
                UPDATE alerts SET status = $2 WHERE id = $1
                RETURNING id, rule_id, incident_id, title, severity, mitre_technique, source_ip,
                          threat_score, status, evidence, acknowledged_by, acknowledged_at, created_at
                """,
                alert_id, body.status,
            )

        await log_action(
            conn, user_id=current_user.id, action="alert_status_changed",
            detail={"alert_id": alert_id, "from_status": existing["status"], "to_status": body.status},
            ip_address=ip_address, user_agent=user_agent,
        )

    return AlertDetail(
        id=row["id"], rule_id=row["rule_id"], incident_id=row["incident_id"],
        title=row["title"], severity=row["severity"], mitre_technique=row["mitre_technique"],
        source_ip=str(row["source_ip"]) if row["source_ip"] else None,
        threat_score=row["threat_score"], status=row["status"],
        evidence=json.loads(row["evidence"]) if row["evidence"] else {},
        acknowledged_by=str(row["acknowledged_by"]) if row["acknowledged_by"] else None,
        acknowledged_at=row["acknowledged_at"], created_at=row["created_at"],
    )
