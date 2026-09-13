import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from ai.summarize import (
    PROVIDER,
    AIProviderError,
    AIUnavailable,
    ai_configured,
    summarize_alert,
    summarize_incident,
)
from auth.audit import log_action
from auth.deps import CurrentUser
from auth.rate_limit import rate_limit
from auth.rbac import require_role
from config import settings
from database import get_pool
from models.ai_summary import AISummaryOut

router = APIRouter()

# Every click is a call to a third party against a quota; cap bursts.
_ai_rate_limit = rate_limit("ai", limit=20, window_minutes=1)

_ALERT_COLUMNS = "id, title, severity, mitre_technique, source_ip, threat_score, evidence"


def _alert_dict(row) -> dict:
    return {
        "title": row["title"],
        "severity": row["severity"],
        "mitre_technique": row["mitre_technique"],
        "source_ip": str(row["source_ip"]) if row["source_ip"] else None,
        "threat_score": row["threat_score"],
        "evidence": json.loads(row["evidence"]) if row["evidence"] else {},
    }


def _require_configured() -> None:
    if not ai_configured():
        raise HTTPException(status_code=503, detail="AI summaries are not configured on this server.")


async def _audit_egress(request: Request, current_user: CurrentUser, target: str, target_id: int) -> None:
    # Written BEFORE the provider call: the evidence leaves this server at that
    # moment, whether or not the provider then returns a usable summary.
    pool = get_pool()
    async with pool.acquire() as conn:
        await log_action(
            conn,
            user_id=current_user.id,
            action="ai_summary_requested",
            detail={"target": target, "target_id": target_id, "provider": PROVIDER, "model": settings.groq_model},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )


async def _call_provider(coro) -> str:
    try:
        return await coro
    except AIUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except AIProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.post("/api/alerts/{alert_id}/summary", response_model=AISummaryOut, dependencies=[Depends(_ai_rate_limit)])
async def summarize_alert_route(
    alert_id: int,
    request: Request,
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(f"SELECT {_ALERT_COLUMNS} FROM alerts WHERE id = $1", alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    _require_configured()

    await _audit_egress(request, current_user, "alert", alert_id)
    # The DB connection is released before the slow external call.
    summary = await _call_provider(summarize_alert(_alert_dict(row)))

    return AISummaryOut(
        target="alert", target_id=alert_id, summary=summary,
        provider=PROVIDER, model=settings.groq_model, generated_at=datetime.now(timezone.utc),
    )


@router.post(
    "/api/incidents/{incident_id}/summary", response_model=AISummaryOut, dependencies=[Depends(_ai_rate_limit)]
)
async def summarize_incident_route(
    incident_id: int,
    request: Request,
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    pool = get_pool()
    async with pool.acquire() as conn:
        inc = await conn.fetchrow(
            """
            SELECT id, title, severity, status, source_ip, alert_count, first_seen, last_seen
            FROM incidents WHERE id = $1
            """,
            incident_id,
        )
        if inc is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        alert_rows = await conn.fetch(
            f"SELECT {_ALERT_COLUMNS} FROM alerts WHERE incident_id = $1 ORDER BY created_at ASC",
            incident_id,
        )
    _require_configured()

    incident = {
        "title": inc["title"],
        "severity": inc["severity"],
        "status": inc["status"],
        "source_ip": str(inc["source_ip"]) if inc["source_ip"] else None,
        "alert_count": inc["alert_count"],
        "first_seen": inc["first_seen"],
        "last_seen": inc["last_seen"],
    }

    await _audit_egress(request, current_user, "incident", incident_id)
    summary = await _call_provider(summarize_incident(incident, [_alert_dict(r) for r in alert_rows]))

    return AISummaryOut(
        target="incident", target_id=incident_id, summary=summary,
        provider=PROVIDER, model=settings.groq_model, generated_at=datetime.now(timezone.utc),
    )
