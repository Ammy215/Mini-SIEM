from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from auth.audit import log_action
from auth.deps import CurrentUser
from auth.rbac import require_role
from database import get_pool
from detection import engine
from models.detection import DetectRangeRequest, DetectRunResult

router = APIRouter()

MAX_RANGE_DAYS = 30


@router.post("/api/detect/run", response_model=DetectRunResult)
async def run_detection(
    request: Request,
    body: DetectRangeRequest | None = None,
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    """A detection pass now. With a body {"from", "to"} (admin only), every
    enabled rule runs over that past range instead."""
    if body is not None:
        if "admin" not in current_user.roles:
            raise HTTPException(status_code=403, detail="Only admins can run detection over a past time range")
        if body.time_to <= body.time_from:
            raise HTTPException(status_code=422, detail="to must be after from")
        if body.time_to - body.time_from > timedelta(days=MAX_RANGE_DAYS):
            raise HTTPException(status_code=422, detail=f"A range can cover at most {MAX_RANGE_DAYS} days")

    pool = get_pool()
    async with pool.acquire() as conn:
        try:
            if body is None:
                results = await engine.run_all(conn)
            else:
                results = await engine.run_range(conn, body.time_from, body.time_to)
                await log_action(
                    conn, user_id=current_user.id, action="detection_range_run",
                    detail={"from": body.time_from.isoformat(), "to": body.time_to.isoformat(),
                            "alerts_created": results["range_alerts_created"]},
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent"),
                )
        except engine.DetectionAlreadyRunning:
            raise HTTPException(
                status_code=409,
                detail="A detection run is already in progress. Try again in a few seconds.",
            )

    return DetectRunResult(results=results, ran_at=datetime.now(timezone.utc))
