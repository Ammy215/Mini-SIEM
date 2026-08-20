from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from auth.deps import CurrentUser
from auth.rbac import require_role
from database import get_pool
from detection import engine
from models.detection import DetectRunResult

router = APIRouter()


@router.post("/api/detect/run", response_model=DetectRunResult)
async def run_detection(current_user: CurrentUser = Depends(require_role("analyst", "admin"))):
    pool = get_pool()
    async with pool.acquire() as conn:
        results = await engine.run_all(conn)

    return DetectRunResult(results=results, ran_at=datetime.now(timezone.utc))
