from fastapi import APIRouter

from database import get_pool

router = APIRouter()


@router.get("/api/health")
async def health():
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        db_status = "up"
    except Exception:
        db_status = "down"

    return {"status": "ok" if db_status == "up" else "degraded", "database": db_status}
