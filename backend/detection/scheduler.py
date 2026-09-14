import asyncio
import logging

from detection import engine

logger = logging.getLogger(__name__)


async def _tick(pool) -> None:
    async with pool.acquire() as conn:
        try:
            await engine.run_all(conn)
        except engine.DetectionAlreadyRunning:
            # A manual POST /api/detect/run is mid-flight; it covers this tick.
            logger.info("detection tick skipped: a run is already in progress")


async def run_scheduler_loop(pool, interval_seconds: int) -> None:
    while True:
        try:
            await _tick(pool)
        except Exception:
            logger.exception("detection scheduler tick failed")
        await asyncio.sleep(interval_seconds)
