import asyncio
import logging

from detection import threshold

logger = logging.getLogger(__name__)


async def _tick(pool) -> None:
    async with pool.acquire() as conn:
        await threshold.run_all(conn)


async def run_scheduler_loop(pool, interval_seconds: int) -> None:
    while True:
        try:
            await _tick(pool)
        except Exception:
            logger.exception("detection scheduler tick failed")
        await asyncio.sleep(interval_seconds)
