import uuid
from contextlib import asynccontextmanager

from detection import correlate, enrich_alerts, seeding, signature, threshold

# How long a claimed run stays exclusive. A normal run takes seconds; the worst
# case (every capped provider lookup timing out) is a few minutes. If the
# process dies mid-run, the lease expires on its own and a later run proceeds.
LEASE_MINUTES = 15


class DetectionAlreadyRunning(Exception):
    pass


@asynccontextmanager
async def detection_lease(conn):
    """Claims the single detection_lease row for the duration of a run.

    Raises DetectionAlreadyRunning if another run holds an unexpired lease.
    Each claim gets a fresh holder id, so a run can only ever release its own
    lease — never one that expired and was claimed by a later run.
    """
    holder = uuid.uuid4()
    claimed = await conn.fetchval(
        """
        UPDATE detection_lease
        SET holder = $1, acquired_at = now(), expires_at = now() + make_interval(mins => $2)
        WHERE id = 1 AND (expires_at IS NULL OR expires_at <= now())
        RETURNING holder
        """,
        holder, LEASE_MINUTES,
    )
    if claimed is None:
        raise DetectionAlreadyRunning("a detection run is already in progress")
    try:
        yield holder
    finally:
        await conn.execute(
            "UPDATE detection_lease SET holder = NULL, acquired_at = NULL, expires_at = NULL "
            "WHERE id = 1 AND holder = $1",
            holder,
        )


async def seed_all(conn) -> None:
    await seeding.seed_builtin_rules(conn)


async def run_all(conn) -> dict[str, int]:
    async with detection_lease(conn):
        results = await threshold.run_all(conn)
        results.update(await signature.run_all(conn))
        # enrichment runs before correlation: incidents inherit an alert's severity
        # once, at link time, so an alert must reach its final post-enrichment
        # severity before correlate.py folds it into an incident.
        results.update(await enrich_alerts.run_all(conn))
        results.update(await correlate.run_all(conn))
        return results
