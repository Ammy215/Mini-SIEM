import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime

from detection import correlate, enrich_alerts, rule_engine, seeding, signature, threshold
from detection.rule_engine import Scope
from enrichment import geo

logger = logging.getLogger(__name__)

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
        results.update(await rule_engine.run_rules(conn, "sequence"))
        # At most one queued upload per pass, so a big file can't hold up live detection for long.
        results.update(await analyze_next_batch(conn))
        # Locations first, so enrichment's foreign_geo check finds them cached.
        results.update(await geo.run_all(conn))
        # enrichment runs before correlation: incidents inherit an alert's severity
        # once, at link time, so an alert must reach its final post-enrichment
        # severity before correlate.py folds it into an incident.
        results.update(await enrich_alerts.run_all(conn))
        results.update(await correlate.run_all(conn))
        return results


async def run_range(conn, time_from: datetime, time_to: datetime) -> dict[str, int]:
    """Every enabled rule over a past time range, then enrichment and correlation."""
    async with detection_lease(conn):
        rule_results, errors = await analyze_scope(conn, Scope(time_from, time_to))
        results = {**rule_results, "range_alerts_created": sum(rule_results.values()), "range_rule_errors": len(errors)}
        results.update(await enrich_alerts.run_all(conn))
        results.update(await correlate.run_all(conn))
        return results


async def analyze_scope(conn, scope: Scope) -> tuple[dict[str, int], dict[str, str]]:
    """({rule_key: alerts created}, {rule_key: why it failed}) for every enabled rule over the scope."""
    results: dict[str, int] = {}
    errors: dict[str, str] = {}
    for rule_type in ("threshold", "signature", "sequence"):
        results.update(await rule_engine.run_rules(conn, rule_type, scope, errors))
    return results, errors


async def analyze_next_batch(conn) -> dict[str, int]:
    """Analyses the longest-waiting queued upload, if there is one, over its
    own events and time span, and records the outcome on the batch."""
    batch = await conn.fetchrow(
        """
        UPDATE ingest_batches
        SET detection_status = 'running', detection_started_at = now(), detection_error = NULL
        WHERE id = (
            SELECT id FROM ingest_batches
            WHERE detection_status = 'queued'
            ORDER BY detection_requested_at NULLS FIRST, created_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, first_event_time, last_event_time
        """
    )
    if batch is None:
        return {}

    started = time.monotonic()
    try:
        if batch["first_event_time"] is None:
            rule_results, errors = {}, {}
        else:
            scope = Scope(batch["first_event_time"], batch["last_event_time"], batch_id=batch["id"])
            rule_results, errors = await analyze_scope(conn, scope)
    except Exception as exc:
        logger.exception("analysis of upload batch %s failed", batch["id"])
        await conn.execute(
            """
            UPDATE ingest_batches SET detection_status = 'failed', detection_finished_at = now(), detection_error = $2
            WHERE id = $1
            """,
            batch["id"], f"analysis failed ({type(exc).__name__})",
        )
        return {"batches_analyzed": 0, "batches_failed": 1}

    created = sum(rule_results.values())
    outcome = {
        "alerts_created": created,
        "rules": {key: count for key, count in rule_results.items() if count},
        "rule_errors": errors,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
    await conn.execute(
        """
        UPDATE ingest_batches SET detection_status = 'done', detection_finished_at = now(), detection_result = $2::jsonb
        WHERE id = $1
        """,
        batch["id"], json.dumps(outcome),
    )
    return {"batches_analyzed": 1, "batch_alerts_created": created}


async def requeue_interrupted_batches(conn) -> int:
    """At startup: an analysis still marked running was cut off by a restart."""
    status = await conn.execute(
        "UPDATE ingest_batches SET detection_status = 'queued' WHERE detection_status = 'running'"
    )
    return int(status.split()[-1])
