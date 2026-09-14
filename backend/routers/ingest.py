import json
import logging
from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile
from pydantic import ValidationError

from auth.deps import CurrentUser
from auth.rate_limit import rate_limit
from auth.rbac import require_role
from database import get_pool
from models.events import EventIn, IngestResult, UploadResult
from parsers import app_json, nginx, ssh, syslog
from parsers.timeutil import InvalidTimestamp

logger = logging.getLogger(__name__)

router = APIRouter()

_ingest_rate_limit = rate_limit("ingest", limit=60, window_minutes=1)

_PARSERS = {
    "ssh": ssh,
    "nginx": nginx,
    "syslog": syslog,
    "app": app_json,
}

_INSERT_SQL = """
    INSERT INTO events (
        event_time, source_type, source_ip, dest_ip, dest_port, username,
        action, status_code, method, url, user_agent, country, raw_message, raw
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)
"""


def _event_to_row(event: dict) -> tuple:
    return (
        event.get("event_time") or datetime.now(timezone.utc),
        event["source_type"],
        event.get("source_ip"),
        event.get("dest_ip"),
        event.get("dest_port"),
        event.get("username"),
        event.get("action"),
        event.get("status_code"),
        event.get("method"),
        event.get("url"),
        event.get("user_agent"),
        event.get("country"),
        event.get("raw_message"),
        json.dumps(event["raw"]) if event.get("raw") is not None else None,
    )


async def _insert_events(conn, events: list[dict]) -> int:
    if not events:
        return 0
    rows = [_event_to_row(e) for e in events]
    await conn.executemany(_INSERT_SQL, rows)
    return len(rows)


@router.post("/api/ingest", response_model=IngestResult, dependencies=[Depends(_ingest_rate_limit)])
async def ingest(
    body: EventIn | list[EventIn],
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    events = [body.model_dump()] if isinstance(body, EventIn) else [e.model_dump() for e in body]

    pool = get_pool()
    async with pool.acquire() as conn:
        inserted = await _insert_events(conn, events)

    return IngestResult(ingested=inserted)


@router.post("/api/logs/upload", response_model=UploadResult, dependencies=[Depends(_ingest_rate_limit)])
async def upload_log(
    file: UploadFile,
    source_type: str = Form(...),
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    if source_type not in _PARSERS:
        raise HTTPException(status_code=400, detail=f"Unknown source_type. Expected one of {list(_PARSERS)}")

    parser = _PARSERS[source_type]
    # Uploaded files are treated as best-effort text: undecodable bytes become
    # U+FFFD and NUL bytes are dropped (PostgreSQL cannot store them). A corrupt
    # file degrades line-by-line rather than failing the whole upload — unlike
    # /api/ingest, which is a structured API and rejects bad input with a 422.
    content = (await file.read()).decode("utf-8", errors="replace").replace("\x00", "")
    lines = [line for line in content.splitlines() if line.strip()]

    events = []
    skipped_reasons: Counter[str] = Counter()
    for line in lines:
        try:
            parsed = parser.parse_line(line)
        except InvalidTimestamp:
            # e.g. `Feb 30`: the line has the right shape but no real date.
            skipped_reasons["invalid_timestamp"] += 1
            continue
        except Exception as exc:
            # One hostile line that trips a parser bug must not fail the whole
            # upload. Only the exception type is logged — never the line itself,
            # which is attacker-controlled.
            logger.warning("%s parser raised %s on an uploaded line", source_type, type(exc).__name__)
            skipped_reasons["parser_error"] += 1
            continue

        if parsed is None:
            skipped_reasons["unrecognized_format"] += 1
            continue

        # Run parsed lines through the same EventIn validation as /api/ingest.
        # Parsers only check shape, so a line like `not-an-ip - - [...]` or an
        # app-JSON `"source_ip": "garbage"` would otherwise reach the INET
        # column and fail the whole upload with a 500.
        try:
            events.append(EventIn(**parsed).model_dump())
        except ValidationError:
            skipped_reasons["invalid_field"] += 1

    pool = get_pool()
    async with pool.acquire() as conn:
        inserted = await _insert_events(conn, events)

    return UploadResult(
        filename=file.filename or "",
        source_type=source_type,
        total_lines=len(lines),
        parsed=len(events),
        skipped=sum(skipped_reasons.values()),
        skipped_reasons=dict(skipped_reasons),
        inserted=inserted,
    )
