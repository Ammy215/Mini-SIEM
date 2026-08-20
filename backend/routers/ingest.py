import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile

from auth.deps import CurrentUser
from auth.rbac import require_role
from database import get_pool
from models.events import EventIn, IngestResult, UploadResult
from parsers import app_json, nginx, ssh, syslog

router = APIRouter()

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


@router.post("/api/ingest", response_model=IngestResult)
async def ingest(
    body: EventIn | list[EventIn],
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    events = [body.model_dump()] if isinstance(body, EventIn) else [e.model_dump() for e in body]

    pool = get_pool()
    async with pool.acquire() as conn:
        inserted = await _insert_events(conn, events)

    return IngestResult(ingested=inserted)


@router.post("/api/logs/upload", response_model=UploadResult)
async def upload_log(
    file: UploadFile,
    source_type: str = Form(...),
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    if source_type not in _PARSERS:
        raise HTTPException(status_code=400, detail=f"Unknown source_type. Expected one of {list(_PARSERS)}")

    parser = _PARSERS[source_type]
    content = (await file.read()).decode("utf-8", errors="replace")
    lines = [line for line in content.splitlines() if line.strip()]

    events = []
    skipped = 0
    for line in lines:
        parsed = parser.parse_line(line)
        if parsed is None:
            skipped += 1
        else:
            events.append(parsed)

    pool = get_pool()
    async with pool.acquire() as conn:
        inserted = await _insert_events(conn, events)

    return UploadResult(
        filename=file.filename or "",
        source_type=source_type,
        total_lines=len(lines),
        parsed=len(events),
        skipped=skipped,
        inserted=inserted,
    )
