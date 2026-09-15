import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, UploadFile

from auth.audit import log_action
from auth.deps import CurrentUser
from auth.rate_limit import rate_limit
from auth.rbac import require_role
from config import settings
from database import get_pool
from middleware.body_size_limit import human_size
from models.events import (
    BatchListResponse, BatchOut, EventIn, FormatListResponse, FormatOut, IngestResult, SkippedSample, UploadResult,
)
from parsers import pipeline
from parsers.base import ParseContext

router = APIRouter()

_ingest_rate_limit = rate_limit("ingest", limit=60, window_minutes=1)
_can_ingest = require_role("analyst", "admin")

MAX_EVENTS_PER_REQUEST = 1000
_INSERT_CHUNK = 1000

_INSERT_SQL = """
    INSERT INTO events (
        event_time, source_type, source_ip, dest_ip, dest_port, username, action, status_code,
        method, url, user_agent, country, raw_message, raw,
        host, event_code, outcome, protocol, src_port, parser, batch_id
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb,
              $15, $16, $17, $18, $19, $20, $21)
"""

_BATCH_SELECT = """
    SELECT b.*, u.email AS uploaded_by
    FROM ingest_batches b
    LEFT JOIN users u ON u.id = b.created_by
"""


def _event_to_row(event: dict, batch_id: UUID | None) -> tuple:
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
        event.get("host"),
        event.get("event_code"),
        event.get("outcome"),
        event.get("protocol"),
        event.get("src_port"),
        event.get("parser"),
        batch_id,
    )


async def _insert_events(conn, events: list[dict], batch_id: UUID | None = None) -> int:
    rows = [_event_to_row(event, batch_id) for event in events]
    for start in range(0, len(rows), _INSERT_CHUNK):
        await conn.executemany(_INSERT_SQL, rows[start:start + _INSERT_CHUNK])
    return len(rows)


def _row_to_batch(row) -> BatchOut:
    return BatchOut(
        id=row["id"], filename=row["filename"], sha256=row["sha256"], size_bytes=row["size_bytes"],
        uploaded_by=row["uploaded_by"], requested_format=row["requested_format"],
        detected_format=row["detected_format"], confidence=row["confidence"],
        total_lines=row["total_lines"], parsed=row["parsed"], skipped=row["skipped"], inserted=row["inserted"],
        by_parser=json.loads(row["by_parser"]), skipped_reasons=json.loads(row["skipped_reasons"]),
        skipped_samples=[SkippedSample(**s) for s in json.loads(row["skipped_samples"])],
        first_event_time=row["first_event_time"], last_event_time=row["last_event_time"],
        created_at=row["created_at"],
    )


@router.post("/api/ingest", response_model=IngestResult, dependencies=[Depends(_ingest_rate_limit)])
async def ingest(
    body: EventIn | list[EventIn],
    current_user: CurrentUser = Depends(_can_ingest),
):
    events = [body] if isinstance(body, EventIn) else body
    if len(events) > MAX_EVENTS_PER_REQUEST:
        raise HTTPException(
            status_code=413,
            detail=f"At most {MAX_EVENTS_PER_REQUEST} events per request; send larger sets in several batches.",
        )

    rows = [{**event.model_dump(), "parser": "api"} for event in events]
    pool = get_pool()
    async with pool.acquire() as conn:
        inserted = await _insert_events(conn, rows)

    return IngestResult(ingested=inserted)


@router.get("/api/ingest/formats", response_model=FormatListResponse)
async def list_formats(current_user: CurrentUser = Depends(_can_ingest)):
    return FormatListResponse(
        formats=[FormatOut(**fmt) for fmt in pipeline.available_formats()],
        max_upload_bytes=settings.max_upload_bytes,
    )


@router.post("/api/logs/upload", response_model=UploadResult, dependencies=[Depends(_ingest_rate_limit)])
async def upload_log(
    request: Request,
    file: UploadFile,
    requested_format: str = Form("auto", alias="format"),
    source_type: str | None = Form(None),
    year: int | None = Form(None, ge=1970, le=2100),
    current_user: CurrentUser = Depends(_can_ingest),
):
    # `source_type` is the field this endpoint took before auto-detection
    # existed; it still forces that format.
    if source_type and requested_format == "auto":
        requested_format = source_type
    if requested_format not in pipeline.FORMAT_NAMES:
        raise HTTPException(
            status_code=400, detail=f"Unknown format. Expected one of {list(pipeline.FORMAT_NAMES)}"
        )

    content = await file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413, detail=f"File is larger than the {human_size(settings.max_upload_bytes)} upload limit."
        )

    text = pipeline.decode_upload(content)
    try:
        report = pipeline.parse_text(text, requested_format, ParseContext(year_hint=year))
    except pipeline.TooManyLines:
        raise HTTPException(
            status_code=413, detail=f"File has more than {pipeline.MAX_LINES:,} lines; split it into smaller uploads."
        )

    filename = (file.filename or "upload").replace("\x00", "")[:255]
    event_times = [event["event_time"] for event in report.events if event.get("event_time")]
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    pool = get_pool()
    async with pool.acquire() as conn:
        # One transaction: a batch record never exists without its events, or
        # events without the batch that explains where they came from.
        async with conn.transaction():
            batch_id = await conn.fetchval(
                """
                INSERT INTO ingest_batches (
                    filename, sha256, size_bytes, created_by, requested_format, detected_format, confidence,
                    total_lines, parsed, skipped, inserted, by_parser, skipped_reasons, skipped_samples,
                    first_event_time, last_event_time
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13::jsonb, $14::jsonb, $15, $16)
                RETURNING id
                """,
                filename, hashlib.sha256(content).hexdigest(), len(content), current_user.id,
                requested_format, report.detected_format, report.confidence,
                report.total_lines, report.parsed, report.skipped, report.parsed,
                json.dumps(report.by_parser), json.dumps(report.skipped_reasons), json.dumps(report.skipped_samples),
                min(event_times, default=None), max(event_times, default=None),
            )
            inserted = await _insert_events(conn, report.events, batch_id)
            await log_action(
                conn, user_id=current_user.id, action="logs_uploaded",
                detail={
                    "batch_id": str(batch_id), "filename": filename, "format": requested_format,
                    "detected_format": report.detected_format, "total_lines": report.total_lines,
                    "inserted": inserted, "skipped": report.skipped,
                },
                ip_address=ip_address, user_agent=user_agent,
            )

    return UploadResult(
        batch_id=batch_id,
        filename=filename,
        format=requested_format,
        detected_format=report.detected_format,
        confidence=report.confidence,
        total_lines=report.total_lines,
        parsed=report.parsed,
        skipped=report.skipped,
        inserted=inserted,
        by_parser=dict(report.by_parser),
        skipped_reasons=dict(report.skipped_reasons),
        skipped_samples=[SkippedSample(**sample) for sample in report.skipped_samples],
    )


@router.get("/api/ingest/batches", response_model=BatchListResponse)
async def list_batches(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: CurrentUser = Depends(_can_ingest),
):
    pool = get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM ingest_batches")
        rows = await conn.fetch(
            _BATCH_SELECT + " ORDER BY b.created_at DESC LIMIT $1 OFFSET $2", limit, offset
        )
    return BatchListResponse(batches=[_row_to_batch(row) for row in rows], total=total)


@router.get("/api/ingest/batches/{batch_id}", response_model=BatchOut)
async def get_batch(batch_id: UUID, current_user: CurrentUser = Depends(_can_ingest)):
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(_BATCH_SELECT + " WHERE b.id = $1", batch_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Upload batch not found")
    return _row_to_batch(row)
