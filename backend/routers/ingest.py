import hashlib
import json
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, UploadFile

from auth.audit import log_action
from auth.deps import CurrentUser
from auth.rate_limit import rate_limit
from auth.rbac import require_role
from config import settings
from database import get_pool
from ingest_service import insert_events
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

_BATCH_SELECT = """
    SELECT b.*, u.email AS uploaded_by
    FROM ingest_batches b
    LEFT JOIN users u ON u.id = b.created_by
"""


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
        detection_status=row["detection_status"], detection_requested_at=row["detection_requested_at"],
        detection_started_at=row["detection_started_at"], detection_finished_at=row["detection_finished_at"],
        detection_result=json.loads(row["detection_result"]) if row["detection_result"] else None,
        detection_error=row["detection_error"],
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
        inserted = await insert_events(conn, rows)

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
    analyze: bool = Form(False),
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
    detection_status = "queued" if analyze and report.parsed else "none"
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
                    first_event_time, last_event_time,
                    detection_status, detection_requested_at, detection_requested_by
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13::jsonb, $14::jsonb, $15, $16,
                          $17::text, CASE WHEN $17::text = 'queued' THEN now() END,
                          CASE WHEN $17::text = 'queued' THEN $4::uuid END)
                RETURNING id
                """,
                filename, hashlib.sha256(content).hexdigest(), len(content), current_user.id,
                requested_format, report.detected_format, report.confidence,
                report.total_lines, report.parsed, report.skipped, report.parsed,
                json.dumps(report.by_parser), json.dumps(report.skipped_reasons), json.dumps(report.skipped_samples),
                min(event_times, default=None), max(event_times, default=None), detection_status,
            )
            inserted = await insert_events(conn, report.events, batch_id)
            await log_action(
                conn, user_id=current_user.id, action="logs_uploaded",
                detail={
                    "batch_id": str(batch_id), "filename": filename, "format": requested_format,
                    "detected_format": report.detected_format, "total_lines": report.total_lines,
                    "inserted": inserted, "skipped": report.skipped, "analyze": detection_status == "queued",
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
        detection_status=detection_status,
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


@router.post("/api/ingest/batches/{batch_id}/analyze", response_model=BatchOut, status_code=202)
async def analyze_batch(batch_id: UUID, request: Request, current_user: CurrentUser = Depends(_can_ingest)):
    """Queues an upload for attack analysis over its own time span. The next
    detection pass runs it (the scheduler's, or POST /api/detect/run)."""
    pool = get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT id, filename, inserted, detection_status FROM ingest_batches WHERE id = $1 FOR UPDATE", batch_id
            )
            if row is None:
                raise HTTPException(status_code=404, detail="Upload batch not found")
            if row["detection_status"] in ("queued", "running"):
                raise HTTPException(status_code=409, detail="This upload is already waiting for, or in, analysis")
            if row["inserted"] == 0:
                raise HTTPException(status_code=400, detail="This upload stored no events, so there is nothing to analyze")
            await conn.execute(
                """
                UPDATE ingest_batches SET detection_status = 'queued', detection_requested_at = now(),
                    detection_requested_by = $2, detection_started_at = NULL, detection_finished_at = NULL,
                    detection_result = NULL, detection_error = NULL
                WHERE id = $1
                """,
                batch_id, current_user.id,
            )
            await log_action(
                conn, user_id=current_user.id, action="batch_analysis_requested",
                detail={"batch_id": str(batch_id), "filename": row["filename"]},
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )
        batch = await conn.fetchrow(_BATCH_SELECT + " WHERE b.id = $1", batch_id)
    return _row_to_batch(batch)
