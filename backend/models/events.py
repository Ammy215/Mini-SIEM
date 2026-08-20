from datetime import datetime

from pydantic import BaseModel, Field


class EventIn(BaseModel):
    event_time: datetime | None = None
    source_type: str
    source_ip: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    username: str | None = None
    action: str | None = None
    status_code: int | None = None
    method: str | None = None
    url: str | None = None
    user_agent: str | None = None
    country: str | None = None
    raw_message: str | None = None
    raw: dict | None = None


class IngestResult(BaseModel):
    ingested: int


class UploadResult(BaseModel):
    filename: str
    source_type: str
    total_lines: int
    parsed: int
    skipped: int
    inserted: int
