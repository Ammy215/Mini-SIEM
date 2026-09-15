import ipaddress
import json
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

# Longest value each text field accepts. Parsers use the same limits, so a
# value that doesn't fit is left out of the field rather than failing a line.
MAX_LENGTHS = {
    "source_type": 64,
    "username": 256,
    "action": 128,
    "method": 32,
    "url": 65_536,
    "user_agent": 4_096,
    "country": 64,
    "host": 256,
    "event_code": 64,
    "protocol": 32,
    "raw_message": 262_144,
}


def _text_field():
    return Field(default=None)


def _contains_null_byte(value) -> bool:
    """PostgreSQL cannot store U+0000 in text or jsonb columns. Reaching the
    driver with one raises CharacterNotInRepertoireError, which surfaces as an
    unhandled 500 — so catch it during validation and return a clean 422."""
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, dict):
        return any(_contains_null_byte(k) or _contains_null_byte(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_null_byte(item) for item in value)
    return False


class EventIn(BaseModel):
    event_time: datetime | None = None
    source_type: str = Field(min_length=1, max_length=MAX_LENGTHS["source_type"])
    source_ip: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    username: str | None = Field(default=None, max_length=MAX_LENGTHS["username"])
    action: str | None = Field(default=None, max_length=MAX_LENGTHS["action"])
    outcome: Literal["success", "failure", "unknown"] | None = None
    status_code: int | None = Field(default=None, ge=0, le=999)
    method: str | None = Field(default=None, max_length=MAX_LENGTHS["method"])
    url: str | None = Field(default=None, max_length=MAX_LENGTHS["url"])
    user_agent: str | None = Field(default=None, max_length=MAX_LENGTHS["user_agent"])
    country: str | None = Field(default=None, max_length=MAX_LENGTHS["country"])
    host: str | None = Field(default=None, max_length=MAX_LENGTHS["host"])
    event_code: str | None = Field(default=None, max_length=MAX_LENGTHS["event_code"])
    protocol: str | None = Field(default=None, max_length=MAX_LENGTHS["protocol"])
    raw_message: str | None = Field(default=None, max_length=MAX_LENGTHS["raw_message"])
    raw: dict | None = None

    @field_validator("source_ip", "dest_ip")
    @classmethod
    def check_ip(cls, v: str | None) -> str | None:
        # These land in INET columns; anything unparseable would otherwise reach
        # asyncpg and raise DataError as a 500.
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("must be a valid IPv4 or IPv6 address")
        return v

    @model_validator(mode="after")
    def check_storable(self):
        for name in type(self).model_fields:
            if _contains_null_byte(getattr(self, name)):
                raise ValueError(f"{name} contains a NUL byte, which PostgreSQL cannot store")
        if self.raw is not None:
            # JSON parsers accept NaN and Infinity; PostgreSQL's jsonb rejects
            # them, which would fail the whole insert with a 500.
            try:
                json.dumps(self.raw, allow_nan=False)
            except (ValueError, TypeError, RecursionError):
                raise ValueError("raw must be plain JSON (no NaN or Infinity)")
        return self


class IngestResult(BaseModel):
    ingested: int


class SkippedSample(BaseModel):
    line: int
    reason: str
    excerpt: str


class UploadResult(BaseModel):
    batch_id: UUID
    filename: str
    # What the uploader asked for: "auto", or a format they forced.
    format: str
    detected_format: str
    # Share of sampled lines the detected format matched; None when forced.
    confidence: float | None
    total_lines: int
    parsed: int
    skipped: int
    inserted: int
    by_parser: dict[str, int]
    skipped_reasons: dict[str, int] = Field(default_factory=dict)
    skipped_samples: list[SkippedSample] = Field(default_factory=list)


class BatchOut(BaseModel):
    id: UUID
    filename: str
    sha256: str
    size_bytes: int
    uploaded_by: str | None
    requested_format: str
    detected_format: str
    confidence: float | None
    total_lines: int
    parsed: int
    skipped: int
    inserted: int
    by_parser: dict[str, int]
    skipped_reasons: dict[str, int]
    skipped_samples: list[SkippedSample]
    first_event_time: datetime | None
    last_event_time: datetime | None
    created_at: datetime


class BatchListResponse(BaseModel):
    batches: list[BatchOut]
    total: int


class FormatOut(BaseModel):
    name: str
    label: str
    description: str


class FormatListResponse(BaseModel):
    formats: list[FormatOut]
    # So the upload page can refuse an oversized file before sending it.
    max_upload_bytes: int


class EventOut(BaseModel):
    id: int
    event_time: datetime
    source_type: str
    source_ip: str | None
    dest_ip: str | None
    dest_port: int | None
    username: str | None
    action: str | None
    status_code: int | None
    method: str | None
    url: str | None
    user_agent: str | None
    country: str | None
    raw_message: str | None
    host: str | None = None
    event_code: str | None = None
    outcome: str | None = None
    protocol: str | None = None
    src_port: int | None = None
    parser: str | None = None
    batch_id: UUID | None = None


class EventListResponse(BaseModel):
    events: list[EventOut]
    total: int
