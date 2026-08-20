import ipaddress
from datetime import datetime

from pydantic import BaseModel, Field, field_validator, model_validator


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
    def reject_null_bytes(self):
        for name in type(self).model_fields:
            if _contains_null_byte(getattr(self, name)):
                raise ValueError(f"{name} contains a NUL byte, which PostgreSQL cannot store")
        return self


class IngestResult(BaseModel):
    ingested: int


class UploadResult(BaseModel):
    filename: str
    source_type: str
    total_lines: int
    parsed: int
    skipped: int
    inserted: int


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


class EventListResponse(BaseModel):
    events: list[EventOut]
    total: int
