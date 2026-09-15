"""The time range a dashboard or stats request covers: a preset (1h, 24h, 7d,
30d) or an explicit from/to of at most 90 days, and a bucket size that keeps a
chart readable at that span."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import HTTPException, Query
from pydantic import AwareDatetime

PRESETS = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
DEFAULT_SPAN = PRESETS["24h"]
MAX_SPAN = timedelta(days=90)
# Buckets line up on this instant, so the database's date_bin and Python agree.
BUCKET_ORIGIN = datetime(2000, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class TimeRange:
    start: datetime
    end: datetime
    bucket: timedelta
    label: str  # a preset name, "custom", or "default" when nothing was asked for


def bucket_for(span: timedelta) -> timedelta:
    if span <= timedelta(hours=6):
        return timedelta(minutes=5)
    if span <= timedelta(days=7):
        return timedelta(hours=1)
    return timedelta(days=1)


def floor_to_bucket(moment: datetime, bucket: timedelta) -> datetime:
    return BUCKET_ORIGIN + ((moment - BUCKET_ORIGIN) // bucket) * bucket


def resolve(preset: str | None, time_from: datetime | None, time_to: datetime | None,
            now: datetime | None = None) -> TimeRange:
    """Raises ValueError with a message for the client when the range is invalid."""
    now = now or datetime.now(timezone.utc)
    if time_from is not None or time_to is not None:
        if time_from is None or time_to is None:
            raise ValueError("Give both from and to, or neither")
        if preset is not None:
            raise ValueError("Use either range or from/to, not both")
        if time_to <= time_from:
            raise ValueError("to must be after from")
        if time_to - time_from > MAX_SPAN:
            raise ValueError("A range can cover at most 90 days")
        return TimeRange(time_from, time_to, bucket_for(time_to - time_from), "custom")
    span = PRESETS[preset] if preset else DEFAULT_SPAN
    return TimeRange(now - span, now, bucket_for(span), preset or "default")


def time_range(
    preset: Literal["1h", "24h", "7d", "30d"] | None = Query(None, alias="range"),
    time_from: AwareDatetime | None = Query(None, alias="from"),
    time_to: AwareDatetime | None = Query(None, alias="to"),
) -> TimeRange:
    try:
        return resolve(preset, time_from, time_to)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
