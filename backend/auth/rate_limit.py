import time
from collections import defaultdict

from fastapi import HTTPException, Request

# In-memory sliding-window buckets. Single-process only (matches this project's
# single Render web service, no horizontal scaling) — resets on restart.
_buckets: dict[tuple[str, str], list[float]] = defaultdict(list)


def _check(bucket_key: tuple[str, str], limit: int, window_seconds: float) -> None:
    now = time.monotonic()
    timestamps = _buckets[bucket_key]
    cutoff = now - window_seconds
    while timestamps and timestamps[0] < cutoff:
        timestamps.pop(0)
    if len(timestamps) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests, try again later")
    timestamps.append(now)


def rate_limit(key: str, limit: int, window_minutes: float):
    window_seconds = window_minutes * 60

    async def _dependency(request: Request) -> None:
        ip = request.client.host if request.client else "unknown"
        _check((key, ip), limit, window_seconds)

    return _dependency
