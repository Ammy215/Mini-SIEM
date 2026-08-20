import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

GLOBAL_LIMIT = 300
GLOBAL_WINDOW_SECONDS = 60.0

# Attack-lab routes are meant to absorb a real Burp Intruder burst by design
# (Phase 10) — they're only reachable at all when ENABLE_ATTACK_LAB=true.
_EXEMPT_PREFIX = "/api/attack-lab/"

_buckets: dict[str, list[float]] = defaultdict(list)


class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path.startswith(_EXEMPT_PREFIX):
            return await call_next(request)

        ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        timestamps = _buckets[ip]
        cutoff = now - GLOBAL_WINDOW_SECONDS
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)
        if len(timestamps) >= GLOBAL_LIMIT:
            return JSONResponse({"detail": "Too many requests, try again later"}, status_code=429)
        timestamps.append(now)

        return await call_next(request)
