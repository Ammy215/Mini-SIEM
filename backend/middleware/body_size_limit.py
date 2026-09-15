"""Refuses request bodies over a size limit before they are read.

FastAPI hands an upload to its handler only after the multipart parser has
spooled the whole body, and parses /api/ingest into Python objects only after
it has fully arrived. A size check inside those handlers runs too late to stop
someone streaming gigabytes, so this counts bytes as they come in.
"""

from fastapi import HTTPException
from starlette.responses import JSONResponse

from config import settings

# Boundaries and the small form fields that surround the file in a multipart body.
_MULTIPART_OVERHEAD = 64 * 1024


def human_size(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.0f} MB"
    if size >= 1024:
        return f"{size / 1024:.0f} KB"
    return f"{size} bytes"


def _limit_for(path: str) -> int | None:
    # Read per request rather than at startup, so a changed setting applies at once.
    if path == "/api/logs/upload":
        return settings.max_upload_bytes + _MULTIPART_OVERHEAD
    if path == "/api/ingest":
        return settings.max_ingest_body_bytes
    return None


def _detail(limit: int) -> str:
    return f"Request body is larger than the {human_size(limit)} limit for this endpoint."


class BodySizeLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        limit = _limit_for(scope["path"]) if scope["type"] == "http" else None
        if limit is None:
            await self.app(scope, receive, send)
            return

        declared = _content_length(scope)
        if declared is not None and declared > limit:
            await JSONResponse({"detail": _detail(limit)}, status_code=413)(scope, receive, send)
            return

        # No Content-Length (a chunked body) or one that under-declares: count
        # what actually arrives.
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # FastAPI re-raises an HTTPException raised while it reads
                    # a body, so this becomes an ordinary 413 response.
                    raise HTTPException(status_code=413, detail=_detail(limit))
            return message

        await self.app(scope, limited_receive, send)


def _content_length(scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None
