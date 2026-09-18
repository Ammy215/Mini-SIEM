"""Refuses NUL bytes in a request's path or query string.

PostgreSQL TEXT cannot hold U+0000, so a NUL that reaches a bound parameter
raises CharacterNotInRepertoireError and surfaces as a 500. Request bodies are
already guarded where they are parsed (models/events.py, models/rules.py), but
path and query values go straight from the URL into SQL, so any caller could
turn `?q=%00` into a server error. A NUL is never a legitimate value in a URL,
so it is rejected here for every route at once rather than per parameter.
"""

from starlette.responses import JSONResponse

_DETAIL = "Request contains a NUL byte (%00), which is not a valid value."


def _has_null_byte(scope) -> bool:
    # scope["path"] is already percent-decoded, so a %00 in the path is a real
    # NUL here. The query string is not decoded yet, so check both forms.
    if "\x00" in scope.get("path", ""):
        return True
    query = scope.get("query_string", b"")
    return b"\x00" in query or b"%00" in query


class NullByteMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and _has_null_byte(scope):
            await JSONResponse({"detail": _DETAIL}, status_code=422)(scope, receive, send)
            return
        await self.app(scope, receive, send)
