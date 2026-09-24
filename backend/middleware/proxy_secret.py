"""Refuses requests that did not come through the Vercel /api proxy.

Uvicorn runs with --forwarded-allow-ips="*", so request.client.host is taken
from X-Forwarded-For. Vercel overwrites that header with the real client IP,
but the Render URL is public too: anyone calling it directly could forge
X-Forwarded-For, get a fresh rate-limit bucket per request and write any IP
they like into the audit log. The Vercel middleware (frontend/middleware.js)
attaches a shared secret to every proxied request; anything without it is
rejected here, before the rate limiter or any route runs.

Blank INTERNAL_PROXY_SECRET turns the check off, so local development and a
first deploy (secret not yet set on both hosts) keep working.
"""

import hmac

from starlette.responses import JSONResponse

HEADER = b"x-internal-proxy-secret"
# The keep-alive workflow pings Render directly; health leaks nothing.
_EXEMPT_PATHS = {"/api/health"}


class ProxySecretMiddleware:
    def __init__(self, app, secret: str):
        self.app = app
        self.secret = secret.encode()

    async def __call__(self, scope, receive, send):
        if (
            self.secret
            and scope["type"] == "http"
            and scope.get("path") not in _EXEMPT_PATHS
            and not hmac.compare_digest(dict(scope.get("headers", [])).get(HEADER, b""), self.secret)
        ):
            await JSONResponse({"detail": "Forbidden"}, status_code=403)(scope, receive, send)
            return
        await self.app(scope, receive, send)
