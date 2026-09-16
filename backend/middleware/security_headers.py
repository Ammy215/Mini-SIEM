from starlette.middleware.base import BaseHTTPMiddleware

from config import settings

# FastAPI's own /docs and /redoc pages are the one place this API renders HTML
# — they load Swagger UI / ReDoc's JS and CSS from a CDN. A blanket
# default-src 'none' (correct for every real endpoint, which returns only
# JSON) makes those two pages load blank with everything blocked. Relax the
# policy only for these exact paths rather than weakening it for the API.
_DOCS_PATHS = {"/docs", "/redoc"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path in _DOCS_PATHS:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; "
                "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com; "
                "font-src fonts.gstatic.com; "
                "img-src 'self' data: fastapi.tiangolo.com; "
                "connect-src 'self'"
            )
        else:
            # Pure JSON API — nothing here ever renders HTML.
            response.headers["Content-Security-Policy"] = "default-src 'none'"
        if settings.app_env == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
