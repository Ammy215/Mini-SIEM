import asyncio
import contextlib
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from database import connect, disconnect
from detection import engine
from detection.scheduler import run_scheduler_loop
from middleware.body_size_limit import BodySizeLimitMiddleware
from middleware.global_rate_limit import GlobalRateLimitMiddleware
from middleware.security_headers import SecurityHeadersMiddleware
from migrations import assert_schema_current
from routers import (
    admin, ai_summary, alerts, attack_lab, auth, detect, enrich, events, health, incidents, ingest, rules, setup, stats,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    pool = await connect()
    async with pool.acquire() as conn:
        # Fail at startup, with the fix in the message, rather than on the
        # first request that happens to touch a column a migration adds.
        await assert_schema_current(conn)
        await engine.seed_all(conn)

    scheduler_task = asyncio.create_task(run_scheduler_loop(pool, settings.detection_interval_seconds))

    yield

    scheduler_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await scheduler_task
    await disconnect()


app = FastAPI(title="Mini SIEM", lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    # FastAPI's default 422 echoes every rejected value back to the client. In
    # a SIEM that value is usually log content an attacker wrote — reflected
    # straight back, sometimes 100 KB of it — and one holding NaN can't be
    # encoded as JSON at all, which turned the 422 into a server error. Where
    # the problem is and what's wrong is all a client needs.
    errors = [{key: error[key] for key in ("type", "loc", "msg") if key in error} for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})


# Middleware order matters: add_middleware() makes the most-recently-added
# layer outermost. CORS is added last so it always wraps the response (even a
# 429 from GlobalRateLimitMiddleware) — otherwise a rate-limited response
# would reach the browser with no Access-Control-Allow-Origin header and show
# up as an opaque CORS failure instead of a readable 429. The body size limit
# is innermost for the same reason: its 413 still gets security headers and CORS.
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(GlobalRateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(setup.router)
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(ingest.router)
app.include_router(detect.router)
app.include_router(enrich.router)
app.include_router(incidents.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(stats.router)
app.include_router(rules.router)
app.include_router(ai_summary.router)

if settings.enable_attack_lab:
    app.include_router(attack_lab.router)
