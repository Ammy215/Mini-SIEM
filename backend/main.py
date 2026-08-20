import asyncio
import contextlib
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from database import connect, disconnect
from detection import engine
from detection.scheduler import run_scheduler_loop
from middleware.global_rate_limit import GlobalRateLimitMiddleware
from middleware.security_headers import SecurityHeadersMiddleware
from routers import admin, alerts, attack_lab, auth, detect, enrich, events, health, incidents, ingest, rules, setup, stats


@asynccontextmanager
async def lifespan(app: FastAPI):
    pool = await connect()
    async with pool.acquire() as conn:
        await engine.seed_all(conn)

    scheduler_task = asyncio.create_task(run_scheduler_loop(pool, settings.detection_interval_seconds))

    yield

    scheduler_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await scheduler_task
    await disconnect()


app = FastAPI(title="Mini SIEM", lifespan=lifespan)

# Middleware order matters: add_middleware() makes the most-recently-added
# layer outermost. CORS is added last so it always wraps the response (even a
# 429 from GlobalRateLimitMiddleware) — otherwise a rate-limited response
# would reach the browser with no Access-Control-Allow-Origin header and show
# up as an opaque CORS failure instead of a readable 429.
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

if settings.enable_attack_lab:
    app.include_router(attack_lab.router)
