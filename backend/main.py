import asyncio
import contextlib
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from database import connect, disconnect
from detection import engine
from detection.scheduler import run_scheduler_loop
from routers import admin, auth, detect, enrich, health, ingest, setup


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
