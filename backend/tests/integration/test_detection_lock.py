"""Only one detection run at a time, across the scheduler and manual runs.

These use committed statements on separate pool connections: a lease only
works if another connection sees it the moment it is claimed, which a
rolled-back test transaction would hide."""

import pytest
import pytest_asyncio

from config import settings
from detection import engine, scheduler

pytestmark = pytest.mark.asyncio(loop_scope="session")

_FREE = "UPDATE detection_lease SET holder = NULL, acquired_at = NULL, expires_at = NULL WHERE id = 1"


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def _free_lease(pool):
    async with pool.acquire() as c:
        await c.execute(_FREE)
    yield
    async with pool.acquire() as c:
        await c.execute(_FREE)


async def test_second_run_is_refused_while_the_first_holds_the_lease(pool):
    async with pool.acquire() as first, pool.acquire() as second:
        async with engine.detection_lease(first):
            with pytest.raises(engine.DetectionAlreadyRunning):
                async with engine.detection_lease(second):
                    pass
        # Released on exit, so the next run can claim it.
        async with engine.detection_lease(second):
            pass


async def test_the_same_connection_cannot_claim_it_twice(pool):
    # Unlike a Postgres advisory lock, which is re-entrant for its own session.
    async with pool.acquire() as c:
        async with engine.detection_lease(c):
            with pytest.raises(engine.DetectionAlreadyRunning):
                async with engine.detection_lease(c):
                    pass


async def test_an_expired_lease_left_by_a_crashed_run_is_reclaimed(pool):
    async with pool.acquire() as c:
        await c.execute(
            "UPDATE detection_lease SET holder = gen_random_uuid(), acquired_at = now() - interval '1 hour', "
            "expires_at = now() - interval '1 minute' WHERE id = 1"
        )
        async with engine.detection_lease(c):
            pass


async def test_an_overrunning_run_does_not_release_a_lease_someone_else_now_holds(pool):
    async with pool.acquire() as c:
        async with engine.detection_lease(c):
            # This run overran: its lease expired and a later run claimed it.
            later_holder = await c.fetchval(
                "UPDATE detection_lease SET holder = gen_random_uuid(), expires_at = now() + interval '5 minutes' "
                "WHERE id = 1 RETURNING holder"
            )
        assert await c.fetchval("SELECT holder FROM detection_lease WHERE id = 1") == later_holder


async def test_manual_run_returns_409_while_a_run_is_in_progress(client, pool):
    login = await client.post(
        "/api/auth/login", json={"email": settings.admin_email, "password": settings.admin_password}
    )
    auth = {"Authorization": f"Bearer {login.json()['access_token']}"}

    async with pool.acquire() as c:
        async with engine.detection_lease(c):
            r = await client.post("/api/detect/run", headers=auth)

    assert r.status_code == 409
    assert "already in progress" in r.json()["detail"]


async def test_scheduler_tick_skips_quietly_while_a_run_is_in_progress(pool):
    async with pool.acquire() as c:
        async with engine.detection_lease(c):
            await scheduler._tick(pool)  # must not raise
