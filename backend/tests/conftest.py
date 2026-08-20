import sys
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Makes `from config import settings` etc. resolve regardless of how pytest
# was invoked (bare `pytest` doesn't add cwd to sys.path the way `python -m
# pytest` does).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database import connect, disconnect  # noqa: E402
from detection import engine  # noqa: E402
from main import app  # noqa: E402

# asyncpg connections are bound to the event loop they were created on, so
# every DB-touching fixture/test in this suite must share one event loop.
# pytest-asyncio's loop-scope marker doesn't propagate down from conftest.py
# to files in subdirectories (verified — it silently stays function-scoped),
# so every test module that uses the `conn`, `pool`, or `client` fixture must
# add this line itself:
#     pytestmark = pytest.mark.asyncio(loop_scope="session")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def pool():
    p = await connect()
    async with p.acquire() as seed_conn:
        await engine.seed_all(seed_conn)
    yield p
    await disconnect()


@pytest_asyncio.fixture(loop_scope="session")
async def conn(pool):
    """A connection wrapped in a transaction that's always rolled back —
    real Postgres, real SQL, just test isolation (not a mock)."""
    async with pool.acquire() as c:
        tr = c.transaction()
        await tr.start()
        try:
            yield c
        finally:
            await tr.rollback()


@pytest.fixture(autouse=True)
def _reset_rate_limit_buckets():
    # The rate limiters use process-wide in-memory state (by design — see
    # auth/rate_limit.py), which would otherwise leak between tests: every
    # request in this suite looks like it comes from the same IP, so an
    # earlier test's login attempts would count toward a later test's limit.
    from auth.rate_limit import _buckets as auth_buckets
    from middleware.global_rate_limit import _buckets as global_buckets

    auth_buckets.clear()
    global_buckets.clear()
    yield


@pytest_asyncio.fixture(loop_scope="session")
async def client(pool):
    # httpx.AsyncClient + ASGITransport calls the app in-process on the
    # *current* event loop — unlike fastapi.testclient.TestClient, which
    # (without `with`) opens a brand-new thread and event loop for every
    # single request via anyio's blocking portal. That's fine for a stateless
    # route, but fatal here: the asyncpg pool from the `pool` fixture is
    # bound to this session's event loop, and a connection can't be used
    # from a different one — confirmed by a hard-to-read
    # "InterfaceError: cannot perform operation: another operation is in
    # progress" the first time this was tried with TestClient.
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
