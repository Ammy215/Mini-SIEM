"""The health endpoint has to answer even when the database does not.

It is what the sign-in page reads to say "Console online", "API up, database
unavailable" or "Cannot reach the API", and what a platform health check polls.
If a database outage made it raise instead of answer, the page would show the
API as unreachable when it is running fine, and the platform would keep
restarting a healthy service.

The state cannot be produced by starting with a broken DATABASE_URL, because the
app connects during startup and refuses to start at all — so the failure is
injected here instead.
"""

import pytest

import routers.health as health_module


class _FailingPool:
    def acquire(self):
        raise ConnectionError("connection to the database was lost")


@pytest.mark.asyncio
async def test_health_reports_degraded_when_the_database_is_gone(monkeypatch):
    monkeypatch.setattr(health_module, "get_pool", lambda: _FailingPool())
    body = await health_module.health()
    assert body == {"status": "degraded", "database": "down"}


@pytest.mark.asyncio
async def test_health_reports_degraded_when_the_pool_itself_is_missing(monkeypatch):
    """Before startup finishes there may be no pool at all."""
    def no_pool():
        raise RuntimeError("database pool is not initialised")

    monkeypatch.setattr(health_module, "get_pool", no_pool)
    body = await health_module.health()
    assert body["status"] == "degraded" and body["database"] == "down"
