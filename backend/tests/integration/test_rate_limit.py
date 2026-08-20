import pytest

pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eleventh_rapid_login_attempt_is_rate_limited(client):
    # Nonexistent email — the login route's dummy-hash branch returns 401
    # without touching the DB, so this needs no cleanup.
    for _ in range(10):
        r = await client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "wrong"})
        assert r.status_code == 401

    r = await client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "wrong"})
    assert r.status_code == 429
