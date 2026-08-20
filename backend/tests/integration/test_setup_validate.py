import uuid

import pytest
import pytest_asyncio

from config import settings

pytestmark = pytest.mark.asyncio(loop_scope="session")

ENDPOINT = "/api/setup/validate"


@pytest_asyncio.fixture(loop_scope="session")
async def viewer_token(client, pool):
    """An approved viewer-role account — the lowest privilege level that can
    actually authenticate."""
    email = f"pytest_{uuid.uuid4().hex[:12]}@example.com"
    password = "ViewerPassword123"
    await client.post("/api/auth/register", json={"email": email, "password": password})
    async with pool.acquire() as conn:
        await conn.execute("UPDATE users SET is_active = TRUE WHERE email = $1", email)

    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    yield r.json()["access_token"]

    async with pool.acquire() as conn:
        user_id = await conn.fetchval("SELECT id FROM users WHERE email = $1", email)
        if user_id is not None:
            await conn.execute("DELETE FROM audit_log WHERE user_id = $1", user_id)
            await conn.execute("DELETE FROM users WHERE id = $1", user_id)


async def test_setup_validate_rejects_anonymous(client):
    r = await client.get(ENDPOINT)
    assert r.status_code == 401


async def test_setup_validate_rejects_non_admin(client, viewer_token):
    r = await client.get(ENDPOINT, headers={"Authorization": f"Bearer {viewer_token}"})
    assert r.status_code == 403


async def test_setup_validate_allows_admin(client):
    login = await client.post(
        "/api/auth/login",
        json={"email": settings.admin_email, "password": settings.admin_password},
    )
    token = login.json()["access_token"]

    r = await client.get(ENDPOINT, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["all_tables_present"] is True
    # Asserted as a type, not a fixed value — a developer legitimately running
    # the suite with ENABLE_ATTACK_LAB=true shouldn't get a spurious failure.
    assert isinstance(body["attack_lab_enabled"], bool)
