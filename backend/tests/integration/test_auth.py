import uuid

import pytest
import pytest_asyncio

pytestmark = pytest.mark.asyncio(loop_scope="session")


@pytest_asyncio.fixture(loop_scope="session")
async def test_user(pool):
    email = f"pytest_{uuid.uuid4().hex[:12]}@example.com"
    password = "TestPassword123"
    yield {"email": email, "password": password}
    async with pool.acquire() as conn:
        user_id = await conn.fetchval("SELECT id FROM users WHERE email = $1", email)
        if user_id is not None:
            await conn.execute("DELETE FROM audit_log WHERE user_id = $1", user_id)
            await conn.execute("DELETE FROM users WHERE id = $1", user_id)


async def _approve(pool, email: str) -> None:
    """Stand-in for an admin approving a pending account
    (PUT /api/admin/users/{id} with is_active=true)."""
    async with pool.acquire() as conn:
        await conn.execute("UPDATE users SET is_active = TRUE WHERE email = $1", email)


async def _register_and_approve(client, pool, user) -> None:
    await client.post("/api/auth/register", json={"email": user["email"], "password": user["password"]})
    await _approve(pool, user["email"])


# --- self-registration is not self-service access ---------------------------

async def test_newly_registered_account_is_inactive_and_cannot_log_in(client, test_user):
    r = await client.post(
        "/api/auth/register", json={"email": test_user["email"], "password": test_user["password"]}
    )
    assert r.status_code == 201
    # The account exists but is explicitly not usable yet.
    assert r.json()["is_active"] is False

    r = await client.post(
        "/api/auth/login", json={"email": test_user["email"], "password": test_user["password"]}
    )
    assert r.status_code == 403
    assert "not active" in r.json()["detail"].lower()


async def test_account_works_once_an_admin_approves_it(client, pool, test_user):
    await client.post(
        "/api/auth/register", json={"email": test_user["email"], "password": test_user["password"]}
    )
    await _approve(pool, test_user["email"])

    r = await client.post(
        "/api/auth/login", json={"email": test_user["email"], "password": test_user["password"]}
    )
    assert r.status_code == 200
    token = r.json()["access_token"]

    r = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["email"] == test_user["email"]
    assert r.json()["roles"] == ["viewer"]


# --- core auth behaviour ----------------------------------------------------

async def test_protected_route_rejects_missing_token(client):
    r = await client.get("/api/auth/me")
    assert r.status_code == 401


async def test_five_failed_logins_lock_the_account(client, pool, test_user):
    await _register_and_approve(client, pool, test_user)

    for _ in range(5):
        r = await client.post(
            "/api/auth/login", json={"email": test_user["email"], "password": "wrong-password"}
        )
        assert r.status_code == 401

    r = await client.post(
        "/api/auth/login", json={"email": test_user["email"], "password": test_user["password"]}
    )
    assert r.status_code == 423


async def test_viewer_role_is_blocked_from_admin_route(client, pool, test_user):
    await _register_and_approve(client, pool, test_user)
    r = await client.post(
        "/api/auth/login", json={"email": test_user["email"], "password": test_user["password"]}
    )
    token = r.json()["access_token"]

    r = await client.get("/api/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


async def test_refresh_cookie_issues_a_new_access_token(client, pool, test_user):
    await _register_and_approve(client, pool, test_user)
    login = await client.post(
        "/api/auth/login", json={"email": test_user["email"], "password": test_user["password"]}
    )
    assert login.status_code == 200

    r = await client.post("/api/auth/refresh")
    assert r.status_code == 200
    assert "access_token" in r.json()
