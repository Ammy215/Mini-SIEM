import uuid

import pytest
import pytest_asyncio

from config import settings

pytestmark = pytest.mark.asyncio(loop_scope="session")


@pytest_asyncio.fixture(loop_scope="session")
async def admin_token(client):
    r = await client.post(
        "/api/auth/login",
        json={"email": settings.admin_email, "password": settings.admin_password},
    )
    assert r.status_code == 200
    return r.json()["access_token"]


async def test_malformed_user_id_returns_422_not_500(client, admin_token):
    """A non-UUID path param must be rejected by validation rather than
    reaching asyncpg and raising an unhandled DataError (500 + stack trace)."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.put("/api/admin/users/197609", json={"is_active": True}, headers=headers)
    assert r.status_code == 422

    r = await client.post("/api/admin/users/not-a-uuid/suspend", headers=headers)
    assert r.status_code == 422


async def test_well_formed_but_unknown_user_id_returns_404(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    missing = uuid.uuid4()

    r = await client.put(f"/api/admin/users/{missing}", json={"is_active": True}, headers=headers)
    assert r.status_code == 404

    r = await client.post(f"/api/admin/users/{missing}/suspend", headers=headers)
    assert r.status_code == 404


# --- admin-driven password reset --------------------------------------------

@pytest_asyncio.fixture(loop_scope="session")
async def managed_user(client, pool, admin_token):
    """A real user created through the admin API, cleaned up afterwards."""
    email = f"pytest_{uuid.uuid4().hex[:12]}@example.com"
    original = "OriginalPass123"
    r = await client.post(
        "/api/admin/users",
        json={"email": email, "password": original, "full_name": "Reset Target", "role": "viewer"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 201
    yield {"id": r.json()["id"], "email": email, "password": original}

    async with pool.acquire() as conn:
        user_id = await conn.fetchval("SELECT id FROM users WHERE email = $1", email)
        if user_id is not None:
            await conn.execute("DELETE FROM audit_log WHERE user_id = $1", user_id)
            await conn.execute("DELETE FROM users WHERE id = $1", user_id)


async def test_admin_can_reset_a_users_password(client, admin_token, managed_user):
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_password = "BrandNewPass456"

    # Sanity: the original password works before the reset.
    r = await client.post(
        "/api/auth/login", json={"email": managed_user["email"], "password": managed_user["password"]}
    )
    assert r.status_code == 200

    r = await client.put(
        f"/api/admin/users/{managed_user['id']}", json={"password": new_password}, headers=headers
    )
    assert r.status_code == 200

    # New password works...
    r = await client.post(
        "/api/auth/login", json={"email": managed_user["email"], "password": new_password}
    )
    assert r.status_code == 200

    # ...and the old one no longer does.
    r = await client.post(
        "/api/auth/login", json={"email": managed_user["email"], "password": managed_user["password"]}
    )
    assert r.status_code == 401


async def test_password_reset_is_never_written_to_the_audit_log(client, admin_token, managed_user):
    headers = {"Authorization": f"Bearer {admin_token}"}
    secret = "SuperSecretReset789"

    r = await client.put(
        f"/api/admin/users/{managed_user['id']}", json={"password": secret}, headers=headers
    )
    assert r.status_code == 200

    r = await client.get("/api/admin/audit", params={"limit": 50}, headers=headers)
    assert r.status_code == 200
    body = r.text
    assert secret not in body, "plaintext password leaked into the audit log"

    entry = next(e for e in r.json()["entries"] if e["action"] == "admin_user_updated")
    assert entry["detail"].get("password_reset") is True
    assert "password" not in entry["detail"]


async def test_password_reset_rejects_too_short_password(client, admin_token, managed_user):
    r = await client.put(
        f"/api/admin/users/{managed_user['id']}",
        json={"password": "short"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 422
