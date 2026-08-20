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
