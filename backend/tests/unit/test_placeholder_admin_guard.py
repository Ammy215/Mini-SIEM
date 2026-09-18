"""Production refuses to run while an admin still has the public placeholder
password. Users are inserted inside the rolled-back test transaction."""

import uuid

import pytest

from auth.password import hash_password
from auth.placeholder_password import admins_using_placeholder_password, assert_no_placeholder_admin
from config import PLACEHOLDER_ADMIN_PASSWORD

pytestmark = pytest.mark.asyncio(loop_scope="session")


async def _user(conn, *, role, password, active=True):
    email = f"guard-{role}-{uuid.uuid4().hex[:8]}@example.com"
    user_id = await conn.fetchval(
        "INSERT INTO users (email, password_hash, is_active) VALUES ($1, $2, $3) RETURNING id",
        email, hash_password(password), active,
    )
    await conn.execute(
        "INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = $2",
        user_id, role,
    )
    return email


async def test_an_admin_on_the_placeholder_password_is_found(conn):
    email = await _user(conn, role="admin", password=PLACEHOLDER_ADMIN_PASSWORD)
    assert email in await admins_using_placeholder_password(conn)


async def test_an_admin_with_a_real_password_is_not_flagged(conn):
    email = await _user(conn, role="admin", password="a-genuinely-private-password-91")
    assert email not in await admins_using_placeholder_password(conn)


async def test_a_suspended_admin_is_not_a_login_risk(conn):
    email = await _user(conn, role="admin", password=PLACEHOLDER_ADMIN_PASSWORD, active=False)
    assert email not in await admins_using_placeholder_password(conn)


async def test_only_admins_are_checked(conn):
    email = await _user(conn, role="viewer", password=PLACEHOLDER_ADMIN_PASSWORD)
    assert email not in await admins_using_placeholder_password(conn)


async def test_startup_guard_names_the_account_and_the_fix(conn):
    email = await _user(conn, role="admin", password=PLACEHOLDER_ADMIN_PASSWORD)
    with pytest.raises(RuntimeError) as raised:
        await assert_no_placeholder_admin(conn)
    message = str(raised.value)
    assert email in message
    assert "reset" in message.lower()
    # the placeholder itself is not repeated into the log
    assert PLACEHOLDER_ADMIN_PASSWORD not in message
