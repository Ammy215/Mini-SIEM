"""The attack lab logs its practice traffic through the same writer as every
other ingestion path, so lab events aren't a second, thinner shape of event."""

import pytest

from routers import attack_lab

pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_practice_login_event_is_stored_with_the_full_event_shape(conn):
    await attack_lab._log_event(
        conn,
        source_type="app",
        source_ip="203.0.113.240",
        dest_port=443,
        username="admin",
        action="login_failed",
        status_code=401,
        raw_message="attack-lab login attempt for 'admin' -> login_failed",
    )

    row = await conn.fetchrow(
        "SELECT * FROM events WHERE source_ip = $1::inet ORDER BY id DESC LIMIT 1", "203.0.113.240"
    )
    assert row["source_type"] == "app"
    assert row["action"] == "login_failed"
    assert row["dest_port"] == 443
    assert row["event_time"] is not None
    # The columns the lab's own INSERT used to leave out entirely.
    assert row["parser"] == "attack_lab"
    assert row["batch_id"] is None


async def test_practice_search_event_keeps_the_attacking_url_and_agent(conn):
    await attack_lab._log_event(
        conn,
        source_type="nginx",
        source_ip="203.0.113.241",
        method="GET",
        url="/search?q=' OR 1=1--",
        user_agent="sqlmap/1.7",
        action="request",
        status_code=200,
        raw_message='"GET /search?q=\' OR 1=1-- HTTP/1.1" 200',
    )

    row = await conn.fetchrow(
        "SELECT * FROM events WHERE source_ip = $1::inet ORDER BY id DESC LIMIT 1", "203.0.113.241"
    )
    assert row["url"] == "/search?q=' OR 1=1--"
    assert row["user_agent"] == "sqlmap/1.7"
    assert row["parser"] == "attack_lab"
