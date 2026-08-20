from datetime import datetime, timezone

import pytest

from detection import signature

pytestmark = pytest.mark.asyncio(loop_scope="session")


async def _insert_nginx_event(conn, *, url=None, user_agent=None, source_ip="203.0.113.220") -> int:
    return await conn.fetchval(
        """
        INSERT INTO events (event_time, source_type, source_ip, method, url, user_agent, action)
        VALUES ($1, 'nginx', $2, 'GET', $3, $4, 'request')
        RETURNING id
        """,
        datetime.now(timezone.utc), source_ip, url, user_agent,
    )


async def _alert_for_event(conn, event_id: int):
    # run_all() scans a global 30-minute window, so asserting against the
    # specific event id this test inserted (rather than a raw result count)
    # keeps the test precise regardless of unrelated events in that window.
    return await conn.fetchrow(
        "SELECT * FROM alerts WHERE (evidence->>'event_id')::bigint = $1", event_id
    )


async def test_sqli_pattern_fires(conn):
    event_id = await _insert_nginx_event(conn, url="/search?q=' OR 1=1")
    await signature.run_all(conn)

    alert = await _alert_for_event(conn, event_id)
    assert alert is not None
    assert alert["mitre_technique"] == "T1190"


async def test_xss_pattern_fires(conn):
    event_id = await _insert_nginx_event(conn, url="/search?q=<script>alert(1)</script>")
    await signature.run_all(conn)

    alert = await _alert_for_event(conn, event_id)
    assert alert is not None
    assert alert["mitre_technique"] == "T1059.007"


async def test_path_traversal_pattern_fires(conn):
    event_id = await _insert_nginx_event(conn, url="/download?file=../../etc/passwd")
    await signature.run_all(conn)

    alert = await _alert_for_event(conn, event_id)
    assert alert is not None
    assert alert["mitre_technique"] == "T1083"


async def test_scanner_user_agent_fires(conn):
    event_id = await _insert_nginx_event(conn, url="/", user_agent="sqlmap/1.7")
    await signature.run_all(conn)

    alert = await _alert_for_event(conn, event_id)
    assert alert is not None
    assert alert["mitre_technique"] == "T1595"


async def test_benign_request_does_not_fire_any_signature_rule(conn):
    event_id = await _insert_nginx_event(conn, url="/dashboard?tab=overview", user_agent="Mozilla/5.0")
    await signature.run_all(conn)

    alert = await _alert_for_event(conn, event_id)
    assert alert is None
