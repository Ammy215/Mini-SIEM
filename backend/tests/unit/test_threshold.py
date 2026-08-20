from datetime import datetime, timedelta, timezone

import pytest

from detection import threshold

pytestmark = pytest.mark.asyncio(loop_scope="session")

NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


async def _insert_events(conn, rows: list[dict]) -> None:
    await conn.executemany(
        """
        INSERT INTO events (event_time, source_type, source_ip, dest_port, username, action)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        [
            (r["event_time"], r.get("source_type", "ssh"), r.get("source_ip"), r.get("dest_port"),
             r.get("username"), r.get("action"))
            for r in rows
        ],
    )


async def test_brute_force_fires_on_eleven_failed_logins(conn):
    ip = "203.0.113.201"
    now = NOW()
    rows = [
        {"event_time": now - timedelta(seconds=i), "source_ip": ip, "username": "admin", "action": "login_failed"}
        for i in range(11)
    ]
    await _insert_events(conn, rows)

    results = await threshold.run_all(conn)
    assert results["brute_force"] == 1

    alert = await conn.fetchrow("SELECT * FROM alerts WHERE rule_id = (SELECT id FROM rules WHERE rule_key = 'brute_force')")
    assert alert["mitre_technique"] == "T1110"
    assert str(alert["source_ip"]) == ip


async def test_brute_force_does_not_fire_on_ten_failed_logins(conn):
    ip = "203.0.113.202"
    now = NOW()
    rows = [
        {"event_time": now - timedelta(seconds=i), "source_ip": ip, "username": "admin", "action": "login_failed"}
        for i in range(10)
    ]
    await _insert_events(conn, rows)

    results = await threshold.run_all(conn)
    assert results["brute_force"] == 0


async def test_credential_stuffing_fires_on_five_distinct_usernames(conn):
    ip = "203.0.113.204"
    now = NOW()
    rows = [
        {"event_time": now - timedelta(seconds=i), "source_ip": ip, "username": f"user{i}", "action": "login_failed"}
        for i in range(5)
    ]
    await _insert_events(conn, rows)

    results = await threshold.run_all(conn)
    assert results["credential_stuffing"] == 1

    alert = await conn.fetchrow(
        "SELECT * FROM alerts WHERE rule_id = (SELECT id FROM rules WHERE rule_key = 'credential_stuffing')"
    )
    assert alert["mitre_technique"] == "T1110.004"


async def test_port_scan_fires_on_fifteen_distinct_ports(conn):
    ip = "203.0.113.203"
    now = NOW()
    rows = [
        {"event_time": now - timedelta(seconds=i), "source_ip": ip, "dest_port": 1000 + i, "action": None}
        for i in range(15)
    ]
    await _insert_events(conn, rows)

    results = await threshold.run_all(conn)
    assert results["port_scan"] == 1

    alert = await conn.fetchrow("SELECT * FROM alerts WHERE rule_id = (SELECT id FROM rules WHERE rule_key = 'port_scan')")
    assert alert["mitre_technique"] == "T1046"


async def test_password_spray_fires_on_five_distinct_ips_one_username(conn):
    now = NOW()
    rows = [
        {"event_time": now - timedelta(seconds=i), "source_ip": f"203.0.113.{210 + i}", "username": "victim",
         "action": "login_failed"}
        for i in range(5)
    ]
    await _insert_events(conn, rows)

    results = await threshold.run_all(conn)
    assert results["password_spray"] == 1

    alert = await conn.fetchrow(
        "SELECT * FROM alerts WHERE rule_id = (SELECT id FROM rules WHERE rule_key = 'password_spray')"
    )
    assert alert["mitre_technique"] == "T1110.003"
    assert alert["source_ip"] is None
