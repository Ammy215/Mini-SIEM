from datetime import datetime, timedelta, timezone

import pytest

from detection import correlate
from detection.common import insert_alert

pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_two_alerts_same_ip_within_window_join_one_incident(conn):
    ip = "203.0.113.230"
    await insert_alert(
        conn, rule_id=None, title="Brute force login attempts", mitre_technique="T1110",
        source_ip=ip, threat_score=30, severity="medium", evidence={},
    )
    await insert_alert(
        conn, rule_id=None, title="Port scan", mitre_technique="T1046",
        source_ip=ip, threat_score=50, severity="high", evidence={},
    )

    results = await correlate.run_all(conn)
    assert results["incidents_created"] == 1
    assert results["alerts_joined"] == 1

    incident = await conn.fetchrow("SELECT * FROM incidents WHERE source_ip = $1::inet", ip)
    assert incident["alert_count"] == 2
    assert incident["severity"] == "high"  # escalated to the worse of the two


async def test_alert_outside_window_starts_a_separate_incident(conn):
    ip = "203.0.113.231"
    old_time = datetime.now(timezone.utc) - timedelta(minutes=90)
    new_time = datetime.now(timezone.utc)

    old_alert_id = await conn.fetchval(
        """
        INSERT INTO alerts (title, severity, mitre_technique, source_ip, threat_score, status, evidence, created_at)
        VALUES ('Old alert', 'low', 'T1046', $1::inet, 10, 'open', '{}'::jsonb, $2)
        RETURNING id
        """,
        ip, old_time,
    )
    new_alert_id = await conn.fetchval(
        """
        INSERT INTO alerts (title, severity, mitre_technique, source_ip, threat_score, status, evidence, created_at)
        VALUES ('New alert', 'low', 'T1046', $1::inet, 10, 'open', '{}'::jsonb, $2)
        RETURNING id
        """,
        ip, new_time,
    )

    results = await correlate.run_all(conn)
    assert results["incidents_created"] == 2
    assert results["alerts_joined"] == 0

    old_incident_id = await conn.fetchval("SELECT incident_id FROM alerts WHERE id = $1", old_alert_id)
    new_incident_id = await conn.fetchval("SELECT incident_id FROM alerts WHERE id = $1", new_alert_id)
    assert old_incident_id != new_incident_id


async def test_incident_severity_follows_an_alert_escalated_after_linking(conn):
    # Enrichment can escalate an alert minutes after correlation already folded
    # it into an incident (a provider that was rate-limited, a retry). The
    # incident used to keep the severity it inherited at link time.
    ip = "203.0.113.232"
    alert_id = await conn.fetchval(
        """
        INSERT INTO alerts (title, severity, mitre_technique, source_ip, threat_score, status, evidence)
        VALUES ('Brute force', 'medium', 'T1110', $1::inet, 30, 'open', '{}'::jsonb)
        RETURNING id
        """,
        ip,
    )
    await correlate.run_all(conn)
    incident_id = await conn.fetchval("SELECT incident_id FROM alerts WHERE id = $1", alert_id)
    assert await conn.fetchval("SELECT severity FROM incidents WHERE id = $1", incident_id) == "medium"

    await conn.execute(
        "UPDATE alerts SET severity = 'high', threat_score = 65 WHERE id = $1", alert_id
    )
    await correlate.run_all(conn)

    assert await conn.fetchval("SELECT severity FROM incidents WHERE id = $1", incident_id) == "high"


async def test_incident_timeline_follows_an_alert_extended_by_a_merge(conn):
    # A repeat hit from the same attacker extends the open alert's
    # last_event_time instead of raising a second alert; the incident's
    # last_seen has to move with it.
    ip = "203.0.113.233"
    first_time = datetime.now(timezone.utc) - timedelta(minutes=20)
    alert_id = await conn.fetchval(
        """
        INSERT INTO alerts (title, severity, mitre_technique, source_ip, threat_score, status, evidence,
                            first_event_time, last_event_time)
        VALUES ('Brute force', 'medium', 'T1110', $1::inet, 30, 'open', '{}'::jsonb, $2, $2)
        RETURNING id
        """,
        ip, first_time,
    )
    await correlate.run_all(conn)
    incident_id = await conn.fetchval("SELECT incident_id FROM alerts WHERE id = $1", alert_id)
    assert await conn.fetchval("SELECT last_seen FROM incidents WHERE id = $1", incident_id) == first_time

    extended = first_time + timedelta(minutes=9)
    await conn.execute("UPDATE alerts SET last_event_time = $2 WHERE id = $1", alert_id, extended)
    await correlate.run_all(conn)

    assert await conn.fetchval("SELECT last_seen FROM incidents WHERE id = $1", incident_id) == extended


async def test_refreshing_an_unchanged_incident_leaves_it_exactly_as_it_was(conn):
    ip = "203.0.113.234"
    await insert_alert(
        conn, rule_id=None, title="Port scan", mitre_technique="T1046",
        source_ip=ip, threat_score=15, severity="low", evidence={},
    )
    await correlate.run_all(conn)

    columns = "severity, alert_count, first_seen, last_seen"
    before = await conn.fetchrow(f"SELECT {columns} FROM incidents WHERE source_ip = $1::inet", ip)
    await correlate.refresh_incidents(conn)
    after = await conn.fetchrow(f"SELECT {columns} FROM incidents WHERE source_ip = $1::inet", ip)

    assert dict(before) == dict(after)


async def test_password_spray_alert_gets_its_own_standalone_incident(conn):
    alert_id = await conn.fetchval(
        """
        INSERT INTO alerts (title, severity, mitre_technique, source_ip, threat_score, status, evidence)
        VALUES ('Password spray', 'high', 'T1110.003', NULL, 20, 'open', $1::jsonb)
        RETURNING id
        """,
        '{"username": "victim"}',
    )

    results = await correlate.run_all(conn)
    assert results["incidents_created"] == 1

    incident_id = await conn.fetchval("SELECT incident_id FROM alerts WHERE id = $1", alert_id)
    incident = await conn.fetchrow("SELECT * FROM incidents WHERE id = $1", incident_id)
    assert incident["source_ip"] is None
    assert incident["alert_count"] == 1
