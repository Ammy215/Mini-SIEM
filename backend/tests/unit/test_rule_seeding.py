"""Seeding keeps untouched built-ins current and leaves edited rules alone;
a rule's severity is the floor for the alerts it raises."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from detection import enrich_alerts, signature, threshold
from detection.seeding import builtin_rules, seed_builtin_rules

pytestmark = pytest.mark.asyncio(loop_scope="session")


async def _rule(conn, rule_key):
    row = await conn.fetchrow("SELECT * FROM rules WHERE rule_key = $1", rule_key)
    return {**dict(row), "definition": json.loads(row["definition"])}


async def test_an_untouched_builtin_keeps_tracking_the_shipped_definition(conn):
    await conn.execute(
        """UPDATE rules SET title = 'stale title', definition = '{"window_minutes": 99, "threshold": 99}'::jsonb,
           user_modified = FALSE WHERE rule_key = 'brute_force'"""
    )

    await seed_builtin_rules(conn)

    rule = await _rule(conn, "brute_force")
    assert rule["title"] == builtin_rules()["brute_force"]["title"]
    assert rule["definition"] == builtin_rules()["brute_force"]["definition"]


async def test_an_edited_rule_survives_a_restart(conn):
    edited = {**builtin_rules()["brute_force"]["definition"], "window_minutes": 20}
    await conn.execute(
        """UPDATE rules SET title = 'Tuned brute force', severity = 'critical', definition = $1::jsonb,
           user_modified = TRUE WHERE rule_key = 'brute_force'""",
        json.dumps(edited),
    )

    await seed_builtin_rules(conn)  # what every startup runs

    rule = await _rule(conn, "brute_force")
    assert rule["title"] == "Tuned brute force"
    assert rule["severity"] == "critical"
    assert rule["definition"]["window_minutes"] == 20
    assert rule["user_modified"] is True


async def test_seeding_never_changes_whether_a_rule_is_enabled(conn):
    await conn.execute("UPDATE rules SET enabled = FALSE WHERE rule_key = 'port_scan'")
    await seed_builtin_rules(conn)
    assert (await _rule(conn, "port_scan"))["enabled"] is False


async def test_threshold_alert_is_never_below_its_rules_severity(conn):
    await conn.execute("UPDATE rules SET severity = 'high', enabled = TRUE WHERE rule_key = 'brute_force'")
    ip = "203.0.113.214"
    now = datetime.now(timezone.utc)
    await conn.executemany(
        "INSERT INTO events (event_time, source_type, source_ip, username, action) VALUES ($1, 'ssh', $2, 'admin', 'login_failed')",
        [(now - timedelta(seconds=i), ip) for i in range(11)],
    )

    await threshold.run_all(conn)

    alert = await conn.fetchrow(
        "SELECT threat_score, severity FROM alerts WHERE source_ip = $1::inet "
        "AND rule_id = (SELECT id FROM rules WHERE rule_key = 'brute_force')",
        ip,
    )
    assert alert["threat_score"] == 30  # on its own, only the medium band
    assert alert["severity"] == "high"


async def test_signature_alert_is_never_below_its_rules_severity(conn):
    await conn.execute("UPDATE rules SET severity = 'critical', enabled = TRUE WHERE rule_key = 'xss-http-001'")
    ip = "203.0.113.215"
    await conn.execute(
        "INSERT INTO events (event_time, source_type, source_ip, url) VALUES (now(), 'nginx', $1, '/search?q=<script>alert(1)</script>')",
        ip,
    )

    await signature.run_all(conn)

    alert = await conn.fetchrow(
        "SELECT threat_score, severity FROM alerts WHERE source_ip = $1::inet "
        "AND rule_id = (SELECT id FROM rules WHERE rule_key = 'xss-http-001')",
        ip,
    )
    assert alert["threat_score"] == 15
    assert alert["severity"] == "critical"


async def test_enrichment_escalation_never_lowers_an_alerts_severity(conn):
    ip = "45.155.205.233"
    for provider, data in (("abuseipdb", {"abuse_confidence_score": 40, "is_whitelisted": False}), ("otx", {"pulse_count": 2})):
        await conn.execute(
            """
            INSERT INTO ioc_cache (indicator, indicator_type, provider, data, expires_at)
            VALUES ($1, 'ip', $2, $3::jsonb, now() + interval '1 day')
            ON CONFLICT (indicator, provider) DO UPDATE SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at
            """,
            ip, provider, json.dumps(data),
        )
    alert_id = await conn.fetchval(
        """
        INSERT INTO alerts (title, severity, mitre_technique, source_ip, threat_score, status, evidence)
        VALUES ('Brute force login attempts', 'high', 'T1110', $1::inet, 30, 'open', '{}'::jsonb)
        RETURNING id
        """,
        ip,
    )

    await enrich_alerts.run_all(conn)

    alert = await conn.fetchrow("SELECT threat_score, severity FROM alerts WHERE id = $1", alert_id)
    assert alert["threat_score"] == 45  # +15 otx_pulse_match: the medium band on its own
    assert alert["severity"] == "high"


async def test_a_poisoned_field_written_straight_to_the_table_still_never_reaches_sql(conn):
    """The Rules API rejects this now; the evaluator's own whitelist stays as a second layer."""
    poisoned = {**builtin_rules()["sqli-http-001"]["definition"], "field": "url FROM events; DROP TABLE alerts; --"}
    await conn.execute(
        "UPDATE rules SET definition = $1::jsonb, enabled = TRUE WHERE rule_key = 'sqli-http-001'",
        json.dumps(poisoned),
    )

    results = await signature.run_all(conn)

    assert results["sqli-http-001"] == 0
    assert await conn.fetchval("SELECT to_regclass('alerts') IS NOT NULL")
