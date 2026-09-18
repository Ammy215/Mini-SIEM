"""Alert grouping: repeat hits from one attacker extend one open alert, reruns
never duplicate, and the sequence shape fires on failures followed by a success."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from config import settings
from detection import rule_engine, signature, threshold
from detection.alerting import MAX_EVIDENCE_VALUES

pytestmark = pytest.mark.asyncio(loop_scope="session")

XSS_URL = "/search?q=<script>alert(1)</script>"


def _now():
    return datetime.now(timezone.utc)


async def _xss_hits(conn, ip, count, *, start=None):
    start = start or _now() - timedelta(minutes=5)
    await conn.executemany(
        "INSERT INTO events (event_time, source_type, source_ip, url, action) VALUES ($1, 'nginx', $2, $3, 'request')",
        [(start + timedelta(seconds=i), ip, XSS_URL) for i in range(count)],
    )


async def _xss_alerts(conn, ip):
    return await conn.fetch(
        """
        SELECT * FROM alerts
        WHERE source_ip = $1::inet AND rule_id = (SELECT id FROM rules WHERE rule_key = 'xss-http-001')
        ORDER BY id
        """,
        ip,
    )


async def _enable(conn, *rule_keys):
    await conn.execute("UPDATE rules SET enabled = TRUE WHERE rule_key = ANY($1::text[])", list(rule_keys))


async def test_three_hits_from_one_ip_make_one_alert_and_a_rerun_adds_nothing(conn):
    await _enable(conn, "xss-http-001")
    ip = "203.0.113.160"
    await _xss_hits(conn, ip, 3)

    first = await signature.run_all(conn)
    second = await signature.run_all(conn)

    assert first["xss-http-001"] == 1
    assert second["xss-http-001"] == 0
    alerts = await _xss_alerts(conn, ip)
    assert len(alerts) == 1
    evidence = json.loads(alerts[0]["evidence"])
    assert evidence["hit_count"] == 3
    assert len(evidence["event_ids"]) == 3
    assert evidence["matched_patterns"] == ["<script>"]
    assert alerts[0]["group_key"] == ip
    assert alerts[0]["first_event_time"] < alerts[0]["last_event_time"]
    assert await conn.fetchval("SELECT count(*) FROM alert_events WHERE alert_id = $1", alerts[0]["id"]) == 3


async def test_a_later_hit_extends_the_open_alert(conn):
    await _enable(conn, "xss-http-001")
    ip = "203.0.113.161"
    await _xss_hits(conn, ip, 2, start=_now() - timedelta(minutes=10))
    await signature.run_all(conn)
    before = (await _xss_alerts(conn, ip))[0]

    await _xss_hits(conn, ip, 1, start=_now() - timedelta(minutes=1))
    assert (await signature.run_all(conn))["xss-http-001"] == 0

    alerts = await _xss_alerts(conn, ip)
    assert len(alerts) == 1
    assert json.loads(alerts[0]["evidence"])["hit_count"] == 3
    assert alerts[0]["last_event_time"] > before["last_event_time"]
    assert alerts[0]["threat_score"] == before["threat_score"]


async def test_different_attackers_get_separate_alerts(conn):
    await _enable(conn, "xss-http-001")
    await _xss_hits(conn, "203.0.113.162", 2)
    await _xss_hits(conn, "203.0.113.163", 2)

    assert (await signature.run_all(conn))["xss-http-001"] == 2


async def test_a_hit_after_the_alert_was_triaged_opens_a_new_alert(conn):
    await _enable(conn, "xss-http-001")
    ip = "203.0.113.164"
    await _xss_hits(conn, ip, 1, start=_now() - timedelta(minutes=10))
    await signature.run_all(conn)
    await conn.execute("UPDATE alerts SET status = 'acknowledged' WHERE source_ip = $1::inet", ip)

    await _xss_hits(conn, ip, 1, start=_now() - timedelta(minutes=1))
    assert (await signature.run_all(conn))["xss-http-001"] == 1
    assert len(await _xss_alerts(conn, ip)) == 2


async def test_a_hit_outside_the_group_window_opens_a_new_alert(conn):
    await _enable(conn, "xss-http-001")
    ip = "203.0.113.165"
    await _xss_hits(conn, ip, 1, start=_now() - timedelta(minutes=10))
    await signature.run_all(conn)
    # As if the first alert's events were two hours old.
    await conn.execute(
        "UPDATE alerts SET first_event_time = now() - interval '2 hours', last_event_time = now() - interval '2 hours' "
        "WHERE source_ip = $1::inet",
        ip,
    )

    await _xss_hits(conn, ip, 1, start=_now() - timedelta(minutes=1))
    assert (await signature.run_all(conn))["xss-http-001"] == 1


async def test_evidence_lists_are_capped_but_the_hit_count_is_not(conn):
    await _enable(conn, "xss-http-001")
    ip = "203.0.113.166"
    await _xss_hits(conn, ip, MAX_EVIDENCE_VALUES + 10)

    await signature.run_all(conn)

    evidence = json.loads((await _xss_alerts(conn, ip))[0]["evidence"])
    assert evidence["hit_count"] == MAX_EVIDENCE_VALUES + 10
    assert len(evidence["event_ids"]) == MAX_EVIDENCE_VALUES


async def test_a_threshold_rule_rerun_extends_instead_of_duplicating(conn):
    await _enable(conn, "brute_force")
    ip = "203.0.113.167"
    now = _now()
    await conn.executemany(
        "INSERT INTO events (event_time, source_type, source_ip, username, action) VALUES ($1, 'ssh', $2, $3, 'login_failed')",
        [(now - timedelta(seconds=i), ip, f"user{i % 3}") for i in range(12)],
    )

    assert (await threshold.run_all(conn))["brute_force"] == 1
    assert (await threshold.run_all(conn))["brute_force"] == 0

    alert = await conn.fetchrow(
        "SELECT * FROM alerts WHERE source_ip = $1::inet AND rule_id = (SELECT id FROM rules WHERE rule_key = 'brute_force')",
        ip,
    )
    evidence = json.loads(alert["evidence"])
    assert alert["title"] == f"Brute force login attempts from {ip}"
    assert evidence["failed_count"] == 12
    assert sorted(evidence["usernames"]) == ["user0", "user1", "user2"]


async def test_port_scan_evidence_keeps_ports_as_numbers(conn):
    await _enable(conn, "port_scan")
    ip = "203.0.113.168"
    now = _now()
    await conn.executemany(
        "INSERT INTO events (event_time, source_type, source_ip, dest_port, action) VALUES ($1, 'firewall', $2, $3, 'blocked')",
        [(now - timedelta(seconds=i), ip, 1000 + i) for i in range(15)],
    )

    await threshold.run_all(conn)

    evidence = json.loads(await conn.fetchval(
        "SELECT evidence FROM alerts WHERE source_ip = $1::inet AND rule_id = (SELECT id FROM rules WHERE rule_key = 'port_scan')",
        ip,
    ))
    assert evidence["distinct_ports"] == 15
    assert evidence["ports"] == sorted(evidence["ports"]) and all(isinstance(p, int) for p in evidence["ports"])


# --- sequence ----------------------------------------------------------------------

SEQUENCE_KEY = "pytest_failures_then_success"
SEQUENCE_DEFINITION = {
    "version": 2,
    "sequence": {
        "join_on": "source_ip",
        "first": {"filter": {"field": "action", "op": "eq", "value": "login_failed"}, "min_count": 5, "within_minutes": 10},
        "then": {"filter": {"field": "action", "op": "eq", "value": "login_success"}, "within_minutes": 10},
    },
    "alert": {"signal": "brute_force_confirmed", "title": "Login succeeded after failures from {source_ip}",
              "count_key": "failed_count"},
}


async def _sequence_rule(conn):
    await conn.execute(
        """
        INSERT INTO rules (rule_key, title, rule_type, severity, mitre_technique, definition, enabled, origin)
        VALUES ($1, 'Failures then success', 'sequence', 'critical', 'T1110', $2::jsonb, TRUE, 'custom')
        """,
        SEQUENCE_KEY, json.dumps(SEQUENCE_DEFINITION),
    )


async def _logins(conn, ip, pattern: str, start):
    """pattern: F = failed, S = success, one per 20 seconds from start."""
    await conn.executemany(
        "INSERT INTO events (event_time, source_type, source_ip, username, action) VALUES ($1, 'ssh', $2, 'admin', $3)",
        [(start + timedelta(seconds=20 * i), ip, "login_failed" if c == "F" else "login_success")
         for i, c in enumerate(pattern)],
    )


async def test_failures_followed_by_a_success_fire_once(conn):
    await _sequence_rule(conn)
    ip = "203.0.113.170"
    await _logins(conn, ip, "FFFFFS", _now() - timedelta(minutes=5))

    assert (await rule_engine.run_rules(conn, "sequence"))[SEQUENCE_KEY] == 1
    assert (await rule_engine.run_rules(conn, "sequence"))[SEQUENCE_KEY] == 0

    # The built-in brute_force_then_success rule fires on the same events; this is the test rule's alert.
    alert = await conn.fetchrow(
        "SELECT * FROM alerts WHERE source_ip = $1::inet AND rule_id = (SELECT id FROM rules WHERE rule_key = $2)",
        ip, SEQUENCE_KEY,
    )
    evidence = json.loads(alert["evidence"])
    assert alert["title"] == f"Login succeeded after failures from {ip}"
    assert alert["severity"] == "critical"
    assert evidence["failed_count"] == 5
    assert evidence["username"] == "admin"
    assert len(evidence["event_ids"]) == 6


@pytest.mark.parametrize(
    "pattern",
    [
        "FFFFS",    # one failure short
        "SFFFFF",   # the success came first
    ],
)
async def test_sequences_that_do_not_complete_do_not_fire(conn, pattern):
    await _sequence_rule(conn)
    await _logins(conn, "203.0.113.171", pattern, _now() - timedelta(minutes=5))

    assert (await rule_engine.run_rules(conn, "sequence"))[SEQUENCE_KEY] == 0


async def test_a_success_long_after_the_failures_does_not_fire(conn):
    await _sequence_rule(conn)
    ip = "203.0.113.172"
    await _logins(conn, ip, "FFFFF", _now() - timedelta(minutes=25))
    await _logins(conn, ip, "S", _now() - timedelta(minutes=2))

    assert (await rule_engine.run_rules(conn, "sequence"))[SEQUENCE_KEY] == 0


async def test_a_rule_whose_definition_does_not_match_its_type_never_runs(conn):
    await conn.execute(
        """
        INSERT INTO rules (rule_key, title, rule_type, severity, definition, enabled, origin)
        VALUES ('pytest_mistyped', 'Mistyped', 'threshold', 'low', $1::jsonb, TRUE, 'custom')
        """,
        json.dumps({"version": 2, "filter": {"field": "url", "op": "contains", "value": "/"}}),
    )
    await _xss_hits(conn, "203.0.113.173", 1)

    assert (await threshold.run_all(conn))["pytest_mistyped"] == 0



# --- after_hours ----------------------------------------------------------------------

def _business_hours(monkeypatch, hours):
    monkeypatch.setattr(settings, "business_hours", hours)
    monkeypatch.setattr(settings, "business_days", "mon-sun")
    monkeypatch.setattr(settings, "business_timezone", "UTC")


async def _one_xss_alert(conn, ip):
    await _enable(conn, "xss-http-001")
    await _xss_hits(conn, ip, 1)
    await signature.run_all(conn)
    alert = (await _xss_alerts(conn, ip))[0]
    return alert, json.loads(alert["evidence"])


async def test_an_alert_outside_business_hours_scores_after_hours(conn, monkeypatch):
    start = (_now().hour + 12) % 24  # a one-hour window half a day away from the events
    _business_hours(monkeypatch, f"{start:02d}:00-{start + 1:02d}:00")

    alert, evidence = await _one_xss_alert(conn, "203.0.113.174")

    assert alert["threat_score"] == 15 + 5
    assert evidence["context_signals"] == ["after_hours"]


async def test_an_alert_inside_business_hours_does_not(conn, monkeypatch):
    _business_hours(monkeypatch, "00:00-24:00")

    alert, evidence = await _one_xss_alert(conn, "203.0.113.175")

    assert alert["threat_score"] == 15
    assert "context_signals" not in evidence and "context_skipped" not in evidence


async def test_unconfigured_business_hours_are_recorded_as_skipped(conn):
    alert, evidence = await _one_xss_alert(conn, "203.0.113.176")

    assert alert["threat_score"] == 15
    assert evidence["context_skipped"] == ["after_hours: business hours not configured"]


async def test_an_old_burst_does_not_merge_into_an_alert_raised_today(conn):
    """Detection over a past range must not fold months-old events into a live alert.

    The merge window was checked in one direction only — "is the open alert too
    old for these events?" — so analysing an upload from March found the alert
    raised today for the same address and merged into it. Because merging widens
    the window with LEAST/GREATEST, the result was a single alert spanning six
    months, and the historical campaign vanished into an unrelated live one.
    """
    await _enable(conn, "xss-http-001")
    ip = "203.0.113.178"

    await _xss_hits(conn, ip, 3)                                   # today
    assert (await signature.run_all(conn))["xss-http-001"] == 1
    [live] = await _xss_alerts(conn, ip)

    months_ago = _now() - timedelta(days=180)
    await _xss_hits(conn, ip, 3, start=months_ago)
    scope = rule_engine.Scope(months_ago - timedelta(hours=1), months_ago + timedelta(hours=1))
    assert (await rule_engine.run_rules(conn, "signature", scope))["xss-http-001"] == 1

    alerts = await _xss_alerts(conn, ip)
    assert len(alerts) == 2, "the old burst should be its own alert, not folded into today's"
    old = next(a for a in alerts if a["id"] != live["id"])
    assert old["last_event_time"] < live["first_event_time"], "the two alerts must not overlap in time"
    still_live = next(a for a in alerts if a["id"] == live["id"])
    assert still_live["first_event_time"] == live["first_event_time"], \
        "today's alert must not have been stretched backwards"
