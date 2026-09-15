"""The Phase 22 built-in rules: success after brute force, Windows account,
privilege and log-clearing rules, and firewall scans. Each has a case that
fires, a boundary, and a look-alike that must not fire.

Assertions look up alerts by this test's own host or IP, since a detection run
also scans whatever real events are in the window."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from detection import rule_engine, signature, threshold
from detection.seeding import builtin_rules

pytestmark = pytest.mark.asyncio(loop_scope="session")


def _ago(minutes=0.0):
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


async def _enable_all(conn):
    await conn.execute("UPDATE rules SET enabled = TRUE WHERE origin = 'builtin'")


async def _alerts(conn, rule_key, *, host=None, source_ip=None):
    return await conn.fetch(
        """
        SELECT * FROM alerts
        WHERE rule_id = (SELECT id FROM rules WHERE rule_key = $1)
          AND ($2::text IS NULL OR evidence->>'host' = $2)
          AND ($3::inet IS NULL OR source_ip = $3::inet)
        ORDER BY id
        """,
        rule_key, host, source_ip,
    )


async def _windows(conn, code, action, *, host, username=None, group=None, minutes_ago=2.0):
    raw = {"channel": "Security", "provider": "Microsoft-Windows-Security-Auditing"}
    if group:
        raw["group_name"] = group
    await conn.execute(
        """
        INSERT INTO events (event_time, source_type, event_code, action, username, host, raw, raw_message)
        VALUES ($1, 'windows', $2, $3, $4, $5, $6::jsonb, $7)
        """,
        _ago(minutes_ago), code, action, username, host, json.dumps(raw), f"pytest event {code}",
    )


async def test_the_new_rules_ship_with_the_right_types():
    rules = builtin_rules()
    assert {key: rules[key]["rule_type"] for key in (
        "brute_force_then_success", "win-account-created", "win-privileged-logon", "win-audit-log-cleared",
        "win-admin-group-add", "firewall-port-scan", "firewall-host-sweep",
    )} == {
        "brute_force_then_success": "sequence", "win-account-created": "signature",
        "win-privileged-logon": "signature", "win-audit-log-cleared": "signature",
        "win-admin-group-add": "signature", "firewall-port-scan": "threshold", "firewall-host-sweep": "threshold",
    }


# --- Windows ------------------------------------------------------------------------

async def test_account_creations_on_one_host_make_one_alert(conn):
    await _enable_all(conn)
    await _windows(conn, "4720", "account_created", host="PYTEST-DC01", username="backdoor1")
    await _windows(conn, "4720", "account_created", host="PYTEST-DC01", username="backdoor2", minutes_ago=1)
    await _windows(conn, "4726", "account_deleted", host="PYTEST-DC02", username="olduser")

    await signature.run_all(conn)

    alerts = await _alerts(conn, "win-account-created", host="PYTEST-DC01")
    assert len(alerts) == 1
    assert alerts[0]["title"] == "Windows account created on PYTEST-DC01"
    assert (alerts[0]["mitre_technique"], alerts[0]["severity"]) == ("T1136", "medium")
    assert alerts[0]["source_ip"] is None
    assert json.loads(alerts[0]["evidence"])["hit_count"] == 2
    assert await _alerts(conn, "win-account-created", host="PYTEST-DC02") == []


async def test_privileged_logons_by_people_alert_but_windows_own_accounts_do_not(conn):
    await _enable_all(conn)
    await _windows(conn, "4672", "privileged_logon", host="PYTEST-WS01", username="alice")
    for account in ("SYSTEM", "PYTEST-WS02$", "DWM-3", "LOCAL SERVICE", "umfd-0", "Network Service"):
        await _windows(conn, "4672", "privileged_logon", host="PYTEST-WS02", username=account)

    await signature.run_all(conn)

    alerts = await _alerts(conn, "win-privileged-logon", host="PYTEST-WS01")
    assert [a["title"] for a in alerts] == ["Privileged logon by alice on PYTEST-WS01"]
    assert json.loads(alerts[0]["evidence"])["username"] == "alice"
    assert await _alerts(conn, "win-privileged-logon", host="PYTEST-WS02") == []


async def test_privileged_logons_are_grouped_per_user_per_host(conn):
    await _enable_all(conn)
    for user, minutes in (("alice", 3), ("alice", 2), ("bob", 1)):
        await _windows(conn, "4672", "privileged_logon", host="PYTEST-WS03", username=user, minutes_ago=minutes)

    await signature.run_all(conn)

    alerts = await _alerts(conn, "win-privileged-logon", host="PYTEST-WS03")
    assert sorted(json.loads(a["evidence"])["username"] for a in alerts) == ["alice", "bob"]


async def test_a_cleared_event_log_alerts_high(conn):
    await _enable_all(conn)
    await _windows(conn, "1102", "audit_log_cleared", host="PYTEST-SRV01", username="mallory")
    # Event 104 from any provider other than Eventlog is parsed as a plain winevent.
    await _windows(conn, "104", "winevent", host="PYTEST-SRV02")

    await signature.run_all(conn)

    alerts = await _alerts(conn, "win-audit-log-cleared", host="PYTEST-SRV01")
    assert len(alerts) == 1
    assert (alerts[0]["severity"], alerts[0]["mitre_technique"]) == ("high", "T1070.001")
    assert await _alerts(conn, "win-audit-log-cleared", host="PYTEST-SRV02") == []


@pytest.mark.parametrize(
    "group,fires",
    [("Administrators", True), ("Domain Admins", True), ("enterprise admins", True),
     ("Remote Desktop Users", False), ("Administrators-Backup", False)],
)
async def test_only_privileged_group_additions_alert(conn, group, fires):
    await _enable_all(conn)
    await _windows(conn, "4732", "group_member_added", host="PYTEST-DC03", username="S-1-5-21-1", group=group)

    await signature.run_all(conn)

    assert len(await _alerts(conn, "win-admin-group-add", host="PYTEST-DC03")) == (1 if fires else 0)


# --- firewall -----------------------------------------------------------------------

async def _firewall(conn, ip, *, ports=None, dest_ips=None, action="blocked"):
    rows = [(ip, port, "192.0.2.10") for port in ports] if ports else [(ip, 443, dest) for dest in dest_ips]
    await conn.executemany(
        """
        INSERT INTO events (event_time, source_type, source_ip, dest_port, dest_ip, action, protocol)
        VALUES (now() - interval '1 minute', 'firewall', $1, $2, $3::inet, $4, 'tcp')
        """,
        [(*row, action) for row in rows],
    )


@pytest.mark.parametrize(
    "ip,ports,action,fires",
    [
        ("203.0.113.180", range(2000, 2010), "blocked", True),    # 10 ports
        ("203.0.113.181", range(2000, 2009), "blocked", False),   # 9 ports
        ("203.0.113.182", range(2000, 2010), "allowed", False),   # allowed, not blocked
    ],
)
async def test_firewall_blocked_port_scan(conn, ip, ports, action, fires):
    await _enable_all(conn)
    await _firewall(conn, ip, ports=list(ports), action=action)

    await threshold.run_all(conn)

    alerts = await _alerts(conn, "firewall-port-scan", source_ip=ip)
    assert len(alerts) == (1 if fires else 0)
    if fires:
        assert json.loads(alerts[0]["evidence"])["distinct_ports"] == 10


@pytest.mark.parametrize("ip,hosts,fires", [("203.0.113.183", 10, True), ("203.0.113.184", 9, False)])
async def test_firewall_host_sweep(conn, ip, hosts, fires):
    await _enable_all(conn)
    await _firewall(conn, ip, dest_ips=[f"10.20.0.{n}" for n in range(1, hosts + 1)])

    await threshold.run_all(conn)

    alerts = await _alerts(conn, "firewall-host-sweep", source_ip=ip)
    assert len(alerts) == (1 if fires else 0)
    if fires:
        evidence = json.loads(alerts[0]["evidence"])
        assert evidence["distinct_hosts"] == 10
        assert "10.20.0.1" in evidence["dest_ips"]
        assert alerts[0]["title"] == f"Host sweep from {ip}"


# --- success after brute force ----------------------------------------------------------

async def _logins(conn, ip, pattern, start_minutes_ago, *, gap_seconds=20):
    await conn.executemany(
        "INSERT INTO events (event_time, source_type, source_ip, username, action) VALUES ($1, 'ssh', $2, 'admin', $3)",
        [(_ago(start_minutes_ago) + timedelta(seconds=gap_seconds * i), ip,
          "login_failed" if c == "F" else "login_success") for i, c in enumerate(pattern)],
    )


async def test_five_failures_then_a_success_is_critical(conn):
    await _enable_all(conn)
    ip = "203.0.113.185"
    await _logins(conn, ip, "FFFFFS", 5)

    await rule_engine.run_rules(conn, "sequence")

    alerts = await _alerts(conn, "brute_force_then_success", source_ip=ip)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["title"] == f"Login succeeded after repeated failures from {ip}"
    assert json.loads(alerts[0]["evidence"])["failed_count"] == 5


async def test_four_failures_then_a_success_does_not_fire(conn):
    await _enable_all(conn)
    ip = "203.0.113.186"
    await _logins(conn, ip, "FFFFS", 5)

    await rule_engine.run_rules(conn, "sequence")

    assert await _alerts(conn, "brute_force_then_success", source_ip=ip) == []


async def test_a_success_eleven_minutes_after_the_failures_does_not_fire(conn):
    await _enable_all(conn)
    ip = "203.0.113.187"
    await _logins(conn, ip, "FFFFF", 20)                           # last failure at about -18.7 min
    await _logins(conn, ip, "S", 20 - (80 / 60) - 11)              # 11 minutes after it

    await rule_engine.run_rules(conn, "sequence")

    assert await _alerts(conn, "brute_force_then_success", source_ip=ip) == []


async def test_a_success_from_a_different_ip_does_not_fire(conn):
    await _enable_all(conn)
    await _logins(conn, "203.0.113.188", "FFFFF", 5)
    await _logins(conn, "203.0.113.189", "S", 2)

    await rule_engine.run_rules(conn, "sequence")

    assert await _alerts(conn, "brute_force_then_success", source_ip="203.0.113.189") == []
