"""Dashboard analytics and Events filters through the API, over a day in 2024
that holds only this file's synthetic events and alerts (committed for each
test, removed afterwards)."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from config import settings
from detection.mitre import TACTIC_ORDER

pytestmark = pytest.mark.asyncio(loop_scope="session")

DAY = datetime(2024, 2, 10, tzinfo=timezone.utc)
WINDOW = {"from": DAY.isoformat(), "to": (DAY + timedelta(days=1)).isoformat()}
HOST = "pytest-stats-host"
USER = "pytest-stats-user"
SSH_IP = "203.0.113.210"
GEO_IP = "185.220.101.77"
ALERT_TITLE = "pytest-stats alert"


@pytest_asyncio.fixture(loop_scope="session")
async def admin(client):
    r = await client.post("/api/auth/login", json={"email": settings.admin_email, "password": settings.admin_password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def seeded(pool):
    async def cleanup(conn):
        await conn.execute("DELETE FROM alerts WHERE title = $1", ALERT_TITLE)
        await conn.execute("DELETE FROM events WHERE host = $1", HOST)
        await conn.execute("DELETE FROM ip_geo WHERE ip = $1::inet", GEO_IP)

    async with pool.acquire() as conn:
        await cleanup(conn)
        rows = (
            [(DAY + timedelta(hours=1), "ssh", SSH_IP, USER, "login_failed", None, None)] * 3
            + [(DAY + timedelta(hours=1, minutes=5), "ssh", SSH_IP, USER, "login_success", None, None)] * 2
            + [(DAY + timedelta(hours=2), "firewall", GEO_IP, None, "blocked", 3389, None)]
            + [(DAY + timedelta(hours=3), "windows", None, "newadmin", "account_created", None, "4720")]
        )
        await conn.executemany(
            """
            INSERT INTO events (event_time, source_type, source_ip, username, action, dest_port, event_code, host)
            VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8)
            """,
            [(*row, HOST) for row in rows],
        )
        await conn.executemany(
            """
            INSERT INTO alerts (title, severity, mitre_technique, source_ip, threat_score, status, evidence,
                                first_event_time, last_event_time)
            VALUES ($1, $2, $3, $4::inet, 30, 'resolved', '{}'::jsonb, $5, $5)
            """,
            [
                (ALERT_TITLE, "high", "T1110", SSH_IP, DAY + timedelta(hours=1, minutes=2)),
                (ALERT_TITLE, "low", "T1046", GEO_IP, DAY + timedelta(hours=2, minutes=1)),
            ],
        )
        await conn.execute(
            """
            INSERT INTO ip_geo (ip, country, source, expires_at) VALUES ($1::inet, 'AQ', 'ipinfo', now() + interval '1 day')
            ON CONFLICT (ip) DO UPDATE SET country = 'AQ', expires_at = EXCLUDED.expires_at
            """,
            GEO_IP,
        )
    yield
    async with pool.acquire() as conn:
        await cleanup(conn)


async def _get(client, admin, path, **params):
    r = await client.get(path, params=params, headers=admin)
    assert r.status_code == 200, r.text
    return r.json()


async def test_breakdown_counts_logins_sources_severities_and_actions(client, admin):
    body = await _get(client, admin, "/api/stats/breakdown", **WINDOW)

    assert body["logins"] == {"success": 2, "failed": 3}
    assert {s["name"]: s["count"] for s in body["events_by_source"]} == {"ssh": 5, "firewall": 1, "windows": 1}
    assert body["alerts_by_severity"] == {"low": 1, "medium": 0, "high": 1, "critical": 0}
    assert body["top_actions"][0] == {"name": "login_failed", "count": 3}


async def test_a_six_hour_timeline_has_every_five_minute_bucket(client, admin):
    body = await _get(
        client, admin, "/api/stats/timeline", **{"from": DAY.isoformat(), "to": (DAY + timedelta(hours=6)).isoformat()}
    )

    assert body["bucket_seconds"] == 300
    assert len(body["buckets"]) == 72
    counts = {b["bucket"][:16]: (b["event_count"], b["alert_count"]) for b in body["buckets"]}
    assert counts["2024-02-10T01:00"] == (3, 1)
    assert counts["2024-02-10T01:05"] == (2, 0)
    assert counts["2024-02-10T02:00"] == (1, 1)
    assert counts["2024-02-10T00:00"] == (0, 0)


async def test_a_day_timeline_is_hourly(client, admin):
    body = await _get(client, admin, "/api/stats/timeline", **WINDOW)

    assert (body["bucket_seconds"], len(body["buckets"])) == (3600, 24)
    assert body["buckets"][1]["event_count"] == 5


async def test_the_older_hours_parameter_still_works(client, admin):
    body = await _get(client, admin, "/api/stats/timeline", hours=6)
    assert body["bucket_seconds"] == 3600


async def test_dashboard_and_top_attackers_follow_the_range(client, admin):
    stats = await _get(client, admin, "/api/stats/dashboard", **WINDOW)
    assert (stats["events_in_range"], stats["alerts_in_range"]) == (7, 2)

    attackers = await _get(client, admin, "/api/stats/top-attackers", **WINDOW)
    assert {a["source_ip"]: a["max_severity"] for a in attackers["attackers"]} == {SSH_IP: "high", GEO_IP: "low"}


async def test_mitre_coverage_is_in_tactic_order_with_counts(client, admin):
    body = await _get(client, admin, "/api/stats/mitre", **WINDOW)

    tactics = [t["tactic"] for t in body["tactics"]]
    assert tactics == [t for t in TACTIC_ORDER if t in tactics]
    by_id = {tech["id"]: tech for t in body["tactics"] for tech in t["techniques"]}
    assert by_id["T1110"]["alert_count"] == 1 and by_id["T1110"]["enabled_rules"] >= 1
    assert by_id["T1046"]["alert_count"] == 1
    assert by_id["T1190"]["alert_count"] == 0
    # A technique under several tactics appears under each of them.
    assert sum(1 for t in body["tactics"] for tech in t["techniques"] if tech["id"] == "T1078") == 4
    assert body["techniques_with_alerts"] == 2


@pytest.mark.parametrize(
    "filters,expected",
    [
        ({"username": USER}, 5),
        ({"event_code": "4720"}, 1),
        ({"dest_port": 3389}, 1),
        ({"country": "AQ"}, 1),
        ({"host": HOST.upper()}, 7),
        ({"source_type": "ssh", "username": USER}, 5),
    ],
)
async def test_events_filters(client, admin, filters, expected):
    body = await _get(client, admin, "/api/events", **WINDOW, **filters)
    assert body["total"] == expected


async def test_event_country_comes_from_the_ip_location_cache(client, admin):
    body = await _get(client, admin, "/api/events", **WINDOW, dest_port=3389)
    assert body["events"][0]["country"] == "AQ"


@pytest.mark.parametrize(
    "path,params",
    [
        ("/api/stats/timeline", {"range": "2y"}),
        ("/api/stats/breakdown", {"from": DAY.isoformat()}),
        ("/api/stats/mitre", {"from": WINDOW["to"], "to": WINDOW["from"]}),
        ("/api/stats/dashboard", {"from": DAY.isoformat(), "to": (DAY + timedelta(days=91)).isoformat()}),
        ("/api/stats/breakdown", {"from": "2024-02-10T00:00:00", "to": "2024-02-11T00:00:00"}),
        ("/api/stats/timeline", {"range": "24h", **WINDOW}),
        ("/api/events", {"country": "usa"}),
        ("/api/events", {"dest_port": 70000}),
        ("/api/events", {"from": WINDOW["to"], "to": WINDOW["from"]}),
    ],
)
async def test_invalid_ranges_and_filters_are_422(client, admin, path, params):
    r = await client.get(path, params=params, headers=admin)
    assert r.status_code == 422, r.text
