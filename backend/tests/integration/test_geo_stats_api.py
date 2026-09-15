"""Where attacks came from, for the attack map: counts per country from the IP
location cache, over a day in 2024 that holds only this file's synthetic rows."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from config import settings

pytestmark = pytest.mark.asyncio(loop_scope="session")

DAY = datetime(2024, 3, 12, tzinfo=timezone.utc)
WINDOW = {"from": DAY.isoformat(), "to": (DAY + timedelta(days=1)).isoformat()}
HOST = "pytest-geo-host"
TITLE = "pytest-geo alert"
DE_IP, BR_IP, UNKNOWN_IP, PRIVATE_IP = "185.220.101.88", "200.160.2.3", "91.198.174.192", "10.9.8.7"


@pytest_asyncio.fixture(loop_scope="session")
async def admin(client):
    r = await client.post("/api/auth/login", json={"email": settings.admin_email, "password": settings.admin_password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def seeded(pool):
    async def cleanup(conn):
        await conn.execute("DELETE FROM alerts WHERE title = $1", TITLE)
        await conn.execute("DELETE FROM events WHERE host = $1", HOST)
        await conn.execute("DELETE FROM ip_geo WHERE ip = ANY($1::inet[])", [DE_IP, BR_IP, UNKNOWN_IP])

    async with pool.acquire() as conn:
        await cleanup(conn)
        await conn.executemany(
            "INSERT INTO ip_geo (ip, country, source, expires_at) VALUES ($1::inet, $2, 'ipinfo', now() + interval '1 day')",
            [(DE_IP, "DE"), (BR_IP, "BR")],
        )
        at = DAY + timedelta(hours=5)
        await conn.executemany(
            "INSERT INTO events (event_time, source_type, source_ip, action, host) VALUES ($1, 'firewall', $2::inet, 'blocked', $3)",
            [(at, ip, HOST) for ip in [DE_IP, DE_IP, DE_IP, BR_IP, UNKNOWN_IP, PRIVATE_IP]],
        )
        await conn.executemany(
            """
            INSERT INTO alerts (title, severity, source_ip, threat_score, status, evidence, first_event_time, last_event_time)
            VALUES ($1, $2, $3::inet, 20, 'resolved', '{}'::jsonb, $4, $4)
            """,
            [(TITLE, "medium", DE_IP, at), (TITLE, "critical", DE_IP, at), (TITLE, "low", BR_IP, at),
             (TITLE, "high", UNKNOWN_IP, at), (TITLE, "high", PRIVATE_IP, at)],
        )
    yield
    async with pool.acquire() as conn:
        await cleanup(conn)


async def _geo(client, admin, **params):
    r = await client.get("/api/stats/geo", params={**WINDOW, **params}, headers=admin)
    assert r.status_code == 200, r.text
    return r.json()


async def test_alerts_by_country_with_their_worst_severity(client, admin):
    body = await _geo(client, admin)

    assert body["metric"] == "alerts"
    assert body["countries"] == [
        {"country": "DE", "count": 2, "max_severity": "critical"},
        {"country": "BR", "count": 1, "max_severity": "low"},
    ]
    # The public IP with no known location counts as unlocated; the private one never does.
    assert body["unlocated"] == 1


async def test_events_by_country(client, admin):
    body = await _geo(client, admin, metric="events")

    assert body["countries"] == [
        {"country": "DE", "count": 3, "max_severity": None},
        {"country": "BR", "count": 1, "max_severity": None},
    ]
    assert body["unlocated"] == 1


async def test_the_range_is_respected(client, admin):
    other_day = {"from": (DAY - timedelta(days=2)).isoformat(), "to": (DAY - timedelta(days=1)).isoformat()}
    r = await client.get("/api/stats/geo", params=other_day, headers=admin)
    assert r.status_code == 200
    assert (r.json()["countries"], r.json()["unlocated"]) == ([], 0)


async def test_an_unknown_metric_is_422(client, admin):
    r = await client.get("/api/stats/geo", params={**WINDOW, "metric": "users"}, headers=admin)
    assert r.status_code == 422
