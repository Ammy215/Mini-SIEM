from pathlib import Path

import pytest

from config import settings

pytestmark = pytest.mark.asyncio(loop_scope="session")

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
async def admin_token(client):
    r = await client.post(
        "/api/auth/login", json={"email": settings.admin_email, "password": settings.admin_password}
    )
    assert r.status_code == 200
    return r.json()["access_token"]


async def test_upload_ssh_fixture_log_normalizes_events(client, admin_token, pool):
    async with pool.acquire() as conn:
        before_max_id = await conn.fetchval("SELECT COALESCE(MAX(id), 0) FROM events")

    content = (FIXTURES_DIR / "sample_ssh.log").read_bytes()
    r = await client.post(
        "/api/logs/upload",
        files={"file": ("sample_ssh.log", content, "text/plain")},
        data={"source_type": "ssh"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    # 7 lines in the fixture, 1 doesn't match the ssh log format.
    assert body["total_lines"] == 7
    assert body["parsed"] == 6
    assert body["skipped"] == 1
    assert body["inserted"] == 6

    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM events WHERE id > $1", before_max_id)


async def test_ingest_and_detect_produces_sqli_alert_and_incident(client, admin_token, pool):
    ip = "203.0.113.250"
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/ingest",
        json={
            "source_type": "nginx", "source_ip": ip, "method": "GET",
            "url": "/search?q=' OR 1=1", "action": "request", "status_code": 200,
        },
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 1

    r = await client.post("/api/detect/run", headers=headers)
    assert r.status_code == 200
    assert r.json()["results"].get("sqli-http-001", 0) >= 1

    r = await client.get("/api/alerts", params={"limit": 200}, headers=headers)
    matching_alerts = [a for a in r.json()["alerts"] if a["source_ip"] == ip and a["mitre_technique"] == "T1190"]
    assert len(matching_alerts) == 1

    r = await client.get("/api/incidents", params={"limit": 200}, headers=headers)
    matching_incidents = [i for i in r.json()["incidents"] if i["source_ip"] == ip]
    assert len(matching_incidents) == 1

    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM alerts WHERE source_ip = $1::inet", ip)
        await conn.execute("DELETE FROM incidents WHERE source_ip = $1::inet", ip)
        await conn.execute("DELETE FROM events WHERE source_ip = $1::inet", ip)
