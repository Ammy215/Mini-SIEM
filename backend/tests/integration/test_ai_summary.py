"""The opt-in AI summary endpoints.

Access control, 404s, and the not-configured path run everywhere (CI has no
Groq key). The live call is opt-in with RUN_LIVE_AI=1, so ordinary test runs
never spend provider quota or depend on the network.
"""

import json
import os
import uuid

import pytest
import pytest_asyncio

from config import settings

pytestmark = pytest.mark.asyncio(loop_scope="session")

SQLI_EVIDENCE = {
    "event_id": 999001,
    "field": "url",
    "matched_patterns": ["UNION SELECT"],
    "value_snippet": "/search.html?q=1' UNION SELECT username,password FROM users--",
}


@pytest_asyncio.fixture(loop_scope="session")
async def alert_id(pool):
    async with pool.acquire() as conn:
        new_id = await conn.fetchval(
            """
            INSERT INTO alerts (title, severity, mitre_technique, source_ip, threat_score, status, evidence)
            VALUES ('SQL Injection Attempt in HTTP Request', 'medium', 'T1190', '203.0.113.202'::inet, 25,
                    'open', $1::jsonb)
            RETURNING id
            """,
            json.dumps(SQLI_EVIDENCE),
        )
    yield new_id
    async with pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM audit_log WHERE action = 'ai_summary_requested' AND detail->>'target_id' = $1",
            str(new_id),
        )
        await conn.execute("DELETE FROM alerts WHERE id = $1", new_id)


@pytest_asyncio.fixture(loop_scope="session")
async def admin_headers(client):
    r = await client.post(
        "/api/auth/login", json={"email": settings.admin_email, "password": settings.admin_password}
    )
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest_asyncio.fixture(loop_scope="session")
async def viewer_headers(client, pool):
    email = f"pytest_{uuid.uuid4().hex[:12]}@example.com"
    password = "ViewerPassword123"
    await client.post("/api/auth/register", json={"email": email, "password": password})
    async with pool.acquire() as conn:
        await conn.execute("UPDATE users SET is_active = TRUE WHERE email = $1", email)
    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    yield {"Authorization": f"Bearer {r.json()['access_token']}"}
    async with pool.acquire() as conn:
        user_id = await conn.fetchval("SELECT id FROM users WHERE email = $1", email)
        if user_id is not None:
            await conn.execute("DELETE FROM audit_log WHERE user_id = $1", user_id)
            await conn.execute("DELETE FROM users WHERE id = $1", user_id)


async def test_viewer_cannot_send_evidence_to_the_ai_provider(client, viewer_headers, alert_id):
    r = await client.post(f"/api/alerts/{alert_id}/summary", headers=viewer_headers)
    assert r.status_code == 403


async def test_anonymous_request_is_rejected(client, alert_id):
    r = await client.post(f"/api/alerts/{alert_id}/summary")
    assert r.status_code == 401


async def test_unknown_alert_and_incident_return_404(client, admin_headers):
    assert (await client.post("/api/alerts/999999999/summary", headers=admin_headers)).status_code == 404
    assert (await client.post("/api/incidents/999999999/summary", headers=admin_headers)).status_code == 404


async def test_not_configured_returns_503_and_nothing_is_sent_or_audited(
    client, admin_headers, alert_id, pool, monkeypatch
):
    monkeypatch.setattr(settings, "groq_api_key", "")
    r = await client.post(f"/api/alerts/{alert_id}/summary", headers=admin_headers)
    assert r.status_code == 503

    async with pool.acquire() as conn:
        audited = await conn.fetchval(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'ai_summary_requested' AND detail->>'target_id' = $1",
            str(alert_id),
        )
    assert audited == 0


@pytest.mark.skipif(
    os.environ.get("RUN_LIVE_AI") != "1" or not settings.groq_api_key,
    reason="live provider call; set RUN_LIVE_AI=1 with GROQ_API_KEY configured",
)
async def test_live_alert_summary_from_groq(client, admin_headers, alert_id, pool):
    r = await client.post(f"/api/alerts/{alert_id}/summary", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["target"] == "alert"
    assert body["target_id"] == alert_id
    assert body["provider"] == "groq"
    assert len(body["summary"]) > 40

    async with pool.acquire() as conn:
        detail = await conn.fetchval(
            "SELECT detail FROM audit_log WHERE action = 'ai_summary_requested' AND detail->>'target_id' = $1",
            str(alert_id),
        )
    detail = json.loads(detail)
    # The egress is audited, but the summary text itself is not stored.
    assert detail["provider"] == "groq"
    assert "summary" not in detail
