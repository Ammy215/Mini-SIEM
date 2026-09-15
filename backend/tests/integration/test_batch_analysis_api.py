"""Analysing an uploaded log for attacks through the API: queue it on upload,
let a detection pass run it, see its alerts, re-run it, and who may do what.

Uploads commit real rows; the batches, events, alerts and incidents a test
creates are removed afterwards."""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from config import settings

pytestmark = pytest.mark.asyncio(loop_scope="session")

IP = "203.0.113.203"
# Twelve failed SSH logins on 1 March, with no year in the timestamps (set via `year`).
SSH_LOG = "\n".join(
    f"Mar  1 10:00:{second:02d} pytest-host sshd[4242]: Failed password for root from {IP} port {40000 + second} ssh2"
    for second in range(0, 48, 4)
).encode()


async def _login(client, email, password):
    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest_asyncio.fixture(loop_scope="session")
async def admin(client):
    return await _login(client, settings.admin_email, settings.admin_password)


async def _user(client, pool, admin, role):
    email = f"pytest_analysis_{role}_{uuid.uuid4().hex[:10]}@example.com"
    r = await client.post(
        "/api/admin/users",
        json={"email": email, "password": "AnalysisPass123", "full_name": "Analysis Tester", "role": role},
        headers=admin,
    )
    assert r.status_code == 201, r.text
    return email, await _login(client, email, "AnalysisPass123")


@pytest_asyncio.fixture(loop_scope="session")
async def others(client, pool, admin):
    viewer_email, viewer = await _user(client, pool, admin, "viewer")
    analyst_email, analyst = await _user(client, pool, admin, "analyst")
    yield {"viewer": viewer, "analyst": analyst}
    async with pool.acquire() as conn:
        for email in (viewer_email, analyst_email):
            user_id = await conn.fetchval("SELECT id FROM users WHERE email = $1", email)
            if user_id is not None:
                await conn.execute("UPDATE ingest_batches SET detection_requested_by = NULL WHERE detection_requested_by = $1", user_id)
                await conn.execute("DELETE FROM audit_log WHERE user_id = $1", user_id)
                await conn.execute("DELETE FROM users WHERE id = $1", user_id)


@pytest_asyncio.fixture(loop_scope="session")
async def batches(pool):
    ids: list[str] = []
    yield ids
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM alerts WHERE batch_id = ANY($1::uuid[]) OR source_ip = $2::inet", ids, IP)
        await conn.execute("DELETE FROM incidents WHERE source_ip = $1::inet", IP)
        await conn.execute("DELETE FROM events WHERE batch_id = ANY($1::uuid[])", ids)
        await conn.execute("DELETE FROM ingest_batches WHERE id = ANY($1::uuid[])", ids)


async def _upload(client, headers, batches, *, analyze):
    r = await client.post(
        "/api/logs/upload",
        files={"file": ("pytest-auth.log", SSH_LOG, "text/plain")},
        data={"year": "2025", "analyze": "true" if analyze else "false"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    batches.append(r.json()["batch_id"])
    return r.json()


async def _run_until_analysed(client, headers, batch_id):
    """Detection passes analyse one queued upload each; keep going until ours is done."""
    for _ in range(6):
        r = await client.post("/api/detect/run", headers=headers)
        if r.status_code == 409:
            await asyncio.sleep(3)
            continue
        assert r.status_code == 200, r.text
        batch = (await client.get(f"/api/ingest/batches/{batch_id}", headers=headers)).json()
        if batch["detection_status"] in ("done", "failed"):
            return batch
    raise AssertionError("the upload was never analysed")


async def test_an_upload_queued_for_analysis_finds_its_old_attack(client, admin, batches):
    uploaded = await _upload(client, admin, batches, analyze=True)
    assert uploaded["detection_status"] == "queued"

    batch = await _run_until_analysed(client, admin, uploaded["batch_id"])

    assert batch["detection_status"] == "done"
    assert batch["detection_result"]["rules"].get("brute_force") == 1
    alerts = (await client.get("/api/alerts", params={"batch_id": uploaded["batch_id"]}, headers=admin)).json()["alerts"]
    brute_force = [a for a in alerts if a["source_ip"] == IP and a["mitre_technique"] == "T1110"]
    assert len(brute_force) == 1
    assert brute_force[0]["origin"] == "batch"
    assert brute_force[0]["first_event_time"].startswith("2025-03-01T10:00:00")

    # Analysing the same upload again finds the same attack, and adds no alert for it.
    r = await client.post(f"/api/ingest/batches/{uploaded['batch_id']}/analyze", headers=admin)
    assert r.status_code == 202 and r.json()["detection_status"] == "queued"
    again = await _run_until_analysed(client, admin, uploaded["batch_id"])
    assert again["detection_result"]["alerts_created"] == 0


async def test_an_upload_without_analyze_is_not_queued(client, admin, batches):
    uploaded = await _upload(client, admin, batches, analyze=False)
    assert uploaded["detection_status"] == "none"
    batch = (await client.get(f"/api/ingest/batches/{uploaded['batch_id']}", headers=admin)).json()
    assert batch["detection_status"] == "none" and batch["detection_result"] is None


async def test_who_may_request_analysis(client, admin, others, batches):
    uploaded = await _upload(client, admin, batches, analyze=False)
    url = f"/api/ingest/batches/{uploaded['batch_id']}/analyze"

    assert (await client.post(url, headers=others["viewer"])).status_code == 403
    assert (await client.post(url, headers=others["analyst"])).status_code == 202
    assert (await client.post(url, headers=others["analyst"])).status_code == 409  # already queued
    assert (await client.post(f"/api/ingest/batches/{uuid.uuid4()}/analyze", headers=admin)).status_code == 404


async def test_detection_over_a_past_range_is_admin_only_and_bounded(client, admin, others):
    day = datetime(2025, 3, 1, tzinfo=timezone.utc)
    valid = {"from": day.isoformat(), "to": (day + timedelta(days=1)).isoformat()}

    assert (await client.post("/api/detect/run", json=valid, headers=others["analyst"])).status_code == 403
    too_long = {"from": day.isoformat(), "to": (day + timedelta(days=31)).isoformat()}
    assert (await client.post("/api/detect/run", json=too_long, headers=admin)).status_code == 422
    backwards = {"from": valid["to"], "to": valid["from"]}
    assert (await client.post("/api/detect/run", json=backwards, headers=admin)).status_code == 422
    no_zone = {"from": "2025-03-01T00:00:00", "to": "2025-03-02T00:00:00"}
    assert (await client.post("/api/detect/run", json=no_zone, headers=admin)).status_code == 422

    for _ in range(6):
        r = await client.post("/api/detect/run", json=valid, headers=admin)
        if r.status_code != 409:
            break
        await asyncio.sleep(3)
    assert r.status_code == 200, r.text
    assert "range_rule_errors" in r.json()["results"]


async def test_alerts_can_be_filtered_by_origin(client, admin):
    r = await client.get("/api/alerts", params={"origin": "batch", "limit": 5}, headers=admin)
    assert r.status_code == 200
    assert all(alert["origin"] == "batch" for alert in r.json()["alerts"])
    assert (await client.get("/api/alerts", params={"origin": "nonsense"}, headers=admin)).status_code == 422
