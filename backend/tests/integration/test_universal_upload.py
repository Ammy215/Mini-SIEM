"""Uploading real-world log formats through the API: format detection, nothing
dropped in auto mode, batch records, access control and size limits.

Uploads commit real rows; each test's events and batches are removed afterwards."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio

from config import settings

pytestmark = pytest.mark.asyncio(loop_scope="session")

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


async def _login(client, email, password):
    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest_asyncio.fixture(loop_scope="session")
async def admin(client):
    return await _login(client, settings.admin_email, settings.admin_password)


@pytest_asyncio.fixture(loop_scope="session")
async def batches(pool):
    """Collects batch ids uploaded by a test and deletes their events and records afterwards."""
    ids: list[str] = []
    yield ids
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM events WHERE batch_id = ANY($1::uuid[])", ids)
        await conn.execute("DELETE FROM ingest_batches WHERE id = ANY($1::uuid[])", ids)


async def _upload(client, headers, batches, name, content, **form):
    r = await client.post(
        "/api/logs/upload", files={"file": (name, content, "text/plain")}, data=form, headers=headers
    )
    if r.status_code == 200:
        batches.append(r.json()["batch_id"])
    return r


async def _events(pool, batch_id):
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM events WHERE batch_id = $1::uuid ORDER BY id", batch_id)
    return [{**dict(row), "raw": json.loads(row["raw"]) if row["raw"] else None} for row in rows]


@pytest.mark.parametrize(
    "fixture,detected,by_parser",
    [
        ("mixed_auth.log", "syslog", {"ssh": 3, "syslog": 3}),
        ("apache_combined.log", "nginx", {"nginx": 4}),
        ("kv_firewall.log", "kv", {"kv": 3}),
        ("events.csv", "csv", {"csv": 3}),
        ("rfc5424.log", "syslog5424", {"syslog5424": 3}),
        ("sample_app.jsonl", "app", {"app": 3, "generic": 1}),
    ],
)
async def test_auto_upload_detects_the_format_and_keeps_every_line(client, admin, batches, fixture, detected, by_parser):
    r = await _upload(client, admin, batches, fixture, (FIXTURES / fixture).read_bytes())

    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["format"], body["detected_format"]) == ("auto", detected)
    assert body["by_parser"] == by_parser
    assert body["skipped"] == 0
    assert body["parsed"] == body["inserted"] == body["total_lines"] == sum(by_parser.values())


async def test_sshd_lines_in_a_mixed_syslog_file_keep_what_brute_force_detection_needs(client, admin, batches, pool):
    r = await _upload(client, admin, batches, "auth.log", (FIXTURES / "mixed_auth.log").read_bytes())
    events = await _events(pool, r.json()["batch_id"])

    failed = [e for e in events if e["action"] == "login_failed"]
    assert len(failed) == 2
    assert {str(e["source_ip"]) for e in failed} == {"198.51.100.23"}
    assert {e["username"] for e in failed} == {"root", "oracle"}
    assert {e["parser"] for e in events} == {"ssh", "syslog"}
    assert all(e["host"] == "bastion" for e in events)


async def test_csv_and_key_value_columns_land_in_event_fields(client, admin, batches, pool):
    csv_batch = (await _upload(client, admin, batches, "events.csv", (FIXTURES / "events.csv").read_bytes())).json()
    kv_batch = (await _upload(client, admin, batches, "fw.log", (FIXTURES / "kv_firewall.log").read_bytes())).json()

    first_csv = (await _events(pool, csv_batch["batch_id"]))[0]
    assert (str(first_csv["source_ip"]), first_csv["dest_port"], first_csv["username"]) == ("203.0.113.61", 22, "root")
    assert (first_csv["action"], first_csv["outcome"]) == ("login_failed", "failure")
    assert first_csv["event_time"] == datetime(2026, 9, 14, 10, 5, tzinfo=timezone.utc)

    first_kv = (await _events(pool, kv_batch["batch_id"]))[0]
    assert (str(first_kv["source_ip"]), first_kv["dest_port"], first_kv["action"]) == ("203.0.113.50", 22, "deny")
    assert first_kv["event_time"] == datetime(2026, 9, 14, 10, 1, 2, tzinfo=timezone.utc)


async def test_text_nothing_recognises_is_stored_and_its_ips_are_not_trusted_as_sources(client, admin, batches, pool):
    content = (
        b"free-form note mentioning 203.0.113.77 at 2026-09-14T08:00:00Z\n"
        b"\xff\xfe binary-ish junk\n"
        b'{"source_ip": "203.0.113.78", "x": NaN}\n'
    )
    r = await _upload(client, admin, batches, "notes.txt", content)

    body = r.json()
    assert (body["detected_format"], body["parsed"], body["skipped"]) == ("unrecognized", 3, 0)
    assert body["by_parser"] == {"generic": 3}

    events = await _events(pool, body["batch_id"])
    assert all(e["source_ip"] is None for e in events)
    assert events[0]["raw"]["_ips_found"] == ["203.0.113.77"]
    assert events[0]["event_time"] == datetime(2026, 9, 14, 8, tzinfo=timezone.utc)
    assert events[1]["raw"]["_time_inferred"] is True


async def test_forced_format_is_strict_and_explains_each_skipped_line(client, admin, batches):
    r = await _upload(client, admin, batches, "auth.log", (FIXTURES / "mixed_auth.log").read_bytes(), format="ssh")

    body = r.json()
    assert (body["format"], body["confidence"]) == ("ssh", None)
    assert (body["parsed"], body["skipped"]) == (3, 3)
    assert body["skipped_reasons"] == {"unrecognized_format": 3}
    assert [s["line"] for s in body["skipped_samples"]] == [3, 5, 6]
    assert body["skipped_samples"][0]["excerpt"].startswith("Sep 14 09:00:05 bastion CRON")


async def test_year_hint_dates_yearless_lines(client, admin, batches, pool):
    line = b"Mar 01 10:00:00 host sshd[1]: Failed password for root from 203.0.113.79 port 1 ssh2\n"
    r = await _upload(client, admin, batches, "old_auth.log", line, year="2019")

    events = await _events(pool, r.json()["batch_id"])
    assert events[0]["event_time"].year == 2019


async def test_batch_history_detail_and_events_by_batch(client, admin, batches, pool):
    r = await _upload(client, admin, batches, "history.log", (FIXTURES / "apache_combined.log").read_bytes())
    batch_id = r.json()["batch_id"]

    listing = (await client.get("/api/ingest/batches", headers=admin)).json()
    listed = next(b for b in listing["batches"] if b["id"] == batch_id)
    assert (listed["filename"], listed["uploaded_by"]) == ("history.log", settings.admin_email)
    assert listed["first_event_time"] < listed["last_event_time"]

    detail = await client.get(f"/api/ingest/batches/{batch_id}", headers=admin)
    assert detail.status_code == 200
    assert detail.json()["by_parser"] == {"nginx": 4}

    by_batch = (await client.get("/api/events", params={"batch_id": batch_id}, headers=admin)).json()
    assert by_batch["total"] == 4
    assert {e["parser"] for e in by_batch["events"]} == {"nginx"}

    assert (await client.get(f"/api/ingest/batches/{uuid.uuid4()}", headers=admin)).status_code == 404
    assert (await client.get("/api/ingest/batches/not-a-uuid", headers=admin)).status_code == 422


async def test_upload_is_audited(client, admin, batches, pool):
    r = await _upload(client, admin, batches, "audited.log", (FIXTURES / "kv_firewall.log").read_bytes())
    batch_id = r.json()["batch_id"]

    async with pool.acquire() as conn:
        detail = await conn.fetchval(
            "SELECT detail FROM audit_log WHERE action = 'logs_uploaded' AND detail->>'batch_id' = $1", batch_id
        )
    assert json.loads(detail)["detected_format"] == "kv"


async def test_formats_endpoint_lists_every_upload_format(client, admin):
    r = await client.get("/api/ingest/formats", headers=admin)
    assert r.status_code == 200
    names = [fmt["name"] for fmt in r.json()["formats"]]
    assert names == [
        "auto", "ssh", "nginx", "windows", "app", "cef", "iptables", "syslog5424", "syslog", "kv", "csv", "generic",
    ]
    assert r.json()["max_upload_bytes"] == settings.max_upload_bytes


async def test_unknown_format_and_impossible_year_are_rejected(client, admin, batches):
    r = await _upload(client, admin, batches, "x.log", b"hello\n", format="evtx-binary")
    assert r.status_code == 400

    r = await _upload(client, admin, batches, "x.log", b"hello\n", year="1800")
    assert r.status_code == 422


async def test_viewer_cannot_upload_list_formats_or_see_batches(client, pool, admin):
    email = f"pytest_upload_viewer_{uuid.uuid4().hex[:10]}@example.com"
    password = "ViewerPass123"
    created = await client.post(
        "/api/admin/users",
        json={"email": email, "password": password, "full_name": "Upload Viewer", "role": "viewer"},
        headers=admin,
    )
    assert created.status_code == 201, created.text
    try:
        viewer = await _login(client, email, password)
        upload = await client.post(
            "/api/logs/upload", files={"file": ("x.log", b"hello\n", "text/plain")}, headers=viewer
        )
        assert upload.status_code == 403
        assert (await client.get("/api/ingest/formats", headers=viewer)).status_code == 403
        assert (await client.get("/api/ingest/batches", headers=viewer)).status_code == 403
    finally:
        async with pool.acquire() as conn:
            user_id = await conn.fetchval("SELECT id FROM users WHERE email = $1", email)
            await conn.execute("DELETE FROM audit_log WHERE user_id = $1", user_id)
            await conn.execute("DELETE FROM users WHERE id = $1", user_id)


# --- size limits ------------------------------------------------------------------

async def _batch_count(pool, filename):
    async with pool.acquire() as conn:
        return await conn.fetchval("SELECT COUNT(*) FROM ingest_batches WHERE filename = $1", filename)


async def test_file_over_the_upload_limit_is_rejected(client, admin, batches, pool, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 1024)

    r = await _upload(client, admin, batches, "just_over.log", b"x" * 4096)

    assert r.status_code == 413
    assert "upload limit" in r.json()["detail"]
    assert await _batch_count(pool, "just_over.log") == 0


async def test_body_far_over_the_limit_is_refused_before_it_is_read(client, admin, batches, pool, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 1024)

    r = await _upload(client, admin, batches, "far_over.log", b"x" * 200_000)

    assert r.status_code == 413
    assert "Request body is larger" in r.json()["detail"]
    assert await _batch_count(pool, "far_over.log") == 0


async def test_streamed_ingest_body_without_a_length_is_cut_off(client, admin, monkeypatch):
    monkeypatch.setattr(settings, "max_ingest_body_bytes", 10_000)

    async def chunks():
        yield b"["
        for _ in range(500):
            yield b'{"source_type": "app", "action": "stream-test"},'
        yield b'{"source_type": "app"}]'

    r = await client.post(
        "/api/ingest", content=chunks(), headers={**admin, "Content-Type": "application/json"}
    )
    assert r.status_code == 413


async def test_more_than_1000_events_in_one_ingest_call_is_rejected(client, admin, pool):
    marker = f"pytest-cap-{uuid.uuid4().hex[:8]}"
    body = [{"source_type": "app", "action": marker} for _ in range(1001)]

    r = await client.post("/api/ingest", json=body, headers=admin)

    assert r.status_code == 413
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT COUNT(*) FROM events WHERE action = $1", marker) == 0


async def test_ingest_api_rejects_nan_in_raw_with_422(client, admin):
    """Regression: the default 422 echoed the rejected value back, and a value
    holding NaN can't be encoded as JSON — so the error response itself crashed."""
    r = await client.post(
        "/api/ingest",
        content='{"source_type": "app", "raw": {"x": NaN}}',
        headers={**admin, "Content-Type": "application/json"},
    )
    assert r.status_code == 422
    # The body accepts one event or a list, so there is an error per shape.
    assert any("plain JSON" in error["msg"] for error in r.json()["detail"])


async def test_validation_errors_never_echo_the_submitted_value(client, admin):
    payload = "<script>alert('reflected')</script>"
    r = await client.post("/api/ingest", json={"source_type": "app", "source_ip": payload}, headers=admin)

    assert r.status_code == 422
    assert payload not in r.text
    assert any("source_ip" in error["loc"] for error in r.json()["detail"])
    assert all(set(error) <= {"type", "loc", "msg"} for error in r.json()["detail"])
