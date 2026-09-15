"""Custom rules through the API: admin-only authoring, validation, dry-run
preview, deletion, and the run health shown with each rule.

These go through the real API, so changes are committed; every rule, event and
alert a test creates uses a pytest- marker and is removed afterwards."""

import json
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest
import pytest_asyncio

from config import settings
from detection import engine, rule_engine

pytestmark = pytest.mark.asyncio(loop_scope="session")

KEY_PREFIX = "pytest-authoring-"


def _key():
    return f"{KEY_PREFIX}{uuid.uuid4().hex[:10]}"


def _signature(value="/pytest-authoring"):
    return {"version": 2, "filter": {"field": "url", "op": "contains", "value": value}}


def _body(**changes):
    return {
        "rule_key": _key(), "title": "Custom probe", "severity": "medium", "mitre_technique": "T1190",
        "definition": _signature(), **changes,
    }


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def _cleanup(pool):
    yield
    async with pool.acquire() as conn:
        rule_ids = await conn.fetch("SELECT id FROM rules WHERE rule_key LIKE $1", f"{KEY_PREFIX}%")
        ids = [row["id"] for row in rule_ids]
        await conn.execute("DELETE FROM alerts WHERE rule_id = ANY($1::int[])", ids)
        await conn.execute("DELETE FROM rules WHERE id = ANY($1::int[])", ids)
        await conn.execute("DELETE FROM events WHERE url LIKE '/pytest-authoring%' OR username LIKE 'pytest-authoring%'")


async def _login(client, email, password):
    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest_asyncio.fixture(loop_scope="session")
async def admin(client):
    return await _login(client, settings.admin_email, settings.admin_password)


@pytest_asyncio.fixture(loop_scope="session")
async def analyst(client, pool, admin):
    email = f"pytest_authoring_{uuid.uuid4().hex[:12]}@example.com"
    password = "AnalystPass123"
    r = await client.post(
        "/api/admin/users",
        json={"email": email, "password": password, "full_name": "Authoring Analyst", "role": "analyst"},
        headers=admin,
    )
    assert r.status_code == 201, r.text
    yield await _login(client, email, password)
    async with pool.acquire() as conn:
        user_id = await conn.fetchval("SELECT id FROM users WHERE email = $1", email)
        if user_id is not None:
            await conn.execute("DELETE FROM audit_log WHERE user_id = $1", user_id)
            await conn.execute("DELETE FROM users WHERE id = $1", user_id)


async def _rules(client, headers):
    return (await client.get("/api/rules", headers=headers)).json()["rules"]


async def test_an_admin_creates_a_custom_rule_that_survives_a_restart(client, pool, admin):
    body = _body()
    r = await client.post("/api/rules", json=body, headers=admin)
    assert r.status_code == 201, r.text
    created = r.json()
    assert (created["origin"], created["rule_type"], created["enabled"]) == ("custom", "signature", True)

    async with pool.acquire() as conn:
        await engine.seed_all(conn)
        audit = await conn.fetchval(
            "SELECT count(*) FROM audit_log WHERE action = 'rule_created' AND detail->>'rule_key' = $1", body["rule_key"]
        )

    listed = next(rule for rule in await _rules(client, admin) if rule["rule_key"] == body["rule_key"])
    assert listed["definition"] == body["definition"]
    assert audit == 1


async def test_only_admins_can_author_rules(client, analyst):
    assert (await client.post("/api/rules", json=_body(), headers=analyst)).status_code == 403
    assert (await client.post("/api/rules/validate", json={"definition": _signature()}, headers=analyst)).status_code == 403
    assert (await client.post("/api/rules/preview", json={"definition": _signature()}, headers=analyst)).status_code == 403


@pytest.mark.parametrize(
    "changes,status,fragment",
    [
        ({"rule_key": "Bad Key!"}, 422, None),
        ({"rule_key": "brute_force"}, 409, "built-in"),
        ({"mitre_technique": "T9999"}, 422, "mitre_technique"),
        ({"severity": "urgent"}, 422, None),
        ({"definition": {"version": 2, "filter": {"field": "password_hash", "op": "eq", "value": "x"}}},
         422, "definition.filter.field"),
        ({"definition": {"version": 2, "filter": {"field": "url", "op": "regex", "value": "(unclosed"}}},
         422, "not a regular expression"),
    ],
)
async def test_invalid_rules_are_refused(client, admin, changes, status, fragment):
    body = _body(**changes)
    r = await client.post("/api/rules", json=body, headers=admin)

    assert r.status_code == status, r.text
    if fragment:
        assert fragment in r.json()["detail"]
    # Nothing custom was saved; a built-in it collided with is still the built-in.
    listed = [rule for rule in await _rules(client, admin) if rule["rule_key"] == body["rule_key"]]
    assert all(rule["origin"] == "builtin" for rule in listed)


async def test_a_duplicate_rule_key_is_refused(client, admin):
    body = _body()
    assert (await client.post("/api/rules", json=body, headers=admin)).status_code == 201
    r = await client.post("/api/rules", json={**body, "title": "Second"}, headers=admin)
    assert r.status_code == 409


async def test_validate_reports_the_rule_type(client, admin):
    sequence = {
        "version": 2,
        "sequence": {
            "join_on": "username",
            "first": {"filter": {"field": "action", "op": "eq", "value": "login_failed"}, "min_count": 3, "within_minutes": 5},
            "then": {"filter": {"field": "action", "op": "eq", "value": "login_success"}, "within_minutes": 5},
        },
    }
    r = await client.post("/api/rules/validate", json={"definition": sequence}, headers=admin)
    assert r.status_code == 200, r.text
    assert r.json() == {"rule_type": "sequence"}


async def test_preview_counts_matches_and_writes_no_alerts(client, pool, admin):
    marker = f"/pytest-authoring-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    async with pool.acquire() as conn:
        await conn.executemany(
            "INSERT INTO events (event_time, source_type, source_ip, url, action) VALUES ($1, 'nginx', $2, $3, 'request')",
            [(now - timedelta(minutes=i), ip, f"{marker}?n={i}")
             for i, ip in enumerate(["203.0.113.140", "203.0.113.140", "203.0.113.141"])],
        )
        alerts_before = await conn.fetchval("SELECT count(*) FROM alerts")

    r = await client.post("/api/rules/preview", json={"definition": _signature(marker), "hours": 1}, headers=admin)

    assert r.status_code == 200, r.text
    result = r.json()
    assert (result["rule_type"], result["matches"], result["groups"]) == ("signature", 3, 2)
    assert len(result["samples"]) == 3 and all(marker in sample["detail"] for sample in result["samples"])
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM alerts") == alerts_before


async def test_preview_of_a_threshold_rule_finds_the_window_that_crossed_it(client, pool, admin):
    username = f"pytest-authoring-{uuid.uuid4().hex[:8]}"
    at = datetime.now(timezone.utc) - timedelta(minutes=2)
    async with pool.acquire() as conn:
        await conn.executemany(
            "INSERT INTO events (event_time, source_type, source_ip, username, action) VALUES ($1, 'ssh', '203.0.113.142', $2, 'login_failed')",
            [(at, username)] * 6,
        )
    definition = {
        "version": 2,
        "filter": {"field": "username", "op": "eq", "value": username},
        "aggregate": {"group_by": "source_ip", "window_minutes": 60, "function": "count", "op": "gte", "threshold": 5},
    }

    r = await client.post("/api/rules/preview", json={"definition": definition, "hours": 2}, headers=admin)

    assert r.status_code == 200, r.text
    result = r.json()
    assert (result["rule_type"], result["matches"], result["groups"]) == ("threshold", 1, 1)
    assert result["samples"][0]["source_ip"] == "203.0.113.142"
    assert result["samples"][0]["detail"].startswith("6 events")


async def test_a_preview_that_runs_too_long_is_a_readable_422(client, admin, monkeypatch):
    async def too_slow(*args, **kwargs):
        raise asyncpg.QueryCanceledError("canceling statement due to statement timeout")

    monkeypatch.setattr(rule_engine, "preview_rule", too_slow)
    r = await client.post("/api/rules/preview", json={"definition": _signature(), "hours": 168}, headers=admin)
    assert r.status_code == 422
    assert "took longer than" in r.json()["detail"]


async def test_preview_range_is_capped_at_a_week(client, admin):
    r = await client.post("/api/rules/preview", json={"definition": _signature(), "hours": 169}, headers=admin)
    assert r.status_code == 422


async def test_deleting_rules(client, pool, admin, analyst):
    unused = (await client.post("/api/rules", json=_body(), headers=admin)).json()
    used = (await client.post("/api/rules", json=_body(), headers=admin)).json()
    builtin = next(rule for rule in await _rules(client, admin) if rule["origin"] == "builtin")
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO alerts (rule_id, title, severity, status) VALUES ($1, 'pytest alert', 'low', 'open')", used["id"]
        )

    assert (await client.delete(f"/api/rules/{unused['id']}", headers=analyst)).status_code == 403
    assert (await client.delete(f"/api/rules/{builtin['id']}", headers=admin)).status_code == 400
    r = await client.delete(f"/api/rules/{used['id']}", headers=admin)
    assert r.status_code == 409 and "Switch it off" in r.json()["detail"]

    assert (await client.delete(f"/api/rules/{unused['id']}", headers=admin)).status_code == 204
    keys = {rule["rule_key"] for rule in await _rules(client, admin)}
    assert unused["rule_key"] not in keys and used["rule_key"] in keys
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM audit_log WHERE action = 'rule_deleted' AND detail->>'rule_key' = $1", unused["rule_key"]
        ) == 1


async def test_the_rules_list_shows_each_rules_last_run(client, pool, admin):
    rule = (await client.post("/api/rules", json=_body(), headers=admin)).json()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO rule_state (rule_id, last_run_at, last_alerts, last_error, last_error_at, consecutive_errors)
            VALUES ($1, now(), 0, 'timed out (took longer than 10s)', now(), 3)
            """,
            rule["id"],
        )

    listed = next(r for r in await _rules(client, admin) if r["id"] == rule["id"])
    assert listed["last_error"] == "timed out (took longer than 10s)"
    assert listed["last_run_at"] is not None


async def test_the_builder_metadata_lists_fields_operators_and_techniques(client, analyst):
    r = await client.get("/api/rules/meta", headers=analyst)
    assert r.status_code == 200
    meta = r.json()
    assert meta["fields"]["dest_port"] == "int"
    assert "regex" in meta["operators"]["text"] and "cidr" in meta["operators"]["inet"]
    assert any(t["id"] == "T1110" for t in meta["techniques"])
    assert "sqli_pattern" in meta["signals"]
    assert meta["limits"]["max_preview_hours"] == 168
