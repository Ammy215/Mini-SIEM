"""The Rules API: who may change what, validation at save time, and edits
that survive a restart.

These go through the real API, so changes are committed. The two rules they
touch are snapshotted before each test and restored exactly afterwards."""

import copy
import json
import uuid

import pytest
import pytest_asyncio

from config import settings
from detection import engine
from detection.seeding import builtin_rules

pytestmark = pytest.mark.asyncio(loop_scope="session")

THRESHOLD_KEY = "port_scan"
SIGNATURE_KEY = "scanner-ua-001"
_COLUMNS = (
    "title", "description", "severity", "mitre_technique", "definition",
    "enabled", "user_modified", "updated_at", "updated_by",
)


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def _restore_touched_rules(pool):
    async with pool.acquire() as conn:
        snapshot = await conn.fetch(
            f"SELECT rule_key, {', '.join(_COLUMNS)} FROM rules WHERE rule_key = ANY($1::text[])",
            [THRESHOLD_KEY, SIGNATURE_KEY],
        )
    yield
    async with pool.acquire() as conn:
        for row in snapshot:
            await conn.execute(
                """
                UPDATE rules SET title = $2, description = $3, severity = $4, mitre_technique = $5,
                    definition = $6::jsonb, enabled = $7, user_modified = $8, updated_at = $9, updated_by = $10
                WHERE rule_key = $1
                """,
                row["rule_key"], *(row[column] for column in _COLUMNS),
            )


async def _login(client, email, password):
    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest_asyncio.fixture(loop_scope="session")
async def admin(client):
    return await _login(client, settings.admin_email, settings.admin_password)


@pytest_asyncio.fixture(loop_scope="session")
async def analyst(client, pool, admin):
    email = f"pytest_rules_{uuid.uuid4().hex[:12]}@example.com"
    password = "AnalystPass123"
    r = await client.post(
        "/api/admin/users",
        json={"email": email, "password": password, "full_name": "Rules Analyst", "role": "analyst"},
        headers=admin,
    )
    assert r.status_code == 201, r.text
    yield await _login(client, email, password)

    async with pool.acquire() as conn:
        user_id = await conn.fetchval("SELECT id FROM users WHERE email = $1", email)
        if user_id is not None:
            # rules.updated_by references users; clear it before deleting the
            # user (the snapshot restore puts the original value back).
            await conn.execute("UPDATE rules SET updated_by = NULL WHERE updated_by = $1", user_id)
            await conn.execute("DELETE FROM audit_log WHERE user_id = $1", user_id)
            await conn.execute("DELETE FROM users WHERE id = $1", user_id)


async def _rule(client, headers, rule_key):
    rules = (await client.get("/api/rules", headers=headers)).json()["rules"]
    return next(r for r in rules if r["rule_key"] == rule_key)


def _with(definition: dict, path: str, value) -> dict:
    """A copy of `definition` with the dotted `path` set to `value`."""
    changed = copy.deepcopy(definition)
    *parents, last = path.split(".")
    target = changed
    for key in parents:
        target = target[key]
    target[last] = value
    return changed


_PORT_SCAN = builtin_rules()[THRESHOLD_KEY]["definition"]


async def test_an_analysts_title_and_severity_edit_survives_a_restart(client, pool, analyst):
    rule = await _rule(client, analyst, THRESHOLD_KEY)

    r = await client.put(
        f"/api/rules/{rule['id']}", json={"title": "Port scan (tuned)", "severity": "high"}, headers=analyst
    )
    assert r.status_code == 200, r.text
    assert r.json()["user_modified"] is True

    async with pool.acquire() as conn:
        await engine.seed_all(conn)  # what every startup runs

    after = await _rule(client, analyst, THRESHOLD_KEY)
    assert (after["title"], after["severity"]) == ("Port scan (tuned)", "high")


async def test_only_admins_can_change_what_a_rule_detects(client, admin, analyst):
    rule = await _rule(client, admin, THRESHOLD_KEY)
    tuned = _with(rule["definition"], "aggregate.window_minutes", 7)

    r = await client.put(f"/api/rules/{rule['id']}", json={"definition": tuned}, headers=analyst)
    assert r.status_code == 403
    assert (await _rule(client, admin, THRESHOLD_KEY))["definition"] == rule["definition"]

    r = await client.put(f"/api/rules/{rule['id']}", json={"definition": tuned}, headers=admin)
    assert r.status_code == 200, r.text
    assert r.json()["definition"]["aggregate"]["window_minutes"] == 7


async def test_an_admins_definition_edit_survives_a_restart(client, pool, admin):
    rule = await _rule(client, admin, SIGNATURE_KEY)
    tuned = _with(rule["definition"], "filter.value", ["sqlmap", "nikto", "nmap", "masscan"])

    r = await client.put(f"/api/rules/{rule['id']}", json={"definition": tuned}, headers=admin)
    assert r.status_code == 200, r.text

    async with pool.acquire() as conn:
        await engine.seed_all(conn)

    assert "masscan" in (await _rule(client, admin, SIGNATURE_KEY))["definition"]["filter"]["value"]


async def test_admin_reset_restores_the_shipped_rule_but_keeps_its_on_off_state(client, admin):
    rule = await _rule(client, admin, THRESHOLD_KEY)
    r = await client.put(
        f"/api/rules/{rule['id']}",
        json={"title": "Custom title", "severity": "critical",
              "definition": _with(rule["definition"], "aggregate.threshold", 40)},
        headers=admin,
    )
    assert r.status_code == 200, r.text

    r = await client.post(f"/api/rules/{rule['id']}/reset", headers=admin)
    assert r.status_code == 200, r.text

    body = r.json()
    shipped = builtin_rules()[THRESHOLD_KEY]
    assert (body["title"], body["severity"]) == (shipped["title"], shipped["severity"])
    assert body["definition"] == shipped["definition"]
    assert body["user_modified"] is False
    assert body["enabled"] == rule["enabled"]


async def test_analysts_cannot_reset_a_rule(client, analyst):
    rule = await _rule(client, analyst, THRESHOLD_KEY)
    r = await client.post(f"/api/rules/{rule['id']}/reset", headers=analyst)
    assert r.status_code == 403


async def test_edits_and_resets_are_audited_with_what_changed(client, pool, admin):
    rule = await _rule(client, admin, THRESHOLD_KEY)
    await client.put(f"/api/rules/{rule['id']}", json={"title": "Audited title"}, headers=admin)
    await client.post(f"/api/rules/{rule['id']}/reset", headers=admin)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT action, detail FROM audit_log
            WHERE detail->>'rule_key' = $1 AND created_at > now() - interval '2 minutes'
            ORDER BY created_at
            """,
            THRESHOLD_KEY,
        )
    actions = [row["action"] for row in rows]
    assert "rule_updated" in actions and "rule_reset" in actions

    update = next(json.loads(row["detail"]) for row in reversed(rows) if row["action"] == "rule_updated")
    assert update["changes"]["title"] == {"from": rule["title"], "to": "Audited title"}


async def test_an_update_that_changes_nothing_does_not_mark_the_rule_modified(client, admin):
    rule = await _rule(client, admin, SIGNATURE_KEY)

    r = await client.put(
        f"/api/rules/{rule['id']}", json={"title": rule["title"], "severity": rule["severity"]}, headers=admin
    )

    assert r.status_code == 200
    assert r.json()["user_modified"] == rule["user_modified"]
    assert r.json()["updated_at"] == rule["updated_at"]


@pytest.mark.parametrize(
    "body,detail_fragment",
    [
        ({"severity": "urgent"}, None),
        ({"unknown_field": "x"}, None),
        ({"title": ""}, None),
        ({"definition": _with(_PORT_SCAN, "aggregate.window_minutes", 0)}, "definition.aggregate.window_minutes"),
        ({"definition": _with(_PORT_SCAN, "aggregate.distinct_field", "password")}, "definition.aggregate.distinct_field"),
        # A valid definition, but for a different kind of rule.
        ({"definition": {"version": 2, "filter": {"field": "url", "op": "contains", "value": "x"}}},
         "describes a signature rule, but this is a threshold rule"),
        # The v1 shape is no longer accepted.
        ({"definition": {"window_minutes": 5, "threshold": 15}}, "definition.version: required"),
    ],
)
async def test_invalid_edits_are_rejected_with_a_422(client, admin, body, detail_fragment):
    rule = await _rule(client, admin, THRESHOLD_KEY)

    r = await client.put(f"/api/rules/{rule['id']}", json=body, headers=admin)

    assert r.status_code == 422
    if detail_fragment:
        assert detail_fragment in r.json()["detail"]
    assert (await _rule(client, admin, THRESHOLD_KEY)) == rule
