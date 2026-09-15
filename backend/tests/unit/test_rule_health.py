"""Each rule's last run is recorded, so a rule that keeps failing is visible
instead of silent; and regexes are checked in PostgreSQL before they're saved."""

import json

import asyncpg
import pytest

from detection import rule_engine
from detection.rule_checks import check_regexes
from models.rule_definitions import InvalidDefinition

pytestmark = pytest.mark.asyncio(loop_scope="session")

GOOD = {"version": 2, "filter": {"field": "url", "op": "contains", "value": "/pytest-health"}}


async def _custom_rule(conn, definition) -> int:
    return await conn.fetchval(
        """
        INSERT INTO rules (rule_key, title, rule_type, severity, definition, enabled, origin)
        VALUES ('pytest-health', 'Health probe', 'signature', 'low', $1::jsonb, TRUE, 'custom')
        RETURNING id
        """,
        json.dumps(definition),
    )


async def _state(conn, rule_id):
    return await conn.fetchrow("SELECT * FROM rule_state WHERE rule_id = $1", rule_id)


async def test_a_failing_rule_records_a_safe_error_until_it_is_fixed(conn):
    broken = {"version": 2, "filter": {"field": "url; DROP TABLE alerts", "op": "eq", "value": "x"}}
    rule_id = await _custom_rule(conn, broken)

    await rule_engine.run_rules(conn, "signature")
    await rule_engine.run_rules(conn, "signature")

    state = await _state(conn, rule_id)
    assert state["last_error"].startswith("invalid definition: definition.filter.field")
    assert "DROP TABLE" not in state["last_error"]
    assert state["consecutive_errors"] == 2
    first_error_at = state["last_error_at"]

    await conn.execute("UPDATE rules SET definition = $1::jsonb WHERE id = $2", json.dumps(GOOD), rule_id)
    await rule_engine.run_rules(conn, "signature")

    state = await _state(conn, rule_id)
    assert state["last_error"] is None
    assert state["consecutive_errors"] == 0
    assert state["last_alerts"] == 0
    assert state["last_error_at"] >= first_error_at  # kept as history


async def test_a_healthy_rule_records_its_run(conn):
    rule_id = await _custom_rule(conn, GOOD)
    await rule_engine.run_rules(conn, "signature")

    state = await _state(conn, rule_id)
    assert state["last_run_at"] is not None
    assert state["last_error"] is None
    assert state["last_duration_ms"] >= 0


async def test_database_errors_are_described_without_their_message():
    class Leaky(Exception):
        pass

    assert rule_engine.describe_rule_error(Leaky("value 'secret' is invalid")) == "failed (Leaky)"
    assert "timed out" in rule_engine.describe_rule_error(asyncpg.QueryCanceledError("canceling statement"))


def _regex(pattern):
    return {"version": 2, "filter": {"all": [{"field": "url", "op": "regex", "value": pattern}]}}


async def test_a_regex_postgresql_accepts_passes(conn):
    await check_regexes(conn, _regex(r"^/admin(/|$)"))
    await check_regexes(conn, _regex(r"(a+)+$"))  # PostgreSQL's engine doesn't backtrack on this


async def test_a_regex_postgresql_rejects_is_refused_with_its_location(conn):
    with pytest.raises(InvalidDefinition, match=r"definition\.filter\.all\.0\.value: not a regular expression"):
        await check_regexes(conn, _regex("(unclosed"))


async def test_a_too_slow_regex_is_refused(conn, monkeypatch):
    import detection.rule_checks as rule_checks

    monkeypatch.setattr(rule_checks, "_PROBE_SQL", "SELECT pg_sleep(2) IS NULL AND $1::text IS NOT NULL")
    with pytest.raises(InvalidDefinition, match="too slow"):
        await check_regexes(conn, _regex("^x"))
