"""The rule compiler: every operator against a real row, and values that never become SQL."""

import json
from datetime import datetime, timezone

import pytest
import pytest_asyncio

from detection.compiler import Params, compile_condition

pytestmark = pytest.mark.asyncio(loop_scope="session")


@pytest_asyncio.fixture(loop_scope="session")
async def event_id(conn):
    return await conn.fetchval(
        """
        INSERT INTO events (event_time, source_type, source_ip, dest_port, username, url, user_agent, raw)
        VALUES ($1, 'nginx', '203.0.113.77', 443, 'admin', '/a_b/100%/search?q='' OR 1=1', 'sqlmap/1.7', $2::jsonb)
        RETURNING id
        """,
        datetime.now(timezone.utc), json.dumps({"logon_type": "10", "channel": "Security"}),
    )


async def _matches(conn, condition, event_id) -> bool:
    add = Params()
    sql, _ = compile_condition(condition, add, "e")
    return await conn.fetchval(f"SELECT {sql} FROM events e WHERE e.id = {add(event_id)}", *add.values)


def _leaf(field, op, value=None):
    leaf = {"field": field, "op": op}
    if value is not None:
        leaf["value"] = value
    return leaf


@pytest.mark.parametrize(
    "condition,expected",
    [
        (_leaf("username", "eq", "admin"), True),
        (_leaf("username", "eq", "ADMIN"), False),
        (_leaf("username", "neq", "root"), True),
        (_leaf("username", "in", ["root", "admin"]), True),
        (_leaf("url", "contains", "OR 1=1"), True),
        (_leaf("url", "contains", "or 1=1"), True),
        (_leaf("user_agent", "contains_any", ["nope", "SQLMAP"]), True),
        (_leaf("user_agent", "contains_any", ["nope", "nikto"]), False),
        (_leaf("url", "startswith", "/a_b/"), True),
        (_leaf("url", "endswith", "1=1"), True),
        (_leaf("url", "regex", "^/a_b/[0-9]+%"), True),
        (_leaf("url", "regex", "^/admin"), False),
        (_leaf("username", "exists"), True),
        (_leaf("dest_ip", "exists"), False),
        (_leaf("dest_port", "gt", 400), True),
        (_leaf("dest_port", "lte", 442), False),
        (_leaf("dest_port", "in", [80, 443]), True),
        (_leaf("dest_port", "neq", 443), False),
        (_leaf("source_ip", "eq", "203.0.113.77"), True),
        (_leaf("source_ip", "in", ["198.51.100.1", "203.0.113.77"]), True),
        (_leaf("source_ip", "cidr", "203.0.113.0/24"), True),
        (_leaf("source_ip", "cidr", "10.0.0.0/8"), False),
        (_leaf("raw.logon_type", "eq", "10"), True),
        (_leaf("raw.missing", "exists"), False),
        ({"not": _leaf("username", "eq", "root")}, True),
        # No value is "doesn't match", so negating it matches.
        ({"not": _leaf("dest_ip", "eq", "192.0.2.1")}, True),
        ({"all": [_leaf("username", "eq", "admin"), _leaf("dest_port", "eq", 22)]}, False),
        ({"any": [_leaf("username", "eq", "root"), _leaf("dest_port", "eq", 443)]}, True),
        ({"all": [{"any": [_leaf("dest_port", "eq", 22), _leaf("dest_port", "eq", 443)]},
                  {"not": _leaf("user_agent", "contains", "mozilla")}]}, True),
    ],
)
async def test_every_operator_against_a_real_event(conn, event_id, condition, expected):
    assert await _matches(conn, condition, event_id) is expected


@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("a_b", True),     # the literal text is in the URL
        ("axb", False),
        ("a%b", False),    # % is literal, not "anything"
        ("100%", True),
        ("_b/1", True),
        ("__b", False),    # _ is literal, not "any one character"
    ],
)
async def test_like_wildcards_in_patterns_are_matched_literally(conn, event_id, pattern, expected):
    assert await _matches(conn, _leaf("url", "contains", pattern), event_id) is expected


async def test_an_sql_injection_string_is_only_ever_a_value(conn, event_id):
    hostile = "admin' OR '1'='1"
    add = Params()
    sql, _ = compile_condition(_leaf("username", "eq", hostile), add, "e")

    assert hostile not in sql and "OR" not in sql
    assert await _matches(conn, _leaf("username", "eq", hostile), event_id) is False
    assert await conn.fetchval("SELECT to_regclass('alerts') IS NOT NULL")


