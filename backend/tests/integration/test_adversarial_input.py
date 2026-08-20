"""Adversarial input: can malicious log CONTENT compromise the app itself?

Not "is the attack detected" — that is the signature rules' job. This asks
whether *ingesting* hostile content is safe: no crash, no SQL execution, no
stored XSS, and clean status codes rather than unhandled 500s.

Derived from a manual adversarial pass run before deployment; the two 500s it
found (NUL byte in a value, malformed IP in a filter) are pinned below.
"""

import json

import pytest
import pytest_asyncio

from config import settings

pytestmark = pytest.mark.asyncio(loop_scope="session")

MARK = "ADVSEC"


@pytest_asyncio.fixture(loop_scope="session")
async def admin_token(client):
    r = await client.post(
        "/api/auth/login",
        json={"email": settings.admin_email, "password": settings.admin_password},
    )
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest_asyncio.fixture(loop_scope="session")
async def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def _cleanup(pool):
    """These tests go through the real API, so rows are committed — remove them."""
    yield
    async with pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM events WHERE username LIKE $1 OR raw_message LIKE $1 OR url LIKE $2",
            f"{MARK}%", f"%{MARK}%",
        )
        await conn.execute("DELETE FROM events WHERE source_ip = '203.0.113.201'::inet")


# --- oversized input -------------------------------------------------------

@pytest.mark.parametrize("size", [10_000, 100_000])
async def test_very_long_values_are_stored_not_crashed(client, auth, pool, size):
    body = {
        "source_type": "app", "action": "info",
        "raw_message": f"{MARK}-LONG-" + ("A" * size),
    }
    r = await client.post("/api/ingest", json=body, headers=auth)
    assert r.status_code == 200

    async with pool.acquire() as conn:
        stored = await conn.fetchval(
            "SELECT max(length(raw_message)) FROM events WHERE raw_message LIKE $1",
            f"{MARK}-LONG-%",
        )
    assert stored >= size


async def test_very_long_line_through_file_upload(client, auth):
    long_url = "/search?q=" + ("B" * 50_000)
    line = (
        f'203.0.113.201 - - [20/Aug/2026:12:00:00 +0000] '
        f'"GET {long_url} HTTP/1.1" 200 0 "-" "{MARK}-ua"'
    )
    r = await client.post(
        "/api/logs/upload",
        files={"file": ("adv_long.log", line.encode(), "text/plain")},
        data={"source_type": "nginx"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["inserted"] == 1


# --- hostile content stored as inert text ----------------------------------

@pytest.mark.parametrize(
    "field,payload",
    [
        ("username", f"{MARK}'; DROP TABLE users; --"),
        ("username", f"{MARK}' UNION SELECT password_hash FROM users --"),
        ("username", f"{MARK}' OR '1'='1"),
        ("username", f"{MARK}<script>alert(1)</script>"),
        ("url", f"/x?u={MARK}'); DELETE FROM alerts; --"),
        ("raw_message", f"{MARK} <img src=x onerror=alert(1)>"),
        ("raw_message", f"{MARK} " + "${{7*7}} {{7*7}} <%= 7*7 %>"),
        ("raw_message", f"{MARK}\r\nFAKE LOG LINE INJECTED"),
    ],
)
async def test_hostile_content_is_stored_verbatim_and_inert(client, auth, pool, field, payload):
    r = await client.post(
        "/api/ingest", json={"source_type": "app", "action": "info", field: payload}, headers=auth
    )
    assert r.status_code == 200

    async with pool.acquire() as conn:
        stored = await conn.fetchval(
            f"SELECT {field} FROM events WHERE {field} = $1 ORDER BY id DESC LIMIT 1", payload
        )
    # Byte-for-byte what was sent: not executed, not interpolated, not stripped.
    assert stored == payload
    assert "49" not in (stored or "") or "7*7" in stored  # template markers never evaluated


async def test_tables_survive_sql_payloads(client, auth, pool):
    async with pool.acquire() as conn:
        for table in ("users", "roles", "events", "rules", "alerts", "incidents", "audit_log"):
            # Would raise UndefinedTableError if any payload had actually executed.
            assert await conn.fetchval(f"SELECT COUNT(*) FROM {table}") >= 0


# --- clean rejections, not 500s (regressions) ------------------------------

async def test_null_byte_in_value_returns_422_not_500(client, auth):
    """PostgreSQL cannot store U+0000; this used to surface as an unhandled 500."""
    r = await client.post(
        "/api/ingest",
        json={"source_type": "app", "action": "info", "username": f"{MARK}\x00evil"},
        headers=auth,
    )
    assert r.status_code == 422
    assert "NUL" in r.text


async def test_null_byte_nested_in_raw_json_returns_422(client, auth):
    r = await client.post(
        "/api/ingest",
        json={"source_type": "app", "raw": {"nested": {"bad": "x\x00y"}}},
        headers=auth,
    )
    assert r.status_code == 422


async def test_malformed_ip_in_event_returns_422_not_500(client, auth):
    r = await client.post(
        "/api/ingest",
        json={"source_type": "app", "source_ip": "not-an-ip'; DROP TABLE users; --"},
        headers=auth,
    )
    assert r.status_code == 422


async def test_malformed_ip_in_query_filter_returns_422_not_500(client, auth):
    """The ${n}::inet cast used to raise asyncpg DataError as a 500."""
    r = await client.get(
        "/api/events", params={"source_ip": "1.1.1.1'; DELETE FROM users; --"}, headers=auth
    )
    assert r.status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        b'{"source_type": "app", ',            # truncated
        b"this is not json <<<>>>",            # not json
        b"[1, 2, 3]",                          # wrong shape
        b"null",                               # null body
        b'{"source_type":"app","raw_message":"a\x00b"}',  # raw NUL in the JSON text
    ],
)
async def test_malformed_json_is_rejected_cleanly(client, auth, body):
    r = await client.post(
        "/api/ingest", content=body, headers={**auth, "Content-Type": "application/json"}
    )
    assert r.status_code == 422


async def test_invalid_utf8_body_is_rejected_cleanly(client, auth):
    body = b'{"source_type":"app","raw_message":"' + b"\xff\xfe\x80bad" + b'"}'
    r = await client.post(
        "/api/ingest", content=body, headers={**auth, "Content-Type": "application/json"}
    )
    assert r.status_code == 400


async def test_upload_with_non_utf8_bytes_degrades_gracefully(client, auth):
    raw = b'203.0.113.201 - - [20/Aug/2026:12:00:00 +0000] "GET /a HTTP/1.1" 200 0 "-" "x"\n'
    raw += b"\xff\xfe\x00\x81 garbage binary line \x90\x90\n"
    raw += b'203.0.113.201 - - [20/Aug/2026:12:00:01 +0000] "GET /b HTTP/1.1" 200 0 "-" "y"\n'
    r = await client.post(
        "/api/logs/upload",
        files={"file": ("adv_binary.log", raw, "application/octet-stream")},
        data={"source_type": "nginx"},
        headers=auth,
    )
    assert r.status_code == 200
    body = r.json()
    # The good lines parse; the corrupt one is skipped rather than crashing.
    assert body["parsed"] == 2
    assert body["skipped"] == 1


# --- no input can change the SQL that runs ---------------------------------

@pytest.mark.parametrize(
    "endpoint,params",
    [
        ("/api/events", {"q": "'; DROP TABLE events; --"}),
        ("/api/events", {"source_type": "app' OR '1'='1"}),
        ("/api/alerts", {"status": "open' OR '1'='1"}),
        ("/api/alerts", {"severity": "'; DROP TABLE alerts; --"}),
        ("/api/incidents", {"status": "open'--"}),
    ],
)
async def test_sql_injection_in_filters_is_treated_as_a_literal_value(client, auth, endpoint, params):
    r = await client.get(endpoint, params=params, headers=auth)
    assert r.status_code == 200
    # Matched as a literal string, so nothing matches — and nothing was dropped.
    assert r.json()["total"] == 0


async def test_poisoned_rule_field_is_rejected_by_the_whitelist(client, auth, pool):
    """detection/signature.py interpolates the field name into SQL, so it is
    whitelisted. A rule editor must not be able to break out through it."""
    rules = (await client.get("/api/rules", headers=auth)).json()["rules"]
    sig = next(r for r in rules if r["rule_type"] == "signature")
    original = sig["definition"]

    poisoned = dict(original)
    poisoned["field"] = "url FROM events; DROP TABLE alerts; --"
    try:
        r = await client.put(f"/api/rules/{sig['id']}", json={"definition": poisoned}, headers=auth)
        assert r.status_code == 200

        # Detection must run without error and without executing the payload.
        r = await client.post("/api/detect/run", headers=auth)
        assert r.status_code == 200
        assert r.json()["results"][sig["rule_key"]] == 0

        async with pool.acquire() as conn:
            assert await conn.fetchval("SELECT COUNT(*) FROM alerts") >= 0
    finally:
        await client.put(f"/api/rules/{sig['id']}", json={"definition": original}, headers=auth)

    restored = (await client.get("/api/rules", headers=auth)).json()["rules"]
    assert next(r for r in restored if r["id"] == sig["id"])["definition"] == original
