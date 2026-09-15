"""The syslog listener on real sockets (127.0.0.1, a free port) storing into the
real database: UDP and TCP framing, the sender allowlist, size caps and the
per-sender rate limit. Events it stores are removed afterwards."""

import asyncio
import json
import socket

import pytest
import pytest_asyncio

from config import settings
from ingest_listener import syslog_server as syslog
from main import app

pytestmark = pytest.mark.asyncio(loop_scope="session")

MARK = "pytest-syslog"


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def _cleanup(pool):
    yield
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM events WHERE host LIKE $1", f"{MARK}%")


@pytest_asyncio.fixture(loop_scope="session")
async def start(pool):
    started = []

    async def _start(allowed="127.0.0.1/32", rate=1000, burst=1000):
        listener = syslog.SyslogListener(
            pool, host="127.0.0.1", port=0, allowed=syslog.parse_allowlist(allowed), rate_per_second=rate, burst=burst,
        )
        await listener.start()
        started.append(listener)
        return listener

    yield _start
    for listener in started:
        await listener.stop()


def _udp(port: int, payload: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload, ("127.0.0.1", port))


async def _events(pool, host: str, count: int, timeout: float = 8.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM events WHERE host = $1 ORDER BY id", host)
        if len(rows) >= count or loop.time() > deadline:
            return rows
        await asyncio.sleep(0.2)


async def test_a_udp_syslog_message_becomes_an_event(pool, start):
    listener = await start()
    _udp(listener.udp_port, b"<38>Mar  1 10:00:00 pytest-syslog-udp sshd[99]: Failed password for root from 203.0.113.231 port 4242 ssh2")

    [row] = await _events(pool, "pytest-syslog-udp", 1)

    raw = json.loads(row["raw"])
    assert (row["action"], str(row["source_ip"]), row["parser"]) == ("login_failed", "203.0.113.231", "ssh")
    assert (raw["via"], raw["peer"], raw["facility"], raw["severity"]) == ("syslog", "127.0.0.1", 4, 6)
    assert listener.stats.stored == 1


async def test_tcp_newline_and_octet_counted_messages_are_all_stored(pool, start):
    listener = await start()
    rfc5424 = b"<34>1 2026-09-14T22:14:15Z pytest-syslog-tcp billing 88 - - payment gateway timeout"
    _, writer = await asyncio.open_connection("127.0.0.1", listener.tcp_port)
    writer.write(b"<13>Mar  1 10:00:01 pytest-syslog-tcp app[1]: first message\n")
    writer.write(b"%d %s" % (len(rfc5424), rfc5424))
    writer.write(b"<13>Mar  1 10:00:02 pytest-syslog-tcp app[1]: last message, no newline")
    await writer.drain()
    writer.close()

    rows = await _events(pool, "pytest-syslog-tcp", 3)

    assert [row["parser"] for row in rows] == ["syslog", "syslog5424", "syslog"]
    assert all(json.loads(row["raw"])["via"] == "syslog" for row in rows)


async def test_senders_outside_the_allowlist_are_ignored(pool, start):
    listener = await start(allowed="10.0.0.0/8")
    _udp(listener.udp_port, b"<13>Mar  1 10:00:00 pytest-syslog-denied app[1]: should not be stored")
    reader, writer = await asyncio.open_connection("127.0.0.1", listener.tcp_port)
    assert await asyncio.wait_for(reader.read(), 5) == b""  # the connection is closed straight away
    writer.close()

    await asyncio.sleep(1.5)
    assert await _events(pool, "pytest-syslog-denied", 1, timeout=0) == []
    assert listener.stats.not_allowed == 2 and listener.stats.stored == 0


async def test_oversize_messages_are_dropped(pool, start):
    listener = await start()
    _udp(listener.udp_port, b"<13>Mar  1 10:00:00 pytest-syslog-big app[1]: " + b"x" * syslog.MAX_DATAGRAM_BYTES)
    reader, writer = await asyncio.open_connection("127.0.0.1", listener.tcp_port)
    writer.write(b"<13>" + b"y" * (syslog.MAX_TCP_MESSAGE_BYTES + 10))
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()

    await asyncio.sleep(1.5)
    assert await _events(pool, "pytest-syslog-big", 1, timeout=0) == []
    assert listener.stats.oversize == 2


async def test_each_sender_is_rate_limited(pool, start):
    listener = await start(rate=0.01, burst=2)
    for n in range(5):
        _udp(listener.udp_port, b"<13>Mar  1 10:00:0%d pytest-syslog-rate app[1]: message %d" % (n, n))

    rows = await _events(pool, "pytest-syslog-rate", 2)
    await asyncio.sleep(1.5)

    assert len(rows) == 2
    assert (listener.stats.rate_limited, listener.stats.stored) == (3, 2)


async def test_admins_can_see_the_listener_status(client, start):
    login = await client.post("/api/auth/login", json={"email": settings.admin_email, "password": settings.admin_password})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    app.state.syslog_listener = None
    assert (await client.get("/api/admin/listener", headers=headers)).json() == {"enabled": False}

    listener = await start()
    app.state.syslog_listener = listener
    try:
        body = (await client.get("/api/admin/listener", headers=headers)).json()
    finally:
        app.state.syslog_listener = None
    assert body["enabled"] is True
    assert body["allowed_sources"] == ["127.0.0.1/32"] and body["udp_port"] == listener.udp_port
    assert set(body["stats"]) >= {"received", "stored", "not_allowed", "oversize", "rate_limited", "queue_full"}
