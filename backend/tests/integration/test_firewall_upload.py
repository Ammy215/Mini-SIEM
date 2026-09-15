"""Firewall logs through the upload API, and the port-scan rule they unlock.

Uploads commit real rows; each test's events and batches are removed afterwards.
Detection runs inside the rolled-back `conn` transaction, so no alert persists."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio

from config import settings
from detection import threshold

pytestmark = pytest.mark.asyncio(loop_scope="session")

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest_asyncio.fixture(loop_scope="session")
async def admin(client):
    r = await client.post("/api/auth/login", json={"email": settings.admin_email, "password": settings.admin_password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest_asyncio.fixture(loop_scope="session")
async def batches(pool):
    ids: list[str] = []
    yield ids
    async with pool.acquire() as c:
        await c.execute("DELETE FROM events WHERE batch_id = ANY($1::uuid[])", ids)
        await c.execute("DELETE FROM ingest_batches WHERE id = ANY($1::uuid[])", ids)


async def _upload(client, headers, batches, name, content):
    r = await client.post("/api/logs/upload", files={"file": (name, content, "text/plain")}, headers=headers)
    if r.status_code == 200:
        batches.append(r.json()["batch_id"])
    return r


@pytest.mark.parametrize("fixture,detected,by_parser", [("ufw.log", "iptables", {"iptables": 5}), ("cef.log", "cef", {"cef": 4})])
async def test_firewall_logs_are_detected_and_fully_kept(client, admin, batches, fixture, detected, by_parser):
    r = await _upload(client, admin, batches, fixture, (FIXTURES / fixture).read_bytes())

    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["detected_format"], body["by_parser"], body["skipped"]) == (detected, by_parser, 0)


async def test_cef_fields_land_in_event_columns(client, admin, batches, pool):
    r = await _upload(client, admin, batches, "paloalto.log", (FIXTURES / "cef.log").read_bytes())

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT source_type, action, source_ip, dest_ip, dest_port, protocol, host, event_code, parser "
            "FROM events WHERE batch_id = $1::uuid AND host = 'pa-fw01'",
            r.json()["batch_id"],
        )
    assert (row["source_type"], row["action"], row["parser"]) == ("firewall", "blocked", "cef")
    assert (str(row["source_ip"]), str(row["dest_ip"]), row["dest_port"]) == ("203.0.113.120", "10.0.0.20", 3389)


async def test_blocked_port_sweep_from_a_ufw_log_triggers_the_port_scan_rule(client, admin, batches, conn):
    """The port-scan rule counts distinct destination ports per source IP. Until
    firewall logs could be ingested, no parser recorded a destination port, so
    this rule had nothing to count."""
    ip = "203.0.113.199"
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    lines = "\n".join(
        f"{(start + timedelta(seconds=port)).strftime('%b %d %H:%M:%S')} fw01 kernel: [UFW BLOCK] IN=eth0 OUT= "
        f"SRC={ip} DST=10.0.0.5 LEN=44 TTL=242 PROTO=TCP SPT={40000 + port} DPT={port} WINDOW=1024 SYN URGP=0"
        for port in range(1, 21)
    )

    r = await _upload(client, admin, batches, "ufw-sweep.log", lines.encode())
    assert r.json()["by_parser"] == {"iptables": 20}

    await conn.execute("UPDATE rules SET enabled = TRUE WHERE rule_key = 'port_scan'")
    results = await threshold.run_all(conn)

    assert results["port_scan"] >= 1
    alert = await conn.fetchrow(
        "SELECT mitre_technique, evidence FROM alerts WHERE source_ip = $1::inet "
        "AND rule_id = (SELECT id FROM rules WHERE rule_key = 'port_scan')",
        ip,
    )
    assert alert["mitre_technique"] == "T1046"
