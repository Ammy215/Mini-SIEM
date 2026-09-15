"""Windows Event Log exports through the upload API, and into detection.

Uploads commit real rows; each test's events and batches are removed afterwards.
Detection runs inside the rolled-back `conn` transaction, so no alert persists."""

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio

from config import settings
from detection import signature, threshold

pytestmark = pytest.mark.asyncio(loop_scope="session")

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


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
    r = await client.post("/api/logs/upload", files={"file": (name, content, "application/octet-stream")}, headers=headers)
    if r.status_code == 200:
        batches.append(r.json()["batch_id"])
    return r


def _failed_logon_burst(ip: str, count: int, start: datetime) -> str:
    events = "".join(
        f'<Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
        f"<EventID>4625</EventID>"
        f'<TimeCreated SystemTime="{(start + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%S.%f")}0Z"/>'
        f"<Channel>Security</Channel><Computer>WS01.corp.example</Computer></System><EventData>"
        f'<Data Name="TargetUserName">administrator</Data><Data Name="LogonType">3</Data>'
        f'<Data Name="IpAddress">{ip}</Data><Data Name="IpPort">{50000 + i}</Data></EventData></Event>'
        for i in range(count)
    )
    return f'<?xml version="1.0" encoding="UTF-16"?><Events>{events}</Events>'


async def test_event_viewer_xml_export_in_utf16_is_ingested(client, admin, batches, pool):
    content = (FIXTURES / "windows_security.xml").read_text(encoding="utf-8").encode("utf-16")

    r = await _upload(client, admin, batches, "Security.xml", content)

    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["detected_format"], body["by_parser"], body["skipped"]) == ("windows", {"windows": 9}, 0)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT username, source_ip, host, action, outcome, event_code, parser FROM events "
            "WHERE batch_id = $1::uuid AND event_code = '4625'",
            body["batch_id"],
        )
    assert (row["username"], str(row["source_ip"]), row["host"]) == ("administrator", "203.0.113.66", "WS01.corp.example")
    assert (row["action"], row["outcome"], row["parser"]) == ("login_failed", "failure", "windows")


async def test_powershell_json_export_is_ingested(client, admin, batches):
    content = (FIXTURES / "windows_events.json").read_text(encoding="utf-8").encode("utf-16")

    r = await _upload(client, admin, batches, "security.json", content)

    assert r.status_code == 200, r.text
    assert (r.json()["detected_format"], r.json()["by_parser"]) == ("windows", {"windows": 3})


async def test_windows_failed_logon_burst_triggers_brute_force_detection(client, admin, batches, conn):
    ip = "203.0.113.188"
    xml = _failed_logon_burst(ip, 11, datetime.now(timezone.utc) - timedelta(minutes=2))

    r = await _upload(client, admin, batches, "burst.xml", xml.encode("utf-16"))
    assert r.json()["by_parser"] == {"windows": 11}

    await conn.execute("UPDATE rules SET enabled = TRUE WHERE rule_key = 'brute_force'")
    results = await threshold.run_all(conn)

    assert results["brute_force"] >= 1
    alert = await conn.fetchrow(
        "SELECT mitre_technique, evidence FROM alerts WHERE source_ip = $1::inet "
        "AND rule_id = (SELECT id FROM rules WHERE rule_key = 'brute_force')",
        ip,
    )
    assert alert["mitre_technique"] == "T1110"


def _security_event(event_id: int, when: datetime, host: str, data: dict[str, str], provider="Microsoft-Windows-Security-Auditing") -> str:
    fields = "".join(f'<Data Name="{name}">{value}</Data>' for name, value in data.items())
    return (
        f'<Event xmlns="{NS}"><System><Provider Name="{provider}"/><EventID>{event_id}</EventID>'
        f'<TimeCreated SystemTime="{when.strftime("%Y-%m-%dT%H:%M:%S.%f")}0Z"/>'
        f"<Channel>Security</Channel><Computer>{host}</Computer></System><EventData>{fields}</EventData></Event>"
    )


async def test_a_windows_export_with_attacker_activity_raises_the_windows_alerts(client, admin, batches, conn):
    host = "PYTEST-WIN01.corp.example"
    at = datetime.now(timezone.utc) - timedelta(minutes=3)
    events = [
        _security_event(4720, at, host, {"TargetUserName": "svc-backup2", "SubjectUserName": "mallory"}),
        _security_event(4732, at, host, {"TargetUserName": "Administrators", "MemberName": "CN=svc-backup2,DC=corp", "SubjectUserName": "mallory"}),
        _security_event(4672, at, host, {"SubjectUserName": "mallory", "SubjectDomainName": "CORP"}),
        _security_event(4672, at, host, {"SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY"}),
        _security_event(1102, at, host, {"SubjectUserName": "mallory"}, provider="Microsoft-Windows-Eventlog"),
    ]
    xml = f'<?xml version="1.0" encoding="UTF-16"?><Events>{"".join(events)}</Events>'

    r = await _upload(client, admin, batches, "attack.xml", xml.encode("utf-16"))
    assert r.json()["by_parser"] == {"windows": 5}

    await conn.execute("UPDATE rules SET enabled = TRUE WHERE rule_key LIKE 'win-%'")
    await signature.run_all(conn)

    rows = await conn.fetch(
        """
        SELECT r.rule_key, a.title, a.severity FROM alerts a JOIN rules r ON r.id = a.rule_id
        WHERE a.evidence->>'host' = $1 ORDER BY r.rule_key
        """,
        host,
    )
    assert [(row["rule_key"], row["title"], row["severity"]) for row in rows] == [
        ("win-account-created", f"Windows account created on {host}", "medium"),
        ("win-admin-group-add", f"Account added to a privileged group on {host}", "high"),
        ("win-audit-log-cleared", f"Event log cleared on {host}", "high"),
        ("win-privileged-logon", f"Privileged logon by mallory on {host}", "low"),
    ]


async def test_billion_laughs_upload_is_refused_quickly_and_stores_nothing(client, admin, batches):
    payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>
<Events><Event><System><EventID>4625</EventID></System><EventData><Data Name="TargetUserName">&lol3;</Data></EventData></Event></Events>"""

    started = time.perf_counter()
    r = await _upload(client, admin, batches, "lolz.xml", payload.encode())

    assert time.perf_counter() - started < 5
    assert r.status_code == 200
    assert (r.json()["inserted"], r.json()["skipped_reasons"]) == (0, {"xml_dtd_forbidden": 1})
