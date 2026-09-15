"""IP locations: cached 30 days, never looked up for private addresses, backed
off for a day on a rate limit, with AbuseIPDB's country as the fallback. The
provider is replaced by a fake, so nothing here touches the network."""

import json

import pytest
import pytest_asyncio

from config import settings
from enrichment import geo, ipinfo
from enrichment.errors import ProviderError

pytestmark = pytest.mark.asyncio(loop_scope="session")

IPS = ["185.220.101.1", "185.220.101.2", "185.220.101.3"]


@pytest.fixture
def calls(monkeypatch):
    made = []

    async def fake_query(ip):
        made.append(ip)
        return {"country": "de", "region": "Hesse", "city": "Frankfurt", "org": "AS64500 Example", "loc": None, "timezone": None}

    monkeypatch.setattr(ipinfo, "query", fake_query)
    monkeypatch.setattr(settings, "enable_geo_lookups", True)
    return made


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def _fresh(conn):
    # Rolled back with the test's transaction, so real cached rows come back afterwards.
    await conn.execute("DELETE FROM ip_geo WHERE ip = ANY($1::inet[])", IPS)
    await conn.execute("DELETE FROM ioc_cache WHERE indicator = ANY($1::text[])", IPS)
    await conn.execute("DELETE FROM provider_backoff")


async def test_a_public_ip_is_looked_up_once_then_cached_for_30_days(conn, calls):
    first = await geo.lookup(conn, IPS[0])
    second = await geo.lookup(conn, IPS[0])

    assert first["country"] == "DE" and first["city"] == "Frankfurt" and first["source"] == "ipinfo"
    assert second["country"] == "DE"
    assert calls == [IPS[0]]
    days = await conn.fetchval("SELECT extract(day FROM expires_at - fetched_at) FROM ip_geo WHERE ip = $1::inet", IPS[0])
    assert days == 30


async def test_non_public_addresses_are_never_looked_up(conn, calls):
    for ip in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "203.0.113.9", "::1", "fe80::1", "not-an-ip"):
        assert await geo.lookup(conn, ip) is None
    assert calls == []


async def test_a_rate_limit_backs_off_and_uses_abuseipdbs_country(conn, monkeypatch):
    made = []

    async def rate_limited(ip):
        made.append(ip)
        raise ProviderError("ipinfo returned HTTP 429")

    monkeypatch.setattr(ipinfo, "query", rate_limited)
    monkeypatch.setattr(settings, "enable_geo_lookups", True)
    await conn.execute(
        """
        INSERT INTO ioc_cache (indicator, indicator_type, provider, data, expires_at)
        VALUES ($1, 'ip', 'abuseipdb', $2::jsonb, now() + interval '1 day')
        """,
        IPS[0], json.dumps({"country_code": "nl", "isp": "Example BV"}),
    )

    location = await geo.lookup(conn, IPS[0])
    assert (location["country"], location["source"]) == ("NL", "abuseipdb")
    assert await geo.backed_off(conn, ipinfo.PROVIDER)

    assert await geo.lookup(conn, IPS[1]) is None  # no fallback data, and ipinfo isn't asked again
    assert made == [IPS[0]]


async def test_a_failed_lookup_with_no_fallback_stores_nothing(conn, monkeypatch):
    async def unavailable(ip):
        raise ProviderError("ipinfo returned HTTP 503")

    monkeypatch.setattr(ipinfo, "query", unavailable)
    monkeypatch.setattr(settings, "enable_geo_lookups", True)

    assert await geo.lookup(conn, IPS[0]) is None
    assert await conn.fetchval("SELECT count(*) FROM ip_geo WHERE ip = $1::inet", IPS[0]) == 0
    assert not await geo.backed_off(conn, ipinfo.PROVIDER)


async def test_switched_off_lookups_never_call_the_provider(conn, calls, monkeypatch):
    monkeypatch.setattr(settings, "enable_geo_lookups", False)
    assert await geo.lookup(conn, IPS[0]) is None
    assert await geo.run_all(conn) == {"geo_looked_up": 0}
    assert calls == []


async def test_the_background_job_fills_recent_event_ips_up_to_its_cap(conn, calls, monkeypatch):
    monkeypatch.setattr(geo, "GEO_LOOKUPS_PER_TICK", 2)
    await conn.executemany(
        "INSERT INTO events (event_time, source_type, source_ip, action) VALUES (now(), 'firewall', $1, 'blocked')",
        [(ip,) for ip in [*IPS, "10.1.2.3", IPS[0]]],
    )

    assert await geo.run_all(conn) == {"geo_looked_up": 2}

    assert len(calls) == 2 and set(calls) <= set(IPS)
    assert await conn.fetchval("SELECT count(*) FROM ip_geo WHERE ip = ANY($1::inet[])", IPS) == 2
