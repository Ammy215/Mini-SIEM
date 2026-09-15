"""Where public IPs are: country, region, city and network owner, cached 30 days
in ip_geo.

ipinfo is asked first (it works without a token, at a lower daily limit). If it
fails or is rate limited, a country AbuseIPDB already returned for the IP (in
ioc_cache) is used instead. A rate limit backs ipinfo off for a day, for every
process, via provider_backoff.
"""

import logging

from config import settings
from enrichment import ipinfo
from enrichment.cache import get_cached
from enrichment.errors import ProviderError
from enrichment.ip import NON_PUBLIC_NETWORKS, is_public

logger = logging.getLogger(__name__)

GEO_TTL_DAYS = 30
# Fallback data from AbuseIPDB is re-checked sooner, so ipinfo gets another go.
FALLBACK_TTL_DAYS = 1
GEO_LOOKUPS_PER_TICK = 25
RATE_LIMIT_BACKOFF_HOURS = 24
RECENT_HOURS = 24
_SCAN_LIMIT = 500


async def cached(conn, ip: str) -> dict | None:
    row = await conn.fetchrow(
        "SELECT country, region, city, org, source FROM ip_geo WHERE ip = $1::inet AND expires_at > now()", ip
    )
    return dict(row) if row else None


async def lookup(conn, ip: str) -> dict | None:
    """Location data for a public IP, from cache or a provider. None for a
    non-public IP, or when nothing could be found this time."""
    if not is_public(ip):
        return None
    hit = await cached(conn, ip)
    if hit is not None:
        return hit

    geo, ttl_days = None, GEO_TTL_DAYS
    if settings.enable_geo_lookups and not await backed_off(conn, ipinfo.PROVIDER):
        try:
            data = await ipinfo.query(ip)
        except ProviderError as exc:
            logger.warning("geo lookup failed: %s", exc)
            if "HTTP 429" in str(exc):
                await back_off(conn, ipinfo.PROVIDER, "rate limited")
        else:
            geo = {
                "country": _country(data.get("country")), "region": data.get("region"), "city": data.get("city"),
                "org": data.get("org"), "source": ipinfo.PROVIDER,
            }

    if geo is None:
        abuse = await get_cached(conn, ip, "abuseipdb")
        country = _country((abuse or {}).get("country_code"))
        if country is None:
            return None
        geo = {"country": country, "region": None, "city": None, "org": (abuse or {}).get("isp"), "source": "abuseipdb"}
        ttl_days = FALLBACK_TTL_DAYS

    await conn.execute(
        """
        INSERT INTO ip_geo (ip, country, region, city, org, source, fetched_at, expires_at)
        VALUES ($1::inet, $2, $3, $4, $5, $6, now(), now() + make_interval(days => $7))
        ON CONFLICT (ip) DO UPDATE SET
            country = EXCLUDED.country, region = EXCLUDED.region, city = EXCLUDED.city, org = EXCLUDED.org,
            source = EXCLUDED.source, fetched_at = EXCLUDED.fetched_at, expires_at = EXCLUDED.expires_at
        """,
        ip, geo["country"], _clip(geo["region"]), _clip(geo["city"]), _clip(geo["org"]), geo["source"], ttl_days,
    )
    return geo


async def run_all(conn) -> dict[str, int]:
    """Looks up public source IPs from recently ingested events that have no
    location yet, a few per detection tick."""
    if not settings.enable_geo_lookups or await backed_off(conn, ipinfo.PROVIDER):
        return {"geo_looked_up": 0}

    rows = await conn.fetch(
        """
        SELECT e.source_ip
        FROM events e
        LEFT JOIN ip_geo g ON g.ip = e.source_ip AND g.expires_at > now()
        WHERE e.ingested_at >= now() - make_interval(hours => $1)
          AND e.source_ip IS NOT NULL
          AND g.ip IS NULL
          AND NOT (e.source_ip <<= ANY($2::cidr[]))
        GROUP BY e.source_ip
        ORDER BY max(e.ingested_at) DESC, e.source_ip
        LIMIT $3
        """,
        RECENT_HOURS, NON_PUBLIC_NETWORKS, _SCAN_LIMIT,
    )

    looked_up = 0
    for row in rows:
        ip = str(row["source_ip"])
        if not is_public(ip):
            continue
        if looked_up >= GEO_LOOKUPS_PER_TICK or await backed_off(conn, ipinfo.PROVIDER):
            break
        looked_up += 1
        try:
            await lookup(conn, ip)
        except Exception:
            logger.exception("geo lookup failed unexpectedly")
    return {"geo_looked_up": looked_up}


async def backed_off(conn, provider: str) -> bool:
    return bool(await conn.fetchval("SELECT 1 FROM provider_backoff WHERE provider = $1 AND until > now()", provider))


async def back_off(conn, provider: str, reason: str) -> None:
    await conn.execute(
        """
        INSERT INTO provider_backoff (provider, until, reason)
        VALUES ($1, now() + make_interval(hours => $2), $3)
        ON CONFLICT (provider) DO UPDATE SET until = EXCLUDED.until, reason = EXCLUDED.reason
        """,
        provider, RATE_LIMIT_BACKOFF_HOURS, reason,
    )


def _country(value) -> str | None:
    if isinstance(value, str) and len(value.strip()) == 2 and value.strip().isalpha():
        return value.strip().upper()
    return None


def _clip(value) -> str | None:
    return value[:200] if isinstance(value, str) else None
