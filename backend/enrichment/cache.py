import json
from datetime import datetime, timedelta, timezone

CACHE_TTL_HOURS = 24


async def get_cached(conn, indicator: str, provider: str) -> dict | None:
    row = await conn.fetchrow(
        """
        SELECT data FROM ioc_cache
        WHERE indicator = $1 AND provider = $2 AND expires_at > now()
        """,
        indicator, provider,
    )
    return json.loads(row["data"]) if row else None


async def set_cached(conn, indicator: str, indicator_type: str, provider: str, data: dict) -> None:
    expires_at = datetime.now(timezone.utc) + timedelta(hours=CACHE_TTL_HOURS)
    await conn.execute(
        """
        INSERT INTO ioc_cache (indicator, indicator_type, provider, data, expires_at)
        VALUES ($1, $2, $3, $4::jsonb, $5)
        ON CONFLICT (indicator, provider) DO UPDATE SET
            data = EXCLUDED.data,
            cached_at = now(),
            expires_at = EXCLUDED.expires_at
        """,
        indicator, indicator_type, provider, json.dumps(data), expires_at,
    )
