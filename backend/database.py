import ssl
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import asyncpg

from config import settings

_pool: asyncpg.Pool | None = None


def _prepare_dsn() -> tuple[str, ssl.SSLContext | str | None]:
    """asyncpg's DSN parser doesn't understand libpq-only params like
    channel_binding (used by Neon). Strip those out and translate
    sslmode into asyncpg's own ssl argument instead."""
    parts = urlsplit(settings.database_url)
    query = dict(parse_qsl(parts.query))
    sslmode = query.pop("sslmode", None)
    query.pop("channel_binding", None)

    clean_dsn = urlunsplit(parts._replace(query=urlencode(query)))

    ssl_arg: ssl.SSLContext | str | None = None
    if sslmode in ("require", "verify-ca", "verify-full"):
        ssl_arg = ssl.create_default_context()
        if sslmode == "require":
            ssl_arg.check_hostname = False
            ssl_arg.verify_mode = ssl.CERT_NONE

    return clean_dsn, ssl_arg


async def connect() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        dsn, ssl_arg = _prepare_dsn()
        _pool = await asyncpg.create_pool(dsn=dsn, ssl=ssl_arg, min_size=1, max_size=5)
    return _pool


async def disconnect() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("Database pool not initialized — call connect() first")
    return _pool
