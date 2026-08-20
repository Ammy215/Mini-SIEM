"""Applies backend/sql/schema.sql against DATABASE_URL. Safe to re-run —
every statement in schema.sql uses IF NOT EXISTS / ON CONFLICT."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database import connect, disconnect  # noqa: E402

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "sql" / "schema.sql"


async def main() -> None:
    schema_sql = SCHEMA_PATH.read_text()
    pool = await connect()
    async with pool.acquire() as conn:
        await conn.execute(schema_sql)
    await disconnect()
    print(f"Migration applied from {SCHEMA_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
