"""Brings the database schema up to date: the v1 baseline (sql/schema.sql),
then every pending numbered migration in sql/migrations/, each exactly once.
Safe to re-run — applied migrations are skipped, and one that was edited after
being applied stops the run rather than being silently re-applied."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database import connect, disconnect  # noqa: E402
from migrations import apply_all, current_version  # noqa: E402


async def main() -> None:
    pool = await connect()
    try:
        async with pool.acquire() as conn:
            applied = await apply_all(conn)
            version = await current_version(conn)
    finally:
        await disconnect()

    for migration in applied:
        print(f"applied {migration.label}")
    if not applied:
        print("no pending migrations")
    print(f"schema is at version {version}")


if __name__ == "__main__":
    asyncio.run(main())
