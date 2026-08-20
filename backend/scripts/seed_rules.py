"""Seeds detection rules (threshold + signature) into the rules table.
Safe to re-run — upserts via rule_key, never overwrites a rule's `enabled` toggle."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database import connect, disconnect  # noqa: E402
from detection import engine  # noqa: E402


async def main() -> None:
    pool = await connect()
    async with pool.acquire() as conn:
        await engine.seed_all(conn)
    await disconnect()
    print("Rules seeded (threshold + signature).")


if __name__ == "__main__":
    asyncio.run(main())
