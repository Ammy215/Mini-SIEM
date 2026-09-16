"""Releases the detection lease after an unclean shutdown.

One detection pass runs at a time, claimed by taking the single row in
`detection_lease` for up to 15 minutes (`detection/engine.py::LEASE_MINUTES`).
A process that is killed mid-pass — Ctrl+C at the wrong moment, a container
stopped, a crash — never releases it, so until that 15 minutes is up:

  * `POST /api/detect/run` answers 409 "A detection run is already in progress"
  * each scheduler tick skips
  * an upload waiting for analysis sits in `queued` and looks stuck

Nothing is lost either way; this just avoids the wait. Run it only when you
know no other instance is genuinely running a pass — on a machine with a second
backend against the same database, releasing the lease lets two passes overlap.

    python scripts/clear_detection_lease.py            # show who holds it
    python scripts/clear_detection_lease.py --release  # release it

Never DELETE the row: the claim is an UPDATE of `id = 1`, so a missing row
makes every run fail with the same 409, permanently.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402


async def main() -> int:
    release = "--release" in sys.argv
    pool = await database.connect()
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT holder, acquired_at, expires_at, now() AS now, "
                "expires_at > now() AS held FROM detection_lease WHERE id = 1"
            )
            if row is None:
                print("No detection_lease row — detection cannot claim a lease and every run "
                      "will answer 409. Restoring it.")
                if release:
                    await conn.execute("INSERT INTO detection_lease (id) VALUES (1) "
                                       "ON CONFLICT DO NOTHING")
                    print("Restored.")
                else:
                    print("Re-run with --release to restore it.")
                return 0

            if not row["held"]:
                print("Lease is free — nothing to do."
                      + (f" (last held by {row['holder']} until {row['expires_at']})"
                         if row["holder"] else ""))
                return 0

            remaining = (row["expires_at"] - row["now"]).total_seconds() / 60
            print(f"Held by  : {row['holder']}")
            print(f"Claimed  : {row['acquired_at']}")
            print(f"Expires  : {row['expires_at']}  ({remaining:.1f} minutes from now)")
            if not release:
                print("\nIf no detection pass is actually running, re-run with --release.")
                return 1

            await conn.execute(
                "UPDATE detection_lease SET holder = NULL, acquired_at = NULL, "
                "expires_at = NULL WHERE id = 1"
            )
            print("\nReleased. The next scheduler tick (or POST /api/detect/run) will proceed.")
            return 0
    finally:
        await database.disconnect()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
