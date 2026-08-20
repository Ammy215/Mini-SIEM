from detection import signature, threshold


async def seed_all(conn) -> None:
    await threshold.seed_rules(conn)
    await signature.seed_rules(conn)


async def run_all(conn) -> dict[str, int]:
    results = await threshold.run_all(conn)
    results.update(await signature.run_all(conn))
    return results
