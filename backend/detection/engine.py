from detection import correlate, enrich_alerts, signature, threshold


async def seed_all(conn) -> None:
    await threshold.seed_rules(conn)
    await signature.seed_rules(conn)


async def run_all(conn) -> dict[str, int]:
    results = await threshold.run_all(conn)
    results.update(await signature.run_all(conn))
    # enrichment runs before correlation: incidents inherit an alert's severity
    # once, at link time, so an alert must reach its final post-enrichment
    # severity before correlate.py folds it into an incident.
    results.update(await enrich_alerts.run_all(conn))
    results.update(await correlate.run_all(conn))
    return results
