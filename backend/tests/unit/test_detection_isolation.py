"""One broken rule must not take the rest of a detection run down with it."""

import pytest

from detection import rule_engine, signature, threshold

pytestmark = pytest.mark.asyncio(loop_scope="session")


def _first_call_fails():
    """An evaluator that writes a partial alert then hits a real SQL error on
    its first call, and runs a normal query on every call after that."""
    calls = []

    async def evaluator(conn, rule):
        calls.append(rule)
        if len(calls) == 1:
            await conn.execute("INSERT INTO alerts (title, severity, status) VALUES ('half-written', 'low', 'open')")
            await conn.fetchval("SELECT 1 / 0")
        # Without per-rule isolation this raises InFailedSQLTransactionError,
        # because the error above left the whole transaction aborted.
        return await conn.fetchval("SELECT 7")

    return evaluator, calls


@pytest.mark.parametrize("rule_type,run", [("threshold", threshold.run_all), ("signature", signature.run_all)])
async def test_a_failing_rule_rolls_back_alone_and_later_rules_still_run(conn, monkeypatch, rule_type, run):
    await conn.execute("UPDATE rules SET enabled = TRUE WHERE rule_type = $1", rule_type)
    rule_count = await conn.fetchval("SELECT count(*) FROM rules WHERE rule_type = $1", rule_type)
    evaluator, calls = _first_call_fails()
    monkeypatch.setattr(rule_engine, "evaluate_rule", evaluator)

    results = await run(conn)

    assert rule_count >= 2
    assert len(calls) == rule_count
    assert sorted(results.values()) == [0] + [7] * (rule_count - 1)
    assert await conn.fetchval("SELECT count(*) FROM alerts WHERE title = 'half-written'") == 0


async def test_a_slow_rule_is_cancelled_by_the_statement_timeout(conn, monkeypatch):
    await conn.execute("UPDATE rules SET enabled = TRUE WHERE rule_type = 'signature'")
    monkeypatch.setattr(rule_engine, "STATEMENT_TIMEOUT", "200ms")

    async def slow(conn, rule):
        return await conn.fetchval("SELECT 1 FROM pg_sleep(2)")

    monkeypatch.setattr(rule_engine, "evaluate_rule", slow)
    results = await signature.run_all(conn)

    assert results and set(results.values()) == {0}
    assert await conn.fetchval("SELECT 1") == 1  # the connection is still usable
