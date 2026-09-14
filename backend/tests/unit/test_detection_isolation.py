"""One broken rule must not take the rest of a detection run down with it."""

import pytest

from detection import signature, threshold

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


async def test_failing_threshold_rule_rolls_back_alone_and_later_rules_still_run(conn, monkeypatch):
    await conn.execute("UPDATE rules SET enabled = TRUE WHERE rule_type = 'threshold'")
    evaluator, calls = _first_call_fails()
    for key in list(threshold._EVALUATORS):
        monkeypatch.setitem(threshold._EVALUATORS, key, evaluator)

    results = await threshold.run_all(conn)

    assert len(calls) == len(threshold._EVALUATORS)
    assert sorted(results.values()) == [0] + [7] * (len(calls) - 1)
    assert await conn.fetchval("SELECT count(*) FROM alerts WHERE title = 'half-written'") == 0


async def test_failing_signature_rule_rolls_back_alone_and_later_rules_still_run(conn, monkeypatch):
    await conn.execute("UPDATE rules SET enabled = TRUE WHERE rule_type = 'signature'")
    rule_count = await conn.fetchval("SELECT count(*) FROM rules WHERE rule_type = 'signature'")
    evaluator, calls = _first_call_fails()
    monkeypatch.setattr(signature, "_evaluate_signature_rule", evaluator)

    results = await signature.run_all(conn)

    assert len(calls) == rule_count
    assert sorted(results.values()) == [0] + [7] * (rule_count - 1)
    assert await conn.fetchval("SELECT count(*) FROM alerts WHERE title = 'half-written'") == 0
