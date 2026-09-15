"""Detection over the past: an uploaded file's own time range, sliding windows,
separate bursts, idempotent re-runs, and the batch analysis queue.

Events here are dated months before the tests run, so live detection, which
only looks back a few minutes, never sees them."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from detection import engine, rule_engine, signature, threshold
from detection.rule_engine import Scope

pytestmark = pytest.mark.asyncio(loop_scope="session")

T0 = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)


async def _batch(conn):
    batch_id = await conn.fetchval(
        """
        INSERT INTO ingest_batches (filename, sha256, size_bytes, requested_format, detected_format,
                                    total_lines, parsed, skipped, inserted, by_parser, skipped_reasons, skipped_samples)
        VALUES ('pytest-history.log', repeat('0', 64), 1, 'auto', 'ssh', 0, 0, 0, 0, '{}', '{}', '[]')
        RETURNING id
        """
    )
    await conn.execute("UPDATE rules SET enabled = TRUE WHERE origin = 'builtin'")
    return batch_id


async def _logins(conn, batch_id, ip, seconds, *, action="login_failed", usernames=None, start=T0):
    await conn.executemany(
        "INSERT INTO events (event_time, source_type, source_ip, username, action, batch_id) VALUES ($1, 'ssh', $2, $3, $4, $5)",
        [(start + timedelta(seconds=s), ip, (usernames[i] if usernames else "admin"), action, batch_id)
         for i, s in enumerate(seconds)],
    )


async def _analyze(conn, batch_id):
    first, last, count = await conn.fetchrow(
        "SELECT min(event_time), max(event_time), count(*) FROM events WHERE batch_id = $1", batch_id
    )
    await conn.execute(
        "UPDATE ingest_batches SET first_event_time = $2, last_event_time = $3, inserted = $4 WHERE id = $1",
        batch_id, first, last, count,
    )
    results, errors = await engine.analyze_scope(conn, Scope(first, last, batch_id=batch_id))
    assert errors == {}
    return results


async def _alerts(conn, rule_key, ip):
    return await conn.fetch(
        """
        SELECT * FROM alerts
        WHERE rule_id = (SELECT id FROM rules WHERE rule_key = $1) AND source_ip = $2::inet
        ORDER BY first_event_time
        """,
        rule_key, ip,
    )


async def test_an_old_brute_force_is_missed_live_but_found_in_the_upload(conn):
    batch_id = await _batch(conn)
    ip = "203.0.113.190"
    await _logins(conn, batch_id, ip, range(0, 180, 15))  # 12 failures in 3 minutes

    await threshold.run_all(conn)
    assert await _alerts(conn, "brute_force", ip) == []

    assert (await _analyze(conn, batch_id))["brute_force"] == 1
    assert (await _analyze(conn, batch_id))["brute_force"] == 0  # re-running adds nothing

    [alert] = await _alerts(conn, "brute_force", ip)
    assert alert["first_event_time"] == T0
    assert (alert["origin"], alert["batch_id"]) == ("batch", batch_id)
    assert json.loads(alert["evidence"])["failed_count"] == 12


async def test_two_bursts_hours_apart_are_two_alerts(conn):
    batch_id = await _batch(conn)
    ip = "203.0.113.191"
    await _logins(conn, batch_id, ip, range(0, 180, 15))
    await _logins(conn, batch_id, ip, range(0, 180, 15), start=T0 + timedelta(hours=2))

    assert (await _analyze(conn, batch_id))["brute_force"] == 2
    assert [a["first_event_time"] for a in await _alerts(conn, "brute_force", ip)] == [T0, T0 + timedelta(hours=2)]


async def test_a_burst_straddling_a_five_minute_mark_is_still_found(conn):
    """6 failures just before 10:05 and 5 just after: fixed 5-minute buckets
    would see 6 and 5, neither over 10. A sliding window sees 11."""
    batch_id = await _batch(conn)
    ip = "203.0.113.192"
    await _logins(conn, batch_id, ip, [*range(240, 300, 10), *range(310, 360, 10)])

    assert (await _analyze(conn, batch_id))["brute_force"] == 1


async def test_ten_in_any_five_minutes_is_not_more_than_ten(conn):
    batch_id = await _batch(conn)
    ip = "203.0.113.193"
    await _logins(conn, batch_id, ip, range(0, 11 * 31, 31))  # 11 failures, never more than 10 inside 5 minutes

    assert (await _analyze(conn, batch_id))["brute_force"] == 0


async def test_distinct_counts_slide_and_ignore_repeats(conn):
    batch_id = await _batch(conn)
    await _logins(conn, batch_id, "203.0.113.194", range(0, 500, 100), usernames=["a", "b", "c", "d", "e"])
    # Five names, but spread over 13 minutes: never five inside 10 minutes.
    await _logins(conn, batch_id, "203.0.113.195", range(0, 1000, 200), usernames=["a", "b", "c", "d", "e"])
    # Six attempts, only four names.
    await _logins(conn, batch_id, "203.0.113.196", range(0, 60, 10), usernames=["a", "a", "a", "b", "c", "d"])

    await _analyze(conn, batch_id)

    assert len(await _alerts(conn, "credential_stuffing", "203.0.113.194")) == 1
    assert await _alerts(conn, "credential_stuffing", "203.0.113.195") == []
    assert await _alerts(conn, "credential_stuffing", "203.0.113.196") == []


async def test_an_old_port_scan_keeps_its_ports(conn):
    batch_id = await _batch(conn)
    ip = "203.0.113.197"
    await conn.executemany(
        "INSERT INTO events (event_time, source_type, source_ip, dest_port, action, batch_id) VALUES ($1, 'firewall', $2, $3, 'blocked', $4)",
        [(T0 + timedelta(seconds=i), ip, 3000 + i, batch_id) for i in range(15)],
    )

    await _analyze(conn, batch_id)

    [alert] = await _alerts(conn, "port_scan", ip)
    evidence = json.loads(alert["evidence"])
    assert evidence["distinct_ports"] == 15
    assert evidence["ports"] == list(range(3000, 3015))


async def test_old_signature_and_sequence_hits_are_found(conn):
    batch_id = await _batch(conn)
    await conn.execute(
        "INSERT INTO events (event_time, source_type, source_ip, url, action, batch_id) VALUES ($1, 'nginx', '203.0.113.198', '/q?<script>x</script>', 'request', $2)",
        T0, batch_id,
    )
    await _logins(conn, batch_id, "203.0.113.199", range(0, 100, 20))
    await _logins(conn, batch_id, "203.0.113.199", [120], action="login_success")

    await signature.run_all(conn)
    await rule_engine.run_rules(conn, "sequence")
    assert await _alerts(conn, "xss-http-001", "203.0.113.198") == []

    results = await _analyze(conn, batch_id)

    assert results["xss-http-001"] == 1 and results["brute_force_then_success"] == 1
    [xss] = await _alerts(conn, "xss-http-001", "203.0.113.198")
    assert (xss["origin"], xss["first_event_time"]) == ("batch", T0)


async def test_an_upload_is_analysed_on_its_own_events_but_a_range_sees_everything(conn):
    batch_id = await _batch(conn)
    ip = "203.0.113.200"
    await _logins(conn, batch_id, ip, range(0, 60, 10))       # 6 in the upload
    await _logins(conn, None, ip, range(5, 65, 10))           # 6 more, not from the upload

    assert (await _analyze(conn, batch_id))["brute_force"] == 0

    results, _ = await engine.analyze_scope(conn, Scope(T0, T0 + timedelta(minutes=5)))
    assert results["brute_force"] == 1
    [alert] = await _alerts(conn, "brute_force", ip)
    assert (alert["origin"], alert["batch_id"]) == ("range", None)


async def test_the_queue_analyses_an_upload_and_records_the_outcome(conn):
    batch_id = await _batch(conn)
    await _logins(conn, batch_id, "203.0.113.201", range(0, 180, 15))
    await conn.execute(
        """
        UPDATE ingest_batches SET first_event_time = $2, last_event_time = $3, inserted = 12,
            detection_status = 'queued', detection_requested_at = '2000-01-01'
        WHERE id = $1
        """,
        batch_id, T0, T0 + timedelta(seconds=165),
    )

    assert await engine.analyze_next_batch(conn) == {"batches_analyzed": 1, "batch_alerts_created": 1}

    batch = await conn.fetchrow("SELECT * FROM ingest_batches WHERE id = $1", batch_id)
    outcome = json.loads(batch["detection_result"])
    assert batch["detection_status"] == "done" and batch["detection_finished_at"] is not None
    assert outcome["alerts_created"] == 1 and outcome["rules"] == {"brute_force": 1} and outcome["rule_errors"] == {}


async def test_a_failed_analysis_is_recorded(conn, monkeypatch):
    batch_id = await _batch(conn)
    await _logins(conn, batch_id, "203.0.113.202", [0])
    await conn.execute(
        "UPDATE ingest_batches SET first_event_time = $2, last_event_time = $2, detection_status = 'queued', detection_requested_at = '2000-01-01' WHERE id = $1",
        batch_id, T0,
    )

    async def broken(conn, scope):
        raise RuntimeError("boom")

    monkeypatch.setattr(engine, "analyze_scope", broken)
    assert await engine.analyze_next_batch(conn) == {"batches_analyzed": 0, "batches_failed": 1}

    batch = await conn.fetchrow("SELECT detection_status, detection_error FROM ingest_batches WHERE id = $1", batch_id)
    assert (batch["detection_status"], batch["detection_error"]) == ("failed", "analysis failed (RuntimeError)")


async def test_an_analysis_cut_off_by_a_restart_is_queued_again(conn):
    batch_id = await _batch(conn)
    await conn.execute("UPDATE ingest_batches SET detection_status = 'running' WHERE id = $1", batch_id)

    assert await engine.requeue_interrupted_batches(conn) >= 1
    assert await conn.fetchval("SELECT detection_status FROM ingest_batches WHERE id = $1", batch_id) == "queued"
