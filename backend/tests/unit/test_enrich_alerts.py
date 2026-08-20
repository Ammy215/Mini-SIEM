import json

import pytest

from detection import enrich_alerts

pytestmark = pytest.mark.asyncio(loop_scope="session")

# A real, well-known public IP — used only so _is_public() passes. The
# AbuseIPDB/OTX data below is fabricated and pre-seeded into ioc_cache, so
# enrich_alerts.run_all() hits the cache path in _get_or_fetch() and never
# makes a live API call. Same allowance as the spec's own testing-strategy
# text ("real (or recorded) API calls") — avoids burning free-tier quota or
# flaking CI on network issues on every push.
PUBLIC_IP = "8.8.8.8"


async def _seed_cache(conn, ip: str, provider: str, data: dict) -> None:
    await conn.execute(
        """
        INSERT INTO ioc_cache (indicator, indicator_type, provider, data, expires_at)
        VALUES ($1, 'ip', $2, $3::jsonb, now() + interval '1 day')
        ON CONFLICT (indicator, provider) DO UPDATE SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at
        """,
        ip, provider, json.dumps(data),
    )


async def _insert_alert(conn, *, source_ip, threat_score=30, severity="medium") -> int:
    return await conn.fetchval(
        """
        INSERT INTO alerts (title, severity, mitre_technique, source_ip, threat_score, status, evidence)
        VALUES ('Brute force login attempts', $2, 'T1110', $1::inet, $3, 'open', '{}'::jsonb)
        RETURNING id
        """,
        source_ip, severity, threat_score,
    )


async def test_known_bad_ip_and_otx_pulse_escalate_score_and_severity(conn):
    await _seed_cache(conn, PUBLIC_IP, "abuseipdb", {"abuse_confidence_score": 95, "total_reports": 40})
    await _seed_cache(conn, PUBLIC_IP, "otx", {"pulse_count": 3})
    alert_id = await _insert_alert(conn, source_ip=PUBLIC_IP, threat_score=30, severity="medium")

    results = await enrich_alerts.run_all(conn)
    assert results["enrichment_escalated"] == 1

    alert = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
    assert alert["threat_score"] == 30 + 20 + 15  # base + known_bad_ip + otx_pulse_match
    assert alert["severity"] == "high"
    evidence = json.loads(alert["evidence"])
    assert set(evidence["enrichment_signals"]) == {"known_bad_ip", "otx_pulse_match"}


async def test_clean_ip_does_not_escalate(conn):
    ip = "1.1.1.1"
    await _seed_cache(conn, ip, "abuseipdb", {"abuse_confidence_score": 0, "total_reports": 0})
    await _seed_cache(conn, ip, "otx", {"pulse_count": 0})
    alert_id = await _insert_alert(conn, source_ip=ip, threat_score=30, severity="medium")

    results = await enrich_alerts.run_all(conn)
    assert results["enrichment_escalated"] == 0

    alert = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
    assert alert["threat_score"] == 30
    assert alert["severity"] == "medium"


async def test_private_ip_is_skipped_not_enriched(conn):
    alert_id = await _insert_alert(conn, source_ip="203.0.113.240", threat_score=30, severity="medium")

    await enrich_alerts.run_all(conn)

    alert = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
    assert alert["threat_score"] == 30
    evidence = json.loads(alert["evidence"])
    assert evidence["enrichment_skipped_reason"] == "non-public IP"


async def test_already_checked_alert_is_not_reprocessed(conn):
    await _seed_cache(conn, PUBLIC_IP, "abuseipdb", {"abuse_confidence_score": 95, "total_reports": 40})
    await _seed_cache(conn, PUBLIC_IP, "otx", {"pulse_count": 3})
    alert_id = await _insert_alert(conn, source_ip=PUBLIC_IP, threat_score=30, severity="medium")

    first = await enrich_alerts.run_all(conn)
    assert first["enrichment_escalated"] == 1

    second = await enrich_alerts.run_all(conn)
    assert second["enrichment_checked"] == 0
    assert second["enrichment_escalated"] == 0

    alert = await conn.fetchrow("SELECT threat_score FROM alerts WHERE id = $1", alert_id)
    assert alert["threat_score"] == 30 + 20 + 15  # unchanged by the second pass
