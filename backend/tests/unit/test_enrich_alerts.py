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


# --- regression: no escalation on legitimate infrastructure ----------------
# Values below are the real provider responses observed for these IPs.

async def test_whitelisted_infrastructure_is_not_escalated_by_otx_pulses(conn):
    """Google's own IP: abuse score 0, AbuseIPDB-whitelisted, yet 6 OTX pulses.
    Pulses alone must not escalate it."""
    ip = "172.217.118.4"
    await _seed_cache(conn, ip, "abuseipdb", {
        "abuse_confidence_score": 0, "total_reports": 222, "is_whitelisted": True, "isp": "Google LLC",
    })
    await _seed_cache(conn, ip, "otx", {"pulse_count": 6})
    alert_id = await _insert_alert(conn, source_ip=ip, threat_score=30, severity="medium")

    results = await enrich_alerts.run_all(conn)
    assert results["enrichment_escalated"] == 0

    alert = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
    assert alert["threat_score"] == 30
    assert alert["severity"] == "medium"
    evidence = json.loads(alert["evidence"])
    assert any("whitelisted" in s for s in evidence["enrichment_suppressed"])


async def test_low_pulse_count_without_abuse_corroboration_is_not_escalated(conn):
    """Not whitelisted, but 2 pulses and a clean abuse score is not enough."""
    ip = "52.110.14.135"
    await _seed_cache(conn, ip, "abuseipdb", {
        "abuse_confidence_score": 0, "total_reports": 0, "is_whitelisted": False,
    })
    await _seed_cache(conn, ip, "otx", {"pulse_count": 2})
    alert_id = await _insert_alert(conn, source_ip=ip, threat_score=30, severity="medium")

    results = await enrich_alerts.run_all(conn)
    assert results["enrichment_escalated"] == 0

    alert = await conn.fetchrow("SELECT threat_score FROM alerts WHERE id = $1", alert_id)
    assert alert["threat_score"] == 30


async def test_low_pulse_count_with_abuse_corroboration_does_escalate(conn):
    """Same 2 pulses, but AbuseIPDB independently reports abuse -> counts."""
    ip = "45.155.205.233"
    await _seed_cache(conn, ip, "abuseipdb", {
        "abuse_confidence_score": 40, "total_reports": 12, "is_whitelisted": False,
    })
    await _seed_cache(conn, ip, "otx", {"pulse_count": 2})
    alert_id = await _insert_alert(conn, source_ip=ip, threat_score=30, severity="medium")

    results = await enrich_alerts.run_all(conn)
    assert results["enrichment_escalated"] == 1

    alert = await conn.fetchrow("SELECT threat_score FROM alerts WHERE id = $1", alert_id)
    assert alert["threat_score"] == 45  # 30 + otx_pulse_match(15)


async def test_genuinely_malicious_ip_still_escalates_to_high(conn):
    """The real Korea Telecom IP from live testing: abuse 100, 5 pulses."""
    ip = "121.176.109.31"
    await _seed_cache(conn, ip, "abuseipdb", {
        "abuse_confidence_score": 100, "total_reports": 44, "is_whitelisted": False,
    })
    await _seed_cache(conn, ip, "otx", {"pulse_count": 5})
    alert_id = await _insert_alert(conn, source_ip=ip, threat_score=30, severity="medium")

    results = await enrich_alerts.run_all(conn)
    assert results["enrichment_escalated"] == 1

    alert = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
    assert alert["threat_score"] == 65  # 30 + known_bad_ip(20) + otx_pulse_match(15)
    assert alert["severity"] == "high"


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
