"""Enrichment when providers fail, are unconfigured, or would blow a quota.

Providers are replaced with in-process fakes and the IPs' cache rows are
cleared inside the rolled-back test transaction, so nothing reaches the
internet and the real ioc_cache is untouched."""

import json

import pytest

from detection import enrich_alerts
from enrichment.errors import ProviderError, ProviderNotConfigured

pytestmark = pytest.mark.asyncio(loop_scope="session")

IP = "8.8.4.4"


async def _down(ip):
    raise ProviderError("abuseipdb returned HTTP 503")


async def _unconfigured(ip):
    raise ProviderNotConfigured("no API key configured")


async def _clean(ip):
    return {"abuse_confidence_score": 0, "pulse_count": 0}


async def _known_bad(ip):
    return {"abuse_confidence_score": 95, "total_reports": 40}


def _use_providers(monkeypatch, abuse_fn, otx_fn):
    monkeypatch.setattr(enrich_alerts, "_PROVIDERS", (("abuseipdb", abuse_fn), ("otx", otx_fn)))


async def _new_alert(conn, ip=IP):
    await conn.execute("DELETE FROM ioc_cache WHERE indicator = $1", ip)
    return await conn.fetchval(
        """
        INSERT INTO alerts (title, severity, mitre_technique, source_ip, threat_score, status, evidence)
        VALUES ('Brute force login attempts', 'medium', 'T1110', $1::inet, 30, 'open', '{}'::jsonb)
        RETURNING id
        """,
        ip,
    )


async def _evidence(conn, alert_id):
    return json.loads(await conn.fetchval("SELECT evidence FROM alerts WHERE id = $1", alert_id))


async def _make_retry_due(conn, alert_id):
    await conn.execute(
        """
        UPDATE alerts
        SET evidence = jsonb_set(evidence, '{enrichment_next_attempt_at}', to_jsonb((now() - interval '1 minute')::text))
        WHERE id = $1 AND evidence ? 'enrichment_next_attempt_at'
        """,
        alert_id,
    )


async def test_provider_failure_schedules_a_retry_instead_of_marking_checked(conn, monkeypatch):
    _use_providers(monkeypatch, _down, _clean)
    alert_id = await _new_alert(conn)

    await enrich_alerts.run_all(conn)

    evidence = await _evidence(conn, alert_id)
    assert "enrichment_checked" not in evidence
    assert evidence["enrichment_attempts"] == 1
    assert evidence["enrichment_last_error"] == "abuseipdb returned HTTP 503"
    assert "enrichment_next_attempt_at" in evidence

    # Not due yet, so an immediate second pass leaves it alone.
    await enrich_alerts.run_all(conn)
    assert (await _evidence(conn, alert_id))["enrichment_attempts"] == 1


async def test_a_later_successful_lookup_completes_enrichment(conn, monkeypatch):
    _use_providers(monkeypatch, _down, _clean)
    alert_id = await _new_alert(conn)
    await enrich_alerts.run_all(conn)

    _use_providers(monkeypatch, _known_bad, _clean)
    await _make_retry_due(conn, alert_id)
    await enrich_alerts.run_all(conn)

    evidence = await _evidence(conn, alert_id)
    assert evidence["enrichment_checked"] is True
    assert evidence["enrichment_signals"] == ["known_bad_ip"]
    assert "enrichment_next_attempt_at" not in evidence
    assert await conn.fetchval("SELECT threat_score FROM alerts WHERE id = $1", alert_id) == 50


async def test_gives_up_after_max_attempts_with_a_visible_reason(conn, monkeypatch):
    _use_providers(monkeypatch, _down, _clean)
    alert_id = await _new_alert(conn)

    for _ in range(enrich_alerts.MAX_LOOKUP_ATTEMPTS):
        await enrich_alerts.run_all(conn)
        await _make_retry_due(conn, alert_id)

    evidence = await _evidence(conn, alert_id)
    assert evidence["enrichment_checked"] is True
    assert evidence["enrichment_skipped_reason"] == "provider_unavailable"
    assert evidence["enrichment_attempts"] == enrich_alerts.MAX_LOOKUP_ATTEMPTS
    assert "enrichment_next_attempt_at" not in evidence


async def test_no_configured_providers_marks_checked_with_a_reason(conn, monkeypatch):
    _use_providers(monkeypatch, _unconfigured, _unconfigured)
    alert_id = await _new_alert(conn)

    await enrich_alerts.run_all(conn)

    evidence = await _evidence(conn, alert_id)
    assert evidence["enrichment_checked"] is True
    assert evidence["enrichment_skipped_reason"] == "no threat-intel providers configured"


async def test_one_unconfigured_provider_does_not_block_the_other(conn, monkeypatch):
    _use_providers(monkeypatch, _known_bad, _unconfigured)
    alert_id = await _new_alert(conn)

    await enrich_alerts.run_all(conn)

    evidence = await _evidence(conn, alert_id)
    assert evidence["enrichment_signals"] == ["known_bad_ip"]
    assert evidence["enrichment_unconfigured"] == ["otx"]


async def test_lookups_per_tick_are_capped_and_the_rest_wait(conn, monkeypatch):
    monkeypatch.setattr(enrich_alerts, "LOOKUPS_PER_TICK", 2)
    looked_up = []

    async def counting(ip):
        looked_up.append(ip)
        return {"abuse_confidence_score": 0}

    _use_providers(monkeypatch, counting, _clean)
    alert_ids = [await _new_alert(conn, ip) for ip in ("8.8.4.1", "8.8.4.2", "8.8.4.3")]

    await enrich_alerts.run_all(conn)

    assert len(looked_up) == 2
    unchecked = [a for a in alert_ids if "enrichment_checked" not in await _evidence(conn, a)]
    assert len(unchecked) == 1


async def test_a_failed_provider_does_not_discard_the_working_one(conn, monkeypatch):
    """One provider being down used to abort the whole enrichment, throwing away
    what the others had already returned. The alert kept nothing at all."""
    _use_providers(monkeypatch, _known_bad, _down)
    alert_id = await _new_alert(conn)

    await enrich_alerts.run_all(conn)

    evidence = await _evidence(conn, alert_id)
    # AbuseIPDB answered, so its signal lands now...
    assert evidence["enrichment_signals"] == ["known_bad_ip"]
    assert await conn.fetchval("SELECT threat_score FROM alerts WHERE id = $1", alert_id) == 50
    # ...and OTX is still owed, so the alert is not finished with.
    assert evidence["enrichment_pending_providers"] == ["otx"]
    assert "enrichment_checked" not in evidence
    assert "enrichment_next_attempt_at" in evidence


async def test_retrying_a_partial_enrichment_does_not_double_count(conn, monkeypatch):
    """The score is rebuilt from the pre-enrichment total each pass, so a signal
    already applied cannot be added a second time when the retry lands."""
    _use_providers(monkeypatch, _known_bad, _down)
    alert_id = await _new_alert(conn)
    await enrich_alerts.run_all(conn)
    assert await conn.fetchval("SELECT threat_score FROM alerts WHERE id = $1", alert_id) == 50

    # OTX comes back, and reports pulses that corroborate AbuseIPDB.
    async def _pulses(ip):
        return {"pulse_count": 5}

    _use_providers(monkeypatch, _known_bad, _pulses)
    await _make_retry_due(conn, alert_id)
    await enrich_alerts.run_all(conn)

    evidence = await _evidence(conn, alert_id)
    assert evidence["enrichment_checked"] is True
    assert sorted(evidence["enrichment_signals"]) == ["known_bad_ip", "otx_pulse_match"]
    assert "enrichment_pending_providers" not in evidence
    # 30 base + 20 known_bad_ip + 15 otx_pulse_match — not 50 + 35.
    assert await conn.fetchval("SELECT threat_score FROM alerts WHERE id = $1", alert_id) == 65


async def test_giving_up_on_a_dead_provider_keeps_what_the_others_found(conn, monkeypatch):
    """After the last attempt the alert is marked checked, but the signals the
    providers that did answer earned must survive."""
    _use_providers(monkeypatch, _known_bad, _down)
    alert_id = await _new_alert(conn)

    for _ in range(enrich_alerts.MAX_LOOKUP_ATTEMPTS):
        await enrich_alerts.run_all(conn)
        await _make_retry_due(conn, alert_id)

    evidence = await _evidence(conn, alert_id)
    assert evidence["enrichment_checked"] is True
    assert evidence["enrichment_skipped_reason"] == "provider_unavailable"
    assert evidence["enrichment_signals"] == ["known_bad_ip"]
    assert await conn.fetchval("SELECT threat_score FROM alerts WHERE id = $1", alert_id) == 50
