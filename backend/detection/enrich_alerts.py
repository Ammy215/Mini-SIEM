import json
import logging
from datetime import datetime, timedelta, timezone

from config import settings
from detection import context
from detection.scorer import THREAT_WEIGHTS, max_severity, severity_for_score
from enrichment import abuseipdb, geo, otx
from enrichment.cache import get_cached, set_cached
from enrichment.errors import ProviderError, ProviderNotConfigured
from enrichment.ip import is_public

logger = logging.getLogger(__name__)

ABUSEIPDB_BAD_THRESHOLD = 80

# A single OTX pulse means almost nothing on its own — pulses are community
# submitted and extremely noisy. Measured against real traffic: Google's and
# Anthropic's own IPs carry 6-7 pulses each, including entries whose titles name
# a completely different IP. So a pulse only counts as a signal when there are
# several of them, or when AbuseIPDB independently reports some abuse.
OTX_PULSE_THRESHOLD = 3

# A provider outage or rate limit used to cost an alert its enrichment forever:
# the failure was indistinguishable from "clean IP" and the alert was marked
# checked. Failed lookups now retry with backoff (2, 4, 8, 16 minutes) and only
# give up after this many attempts.
MAX_LOOKUP_ATTEMPTS = 5

# Alerts that need provider lookups handled per scheduler tick, newest first;
# the rest wait for the next tick. Keeps a burst of new alerts from spending a
# free-tier daily quota in one go.
LOOKUPS_PER_TICK = 25

_PROVIDERS = ((abuseipdb.PROVIDER, abuseipdb.query), (otx.PROVIDER, otx.query))


_is_public = is_public


async def _foreign_geo(conn, ip: str, provider_data: dict) -> tuple[list[str], str | None, str | None]:
    """(signals, country, skipped reason). The country AbuseIPDB returned is
    used when there is one; otherwise the geo lookup (cache first)."""
    home = context.parse_countries(settings.home_countries)
    if not home:
        return [], None, "foreign_geo: home countries not configured"
    country = (provider_data.get(abuseipdb.PROVIDER) or {}).get("country_code")
    if not country:
        location = await geo.lookup(conn, ip)
        country = location["country"] if location else None
    if not country:
        return [], None, "foreign_geo: country unknown"
    country = country.upper()
    return (["foreign_geo"] if context.is_foreign(country, home) else []), country, None


async def _get_or_fetch(conn, ip: str, provider_name: str, query_fn) -> dict | None:
    """Cached or fresh provider data, or None when the provider has no API key.
    Raises ProviderError when the provider is configured but the lookup failed."""
    cached = await get_cached(conn, ip, provider_name)
    if cached is not None:
        return cached
    try:
        data = await query_fn(ip)
    except ProviderNotConfigured:
        return None
    await set_cached(conn, ip, "ip", provider_name, data)
    return data


def evaluate_signals(abuse_data: dict, otx_data: dict) -> tuple[list[str], list[str], dict]:
    """Decide which threat-intel signals an IP earns.

    Returns (signals, suppressed_reasons, observed_values). Pure and provider-
    shape tolerant — both providers can return partial data or nothing at all.
    """
    signals: list[str] = []
    suppressed: list[str] = []

    raw_score = abuse_data.get("abuse_confidence_score")
    abuse_score = raw_score if isinstance(raw_score, (int, float)) else None
    # AbuseIPDB flags known-good infrastructure (major clouds, public resolvers).
    # We already fetched this field and previously ignored it.
    is_whitelisted = abuse_data.get("is_whitelisted") is True

    if abuse_score is not None and abuse_score > ABUSEIPDB_BAD_THRESHOLD:
        signals.append("known_bad_ip")

    raw_pulses = otx_data.get("pulse_count")
    pulse_count = raw_pulses if isinstance(raw_pulses, (int, float)) else None

    if pulse_count is not None and pulse_count > 0:
        if is_whitelisted:
            suppressed.append("otx_pulse_match: AbuseIPDB-whitelisted infrastructure")
        elif pulse_count >= OTX_PULSE_THRESHOLD or (abuse_score or 0) > 0:
            signals.append("otx_pulse_match")
        else:
            suppressed.append(
                f"otx_pulse_match: only {int(pulse_count)} pulse(s) and no AbuseIPDB corroboration"
            )

    observed = {
        "abuse_confidence_score": abuse_score,
        "is_whitelisted": is_whitelisted,
        "otx_pulse_count": pulse_count,
    }
    return signals, suppressed, observed


async def _save_evidence(conn, alert_id: int, evidence: dict) -> None:
    await conn.execute(
        "UPDATE alerts SET evidence = $2::jsonb WHERE id = $1",
        alert_id, json.dumps(evidence),
    )


async def _mark_checked(conn, alert_id: int, evidence: dict, signals: list[str] | None = None, reason: str | None = None) -> None:
    evidence["enrichment_checked"] = True
    evidence.pop("enrichment_next_attempt_at", None)
    if signals is not None:
        evidence["enrichment_signals"] = signals
    if reason is not None:
        evidence["enrichment_skipped_reason"] = reason
    await _save_evidence(conn, alert_id, evidence)


async def _gather_providers(conn, ip: str) -> tuple[dict[str, dict | None], list[str], dict[str, str]]:
    """Looks each provider up on its own.

    Returns (data, unconfigured, failures). Awaiting them together meant one
    provider being unreachable threw away what the others had already returned
    — including the country code `foreign_geo` needs — so an alert from a known
    bad foreign IP scored as if nothing were known about it. A provider that is
    down now costs only its own signals.
    """
    data: dict[str, dict | None] = {}
    unconfigured: list[str] = []
    failures: dict[str, str] = {}
    for name, query_fn in _PROVIDERS:
        try:
            result = await _get_or_fetch(conn, ip, name, query_fn)
        except ProviderError as exc:
            data[name], failures[name] = None, str(exc)
            continue
        except Exception as exc:  # noqa: BLE001 - one provider must not stop the rest
            logger.exception("enrichment lookup failed for ip=%s provider=%s", ip, name)
            data[name], failures[name] = None, type(exc).__name__
            continue
        if result is None:          # no API key configured for this provider
            unconfigured.append(name)
        data[name] = result
    return data, unconfigured, failures


async def _record_failed_attempt(conn, alert_id: int, evidence: dict, error: str,
                                 signals: list[str] | None = None) -> bool:
    """Schedules a retry. Returns True when that was the last allowed attempt
    and the alert has been marked checked instead. `signals` are the ones the
    providers that *did* answer earned, and survive giving up on the rest."""
    attempts = int(evidence.get("enrichment_attempts") or 0) + 1
    evidence["enrichment_attempts"] = attempts
    evidence["enrichment_last_error"] = error
    logger.warning("enrichment lookup failed for alert_id=%s (attempt %s/%s): %s",
                   alert_id, attempts, MAX_LOOKUP_ATTEMPTS, error)

    if attempts >= MAX_LOOKUP_ATTEMPTS:
        await _mark_checked(conn, alert_id, evidence,
                            signals=list(signals or []), reason="provider_unavailable")
        return True

    retry_at = datetime.now(timezone.utc) + timedelta(minutes=2 ** attempts)
    evidence["enrichment_next_attempt_at"] = retry_at.isoformat()
    await _save_evidence(conn, alert_id, evidence)
    return False


async def run_all(conn) -> dict[str, int]:
    rows = await conn.fetch(
        """
        SELECT id, source_ip, threat_score, severity, evidence
        FROM alerts
        WHERE source_ip IS NOT NULL
          AND (evidence->>'enrichment_checked') IS NULL
          AND (evidence->>'enrichment_next_attempt_at' IS NULL
               OR (evidence->>'enrichment_next_attempt_at')::timestamptz <= now())
        ORDER BY created_at DESC
        """
    )

    checked = 0
    escalated = 0
    retry_scheduled = 0
    lookups = 0

    for row in rows:
        ip = str(row["source_ip"])
        evidence = json.loads(row["evidence"]) if row["evidence"] else {}

        if not _is_public(ip):
            await _mark_checked(conn, row["id"], evidence, signals=[], reason="non-public IP")
            checked += 1
            continue

        if lookups >= LOOKUPS_PER_TICK:
            continue  # left unchecked; a later tick picks it up
        lookups += 1

        provider_data, unconfigured, failures = await _gather_providers(conn, ip)

        geo_signals, country, geo_skipped = await _foreign_geo(conn, ip, provider_data)
        if geo_skipped:
            evidence["enrichment_context_skipped"] = [geo_skipped]

        if len(unconfigured) == len(provider_data) and not geo_signals:
            await _mark_checked(conn, row["id"], evidence, signals=[], reason="no threat-intel providers configured")
            checked += 1
            continue
        if unconfigured:
            evidence["enrichment_unconfigured"] = unconfigured

        signals, suppressed, observed = evaluate_signals(
            provider_data[abuseipdb.PROVIDER] or {}, provider_data[otx.PROVIDER] or {},
        )
        signals += geo_signals
        if country:
            observed["country"] = country

        # Recorded either way so an analyst can see what the providers said and
        # why a signal did or didn't count.
        evidence["enrichment_observed"] = observed
        if suppressed:
            evidence["enrichment_suppressed"] = suppressed

        # The score is always rebuilt from the alert's pre-enrichment total, not
        # added to its running one. Partial results can therefore be applied now
        # and recomputed after a retry without counting a signal twice.
        base = evidence.get("enrichment_base_score")
        if base is None:
            base = row["threat_score"] or 0
            evidence["enrichment_base_score"] = base
        bonus = sum(THREAT_WEIGHTS.get(s, 0) for s in signals)
        new_score = min(100, base + bonus)
        # Escalation only: the alert already carries its rule's minimum
        # severity, which a higher score must never drop below.
        new_severity = max_severity(row["severity"], severity_for_score(new_score))

        if failures:
            # Keep what the providers that answered earned, and come back for
            # the rest. Without this an outage at one provider left the alert
            # with nothing, even when another had already named the IP as bad.
            evidence["enrichment_signals"] = signals
            evidence["enrichment_pending_providers"] = sorted(failures)
            await conn.execute(
                "UPDATE alerts SET threat_score = $2, severity = $3 WHERE id = $1",
                row["id"], new_score, new_severity,
            )
            gave_up = await _record_failed_attempt(
                # Provider errors already name their provider.
                conn, row["id"], evidence,
                "; ".join(err for _, err in sorted(failures.items())),
                signals=signals,
            )
            if gave_up:
                checked += 1
            else:
                retry_scheduled += 1
            if signals:
                escalated += 1
            continue

        evidence.pop("enrichment_pending_providers", None)
        if signals:
            evidence["enrichment_checked"] = True
            evidence["enrichment_signals"] = signals
            evidence.pop("enrichment_next_attempt_at", None)
            await conn.execute(
                "UPDATE alerts SET threat_score = $2, severity = $3, evidence = $4::jsonb WHERE id = $1",
                row["id"], new_score, new_severity, json.dumps(evidence),
            )
            escalated += 1
        else:
            await _mark_checked(conn, row["id"], evidence, signals=[])

        checked += 1

    return {
        "enrichment_checked": checked,
        "enrichment_escalated": escalated,
        "enrichment_retry_scheduled": retry_scheduled,
    }
