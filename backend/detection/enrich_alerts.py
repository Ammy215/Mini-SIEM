import ipaddress
import json
import logging

from detection.scorer import THREAT_WEIGHTS, severity_for_score
from enrichment import abuseipdb, otx
from enrichment.cache import get_cached, set_cached

logger = logging.getLogger(__name__)

ABUSEIPDB_BAD_THRESHOLD = 80

# A single OTX pulse means almost nothing on its own — pulses are community
# submitted and extremely noisy. Measured against real traffic: Google's and
# Anthropic's own IPs carry 6-7 pulses each, including entries whose titles name
# a completely different IP. So a pulse only counts as a signal when there are
# several of them, or when AbuseIPDB independently reports some abuse.
OTX_PULSE_THRESHOLD = 3


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast or addr.is_unspecified
    )


async def _get_or_fetch(conn, ip: str, provider_name: str, query_fn) -> dict:
    cached = await get_cached(conn, ip, provider_name)
    if cached is not None:
        return cached
    data = await query_fn(ip)
    if "error" not in data:
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


async def _mark_checked(conn, alert_id: int, evidence: dict, signals: list[str] | None = None, reason: str | None = None) -> None:
    evidence["enrichment_checked"] = True
    if signals is not None:
        evidence["enrichment_signals"] = signals
    if reason is not None:
        evidence["enrichment_skipped_reason"] = reason
    await conn.execute(
        "UPDATE alerts SET evidence = $2::jsonb WHERE id = $1",
        alert_id, json.dumps(evidence),
    )


async def run_all(conn) -> dict[str, int]:
    rows = await conn.fetch(
        """
        SELECT id, source_ip, threat_score, severity, evidence
        FROM alerts
        WHERE source_ip IS NOT NULL
          AND (evidence->>'enrichment_checked') IS NULL
        """
    )

    checked = 0
    escalated = 0

    for row in rows:
        ip = str(row["source_ip"])
        evidence = json.loads(row["evidence"]) if row["evidence"] else {}

        if not _is_public(ip):
            await _mark_checked(conn, row["id"], evidence, signals=[], reason="non-public IP")
            checked += 1
            continue

        try:
            abuse_data = await _get_or_fetch(conn, ip, abuseipdb.PROVIDER, abuseipdb.query)
            otx_data = await _get_or_fetch(conn, ip, otx.PROVIDER, otx.query)
        except Exception:
            logger.exception("enrichment lookup failed for alert_id=%s ip=%s", row["id"], ip)
            continue

        signals, suppressed, observed = evaluate_signals(abuse_data, otx_data)

        # Recorded either way so an analyst can see what the providers said and
        # why a signal did or didn't count.
        evidence["enrichment_observed"] = observed
        if suppressed:
            evidence["enrichment_suppressed"] = suppressed

        if signals:
            bonus = sum(THREAT_WEIGHTS.get(s, 0) for s in signals)
            new_score = min(100, row["threat_score"] + bonus)
            new_severity = severity_for_score(new_score)
            evidence["enrichment_checked"] = True
            evidence["enrichment_signals"] = signals
            await conn.execute(
                "UPDATE alerts SET threat_score = $2, severity = $3, evidence = $4::jsonb WHERE id = $1",
                row["id"], new_score, new_severity, json.dumps(evidence),
            )
            escalated += 1
        else:
            await _mark_checked(conn, row["id"], evidence, signals=[])

        checked += 1

    return {"enrichment_checked": checked, "enrichment_escalated": escalated}
