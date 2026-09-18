"""Creating alerts — or extending one that's already open for the same attacker.

A rule's matches for one group (an attacker IP, a targeted username) within
its merge window extend a single open alert: more event ids, a growing hit
count, a later last-seen time. The alert keeps the score and severity it was
created with; threat intel can still raise them.
"""

import json

from config import settings
from detection import context
from detection.scorer import score_alert

MAX_EVIDENCE_VALUES = 50

# Evidence describing the first matching event stays as it was first written.
_FIRST_WRITE_WINS = ("event_id", "field", "value_snippet", "event_time")


async def upsert_alert(
    conn, *, rule, group_key: str, source_ip: str | None, first_time, last_time,
    evidence: dict, signals: list[str], merge_minutes: int, title: str,
    origin: str = "live", batch_id=None,
) -> tuple[int, bool]:
    """Returns (alert id, whether a new alert was created)."""
    # Both bounds matter. Checking only that the open alert is not too OLD let
    # detection over a past range fold a months-old burst into an alert raised
    # today for the same address: the merge widens the window with LEAST/GREATEST,
    # so one alert ended up spanning March to September and the historical
    # campaign disappeared into an unrelated live one. The two windows now have
    # to be within merge_minutes of each other in either direction.
    existing = await conn.fetchrow(
        """
        SELECT id, evidence FROM alerts
        WHERE rule_id = $1 AND group_key = $2 AND status = 'open'
          AND last_event_time  >= $3::timestamptz - make_interval(mins => $4)
          AND first_event_time <= $5::timestamptz + make_interval(mins => $4)
        ORDER BY last_event_time DESC
        LIMIT 1
        FOR UPDATE
        """,
        rule["id"], group_key, first_time, merge_minutes, last_time,
    )
    if existing is not None:
        merged = merge_evidence(json.loads(existing["evidence"]) if existing["evidence"] else {}, evidence)
        await conn.execute(
            """
            UPDATE alerts SET evidence = $2::jsonb,
                first_event_time = LEAST(first_event_time, $3),
                last_event_time = GREATEST(last_event_time, $4)
            WHERE id = $1
            """,
            existing["id"], json.dumps(merged), first_time, last_time,
        )
        return existing["id"], False

    signals, evidence = list(signals), dict(evidence)
    business_hours = context.load(settings).business_hours
    if business_hours is None:
        evidence["context_skipped"] = ["after_hours: business hours not configured"]
    elif context.is_after_hours(first_time, business_hours):
        signals.append("after_hours")
        evidence["context_signals"] = ["after_hours"]

    score, severity = score_alert(signals, minimum=rule["severity"])
    alert_id = await conn.fetchval(
        """
        INSERT INTO alerts (rule_id, title, severity, mitre_technique, source_ip, threat_score, status, evidence,
                            group_key, first_event_time, last_event_time, origin, batch_id)
        VALUES ($1, $2, $3, $4, $5::inet, $6, 'open', $7::jsonb, $8, $9, $10, $11, $12)
        RETURNING id
        """,
        rule["id"], title, severity, rule["mitre_technique"], source_ip, score, json.dumps(evidence),
        group_key, first_time, last_time, origin, batch_id,
    )
    return alert_id, True


async def link_events(conn, rule_id: int, alert_id: int, event_ids: list[int]) -> None:
    """Records that these events are covered, so the rule never alerts on them again."""
    await conn.executemany(
        "INSERT INTO alert_events (rule_id, event_id, alert_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        [(rule_id, event_id, alert_id) for event_id in event_ids],
    )


def merge_evidence(old: dict, new: dict) -> dict:
    merged = dict(old)
    for key, value in new.items():
        previous = merged.get(key)
        if key in _FIRST_WRITE_WINS:
            merged.setdefault(key, value)
        elif key == "hit_count":
            merged[key] = (previous or 0) + value
        elif key == "first_seen":
            merged[key] = min(v for v in (previous, value) if v) if (previous or value) else None
        elif key == "last_seen":
            merged[key] = max(v for v in (previous, value) if v) if (previous or value) else None
        elif isinstance(value, list):
            combined = list(previous) if isinstance(previous, list) else []
            for item in value:
                if item not in combined:
                    combined.append(item)
            merged[key] = combined[:MAX_EVIDENCE_VALUES]
        elif isinstance(value, int) and not isinstance(value, bool) and isinstance(previous, int):
            merged[key] = max(previous, value)  # counts: the largest window seen
        elif previous is None:
            merged[key] = value
    return merged
