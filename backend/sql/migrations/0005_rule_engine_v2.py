"""Rule engine v2.

- alert_events records which events an alert already covers, so a match rule
  never alerts twice on the same event. It replaces re-reading every past
  alert's evidence on every detection run.
- alerts gain group_key and event-time bounds, so repeat hits from one
  attacker extend one open alert instead of creating one alert per event.
- rule definitions move from the v1 shapes to the v2 rule language. Built-in
  rules nobody edited are rewritten from the shipped YAML at the next startup
  anyway; translating here also keeps rules someone edited (their windows,
  thresholds and patterns), and leaves no v1 definition for the engine.

Self-contained on purpose: a migration has to keep working after the app code
written alongside it changes.
"""

import json
from datetime import datetime

DDL = """
CREATE TABLE IF NOT EXISTS alert_events (
  rule_id  INT    NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
  -- No foreign key to events: events can be deleted (retention, test cleanup)
  -- without rewriting alert history.
  event_id BIGINT NOT NULL,
  alert_id BIGINT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  PRIMARY KEY (rule_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_events_alert ON alert_events (alert_id);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS group_key        TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS first_event_time TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS last_event_time  TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_alerts_rule_group_open
  ON alerts (rule_id, group_key, last_event_time DESC) WHERE status = 'open';
"""

_LOGIN_FAILED = {"field": "action", "op": "eq", "value": "login_failed"}

# What each v1 threshold evaluator hard-coded in its SQL.
_THRESHOLD_SHAPES = {
    "brute_force": {
        "filter": _LOGIN_FAILED, "group_by": "source_ip", "function": "count", "distinct_field": None, "op": "gt",
        "signal": "brute_force_confirmed", "title": "Brute force login attempts from {source_ip}",
        "count_key": "failed_count", "values_key": "usernames", "values_field": "username",
    },
    "credential_stuffing": {
        "filter": _LOGIN_FAILED, "group_by": "source_ip", "function": "distinct", "distinct_field": "username",
        "op": "gte", "signal": "credential_stuffing", "title": "Credential stuffing from {source_ip}",
        "count_key": "distinct_usernames", "values_key": "usernames", "values_field": "username",
    },
    "port_scan": {
        "filter": None, "group_by": "source_ip", "function": "distinct", "distinct_field": "dest_port", "op": "gte",
        "signal": "port_scan", "title": "Port scan from {source_ip}",
        "count_key": "distinct_ports", "values_key": "ports", "values_field": "dest_port",
    },
    "password_spray": {
        "filter": _LOGIN_FAILED, "group_by": "username", "function": "distinct", "distinct_field": "source_ip",
        "op": "gte", "signal": "password_spray_confirmed", "title": "Password spray against user '{username}'",
        "count_key": "distinct_ips", "values_key": "source_ips", "values_field": "source_ip",
    },
}


def _threshold_v2(rule_key: str, v1: dict) -> dict | None:
    shape = _THRESHOLD_SHAPES.get(rule_key)
    window, threshold = v1.get("window_minutes"), v1.get("threshold")
    if shape is None or not isinstance(window, int) or not isinstance(threshold, int):
        return None

    aggregate = {"group_by": shape["group_by"], "window_minutes": window, "function": shape["function"]}
    if shape["distinct_field"]:
        aggregate["distinct_field"] = shape["distinct_field"]
    aggregate.update({"op": shape["op"], "threshold": threshold})

    definition: dict = {"version": 2}
    if shape["filter"]:
        definition["filter"] = shape["filter"]
    definition["aggregate"] = aggregate
    definition["alert"] = {key: shape[key] for key in ("signal", "title", "count_key", "values_key", "values_field")}
    return definition


def _signature_v2(v1: dict) -> dict | None:
    field, patterns = v1.get("field"), v1.get("contains")
    if not isinstance(field, str) or not isinstance(patterns, list) or not patterns:
        return None
    definition: dict = {"version": 2}
    if v1.get("logsource"):
        definition["logsource"] = [v1["logsource"]]
    definition["filter"] = {"field": field, "op": "contains_any", "value": patterns}
    alert: dict = {"group_window_minutes": 60}
    if v1.get("signal"):
        alert["signal"] = v1["signal"]
    definition["alert"] = alert
    return definition


def _aware_time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


async def up(conn):
    await conn.execute(DDL)

    for rule in await conn.fetch("SELECT id, rule_key, rule_type, definition FROM rules"):
        v1 = json.loads(rule["definition"]) if isinstance(rule["definition"], str) else rule["definition"]
        if not isinstance(v1, dict) or v1.get("version") == 2:
            continue
        if rule["rule_type"] == "threshold":
            translated = _threshold_v2(rule["rule_key"], v1)
        elif rule["rule_type"] == "signature":
            translated = _signature_v2(v1)
        else:
            translated = None
        # A definition that can't be translated (hand-edited into something
        # invalid) is left as it is; the engine refuses it and logs why.
        if translated is not None:
            await conn.execute("UPDATE rules SET definition = $2::jsonb WHERE id = $1", rule["id"], json.dumps(translated))

    for alert in await conn.fetch(
        "SELECT id, rule_id, source_ip, evidence, created_at FROM alerts WHERE group_key IS NULL"
    ):
        evidence = json.loads(alert["evidence"]) if alert["evidence"] else {}
        group_key = str(alert["source_ip"]) if alert["source_ip"] else str(evidence.get("username") or "")
        first = _aware_time(evidence.get("first_seen")) or _aware_time(evidence.get("event_time")) or alert["created_at"]
        last = _aware_time(evidence.get("last_seen")) or _aware_time(evidence.get("event_time")) or alert["created_at"]
        await conn.execute(
            "UPDATE alerts SET group_key = $2, first_event_time = $3, last_event_time = $4 WHERE id = $1",
            alert["id"], group_key, first, last,
        )
        event_id = evidence.get("event_id")
        if alert["rule_id"] is not None and isinstance(event_id, int) and not isinstance(event_id, bool):
            await conn.execute(
                "INSERT INTO alert_events (rule_id, event_id, alert_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                alert["rule_id"], event_id, alert["id"],
            )
