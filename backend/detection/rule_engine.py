"""Evaluates detection rules written in the v2 rule language.

    match      events matching a filter; hits are grouped into one alert per
               attacker per window (signature rules)
    aggregate  events matching a filter, counted per group over a window
               (threshold rules)
    sequence   a key (an IP, a user) with enough "first" events followed by a
               "then" event soon after (sequence rules)

Each rule runs in its own transaction with a statement timeout, so one slow or
failing rule rolls back alone and can't stall the run. SET LOCAL lives exactly
as long as that transaction, which is also what keeps it safe through Neon's
transaction-mode connection pooler.
"""

import ipaddress
import json
import logging
import re

from detection.alerting import MAX_EVIDENCE_VALUES, link_events, upsert_alert
from detection.common import iso
from detection.compiler import Params, compile_condition
from detection.rule_fields import field_sql
from models.rule_definitions import InvalidDefinition, validate_definition

logger = logging.getLogger(__name__)

# How far back match and sequence rules look for new events.
LOOKBACK_MINUTES = 30
MAX_HITS_PER_RUN = 5_000
STATEMENT_TIMEOUT = "10s"
DEFAULT_GROUP_WINDOW_MINUTES = 60
SNIPPET_CHARS = 300

_TITLE_FIELD_RE = re.compile(r"\{(source_ip|username|host|dest_ip|event_code|group|count)\}")


async def run_rules(conn, rule_type: str) -> dict[str, int]:
    """Runs every enabled rule of one type. Returns {rule_key: alerts created}."""
    rows = await conn.fetch(
        """
        SELECT id, rule_key, title, severity, mitre_technique, rule_type, definition
        FROM rules WHERE rule_type = $1 AND enabled = TRUE
        ORDER BY rule_key
        """,
        rule_type,
    )
    results: dict[str, int] = {}
    for rule in rows:
        try:
            async with conn.transaction():
                await conn.execute(f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'")
                results[rule["rule_key"]] = await evaluate_rule(conn, rule)
        except Exception:
            logger.exception("detection rule %s failed", rule["rule_key"])
            results[rule["rule_key"]] = 0
    return results


async def evaluate_rule(conn, rule) -> int:
    stored = rule["definition"]
    definition, rule_type = validate_definition(json.loads(stored) if isinstance(stored, str) else stored)
    if rule_type != rule["rule_type"]:
        raise InvalidDefinition(
            f"rule {rule['rule_key']} is stored as a {rule['rule_type']} rule but defines a {rule_type} rule"
        )
    if rule_type == "sequence":
        return await _evaluate_sequence(conn, rule, definition)
    if rule_type == "threshold":
        return await _evaluate_aggregate(conn, rule, definition)
    return await _evaluate_match(conn, rule, definition)


# --- match ------------------------------------------------------------------------

async def _evaluate_match(conn, rule, definition: dict) -> int:
    alert_spec = definition.get("alert", {})
    add = Params()
    filter_sql, leaves = compile_condition(definition["filter"], add, "e")

    where = [
        f"e.event_time >= now() - make_interval(mins => {add(LOOKBACK_MINUTES)})",
        filter_sql,
        f"NOT EXISTS (SELECT 1 FROM alert_events ae WHERE ae.rule_id = {add(rule['id'])} AND ae.event_id = e.id)",
    ]
    if definition.get("logsource"):
        where.append(f"e.source_type = ANY({add(definition['logsource'], 'text[]')})")

    leaf_columns = "".join(
        f", ({leaf.value_sql}) AS v{leaf.index}, COALESCE(({leaf.sql}), false) AS m{leaf.index}" for leaf in leaves
    )
    rows = await conn.fetch(
        f"""
        SELECT e.id, e.event_time, e.source_ip{leaf_columns}
        FROM events e
        WHERE {' AND '.join(where)}
        ORDER BY e.event_time, e.id
        LIMIT {add(MAX_HITS_PER_RUN)}
        """,
        *add.values,
    )

    groups: dict[str, list] = {}
    for row in rows:
        groups.setdefault(_text(row["source_ip"]) or "", []).append(row)

    created = 0
    for group_key, hits in groups.items():
        patterns, field, snippet = _match_evidence(leaves, hits)
        first, last = hits[0], hits[-1]
        event_ids = [hit["id"] for hit in hits]
        evidence = {
            "event_id": first["id"],
            "event_ids": event_ids[:MAX_EVIDENCE_VALUES],
            "field": field,
            "matched_patterns": patterns,
            "value_snippet": snippet,
            "event_time": iso(first["event_time"]),
            "first_seen": iso(first["event_time"]),
            "last_seen": iso(last["event_time"]),
            "hit_count": len(hits),
        }
        source_ip = group_key or None
        alert_id, is_new = await upsert_alert(
            conn, rule=rule, group_key=group_key, source_ip=source_ip,
            first_time=first["event_time"], last_time=last["event_time"], evidence=evidence,
            signals=_signals(alert_spec),
            merge_minutes=alert_spec.get("group_window_minutes", DEFAULT_GROUP_WINDOW_MINUTES),
            title=render_title(alert_spec.get("title"), {"source_ip": source_ip, "group": source_ip}, rule["title"]),
        )
        await link_events(conn, rule["id"], alert_id, event_ids)
        created += is_new
    return created


def _match_evidence(leaves, hits) -> tuple[list[str], str | None, str | None]:
    """What matched, and in which field — from the conditions that were true.
    Patterns are re-checked with a plain substring test; a user-written regex
    only ever runs inside PostgreSQL, under the statement timeout."""
    patterns: list[str] = []
    field = snippet = None
    for hit in hits:
        for leaf in leaves:
            if leaf.negated or not hit[f"m{leaf.index}"]:
                continue
            text = _text(hit[f"v{leaf.index}"]) or ""
            for pattern in _leaf_patterns(leaf, text):
                if pattern not in patterns:
                    patterns.append(pattern)
            if field is None and text:
                field, snippet = leaf.field, text[:SNIPPET_CHARS]
    return patterns, field, snippet


def _leaf_patterns(leaf, text: str) -> list[str]:
    lowered = text.lower()
    if leaf.op == "contains_any":
        return [pattern for pattern in leaf.value if pattern.lower() in lowered]
    if leaf.op in ("contains", "startswith", "endswith", "regex"):
        return [leaf.value]
    if leaf.op in ("eq", "in") and text:
        return [text]
    return []


# --- aggregate --------------------------------------------------------------------

async def _evaluate_aggregate(conn, rule, definition: dict) -> int:
    aggregate = definition["aggregate"]
    alert_spec = definition.get("alert", {})
    group_by = aggregate["group_by"]
    add = Params()

    group_col = field_sql(group_by, "e", add)
    where = [f"e.event_time >= now() - make_interval(mins => {add(aggregate['window_minutes'])})", f"{group_col} IS NOT NULL"]
    if aggregate["function"] == "distinct":
        distinct_col = field_sql(aggregate["distinct_field"], "e", add)
        count_expr = f"COUNT(DISTINCT {distinct_col})"
        where.append(f"{distinct_col} IS NOT NULL")
    else:
        count_expr = "COUNT(*)"
    if definition.get("filter"):
        filter_sql, _ = compile_condition(definition["filter"], add, "e")
        where.append(filter_sql)
    if definition.get("logsource"):
        where.append(f"e.source_type = ANY({add(definition['logsource'], 'text[]')})")

    values_field = alert_spec.get("values_field")
    values_expr = (
        f"(array_agg(DISTINCT {field_sql(values_field, 'e', add)}))[1:{MAX_EVIDENCE_VALUES}]"
        if values_field else "NULL"
    )
    comparison = ">" if aggregate["op"] == "gt" else ">="

    rows = await conn.fetch(
        f"""
        SELECT {group_col} AS group_value, {count_expr} AS cnt, {values_expr} AS agg_values,
               (array_agg(e.id ORDER BY e.event_time))[1:{MAX_EVIDENCE_VALUES}] AS event_ids,
               min(e.event_time) AS first_seen, max(e.event_time) AS last_seen
        FROM events e
        WHERE {' AND '.join(where)}
        GROUP BY {group_col}
        HAVING {count_expr} {comparison} {add(aggregate['threshold'])}
        """,
        *add.values,
    )

    created = 0
    for row in rows:
        group_value = _text(row["group_value"])
        source_ip = group_value if group_by == "source_ip" else None
        evidence: dict = {alert_spec.get("count_key") or "count": row["cnt"]}
        if values_field:
            evidence[alert_spec.get("values_key") or "values"] = [_json_value(v) for v in row["agg_values"] or []]
        if group_by != "source_ip":
            evidence[group_by] = group_value
        evidence.update({
            "event_ids": list(row["event_ids"] or []),
            "first_seen": iso(row["first_seen"]),
            "last_seen": iso(row["last_seen"]),
        })
        title_values = {group_by: group_value, "group": group_value, "count": row["cnt"], "source_ip": source_ip}
        _, is_new = await upsert_alert(
            conn, rule=rule, group_key=group_value, source_ip=source_ip,
            first_time=row["first_seen"], last_time=row["last_seen"], evidence=evidence,
            signals=_signals(alert_spec), merge_minutes=aggregate["window_minutes"],
            title=render_title(alert_spec.get("title"), title_values, rule["title"]),
        )
        created += is_new
    return created


# --- sequence ---------------------------------------------------------------------

async def _evaluate_sequence(conn, rule, definition: dict) -> int:
    sequence = definition["sequence"]
    first, then = sequence["first"], sequence["then"]
    alert_spec = definition.get("alert", {})
    join_on = sequence["join_on"]
    add = Params()

    join_then = field_sql(join_on, "t", add)
    join_first = field_sql(join_on, "f", add)
    then_sql, _ = compile_condition(then["filter"], add, "t")
    first_sql, _ = compile_condition(first["filter"], add, "f")
    logsource_then = logsource_first = ""
    if definition.get("logsource"):
        logsource_then = f" AND t.source_type = ANY({add(definition['logsource'], 'text[]')})"
        logsource_first = f" AND f.source_type = ANY({add(definition['logsource'], 'text[]')})"

    rows = await conn.fetch(
        f"""
        SELECT t.id, t.event_time, t.username, {join_then} AS join_value,
               prior.cnt, prior.first_ids, prior.first_seen
        FROM events t
        CROSS JOIN LATERAL (
            SELECT COUNT(*) AS cnt,
                   (array_agg(f.id ORDER BY f.event_time))[1:{MAX_EVIDENCE_VALUES}] AS first_ids,
                   min(f.event_time) AS first_seen, max(f.event_time) AS last_first
            FROM events f
            WHERE {join_first} = {join_then}
              AND f.event_time >= t.event_time - make_interval(mins => {add(first['within_minutes'])})
              AND f.event_time < t.event_time
              AND {first_sql}{logsource_first}
        ) prior
        WHERE t.event_time >= now() - make_interval(mins => {add(LOOKBACK_MINUTES)})
          AND {join_then} IS NOT NULL
          AND {then_sql}{logsource_then}
          AND prior.cnt >= {add(first['min_count'])}
          AND prior.last_first >= t.event_time - make_interval(mins => {add(then['within_minutes'])})
          AND NOT EXISTS (SELECT 1 FROM alert_events ae WHERE ae.rule_id = {add(rule['id'])} AND ae.event_id = t.id)
        ORDER BY t.event_time, t.id
        LIMIT {add(MAX_HITS_PER_RUN)}
        """,
        *add.values,
    )

    groups: dict[str, list] = {}
    for row in rows:
        groups.setdefault(_text(row["join_value"]), []).append(row)

    created = 0
    for join_value, hits in groups.items():
        last = hits[-1]
        prior_ids = []
        for hit in hits:
            prior_ids.extend(event_id for event_id in hit["first_ids"] or [] if event_id not in prior_ids)
        then_ids = [hit["id"] for hit in hits]
        source_ip = join_value if join_on == "source_ip" else None
        first_seen = min(hit["first_seen"] for hit in hits)
        evidence = {
            alert_spec.get("count_key") or "first_step_count": max(hit["cnt"] for hit in hits),
            "event_id": hits[0]["id"],
            "event_ids": (then_ids + prior_ids)[:MAX_EVIDENCE_VALUES],
            "first_seen": iso(first_seen),
            "last_seen": iso(last["event_time"]),
        }
        if join_on != "source_ip":
            evidence[join_on] = join_value
        elif last["username"]:
            evidence["username"] = last["username"]
        title_values = {join_on: join_value, "group": join_value, "source_ip": source_ip, "username": last["username"]}
        alert_id, is_new = await upsert_alert(
            conn, rule=rule, group_key=join_value, source_ip=source_ip,
            first_time=first_seen, last_time=last["event_time"], evidence=evidence,
            signals=_signals(alert_spec),
            merge_minutes=first["within_minutes"] + then["within_minutes"],
            title=render_title(alert_spec.get("title"), title_values, rule["title"]),
        )
        await link_events(conn, rule["id"], alert_id, then_ids)
        created += is_new
    return created


# --- shared -------------------------------------------------------------------------

def render_title(template: str | None, values: dict, fallback: str) -> str:
    """Fills {source_ip}, {username}, … from a fixed list. Deliberately not
    str.format, which would let a template reach object attributes."""
    if not template:
        return fallback
    return _TITLE_FIELD_RE.sub(lambda m: _text(values.get(m.group(1))) or "unknown", template)[:300]


def _signals(alert_spec: dict) -> list[str]:
    return [alert_spec["signal"]] if alert_spec.get("signal") else []


def _text(value) -> str | None:
    return None if value is None else str(value)


def _json_value(value):
    """Keeps numbers as numbers (ports stay sortable); IP addresses become text."""
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(value)
    return value
