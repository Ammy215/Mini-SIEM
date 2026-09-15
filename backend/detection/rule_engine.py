"""Evaluates detection rules written in the v2 rule language.

    match      events matching a filter; hits are grouped into one alert per
               attacker per window (signature rules)
    aggregate  events matching a filter, counted per group over a window
               (threshold rules)
    sequence   a key (an IP, a user) with enough "first" events followed by a
               "then" event soon after (sequence rules)

A run is either live (no Scope: look back a few minutes from now) or over a
Scope: a past time range, optionally limited to one upload's events. Over a
range, threshold rules use a sliding window across the whole range, so a burst
is found wherever it happened, and each separate burst becomes its own alert.

Each rule runs in its own transaction with a statement timeout, so one slow or
failing rule rolls back alone and can't stall the run. SET LOCAL lives exactly
as long as that transaction, which is also what keeps it safe through Neon's
transaction-mode connection pooler.
"""

import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

import asyncpg

from detection.alerting import MAX_EVIDENCE_VALUES, link_events, upsert_alert
from detection.common import iso
from detection.compiler import Params, compile_condition
from detection.rule_fields import field_sql
from models.rule_definitions import InvalidDefinition, validate_definition

logger = logging.getLogger(__name__)

# How far back live match and sequence rules look for new events.
LOOKBACK_MINUTES = 30
MAX_HITS_PER_RUN = 5_000
STATEMENT_TIMEOUT = "10s"
DEFAULT_GROUP_WINDOW_MINUTES = 60
SNIPPET_CHARS = 300

# Over a past range: more time per rule, repeated passes for match and
# sequence rules (each pass takes the next MAX_HITS_PER_RUN events), and a cap
# on the separate bursts one threshold rule can report.
RANGE_STATEMENT_TIMEOUT = "30s"
MAX_RANGE_PASSES = 40
MAX_EPISODES_PER_RULE = 500

PREVIEW_TIMEOUT = "5s"
PREVIEW_SAMPLES = 10
PREVIEW_ROW_CAP = 1_000

_TITLE_FIELD_RE = re.compile(r"\{(source_ip|username|host|dest_ip|event_code|group|count)\}")
_TITLE_FIELDS = ("source_ip", "username", "host", "dest_ip", "event_code")


@dataclass(frozen=True)
class Scope:
    """A past time range to analyse (both ends inclusive), optionally only the
    events of one upload."""
    time_from: datetime
    time_to: datetime
    batch_id: UUID | None = None

    @property
    def origin(self) -> str:
        return "batch" if self.batch_id is not None else "range"


async def run_rules(conn, rule_type: str, scope: Scope | None = None, errors: dict | None = None) -> dict[str, int]:
    """Runs every enabled rule of one type. Returns {rule_key: alerts created}.
    A rule that fails counts 0; over a scope, its reason goes into `errors`."""
    rows = await conn.fetch(
        """
        SELECT id, rule_key, title, severity, mitre_technique, rule_type, definition
        FROM rules WHERE rule_type = $1 AND enabled = TRUE
        ORDER BY rule_key
        """,
        rule_type,
    )
    timeout = RANGE_STATEMENT_TIMEOUT if scope else STATEMENT_TIMEOUT
    results: dict[str, int] = {}
    for rule in rows:
        started = time.monotonic()
        error = None
        try:
            async with conn.transaction():
                await conn.execute(f"SET LOCAL statement_timeout = '{timeout}'")
                results[rule["rule_key"]] = await evaluate_rule(conn, rule, scope)
        except Exception as exc:
            logger.exception("detection rule %s failed", rule["rule_key"])
            results[rule["rule_key"]] = 0
            error = describe_rule_error(exc, timeout)
        if scope is None:
            # Rule health describes the live scheduler's runs.
            await _record_state(conn, rule["id"], results[rule["rule_key"]], error, started)
        elif error and errors is not None:
            errors[rule["rule_key"]] = error
    return results


async def evaluate_rule(conn, rule, scope: Scope | None = None) -> int:
    stored = rule["definition"]
    definition, rule_type = validate_definition(json.loads(stored) if isinstance(stored, str) else stored)
    if rule_type != rule["rule_type"]:
        raise InvalidDefinition(
            f"definition: describes a {rule_type} rule, but this is a {rule['rule_type']} rule"
        )
    if rule_type == "sequence":
        return await _evaluate_sequence(conn, rule, definition, scope)
    if rule_type == "threshold":
        if scope is not None:
            return await _evaluate_aggregate_range(conn, rule, definition, scope)
        return await _evaluate_aggregate(conn, rule, definition)
    return await _evaluate_match(conn, rule, definition, scope)


def describe_rule_error(exc: Exception, timeout: str = STATEMENT_TIMEOUT) -> str:
    """A message safe to show on the Rules page: never a raw database error,
    which could quote the data a query was looking at."""
    if isinstance(exc, InvalidDefinition):
        return f"invalid definition: {exc}"[:300]
    if isinstance(exc, asyncpg.QueryCanceledError):
        return f"timed out (took longer than {timeout})"
    if isinstance(exc, asyncpg.InvalidRegularExpressionError):
        return "PostgreSQL rejected a regular expression in this rule"
    return f"failed ({type(exc).__name__})"


async def _record_state(conn, rule_id: int, alerts: int, error: str | None, started: float) -> None:
    try:
        await conn.execute(
            """
            INSERT INTO rule_state (rule_id, last_run_at, last_duration_ms, last_alerts, last_error, last_error_at,
                                    consecutive_errors)
            VALUES ($1, now(), $2, $3, $4::text, CASE WHEN $4::text IS NULL THEN NULL ELSE now() END,
                    CASE WHEN $4::text IS NULL THEN 0 ELSE 1 END)
            ON CONFLICT (rule_id) DO UPDATE SET
                last_run_at = now(),
                last_duration_ms = EXCLUDED.last_duration_ms,
                last_alerts = EXCLUDED.last_alerts,
                last_error = EXCLUDED.last_error,
                last_error_at = COALESCE(EXCLUDED.last_error_at, rule_state.last_error_at),
                consecutive_errors = CASE WHEN EXCLUDED.last_error IS NULL THEN 0
                                          ELSE rule_state.consecutive_errors + 1 END
            """,
            rule_id, int((time.monotonic() - started) * 1000), alerts, error,
        )
    except Exception:
        # Bookkeeping must never stop detection.
        logger.exception("could not record run state for rule id %s", rule_id)


# --- scope helpers ------------------------------------------------------------------

def _scope_sql(alias: str, add: Params, scope: Scope, start_sql: str, end_sql: str) -> str:
    sql = f"{alias}.event_time >= {start_sql} AND {alias}.event_time <= {end_sql}"
    if scope.batch_id is not None:
        sql += f" AND {alias}.batch_id = {add(scope.batch_id)}"
    return sql


def _time_bounds(alias: str, add: Params, scope: Scope | None, lookback_minutes: int) -> str:
    if scope is None:
        return f"{alias}.event_time >= now() - make_interval(mins => {add(lookback_minutes)})"
    return _scope_sql(alias, add, scope, add(scope.time_from), add(scope.time_to))


def _origin(scope: Scope | None) -> tuple[str, UUID | None]:
    return ("live", None) if scope is None else (scope.origin, scope.batch_id)


def _clusters(rows, gap_minutes: int):
    """Splits time-ordered rows wherever two in a row are further apart than
    the gap, so a week of hits from one source isn't one alert."""
    gap = timedelta(minutes=gap_minutes)
    cluster: list = []
    for row in rows:
        if cluster and row["event_time"] - cluster[-1]["event_time"] > gap:
            yield cluster
            cluster = []
        cluster.append(row)
    if cluster:
        yield cluster


# --- match ------------------------------------------------------------------------

def _match_filter(definition: dict, add: Params, lookback_minutes: int, rule_id: int | None, scope: Scope | None = None):
    """WHERE clause for a match rule's events, and its compiled leaves. With a
    rule id, events that rule already alerted on are excluded."""
    filter_sql, leaves = compile_condition(definition["filter"], add, "e")
    where = [_time_bounds("e", add, scope, lookback_minutes), filter_sql]
    if rule_id is not None:
        where.append(
            f"NOT EXISTS (SELECT 1 FROM alert_events ae WHERE ae.rule_id = {add(rule_id)} AND ae.event_id = e.id)"
        )
    if definition.get("logsource"):
        where.append(f"e.source_type = ANY({add(definition['logsource'], 'text[]')})")
    return " AND ".join(where), leaves


def _leaf_columns(leaves) -> str:
    return "".join(
        f", ({leaf.value_sql}) AS v{leaf.index}, COALESCE(({leaf.sql}), false) AS m{leaf.index}" for leaf in leaves
    )


async def _evaluate_match(conn, rule, definition: dict, scope: Scope | None) -> int:
    alert_spec = definition.get("alert", {})
    group_by = alert_spec.get("group_by") or ["source_ip"]
    merge_minutes = alert_spec.get("group_window_minutes", DEFAULT_GROUP_WINDOW_MINUTES)
    created = 0
    for _ in range(MAX_RANGE_PASSES if scope else 1):
        add = Params()
        where, leaves = _match_filter(definition, add, LOOKBACK_MINUTES, rule["id"], scope)
        rows = await conn.fetch(
            f"""
            SELECT e.id, e.event_time, e.source_ip, e.username, e.host, e.dest_ip, e.event_code{_leaf_columns(leaves)}
            FROM events e
            WHERE {where}
            ORDER BY e.event_time, e.id
            LIMIT {add(MAX_HITS_PER_RUN)}
            """,
            *add.values,
        )

        # One alert per distinct combination of the group_by values (by default,
        # per attacker IP). Windows events often have no IP, so those rules group
        # by host or user instead.
        groups: dict[str, list] = {}
        for row in rows:
            groups.setdefault("|".join(_text(row[field]) or "" for field in group_by), []).append(row)
        for group_key, group_rows in groups.items():
            for hits in _clusters(group_rows, merge_minutes):
                created += await _alert_on_matches(
                    conn, rule, alert_spec, group_by, group_key, leaves, hits, merge_minutes, scope
                )
        # Matched events are linked to their alert, so the next pass starts after them.
        if len(rows) < MAX_HITS_PER_RUN:
            break
    return created


async def _alert_on_matches(conn, rule, alert_spec, group_by, group_key, leaves, hits, merge_minutes, scope) -> int:
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
    for name in group_by:
        if name != "source_ip":
            evidence[name] = _text(first[name])
    source_ip = _text(first["source_ip"]) if "source_ip" in group_by else None
    title_values = {name: _text(first[name]) for name in _TITLE_FIELDS}
    title_values["group"] = group_key or None
    origin, batch_id = _origin(scope)
    alert_id, is_new = await upsert_alert(
        conn, rule=rule, group_key=group_key, source_ip=source_ip,
        first_time=first["event_time"], last_time=last["event_time"], evidence=evidence,
        signals=_signals(alert_spec), merge_minutes=merge_minutes,
        title=render_title(alert_spec.get("title"), title_values, rule["title"]),
        origin=origin, batch_id=batch_id,
    )
    await link_events(conn, rule["id"], alert_id, event_ids)
    return int(is_new)


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

def _aggregate_parts(definition: dict, add: Params, time_sql: str):
    """(group expression, count expression, WHERE conditions, comparison)."""
    aggregate = definition["aggregate"]
    group_col = field_sql(aggregate["group_by"], "e", add)
    where = [time_sql, f"{group_col} IS NOT NULL"]
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
    comparison = ">" if aggregate["op"] == "gt" else ">="
    return group_col, count_expr, where, comparison


def _values_expr(alert_spec: dict, add: Params) -> str:
    values_field = alert_spec.get("values_field")
    if not values_field:
        return "NULL"
    return f"(array_agg(DISTINCT {field_sql(values_field, 'e', add)}))[1:{MAX_EVIDENCE_VALUES}]"


async def _evaluate_aggregate(conn, rule, definition: dict) -> int:
    aggregate = definition["aggregate"]
    alert_spec = definition.get("alert", {})
    add = Params()
    time_sql = f"e.event_time >= now() - make_interval(mins => {add(aggregate['window_minutes'])})"
    group_col, count_expr, where, comparison = _aggregate_parts(definition, add, time_sql)
    values_expr = _values_expr(alert_spec, add)

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
        created += await _alert_on_aggregate(
            conn, rule, definition, row["group_value"], row["cnt"], row["agg_values"],
            row["event_ids"], row["first_seen"], row["last_seen"], None,
        )
    return created


async def _evaluate_aggregate_range(conn, rule, definition: dict, scope: Scope) -> int:
    """Finds every burst in the range, with a window that slides rather than
    fixed buckets, so a burst split across a bucket edge is still caught.

    Each event (for count) or each run of one distinct value (for distinct) is
    "active" for window_minutes from when it happened. Sweeping those start and
    end edges in time order gives the number active at every moment; the
    moments at or over the threshold, merged when they're within a window of
    each other, are the bursts. One sort per group, rather than a count per event.
    """
    aggregate = definition["aggregate"]
    alert_spec = definition.get("alert", {})
    add = Params()
    window = add(aggregate["window_minutes"])
    time_from, time_to = add(scope.time_from), add(scope.time_to)
    scoped_time = _scope_sql("e", add, scope, f"{time_from}::timestamptz - make_interval(mins => {window})", time_to)
    group_col, _, where, comparison = _aggregate_parts(definition, add, scoped_time)
    distinct_col = (
        field_sql(aggregate["distinct_field"], "e", add) if aggregate["function"] == "distinct" else "e.id"
    )

    episodes = await conn.fetch(
        f"""
        WITH scoped AS (
            SELECT e.id, e.event_time, {group_col} AS g, {distinct_col} AS d
            FROM events e
            WHERE {' AND '.join(where)}
        ),
        occurrences AS (
            SELECT id, g, d, event_time,
                   lag(event_time) OVER (PARTITION BY g, d ORDER BY event_time, id) AS previous
            FROM scoped
        ),
        runs AS (
            SELECT g, d, event_time,
                   SUM(CASE WHEN previous IS NULL OR previous <= event_time - make_interval(mins => {window})
                            THEN 1 ELSE 0 END)
                       OVER (PARTITION BY g, d ORDER BY event_time, id ROWS UNBOUNDED PRECEDING) AS run
            FROM occurrences
        ),
        spans AS (
            SELECT g, min(event_time) AS starts, max(event_time) + make_interval(mins => {window}) AS ends
            FROM runs
            GROUP BY g, d, run
        ),
        edges AS (
            SELECT g, starts AS t, 1 AS delta FROM spans
            UNION ALL
            SELECT g, ends AS t, -1 AS delta FROM spans
        ),
        sweep AS (
            SELECT g, t, delta,
                   SUM(delta) OVER (PARTITION BY g ORDER BY t, delta ROWS UNBOUNDED PRECEDING) AS active
            FROM edges
        ),
        crossings AS (
            SELECT g, t, active, lag(t) OVER (PARTITION BY g ORDER BY t) AS previous_t
            FROM sweep
            WHERE delta = 1 AND active {comparison} {add(aggregate['threshold'])}
              AND t >= {time_from} AND t <= {time_to}
        ),
        episodes AS (
            SELECT g, t, active,
                   SUM(CASE WHEN previous_t IS NULL OR t - previous_t > make_interval(mins => {window})
                            THEN 1 ELSE 0 END)
                       OVER (PARTITION BY g ORDER BY t ROWS UNBOUNDED PRECEDING) AS episode
            FROM crossings
        )
        SELECT g AS group_value, min(t) AS crossed_at, max(t) AS last_crossing, max(active) AS peak
        FROM episodes
        GROUP BY g, episode
        ORDER BY min(t)
        LIMIT {add(MAX_EPISODES_PER_RULE)}
        """,
        *add.values,
    )

    created = 0
    for episode in episodes:
        # The events behind this burst: its group, from one window before it
        # first crossed the threshold to the last moment it was over it.
        e_add = Params()
        start = f"{e_add(episode['crossed_at'])}::timestamptz - make_interval(mins => {e_add(aggregate['window_minutes'])})"
        e_group, _, e_where, _ = _aggregate_parts(
            definition, e_add, _scope_sql("e", e_add, scope, start, e_add(episode["last_crossing"]))
        )
        e_where.append(f"{e_group} = {e_add(episode['group_value'])}")
        values_expr = _values_expr(alert_spec, e_add)
        row = await conn.fetchrow(
            f"""
            SELECT {values_expr} AS agg_values,
                   (array_agg(e.id ORDER BY e.event_time))[1:{MAX_EVIDENCE_VALUES}] AS event_ids,
                   min(e.event_time) AS first_seen, max(e.event_time) AS last_seen
            FROM events e
            WHERE {' AND '.join(e_where)}
            """,
            *e_add.values,
        )
        created += await _alert_on_aggregate(
            conn, rule, definition, episode["group_value"], episode["peak"], row["agg_values"],
            row["event_ids"], row["first_seen"], row["last_seen"], scope,
        )
    return created


async def _alert_on_aggregate(conn, rule, definition, group_value, count, agg_values, event_ids,
                              first_seen, last_seen, scope) -> int:
    aggregate = definition["aggregate"]
    alert_spec = definition.get("alert", {})
    group_by = aggregate["group_by"]
    group_text = _text(group_value)
    source_ip = group_text if group_by == "source_ip" else None
    evidence: dict = {alert_spec.get("count_key") or "count": count}
    if alert_spec.get("values_field"):
        evidence[alert_spec.get("values_key") or "values"] = [_json_value(v) for v in agg_values or []]
    if group_by != "source_ip":
        evidence[group_by] = group_text
    evidence.update({
        "event_ids": list(event_ids or []),
        "first_seen": iso(first_seen),
        "last_seen": iso(last_seen),
    })
    title_values = {group_by: group_text, "group": group_text, "count": count, "source_ip": source_ip}
    origin, batch_id = _origin(scope)
    _, is_new = await upsert_alert(
        conn, rule=rule, group_key=group_text, source_ip=source_ip,
        first_time=first_seen, last_time=last_seen, evidence=evidence,
        signals=_signals(alert_spec), merge_minutes=aggregate["window_minutes"],
        title=render_title(alert_spec.get("title"), title_values, rule["title"]),
        origin=origin, batch_id=batch_id,
    )
    return int(is_new)


# --- sequence ---------------------------------------------------------------------

def _sequence_query(definition: dict, add: Params, lookback_minutes: int, rule_id: int | None, limit: int,
                    newest_first: bool = False, scope: Scope | None = None) -> str:
    """The "then" events that complete a sequence. Over an upload's scope, the
    "then" event must be in the upload; the "first" events can come from anywhere."""
    sequence = definition["sequence"]
    first, then = sequence["first"], sequence["then"]
    join_on = sequence["join_on"]

    join_then = field_sql(join_on, "t", add)
    join_first = field_sql(join_on, "f", add)
    then_sql, _ = compile_condition(then["filter"], add, "t")
    first_sql, _ = compile_condition(first["filter"], add, "f")
    logsource_then = logsource_first = ""
    if definition.get("logsource"):
        logsource_then = f" AND t.source_type = ANY({add(definition['logsource'], 'text[]')})"
        logsource_first = f" AND f.source_type = ANY({add(definition['logsource'], 'text[]')})"
    already_alerted = (
        f" AND NOT EXISTS (SELECT 1 FROM alert_events ae WHERE ae.rule_id = {add(rule_id)} AND ae.event_id = t.id)"
        if rule_id is not None else ""
    )
    order = "DESC" if newest_first else "ASC"

    return f"""
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
        WHERE {_time_bounds("t", add, scope, lookback_minutes)}
          AND {join_then} IS NOT NULL
          AND {then_sql}{logsource_then}
          AND prior.cnt >= {add(first['min_count'])}
          AND prior.last_first >= t.event_time - make_interval(mins => {add(then['within_minutes'])}){already_alerted}
        ORDER BY t.event_time {order}, t.id {order}
        LIMIT {add(limit)}
    """


async def _evaluate_sequence(conn, rule, definition: dict, scope: Scope | None) -> int:
    sequence = definition["sequence"]
    gap_minutes = sequence["first"]["within_minutes"] + sequence["then"]["within_minutes"]
    created = 0
    for _ in range(MAX_RANGE_PASSES if scope else 1):
        add = Params()
        rows = await conn.fetch(
            _sequence_query(definition, add, LOOKBACK_MINUTES, rule["id"], MAX_HITS_PER_RUN, scope=scope), *add.values
        )
        groups: dict[str, list] = {}
        for row in rows:
            groups.setdefault(_text(row["join_value"]), []).append(row)
        for join_value, group_rows in groups.items():
            for hits in _clusters(group_rows, gap_minutes):
                created += await _alert_on_sequence(conn, rule, definition, join_value, hits, gap_minutes, scope)
        if len(rows) < MAX_HITS_PER_RUN:
            break
    return created


async def _alert_on_sequence(conn, rule, definition, join_value, hits, merge_minutes, scope) -> int:
    alert_spec = definition.get("alert", {})
    join_on = definition["sequence"]["join_on"]
    last = hits[-1]
    prior_ids: list[int] = []
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
    origin, batch_id = _origin(scope)
    alert_id, is_new = await upsert_alert(
        conn, rule=rule, group_key=join_value, source_ip=source_ip,
        first_time=first_seen, last_time=last["event_time"], evidence=evidence,
        signals=_signals(alert_spec), merge_minutes=merge_minutes,
        title=render_title(alert_spec.get("title"), title_values, rule["title"]),
        origin=origin, batch_id=batch_id,
    )
    await link_events(conn, rule["id"], alert_id, then_ids)
    return int(is_new)


# --- preview ----------------------------------------------------------------------

async def preview_rule(conn, definition: dict, rule_type: str, hours: int) -> dict:
    """What a validated definition would have matched over the last `hours`,
    without writing anything. Raises asyncpg.QueryCanceledError past PREVIEW_TIMEOUT."""
    lookback = hours * 60
    async with conn.transaction():
        await conn.execute(f"SET LOCAL statement_timeout = '{PREVIEW_TIMEOUT}'")
        if rule_type == "threshold":
            result = await _preview_aggregate(conn, definition, lookback)
        elif rule_type == "sequence":
            result = await _preview_sequence(conn, definition, lookback)
        else:
            result = await _preview_match(conn, definition, lookback)
    return {"rule_type": rule_type, "hours": hours, **result}


async def _preview_match(conn, definition: dict, lookback: int) -> dict:
    add = Params()
    where, _ = _match_filter(definition, add, lookback, None)
    counts = await conn.fetchrow(
        f"SELECT count(*) AS matches, count(DISTINCT e.source_ip) AS groups FROM events e WHERE {where}",
        *add.values,
    )

    add = Params()
    where, leaves = _match_filter(definition, add, lookback, None)
    rows = await conn.fetch(
        f"""
        SELECT e.id, e.event_time, e.source_ip{_leaf_columns(leaves)}
        FROM events e WHERE {where}
        ORDER BY e.event_time DESC, e.id DESC
        LIMIT {add(PREVIEW_SAMPLES)}
        """,
        *add.values,
    )
    samples = []
    for row in rows:
        _, _, snippet = _match_evidence(leaves, [row])
        ip = _text(row["source_ip"])
        samples.append({"time": row["event_time"], "group": ip, "source_ip": ip, "event_id": row["id"], "detail": snippet})
    return {"matches": counts["matches"], "groups": counts["groups"], "truncated": False, "samples": samples}


async def _preview_aggregate(conn, definition: dict, lookback: int) -> dict:
    """Counted in fixed windows (00:00-00:05, 00:05-00:10, ...), so a burst that
    straddles two windows can be missed here even though live detection, which
    looks back from each run, would catch it."""
    aggregate = definition["aggregate"]
    add = Params()
    time_sql = f"e.event_time >= now() - make_interval(mins => {add(lookback)})"
    group_col, count_expr, where, comparison = _aggregate_parts(definition, add, time_sql)
    window = add(aggregate["window_minutes"])
    rows = await conn.fetch(
        f"""
        SELECT {group_col} AS group_value,
               date_bin(make_interval(mins => {window}), e.event_time, TIMESTAMPTZ '2000-01-01') AS bucket,
               {count_expr} AS cnt, min(e.event_time) AS first_seen
        FROM events e
        WHERE {' AND '.join(where)}
        GROUP BY 1, 2
        HAVING {count_expr} {comparison} {add(aggregate['threshold'])}
        ORDER BY 2 DESC
        LIMIT {add(PREVIEW_ROW_CAP)}
        """,
        *add.values,
    )
    noun = f"distinct {aggregate['distinct_field']} values" if aggregate["function"] == "distinct" else "events"
    samples = [
        {
            "time": row["first_seen"], "group": _text(row["group_value"]),
            "source_ip": _text(row["group_value"]) if aggregate["group_by"] == "source_ip" else None,
            "event_id": None, "detail": f"{row['cnt']} {noun} in {aggregate['window_minutes']} min",
        }
        for row in rows[:PREVIEW_SAMPLES]
    ]
    return {
        "matches": len(rows), "groups": len({row["group_value"] for row in rows}),
        "truncated": len(rows) == PREVIEW_ROW_CAP, "samples": samples,
    }


async def _preview_sequence(conn, definition: dict, lookback: int) -> dict:
    join_on = definition["sequence"]["join_on"]
    add = Params()
    rows = await conn.fetch(
        _sequence_query(definition, add, lookback, None, PREVIEW_ROW_CAP, newest_first=True), *add.values
    )
    samples = [
        {
            "time": row["event_time"], "group": _text(row["join_value"]),
            "source_ip": _text(row["join_value"]) if join_on == "source_ip" else None,
            "event_id": row["id"], "detail": f"{row['cnt']} earlier matching events, then this one",
        }
        for row in rows[:PREVIEW_SAMPLES]
    ]
    return {
        "matches": len(rows), "groups": len({row["join_value"] for row in rows}),
        "truncated": len(rows) == PREVIEW_ROW_CAP, "samples": samples,
    }


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
