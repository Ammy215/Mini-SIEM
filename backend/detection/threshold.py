import json
import logging

from detection.scorer import score_alert

logger = logging.getLogger(__name__)

SEED_DEFS = [
    {
        "rule_key": "brute_force",
        "title": "Brute Force Login Attempts",
        "description": "More than 10 failed login attempts from a single source IP within 5 minutes.",
        "severity": "high",
        "mitre_technique": "T1110",
        "definition": {
            "window_minutes": 5, "threshold": 10, "comparison": "gt",
            "group_by": "source_ip", "action_filter": "login_failed",
        },
    },
    {
        "rule_key": "credential_stuffing",
        "title": "Credential Stuffing",
        "description": "5 or more distinct usernames attempted from a single source IP within 10 minutes.",
        "severity": "high",
        "mitre_technique": "T1110.004",
        "definition": {
            "window_minutes": 10, "threshold": 5, "comparison": "gte",
            "group_by": "source_ip", "action_filter": "login_failed",
        },
    },
    {
        "rule_key": "port_scan",
        "title": "Port Scan",
        "description": "15 or more distinct destination ports touched by a single source IP within 5 minutes.",
        "severity": "medium",
        "mitre_technique": "T1046",
        "definition": {
            "window_minutes": 5, "threshold": 15, "comparison": "gte",
            "group_by": "source_ip", "action_filter": None,
        },
    },
    {
        "rule_key": "password_spray",
        "title": "Password Spray",
        "description": "One username targeted from 5 or more distinct source IPs within 10 minutes.",
        "severity": "high",
        "mitre_technique": "T1110.003",
        "definition": {
            "window_minutes": 10, "threshold": 5, "comparison": "gte",
            "group_by": "username", "action_filter": "login_failed",
        },
    },
]

_SEED_SQL = """
    INSERT INTO rules (rule_key, title, description, rule_type, severity, mitre_technique, definition, enabled)
    VALUES ($1, $2, $3, 'threshold', $4, $5, $6::jsonb, TRUE)
    ON CONFLICT (rule_key) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        severity = EXCLUDED.severity,
        mitre_technique = EXCLUDED.mitre_technique,
        definition = EXCLUDED.definition
"""


async def seed_rules(conn) -> None:
    for rule in SEED_DEFS:
        await conn.execute(
            _SEED_SQL,
            rule["rule_key"], rule["title"], rule["description"],
            rule["severity"], rule["mitre_technique"], json.dumps(rule["definition"]),
        )


async def _is_suppressed(conn, rule_id: int, window_minutes: int, source_ip: str | None, username: str | None) -> bool:
    row = await conn.fetchrow(
        """
        SELECT id FROM alerts
        WHERE rule_id = $1 AND status = 'open'
          AND created_at >= now() - make_interval(mins => $2)
          AND (
            ($3::inet IS NOT NULL AND source_ip = $3::inet)
            OR ($4::text IS NOT NULL AND evidence->>'username' = $4)
          )
        LIMIT 1
        """,
        rule_id, window_minutes, source_ip, username,
    )
    return row is not None


async def _insert_alert(conn, *, rule_id, title, mitre_technique, source_ip, threat_score, severity, evidence) -> None:
    await conn.execute(
        """
        INSERT INTO alerts (rule_id, title, severity, mitre_technique, source_ip, threat_score, status, evidence)
        VALUES ($1, $2, $3, $4, $5, $6, 'open', $7::jsonb)
        """,
        rule_id, title, severity, mitre_technique, source_ip, threat_score, json.dumps(evidence),
    )


def _iso(dt) -> str | None:
    return dt.isoformat() if dt is not None else None


async def _evaluate_brute_force(conn, rule) -> int:
    d = rule["def"]
    rows = await conn.fetch(
        """
        SELECT source_ip, COUNT(*) AS cnt, array_agg(DISTINCT username) AS usernames,
               array_agg(id ORDER BY event_time) AS event_ids,
               min(event_time) AS first_seen, max(event_time) AS last_seen
        FROM events
        WHERE event_time >= now() - make_interval(mins => $1)
          AND action = 'login_failed' AND source_ip IS NOT NULL
        GROUP BY source_ip
        HAVING COUNT(*) > $2
        """,
        d["window_minutes"], d["threshold"],
    )

    created = 0
    for row in rows:
        source_ip = str(row["source_ip"])
        if await _is_suppressed(conn, rule["id"], d["window_minutes"], source_ip, None):
            continue
        score, severity = score_alert(["brute_force_confirmed"])
        await _insert_alert(
            conn, rule_id=rule["id"], title=f"Brute force login attempts from {source_ip}",
            mitre_technique=rule["mitre_technique"], source_ip=source_ip, threat_score=score, severity=severity,
            evidence={
                "failed_count": row["cnt"], "usernames": row["usernames"], "event_ids": row["event_ids"],
                "first_seen": _iso(row["first_seen"]), "last_seen": _iso(row["last_seen"]),
            },
        )
        created += 1
    return created


async def _evaluate_credential_stuffing(conn, rule) -> int:
    d = rule["def"]
    rows = await conn.fetch(
        """
        SELECT source_ip, COUNT(DISTINCT username) AS cnt, array_agg(DISTINCT username) AS usernames,
               array_agg(id ORDER BY event_time) AS event_ids,
               min(event_time) AS first_seen, max(event_time) AS last_seen
        FROM events
        WHERE event_time >= now() - make_interval(mins => $1)
          AND action = 'login_failed' AND source_ip IS NOT NULL AND username IS NOT NULL
        GROUP BY source_ip
        HAVING COUNT(DISTINCT username) >= $2
        """,
        d["window_minutes"], d["threshold"],
    )

    created = 0
    for row in rows:
        source_ip = str(row["source_ip"])
        if await _is_suppressed(conn, rule["id"], d["window_minutes"], source_ip, None):
            continue
        score, severity = score_alert(["credential_stuffing"])
        await _insert_alert(
            conn, rule_id=rule["id"], title=f"Credential stuffing from {source_ip}",
            mitre_technique=rule["mitre_technique"], source_ip=source_ip, threat_score=score, severity=severity,
            evidence={
                "distinct_usernames": row["cnt"], "usernames": row["usernames"], "event_ids": row["event_ids"],
                "first_seen": _iso(row["first_seen"]), "last_seen": _iso(row["last_seen"]),
            },
        )
        created += 1
    return created


async def _evaluate_port_scan(conn, rule) -> int:
    d = rule["def"]
    rows = await conn.fetch(
        """
        SELECT source_ip, COUNT(DISTINCT dest_port) AS cnt, array_agg(DISTINCT dest_port) AS ports,
               array_agg(id ORDER BY event_time) AS event_ids,
               min(event_time) AS first_seen, max(event_time) AS last_seen
        FROM events
        WHERE event_time >= now() - make_interval(mins => $1)
          AND dest_port IS NOT NULL AND source_ip IS NOT NULL
        GROUP BY source_ip
        HAVING COUNT(DISTINCT dest_port) >= $2
        """,
        d["window_minutes"], d["threshold"],
    )

    created = 0
    for row in rows:
        source_ip = str(row["source_ip"])
        if await _is_suppressed(conn, rule["id"], d["window_minutes"], source_ip, None):
            continue
        score, severity = score_alert(["port_scan"])
        await _insert_alert(
            conn, rule_id=rule["id"], title=f"Port scan from {source_ip}",
            mitre_technique=rule["mitre_technique"], source_ip=source_ip, threat_score=score, severity=severity,
            evidence={
                "distinct_ports": row["cnt"], "ports": row["ports"], "event_ids": row["event_ids"],
                "first_seen": _iso(row["first_seen"]), "last_seen": _iso(row["last_seen"]),
            },
        )
        created += 1
    return created


async def _evaluate_password_spray(conn, rule) -> int:
    d = rule["def"]
    rows = await conn.fetch(
        """
        SELECT username, COUNT(DISTINCT source_ip) AS cnt, array_agg(DISTINCT source_ip) AS source_ips,
               array_agg(id ORDER BY event_time) AS event_ids,
               min(event_time) AS first_seen, max(event_time) AS last_seen
        FROM events
        WHERE event_time >= now() - make_interval(mins => $1)
          AND action = 'login_failed' AND username IS NOT NULL AND source_ip IS NOT NULL
        GROUP BY username
        HAVING COUNT(DISTINCT source_ip) >= $2
        """,
        d["window_minutes"], d["threshold"],
    )

    created = 0
    for row in rows:
        username = row["username"]
        if await _is_suppressed(conn, rule["id"], d["window_minutes"], None, username):
            continue
        score, severity = score_alert(["password_spray_confirmed"])
        await _insert_alert(
            conn, rule_id=rule["id"], title=f"Password spray against user '{username}'",
            mitre_technique=rule["mitre_technique"], source_ip=None, threat_score=score, severity=severity,
            evidence={
                "username": username, "distinct_ips": row["cnt"],
                "source_ips": [str(ip) for ip in row["source_ips"]], "event_ids": row["event_ids"],
                "first_seen": _iso(row["first_seen"]), "last_seen": _iso(row["last_seen"]),
            },
        )
        created += 1
    return created


_EVALUATORS = {
    "brute_force": _evaluate_brute_force,
    "credential_stuffing": _evaluate_credential_stuffing,
    "port_scan": _evaluate_port_scan,
    "password_spray": _evaluate_password_spray,
}


async def run_all(conn) -> dict[str, int]:
    rows = await conn.fetch("SELECT * FROM rules WHERE rule_type = 'threshold' AND enabled = TRUE")

    results: dict[str, int] = {}
    for row in rows:
        rule_key = row["rule_key"]
        evaluator = _EVALUATORS.get(rule_key)
        if evaluator is None:
            continue
        rule = {
            "id": row["id"],
            "mitre_technique": row["mitre_technique"],
            "def": json.loads(row["definition"]),
        }
        try:
            results[rule_key] = await evaluator(conn, rule)
        except Exception:
            logger.exception("threshold evaluator failed for rule_key=%s", rule_key)
            results[rule_key] = 0

    return results
