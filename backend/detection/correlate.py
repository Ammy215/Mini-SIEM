import logging

from detection.scorer import max_severity

logger = logging.getLogger(__name__)

CORRELATION_WINDOW_MINUTES = 60


async def _find_open_incident(conn, source_ip: str, first_time, last_time):
    return await conn.fetchrow(
        """
        SELECT id, severity
        FROM incidents
        WHERE source_ip = $1::inet AND status = 'open'
          AND last_seen >= $2::timestamptz - make_interval(mins => $4)
          AND first_seen <= $3::timestamptz + make_interval(mins => $4)
        ORDER BY last_seen DESC
        LIMIT 1
        """,
        source_ip, first_time, last_time, CORRELATION_WINDOW_MINUTES,
    )


async def _create_incident(conn, *, title, source_ip, severity, first_time, last_time) -> int:
    row = await conn.fetchrow(
        """
        INSERT INTO incidents (title, source_ip, severity, status, alert_count, first_seen, last_seen)
        VALUES ($1, $2::inet, $3, 'open', 1, $4, $5)
        RETURNING id
        """,
        title, source_ip, severity, first_time, last_time,
    )
    return row["id"]


async def _join_incident(conn, incident_id: int, *, severity: str, first_time, last_time) -> None:
    await conn.execute(
        """
        UPDATE incidents
        SET alert_count = alert_count + 1,
            severity = $2,
            first_seen = LEAST(first_seen, $3),
            last_seen = GREATEST(last_seen, $4)
        WHERE id = $1
        """,
        incident_id, severity, first_time, last_time,
    )


async def _link_alert(conn, alert_id: int, incident_id: int) -> None:
    await conn.execute("UPDATE alerts SET incident_id = $1 WHERE id = $2", incident_id, alert_id)


# An incident's severity, timeline and alert count are derived facts about the
# alerts linked to it — not analyst decisions (only `status` is that). They were
# previously written once, when an alert joined, so later changes to the same
# alert drifted: enrichment escalates an alert's severity after correlation ran,
# and a repeat hit extends its last_event_time when it merges into the open
# alert. Both left the Incidents page disagreeing with the alert it came from.
# Recomputing them every pass makes the incident follow its alerts instead.
_REFRESH_SQL = """
    WITH derived AS (
        SELECT incident_id AS id,
               COUNT(*)::int AS alert_count,
               MIN(COALESCE(first_event_time, created_at)) AS first_seen,
               MAX(COALESCE(last_event_time, created_at)) AS last_seen,
               MAX(CASE severity
                       WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                       WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS severity_rank
        FROM alerts
        WHERE incident_id IS NOT NULL
        GROUP BY incident_id
    ), target AS (
        SELECT id, alert_count, first_seen, last_seen,
               CASE severity_rank
                   WHEN 4 THEN 'critical' WHEN 3 THEN 'high'
                   WHEN 2 THEN 'medium' WHEN 1 THEN 'low' END AS severity
        FROM derived
    )
    UPDATE incidents i
    SET alert_count = t.alert_count,
        first_seen = t.first_seen,
        last_seen = t.last_seen,
        severity = COALESCE(t.severity, i.severity)
    FROM target t
    WHERE i.id = t.id
      AND (i.alert_count IS DISTINCT FROM t.alert_count
           OR i.first_seen IS DISTINCT FROM t.first_seen
           OR i.last_seen IS DISTINCT FROM t.last_seen
           OR i.severity IS DISTINCT FROM COALESCE(t.severity, i.severity))
    RETURNING i.id
"""


async def refresh_incidents(conn) -> int:
    """Recomputes every incident from its linked alerts. Returns rows changed."""
    rows = await conn.fetch(_REFRESH_SQL)
    return len(rows)


async def run_all(conn) -> dict[str, int]:
    # Alerts are placed on the timeline by when their events happened. Alerts
    # written without event times (older rows, hand-inserted ones) fall back to
    # when the alert was created.
    rows = await conn.fetch(
        """
        SELECT id, title, source_ip, severity, evidence->>'username' AS spray_username,
               evidence ? 'distinct_ips' AS is_spray,
               COALESCE(first_event_time, created_at) AS first_time,
               COALESCE(last_event_time, created_at) AS last_time
        FROM alerts
        WHERE incident_id IS NULL
        ORDER BY COALESCE(first_event_time, created_at) ASC, id ASC
        """
    )

    incidents_created = 0
    alerts_joined = 0

    for row in rows:
        source_ip = str(row["source_ip"]) if row["source_ip"] else None
        severity = row["severity"]
        first_time, last_time = row["first_time"], row["last_time"]

        if source_ip is None:
            # Nothing to group on without an attacker IP, so the alert stands
            # as its own incident: a password spray (many IPs, one user), or a
            # host-level finding such as a cleared Windows event log.
            username = row["spray_username"]
            if row["is_spray"]:
                title = f"Password spray campaign targeting '{username}'" if username else "Password spray campaign"
            else:
                title = row["title"]
            incident_id = await _create_incident(
                conn, title=title, source_ip=None, severity=severity, first_time=first_time, last_time=last_time
            )
            await _link_alert(conn, row["id"], incident_id)
            incidents_created += 1
            continue

        existing = await _find_open_incident(conn, source_ip, first_time, last_time)
        if existing:
            new_severity = max_severity(existing["severity"], severity)
            await _join_incident(
                conn, existing["id"], severity=new_severity, first_time=first_time, last_time=last_time
            )
            await _link_alert(conn, row["id"], existing["id"])
            alerts_joined += 1
        else:
            title = f"Attack campaign from {source_ip}"
            incident_id = await _create_incident(
                conn, title=title, source_ip=source_ip, severity=severity, first_time=first_time, last_time=last_time
            )
            await _link_alert(conn, row["id"], incident_id)
            incidents_created += 1

    incidents_refreshed = await refresh_incidents(conn)

    return {
        "incidents_created": incidents_created,
        "alerts_joined": alerts_joined,
        "incidents_refreshed": incidents_refreshed,
    }
