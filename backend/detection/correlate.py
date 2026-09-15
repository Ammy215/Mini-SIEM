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


async def run_all(conn) -> dict[str, int]:
    # Alerts are placed on the timeline by when their events happened. Alerts
    # written without event times (older rows, hand-inserted ones) fall back to
    # when the alert was created.
    rows = await conn.fetch(
        """
        SELECT id, source_ip, severity, evidence->>'username' AS spray_username,
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
            username = row["spray_username"]
            title = f"Password spray campaign targeting '{username}'" if username else "Password spray campaign"
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

    return {"incidents_created": incidents_created, "alerts_joined": alerts_joined}
