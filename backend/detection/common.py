import json


async def insert_alert(conn, *, rule_id, title, mitre_technique, source_ip, threat_score, severity, evidence) -> None:
    await conn.execute(
        """
        INSERT INTO alerts (rule_id, title, severity, mitre_technique, source_ip, threat_score, status, evidence)
        VALUES ($1, $2, $3, $4, $5, $6, 'open', $7::jsonb)
        """,
        rule_id, title, severity, mitre_technique, source_ip, threat_score, json.dumps(evidence),
    )


def iso(dt) -> str | None:
    return dt.isoformat() if dt is not None else None
