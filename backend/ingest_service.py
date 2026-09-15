"""Storing normalised events: shared by the ingest API, file uploads and the
live syslog listener."""

import json
from datetime import datetime, timezone
from uuid import UUID

INSERT_CHUNK = 1000

_INSERT_SQL = """
    INSERT INTO events (
        event_time, source_type, source_ip, dest_ip, dest_port, username, action, status_code,
        method, url, user_agent, country, raw_message, raw,
        host, event_code, outcome, protocol, src_port, parser, batch_id
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb,
              $15, $16, $17, $18, $19, $20, $21)
"""


def _event_to_row(event: dict, batch_id: UUID | None) -> tuple:
    return (
        event.get("event_time") or datetime.now(timezone.utc),
        event["source_type"],
        event.get("source_ip"),
        event.get("dest_ip"),
        event.get("dest_port"),
        event.get("username"),
        event.get("action"),
        event.get("status_code"),
        event.get("method"),
        event.get("url"),
        event.get("user_agent"),
        event.get("country"),
        event.get("raw_message"),
        json.dumps(event["raw"]) if event.get("raw") is not None else None,
        event.get("host"),
        event.get("event_code"),
        event.get("outcome"),
        event.get("protocol"),
        event.get("src_port"),
        event.get("parser"),
        batch_id,
    )


async def insert_events(conn, events: list[dict], batch_id: UUID | None = None) -> int:
    """Inserts already-validated events. Returns how many were stored."""
    rows = [_event_to_row(event, batch_id) for event in events]
    for start in range(0, len(rows), INSERT_CHUNK):
        await conn.executemany(_INSERT_SQL, rows[start:start + INSERT_CHUNK])
    return len(rows)
