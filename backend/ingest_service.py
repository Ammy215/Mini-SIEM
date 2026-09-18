"""Storing normalised events: shared by the ingest API, file uploads and the
live syslog listener."""

import json
from datetime import datetime, timezone
from uuid import UUID

from parsers.urls import decode_url

INSERT_CHUNK = 1000

_INSERT_SQL = """
    INSERT INTO events (
        event_time, source_type, source_ip, dest_ip, dest_port, username, action, status_code,
        method, url, user_agent, country, raw_message, raw,
        host, event_code, outcome, protocol, src_port, parser, batch_id
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb,
              $15, $16, $17, $18, $19, $20, $21)
"""


def _normalised_url(event: dict) -> tuple[str | None, dict | None]:
    """A URL is stored percent-decoded whichever door it came in by.

    The nginx parser has always decoded what it parses, but an agent posting a
    structured event to /api/ingest sends the URL as it went over the wire —
    and that is exactly the form an attacker uses. Left encoded, `%27%20OR%201%3D1`
    matched no signature rule, so SQLi, XSS and traversal pushed through the
    ingest API went undetected. Decoding here covers every write path at once.

    The wire form is kept in `raw.url_raw`, as the parser already does, so
    nothing an analyst might need is thrown away.
    """
    url = event.get("url")
    raw = event.get("raw")
    if not url:
        return url, raw
    decoded = decode_url(url)
    if decoded == url:
        return url, raw
    return decoded, {**raw, "url_raw": url} if raw is not None else {"url_raw": url}


def _event_to_row(event: dict, batch_id: UUID | None) -> tuple:
    url, raw = _normalised_url(event)
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
        url,
        event.get("user_agent"),
        event.get("country"),
        event.get("raw_message"),
        json.dumps(raw) if raw is not None else None,
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
