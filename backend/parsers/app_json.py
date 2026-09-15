import json
from datetime import datetime, timezone

from parsers.fields import extract_fields, extract_time

# Mini SIEM's own event field names. When a line uses them, the values are
# taken as given and validated strictly, so a wrong value fails that line.
_KNOWN_FIELDS = {
    "source_ip", "dest_ip", "dest_port", "src_port", "username", "action", "outcome",
    "status_code", "method", "url", "user_agent", "country", "host", "event_code", "protocol",
}


def reject_json_constant(name: str):
    # Python's json accepts NaN and Infinity; PostgreSQL's jsonb doesn't.
    raise ValueError(f"{name} is not valid JSON")


def parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line.startswith("{"):
        return None

    try:
        obj = json.loads(line, parse_constant=reject_json_constant)
    except ValueError:  # includes JSONDecodeError
        return None

    if not isinstance(obj, dict):
        return None
    return parse_object(obj, line)


def parse_object(obj: dict, raw_line: str) -> dict:
    """An event from one JSON object — a line of JSON lines, or one item of a JSON array."""
    event = {
        "event_time": extract_time(obj) or datetime.now(timezone.utc),
        "source_type": "app",
        "raw_message": obj.get("message", raw_line),
        "raw": obj,
    }
    for field in _KNOWN_FIELDS:
        if field in obj:
            event[field] = obj[field]

    # Other tools' names for the same things (src_ip, user, @timestamp, ...)
    # fill in only what the line didn't already set under Mini SIEM's own names.
    for field, value in extract_fields(obj).items():
        event.setdefault(field, value)

    return event
