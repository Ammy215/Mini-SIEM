import json
from datetime import datetime, timezone

_KNOWN_FIELDS = {
    "source_ip", "dest_ip", "dest_port", "username", "action",
    "status_code", "method", "url", "user_agent", "country",
}


def parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None

    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(obj, dict):
        return None

    event_time = datetime.now(timezone.utc)
    if "event_time" in obj:
        try:
            event_time = datetime.fromisoformat(str(obj["event_time"]))
        except ValueError:
            pass

    event = {"event_time": event_time, "source_type": "app", "raw_message": obj.get("message", line), "raw": obj}
    for field in _KNOWN_FIELDS:
        if field in obj:
            event[field] = obj[field]

    return event
