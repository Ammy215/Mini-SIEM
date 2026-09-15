"""Maps the field names other tools use onto Mini SIEM's event fields.

JSON, key=value and CSV logs from different products name the same thing
differently — src, srcip, client_ip, remote_addr. Each alias list is checked in
order and the first usable value wins. A value that doesn't fit its field (an
invalid IP, a port of 99999) is left out of that field instead of failing the
whole line; the original is always still in `raw`.
"""

import ipaddress
from datetime import datetime, timezone

from models.events import MAX_LENGTHS
from parsers.timeutil import parse_flexible

ALIASES: dict[str, tuple[str, ...]] = {
    "source_ip": ("source_ip", "src_ip", "srcip", "src", "source_address", "client_ip", "clientip",
                  "remote_addr", "remote_ip", "ip"),
    "dest_ip": ("dest_ip", "dst_ip", "dstip", "dst", "destination_ip", "destination_address", "server_ip"),
    "src_port": ("src_port", "srcport", "source_port", "spt", "sport"),
    "dest_port": ("dest_port", "dst_port", "dstport", "dpt", "dport", "destination_port"),
    "username": ("username", "user", "user_name", "account", "login"),
    "action": ("action", "act", "event_type", "event", "activity"),
    "outcome": ("outcome", "result", "status"),
    "status_code": ("status_code", "http_status", "response_code", "status"),
    "method": ("method", "http_method", "request_method"),
    "url": ("url", "uri", "request_uri", "path"),
    "user_agent": ("user_agent", "useragent", "http_user_agent", "ua"),
    "host": ("host", "hostname", "devname", "device", "computer"),
    "protocol": ("protocol", "proto"),
    "event_code": ("event_code", "event_id", "eventid", "logid"),
    "country": ("country", "country_code"),
}

TIME_KEYS = ("event_time", "@timestamp", "timestamp", "time", "ts", "datetime", "eventtime", "created_at", "date")

_IP_FIELDS = {"source_ip", "dest_ip"}
_PORT_FIELDS = {"src_port", "dest_port"}
_OUTCOMES = {
    "success": "success", "succeeded": "success", "successful": "success", "ok": "success",
    "failure": "failure", "failed": "failure", "fail": "failure", "error": "failure",
    "unknown": "unknown",
}


def extract_fields(obj: dict) -> dict:
    lowered = _lowered(obj)
    fields = {}
    for field, aliases in ALIASES.items():
        for alias in aliases:
            value = _coerce(field, lowered.get(alias))
            if value is not None:
                fields[field] = value
                break
    return fields


def extract_time(obj: dict) -> datetime | None:
    lowered = _lowered(obj)
    # Fortinet and others split one timestamp across `date=` and `time=`.
    date, time = lowered.get("date"), lowered.get("time")
    if isinstance(date, str) and isinstance(time, str):
        combined = parse_flexible(f"{date.strip()}T{time.strip()}")
        if combined is not None:
            return combined
    for key in TIME_KEYS:
        parsed = parse_flexible(lowered.get(key))
        if parsed is not None:
            return parsed
    return None


def normalize(obj: dict, *, source_type: str, raw_message: str) -> dict:
    """An event built from a flat mapping of field names to values."""
    raw = {str(key): value for key, value in obj.items()}
    event_time = extract_time(obj)
    if event_time is None:
        event_time = datetime.now(timezone.utc)
        raw["_time_inferred"] = True
    return {
        "event_time": event_time,
        "source_type": source_type,
        "raw_message": raw_message,
        "raw": raw,
        **extract_fields(obj),
    }


def _lowered(obj: dict) -> dict:
    lowered = {}
    for key, value in obj.items():
        lowered.setdefault(str(key).strip().lower(), value)
    return lowered


def _coerce(field: str, value):
    if value is None or isinstance(value, bool):
        return None
    if field in _IP_FIELDS:
        try:
            return str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            return None
    if field in _PORT_FIELDS:
        return _int_between(value, 0, 65535)
    if field == "status_code":
        return _int_between(value, 100, 599)
    if field == "outcome":
        return _OUTCOMES.get(str(value).strip().lower())
    if isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    if not text or len(text) > MAX_LENGTHS.get(field, 256):
        return None
    return text


def _int_between(value, low: int, high: int) -> int | None:
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    elif isinstance(value, str) and value.strip().isdecimal():
        value = int(value.strip())
    return value if isinstance(value, int) and low <= value <= high else None
