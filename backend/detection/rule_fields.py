"""The event fields detection rules may use, and how each becomes SQL.

This whitelist is the only way a field name reaches SQL text. A `raw.<key>`
field reads the event's raw JSON; its key is always a bound parameter.
"""

import re

FIELD_TYPES: dict[str, str] = {
    "source_type": "text",
    "source_ip": "inet",
    "dest_ip": "inet",
    "dest_port": "int",
    "src_port": "int",
    "username": "text",
    "action": "text",
    "outcome": "text",
    "status_code": "int",
    "method": "text",
    "url": "text",
    "user_agent": "text",
    "country": "text",
    "host": "text",
    "event_code": "text",
    "protocol": "text",
    "raw_message": "text",
    "parser": "text",
}

OPERATORS: dict[str, tuple[str, ...]] = {
    "text": ("eq", "neq", "in", "contains", "contains_any", "startswith", "endswith", "regex", "exists"),
    "int": ("eq", "neq", "in", "gt", "gte", "lt", "lte", "exists"),
    "inet": ("eq", "in", "cidr", "exists"),
}

# Fields an aggregate can group by, or a sequence can join its steps on.
GROUP_FIELDS = ("source_ip", "username", "host", "dest_ip", "event_code")
JOIN_FIELDS = ("source_ip", "username", "host")

_RAW_KEY_RE = re.compile(r"raw\.([A-Za-z0-9_]{1,64})")


def field_type(name) -> str | None:
    if not isinstance(name, str):
        return None
    if name in FIELD_TYPES:
        return FIELD_TYPES[name]
    return "text" if _RAW_KEY_RE.fullmatch(name) else None


def field_sql(name: str, alias: str, add) -> str:
    """SQL for a whitelisted field on the events row aliased `alias`.
    `add` binds a value and returns its placeholder (see compiler.Params)."""
    if name in FIELD_TYPES:
        return f"{alias}.{name}"
    match = _RAW_KEY_RE.fullmatch(name)
    if match is None:
        # Definitions are validated before this point; this is the last line of defence.
        raise ValueError("field is not on the rule field whitelist")
    return f"({alias}.raw->>{add(match.group(1))})"
