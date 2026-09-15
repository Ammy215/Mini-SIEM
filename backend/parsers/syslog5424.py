"""Syslog, RFC 5424 — what rsyslog, journald forwarders and most modern devices send.

    <34>1 2026-09-14T22:14:15.003Z bastion sshd 4123 - - Failed password for root from 203.0.113.9 port 50022 ssh2
    <165>1 2026-09-14T22:14:16Z app01 billing 88 PAY [origin ip="10.0.0.4"] payment gateway timeout
"""

import re
from datetime import datetime, timezone

from parsers import ssh
from parsers.timeutil import parse_flexible

_NIL = "-"

_LINE_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) "
    r"(?P<procid>\S+) (?P<msgid>\S+) (?P<sd>-|(?:\[[^\]]*\])+)(?: (?P<message>.*))?$"
)


def parse_line(line: str) -> dict | None:
    match = _LINE_RE.match(line.strip())
    if match is None:
        return None

    raw = {
        "priority": int(match["pri"]),
        "version": int(match["version"]),
        "app_name": _value(match["app"]),
        "procid": _value(match["procid"]),
        "msgid": _value(match["msgid"]),
        "structured_data": _value(match["sd"]),
    }

    if match["ts"] == _NIL:
        event_time = datetime.now(timezone.utc)
        raw["_time_inferred"] = True
    else:
        event_time = parse_flexible(match["ts"])
        if event_time is None:
            return None  # shaped like RFC 5424 but not a real timestamp: not this format

    event = {
        "event_time": event_time,
        "source_type": "syslog",
        "host": _value(match["host"]),
        "action": "log",
        "raw_message": line.strip(),
        "raw": raw,
    }

    # An sshd message is the same text OpenSSH writes to auth.log, so it
    # carries the same login fields brute-force detection needs.
    if raw["app_name"] == "sshd":
        auth = ssh.parse_auth_message((match["message"] or "").lstrip("﻿"))
        if auth is not None:
            event.update({key: value for key, value in auth.items() if key != "raw"})
            event["raw"] = {**raw, **auth["raw"]}

    return event


def _value(text: str) -> str | None:
    return None if text == _NIL else text
