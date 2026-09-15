"""The syslog envelope in front of another format's message.

Firewall kernel lines and CEF records usually arrive wrapped in syslog:

    Sep 14 10:21:03 fw01 kernel: [UFW BLOCK] IN=eth0 …
    <134>Sep 14 10:30:05 fgt01 CEF:0|Fortinet|…
    2026-09-14T10:21:03+0000 fw01 kernel: …        (journalctl -o short-iso)

The inner parser owns the fields; this only recovers when and where.
"""

import re
from datetime import datetime

from parsers import syslog, syslog5424
from parsers.timeutil import parse_flexible

_ISO_HEADER_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s")


def syslog_header(line: str, year_hint: int | None = None) -> tuple[datetime | None, str | None]:
    """(timestamp, host) from the envelope, or (None, None) if there isn't one.
    Raises InvalidTimestamp when the envelope's date doesn't exist."""
    stripped = line.strip()

    if stripped.startswith("<"):
        envelope = syslog5424.parse_line(stripped)
        if envelope is not None:
            inferred = envelope["raw"].get("_time_inferred")
            return (None if inferred else envelope["event_time"]), envelope.get("host")

    envelope = syslog.parse_line(stripped, year_hint=year_hint)
    if envelope is not None:
        return envelope["event_time"], envelope.get("host")

    match = _ISO_HEADER_RE.match(stripped)
    if match:
        return parse_flexible(match["ts"]), match["host"]
    return None, None
