import re

from parsers.timeutil import parse_yearless

# <134>Jan 10 10:00:01 host process[1234]: message text here
# Jan 10 10:00:01 host process[1234]: message text here   (priority prefix optional)
_LINE_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)


def parse_line(line: str) -> dict | None:
    """Returns None for non-syslog lines. Raises InvalidTimestamp for a
    matching line whose date doesn't exist (Feb 30)."""
    match = _LINE_RE.search(line)
    if match is None:
        return None

    return {
        "event_time": parse_yearless(match["ts"]),
        "source_type": "syslog",
        "action": "log",
        "raw_message": line.strip(),
        "raw": {
            "host": match["host"],
            "process": match["process"].strip(),
            "pid": int(match["pid"]) if match["pid"] else None,
            "priority": int(match["pri"]) if match["pri"] else None,
        },
    }
