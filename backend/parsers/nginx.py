import re
from datetime import datetime

# 203.0.113.5 - - [10/Jan/2026:10:00:01 +0000] "GET /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"
_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r'(?P<status>\d+) (?P<bytes>\d+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_line(line: str) -> dict | None:
    match = _LINE_RE.search(line)
    if match is None:
        return None

    event_time = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z")

    return {
        "event_time": event_time,
        "source_type": "nginx",
        "source_ip": match["ip"],
        "action": "request",
        "status_code": int(match["status"]),
        "method": match["method"],
        "url": match["url"],
        "user_agent": match["ua"],
        "raw_message": line.strip(),
        "raw": {"bytes_sent": int(match["bytes"]), "referer": match["referer"]},
    }
