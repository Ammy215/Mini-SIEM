import re
from datetime import datetime, timezone

# Jan 10 10:00:01 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2
# Jan 10 10:00:10 host sshd[1234]: Accepted publickey for deploy from 198.51.100.7 port 51237 ssh2: RSA ...
_LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted)\s+(?P<method>password|publickey)\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)


def _parse_timestamp(ts: str) -> datetime:
    # Syslog-style timestamps omit the year — assume the current year.
    parsed = datetime.strptime(ts, "%b %d %H:%M:%S")
    return parsed.replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)


def parse_line(line: str) -> dict | None:
    match = _LINE_RE.search(line)
    if match is None:
        return None

    action = "login_success" if match["result"] == "Accepted" else "login_failed"

    return {
        "event_time": _parse_timestamp(match["ts"]),
        "source_type": "ssh",
        "source_ip": match["ip"],
        "dest_port": 22,
        "username": match["user"],
        "action": action,
        "raw_message": line.strip(),
        "raw": {"auth_method": match["method"], "source_port": int(match["port"])},
    }
