import re

from parsers.timeutil import parse_yearless

# Jan 10 10:00:01 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2
# Jan 10 10:00:10 host sshd[1234]: Accepted publickey for deploy from 198.51.100.7 port 51237 ssh2: RSA ...
_LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.*)$"
)
_AUTH_RE = re.compile(
    r"^(?P<result>Failed|Accepted)\s+(?P<method>password|publickey)\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)


def parse_auth_message(message: str) -> dict | None:
    """The login fields in an sshd message (the text after `sshd[pid]: `).
    Shared with the RFC 5424 syslog parser, which carries the same messages."""
    match = _AUTH_RE.match(message)
    if match is None:
        return None
    succeeded = match["result"] == "Accepted"
    return {
        "source_type": "ssh",
        "source_ip": match["ip"],
        "src_port": int(match["port"]),
        "dest_port": 22,
        "username": match["user"],
        "action": "login_success" if succeeded else "login_failed",
        "outcome": "success" if succeeded else "failure",
        "raw": {"auth_method": match["method"], "source_port": int(match["port"])},
    }


def parse_line(line: str, year_hint: int | None = None) -> dict | None:
    """Returns None for lines that aren't sshd auth results. Raises
    InvalidTimestamp for a matching line whose date doesn't exist (Feb 30)."""
    match = _LINE_RE.search(line)
    if match is None:
        return None
    auth = parse_auth_message(match["message"])
    if auth is None:
        return None

    return {
        **auth,
        "event_time": parse_yearless(match["ts"], year_hint=year_hint),
        "host": match["host"],
        "raw_message": line.strip(),
    }
