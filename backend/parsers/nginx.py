import re
from datetime import datetime
from urllib.parse import unquote, unquote_plus

# 203.0.113.5 - - [10/Jan/2026:10:00:01 +0000] "GET /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"
_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r'(?P<status>\d+) (?P<bytes>\d+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


def decode_url(url: str) -> str:
    """Percent-decode a request URL so signature rules match what the attacker
    actually meant, not its wire encoding.

    Real HTTP clients encode payloads: `' OR 1=1` arrives as `%27+OR+1%3d1`,
    `<script>` as `%3cscript%3e`, `../` as `..%2f`. Matching literal patterns
    against the raw line silently misses all of it.

    Path and query are decoded separately because `+` only means a space in the
    query string — in a path it is a literal plus.
    """
    path, sep, query = url.partition("?")
    decoded_path = unquote(path)
    if not sep:
        return decoded_path
    return f"{decoded_path}?{unquote_plus(query)}"


def parse_line(line: str) -> dict | None:
    match = _LINE_RE.search(line)
    if match is None:
        return None

    event_time = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z")
    raw_url = match["url"]
    decoded_url = decode_url(raw_url)

    return {
        "event_time": event_time,
        "source_type": "nginx",
        "source_ip": match["ip"],
        "action": "request",
        "status_code": int(match["status"]),
        "method": match["method"],
        # Detection reads `url`, so it holds the decoded form. The exact bytes
        # off the wire are preserved in raw.url_raw and in raw_message.
        "url": decoded_url,
        "user_agent": match["ua"],
        "raw_message": line.strip(),
        "raw": {
            "bytes_sent": int(match["bytes"]),
            "referer": match["referer"],
            "url_raw": raw_url,
            "url_was_encoded": raw_url != decoded_url,
        },
    }
