import re
from datetime import datetime
from urllib.parse import unquote, unquote_plus

from parsers.timeutil import InvalidTimestamp

# 203.0.113.5 - - [10/Jan/2026:10:00:01 +0000] "GET /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"
_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    # Apache writes "-" instead of 0 when no body was sent.
    r'(?P<status>\d+) (?P<bytes>\d+|-) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

# The request field is logged verbatim, so its URL can contain literal spaces:
# a browser would percent-encode them, but an attacker writes the request line
# by hand. Splitting it into exactly three tokens therefore dropped precisely
# the requests worth detecting — `GET /p?id=1' OR 1=1-- HTTP/1.1` lost its url,
# status and user agent to the generic parser, so the SQLi and scanner-UA rules
# could never match it. Anchor on the trailing protocol instead and let the URL
# hold whatever is between it and the method.
_REQUEST_RE = re.compile(r'^(?P<method>\S+) (?P<url>.*) (?P<proto>HTTP/[0-9.]+)$')


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
    """Returns None for lines that aren't combined log format. Raises
    InvalidTimestamp for a matching line with an impossible time stamp."""
    match = _LINE_RE.search(line)
    if match is None:
        return None

    # Anything that isn't a recognisable request line — raw TLS bytes sent to an
    # HTTP port, say — is left for the generic parser, as before.
    request = _REQUEST_RE.match(match["request"])
    if request is None:
        return None

    try:
        event_time = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError as exc:
        raise InvalidTimestamp(f"not a real timestamp: {match['ts']!r}") from exc

    raw_url = request["url"]
    decoded_url = decode_url(raw_url)

    return {
        "event_time": event_time,
        "source_type": "nginx",
        "source_ip": match["ip"],
        "action": "request",
        "status_code": int(match["status"]),
        "method": request["method"],
        # Detection reads `url`, so it holds the decoded form. The exact bytes
        # off the wire are preserved in raw.url_raw and in raw_message.
        "url": decoded_url,
        "user_agent": match["ua"],
        "raw_message": line.strip(),
        "raw": {
            "bytes_sent": 0 if match["bytes"] == "-" else int(match["bytes"]),
            "referer": match["referer"],
            "url_raw": raw_url,
            "url_was_encoded": raw_url != decoded_url,
        },
    }
