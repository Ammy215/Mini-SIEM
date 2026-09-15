"""The catch-all: stores any line as-is, so nothing uploaded in auto mode is lost.

It deliberately doesn't guess event fields. In particular, an IP found in free
text is never made the event's source_ip — that would feed brute-force and
port-scan rules with addresses that may be nothing of the kind. Found IPs are
listed in raw._ips_found instead, and the line stays full-text searchable.
"""

import ipaddress
import re
from datetime import datetime, timezone

from parsers.timeutil import parse_flexible

_ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MAX_IPS = 20


def parse_line(line: str) -> dict:
    text = line.strip()
    raw: dict = {}

    match = _ISO_RE.search(text)
    event_time = parse_flexible(match.group(0).replace(",", ".")) if match else None
    if event_time is None:
        event_time = datetime.now(timezone.utc)
        raw["_time_inferred"] = True

    ips: list[str] = []
    for candidate in _IPV4_RE.finditer(text):
        address = candidate.group(0)
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue
        if address not in ips:
            ips.append(address)
            if len(ips) == MAX_IPS:
                break
    if ips:
        raw["_ips_found"] = ips

    return {
        "event_time": event_time,
        "source_type": "generic",
        "action": "log",
        "raw_message": text,
        "raw": raw,
    }
