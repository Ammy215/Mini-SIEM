"""Linux firewall logs: netfilter's LOG target, as written by iptables, nftables and UFW.

    Sep 14 10:21:03 fw01 kernel: [123456.789012] [UFW BLOCK] IN=eth0 OUT= MAC=… SRC=203.0.113.99
        DST=10.0.0.5 LEN=44 TTL=242 PROTO=TCP SPT=40404 DPT=3389 WINDOW=1024 SYN URGP=0
    Sep 14 10:21:06 fw01 kernel: IPTABLES-DROP: IN=eth1 OUT= SRC=2001:db8::66 DST=2001:db8::1 PROTO=UDP SPT=5353 DPT=53

Blocked connections carry the destination port, which is what the port-scan
rule counts — no other log format here recorded it.
"""

import ipaddress
import re
from datetime import datetime, timezone

from parsers.fields import normalize_protocol
from parsers.headers import syslog_header

_UPTIME_RE = re.compile(r"\[\s*\d+\.\d+\]")
_BLOCK_WORDS = ("BLOCK", "DROP", "REJECT", "DENY")
_ALLOW_WORDS = ("ALLOW", "ACCEPT", "PERMIT", "PASS")
_MAX_PREFIX_CHARS = 64


def parse_line(line: str, year_hint: int | None = None) -> dict | None:
    start = _fields_start(line)
    if start is None:
        return None

    fields: dict[str, str] = {}
    flags: list[str] = []
    for token in line[start:].split():
        key, separator, value = token.partition("=")
        if separator and key.isalnum() and key.isupper():
            fields.setdefault(key, value)
        elif token.isalpha() and token.isupper():
            flags.append(token)  # TCP flags such as SYN, ACK; DF

    source_ip, dest_ip = _ip(fields.get("SRC")), _ip(fields.get("DST"))
    if source_ip is None or dest_ip is None:
        return None

    prefix = _prefix(line[:start])
    event_time, host = syslog_header(line, year_hint)

    raw: dict = {key.lower(): value for key, value in fields.items()}
    if prefix:
        raw["prefix"] = prefix
    if flags:
        raw["flags"] = flags
    if event_time is None:
        event_time = datetime.now(timezone.utc)
        raw["_time_inferred"] = True

    event = {
        "event_time": event_time,
        "source_type": "firewall",
        "action": _action(prefix),
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "protocol": normalize_protocol(fields.get("PROTO")),
        "src_port": _port(fields.get("SPT")),
        "dest_port": _port(fields.get("DPT")),
        "host": host,
        "raw_message": line.strip(),
        "raw": raw,
    }
    return {key: value for key, value in event.items() if value is not None}


def _fields_start(line: str) -> int | None:
    """Where the netfilter fields begin: `IN=`, followed by `OUT=` and `SRC=`."""
    if line.startswith("IN="):
        index = 0
    else:
        index = line.find(" IN=")
        if index == -1:
            return None
        index += 1
    rest = line[index:]
    if " OUT=" not in rest or " SRC=" not in rest:
        return None
    return index


def _prefix(before_fields: str) -> str:
    """The rule's log prefix — "[UFW BLOCK]", "IPTABLES-DROP:" — without the
    syslog header or the kernel's uptime stamp in front of it."""
    text = before_fields.rstrip()
    kernel = text.rfind("kernel:")
    if kernel != -1:
        text = text[kernel + len("kernel:"):]
    return _UPTIME_RE.sub("", text).strip()[-_MAX_PREFIX_CHARS:]


def _action(prefix: str) -> str:
    upper = prefix.upper()
    if "UFW AUDIT" in upper:
        return "audit"
    if any(word in upper for word in _BLOCK_WORDS):
        return "blocked"
    if any(word in upper for word in _ALLOW_WORDS):
        return "allowed"
    return "firewall"


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _port(value: str | None) -> int | None:
    if value and value.isdecimal() and 0 <= int(value) <= 65535:
        return int(value)
    return None
