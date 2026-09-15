"""CEF — Common Event Format, the export format of most commercial security
appliances (Palo Alto, Fortinet, Check Point, Cisco, Sophos…).

    Sep 14 10:30:00 pa-fw01 CEF:0|Palo Alto Networks|PAN-OS|10.1.0|end|TRAFFIC|1|src=203.0.113.120 dst=10.0.0.20 dpt=3389 act=deny

    CEF:Version|Vendor|Product|Version|Signature ID|Name|Severity|Extension

Header fields escape `|` and `\\`. Extension values escape `=` and `\\` and may
contain spaces, so a value ends only where the next `key=` begins.
"""

import ipaddress
from datetime import datetime, timezone

from parsers.fields import normalize_protocol
from parsers.headers import syslog_header
from parsers.timeutil import InvalidTimestamp, parse_flexible, parse_yearless

_MARKER = "CEF:"
_HEADER_FIELDS = 7  # version, vendor, product, device version, signature id, name, severity

_BLOCKED = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected",
            "reset", "reset-both", "reset-client", "reset-server", "prevent", "prevented"}
_ALLOWED = {"allow", "allowed", "accept", "accepted", "permit", "permitted", "pass", "passed"}
_OUTCOMES = {"success": "success", "succeeded": "success", "failure": "failure", "failed": "failure"}

# CEF is also sent by IDS, proxies and endpoint agents. Events from firewall
# products get source_type "firewall", so firewall rules can target them.
_FIREWALL_HINTS = ("palo alto", "pan-os", "fortinet", "fortigate", "check point", "checkpoint", "firewall",
                   "asa", "sonicwall", "pfsense", "juniper", "srx", "sophos", "watchguard", "netscreen")

_TIME_FORMATS = ("%b %d %Y %H:%M:%S.%f", "%b %d %Y %H:%M:%S")


def parse_line(line: str, year_hint: int | None = None) -> dict | None:
    marker = line.find(_MARKER)
    if marker == -1:
        return None

    split = _split_header(line[marker + len(_MARKER):])
    if split is None:
        return None
    (version, vendor, product, device_version, signature_id, name, severity), extension = split
    if not version.strip().isdecimal():
        return None

    pairs = _extension_pairs(extension)
    header_time, header_host = syslog_header(line, year_hint) if marker > 0 else (None, None)
    event_time = _cef_time(pairs.get("rt"), year_hint) or _cef_time(pairs.get("start"), year_hint) or header_time

    raw: dict = {
        "cef_version": version.strip(),
        "vendor": vendor,
        "product": product,
        "device_version": device_version,
        "signature_id": signature_id,
        "name": name,
        "severity": severity,
        "extension": pairs,
    }
    if event_time is None:
        event_time = datetime.now(timezone.utc)
        raw["_time_inferred"] = True

    act = pairs.get("act", "").strip()
    if act:
        raw["act"] = act

    event = {
        "event_time": event_time,
        "source_type": "firewall" if _is_firewall(vendor, product) else "cef",
        "action": _action(act),
        "outcome": _OUTCOMES.get(pairs.get("outcome", "").strip().lower()),
        "source_ip": _ip(pairs.get("src")),
        "dest_ip": _ip(pairs.get("dst")),
        "src_port": _port(pairs.get("spt")),
        "dest_port": _port(pairs.get("dpt")),
        "protocol": normalize_protocol(pairs.get("proto")),
        "username": _text(pairs.get("suser"), 256) or _text(pairs.get("duser"), 256),
        "url": _text(pairs.get("request"), 65_536),
        "method": _text(pairs.get("requestMethod"), 32),
        "user_agent": _text(pairs.get("requestClientApplication"), 4_096),
        "host": _text(pairs.get("dvchost"), 256) or _text(header_host, 256),
        "event_code": _text(signature_id, 64),
        "raw_message": line.strip(),
        "raw": raw,
    }
    return {key: value for key, value in event.items() if value is not None}


def _split_header(text: str) -> tuple[list[str], str] | None:
    """The seven header fields, unescaped, and the extension after them."""
    fields: list[str] = []
    current: list[str] = []
    i, n = 0, len(text)
    while i < n and len(fields) < _HEADER_FIELDS:
        char = text[i]
        if char == "\\" and i + 1 < n and text[i + 1] in "|\\":
            current.append(text[i + 1])
            i += 2
            continue
        if char == "|":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    if len(fields) < _HEADER_FIELDS:
        return None
    return fields, text[i:]


def _extension_pairs(text: str) -> dict[str, str]:
    """key=value pairs from a CEF extension, in two linear passes.

    First every unescaped "=" is found. An "=" starts a new pair only when the
    word right before it begins the string or follows a space — so the "=" in
    `msg=a=b` stays part of the value. Each value then runs up to the space
    before the next key.
    """
    n = len(text)
    equals: list[int] = []
    i = 0
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "=":
            equals.append(i)
        i += 1

    keys: list[tuple[int, int]] = []
    for position in equals:
        start = position
        while start > 0 and _is_key_char(text[start - 1]):
            start -= 1
        if start == position or (start > 0 and text[start - 1] != " "):
            continue
        keys.append((start, position))

    pairs: dict[str, str] = {}
    for index, (start, position) in enumerate(keys):
        end = keys[index + 1][0] - 1 if index + 1 < len(keys) else n
        pairs.setdefault(text[start:position], _unescape_value(text[position + 1:end]).strip())
    return pairs


def _unescape_value(value: str) -> str:
    if "\\" not in value:
        return value
    out: list[str] = []
    i, n = 0, len(value)
    while i < n:
        char = value[i]
        if char == "\\" and i + 1 < n:
            following = value[i + 1]
            out.append({"n": "\n", "r": "\r", "=": "=", "\\": "\\"}.get(following, "\\" + following))
            i += 2
            continue
        out.append(char)
        i += 1
    return "".join(out)


def _is_key_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def _cef_time(value: str | None, year_hint: int | None) -> datetime | None:
    if not value or not value.strip():
        return None
    parsed = parse_flexible(value)  # epoch milliseconds, or ISO-8601
    if parsed is not None:
        return parsed

    text = value.strip()
    head, _, zone = text.rpartition(" ")
    if head and zone.isalpha():
        text = head  # "GMT", "UTC" — taken as UTC
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return parse_yearless(text, year_hint=year_hint)
    except InvalidTimestamp:
        return None


def _is_firewall(vendor: str, product: str) -> bool:
    text = f"{vendor} {product}".lower()
    return any(hint in text for hint in _FIREWALL_HINTS)


def _action(act: str) -> str:
    lowered = act.lower()
    if lowered in _BLOCKED:
        return "blocked"
    if lowered in _ALLOWED:
        return "allowed"
    return lowered[:128] if lowered else "cef_event"


def _ip(value: str | None) -> str | None:
    if not value or not value.strip():
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _port(value: str | None) -> int | None:
    if value and value.strip().isdecimal() and 0 <= int(value) <= 65535:
        return int(value)
    return None


def _text(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text if text and len(text) <= limit else None
