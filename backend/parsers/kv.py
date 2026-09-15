"""key=value logs: firewalls, appliances, and many application loggers.

    date=2026-09-14 time=10:01:02 devname="FGT-HQ" srcip=203.0.113.50 dstport=22 action="deny"
"""

import re

from parsers.fields import normalize

MIN_PAIRS = 3
MAX_PAIRS = 200

_KEY_RE = re.compile(r"[A-Za-z_@][\w.@-]{0,63}")


def parse_line(line: str) -> dict | None:
    if "=" not in line:
        return None
    pairs = _pairs(line)
    if len(pairs) < MIN_PAIRS:
        return None
    return normalize(pairs, source_type="kv", raw_message=line.strip())


def _pairs(line: str) -> dict[str, str]:
    """Reads key=value pairs in one left-to-right pass.

    Deliberately not a regex: with quoted values, a regex retries from every
    `key="` it finds, so a hostile line of thousands of unterminated quotes
    takes quadratic time. A single pass stays linear on any input.
    """
    pairs: dict[str, str] = {}
    i, n = 0, len(line)

    while i < n and len(pairs) < MAX_PAIRS:
        while i < n and line[i].isspace():
            i += 1
        key_start = i
        while i < n and not line[i].isspace() and line[i] != "=":
            i += 1
        key = line[key_start:i]

        if i >= n or line[i] != "=" or not _KEY_RE.fullmatch(key):
            while i < n and not line[i].isspace():
                i += 1
            continue

        i += 1  # past "="
        if i < n and line[i] in "\"'":
            quote = line[i]
            i += 1
            end = line.find(quote, i)
            while end != -1 and line[end - 1] == "\\":
                end = line.find(quote, end + 1)
            if end == -1:
                value, i = line[i:], n
            else:
                value, i = line[i:end].replace("\\" + quote, quote), end + 1
        else:
            value_start = i
            while i < n and not line[i].isspace():
                i += 1
            value = line[value_start:i]

        pairs.setdefault(key, value)

    return pairs
