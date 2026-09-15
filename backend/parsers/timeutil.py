"""Timestamps from log lines.

Classic syslog and OpenSSH lines are stamped `Jan 10 10:00:01` — no year. The
old approach, `strptime(ts, "%b %d ...")` then `.replace(year=...)`, parses into
Python's default year 1900 first. 1900 is not a leap year, so any `Feb 29` line
raised ValueError and failed a whole upload with a 500; it is also deprecated
and changes behaviour in Python 3.15.

JSON, CSV and key=value logs instead carry ISO-8601 strings or Unix epochs,
handled by parse_flexible.
"""

import re
from datetime import datetime, timedelta, timezone

_FORMAT = "%Y %b %d %H:%M:%S"

# Device clocks drift and timezones get misconfigured; a line a few hours "in
# the future" is skew, not last year's log.
_FUTURE_TOLERANCE = timedelta(days=1)

# Far enough back to always reach a leap year (the longest gap is 8 years).
_YEARS_TO_TRY = 9

_EPOCH_RE = re.compile(r"\d{9,13}(?:\.\d+)?")
_LONG_FRACTION_RE = re.compile(r"(\.\d{6})\d+")

# March 1973 to the year 3000. Outside that, a number is a counter, a duration
# or an ID rather than a time: `"time": 12` must not date an event to 1970.
# (The same floor as _EPOCH_RE's nine-digit minimum for epoch strings.)
_MIN_EPOCH_SECONDS = 100_000_000
_MAX_EPOCH_SECONDS = 32_503_680_000


class InvalidTimestamp(ValueError):
    """The text looks like a timestamp but isn't a real date or time."""


def parse_yearless(ts: str, now: datetime | None = None, year_hint: int | None = None) -> datetime:
    """Parses `Mon DD HH:MM:SS` into an aware UTC datetime.

    Picks the most recent year in which that date exists and isn't more than a
    day in the future — so `Dec 31` read on Jan 1 lands in last year, and
    `Feb 29` lands in the latest leap year. `year_hint` overrides the guess.
    """
    ts = " ".join(ts.split())  # "Sep  5" (syslog pads single-digit days) -> "Sep 5"

    if year_hint is not None:
        try:
            return _parse(year_hint, ts)
        except ValueError as exc:
            raise InvalidTimestamp(f"not a real date in {year_hint}: {ts!r}") from exc

    now = now or datetime.now(timezone.utc)
    for year in range(now.year, now.year - _YEARS_TO_TRY, -1):
        try:
            parsed = _parse(year, ts)
        except ValueError:
            continue
        if parsed <= now + _FUTURE_TOLERANCE:
            return parsed

    raise InvalidTimestamp(f"not a real date: {ts!r}")


def parse_flexible(value) -> datetime | None:
    """An ISO-8601 string or a Unix epoch (seconds or milliseconds) as an aware
    datetime, or None if the value is neither. A naive ISO value is taken as UTC."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))
    if not isinstance(value, str):
        return None

    text = value.strip()
    if _EPOCH_RE.fullmatch(text):
        return _from_epoch(float(text))
    if not text or len(text) > 64:
        return None
    # Windows writes 7 fractional digits and journald 9; Python accepts at most 6.
    text = _LONG_FRACTION_RE.sub(r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _parse(year: int, ts: str) -> datetime:
    return datetime.strptime(f"{year} {ts}", _FORMAT).replace(tzinfo=timezone.utc)


def _from_epoch(number: float) -> datetime | None:
    if number > 1e11:  # milliseconds
        number /= 1000
    if not _MIN_EPOCH_SECONDS <= number < _MAX_EPOCH_SECONDS:
        return None
    return datetime.fromtimestamp(number, tz=timezone.utc)
