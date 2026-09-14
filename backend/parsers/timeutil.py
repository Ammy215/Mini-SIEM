"""Timestamps for log formats that leave out the year.

Classic syslog and OpenSSH lines are stamped `Jan 10 10:00:01` — no year. The
old approach, `strptime(ts, "%b %d ...")` then `.replace(year=...)`, parses into
Python's default year 1900 first. 1900 is not a leap year, so any `Feb 29` line
raised ValueError and failed a whole upload with a 500; it is also deprecated
and changes behaviour in Python 3.15.
"""

from datetime import datetime, timedelta, timezone

_FORMAT = "%Y %b %d %H:%M:%S"

# Device clocks drift and timezones get misconfigured; a line a few hours "in
# the future" is skew, not last year's log.
_FUTURE_TOLERANCE = timedelta(days=1)

# Far enough back to always reach a leap year (the longest gap is 8 years).
_YEARS_TO_TRY = 9


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


def _parse(year: int, ts: str) -> datetime:
    return datetime.strptime(f"{year} {ts}", _FORMAT).replace(tzinfo=timezone.utc)
