"""Context signals: did it happen outside business hours, did it come from
outside the home countries.

Pure functions, plus parsing of the settings that configure them. A signal that
isn't configured is skipped, and the alert records why, rather than guessed.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_HOURS_RE = re.compile(r"^\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")


@dataclass(frozen=True)
class BusinessHours:
    start: int              # minutes after local midnight
    end: int                # minutes after local midnight, up to 1440; before start = overnight
    days: frozenset[int]    # weekday() numbers, 0 = Monday
    tz: ZoneInfo


@dataclass(frozen=True)
class Context:
    business_hours: BusinessHours | None
    home_countries: frozenset[str]


def parse_hours(text: str) -> tuple[int, int]:
    match = _HOURS_RE.match(text or "")
    error = ValueError("BUSINESS_HOURS must look like 08:00-18:00 (24-hour clock, end up to 24:00)")
    if not match:
        raise error
    start_h, start_m, end_h, end_m = map(int, match.groups())
    start, end = start_h * 60 + start_m, end_h * 60 + end_m
    if start_m > 59 or end_m > 59 or start >= 1440 or end > 1440 or start == end:
        raise error
    return start, end


def parse_days(text: str) -> frozenset[int]:
    """'mon-fri', 'sat,sun', 'fri-mon' (wraps), or a mix."""
    days: set[int] = set()
    for part in (text or "").lower().split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            first, last = (_day(p) for p in part.split("-", 1))
            day = first
            while True:
                days.add(day)
                if day == last:
                    break
                day = (day + 1) % 7
        else:
            days.add(_day(part))
    if not days:
        raise ValueError("BUSINESS_DAYS must name at least one day, e.g. mon-fri")
    return frozenset(days)


def _day(name: str) -> int:
    name = name.strip()[:3]
    if name not in _DAY_NAMES:
        raise ValueError("BUSINESS_DAYS must use mon, tue, wed, thu, fri, sat, sun, e.g. mon-fri")
    return _DAY_NAMES.index(name)


def parse_countries(text: str) -> frozenset[str]:
    codes = {code.strip().upper() for code in (text or "").split(",") if code.strip()}
    if any(not _COUNTRY_RE.match(code) for code in codes):
        raise ValueError("HOME_COUNTRIES must be two-letter ISO country codes, e.g. US,GB")
    return frozenset(codes)


def parse_business_hours(hours: str, days: str, timezone: str) -> BusinessHours | None:
    if not (hours or "").strip():
        return None
    start, end = parse_hours(hours)
    try:
        tz = ZoneInfo((timezone or "").strip())
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError("BUSINESS_TIMEZONE must be an IANA time zone, e.g. Europe/London") from None
    return BusinessHours(start, end, parse_days(days), tz)


def load(settings) -> Context:
    """Raises ValueError, naming the setting, when any of them is malformed."""
    return Context(
        business_hours=parse_business_hours(settings.business_hours, settings.business_days, settings.business_timezone),
        home_countries=parse_countries(settings.home_countries),
    )


def is_after_hours(when: datetime, hours: BusinessHours) -> bool:
    """Whether an aware datetime falls outside business hours, in the business's
    own time zone (so daylight-saving changes are handled)."""
    local = when.astimezone(hours.tz)
    minute = local.hour * 60 + local.minute
    weekday = local.weekday()
    if hours.start < hours.end:
        inside = hours.start <= minute < hours.end and weekday in hours.days
    elif minute >= hours.start:
        inside = weekday in hours.days
    elif minute < hours.end:
        # An overnight shift's early-morning part belongs to the day it started.
        inside = (weekday - 1) % 7 in hours.days
    else:
        inside = False
    return not inside


def is_foreign(country: str | None, home: frozenset[str]) -> bool | None:
    """None when the country isn't known: unknown is not the same as foreign."""
    if not country:
        return None
    return country.strip().upper() not in home
