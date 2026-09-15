"""Business hours, days, time zones and home countries: the pure checks behind
the after_hours and foreign_geo signals."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from detection import context

UTC = timezone.utc


def _hours(text="09:00-17:00", days="mon-fri", tz="UTC"):
    return context.parse_business_hours(text, days, tz)


# 2026-09-14 is a Monday.
@pytest.mark.parametrize(
    "when,after_hours",
    [
        (datetime(2026, 9, 14, 8, 59, tzinfo=UTC), True),
        (datetime(2026, 9, 14, 9, 0, tzinfo=UTC), False),    # the start minute is inside
        (datetime(2026, 9, 14, 16, 59, tzinfo=UTC), False),
        (datetime(2026, 9, 14, 17, 0, tzinfo=UTC), True),    # the end minute is outside
        (datetime(2026, 9, 19, 12, 0, tzinfo=UTC), True),    # Saturday
        (datetime(2026, 9, 18, 12, 0, tzinfo=UTC), False),   # Friday
    ],
)
def test_weekday_business_hours(when, after_hours):
    assert context.is_after_hours(when, _hours()) is after_hours


def test_daylight_saving_time_is_applied_in_the_business_time_zone():
    new_york = _hours(tz="America/New_York")
    # 13:30 UTC is 08:30 in EST (before the 2026-03-08 change) but 09:30 in EDT after it.
    assert context.is_after_hours(datetime(2026, 3, 6, 13, 30, tzinfo=UTC), new_york) is True
    assert context.is_after_hours(datetime(2026, 3, 9, 13, 30, tzinfo=UTC), new_york) is False


def test_half_hour_offsets_are_handled():
    kolkata = _hours(tz="Asia/Kolkata")  # UTC+05:30
    assert context.is_after_hours(datetime(2026, 9, 14, 3, 30, tzinfo=UTC), kolkata) is False
    assert context.is_after_hours(datetime(2026, 9, 14, 3, 29, tzinfo=UTC), kolkata) is True


@pytest.mark.parametrize(
    "when,after_hours",
    [
        (datetime(2026, 9, 14, 23, 0, tzinfo=UTC), False),   # Monday night shift
        (datetime(2026, 9, 15, 5, 0, tzinfo=UTC), False),    # Tuesday early morning: Monday's shift
        (datetime(2026, 9, 19, 5, 0, tzinfo=UTC), False),    # Saturday early morning: Friday's shift
        (datetime(2026, 9, 20, 5, 0, tzinfo=UTC), True),     # Sunday early morning: no Saturday shift
        (datetime(2026, 9, 14, 12, 0, tzinfo=UTC), True),    # midday is outside a night shift
    ],
)
def test_overnight_shifts(when, after_hours):
    assert context.is_after_hours(when, _hours("22:00-06:00")) is after_hours


def test_round_the_clock_hours_are_never_after_hours():
    always = _hours("00:00-24:00", "mon-sun")
    assert not any(
        context.is_after_hours(datetime(2026, 9, day, hour, 59, tzinfo=UTC), always)
        for day in range(14, 21) for hour in range(24)
    )


def test_day_lists_and_ranges():
    assert context.parse_days("mon-fri") == {0, 1, 2, 3, 4}
    assert context.parse_days("sat, sun") == {5, 6}
    assert context.parse_days("fri-mon") == {4, 5, 6, 0}
    assert context.parse_days("Monday-Wednesday") == {0, 1, 2}


def test_countries():
    assert context.parse_countries(" us, gb ") == {"US", "GB"}
    assert context.parse_countries("") == frozenset()
    assert context.is_foreign("RU", frozenset({"US"})) is True
    assert context.is_foreign("us", frozenset({"US"})) is False
    assert context.is_foreign(None, frozenset({"US"})) is None


@pytest.mark.parametrize(
    "call,setting",
    [
        (lambda: context.parse_hours("9-5"), "BUSINESS_HOURS"),
        (lambda: context.parse_hours("25:00-26:00"), "BUSINESS_HOURS"),
        (lambda: context.parse_hours("09:60-10:00"), "BUSINESS_HOURS"),
        (lambda: context.parse_hours("09:00-09:00"), "BUSINESS_HOURS"),
        (lambda: context.parse_days("funday"), "BUSINESS_DAYS"),
        (lambda: context.parse_days(" , "), "BUSINESS_DAYS"),
        (lambda: context.parse_countries("USA"), "HOME_COUNTRIES"),
        (lambda: context.parse_countries("U1"), "HOME_COUNTRIES"),
        (lambda: _hours(tz="Mars/Olympus_Mons"), "BUSINESS_TIMEZONE"),
        (lambda: _hours(tz="../../etc/passwd"), "BUSINESS_TIMEZONE"),
    ],
)
def test_malformed_settings_name_the_setting(call, setting):
    with pytest.raises(ValueError, match=setting):
        call()


def test_blank_settings_mean_not_configured():
    loaded = context.load(SimpleNamespace(business_hours="", business_days="mon-fri", business_timezone="UTC", home_countries=""))
    assert loaded.business_hours is None
    assert loaded.home_countries == frozenset()
