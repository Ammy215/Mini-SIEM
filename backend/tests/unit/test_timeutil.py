from datetime import datetime, timezone

import pytest

from parsers.timeutil import InvalidTimestamp, parse_yearless

NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)


def test_ordinary_timestamp_gets_the_current_year():
    assert parse_yearless("Jan 10 10:00:01", now=NOW) == datetime(2026, 1, 10, 10, 0, 1, tzinfo=timezone.utc)


def test_syslog_padded_single_digit_day():
    assert parse_yearless("Sep  5 08:30:00", now=NOW) == datetime(2026, 9, 5, 8, 30, tzinfo=timezone.utc)


def test_line_from_late_last_year_read_early_this_year_is_not_dated_into_the_future():
    new_year = datetime(2027, 1, 1, 0, 30, tzinfo=timezone.utc)
    assert parse_yearless("Dec 31 23:59:00", now=new_year) == datetime(2026, 12, 31, 23, 59, tzinfo=timezone.utc)


def test_a_few_hours_of_clock_skew_stays_in_the_current_year():
    assert parse_yearless("Sep 14 20:00:00", now=NOW).year == 2026


def test_feb_29_outside_a_leap_year_resolves_to_the_latest_leap_year():
    # Used to raise inside strptime (default year 1900 isn't a leap year) and 500 the upload.
    assert parse_yearless("Feb 29 06:00:00", now=NOW) == datetime(2024, 2, 29, 6, tzinfo=timezone.utc)


def test_feb_29_during_a_leap_year_stays_in_that_year():
    assert parse_yearless("Feb 29 06:00:00", now=datetime(2028, 3, 1, tzinfo=timezone.utc)).year == 2028


@pytest.mark.parametrize("ts", ["Feb 30 10:00:00", "Apr 31 10:00:00", "Foo 10 10:00:00", "Jan 10 25:00:00"])
def test_impossible_dates_and_times_raise_invalid_timestamp(ts):
    with pytest.raises(InvalidTimestamp):
        parse_yearless(ts, now=NOW)


def test_invalid_timestamp_is_still_a_value_error():
    # Callers that already catch ValueError keep working.
    assert issubclass(InvalidTimestamp, ValueError)


def test_year_hint_is_used_as_given():
    assert parse_yearless("Mar 01 00:00:00", now=NOW, year_hint=2019).year == 2019


def test_year_hint_does_not_rescue_an_impossible_date():
    with pytest.raises(InvalidTimestamp):
        parse_yearless("Feb 29 00:00:00", now=NOW, year_hint=2025)
