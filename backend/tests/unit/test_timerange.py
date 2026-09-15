"""Dashboard time ranges: presets, custom from/to, limits, and bucket sizes."""

from datetime import datetime, timedelta, timezone

import pytest

from routers._timerange import floor_to_bucket, resolve

NOW = datetime(2026, 9, 15, 12, 34, 56, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "preset,span,bucket",
    [
        ("1h", timedelta(hours=1), timedelta(minutes=5)),
        ("24h", timedelta(hours=24), timedelta(hours=1)),
        ("7d", timedelta(days=7), timedelta(hours=1)),
        ("30d", timedelta(days=30), timedelta(days=1)),
    ],
)
def test_presets_end_now_with_a_readable_bucket(preset, span, bucket):
    tr = resolve(preset, None, None, NOW)
    assert (tr.start, tr.end, tr.bucket, tr.label) == (NOW - span, NOW, bucket, preset)


def test_no_range_means_the_last_24_hours():
    tr = resolve(None, None, None, NOW)
    assert (tr.end - tr.start, tr.label) == (timedelta(hours=24), "default")


@pytest.mark.parametrize(
    "span,bucket",
    [
        (timedelta(hours=6), timedelta(minutes=5)),
        (timedelta(hours=6, minutes=1), timedelta(hours=1)),
        (timedelta(days=7), timedelta(hours=1)),
        (timedelta(days=8), timedelta(days=1)),
        (timedelta(days=90), timedelta(days=1)),
    ],
)
def test_custom_ranges_pick_their_bucket_from_their_length(span, bucket):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tr = resolve(None, start, start + span, NOW)
    assert (tr.bucket, tr.label) == (bucket, "custom")


@pytest.mark.parametrize(
    "preset,time_from,time_to,message",
    [
        (None, NOW, None, "both from and to"),
        (None, None, NOW, "both from and to"),
        ("24h", NOW - timedelta(hours=1), NOW, "either range or from/to"),
        (None, NOW, NOW, "after from"),
        (None, NOW, NOW - timedelta(minutes=1), "after from"),
        (None, NOW - timedelta(days=90, seconds=1), NOW, "at most 90 days"),
    ],
)
def test_invalid_ranges_say_why(preset, time_from, time_to, message):
    with pytest.raises(ValueError, match=message):
        resolve(preset, time_from, time_to, NOW)


def test_buckets_line_up_on_whole_units_in_utc():
    assert floor_to_bucket(NOW, timedelta(minutes=5)) == datetime(2026, 9, 15, 12, 30, tzinfo=timezone.utc)
    assert floor_to_bucket(NOW, timedelta(hours=1)) == datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
    assert floor_to_bucket(NOW, timedelta(days=1)) == datetime(2026, 9, 15, tzinfo=timezone.utc)
