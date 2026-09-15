"""Parsers, format detection and the upload pipeline, on synthetic fixture lines.
No database."""

import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from parsers import app_json, csv_format, generic, kv, nginx, pipeline, syslog5424
from parsers.base import ParseContext
from parsers.timeutil import parse_flexible

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CTX = ParseContext()
UTC = timezone.utc


def _fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


# --- flexible timestamps ------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        ("2026-09-14T10:05:00Z", datetime(2026, 9, 14, 10, 5, tzinfo=UTC)),
        ("2026-09-14 10:05:00", datetime(2026, 9, 14, 10, 5, tzinfo=UTC)),  # naive is taken as UTC
        (1789380300, datetime.fromtimestamp(1789380300, tz=UTC)),
        ("1789380300000", datetime.fromtimestamp(1789380300, tz=UTC)),      # epoch milliseconds
    ],
)
def test_parse_flexible_reads_iso_and_epoch(value, expected):
    assert parse_flexible(value) == expected


@pytest.mark.parametrize("value", ["yesterday", "", True, None, {"a": 1}, 12, "99999999999999999"])
def test_parse_flexible_rejects_what_is_not_a_time(value):
    assert parse_flexible(value) is None


# --- key=value ------------------------------------------------------------------

def test_kv_maps_common_firewall_field_names():
    event = kv.parse_line(
        'date=2026-09-14 time=10:01:02 devname="FGT-HQ" srcip=203.0.113.50 srcport=51515 '
        'dstip=10.0.0.8 dstport=22 proto=6 action="deny"'
    )
    assert event["source_ip"] == "203.0.113.50"
    assert event["dest_ip"] == "10.0.0.8"
    assert (event["src_port"], event["dest_port"]) == (51515, 22)
    assert (event["host"], event["action"], event["protocol"]) == ("FGT-HQ", "deny", "tcp")
    assert event["event_time"] == datetime(2026, 9, 14, 10, 1, 2, tzinfo=UTC)
    assert event["raw"]["devname"] == "FGT-HQ"


def test_kv_quoted_values_keep_spaces_and_escaped_quotes():
    event = kv.parse_line(r'user="alice smith" msg="said \"hi\"" act=allowed')
    assert event["username"] == "alice smith"
    assert event["raw"]["msg"] == 'said "hi"'


def test_kv_needs_three_real_pairs():
    assert kv.parse_line("GET /search?q=1&page=2 HTTP/1.1") is None
    assert kv.parse_line("a=1 b=2") is None


def test_kv_value_that_does_not_fit_its_field_stays_in_raw_only():
    event = kv.parse_line("src=not-an-ip dpt=99999 user=bob")
    assert "source_ip" not in event and "dest_port" not in event
    assert event["raw"]["src"] == "not-an-ip"
    assert event["username"] == "bob"


def test_kv_hostile_line_of_unterminated_quotes_parses_in_linear_time():
    line = 'k="' * 80_000 + " a=1 b=2 c=3"
    started = time.perf_counter()
    kv.parse_line(line)
    assert time.perf_counter() - started < 2


# --- catch-all ------------------------------------------------------------------

def test_generic_lists_ips_but_never_makes_one_the_source_ip():
    event = generic.parse_line("backup from 203.0.113.9 to 10.0.0.2 failed; 999.1.1.1 is not an address")
    assert "source_ip" not in event
    assert event["raw"]["_ips_found"] == ["203.0.113.9", "10.0.0.2"]


def test_generic_uses_an_iso_timestamp_when_the_line_has_one():
    event = generic.parse_line("2026-09-14T08:00:00Z nightly job finished")
    assert event["event_time"] == datetime(2026, 9, 14, 8, tzinfo=UTC)
    assert "_time_inferred" not in event["raw"]


def test_generic_marks_the_time_as_inferred_otherwise():
    assert generic.parse_line("no time here")["raw"]["_time_inferred"] is True


# --- syslog RFC 5424 ----------------------------------------------------------

def test_rfc5424_sshd_message_becomes_a_login_event():
    event = syslog5424.parse_line(
        "<34>1 2026-09-14T22:14:15.003Z bastion sshd 4123 - - Failed password for root from 203.0.113.9 port 50022 ssh2"
    )
    assert event["source_type"] == "ssh"
    assert (event["action"], event["username"], event["source_ip"]) == ("login_failed", "root", "203.0.113.9")
    assert event["host"] == "bastion"
    assert event["event_time"] == datetime(2026, 9, 14, 22, 14, 15, 3000, tzinfo=UTC)


def test_rfc5424_structured_data_and_nil_timestamp():
    event = syslog5424.parse_line('<86>1 - web02 billing 88 PAY [exampleSDID@32473 iut="3"] payment timeout')
    assert event["raw"]["structured_data"] == '[exampleSDID@32473 iut="3"]'
    assert event["raw"]["app_name"] == "billing"
    assert event["raw"]["_time_inferred"] is True


def test_rfc3164_line_is_not_taken_for_rfc5424():
    assert syslog5424.parse_line("<134>Jan 10 10:00:01 fw01 kernel[0]: hello") is None


# --- JSON lines ------------------------------------------------------------------

def test_json_lines_from_other_tools_have_their_field_names_mapped():
    event = app_json.parse_line(
        '{"@timestamp": "2026-09-14T10:00:00Z", "src_ip": "203.0.113.4", "user": "bob", "event": "login_failed"}'
    )
    assert (event["source_ip"], event["username"], event["action"]) == ("203.0.113.4", "bob", "login_failed")
    assert event["event_time"] == datetime(2026, 9, 14, 10, tzinfo=UTC)


def test_json_epoch_milliseconds():
    event = app_json.parse_line('{"ts": 1789380300000, "msg": "x"}')
    assert event["event_time"] == datetime.fromtimestamp(1789380300, tz=UTC)


def test_json_own_field_names_win_and_stay_strict():
    event = app_json.parse_line('{"source_ip": "garbage", "src_ip": "203.0.113.4"}')
    assert event["source_ip"] == "garbage"  # validated later, so a forced upload rejects the line


def test_json_nan_is_not_accepted_as_json():
    assert app_json.parse_line('{"x": NaN}') is None


# --- web access log ---------------------------------------------------------------

def test_apache_dash_for_zero_bytes_is_accepted():
    event = nginx.parse_line('192.0.2.11 - - [14/Sep/2026:10:00:02 +0000] "POST /login HTTP/1.1" 302 - "-" "curl/8.4.0"')
    assert event["status_code"] == 302
    assert event["raw"]["bytes_sent"] == 0


# --- CSV --------------------------------------------------------------------------

def test_csv_sniff_recognises_a_header_and_consistent_rows():
    assert csv_format.sniff(_fixture("events.csv").splitlines()) == 1.0


def test_web_access_log_is_not_mistaken_for_csv():
    assert csv_format.sniff(_fixture("sample_nginx.log").splitlines()) < pipeline.MIN_CONFIDENCE


# --- format detection -------------------------------------------------------------

@pytest.mark.parametrize(
    "fixture,expected",
    [
        ("sample_ssh.log", "ssh"),
        ("sample_nginx.log", "nginx"),
        ("apache_combined.log", "nginx"),
        ("sample_app.jsonl", "app"),
        ("sample_syslog.log", "syslog"),
        ("mixed_auth.log", "syslog"),
        ("rfc5424.log", "syslog5424"),
        ("kv_firewall.log", "kv"),
        ("events.csv", "csv"),
    ],
)
def test_format_detection(fixture, expected):
    lines = [line for line in _fixture(fixture).splitlines() if line.strip()]
    detected, confidence = pipeline.detect_format(lines, CTX)
    assert detected == expected
    assert confidence >= pipeline.MIN_CONFIDENCE


# --- the pipeline -------------------------------------------------------------------

def test_auto_mode_keeps_every_line_even_when_nothing_recognises_it():
    report = pipeline.parse_text("just words\n\n more words 10.0.0.1\n{not json\n", "auto", CTX)
    assert (report.total_lines, report.parsed, report.skipped) == (3, 3, 0)
    assert report.by_parser == {"generic": 3}
    assert report.detected_format == "unrecognized"


def test_sshd_lines_inside_a_syslog_file_keep_their_login_fields():
    report = pipeline.parse_text(_fixture("mixed_auth.log"), "auto", CTX)
    assert report.detected_format == "syslog"
    assert report.by_parser == {"ssh": 3, "syslog": 3}
    assert sum(1 for event in report.events if event["action"] == "login_failed") == 2


def test_auto_mode_stores_a_line_with_an_impossible_date_instead_of_dropping_it():
    report = pipeline.parse_text(
        "Feb 30 10:00:00 host sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2", "auto", CTX
    )
    assert (report.parsed, report.skipped) == (1, 0)
    assert report.by_parser == {"generic": 1}


def test_forced_format_skips_what_it_cannot_parse_and_says_why():
    report = pipeline.parse_text(
        "not ssh at all\nFeb 30 10:00:00 host sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2\n",
        "ssh", CTX,
    )
    assert report.skipped_reasons == {"unrecognized_format": 1, "invalid_timestamp": 1}
    assert [sample["line"] for sample in report.skipped_samples] == [1, 2]
    assert report.confidence is None


def test_overlong_line_is_truncated_in_auto_mode_and_skipped_when_forced(monkeypatch):
    monkeypatch.setattr(pipeline, "MAX_LINE_CHARS", 100)
    line = "x" * 250

    event = pipeline.parse_text(line, "auto", CTX).events[0]
    assert len(event["raw_message"]) == 100
    assert event["raw"]["_truncated"] is True
    assert event["raw"]["_original_length"] == 250

    assert pipeline.parse_text(line, "generic", CTX).skipped_reasons == {"line_too_long": 1}


def test_too_many_lines_is_refused(monkeypatch):
    monkeypatch.setattr(pipeline, "MAX_LINES", 3)
    with pytest.raises(pipeline.TooManyLines):
        pipeline.parse_text("a\nb\nc\nd\n", "auto", CTX)


def test_json_line_with_nan_falls_through_to_plain_text():
    report = pipeline.parse_text('{"source_ip": "203.0.113.5", "x": NaN}', "auto", CTX)
    assert report.by_parser == {"generic": 1}


def test_year_hint_reaches_parsers_whose_timestamps_have_no_year():
    report = pipeline.parse_text(
        "Mar 01 10:00:00 host sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
        "auto", ParseContext(year_hint=2019),
    )
    assert report.events[0]["event_time"].year == 2019


def test_csv_upload_maps_columns_and_handles_quoted_delimiters():
    report = pipeline.parse_text(_fixture("events.csv"), "auto", CTX)
    assert report.detected_format == "csv"
    assert (report.total_lines, report.by_parser) == (3, {"csv": 3})
    last = report.events[-1]
    assert (last["username"], last["outcome"], last["dest_port"]) == ("smith, alice", "success", 443)


def test_csv_row_with_the_wrong_column_count():
    text = (
        "src_ip,user,action\n"
        "203.0.113.5,root,login_failed\n203.0.113.6,admin,login_failed\n"
        "203.0.113.7,guest,login_failed\n203.0.113.8,only-two\n203.0.113.9,oracle,login_failed\n"
    )
    strict = pipeline.parse_text(text, "csv", CTX)
    assert strict.skipped_reasons == {"column_count_mismatch": 1}

    auto = pipeline.parse_text(text, "auto", CTX)
    assert auto.detected_format == "csv"
    assert (auto.skipped, auto.by_parser) == (0, {"csv": 4, "generic": 1})
