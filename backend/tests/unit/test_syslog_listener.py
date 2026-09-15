"""The live syslog listener's safety checks and message handling, without sockets."""

from types import SimpleNamespace

import pytest

from ingest_listener import syslog_server as syslog
from parsers import pipeline
from parsers.base import ParseContext


def _settings(**overrides):
    base = dict(
        enable_syslog_listener=True, syslog_host="127.0.0.1", syslog_port=5514,
        syslog_allowed_sources="127.0.0.1/32", syslog_rate_per_second=200, syslog_burst=1000, app_env="development",
    )
    return SimpleNamespace(**{**base, **overrides})


def test_an_allowlist_takes_addresses_and_ranges():
    assert [str(n) for n in syslog.parse_allowlist("192.168.1.0/24, 10.0.0.5")] == ["192.168.1.0/24", "10.0.0.5/32"]


@pytest.mark.parametrize("text", ["", " , ", None])
def test_an_empty_allowlist_is_refused(text):
    with pytest.raises(syslog.ListenerConfigError, match="must list the senders"):
        syslog.parse_allowlist(text)


def test_a_malformed_allowlist_entry_is_refused():
    with pytest.raises(syslog.ListenerConfigError, match="isn't an IP address"):
        syslog.parse_allowlist("192.168.1.0/24,not-an-ip")


@pytest.mark.parametrize(
    "peer,allowed",
    [
        ("192.168.1.77", True), ("192.168.2.1", False), ("127.0.0.1", True),
        ("::ffff:127.0.0.1", True), ("::1", False), ("garbage", False), ("", False),
    ],
)
def test_senders_are_checked_against_the_allowlist(peer, allowed):
    networks = syslog.parse_allowlist("192.168.1.0/24,127.0.0.1")
    assert syslog.is_allowed(peer, networks) is allowed


@pytest.mark.parametrize(
    "host,env,refused",
    [("0.0.0.0", "production", True), ("::", "production", True), ("", "production", True),
     ("0.0.0.0", "development", False), ("192.168.1.10", "production", False)],
)
def test_every_interface_is_refused_in_production(host, env, refused):
    if refused:
        with pytest.raises(syslog.ListenerConfigError, match="every interface"):
            syslog.check_bind(host, env)
    else:
        syslog.check_bind(host, env)


def test_a_token_bucket_allows_a_burst_then_its_rate():
    bucket = syslog.TokenBucket(rate=1, burst=2, now=0)
    assert [bucket.take(now=0) for _ in range(3)] == [True, True, False]
    assert bucket.take(now=1) is True
    assert bucket.take(now=1) is False


def test_newline_framing():
    assert syslog.split_frames(b"<34>one\n<34>two\npartial") == ([b"<34>one", b"<34>two"], b"partial", False)


def test_octet_counted_framing():
    message = b"<34>1 2026-09-14T22:14:15Z host app - - - hello"
    stream = b"%d %s" % (len(message), message) * 2 + b"12 <3"
    assert syslog.split_frames(stream) == ([message, message], b"12 <3", False)


def test_a_plain_line_starting_with_a_number_is_not_octet_counted():
    assert syslog.split_frames(b"12 apples\n") == ([b"12 apples"], b"", False)


# Short ids: pytest puts a test's id in an environment variable, and a 64 KB one
# is over Windows' 32,767-character limit.
@pytest.mark.parametrize(
    "stream", [b"x" * (syslog.MAX_TCP_MESSAGE_BYTES + 1), b"999999 <34>"], ids=["long-line", "huge-octet-count"]
)
def test_an_oversize_message_closes_the_connection(stream):
    assert syslog.split_frames(stream)[2] is True


def test_rfc3164_loses_its_priority_prefix_but_rfc5424_keeps_it():
    line, extra = syslog.prepare_line("<38>Mar  1 10:00:00 host sshd[1]: Failed password\x00\r\n")
    assert line == "Mar  1 10:00:00 host sshd[1]: Failed password"
    assert extra == {"via": "syslog", "facility": 4, "severity": 6}

    rfc5424 = "<34>1 2026-09-14T22:14:15Z host app - - - hello"
    assert syslog.prepare_line(rfc5424)[0] == rfc5424
    assert syslog.prepare_line("no header at all") == ("no header at all", {"via": "syslog"})


def test_streamed_lines_are_each_parsed_and_none_dropped():
    report = pipeline.parse_lines(
        ["", "not a known format ✓", "Mar  1 10:00:00 host sshd[7]: Failed password for root from 203.0.113.5 port 22 ssh2"],
        ParseContext(),
    )
    assert report.total_lines == 2
    assert [e["parser"] for e in report.events] == ["generic", "ssh"]


def test_the_listener_is_off_unless_switched_on():
    assert syslog.from_settings(None, _settings(enable_syslog_listener=False)) is None


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"syslog_allowed_sources": ""}, "must list the senders"),
        ({"syslog_host": "0.0.0.0", "app_env": "production"}, "every interface"),
        ({"syslog_port": 0}, "SYSLOG_PORT"),
    ],
)
def test_unsafe_settings_stop_it_starting(overrides, message):
    with pytest.raises(syslog.ListenerConfigError, match=message):
        syslog.from_settings(None, _settings(**overrides))


def test_valid_settings_give_a_listener_ready_to_start():
    listener = syslog.from_settings(None, _settings())
    assert (listener.host, listener.port, [str(n) for n in listener.allowed]) == ("127.0.0.1", 5514, ["127.0.0.1/32"])
