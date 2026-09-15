"""Linux netfilter (iptables / nftables / UFW) and CEF parsing, on synthetic
lines shaped like the real products' output. No database."""

import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from parsers import cef, iptables, pipeline
from parsers.base import ParseContext

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CTX = ParseContext()
UTC = timezone.utc

UFW = (FIXTURES / "ufw.log").read_text(encoding="utf-8").splitlines()
CEF = (FIXTURES / "cef.log").read_text(encoding="utf-8").splitlines()


# --- netfilter ----------------------------------------------------------------------

def test_ufw_block_carries_addresses_ports_and_the_rule_prefix():
    event = iptables.parse_line(UFW[0])
    assert (event["source_type"], event["action"]) == ("firewall", "blocked")
    assert (event["source_ip"], event["dest_ip"]) == ("203.0.113.99", "10.0.0.5")
    assert (event["protocol"], event["src_port"], event["dest_port"]) == ("tcp", 40404, 3389)
    assert event["host"] == "fw01"
    assert event["raw"]["prefix"] == "[UFW BLOCK]"
    assert event["raw"]["flags"] == ["SYN"]
    assert (event["raw"]["ttl"], event["raw"]["in"]) == ("242", "eth0")


def test_ufw_allow_and_audit():
    assert iptables.parse_line(UFW[1])["action"] == "allowed"
    audit = iptables.parse_line(UFW[4])
    assert audit["action"] == "audit"
    # A bare dmesg line has no syslog header: no host, and the time is inferred.
    assert "host" not in audit
    assert audit["raw"]["_time_inferred"] is True


def test_icmp_has_no_ports():
    event = iptables.parse_line(UFW[2])
    assert event["protocol"] == "icmp"
    assert "dest_port" not in event and "src_port" not in event


def test_custom_iptables_prefix_over_ipv6():
    event = iptables.parse_line(UFW[3])
    assert (event["action"], event["source_ip"], event["dest_port"]) == ("blocked", "2001:db8::66", 53)
    assert event["raw"]["prefix"] == "IPTABLES-DROP:"


@pytest.mark.parametrize(
    "line",
    [
        "user logged IN=yes from somewhere",
        "Sep 14 10:00:00 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=not-an-ip DST=10.0.0.5 PROTO=TCP",
        "IN=eth0 SRC=203.0.113.9 DST=10.0.0.5",  # no OUT=, so not netfilter's format
    ],
)
def test_lines_that_are_not_netfilter_logs(line):
    assert iptables.parse_line(line) is None


# --- CEF --------------------------------------------------------------------------------

def test_palo_alto_traffic_deny():
    event = cef.parse_line(CEF[0])
    assert (event["source_type"], event["action"]) == ("firewall", "blocked")
    assert (event["source_ip"], event["dest_ip"], event["dest_port"], event["protocol"]) == (
        "203.0.113.120", "10.0.0.20", 3389, "tcp",
    )
    assert event["host"] == "pa-fw01"
    assert event["event_code"] == "end"
    assert event["event_time"] == datetime(2026, 9, 14, 10, 30, tzinfo=UTC)  # rt=… GMT
    assert (event["raw"]["vendor"], event["raw"]["name"]) == ("Palo Alto Networks", "TRAFFIC")
    assert "username" not in event  # suser= and duser= are empty


def test_fortinet_with_a_priority_header_and_an_escaped_equals_sign():
    event = cef.parse_line(CEF[1])
    assert (event["action"], event["dest_port"]) == ("blocked", 22)
    assert event["protocol"] == "tcp"  # logged as IANA number 6
    assert event["host"] == "fgt01"
    assert event["raw"]["extension"]["msg"] == "policy = deny-all, rule id 7"
    assert event["event_time"] == datetime(2026, 9, 14, 10, 30, 5, tzinfo=UTC)


@pytest.mark.parametrize(
    "value,expected",
    [(6, "tcp"), ("17", "udp"), ("1", "icmp"), ("58", "ipv6-icmp"), ("TCP", "tcp"), ("999", "999"), ("", None), (None, None)],
)
def test_protocol_numbers_and_names_normalise_to_one_spelling(value, expected):
    from parsers.fields import normalize_protocol

    assert normalize_protocol(value) == expected


def test_check_point_epoch_time_and_escaped_backslash():
    event = cef.parse_line(CEF[2])
    assert event["action"] == "blocked"
    assert event["username"] == "CORP\\alice"
    assert event["event_time"] == datetime.fromtimestamp(1789381200, tz=UTC)


def test_non_firewall_cef_keeps_its_own_source_type():
    event = cef.parse_line(CEF[3])  # the example from the ArcSight CEF specification
    assert (event["source_type"], event["action"]) == ("cef", "cef_event")
    assert event["raw"]["extension"]["filePath"] == "C:\\Windows\\temp\\x.exe"
    assert event["raw"]["extension"]["msg"] == "Detected a threat. No action needed."


def test_header_escapes():
    event = cef.parse_line(r"CEF:0|Acme\|Inc|Gate|1|42|name with \\ slash|3|src=203.0.113.5")
    assert event["raw"]["vendor"] == "Acme|Inc"
    assert event["raw"]["name"] == "name with \\ slash"
    assert event["source_ip"] == "203.0.113.5"


def test_an_equals_sign_inside_a_value_does_not_start_a_new_key():
    event = cef.parse_line("CEF:0|V|P|1|s|n|1|msg=a=b c=d")
    assert event["raw"]["extension"] == {"msg": "a=b", "c": "d"}


@pytest.mark.parametrize("line", ["CEF:0|only|three|fields", "not cef at all", "CEF:x|V|P|1|s|n|1|src=1.2.3.4"])
def test_lines_that_are_not_cef(line):
    assert cef.parse_line(line) is None


def test_hostile_extension_parses_in_linear_time():
    line = "CEF:0|V|P|1|s|n|1|" + "a=" * 60_000 + "\\" * 60_000 + " src=203.0.113.5"
    started = time.perf_counter()
    cef.parse_line(line)
    assert time.perf_counter() - started < 2


# --- through the pipeline ------------------------------------------------------------------

@pytest.mark.parametrize("fixture,expected", [("ufw.log", "iptables"), ("cef.log", "cef")])
def test_detection(fixture, expected):
    lines = (FIXTURES / fixture).read_text(encoding="utf-8").splitlines()
    detected, confidence = pipeline.detect_format(lines, CTX)
    assert detected == expected
    assert confidence == 1.0


def test_firewall_lines_are_not_swallowed_by_the_syslog_parser():
    report = pipeline.parse_text("\n".join(UFW), "auto", CTX)
    assert report.by_parser == {"iptables": 5}
    report = pipeline.parse_text("\n".join(CEF), "auto", CTX)
    assert report.by_parser == {"cef": 4}
