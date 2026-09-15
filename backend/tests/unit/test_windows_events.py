"""Windows Event Log parsing on synthetic exports shaped like Event Viewer,
wevtutil and PowerShell output. No database."""

import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from parsers import pipeline, winevt
from parsers.base import ParseContext

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CTX = ParseContext()
UTC = timezone.utc

XML_EXPORT = (FIXTURES / "windows_security.xml").read_text(encoding="utf-8")
JSON_EXPORT = (FIXTURES / "windows_events.json").read_text(encoding="utf-8")

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol9 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<Events><Event><System><EventID>4625</EventID></System><EventData><Data Name="TargetUserName">&lol9;</Data></EventData></Event></Events>"""

XXE = """<?xml version="1.0"?>
<!DOCTYPE Events [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Events><Event><System><EventID>4625</EventID></System><EventData><Data Name="TargetUserName">&xxe;</Data></EventData></Event></Events>"""


def _by_code(events):
    return {event["event_code"]: event for event in events if event}


@pytest.fixture(scope="module")
def xml_events():
    events, error = winevt.parse_xml_document(XML_EXPORT)
    assert error is None
    return _by_code(events)


# --- XML ----------------------------------------------------------------------------

def test_failed_logon_4625_carries_what_brute_force_detection_needs(xml_events):
    event = xml_events["4625"]
    assert (event["action"], event["outcome"]) == ("login_failed", "failure")
    assert (event["username"], event["source_ip"], event["src_port"]) == ("administrator", "203.0.113.66", 49822)
    assert event["host"] == "WS01.corp.example"
    assert event["source_type"] == "windows"
    assert event["raw"]["logon_type"] == "3"
    assert event["raw"]["status"] == "0xc000006d"
    assert event["raw"]["workstation"] == "ATTACKBOX"
    assert event["raw_message"] == "An account failed to log on."
    # Windows writes 9 fractional digits; they are cut to microseconds, not rejected.
    assert event["event_time"] == datetime(2026, 9, 14, 10, 15, 2, 123456, tzinfo=UTC)


def test_successful_logon_uses_the_target_account_and_unwraps_ipv4_mapped_addresses(xml_events):
    event = xml_events["4624"]
    assert (event["action"], event["outcome"]) == ("login_success", "success")
    assert event["username"] == "jsmith"  # not the machine account in SubjectUserName
    assert event["source_ip"] == "192.0.2.50"
    assert event["raw"]["logon_type"] == "10"


@pytest.mark.parametrize(
    "code,action,username",
    [
        ("4672", "privileged_logon", "jsmith"),
        ("4720", "account_created", "backdoor"),
        ("4732", "group_member_added", "CN=backdoor,CN=Users,DC=corp,DC=example"),
        ("1102", "audit_log_cleared", "jsmith"),       # fields live in UserData, not EventData
        ("7045", "winevent", None),                      # unmapped event ID: kept, no guessed user
    ],
)
def test_other_security_events_are_classified(xml_events, code, action, username):
    event = xml_events[code]
    assert event["action"] == action
    assert event.get("username") == username


def test_group_membership_change_records_the_group(xml_events):
    assert xml_events["4732"]["raw"]["group_name"] == "Administrators"


def test_unmapped_event_keeps_all_its_named_data(xml_events):
    event = xml_events["7045"]
    assert event["raw"]["event_data"]["ImagePath"] == r"C:\Users\Public\updater.exe"
    assert "outcome" not in event


def test_domain_controller_kerberos_and_ntlm_failures_count_as_failed_logins(xml_events):
    kerberos, ntlm = xml_events["4771"], xml_events["4776"]
    assert (kerberos["action"], kerberos["username"], kerberos["source_ip"]) == ("login_failed", "svc_sql", "203.0.113.67")
    assert (ntlm["action"], ntlm["username"], ntlm["raw"]["workstation"]) == ("login_failed", "helpdesk", "WS22")


def test_ntlm_validation_with_a_zero_status_is_a_success():
    xml = XML_EXPORT.replace("<Data Name=\"Status\">0xc000006a</Data>", "<Data Name=\"Status\">0x0</Data>")
    events, _ = winevt.parse_xml_document(xml)
    assert _by_code(events)["4776"]["action"] == "credential_validated"


def test_wevtutil_output_without_a_root_element():
    one = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><Computer>A</Computer></System></Event>'
    events, error = winevt.parse_xml_document(one + one)
    assert (len(events), error) == (2, None)


def test_xml_of_another_kind_is_left_to_other_parsers():
    with pytest.raises(winevt.NotWindowsXml):
        winevt.parse_xml_document('<?xml version="1.0"?><rss><channel/></rss>')


def test_document_cut_off_mid_event_keeps_the_events_before_it():
    events, error = winevt.parse_xml_document(XML_EXPORT.split("<Event xmlns", 3)[0] + "<Event xmlns" + XML_EXPORT.split("<Event xmlns", 3)[1] + "<Event><System>")
    assert len(events) == 1
    assert error == "malformed_xml"


# --- XML attacks ----------------------------------------------------------------------

@pytest.mark.parametrize("payload", [BILLION_LAUGHS, XXE], ids=["billion-laughs", "xxe"])
def test_documents_with_a_dtd_are_refused_before_parsing(payload):
    started = time.perf_counter()
    with pytest.raises(winevt.WindowsLogRejected) as rejected:
        winevt.parse_xml_document(payload)
    assert rejected.value.reason == "xml_dtd_forbidden"
    assert time.perf_counter() - started < 1


def test_a_dtd_hidden_past_the_quick_check_is_still_refused_by_defusedxml():
    hidden = XXE.replace('<?xml version="1.0"?>', '<?xml version="1.0"?><!--' + "x" * 70_000 + "-->")
    with pytest.raises(winevt.WindowsLogRejected) as rejected:
        winevt.parse_xml_document(hidden)
    assert rejected.value.reason == "xml_forbidden_construct"


def test_absurdly_deep_nesting_is_refused():
    deep = "<Events>" + "<a>" * 100 + "</a>" * 100 + "</Events>"
    with pytest.raises(winevt.WindowsLogRejected) as rejected:
        winevt.parse_xml_document(deep)
    assert rejected.value.reason == "xml_too_deep"


# --- PowerShell JSON ---------------------------------------------------------------------

@pytest.fixture(scope="module")
def json_events():
    items = pipeline._json_document(JSON_EXPORT)
    return [winevt.from_json_object(item) for item in items]


def test_positional_4625_properties_map_to_named_fields(json_events):
    event = json_events[0]
    assert (event["action"], event["username"], event["source_ip"], event["src_port"]) == (
        "login_failed", "administrator", "203.0.113.66", 49822,
    )
    assert event["raw"]["logon_type"] == "3"
    assert event["event_time"] == datetime.fromtimestamp(1789380300, tz=UTC)  # "/Date(ms)/"


def test_event_ids_without_a_verified_field_order_are_not_guessed(json_events):
    event = json_events[1]
    assert (event["event_code"], event["action"]) == ("4720", "account_created")
    assert "username" not in event
    assert event["raw"]["event_data"] == {"Data0": "backdoor", "Data1": "CORP"}


def test_an_embedded_xml_property_gives_named_fields(json_events):
    event = json_events[2]
    assert (event["action"], event["username"], event["source_ip"]) == ("login_success", "jsmith", "192.0.2.50")


def test_one_compact_event_object_per_line():
    line = '{"Id":4625,"TimeCreated":"/Date(1789380300000)/","MachineName":"WS01","Properties":[' + ",".join(
        '{"Value":"%s"}' % value for value in
        ["S-1-0-0", "-", "-", "0x0", "S-1-0-0", "root", "CORP", "0xc000006d", "%%2313", "0xc000006a", "3",
         "NtLmSsp", "NTLM", "X", "-", "-", "0", "0", "-", "203.0.113.90", "4000"]
    ) + "]}"
    event = winevt.parse_json_line(line)
    assert (event["username"], event["source_ip"]) == ("root", "203.0.113.90")


# --- through the upload pipeline ------------------------------------------------------------

def test_utf16_event_viewer_export_is_decoded_and_detected():
    content = XML_EXPORT.encode("utf-16")  # with a byte-order mark, as Event Viewer saves it
    report = pipeline.parse_text(pipeline.decode_upload(content), "auto", CTX)
    assert (report.detected_format, report.skipped) == ("windows", 0)
    assert report.by_parser == {"windows": 9}


def test_utf8_bom_is_stripped():
    assert pipeline.decode_upload(b"\xef\xbb\xbfhello") == "hello"


def test_powershell_json_export_is_detected_as_windows():
    report = pipeline.parse_text(JSON_EXPORT, "auto", CTX)
    assert (report.detected_format, report.by_parser, report.skipped) == ("windows", {"windows": 3}, 0)


def test_billion_laughs_upload_is_skipped_with_a_reason_not_expanded():
    report = pipeline.parse_text(BILLION_LAUGHS, "auto", CTX)
    assert (report.parsed, report.skipped_reasons) == (0, {"xml_dtd_forbidden": 1})


def test_non_windows_json_array_is_mapped_like_json_lines():
    text = '[\n  {"src_ip": "203.0.113.4", "user": "bob", "event": "login_failed"},\n  {"src_ip": "203.0.113.5"}\n]'
    report = pipeline.parse_text(text, "auto", CTX)
    assert (report.detected_format, report.by_parser) == ("app", {"app": 2})
    assert report.events[0]["username"] == "bob"
