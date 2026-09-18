"""A URL is stored percent-decoded whichever door the event came in by.

The nginx parser decoded what it parsed, but an event posted to /api/ingest kept
the wire form — so `%27%20OR%201%3D1` matched no signature rule and SQLi, XSS and
traversal sent through the ingest API went undetected. Decoding moved to the
shared write path; these pin both that and the NUL case that came with it.
"""

import json

from ingest_service import _event_to_row, _normalised_url
from parsers.nginx import parse_line
from parsers.urls import decode_url

# Column order in _INSERT_SQL.
URL_COLUMN = 9
RAW_COLUMN = 13


def test_encoded_sqli_posted_to_ingest_is_stored_decoded():
    url, _ = _normalised_url({"url": "/products?id=%27%20OR%201%3D1--"})
    assert url == "/products?id=' OR 1=1--"


def test_encoded_xss_and_traversal_are_stored_decoded():
    assert _normalised_url({"url": "/s?q=%3Cscript%3E"})[0] == "/s?q=<script>"
    assert _normalised_url({"url": "/view?f=..%2f..%2fetc%2fpasswd"})[0] == "/view?f=../../etc/passwd"


def test_the_wire_form_is_kept_in_raw():
    url, raw = _normalised_url({"url": "/a?q=%27", "raw": {"host": "web01"}})
    assert url == "/a?q='"
    assert raw == {"host": "web01", "url_raw": "/a?q=%27"}


def test_an_event_with_no_raw_still_records_the_wire_form():
    url, raw = _normalised_url({"url": "/a?q=%27"})
    assert url == "/a?q='" and raw == {"url_raw": "/a?q=%27"}


def test_a_plain_url_is_left_exactly_as_it_was():
    """No decoding to do means raw is untouched — not rewritten to {}."""
    url, raw = _normalised_url({"url": "/dashboard", "raw": None})
    assert url == "/dashboard" and raw is None


def test_a_literal_plus_in_a_path_survives():
    assert _normalised_url({"url": "/a+b/c"})[0] == "/a+b/c"


def test_events_without_a_url_are_unaffected():
    assert _normalised_url({"source_type": "ssh"}) == (None, None)


def test_a_url_that_is_not_a_string_does_not_crash_the_write():
    """Parsers coerce it, but the shared writer must not depend on that."""
    assert _normalised_url({"url": 8080}) == (8080, None)


def test_the_row_built_for_insert_carries_the_decoded_url():
    row = _event_to_row({"source_type": "nginx", "url": "/p?id=%27+OR+1%3d1"}, None)
    assert row[URL_COLUMN] == "/p?id=' OR 1=1"
    assert json.loads(row[RAW_COLUMN])["url_raw"] == "/p?id=%27+OR+1%3d1"


# --- NUL truncation ---------------------------------------------------------

def test_decoding_never_yields_a_nul_byte():
    """`%00` decodes to U+0000, which PostgreSQL TEXT cannot store: a real log
    line using the old truncation trick would have failed the whole upload."""
    assert decode_url("/a?file=boot.ini%00.jpg") == "/a?file=boot.ini.jpg"
    assert "\x00" not in decode_url("/%00")


def test_an_nginx_line_with_an_encoded_nul_parses_to_storable_text():
    line = ('127.0.0.1 - - [20/Aug/2026:23:09:19 +0530] '
            '"GET /a?file=boot.ini%00.jpg HTTP/1.1" 200 0 "-" "curl/8"')
    event = parse_line(line)
    assert "\x00" not in event["url"]


def test_the_rest_of_a_payload_after_a_nul_is_still_matchable():
    """Dropping the NUL rather than truncating means the trick hides nothing."""
    assert decode_url("/v?f=%00../../etc/passwd") == "/v?f=../../etc/passwd"
