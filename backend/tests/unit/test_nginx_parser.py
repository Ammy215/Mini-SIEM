"""The four log lines below are verbatim from a real capture: a real Python
HTTP server logging real curl requests. They are the exact wire encodings that
previously slipped past signature detection."""

from parsers.nginx import decode_url, parse_line

REAL_SQLI_TAUTOLOGY = '127.0.0.1 - - [20/Aug/2026:23:09:19 +0530] "GET /search.html?q=%27+OR+1%3d1 HTTP/1.1" 200 0 "-" "curl/8.15.0"'
REAL_SQLI_UNION = '127.0.0.1 - - [20/Aug/2026:23:09:19 +0530] "GET /search.html?q=1%27+UNION+SELECT+username%2cpassword+FROM+users-- HTTP/1.1" 200 0 "-" "curl/8.15.0"'
REAL_XSS = '127.0.0.1 - - [20/Aug/2026:23:09:19 +0530] "GET /search.html?q=%3cscript%3ealert%28document.cookie%29%3c%2fscript%3e HTTP/1.1" 200 0 "-" "curl/8.15.0"'
REAL_TRAVERSAL = '127.0.0.1 - - [20/Aug/2026:23:09:20 +0530] "GET /view?file=..%2f..%2f..%2f..%2fetc%2fpasswd HTTP/1.1" 404 0 "-" "curl/8.15.0"'
REAL_BENIGN = '127.0.0.1 - - [20/Aug/2026:23:11:03 +0530] "GET /reports.html HTTP/1.1" 200 0 "http://127.0.0.1:8090/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/151.0.7922.34 Safari/537.36"'


def test_decode_url_query_string_plus_is_a_space():
    assert decode_url("/search.html?q=%27+OR+1%3d1") == "/search.html?q=' OR 1=1"


def test_decode_url_path_plus_stays_literal():
    # `+` only means space in a query string; in a path it is a literal plus.
    assert decode_url("/a+b/c") == "/a+b/c"
    assert decode_url("/a+b?x=1+2") == "/a+b?x=1 2"


def test_decode_url_leaves_unencoded_urls_untouched():
    assert decode_url("/reports.html") == "/reports.html"


def test_real_sqli_tautology_decodes_to_matchable_text():
    e = parse_line(REAL_SQLI_TAUTOLOGY)
    assert e["url"] == "/search.html?q=' OR 1=1"


def test_real_union_select_decodes_with_a_real_space():
    e = parse_line(REAL_SQLI_UNION)
    # Previously "UNION+SELECT" never matched the "UNION SELECT" pattern.
    assert "UNION SELECT" in e["url"]


def test_real_xss_decodes_to_a_script_tag():
    e = parse_line(REAL_XSS)
    assert "<script>" in e["url"]


def test_real_traversal_decodes_to_dot_dot_slash():
    e = parse_line(REAL_TRAVERSAL)
    assert "../" in e["url"]
    assert "/etc/passwd" in e["url"]


def test_original_encoded_url_is_preserved_for_the_record():
    e = parse_line(REAL_TRAVERSAL)
    assert e["raw"]["url_raw"] == "/view?file=..%2f..%2f..%2f..%2fetc%2fpasswd"
    assert e["raw"]["url_was_encoded"] is True
    # The verbatim log line is kept too.
    assert e["raw_message"] == REAL_TRAVERSAL


def test_benign_real_browser_request_is_unaffected():
    e = parse_line(REAL_BENIGN)
    assert e["url"] == "/reports.html"
    assert e["raw"]["url_was_encoded"] is False
    assert e["status_code"] == 200
    assert "HeadlessChrome" in e["user_agent"]


# A browser percent-encodes spaces in a URL. An attacker writing the request
# line by hand need not, and nginx logs whatever arrived. Splitting the request
# field into exactly three tokens therefore dropped the requests most worth
# detecting: url, status_code and user_agent were all lost to the generic
# parser, so the SQLi and scanner-UA rules could never match them.
SQLI_WITH_LITERAL_SPACES = (
    '203.0.113.5 - - [10/Jan/2026:10:00:02 +0000] '
    '"GET /products?id=1\' OR 1=1-- HTTP/1.1" 500 128 "-" "sqlmap/1.6"'
)


def test_request_line_with_unencoded_spaces_still_parses():
    e = parse_line(SQLI_WITH_LITERAL_SPACES)
    assert e is not None
    assert e["method"] == "GET"
    assert e["url"] == "/products?id=1' OR 1=1--"
    assert e["status_code"] == 500
    assert e["user_agent"] == "sqlmap/1.6"


def test_unencoded_spaces_keep_the_text_the_sqli_rule_matches():
    e = parse_line(SQLI_WITH_LITERAL_SPACES)
    assert "' OR 1=1" in e["url"]


def test_unencoded_spaces_keep_the_user_agent_the_scanner_rule_matches():
    e = parse_line(SQLI_WITH_LITERAL_SPACES)
    assert "sqlmap" in e["user_agent"]


def test_xss_payload_with_spaces_survives():
    line = ('198.51.100.9 - - [10/Jan/2026:10:00:04 +0000] '
            '"GET /s?q=<script> alert(1) </script> HTTP/1.1" 200 300 "-" "Mozilla/5.0"')
    assert parse_line(line)["url"] == "/s?q=<script> alert(1) </script>"


def test_a_request_field_that_is_not_a_request_line_is_left_to_generic():
    # Raw TLS bytes sent to an HTTP port; nginx logs them verbatim.
    line = '203.0.113.9 - - [10/Jan/2026:10:00:05 +0000] "\x16\x03\x01" 400 0 "-" "-"'
    assert parse_line(line) is None


def test_a_request_without_a_protocol_is_left_to_generic():
    line = '203.0.113.9 - - [10/Jan/2026:10:00:06 +0000] "GET /only-two" 400 0 "-" "-"'
    assert parse_line(line) is None
