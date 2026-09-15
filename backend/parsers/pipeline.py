"""Turns uploaded log text into events.

Whole-document formats are recognised first: Windows event XML, and JSON
arrays (Windows Get-WinEvent exports or any other tool's). Everything else is
read line by line. Auto mode samples the start of the file to report what it
is, then offers every line to the parsers in LINE_FORMATS order — most specific
first — and keeps the first reading that parses and validates. A line nothing
recognises is stored by the generic catch-all, so auto mode never drops data.

A forced format is strict: the uploader said what the file is, so lines that
format can't parse are skipped, each with a reason.

Keys starting with "_" in an event's raw data (_time_inferred, _ips_found,
_truncated) are notes added during ingestion, not part of the original log.
"""

import codecs
import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable

from pydantic import ValidationError

from models.events import EventIn
from parsers import app_json, csv_format, generic, kv, nginx, ssh, syslog, syslog5424, winevt
from parsers.base import ParseContext
from parsers.timeutil import InvalidTimestamp

MAX_LINES = 200_000
MAX_LINE_CHARS = 256_000
SAMPLE_SIZE = 50
MIN_CONFIDENCE = 0.6
MAX_SKIPPED_SAMPLES = 20
EXCERPT_CHARS = 200


class TooManyLines(ValueError):
    pass


@dataclass(frozen=True)
class LineFormat:
    name: str
    label: str
    description: str
    parse: Callable[[str, ParseContext], dict | None]


# Most specific first, and the order is fixed. An sshd line is also valid
# classic syslog, and a syslog message can contain key=value pairs; trying the
# more specific reading first keeps the fields detection rules depend on
# (username, source_ip, action=login_failed). The detected format is reported,
# never used to reorder this list — in a mixed auth.log, syslog would otherwise
# swallow every sshd line.
LINE_FORMATS: tuple[LineFormat, ...] = (
    LineFormat(
        "ssh", "OpenSSH auth log",
        "sshd login results (Failed/Accepted password or publickey), e.g. /var/log/auth.log",
        lambda line, ctx: ssh.parse_line(line, year_hint=ctx.year_hint),
    ),
    LineFormat(
        "nginx", "Web access log (Nginx / Apache combined)",
        'IP - user [time] "METHOD /path HTTP/1.1" status bytes "referer" "user agent"',
        lambda line, ctx: nginx.parse_line(line),
    ),
    LineFormat(
        "windows", "Windows Event Log",
        "Event Viewer or wevtutil XML, or PowerShell Get-WinEvent | ConvertTo-Json. "
        "Logons (4624/4625), Kerberos and NTLM failures, account and group changes, log clearing. "
        "Include the event XML in PowerShell exports to keep every field of every event ID",
        lambda line, ctx: winevt.parse_json_line(line),
    ),
    LineFormat(
        "app", "JSON",
        "JSON lines or a JSON array; common field names such as src_ip, user and @timestamp are mapped",
        lambda line, ctx: app_json.parse_line(line),
    ),
    LineFormat(
        "syslog5424", "Syslog (RFC 5424)",
        "<PRI>1 ISO-timestamp host app procid msgid [structured-data] message",
        lambda line, ctx: syslog5424.parse_line(line),
    ),
    LineFormat(
        "syslog", "Syslog (RFC 3164 / BSD)",
        "<PRI>Mon DD HH:MM:SS host process[pid]: message",
        lambda line, ctx: syslog.parse_line(line, year_hint=ctx.year_hint),
    ),
    LineFormat(
        "kv", "key=value",
        "Lines with three or more key=value pairs, typical of firewalls and appliances",
        lambda line, ctx: kv.parse_line(line),
    ),
)

GENERIC = LineFormat(
    "generic", "Plain text (catch-all)",
    "Stores any line as-is and keeps it searchable; notes an ISO timestamp and any IPs it contains",
    lambda line, ctx: generic.parse_line(line),
)

_CSV_INFO = {
    "name": "csv", "label": "CSV / TSV with a header row",
    "description": "Spreadsheet-style exports; columns such as src_ip, user and timestamp are mapped",
}

_BY_NAME = {fmt.name: fmt for fmt in (*LINE_FORMATS, GENERIC)}
FORMAT_NAMES = ("auto", *(fmt.name for fmt in LINE_FORMATS), "csv", GENERIC.name)


@dataclass
class ParseReport:
    requested_format: str
    detected_format: str
    confidence: float | None
    total_lines: int = 0
    events: list[dict] = field(default_factory=list)
    by_parser: Counter = field(default_factory=Counter)
    skipped_reasons: Counter = field(default_factory=Counter)
    skipped_samples: list[dict] = field(default_factory=list)

    @property
    def parsed(self) -> int:
        return len(self.events)

    @property
    def skipped(self) -> int:
        return sum(self.skipped_reasons.values())

    def add(self, parser_name: str, event: dict) -> None:
        self.events.append({**event, "parser": parser_name})
        self.by_parser[parser_name] += 1

    def skip(self, line_no: int, reason: str, text: str) -> None:
        self.skipped_reasons[reason] += 1
        if len(self.skipped_samples) < MAX_SKIPPED_SAMPLES:
            self.skipped_samples.append({"line": line_no, "reason": reason, "excerpt": text[:EXCERPT_CHARS]})


def decode_upload(content: bytes) -> str:
    """Upload bytes as text.

    Event Viewer's XML export and Windows PowerShell 5.1's Out-File write
    UTF-16 with a byte-order mark, which read as UTF-8 comes out as every other
    character NUL. Otherwise it is best-effort UTF-8: undecodable bytes become
    U+FFFD so a partly corrupt file degrades line by line. NUL is dropped either
    way — PostgreSQL can't store it.
    """
    if content.startswith(codecs.BOM_UTF8):
        text = content[len(codecs.BOM_UTF8):].decode("utf-8", errors="replace")
    elif content.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        text = content.decode("utf-16", errors="replace")
    else:
        text = content.decode("utf-8", errors="replace")
    return text.replace("\x00", "")


def available_formats() -> list[dict]:
    return [
        {"name": "auto", "label": "Auto-detect",
         "description": "Recognises the format from the first lines; anything no parser understands is still stored as plain text"},
        *({"name": fmt.name, "label": fmt.label, "description": fmt.description} for fmt in LINE_FORMATS),
        _CSV_INFO,
        {"name": GENERIC.name, "label": GENERIC.label, "description": GENERIC.description},
    ]


def detect_format(lines: list[str], ctx: ParseContext) -> tuple[str, float]:
    """(format name, share of sampled lines it matched). Ties go to the more
    specific format. "mixed" means no format reached MIN_CONFIDENCE."""
    sample = lines[:SAMPLE_SIZE]
    if not sample:
        return "empty", 0.0

    best_name, best_rate = "unrecognized", 0.0
    for fmt in LINE_FORMATS:
        rate = sum(1 for line in sample if _parses(fmt, line, ctx)) / len(sample)
        if rate > best_rate:
            best_name, best_rate = fmt.name, rate

    if best_rate >= MIN_CONFIDENCE:
        return best_name, round(best_rate, 3)

    csv_rate = csv_format.sniff(sample)
    if csv_rate >= MIN_CONFIDENCE:
        return "csv", round(csv_rate, 3)
    if best_rate > 0:
        return "mixed", round(best_rate, 3)
    return "unrecognized", 0.0


def parse_text(text: str, requested: str, ctx: ParseContext) -> ParseReport:
    text = text.lstrip("﻿")

    if requested in ("auto", "windows") and winevt.looks_like_xml(text):
        report = _parse_windows_xml(text, requested)
        if report is not None:
            return report

    if requested in ("auto", "windows", "app"):
        items = _json_document(text)
        if items is not None:
            return _parse_json_document(items, requested)

    numbered = [(no, line) for no, line in enumerate(text.splitlines(), start=1) if line.strip()]
    if len(numbered) > MAX_LINES:
        raise TooManyLines(f"more than {MAX_LINES} lines")

    if requested == "auto":
        detected, confidence = detect_format([line for _, line in numbered], ctx)
        report = ParseReport("auto", detected, confidence)
        if detected == "csv":
            _parse_csv(report, text, ctx, strict=False)
        else:
            report.total_lines = len(numbered)
            for line_no, line in numbered:
                _parse_line_auto(report, line_no, line, ctx)
        return report

    report = ParseReport(requested, requested, None)
    if requested == "csv":
        _parse_csv(report, text, ctx, strict=True)
        return report

    fmt = _BY_NAME[requested]
    report.total_lines = len(numbered)
    for line_no, line in numbered:
        if len(line) > MAX_LINE_CHARS:
            report.skip(line_no, "line_too_long", line)
            continue
        event, reason = _attempt(fmt, line, ctx)
        if event is None:
            report.skip(line_no, reason, line)
        else:
            report.add(fmt.name, event)
    return report


def _parse_windows_xml(text: str, requested: str) -> ParseReport | None:
    """None when the XML isn't Windows event XML, so line parsing takes over."""
    report = ParseReport(requested, "windows", 1.0 if requested == "auto" else None)
    try:
        events, error = winevt.parse_xml_document(text)
    except winevt.NotWindowsXml:
        return None
    except winevt.WindowsLogRejected as rejected:
        report.total_lines = 1
        report.skip(1, rejected.reason, text)
        return report

    report.total_lines = len(events) + (1 if error else 0)
    for index, parsed in enumerate(events, start=1):
        _add_document_item(report, "windows", index, parsed, "missing_event_id")
    if error:
        report.skip(len(events) + 1, error, "")
    return report


def _json_document(text: str) -> list[dict] | None:
    """The objects of a whole-file JSON array (or single pretty-printed object);
    None for JSON lines, which are read line by line instead."""
    stripped = text.strip()
    if not stripped.startswith(("[", "{")):
        return None
    try:
        data = json.loads(stripped, parse_constant=app_json.reject_json_constant)
    except (ValueError, RecursionError):
        return None
    items = data if isinstance(data, list) else [data]
    if not items or not all(isinstance(item, dict) for item in items):
        return None
    return items


def _parse_json_document(items: list[dict], requested: str) -> ParseReport:
    is_windows = requested == "windows" or (
        requested == "auto" and all(winevt.is_winevent_object(item) for item in items[:SAMPLE_SIZE])
    )
    name = "windows" if is_windows else "app"
    report = ParseReport(requested, name, 1.0 if requested == "auto" else None)
    report.total_lines = len(items)

    for index, item in enumerate(items, start=1):
        try:
            if is_windows:
                parsed = winevt.from_json_object(item)
            else:
                parsed = app_json.parse_object(item, json.dumps(item)[:MAX_LINE_CHARS])
        except Exception:
            report.skip(index, "parser_error", "")
            continue
        _add_document_item(report, name, index, parsed, "unrecognized_format")
    return report


def _add_document_item(report: ParseReport, name: str, index: int, parsed: dict | None, missing_reason: str) -> None:
    if parsed is None:
        report.skip(index, missing_reason, "")
        return
    event = _validate(parsed)
    if event is None:
        report.skip(index, "invalid_field", str(parsed.get("raw_message") or ""))
    else:
        report.add(name, event)


def _parse_line_auto(report: ParseReport, line_no: int, line: str, ctx: ParseContext) -> None:
    if len(line) > MAX_LINE_CHARS:
        truncated = generic.parse_line(line[:MAX_LINE_CHARS])
        truncated["raw"].update({"_truncated": True, "_original_length": len(line)})
        event = _validate(truncated)
        if event is None:
            report.skip(line_no, "invalid_field", line)
        else:
            report.add(GENERIC.name, event)
        return

    for fmt in LINE_FORMATS:
        event, _ = _attempt(fmt, line, ctx)
        if event is not None:
            report.add(fmt.name, event)
            return

    event, reason = _attempt(GENERIC, line, ctx)
    if event is None:
        report.skip(line_no, reason, line)
    else:
        report.add(GENERIC.name, event)


def _parse_csv(report: ParseReport, text: str, ctx: ParseContext, *, strict: bool) -> None:
    for line_no, row_text, parsed, reason in csv_format.rows(text):
        report.total_lines += 1
        if parsed is not None:
            event = _validate(parsed)
            if event is not None:
                report.add("csv", event)
                continue
            reason = "invalid_field"

        if strict or not row_text.strip():
            report.skip(line_no, reason, row_text)
            continue

        event, fallback_reason = _attempt(GENERIC, row_text, ctx)
        if event is None:
            report.skip(line_no, fallback_reason, row_text)
        else:
            report.add(GENERIC.name, event)


def _parses(fmt: LineFormat, line: str, ctx: ParseContext) -> bool:
    try:
        return fmt.parse(line, ctx) is not None
    except Exception:
        return False


def _attempt(fmt: LineFormat, line: str, ctx: ParseContext) -> tuple[dict | None, str | None]:
    """(validated event, None) or (None, why it was rejected)."""
    try:
        parsed = fmt.parse(line, ctx)
    except InvalidTimestamp:
        return None, "invalid_timestamp"
    except Exception:
        # A parser bug on one hostile line must not fail the upload. The line
        # itself is never logged: it is attacker-controlled.
        return None, "parser_error"
    if parsed is None:
        return None, "unrecognized_format"
    event = _validate(parsed)
    return (event, None) if event is not None else (None, "invalid_field")


def _validate(parsed: dict) -> dict | None:
    try:
        return EventIn(**parsed).model_dump()
    except ValidationError:
        return None
