"""CSV and TSV exports with a header row — spreadsheets, SIEM and EDR exports,
database audit dumps. Column names are mapped through parsers.fields, so
`src_ip`, `user` or `timestamp` columns land in the right event fields.

Values are stored as text only. Nothing here writes CSV back out; if an export
is ever added, cells starting with = + - @ must be escaped against formula
injection when opened in a spreadsheet.
"""

import csv
import io
import ipaddress
from collections.abc import Iterator

from parsers.fields import normalize

SAMPLE_LINES = 50
_DELIMITERS = (",", "\t", ";", "|")

# A single cell larger than this is rejected by the reader rather than held in memory.
csv.field_size_limit(256_000)


def sniff(sample_lines: list[str]) -> float:
    """Share of sample rows whose column count matches a plausible header row."""
    choice = _best_delimiter(sample_lines)
    return choice[1] if choice else 0.0


def rows(text: str) -> Iterator[tuple[int, str, dict | None, str | None]]:
    """Yields (line_number, row_text, event, skip_reason) for each data row;
    exactly one of event and skip_reason is set."""
    choice = _best_delimiter(text.splitlines()[:SAMPLE_LINES])
    delimiter = choice[0] if choice else ","
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
    header: list[str] | None = None

    while True:
        try:
            row = next(reader)
        except StopIteration:
            return
        except csv.Error:
            if header is None:
                return
            yield reader.line_num, "", None, "malformed_csv_row"
            continue

        if not any(cell.strip() for cell in row):
            continue
        if header is None:
            header = [cell.strip() for cell in row]
            continue

        row_text = delimiter.join(row)
        if len(row) != len(header):
            yield reader.line_num, row_text, None, "column_count_mismatch"
            continue
        event = normalize(dict(zip(header, row)), source_type="csv", raw_message=row_text)
        yield reader.line_num, row_text, event, None


def _best_delimiter(lines: list[str]) -> tuple[str, float] | None:
    """The delimiter under which the first row reads as a header and the most
    rows share its column count, with that share.

    Not csv.Sniffer: it gives up unless about 90% of lines agree, so an export
    with a few ragged rows would never be recognised, whatever threshold the
    caller asks for. The reader used here is quote-aware, so a quoted
    "smith, alice" counts as one cell.
    """
    lines = [line for line in lines if line.strip()]
    if len(lines) < 2:
        return None

    best: tuple[str, float] | None = None
    for delimiter in _DELIMITERS:
        try:
            parsed = list(csv.reader(lines, delimiter=delimiter))
        except csv.Error:
            continue
        header, body = parsed[0], parsed[1:]
        if not _is_header(header):
            continue
        share = sum(1 for row in body if len(row) == len(header)) / len(body)
        if best is None or share > best[1]:
            best = (delimiter, share)
    return best


def _is_header(cells: list[str]) -> bool:
    names = [cell.strip() for cell in cells]
    if len(names) < 2 or not all(names) or len({name.lower() for name in names}) != len(names):
        return False
    return not any(_looks_like_data(name) for name in names)


def _looks_like_data(value: str) -> bool:
    if len(value) > 64:
        return True
    try:
        float(value)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
