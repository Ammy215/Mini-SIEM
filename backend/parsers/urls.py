"""Normalising a request URL, for every path that stores one."""

from urllib.parse import unquote, unquote_plus


def decode_url(url: str) -> str:
    """Percent-decode a request URL so signature rules match what the attacker
    actually meant, not its wire encoding.

    Real HTTP clients encode payloads: `' OR 1=1` arrives as `%27+OR+1%3d1`,
    `<script>` as `%3cscript%3e`, `../` as `..%2f`. Matching literal patterns
    against the raw line silently misses all of it.

    Path and query are decoded separately because `+` only means a space in the
    query string — in a path it is a literal plus.

    `%00` decodes to U+0000, which PostgreSQL TEXT cannot store, so a real log
    line using the old NUL-truncation trick (`boot.ini%00.jpg`) would otherwise
    fail the whole upload with a 500. The NUL is dropped, as the file reader
    already does for raw bytes — which also means the trick cannot hide the rest
    of the payload from a rule.
    """
    path, sep, query = url.partition("?")
    decoded = unquote(path) if not sep else f"{unquote(path)}?{unquote_plus(query)}"
    return decoded.replace("\x00", "")
