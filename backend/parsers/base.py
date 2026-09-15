from dataclasses import dataclass


@dataclass(frozen=True)
class ParseContext:
    """Per-upload options a parser may use."""

    # For formats whose timestamps carry no year (classic syslog, OpenSSH).
    year_hint: int | None = None
