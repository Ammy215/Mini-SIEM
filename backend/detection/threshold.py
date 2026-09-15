"""Threshold rules: events counted per group over a time window.

The rules themselves are data (rules_yaml/*.yml, editable on the Rules page);
detection/rule_engine.py evaluates them.
"""

from detection import rule_engine


async def run_all(conn) -> dict[str, int]:
    return await rule_engine.run_rules(conn, "threshold")
