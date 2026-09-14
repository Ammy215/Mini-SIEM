"""Built-in detection rules: the definitions the app ships with, and how they
reach the rules table."""

import json

from detection import signature, threshold

# A built-in nobody has edited keeps tracking the shipped definition on every
# startup, so a tuned pattern (like dropping the bare "--" from the SQLi rule)
# reaches existing databases without anyone bumping a version number. A rule
# someone edited on the Rules page is left exactly as they saved it, until an
# admin resets it. `enabled` is never touched either way.
_UPSERT_SQL = """
    INSERT INTO rules (rule_key, title, description, rule_type, severity, mitre_technique, definition, enabled, origin)
    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, TRUE, 'builtin')
    ON CONFLICT (rule_key) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        severity = EXCLUDED.severity,
        mitre_technique = EXCLUDED.mitre_technique,
        definition = EXCLUDED.definition
    WHERE rules.origin = 'builtin' AND NOT rules.user_modified
"""


def builtin_rules() -> dict[str, dict]:
    return {rule["rule_key"]: rule for rule in threshold.seed_rows() + signature.seed_rows()}


async def seed_builtin_rules(conn) -> None:
    for rule in builtin_rules().values():
        await conn.execute(
            _UPSERT_SQL,
            rule["rule_key"], rule["title"], rule["description"], rule["rule_type"],
            rule["severity"], rule["mitre_technique"], json.dumps(rule["definition"]),
        )
