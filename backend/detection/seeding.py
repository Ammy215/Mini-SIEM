"""Built-in detection rules: the definitions the app ships with (rules_yaml/*.yml),
and how they reach the rules table."""

import json
from pathlib import Path

import yaml

from models.rule_definitions import InvalidDefinition, validate_definition, validate_rule_severity

RULES_DIR = Path(__file__).resolve().parent.parent / "rules_yaml"
_REQUIRED_KEYS = ("rule_key", "title", "severity", "mitre", "definition")

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
        rule_type = EXCLUDED.rule_type,
        severity = EXCLUDED.severity,
        mitre_technique = EXCLUDED.mitre_technique,
        definition = EXCLUDED.definition
    WHERE rules.origin = 'builtin' AND NOT rules.user_modified
"""


def builtin_rules() -> dict[str, dict]:
    """Every shipped rule, validated. A broken rule file stops startup with the
    file name and the problem, rather than shipping a rule that never runs."""
    rules: dict[str, dict] = {}
    for path in sorted(RULES_DIR.glob("*.yml")):
        with path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        if not isinstance(raw, dict):
            raise ValueError(f"{path.name}: must be a YAML mapping")
        missing = [key for key in _REQUIRED_KEYS if key not in raw]
        if missing:
            raise ValueError(f"{path.name}: missing required keys {missing}")
        try:
            definition, rule_type = validate_definition(raw["definition"])
            validate_rule_severity(raw["severity"])
        except InvalidDefinition as exc:
            raise ValueError(f"{path.name}: {exc}") from None
        if raw["rule_key"] in rules:
            raise ValueError(f"{path.name}: duplicate rule_key {raw['rule_key']!r}")
        rules[raw["rule_key"]] = {
            "rule_key": raw["rule_key"],
            "title": raw["title"],
            "description": raw.get("description"),
            "rule_type": rule_type,
            "severity": raw["severity"],
            "mitre_technique": raw["mitre"],
            "definition": definition,
        }
    return rules


async def seed_builtin_rules(conn) -> None:
    for rule in builtin_rules().values():
        await conn.execute(
            _UPSERT_SQL,
            rule["rule_key"], rule["title"], rule["description"], rule["rule_type"],
            rule["severity"], rule["mitre_technique"], json.dumps(rule["definition"]),
        )
