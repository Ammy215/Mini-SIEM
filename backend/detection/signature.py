import json
import logging
from pathlib import Path

import yaml

from detection.common import insert_alert
from detection.scorer import score_alert

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parent.parent / "rules_yaml"
LOOKBACK_MINUTES = 30

_ALLOWED_FIELDS = {"url", "user_agent", "raw_message", "username", "method"}

_SEED_SQL = """
    INSERT INTO rules (rule_key, title, description, rule_type, severity, mitre_technique, definition, enabled)
    VALUES ($1, $2, $3, 'signature', $4, $5, $6::jsonb, TRUE)
    ON CONFLICT (rule_key) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        severity = EXCLUDED.severity,
        mitre_technique = EXCLUDED.mitre_technique,
        definition = EXCLUDED.definition
"""


def load_yaml_rules() -> list[dict]:
    rules = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        with path.open("r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        for required in ("rule_key", "title", "severity", "mitre", "detection"):
            if required not in rule:
                raise ValueError(f"{path.name}: missing required key '{required}'")
        rules.append(rule)
    return rules


async def seed_rules(conn) -> None:
    for rule in load_yaml_rules():
        definition = dict(rule["detection"])
        if rule.get("logsource"):
            definition["logsource"] = rule["logsource"]

        await conn.execute(
            _SEED_SQL,
            rule["rule_key"], rule["title"], rule.get("description"),
            rule["severity"], rule["mitre"], json.dumps(definition),
        )


async def _evaluate_signature_rule(conn, rule) -> int:
    d = rule["def"]
    field = d.get("field")
    if field not in _ALLOWED_FIELDS:
        logger.error("signature rule %s: disallowed field %r", rule["rule_key"], field)
        return 0

    patterns = d.get("contains") or []
    if not patterns:
        return 0

    condition = d.get("condition", "any")
    if condition != "any":
        logger.error("signature rule %s: unsupported condition %r", rule["rule_key"], condition)
        return 0

    params: list = [LOOKBACK_MINUTES]
    where = ["event_time >= now() - make_interval(mins => $1)", f"{field} IS NOT NULL"]

    logsource = d.get("logsource")
    if logsource:
        params.append(logsource)
        where.append(f"source_type = ${len(params)}")

    params.append([f"%{p}%" for p in patterns])
    where.append(f"{field} ILIKE ANY(${len(params)}::text[])")

    query = f"SELECT id, {field} AS val, source_ip, event_time FROM events WHERE " + " AND ".join(where)
    candidates = await conn.fetch(query, *params)
    if not candidates:
        return 0

    already_rows = await conn.fetch(
        "SELECT (evidence->>'event_id')::bigint AS eid FROM alerts WHERE rule_id = $1",
        rule["id"],
    )
    already = {r["eid"] for r in already_rows}

    created = 0
    for row in candidates:
        if row["id"] in already:
            continue

        value = row["val"] or ""
        matched = [p for p in patterns if p.lower() in value.lower()]
        if not matched:
            continue

        signal = d.get("signal")
        score, severity = score_alert([signal] if signal else [])

        await insert_alert(
            conn, rule_id=rule["id"], title=rule["title"],
            mitre_technique=rule["mitre_technique"],
            source_ip=str(row["source_ip"]) if row["source_ip"] else None,
            threat_score=score, severity=severity,
            evidence={
                "event_id": row["id"], "field": field, "matched_patterns": matched,
                "value_snippet": value[:300],
                "event_time": row["event_time"].isoformat() if row["event_time"] else None,
            },
        )
        created += 1

    return created


async def run_all(conn) -> dict[str, int]:
    rows = await conn.fetch("SELECT * FROM rules WHERE rule_type = 'signature' AND enabled = TRUE")

    results: dict[str, int] = {}
    for row in rows:
        rule = {
            "id": row["id"],
            "title": row["title"],
            "mitre_technique": row["mitre_technique"],
            "rule_key": row["rule_key"],
            "def": json.loads(row["definition"]),
        }
        try:
            results[row["rule_key"]] = await _evaluate_signature_rule(conn, rule)
        except Exception:
            logger.exception("signature evaluator failed for rule_key=%s", row["rule_key"])
            results[row["rule_key"]] = 0

    return results
