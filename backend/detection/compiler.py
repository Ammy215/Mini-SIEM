"""Compiles rule conditions into parameterised SQL.

Field names become SQL only through the whitelist in detection/rule_fields.py.
Every value — patterns, lists, regexes, raw.<key> names — is a bound parameter,
so nothing a rule author writes is ever pasted into the SQL text.

Every sub-expression is wrapped in COALESCE(…, false): an event with no value
for a field simply doesn't match, including under `not`. So
`not username eq "root"` matches events with no username at all.
"""

import ipaddress
from dataclasses import dataclass

from detection.rule_fields import field_sql, field_type

_COMPARISONS = {"eq": "=", "neq": "<>", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}


class Params:
    """Collects bound values and hands back their $n placeholders."""

    def __init__(self):
        self.values: list = []

    def __call__(self, value, cast: str | None = None) -> str:
        self.values.append(value)
        ref = f"${len(self.values)}"
        return f"{ref}::{cast}" if cast else ref


@dataclass(frozen=True)
class Leaf:
    index: int
    field: str
    op: str
    value: object
    sql: str        # true when this comparison matches
    value_sql: str  # the field's value, selected for alert evidence
    negated: bool   # under an odd number of `not`s — never evidence of a match


def compile_condition(condition: dict, add: Params, alias: str) -> tuple[str, list[Leaf]]:
    """(SQL that is true exactly when the condition matches, the leaves in order)."""
    leaves: list[Leaf] = []
    sql = _compile(condition, add, alias, leaves, negated=False)
    return f"COALESCE(({sql}), false)", leaves


def escape_like(value: str) -> str:
    # Backslash is PostgreSQL's default LIKE escape character.
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _compile(condition: dict, add: Params, alias: str, leaves: list[Leaf], negated: bool) -> str:
    if "all" in condition:
        return " AND ".join(f"COALESCE(({_compile(c, add, alias, leaves, negated)}), false)" for c in condition["all"])
    if "any" in condition:
        return " OR ".join(f"COALESCE(({_compile(c, add, alias, leaves, negated)}), false)" for c in condition["any"])
    if "not" in condition:
        return f"NOT COALESCE(({_compile(condition['not'], add, alias, leaves, not negated)}), false)"

    field, op, value = condition["field"], condition["op"], condition.get("value")
    kind = field_type(field)
    column = field_sql(field, alias, add)

    if op == "exists":
        sql = f"{column} IS NOT NULL"
    elif kind == "text":
        sql = _text(column, op, value, add)
    elif kind == "int":
        sql = _int(column, op, value, add)
    else:
        sql = _inet(column, op, value, add)

    leaves.append(Leaf(len(leaves), field, op, value, sql, column, negated))
    return sql


def _text(column: str, op: str, value, add: Params) -> str:
    if op in ("eq", "neq"):
        return f"{column} {_COMPARISONS[op]} {add(value)}"
    if op == "in":
        return f"{column} = ANY({add(list(value), 'text[]')})"
    if op == "contains":
        return f"{column} ILIKE {add('%' + escape_like(value) + '%')}"
    if op == "contains_any":
        return f"{column} ILIKE ANY({add(['%' + escape_like(v) + '%' for v in value], 'text[]')})"
    if op == "startswith":
        return f"{column} ILIKE {add(escape_like(value) + '%')}"
    if op == "endswith":
        return f"{column} ILIKE {add('%' + escape_like(value))}"
    if op == "regex":
        return f"{column} ~* {add(value)}"
    raise ValueError(f"operator not supported for text: {op}")


def _int(column: str, op: str, value, add: Params) -> str:
    if op in _COMPARISONS:
        return f"{column} {_COMPARISONS[op]} {add(value)}"
    if op == "in":
        return f"{column} = ANY({add(list(value), 'int[]')})"
    raise ValueError(f"operator not supported for numbers: {op}")


def _inet(column: str, op: str, value, add: Params) -> str:
    if op == "eq":
        return f"{column} = {add(ipaddress.ip_address(value), 'inet')}"
    if op == "in":
        return f"{column} = ANY({add([ipaddress.ip_address(v) for v in value], 'inet[]')})"
    if op == "cidr":
        return f"{column} <<= {add(ipaddress.ip_network(value, strict=False), 'cidr')}"
    raise ValueError(f"operator not supported for IP addresses: {op}")
