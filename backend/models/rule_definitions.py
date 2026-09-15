"""What a detection rule may contain: the v2 rule language.

Checked when a rule is saved, and again before the engine runs it, so a
definition that reached the table some other way still never reaches SQL.

A definition's shape decides its rule type:

    filter                  signature  events matching a condition
    filter? + aggregate     threshold  matching events counted per group over a window
    sequence                sequence   enough "first" events, then a "then" event, on one key

Error messages are built from locations and fixed text only, never from the
submitted value, so a hostile value is never echoed back.
"""

import copy
import ipaddress
import re

from detection.rule_fields import FIELD_TYPES, GROUP_FIELDS, JOIN_FIELDS, OPERATORS, field_type
from detection.scorer import SEVERITY_ORDER, THREAT_WEIGHTS

MAX_DEPTH = 4
MAX_CONDITIONS = 20
MAX_LIST_VALUES = 100
MAX_VALUE_CHARS = 512
MAX_REGEX_CHARS = 256
MAX_WINDOW_MINUTES = 1440
MAX_THRESHOLD = 100_000
MAX_SEQUENCE_COUNT = 10_000
MAX_TITLE_CHARS = 200
MAX_LOGSOURCES = 20

TITLE_PLACEHOLDERS = ("source_ip", "username", "host", "dest_ip", "event_code", "group", "count")
# Evidence keys the engine writes itself; a rule's own count/values keys can't replace them.
RESERVED_EVIDENCE_KEYS = frozenset({
    "event_id", "event_ids", "event_time", "field", "matched_patterns", "value_snippet", "first_seen",
    "last_seen", "hit_count", "source_ip", "username", "host", "dest_ip", "event_code",
})

_INT_MIN, _INT_MAX = -(2**31), 2**31 - 1
_SAFE_KEY_RE = re.compile(r"[A-Za-z0-9_.]{1,40}")
_EVIDENCE_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,39}")
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")
# PostgreSQL regexes support \1-\9 backreferences, which is where catastrophic
# backtracking comes from. (Rejects an escaped backslash before a digit too.)
_BACKREFERENCE_RE = re.compile(r"\\[1-9]")


class InvalidDefinition(ValueError):
    pass


def validate_definition(definition) -> tuple[dict, str]:
    """Returns (a copy of the definition, the rule type its shape describes),
    or raises InvalidDefinition with a message a person can act on."""
    path = "definition"
    _object(definition, path, required=("version",), optional=("logsource", "filter", "aggregate", "sequence", "alert"))
    if type(definition["version"]) is not int or definition["version"] != 2:
        _fail(f"{path}.version", "must be 2")

    if "logsource" in definition:
        _string_list(definition["logsource"], f"{path}.logsource", MAX_LOGSOURCES, 64)

    conditions = [0]
    if "aggregate" in definition and "sequence" in definition:
        _fail(path, "use either aggregate or sequence, not both")
    if "sequence" in definition:
        rule_type = "sequence"
        if "filter" in definition:
            _fail(f"{path}.filter", "sequence rules put a filter on each step instead")
        _sequence(definition["sequence"], f"{path}.sequence", conditions)
    elif "aggregate" in definition:
        rule_type = "threshold"
        if "filter" in definition:
            _condition(definition["filter"], f"{path}.filter", 1, conditions)
        _aggregate(definition["aggregate"], f"{path}.aggregate")
    else:
        rule_type = "signature"
        if "filter" not in definition:
            _fail(f"{path}.filter", "required, unless the rule has an aggregate or a sequence")
        _condition(definition["filter"], f"{path}.filter", 1, conditions)

    if "alert" in definition:
        _alert(definition["alert"], f"{path}.alert", rule_type)

    return copy.deepcopy(definition), rule_type


def regex_patterns(definition: dict) -> list[tuple[str, str]]:
    """(location, pattern) for every regex condition in a validated definition."""
    found: list[tuple[str, str]] = []

    def walk(condition, path):
        for key in ("all", "any"):
            if key in condition:
                for index, item in enumerate(condition[key]):
                    walk(item, f"{path}.{key}.{index}")
                return
        if "not" in condition:
            walk(condition["not"], f"{path}.not")
        elif condition.get("op") == "regex":
            found.append((f"{path}.value", condition["value"]))

    if "filter" in definition:
        walk(definition["filter"], "definition.filter")
    if "sequence" in definition:
        for step in ("first", "then"):
            walk(definition["sequence"][step]["filter"], f"definition.sequence.{step}.filter")
    return found


def validate_rule_severity(severity) -> None:
    if severity not in SEVERITY_ORDER:
        raise InvalidDefinition(f"severity: must be one of {', '.join(SEVERITY_ORDER)}")


# --- shapes ------------------------------------------------------------------------

def _condition(condition, path: str, depth: int, conditions: list[int]) -> None:
    if depth > MAX_DEPTH:
        _fail(path, f"conditions can nest at most {MAX_DEPTH} levels deep")
    if not isinstance(condition, dict):
        _fail(path, "must be an object")

    groups = [key for key in ("all", "any", "not") if key in condition]
    if groups:
        key = groups[0]
        if len(condition) != 1:
            _fail(path, "a group holds exactly one of all, any or not, and nothing else")
        if key == "not":
            _condition(condition["not"], f"{path}.not", depth + 1, conditions)
            return
        items = condition[key]
        if not isinstance(items, list) or not items:
            _fail(f"{path}.{key}", "must be a non-empty list of conditions")
        for index, item in enumerate(items):
            _condition(item, f"{path}.{key}.{index}", depth + 1, conditions)
        return

    _object(condition, path, required=("field", "op"), optional=("value",))
    conditions[0] += 1
    if conditions[0] > MAX_CONDITIONS:
        _fail(path, f"a rule can have at most {MAX_CONDITIONS} conditions")

    kind = field_type(condition["field"])
    if kind is None:
        _fail(f"{path}.field", "not a field rules can use (an event field, or raw.<key> using letters, digits and _)")
    op = condition["op"]
    if not isinstance(op, str) or op not in OPERATORS[kind]:
        _fail(f"{path}.op", f"must be one of {', '.join(OPERATORS[kind])} for this field")

    if op == "exists":
        if "value" in condition:
            _fail(f"{path}.value", "exists takes no value")
        return
    if "value" not in condition:
        _fail(f"{path}.value", "required")

    value = condition["value"]
    if op in ("in", "contains_any"):
        if not isinstance(value, list) or not 1 <= len(value) <= MAX_LIST_VALUES:
            _fail(f"{path}.value", f"must be a list of 1 to {MAX_LIST_VALUES} values")
        for index, item in enumerate(value):
            _scalar(kind, "eq" if op == "in" else "contains", item, f"{path}.value.{index}")
    else:
        _scalar(kind, op, value, f"{path}.value")


def _scalar(kind: str, op: str, value, path: str) -> None:
    if kind == "int":
        _int(value, path, _INT_MIN, _INT_MAX)
    elif kind == "inet":
        expected = "a CIDR range like 10.0.0.0/8" if op == "cidr" else "an IP address"
        if not isinstance(value, str) or len(value) > 64:
            _fail(path, f"must be {expected}")
        try:
            ipaddress.ip_network(value, strict=False) if op == "cidr" else ipaddress.ip_address(value)
        except ValueError:
            _fail(path, f"must be {expected}")
    elif op == "regex":
        _string(value, path, MAX_REGEX_CHARS)
        if _BACKREFERENCE_RE.search(value):
            _fail(path, "regex backreferences (\\1 to \\9) aren't allowed")
    else:
        _string(value, path, MAX_VALUE_CHARS)


def _aggregate(aggregate, path: str) -> None:
    _object(
        aggregate, path,
        required=("group_by", "window_minutes", "function", "op", "threshold"), optional=("distinct_field",),
    )
    if not _one_of(aggregate["group_by"], GROUP_FIELDS):
        _fail(f"{path}.group_by", f"must be one of {', '.join(GROUP_FIELDS)}")
    _int(aggregate["window_minutes"], f"{path}.window_minutes", 1, MAX_WINDOW_MINUTES)
    if not _one_of(aggregate["function"], ("count", "distinct")):
        _fail(f"{path}.function", "must be count or distinct")
    if aggregate["function"] == "distinct":
        if "distinct_field" not in aggregate:
            _fail(f"{path}.distinct_field", "required when function is distinct")
        if not _one_of(aggregate["distinct_field"], tuple(FIELD_TYPES)):
            _fail(f"{path}.distinct_field", "must be an event field")
        if aggregate["distinct_field"] == aggregate["group_by"]:
            _fail(f"{path}.distinct_field", "must differ from group_by")
    elif "distinct_field" in aggregate:
        _fail(f"{path}.distinct_field", "only used when function is distinct")
    if not _one_of(aggregate["op"], ("gt", "gte")):
        _fail(f"{path}.op", "must be gt or gte")
    _int(aggregate["threshold"], f"{path}.threshold", 1, MAX_THRESHOLD)


def _sequence(sequence, path: str, conditions: list[int]) -> None:
    _object(sequence, path, required=("join_on", "first", "then"))
    if not _one_of(sequence["join_on"], JOIN_FIELDS):
        _fail(f"{path}.join_on", f"must be one of {', '.join(JOIN_FIELDS)}")

    first = sequence["first"]
    _object(first, f"{path}.first", required=("filter", "min_count", "within_minutes"))
    _condition(first["filter"], f"{path}.first.filter", 1, conditions)
    _int(first["min_count"], f"{path}.first.min_count", 1, MAX_SEQUENCE_COUNT)
    _int(first["within_minutes"], f"{path}.first.within_minutes", 1, MAX_WINDOW_MINUTES)

    then = sequence["then"]
    _object(then, f"{path}.then", required=("filter", "within_minutes"))
    _condition(then["filter"], f"{path}.then.filter", 1, conditions)
    _int(then["within_minutes"], f"{path}.then.within_minutes", 1, MAX_WINDOW_MINUTES)


def _alert(alert, path: str, rule_type: str) -> None:
    allowed = ["signal", "title"]
    if rule_type == "signature":
        allowed += ["group_by", "group_window_minutes"]
    else:
        allowed.append("count_key")
    if rule_type == "threshold":
        allowed += ["values_key", "values_field"]
    _object(alert, path, required=(), optional=tuple(allowed), unknown=f"not a setting {rule_type} rules use")

    if "signal" in alert and not _one_of(alert["signal"], tuple(THREAT_WEIGHTS)):
        _fail(f"{path}.signal", f"unknown signal; expected one of {', '.join(sorted(THREAT_WEIGHTS))}")
    if "title" in alert:
        _string(alert["title"], f"{path}.title", MAX_TITLE_CHARS)
        if any(name not in TITLE_PLACEHOLDERS for name in _PLACEHOLDER_RE.findall(alert["title"])):
            _fail(f"{path}.title", f"placeholders must be one of {', '.join('{' + n + '}' for n in TITLE_PLACEHOLDERS)}")
    if "group_by" in alert:
        group_by = alert["group_by"]
        if (
            not isinstance(group_by, list) or not 1 <= len(group_by) <= 3
            or any(not _one_of(field, GROUP_FIELDS) for field in group_by) or len(set(group_by)) != len(group_by)
        ):
            _fail(f"{path}.group_by", f"must list 1 to 3 different fields from {', '.join(GROUP_FIELDS)}")
    if "group_window_minutes" in alert:
        _int(alert["group_window_minutes"], f"{path}.group_window_minutes", 1, MAX_WINDOW_MINUTES)
    for key in ("count_key", "values_key"):
        if key in alert:
            value = alert[key]
            if not isinstance(value, str) or not _EVIDENCE_KEY_RE.fullmatch(value) or value in RESERVED_EVIDENCE_KEYS:
                _fail(f"{path}.{key}", "must be a lowercase name (letters, digits, _) the engine doesn't already use")
    if "values_field" in alert and not _one_of(alert["values_field"], tuple(FIELD_TYPES)):
        _fail(f"{path}.values_field", "must be an event field")
    if "values_key" in alert and "values_field" not in alert:
        _fail(f"{path}.values_field", "required when values_key is set")
    if alert.get("count_key") and alert.get("count_key") == alert.get("values_key"):
        _fail(f"{path}.values_key", "must differ from count_key")


# --- primitives ------------------------------------------------------------------

def _fail(path: str, message: str):
    raise InvalidDefinition(f"{path}: {message}")


def _object(value, path: str, required: tuple, optional: tuple = (), unknown: str = "unknown setting") -> None:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    # Missing keys first: a definition in an old or wrong shape reads better as
    # "version: required" than as a complaint about its first unfamiliar key.
    for key in required:
        if key not in value:
            _fail(f"{path}.{key}", "required")
    for key in value:
        if key not in required and key not in optional:
            shown = key if isinstance(key, str) and _SAFE_KEY_RE.fullmatch(key) else "<key>"
            _fail(f"{path}.{shown}", unknown)


def _one_of(value, options: tuple) -> bool:
    return isinstance(value, str) and value in options


def _int(value, path: str, low: int, high: int) -> None:
    if type(value) is not int or not low <= value <= high:
        _fail(path, f"must be a whole number from {low} to {high}")


def _string(value, path: str, max_chars: int) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= max_chars:
        _fail(path, f"must be text of 1 to {max_chars} characters")
    if "\x00" in value:
        _fail(path, "cannot contain NUL bytes")


def _string_list(value, path: str, max_items: int, max_chars: int) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= max_items:
        _fail(path, f"must be a list of 1 to {max_items} values")
    for index, item in enumerate(value):
        _string(item, f"{path}.{index}", max_chars)
