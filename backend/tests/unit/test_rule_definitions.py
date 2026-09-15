"""The v2 rule language: what a rule may contain, and the rule type its shape describes."""

import copy

import pytest

from detection.seeding import builtin_rules
from models.rule_definitions import MAX_CONDITIONS, InvalidDefinition, validate_definition

BUILTINS = builtin_rules()


def _leaf(field="url", op="contains", value="x"):
    return {"field": field, "op": op, "value": value}


def _match(condition=None, **extra):
    return {"version": 2, "filter": condition or _leaf(), **extra}


def _brute_force(**aggregate_changes):
    definition = copy.deepcopy(BUILTINS["brute_force"]["definition"])
    definition["aggregate"].update(aggregate_changes)
    return definition


def _reject(definition, message):
    with pytest.raises(InvalidDefinition, match=message):
        validate_definition(definition)


def test_all_eight_original_rules_ship_in_the_v2_language():
    expected = {
        "brute_force": "threshold", "credential_stuffing": "threshold", "port_scan": "threshold",
        "password_spray": "threshold", "sqli-http-001": "signature", "xss-http-001": "signature",
        "path-traversal-001": "signature", "scanner-ua-001": "signature",
    }
    assert {key: BUILTINS[key]["rule_type"] for key in expected} == expected


@pytest.mark.parametrize("rule_key", sorted(BUILTINS))
def test_every_shipped_rule_passes_its_own_validation_unchanged(rule_key):
    rule = BUILTINS[rule_key]
    assert validate_definition(rule["definition"]) == (rule["definition"], rule["rule_type"])


def test_the_shape_decides_the_rule_type():
    assert validate_definition(_match())[1] == "signature"
    assert validate_definition(_brute_force())[1] == "threshold"
    sequence = {
        "version": 2,
        "sequence": {
            "join_on": "source_ip",
            "first": {"filter": _leaf("action", "eq", "login_failed"), "min_count": 5, "within_minutes": 10},
            "then": {"filter": _leaf("action", "eq", "login_success"), "within_minutes": 10},
        },
    }
    assert validate_definition(sequence)[1] == "sequence"


def test_nested_groups_raw_fields_and_every_type_of_value_are_accepted():
    condition = {"all": [
        _leaf("source_type", "in", ["windows", "ssh"]),
        {"any": [_leaf("dest_port", "gte", 1024), _leaf("source_ip", "cidr", "10.0.0.0/8")]},
        {"not": _leaf("username", "endswith", "$")},
        {"field": "raw.logon_type", "op": "exists"},
        _leaf("url", "regex", r"^/admin(/|$)"),
    ]}
    assert validate_definition(_match(condition))[1] == "signature"


@pytest.mark.parametrize(
    "definition,message",
    [
        ({"filter": _leaf()}, r"definition\.version: required"),
        (_match(version=1), r"definition\.version: must be 2"),
        ({"version": 2}, r"definition\.filter: required"),
        (_match(surprise=True), r"definition\.surprise: unknown setting"),
        (_match(_leaf(field="url; DROP TABLE alerts")), r"definition\.filter\.field: not a field"),
        (_match(_leaf(field="raw")), r"definition\.filter\.field: not a field"),
        (_match(_leaf(field="raw.bad-key")), r"definition\.filter\.field: not a field"),
        (_match(_leaf(field="dest_port", op="contains", value="80")), r"definition\.filter\.op: must be one of"),
        (_match(_leaf(field="dest_port", op="gt", value="80")), r"definition\.filter\.value: must be a whole number"),
        (_match(_leaf(field="dest_port", op="gt", value=True)), r"definition\.filter\.value: must be a whole number"),
        (_match(_leaf(field="source_ip", op="eq", value="not-an-ip")), r"must be an IP address"),
        (_match(_leaf(field="source_ip", op="cidr", value="10.0.0.0/99")), r"must be a CIDR range"),
        (_match(_leaf(value="")), r"must be text of 1 to 512"),
        (_match(_leaf(value="x" * 513)), r"must be text of 1 to 512"),
        (_match(_leaf(value="bad\x00byte")), r"NUL bytes"),
        (_match(_leaf(op="contains_any", value=[])), r"list of 1 to 100"),
        (_match(_leaf(op="contains_any", value=["x"] * 101)), r"list of 1 to 100"),
        (_match(_leaf(op="regex", value="x" * 257)), r"1 to 256"),
        (_match(_leaf(op="regex", value=r"(a+)\1")), r"backreferences"),
        (_match({"field": "url", "op": "exists", "value": "x"}), r"exists takes no value"),
        (_match({"all": []}), r"non-empty list"),
        (_match({"all": [_leaf()], "any": [_leaf()]}), r"exactly one of all, any or not"),
        (_match({"not": {"not": {"not": {"not": _leaf()}}}}), r"nest at most 4"),
        (_match({"all": [_leaf()] * (MAX_CONDITIONS + 1)}), r"at most 20 conditions"),
        (_match(alert={"signal": "made_up"}), r"unknown signal"),
        (_match(alert={"title": "Hit from {source_ip.__class__}"}), r"placeholders must be one of"),
        (_match(alert={"count_key": "hits"}), r"alert\.count_key: not a setting signature rules use"),
        (_brute_force(window_minutes=0), r"aggregate\.window_minutes: must be a whole number from 1 to 1440"),
        (_brute_force(threshold=-1), r"aggregate\.threshold"),
        (_brute_force(threshold="ten"), r"aggregate\.threshold"),
        (_brute_force(group_by="url"), r"aggregate\.group_by: must be one of"),
        (_brute_force(function="distinct"), r"aggregate\.distinct_field: required"),
        (_brute_force(distinct_field="username"), r"only used when function is distinct"),
        (_brute_force(op="lt"), r"aggregate\.op: must be gt or gte"),
        ({**_brute_force(), "sequence": {}}, r"either aggregate or sequence"),
    ],
)
def test_definitions_the_engine_cannot_run_safely_are_rejected(definition, message):
    _reject(definition, message)


def test_evidence_keys_cannot_overwrite_what_the_engine_writes():
    definition = _brute_force()
    definition["alert"]["count_key"] = "event_ids"
    _reject(definition, r"alert\.count_key")


def test_rejection_messages_never_echo_the_submitted_value():
    for definition in (
        _match(_leaf(field="url; DROP TABLE alerts")),
        _match(_leaf(field="source_ip", op="eq", value="DROP TABLE alerts")),
        {"version": 2, "filter": _leaf(), "DROP TABLE alerts": 1},
    ):
        with pytest.raises(InvalidDefinition) as exc_info:
            validate_definition(definition)
        assert "DROP TABLE" not in str(exc_info.value)


def test_non_object_definitions_are_rejected():
    for definition in (None, [], "text", 2):
        _reject(definition, r"definition: must be an object")
