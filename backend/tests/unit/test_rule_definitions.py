import pytest

from detection.seeding import builtin_rules
from models.rule_definitions import InvalidDefinition, validate_definition

BUILTINS = builtin_rules()
BRUTE_FORCE = BUILTINS["brute_force"]
SQLI = BUILTINS["sqli-http-001"]


def _threshold(**changes):
    return {**BRUTE_FORCE["definition"], **changes}


def _signature(**changes):
    return {**SQLI["definition"], **changes}


@pytest.mark.parametrize("rule_key", sorted(BUILTINS))
def test_every_shipped_rule_passes_its_own_validation_unchanged(rule_key):
    rule = BUILTINS[rule_key]
    assert validate_definition(rule["rule_type"], rule["definition"], rule) == rule["definition"]


def test_threshold_window_and_count_can_be_tuned():
    saved = validate_definition("threshold", _threshold(window_minutes=15, threshold=25), BRUTE_FORCE)
    assert (saved["window_minutes"], saved["threshold"]) == (15, 25)


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"window_minutes": 0}, "window_minutes"),
        ({"threshold": -1}, "threshold"),
        ({"threshold": "ten"}, "threshold"),
        ({"surprise": True}, "surprise"),
        # Accepted by the old API, then silently ignored: the evaluator's SQL
        # hardcodes these.
        ({"group_by": "username"}, "group_by is fixed"),
        ({"action_filter": "login_success"}, "action_filter is fixed"),
    ],
)
def test_threshold_edits_that_would_break_or_silently_do_nothing_are_rejected(changes, message):
    with pytest.raises(InvalidDefinition, match=message):
        validate_definition("threshold", _threshold(**changes), BRUTE_FORCE)


def test_threshold_definition_missing_a_required_value_is_rejected():
    definition = {k: v for k, v in BRUTE_FORCE["definition"].items() if k != "threshold"}
    with pytest.raises(InvalidDefinition, match="threshold: Field required"):
        validate_definition("threshold", definition, BRUTE_FORCE)


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"field": "url FROM events; DROP TABLE alerts; --"}, "definition.field"),
        ({"field": "raw"}, "definition.field"),
        ({"contains": []}, "definition.contains"),
        ({"contains": ["x" * 513]}, "definition.contains.0"),
        ({"contains": ["fine", "bad\x00byte"]}, "NUL bytes"),
        ({"condition": "all"}, "definition.condition"),
        ({"signal": "made_up_signal"}, "unknown signal"),
        ({"logsource": ""}, "definition.logsource"),
    ],
)
def test_signature_edits_outside_what_the_engine_supports_are_rejected(changes, message):
    with pytest.raises(InvalidDefinition, match=message):
        validate_definition("signature", _signature(**changes), SQLI)


def test_rejection_message_never_echoes_the_submitted_value():
    with pytest.raises(InvalidDefinition) as exc_info:
        validate_definition("signature", _signature(field="url; DROP TABLE alerts"), SQLI)
    assert "DROP TABLE" not in str(exc_info.value)


def test_unknown_rule_type_cannot_be_edited():
    with pytest.raises(InvalidDefinition, match="can't be edited"):
        validate_definition("sequence", {}, None)
