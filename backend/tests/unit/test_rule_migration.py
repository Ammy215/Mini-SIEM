"""Migration 0005 translates stored v1 rule definitions into the v2 language,
keeping whatever someone tuned."""

import copy
import importlib.util
from pathlib import Path

import pytest

from detection.seeding import builtin_rules
from models.rule_definitions import validate_definition

_PATH = Path(__file__).resolve().parents[2] / "sql" / "migrations" / "0005_rule_engine_v2.py"
_spec = importlib.util.spec_from_file_location("migration_0005", _PATH)
migration = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(migration)

# The definitions as the v1 engine stored them (Phases 4-18).
V1_THRESHOLD = {
    "brute_force": {"window_minutes": 5, "threshold": 10, "comparison": "gt", "group_by": "source_ip", "action_filter": "login_failed"},
    "credential_stuffing": {"window_minutes": 10, "threshold": 5, "comparison": "gte", "group_by": "source_ip", "action_filter": "login_failed"},
    "port_scan": {"window_minutes": 5, "threshold": 15, "comparison": "gte", "group_by": "source_ip", "action_filter": None},
    "password_spray": {"window_minutes": 10, "threshold": 5, "comparison": "gte", "group_by": "username", "action_filter": "login_failed"},
}
V1_SIGNATURE = {
    "path-traversal-001": {"field": "url", "contains": ["../", "/etc/passwd"], "condition": "any", "signal": "path_traversal", "logsource": "nginx"},
    "scanner-ua-001": {"field": "user_agent", "contains": ["sqlmap", "nikto", "nmap"], "condition": "any", "signal": "scanner_user_agent"},
    "xss-http-001": {"field": "url", "contains": ["<script>", "onerror="], "condition": "any", "signal": "xss_pattern", "logsource": "nginx"},
}


@pytest.mark.parametrize("rule_key", sorted(V1_THRESHOLD))
def test_untouched_threshold_rules_translate_to_exactly_the_shipped_rule(rule_key):
    assert migration._threshold_v2(rule_key, V1_THRESHOLD[rule_key]) == builtin_rules()[rule_key]["definition"]


@pytest.mark.parametrize("rule_key", sorted(V1_SIGNATURE))
def test_untouched_signature_rules_translate_to_exactly_the_shipped_rule(rule_key):
    assert migration._signature_v2(V1_SIGNATURE[rule_key]) == builtin_rules()[rule_key]["definition"]


def test_a_tuned_threshold_keeps_its_window_and_count():
    tuned = {**V1_THRESHOLD["brute_force"], "window_minutes": 20, "threshold": 3}
    translated = migration._threshold_v2("brute_force", tuned)

    assert (translated["aggregate"]["window_minutes"], translated["aggregate"]["threshold"]) == (20, 3)
    assert validate_definition(translated)[1] == "threshold"


def test_tuned_signature_patterns_are_kept():
    tuned = copy.deepcopy(V1_SIGNATURE["scanner-ua-001"])
    tuned["contains"].append("masscan")
    translated = migration._signature_v2(tuned)

    assert translated["filter"]["value"] == ["sqlmap", "nikto", "nmap", "masscan"]
    assert validate_definition(translated)[1] == "signature"


def test_definitions_that_cannot_be_translated_are_left_alone():
    assert migration._threshold_v2("brute_force", {"window_minutes": "five", "threshold": 10}) is None
    assert migration._threshold_v2("some_custom_rule", V1_THRESHOLD["brute_force"]) is None
    assert migration._signature_v2({"field": "url", "contains": []}) is None
