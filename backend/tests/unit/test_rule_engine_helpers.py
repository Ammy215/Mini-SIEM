"""Rule engine pieces that need no database: title templates, evidence merging, compiled SQL."""

import pytest

from detection.alerting import merge_evidence
from detection.compiler import Params, compile_condition
from detection.rule_engine import render_title


def _leaf(field, op, value=None):
    leaf = {"field": field, "op": op}
    if value is not None:
        leaf["value"] = value
    return leaf


def test_titles_fill_only_known_placeholders():
    assert render_title("From {source_ip} as {username}", {"source_ip": "192.0.2.1"}, "fallback") == (
        "From 192.0.2.1 as unknown"
    )
    assert render_title("{source_ip.__class__} {0}", {"source_ip": "192.0.2.1"}, "fallback") == (
        "{source_ip.__class__} {0}"
    )
    assert render_title(None, {}, "fallback") == "fallback"


def test_merging_keeps_the_first_match_and_combines_the_rest():
    old = {"event_id": 1, "event_ids": [1, 2], "hit_count": 2, "matched_patterns": ["a"], "failed_count": 11,
           "first_seen": "2026-01-01T10:00:00+00:00", "last_seen": "2026-01-01T10:05:00+00:00",
           "enrichment_signals": ["known_bad_ip"]}
    new = {"event_id": 9, "event_ids": [2, 3], "hit_count": 1, "matched_patterns": ["b"], "failed_count": 7,
           "first_seen": "2026-01-01T09:59:00+00:00", "last_seen": "2026-01-01T10:09:00+00:00"}

    merged = merge_evidence(old, new)

    assert merged == {
        "event_id": 1, "event_ids": [1, 2, 3], "hit_count": 3, "matched_patterns": ["a", "b"], "failed_count": 11,
        "first_seen": "2026-01-01T09:59:00+00:00", "last_seen": "2026-01-01T10:09:00+00:00",
        "enrichment_signals": ["known_bad_ip"],
    }


def test_a_field_outside_the_whitelist_never_compiles():
    for field in ("url; DROP TABLE alerts", "raw", "raw.bad-key", "password_hash"):
        with pytest.raises(ValueError):
            compile_condition(_leaf(field, "eq", "x"), Params(), "e")


def test_leaves_under_an_odd_number_of_nots_are_marked_negated():
    condition = {"all": [_leaf("url", "contains", "a"), {"not": _leaf("url", "contains", "b")},
                         {"not": {"not": _leaf("url", "contains", "c")}}]}
    _, leaves = compile_condition(condition, Params(), "e")
    assert [(leaf.value, leaf.negated) for leaf in leaves] == [("a", False), ("b", True), ("c", False)]


def test_raw_keys_are_bound_not_pasted():
    add = Params()
    sql, _ = compile_condition(_leaf("raw.logon_type", "eq", "10"), add, "e")
    assert "logon_type" not in sql
    assert add.values == ["logon_type", "10"]
