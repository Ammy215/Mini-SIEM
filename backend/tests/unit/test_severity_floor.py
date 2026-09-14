import pytest

from detection.scorer import final_severity, score_alert


@pytest.mark.parametrize(
    "score,minimum,expected",
    [
        (30, "high", "high"),         # base brute force score, rule marked high
        (30, "low", "medium"),        # score above the minimum wins
        (80, "medium", "critical"),   # threat intel can still escalate past it
        (0, "critical", "critical"),
        (60, None, "high"),           # no rule severity: score decides alone
        (60, "urgent", "high"),       # an unknown label is ignored, not trusted
    ],
)
def test_rule_severity_is_a_floor_not_a_ceiling(score, minimum, expected):
    assert final_severity(score, minimum) == expected


def test_score_alert_applies_the_rule_minimum():
    assert score_alert(["brute_force_confirmed"], minimum="high") == (30, "high")


def test_score_alert_without_a_minimum_is_unchanged():
    assert score_alert(["brute_force_confirmed"]) == (30, "medium")
