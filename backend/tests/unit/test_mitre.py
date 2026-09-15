from detection.mitre import TECHNIQUES, technique_info
from detection.seeding import builtin_rules


def test_every_technique_a_rule_can_emit_has_an_official_name():
    emitted = {rule["mitre_technique"] for rule in builtin_rules().values()}
    missing = emitted - TECHNIQUES.keys()
    assert not missing, f"add these to detection/mitre.py: {sorted(missing)}"


def test_the_two_techniques_the_ai_previously_mislabelled():
    assert technique_info("T1059.007") == {
        "name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
    }
    assert technique_info("T1595") == {"name": "Active Scanning", "tactic": "Reconnaissance"}


def test_unknown_or_missing_technique_returns_none():
    assert technique_info("T9999") is None
    assert technique_info(None) is None
    assert technique_info("") is None
