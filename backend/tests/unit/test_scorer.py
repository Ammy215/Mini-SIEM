from detection.scorer import max_severity, score_alert, severity_for_score


def test_score_alert_sums_weights():
    score, severity = score_alert(["brute_force_confirmed"])
    assert score == 30
    assert severity == "medium"


def test_score_alert_combines_multiple_signals():
    score, severity = score_alert(["known_bad_ip", "otx_pulse_match"])
    assert score == 35
    assert severity == "medium"


def test_score_alert_unknown_signal_contributes_zero():
    score, _ = score_alert(["not_a_real_signal"])
    assert score == 0


def test_score_alert_clamps_at_100():
    score, severity = score_alert(["sqli_pattern", "path_traversal", "known_bad_ip", "brute_force_confirmed", "port_scan"])
    assert score == 100
    assert severity == "critical"


def test_severity_band_boundaries():
    assert severity_for_score(0) == "low"
    assert severity_for_score(24) == "low"
    assert severity_for_score(25) == "medium"
    assert severity_for_score(49) == "medium"
    assert severity_for_score(50) == "high"
    assert severity_for_score(74) == "high"
    assert severity_for_score(75) == "critical"
    assert severity_for_score(100) == "critical"


def test_severity_for_score_clamps_out_of_range_input():
    assert severity_for_score(-10) == "low"
    assert severity_for_score(500) == "critical"


def test_max_severity_picks_higher():
    assert max_severity("low", "high") == "high"
    assert max_severity("critical", "medium") == "critical"
    assert max_severity("medium", "medium") == "medium"
