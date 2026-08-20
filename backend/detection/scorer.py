THREAT_WEIGHTS = {
    "brute_force_confirmed":   30,
    "credential_stuffing":     20,
    "port_scan":               15,
    "sqli_pattern":            25,
    "xss_pattern":             15,
    "path_traversal":          20,
    "known_bad_ip":            20,
    "otx_pulse_match":         15,
    "scanner_user_agent":      15,
    "after_hours":              5,
    "foreign_geo":              5,
    "password_spray_confirmed": 20,
}

SEVERITY_BANDS = {(0, 25): "low", (25, 50): "medium", (50, 75): "high", (75, 101): "critical"}


def severity_for_score(score: int) -> str:
    score = max(0, min(100, score))
    for (lo, hi), label in SEVERITY_BANDS.items():
        if lo <= score < hi:
            return label
    return "critical"


def score_alert(signals: list[str]) -> tuple[int, str]:
    score = min(100, sum(THREAT_WEIGHTS.get(signal, 0) for signal in signals))
    return score, severity_for_score(score)


SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b
