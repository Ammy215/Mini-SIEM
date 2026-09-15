"""Official MITRE ATT&CK (Enterprise) names for every technique this SIEM tags.

Local reference data, no network lookup. It covers every technique the detection
rules can emit; tests/unit/test_mitre.py fails if a rule introduces one that is
missing here, so the table can't silently drift behind the rule set.
"""

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1059.007": {"name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution"},
    "T1070.001": {"name": "Indicator Removal: Clear Windows Event Logs", "tactic": "Defense Evasion"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence, Privilege Escalation"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.003": {"name": "Brute Force: Password Spraying", "tactic": "Credential Access"},
    "T1110.004": {"name": "Brute Force: Credential Stuffing", "tactic": "Credential Access"},
    "T1136": {"name": "Create Account", "tactic": "Persistence"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
}


# ATT&CK Enterprise tactics in the matrix's left-to-right order.
TACTIC_ORDER: tuple[str, ...] = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
)


def tactics_of(technique_id: str | None) -> list[str]:
    """Every tactic a technique belongs to (some, like T1078, sit under several)."""
    info = TECHNIQUES.get(technique_id or "")
    return [tactic.strip() for tactic in info["tactic"].split(",")] if info else []


def technique_info(technique_id: str | None) -> dict[str, str] | None:
    if not technique_id:
        return None
    return TECHNIQUES.get(technique_id)
