from datetime import datetime

from pydantic import BaseModel


class AlertSummary(BaseModel):
    id: int
    rule_id: int | None
    incident_id: int | None
    title: str
    severity: str
    mitre_technique: str | None
    source_ip: str | None
    threat_score: int | None
    status: str
    created_at: datetime


class AlertDetail(AlertSummary):
    evidence: dict
    acknowledged_by: str | None
    acknowledged_at: datetime | None


class AlertListResponse(BaseModel):
    alerts: list[AlertSummary]
    total: int


def alert_summary_from_row(row) -> AlertSummary:
    return AlertSummary(
        id=row["id"], rule_id=row["rule_id"], incident_id=row["incident_id"],
        title=row["title"], severity=row["severity"], mitre_technique=row["mitre_technique"],
        source_ip=str(row["source_ip"]) if row["source_ip"] else None,
        threat_score=row["threat_score"], status=row["status"], created_at=row["created_at"],
    )
