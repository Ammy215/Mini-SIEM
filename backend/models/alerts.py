from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel


class AlertUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved", "false_positive"]


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
    # When the events behind the alert happened, which for an uploaded
    # historical log can be long before the alert was created.
    first_event_time: datetime | None = None
    last_event_time: datetime | None = None
    # live | batch (an upload's analysis) | range (an admin's past-range run)
    origin: str = "live"
    batch_id: UUID | None = None


class AlertDetail(AlertSummary):
    evidence: dict
    acknowledged_by: str | None
    acknowledged_at: datetime | None


class AlertListResponse(BaseModel):
    alerts: list[AlertSummary]
    total: int


def _optional_fields(row) -> dict:
    # Rows from other queries (incident detail, dashboard) may not select these.
    return {
        "first_event_time": row.get("first_event_time"),
        "last_event_time": row.get("last_event_time"),
        "origin": row.get("origin") or "live",
        "batch_id": row.get("batch_id"),
    }


def alert_summary_from_row(row) -> AlertSummary:
    return AlertSummary(
        id=row["id"], rule_id=row["rule_id"], incident_id=row["incident_id"],
        title=row["title"], severity=row["severity"], mitre_technique=row["mitre_technique"],
        source_ip=str(row["source_ip"]) if row["source_ip"] else None,
        threat_score=row["threat_score"], status=row["status"], created_at=row["created_at"],
        **_optional_fields(row),
    )


def alert_detail_from_row(row, evidence: dict) -> AlertDetail:
    return AlertDetail(
        **alert_summary_from_row(row).model_dump(),
        evidence=evidence,
        acknowledged_by=str(row["acknowledged_by"]) if row["acknowledged_by"] else None,
        acknowledged_at=row["acknowledged_at"],
    )
