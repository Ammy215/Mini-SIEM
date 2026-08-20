from datetime import datetime

from pydantic import BaseModel


class AlertSummary(BaseModel):
    id: int
    rule_id: int | None
    title: str
    severity: str
    mitre_technique: str | None
    source_ip: str | None
    threat_score: int | None
    status: str
    created_at: datetime


class IncidentSummary(BaseModel):
    id: int
    title: str
    source_ip: str | None
    severity: str
    status: str
    alert_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    created_at: datetime


class IncidentListResponse(BaseModel):
    incidents: list[IncidentSummary]
    total: int


class IncidentDetail(IncidentSummary):
    alerts: list[AlertSummary]
