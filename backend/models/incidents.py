from datetime import datetime

from pydantic import BaseModel

from models.alerts import AlertSummary


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
