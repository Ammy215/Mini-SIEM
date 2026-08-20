from datetime import datetime

from pydantic import BaseModel


class DashboardStats(BaseModel):
    total_events: int
    events_last_24h: int
    open_alerts: int
    open_incidents: int
    alerts_by_severity: dict[str, int]


class TimelineBucket(BaseModel):
    bucket: datetime
    event_count: int
    alert_count: int


class TimelineResponse(BaseModel):
    buckets: list[TimelineBucket]


class TopAttacker(BaseModel):
    source_ip: str
    alert_count: int
    max_severity: str
    last_seen: datetime


class TopAttackersResponse(BaseModel):
    attackers: list[TopAttacker]
