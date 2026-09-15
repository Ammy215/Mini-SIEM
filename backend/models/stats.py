from datetime import datetime

from pydantic import BaseModel


class DashboardStats(BaseModel):
    total_events: int
    events_last_24h: int
    open_alerts: int
    open_incidents: int
    alerts_by_severity: dict[str, int]
    # For the time range the request asked for.
    events_in_range: int
    alerts_in_range: int
    range_start: datetime
    range_end: datetime


class TimelineBucket(BaseModel):
    bucket: datetime
    event_count: int
    alert_count: int


class TimelineResponse(BaseModel):
    # Every bucket in the range, including empty ones.
    buckets: list[TimelineBucket]
    bucket_seconds: int
    start: datetime
    end: datetime


class TopAttacker(BaseModel):
    source_ip: str
    alert_count: int
    max_severity: str
    last_seen: datetime


class TopAttackersResponse(BaseModel):
    attackers: list[TopAttacker]


class NamedCount(BaseModel):
    name: str
    count: int


class BreakdownResponse(BaseModel):
    start: datetime
    end: datetime
    logins: dict[str, int]              # success, failed
    events_by_source: list[NamedCount]  # largest first; the tail folded into "other"
    alerts_by_severity: dict[str, int]  # low, medium, high, critical
    top_actions: list[NamedCount]


class GeoCountry(BaseModel):
    country: str          # ISO 3166-1 alpha-2
    count: int
    max_severity: str | None  # alerts only


class GeoResponse(BaseModel):
    start: datetime
    end: datetime
    metric: str
    countries: list[GeoCountry]
    # Alerts/events in the range with a public source IP whose location isn't known (yet).
    unlocated: int


class MitreTechniqueOut(BaseModel):
    id: str
    name: str
    tactics: list[str]
    alert_count: int      # alerts in the range tagged with this technique
    enabled_rules: int    # enabled rules that can raise it


class MitreTacticOut(BaseModel):
    tactic: str
    techniques: list[MitreTechniqueOut]


class MitreCoverageResponse(BaseModel):
    start: datetime
    end: datetime
    tactics: list[MitreTacticOut]
    techniques_covered: int
    techniques_with_alerts: int
