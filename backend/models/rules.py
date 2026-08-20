from datetime import datetime

from pydantic import BaseModel


class RuleOut(BaseModel):
    id: int
    rule_key: str
    title: str
    description: str | None
    rule_type: str
    severity: str
    mitre_technique: str | None
    definition: dict
    enabled: bool
    created_at: datetime


class RuleListResponse(BaseModel):
    rules: list[RuleOut]


class RuleUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    definition: dict | None = None


class ToggleResult(BaseModel):
    id: int
    enabled: bool
