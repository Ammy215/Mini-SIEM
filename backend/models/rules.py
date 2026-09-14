from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Severity = Literal["low", "medium", "high", "critical"]


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
    origin: str
    user_modified: bool
    updated_at: datetime | None
    created_at: datetime


class RuleListResponse(BaseModel):
    rules: list[RuleOut]


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    # The minimum severity of this rule's alerts; threat intel can raise it.
    severity: Severity | None = None
    # The detection logic itself. Admin-only, and validated per rule type.
    definition: dict | None = None

    @model_validator(mode="after")
    def reject_null_bytes(self):
        for name in ("title", "description"):
            value = getattr(self, name)
            if value is not None and "\x00" in value:
                raise ValueError(f"{name} contains a NUL byte, which PostgreSQL cannot store")
        return self


class ToggleResult(BaseModel):
    id: int
    enabled: bool
