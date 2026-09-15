from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Severity = Literal["low", "medium", "high", "critical"]

RULE_KEY_PATTERN = r"^[a-z0-9][a-z0-9_-]{2,63}$"


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
    # How the most recent detection run of this rule went.
    last_run_at: datetime | None = None
    last_alerts: int | None = None
    last_error: str | None = None
    last_error_at: datetime | None = None


class RuleListResponse(BaseModel):
    rules: list[RuleOut]


def _reject_nul(model, names):
    for name in names:
        value = getattr(model, name)
        if value is not None and "\x00" in value:
            raise ValueError(f"{name} contains a NUL byte, which PostgreSQL cannot store")
    return model


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    # The minimum severity of this rule's alerts; threat intel can raise it.
    severity: Severity | None = None
    # The detection logic itself. Admin-only, validated as a v2 definition.
    definition: dict | None = None

    @model_validator(mode="after")
    def reject_null_bytes(self):
        return _reject_nul(self, ("title", "description"))


class RuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_key: str = Field(pattern=RULE_KEY_PATTERN)
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    severity: Severity
    mitre_technique: str | None = Field(default=None, max_length=16)
    definition: dict
    enabled: bool = True

    @model_validator(mode="after")
    def reject_null_bytes(self):
        return _reject_nul(self, ("title", "description"))


class RuleDefinitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    definition: dict


class RulePreviewRequest(RuleDefinitionRequest):
    hours: int = Field(default=24, ge=1, le=168)


class RuleValidateOut(BaseModel):
    rule_type: str


class RulePreviewSample(BaseModel):
    time: datetime | None
    group: str | None
    source_ip: str | None
    event_id: int | None
    detail: str | None


class RulePreviewOut(BaseModel):
    rule_type: str
    hours: int
    matches: int
    groups: int
    truncated: bool
    samples: list[RulePreviewSample]


class TechniqueOut(BaseModel):
    id: str
    name: str
    tactic: str


class RuleMetaOut(BaseModel):
    """What the rule builder can offer: fields, operators, signals, techniques, limits."""
    fields: dict[str, str]
    operators: dict[str, list[str]]
    group_fields: list[str]
    join_fields: list[str]
    signals: list[str]
    techniques: list[TechniqueOut]
    title_placeholders: list[str]
    limits: dict[str, int]


class ToggleResult(BaseModel):
    id: int
    enabled: bool
