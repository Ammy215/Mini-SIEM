"""What a rule definition may contain, checked when someone saves a rule.

The engine still runs the fixed evaluators in detection/threshold.py and
detection/signature.py, so this accepts exactly what they read. Anything else
is rejected with a message, rather than being saved and then silently ignored
— or failing — at detection time.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator

from detection.scorer import THREAT_WEIGHTS

Pattern = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class ThresholdDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_minutes: int = Field(ge=1, le=1440)
    threshold: int = Field(ge=1, le=100_000)
    # Each threshold rule's comparison, grouping and action filter are written
    # into its evaluator's SQL. They stay in the definition to document what the
    # rule does, but changing them would do nothing — see _FIXED_THRESHOLD_KEYS.
    comparison: Literal["gt", "gte"] | None = None
    group_by: Literal["source_ip", "username"] | None = None
    action_filter: str | None = None


class SignatureDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: Literal["url", "user_agent", "raw_message", "username", "method"]
    contains: list[Pattern] = Field(min_length=1, max_length=100)
    condition: Literal["any"] = "any"
    signal: str | None = None
    logsource: str | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("contains")
    @classmethod
    def no_nul_bytes(cls, patterns: list[str]) -> list[str]:
        if any("\x00" in p for p in patterns):
            raise ValueError("patterns cannot contain NUL bytes")
        return patterns

    @field_validator("signal")
    @classmethod
    def known_signal(cls, signal: str | None) -> str | None:
        if signal is not None and signal not in THREAT_WEIGHTS:
            raise ValueError(f"unknown signal; expected one of {sorted(THREAT_WEIGHTS)}")
        return signal


_MODELS = {"threshold": ThresholdDefinition, "signature": SignatureDefinition}
_FIXED_THRESHOLD_KEYS = ("comparison", "group_by", "action_filter")


class InvalidDefinition(ValueError):
    pass


def validate_definition(rule_type: str, definition: dict, builtin: dict | None) -> dict:
    """Returns the definition to store, or raises InvalidDefinition with a
    message a person can act on. `builtin` is the shipped version of the rule."""
    model = _MODELS.get(rule_type)
    if model is None:
        raise InvalidDefinition(f"rules of type {rule_type!r} can't be edited")

    try:
        parsed = model.model_validate(definition)
    except ValidationError as exc:
        raise InvalidDefinition(_describe(exc)) from None

    if rule_type == "threshold" and builtin is not None:
        for key in _FIXED_THRESHOLD_KEYS:
            if key in parsed.model_fields_set and getattr(parsed, key) != builtin["definition"].get(key):
                raise InvalidDefinition(
                    f"definition.{key} is fixed for this rule; only window_minutes and threshold can be changed"
                )

    return parsed.model_dump(exclude_unset=True)


def _describe(exc: ValidationError) -> str:
    # Built from each error's location and message only, never its input, so a
    # hostile value isn't echoed back in the response.
    parts = []
    for error in exc.errors(include_url=False):
        location = ".".join(str(part) for part in error["loc"])
        parts.append(f"definition.{location}: {error['msg']}" if location else f"definition: {error['msg']}")
    return "; ".join(parts)
