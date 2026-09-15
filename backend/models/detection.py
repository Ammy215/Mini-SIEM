from datetime import datetime

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class DetectRunResult(BaseModel):
    results: dict[str, int]
    ran_at: datetime


class DetectRangeRequest(BaseModel):
    """Run detection over a past time range instead of the last few minutes."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    # Time zones are required: a range without one is ambiguous by hours.
    time_from: AwareDatetime = Field(alias="from")
    time_to: AwareDatetime = Field(alias="to")
