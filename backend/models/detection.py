from datetime import datetime

from pydantic import BaseModel


class DetectRunResult(BaseModel):
    results: dict[str, int]
    ran_at: datetime
