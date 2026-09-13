from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class AISummaryOut(BaseModel):
    target: Literal["alert", "incident"]
    target_id: int
    summary: str
    provider: str
    model: str
    generated_at: datetime
