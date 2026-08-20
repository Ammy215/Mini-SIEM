from pydantic import BaseModel


class EnrichmentResult(BaseModel):
    ip: str
    abuseipdb: dict
    otx: dict
    ipinfo: dict
    cached: dict[str, bool]
