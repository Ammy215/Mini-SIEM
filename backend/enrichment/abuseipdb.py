import httpx

from config import settings
from enrichment.errors import ProviderError, ProviderNotConfigured, provider_http_error

PROVIDER = "abuseipdb"
_URL = "https://api.abuseipdb.com/api/v2/check"


async def query(ip: str) -> dict:
    """Raises ProviderNotConfigured without an API key, ProviderError when the
    lookup fails. Callers must pass an already-validated public IP."""
    if not settings.abuseipdb_api_key:
        raise ProviderNotConfigured(f"{PROVIDER}: no API key configured")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                _URL,
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            resp.raise_for_status()
            body = resp.json()
    except httpx.HTTPError as exc:
        raise provider_http_error(PROVIDER, exc) from None
    except ValueError:
        raise ProviderError(f"{PROVIDER} returned a response that isn't JSON") from None

    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        raise ProviderError(f"{PROVIDER} returned an unexpected response shape")

    return {
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "is_whitelisted": data.get("isWhitelisted"),
        "last_reported_at": data.get("lastReportedAt"),
    }
