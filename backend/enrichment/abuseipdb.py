import httpx

from config import settings

PROVIDER = "abuseipdb"
_URL = "https://api.abuseipdb.com/api/v2/check"


async def query(ip: str) -> dict:
    if not settings.abuseipdb_api_key:
        return {"error": "no API key configured"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                _URL,
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
    except httpx.HTTPError as exc:
        return {"error": str(exc)}

    return {
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "is_whitelisted": data.get("isWhitelisted"),
        "last_reported_at": data.get("lastReportedAt"),
    }
