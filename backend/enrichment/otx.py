import httpx

from config import settings

PROVIDER = "otx"


async def query(ip: str) -> dict:
    if not settings.otx_api_key:
        return {"error": "no API key configured"}

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers={"X-OTX-API-KEY": settings.otx_api_key})
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        return {"error": str(exc)}

    pulse_info = data.get("pulse_info", {})
    pulses = pulse_info.get("pulses", [])

    return {
        "pulse_count": pulse_info.get("count", 0),
        "pulse_names": [p.get("name") for p in pulses[:5]],
        "country": data.get("country_name"),
        "asn": data.get("asn"),
    }
