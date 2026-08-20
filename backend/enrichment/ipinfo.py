import httpx

from config import settings

PROVIDER = "ipinfo"


async def query(ip: str) -> dict:
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": settings.ipinfo_token} if settings.ipinfo_token else {}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        return {"error": str(exc)}

    return {
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "loc": data.get("loc"),
        "org": data.get("org"),
        "timezone": data.get("timezone"),
    }
