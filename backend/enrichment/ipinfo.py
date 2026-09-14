import httpx

from config import settings
from enrichment.errors import ProviderError, provider_http_error

PROVIDER = "ipinfo"


async def query(ip: str) -> dict:
    """Works without a token (at a lower rate limit). Raises ProviderError when
    the lookup fails. Callers must pass an already-validated public IP."""
    url = f"https://ipinfo.io/{ip}/json"
    # The token goes in a header, never the URL: httpx error messages and
    # proxy/server logs record URLs, and this one used to carry ?token=.
    headers = {"Authorization": f"Bearer {settings.ipinfo_token}"} if settings.ipinfo_token else {}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        raise provider_http_error(PROVIDER, exc) from None
    except ValueError:
        raise ProviderError(f"{PROVIDER} returned a response that isn't JSON") from None

    if not isinstance(data, dict):
        raise ProviderError(f"{PROVIDER} returned an unexpected response shape")

    return {
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "loc": data.get("loc"),
        "org": data.get("org"),
        "timezone": data.get("timezone"),
    }
