import ipaddress

from fastapi import APIRouter, Depends, HTTPException

from auth.deps import CurrentUser, get_current_user
from database import get_pool
from enrichment import abuseipdb, ipinfo, otx
from enrichment.cache import get_cached, set_cached
from enrichment.errors import ProviderError, ProviderNotConfigured
from models.enrichment import EnrichmentResult

router = APIRouter()

_PROVIDERS = {
    abuseipdb.PROVIDER: abuseipdb.query,
    otx.PROVIDER: otx.query,
    ipinfo.PROVIDER: ipinfo.query,
}


def _reject_if_not_public(ip: str) -> None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        raise HTTPException(status_code=400, detail="Private/reserved IP addresses cannot be enriched")


@router.get("/api/enrich/ip/{ip}", response_model=EnrichmentResult)
async def enrich_ip(ip: str, current_user: CurrentUser = Depends(get_current_user)):
    _reject_if_not_public(ip)

    pool = get_pool()
    results: dict[str, dict] = {}
    cached_flags: dict[str, bool] = {}

    async with pool.acquire() as conn:
        for provider_name, query_fn in _PROVIDERS.items():
            cached = await get_cached(conn, ip, provider_name)
            if cached is not None:
                results[provider_name] = cached
                cached_flags[provider_name] = True
                continue

            # The page shows a per-provider {"error": ...} card, so a provider
            # failure degrades that one card instead of the whole lookup. The
            # messages come from enrichment.errors and never include a URL or key.
            try:
                data = await query_fn(ip)
            except ProviderNotConfigured:
                data = {"error": "no API key configured"}
            except ProviderError as exc:
                data = {"error": str(exc)}
            else:
                await set_cached(conn, ip, "ip", provider_name, data)

            results[provider_name] = data
            cached_flags[provider_name] = False

    return EnrichmentResult(
        ip=ip,
        abuseipdb=results["abuseipdb"],
        otx=results["otx"],
        ipinfo=results["ipinfo"],
        cached=cached_flags,
    )
