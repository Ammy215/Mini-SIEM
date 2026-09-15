from fastapi import APIRouter, Depends

from auth.deps import CurrentUser
from auth.rbac import require_role
from config import settings
from database import get_pool
from detection import context

router = APIRouter()

EXPECTED_TABLES = [
    "users", "roles", "user_roles", "events", "rules",
    "incidents", "alerts", "ioc_cache", "audit_log",
]

API_KEYS = {
    "abuseipdb": settings.abuseipdb_api_key,
    "otx": settings.otx_api_key,
    "ipinfo": settings.ipinfo_token,
    "virustotal": settings.virustotal_api_key,
    "nvd": settings.nvd_api_key,
    "groq": settings.groq_api_key,
}


# Admin-only: discloses the table inventory, which threat-intel providers are
# configured, and whether the attack lab is enabled — free recon if left public.
@router.get("/api/setup/validate")
async def validate(current_user: CurrentUser = Depends(require_role("admin"))):
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
        )
    existing_tables = {row["table_name"] for row in rows}

    tables = {name: (name in existing_tables) for name in EXPECTED_TABLES}
    keys_present = {name: bool(value) for name, value in API_KEYS.items()}

    # Validated at startup, so this can't fail here.
    ctx = context.load(settings)

    return {
        "database": "connected",
        "tables": tables,
        "all_tables_present": all(tables.values()),
        "api_keys_present": keys_present,
        "attack_lab_enabled": settings.enable_attack_lab,
        "context": {
            "home_countries": sorted(ctx.home_countries),
            "business_hours_configured": ctx.business_hours is not None,
            "business_hours": settings.business_hours if ctx.business_hours else None,
            "business_days": settings.business_days if ctx.business_hours else None,
            "business_timezone": settings.business_timezone if ctx.business_hours else None,
            "geo_lookups_enabled": settings.enable_geo_lookups,
        },
    }
