from fastapi import APIRouter

from config import settings
from database import get_pool

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


@router.get("/api/setup/validate")
async def validate():
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
        )
    existing_tables = {row["table_name"] for row in rows}

    tables = {name: (name in existing_tables) for name in EXPECTED_TABLES}
    keys_present = {name: bool(value) for name, value in API_KEYS.items()}

    return {
        "database": "connected",
        "tables": tables,
        "all_tables_present": all(tables.values()),
        "api_keys_present": keys_present,
        "attack_lab_enabled": settings.enable_attack_lab,
    }
