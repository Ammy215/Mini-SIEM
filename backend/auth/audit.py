import json
from uuid import UUID

import asyncpg


async def log_action(
    conn: asyncpg.Connection,
    *,
    user_id: UUID | None,
    action: str,
    detail: dict,
    ip_address: str | None,
    user_agent: str | None,
) -> None:
    await conn.execute(
        """
        INSERT INTO audit_log (user_id, action, detail, ip_address, user_agent)
        VALUES ($1, $2, $3::jsonb, $4, $5)
        """,
        user_id,
        action,
        json.dumps(detail),
        ip_address,
        user_agent,
    )
