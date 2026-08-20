"""Creates the initial admin user from ADMIN_EMAIL/ADMIN_PASSWORD in .env.
Safe to re-run — does nothing if that email already exists."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth.audit import log_action  # noqa: E402
from auth.password import hash_password  # noqa: E402
from config import settings  # noqa: E402
from database import connect, disconnect  # noqa: E402

PLACEHOLDER_PASSWORD = "change_me_strong_password"


async def main() -> None:
    if settings.app_env == "production" and settings.admin_password == PLACEHOLDER_PASSWORD:
        print("Refusing to seed admin: ADMIN_PASSWORD is still the placeholder value in production.")
        return

    pool = await connect()
    already_exists = False

    async with pool.acquire() as conn:
        existing = await conn.fetchval("SELECT 1 FROM users WHERE email = $1", settings.admin_email)
        if existing:
            already_exists = True
        else:
            password_hash = hash_password(settings.admin_password)

            async with conn.transaction():
                user_id = await conn.fetchval(
                    """
                    INSERT INTO users (email, password_hash, full_name, is_active)
                    VALUES ($1, $2, 'Admin', TRUE)
                    RETURNING id
                    """,
                    settings.admin_email,
                    password_hash,
                )
                await conn.execute(
                    """
                    INSERT INTO user_roles (user_id, role_id)
                    SELECT $1, id FROM roles WHERE name = 'admin'
                    ON CONFLICT DO NOTHING
                    """,
                    user_id,
                )

            await log_action(
                conn,
                user_id=user_id,
                action="admin_seeded",
                detail={"email": settings.admin_email},
                ip_address=None,
                user_agent=None,
            )

    await disconnect()

    if already_exists:
        print(f"Admin user {settings.admin_email} already exists — nothing to do.")
    else:
        print(f"Admin user created: {settings.admin_email}")


if __name__ == "__main__":
    asyncio.run(main())
