"""Stops production from running with an admin anyone can sign in as.

`seed_admin.py` refuses to *create* an admin with the placeholder password in
production, but it cannot catch an admin that already exists: a database built
during development (where the placeholder is fine) and then deployed as-is
carries that account over. The password sits in the public .env.example, so the
live site would have an admin login anyone who reads the repository can use.
"""

import asyncio

from auth.password import verify_password
from config import PLACEHOLDER_ADMIN_PASSWORD


async def admins_using_placeholder_password(conn) -> list[str]:
    """Emails of active admins whose password is the public placeholder."""
    rows = await conn.fetch(
        """
        SELECT u.email, u.password_hash
        FROM users u
        JOIN user_roles ur ON ur.user_id = u.id
        JOIN roles r ON r.id = ur.role_id
        WHERE r.name = 'admin' AND u.is_active
        ORDER BY u.email
        """
    )
    found = []
    for row in rows:
        # bcrypt is deliberately slow (~0.25 s); keep it off the event loop.
        if await asyncio.to_thread(verify_password, PLACEHOLDER_ADMIN_PASSWORD, row["password_hash"]):
            found.append(row["email"])
    return found


async def assert_no_placeholder_admin(conn) -> None:
    emails = await admins_using_placeholder_password(conn)
    if emails:
        raise RuntimeError(
            f"Refusing to start in production: admin account(s) {', '.join(emails)} still use the "
            "placeholder password from .env.example, which anyone can read. Reset it first — "
            "Admin → Users → reset password, or PUT /api/admin/users/{id} with a new password — "
            "while running with APP_ENV=development."
        )
