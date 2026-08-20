import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from auth.audit import log_action
from auth.deps import CurrentUser
from auth.password import hash_password
from auth.rbac import require_role
from database import get_pool
from models.admin import (
    AdminUserCreate,
    AdminUserListResponse,
    AdminUserOut,
    AdminUserUpdate,
    AuditLogEntry,
    AuditLogResponse,
)

router = APIRouter()


@router.get("/api/admin/ping")
async def ping(current_user: CurrentUser = Depends(require_role("admin"))):
    return {"ok": True, "as": current_user.email}


async def _fetch_roles(conn, user_id) -> list[str]:
    rows = await conn.fetch(
        "SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = $1",
        user_id,
    )
    return [row["name"] for row in rows]


async def _set_role(conn, user_id, role: str) -> None:
    await conn.execute("DELETE FROM user_roles WHERE user_id = $1", user_id)
    await conn.execute(
        "INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = $2",
        user_id, role,
    )


@router.get("/api/admin/users", response_model=AdminUserListResponse)
async def list_users(current_user: CurrentUser = Depends(require_role("admin"))):
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, email, full_name, is_active, last_login_at, created_at FROM users ORDER BY created_at DESC"
        )
        users = []
        for row in rows:
            roles = await _fetch_roles(conn, row["id"])
            users.append(AdminUserOut(
                id=row["id"], email=row["email"], full_name=row["full_name"], is_active=row["is_active"],
                roles=roles, last_login_at=row["last_login_at"], created_at=row["created_at"],
            ))
    return AdminUserListResponse(users=users)


@router.post("/api/admin/users", response_model=AdminUserOut, status_code=201)
async def create_user(body: AdminUserCreate, request: Request, current_user: CurrentUser = Depends(require_role("admin"))):
    pool = get_pool()
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    async with pool.acquire() as conn:
        existing = await conn.fetchval("SELECT 1 FROM users WHERE email = $1", body.email)
        if existing:
            raise HTTPException(status_code=409, detail="Email already registered")

        password_hash = hash_password(body.password)
        async with conn.transaction():
            user_id = await conn.fetchval(
                "INSERT INTO users (email, password_hash, full_name) VALUES ($1, $2, $3) RETURNING id",
                body.email, password_hash, body.full_name,
            )
            await _set_role(conn, user_id, body.role)

        await log_action(
            conn, user_id=current_user.id, action="admin_user_created",
            detail={"created_user_id": str(user_id), "email": body.email, "role": body.role},
            ip_address=ip_address, user_agent=user_agent,
        )

        row = await conn.fetchrow(
            "SELECT id, email, full_name, is_active, last_login_at, created_at FROM users WHERE id = $1", user_id
        )

    return AdminUserOut(
        id=row["id"], email=row["email"], full_name=row["full_name"], is_active=row["is_active"],
        roles=[body.role], last_login_at=row["last_login_at"], created_at=row["created_at"],
    )


@router.put("/api/admin/users/{user_id}", response_model=AdminUserOut)
async def update_user(
    user_id: UUID, body: AdminUserUpdate, request: Request,
    current_user: CurrentUser = Depends(require_role("admin")),
):
    pool = get_pool()
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT id FROM users WHERE id = $1", user_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="User not found")

        await conn.execute(
            """
            UPDATE users SET
                full_name = COALESCE($2, full_name),
                is_active = COALESCE($3, is_active)
            WHERE id = $1
            """,
            user_id, body.full_name, body.is_active,
        )
        if body.role is not None:
            await _set_role(conn, user_id, body.role)

        if body.password is not None:
            # A reset also clears any active lockout — otherwise the admin hands
            # over a new password the user still can't log in with.
            await conn.execute(
                """
                UPDATE users
                SET password_hash = $2, failed_login_count = 0, locked_until = NULL
                WHERE id = $1
                """,
                user_id, hash_password(body.password),
            )

        # NEVER spread the raw body into the audit detail — `password` would be
        # written to audit_log in plaintext and then served by GET /api/admin/audit.
        detail = body.model_dump(exclude_none=True, exclude={"password"})
        detail["target_user_id"] = str(user_id)
        if body.password is not None:
            detail["password_reset"] = True

        await log_action(
            conn, user_id=current_user.id, action="admin_user_updated",
            detail=detail,
            ip_address=ip_address, user_agent=user_agent,
        )

        row = await conn.fetchrow(
            "SELECT id, email, full_name, is_active, last_login_at, created_at FROM users WHERE id = $1", user_id
        )
        roles = await _fetch_roles(conn, user_id)

    return AdminUserOut(
        id=row["id"], email=row["email"], full_name=row["full_name"], is_active=row["is_active"],
        roles=roles, last_login_at=row["last_login_at"], created_at=row["created_at"],
    )


@router.post("/api/admin/users/{user_id}/suspend", response_model=AdminUserOut)
async def suspend_user(user_id: UUID, request: Request, current_user: CurrentUser = Depends(require_role("admin"))):
    pool = get_pool()
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE users SET is_active = FALSE WHERE id = $1 RETURNING id, email, full_name, is_active, last_login_at, created_at",
            user_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="User not found")

        await log_action(
            conn, user_id=current_user.id, action="admin_user_suspended",
            detail={"target_user_id": str(user_id)},
            ip_address=ip_address, user_agent=user_agent,
        )
        roles = await _fetch_roles(conn, user_id)

    return AdminUserOut(
        id=row["id"], email=row["email"], full_name=row["full_name"], is_active=row["is_active"],
        roles=roles, last_login_at=row["last_login_at"], created_at=row["created_at"],
    )


@router.get("/api/admin/audit", response_model=AuditLogResponse)
async def get_audit_log(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: CurrentUser = Depends(require_role("admin")),
):
    pool = get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM audit_log")
        rows = await conn.fetch(
            """
            SELECT a.id, a.user_id, u.email AS user_email, a.action, a.detail, a.ip_address, a.user_agent, a.created_at
            FROM audit_log a
            LEFT JOIN users u ON u.id = a.user_id
            ORDER BY a.created_at DESC
            LIMIT $1 OFFSET $2
            """,
            limit, offset,
        )

    entries = [
        AuditLogEntry(
            id=r["id"], user_id=r["user_id"], user_email=r["user_email"], action=r["action"],
            detail=json.loads(r["detail"]) if r["detail"] else {},
            ip_address=str(r["ip_address"]) if r["ip_address"] else None,
            user_agent=r["user_agent"], created_at=r["created_at"],
        )
        for r in rows
    ]
    return AuditLogResponse(entries=entries, total=total)
