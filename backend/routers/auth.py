from datetime import datetime, timezone

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from auth.audit import log_action
from auth.deps import CurrentUser, get_current_user
from auth.jwt import create_access_token, create_refresh_token, decode_token
from auth.password import hash_password, verify_dummy, verify_password
from auth.rate_limit import rate_limit
from config import settings
from database import get_pool
from models.auth import LoginRequest, RegisterRequest, TokenResponse, UserOut

router = APIRouter()

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
REFRESH_COOKIE_NAME = "refresh_token"
REFRESH_COOKIE_PATH = "/api/auth/refresh"

# Shared bucket key: register and login are both pre-auth and equally abuse-prone.
_auth_rate_limit = rate_limit("auth", limit=10, window_minutes=15)


def _cookie_kwargs() -> dict:
    is_prod = settings.app_env == "production"
    return {
        "httponly": True,
        "path": REFRESH_COOKIE_PATH,
        "samesite": "none" if is_prod else "lax",
        "secure": is_prod,
    }


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        max_age=settings.jwt_refresh_ttl_days * 24 * 60 * 60,
        **_cookie_kwargs(),
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=REFRESH_COOKIE_NAME, **_cookie_kwargs())


async def _fetch_roles(conn, user_id) -> list[str]:
    rows = await conn.fetch(
        """
        SELECT r.name FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = $1
        """,
        user_id,
    )
    return [row["name"] for row in rows]


@router.post("/api/auth/register", response_model=UserOut, status_code=201, dependencies=[Depends(_auth_rate_limit)])
async def register(body: RegisterRequest, request: Request):
    pool = get_pool()
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    async with pool.acquire() as conn:
        existing = await conn.fetchval("SELECT 1 FROM users WHERE email = $1", body.email)
        if existing:
            raise HTTPException(status_code=409, detail="Email already registered")

        password_hash = hash_password(body.password)

        async with conn.transaction():
            try:
                # Self-registered accounts land INACTIVE and cannot log in until an
                # admin approves them via PUT /api/admin/users/{id} {"is_active": true}.
                # Without this, anyone who finds the public URL could self-register a
                # viewer account and read every event, alert, incident and rule.
                user_id = await conn.fetchval(
                    """
                    INSERT INTO users (email, password_hash, full_name, is_active)
                    VALUES ($1, $2, $3, FALSE)
                    RETURNING id
                    """,
                    body.email,
                    password_hash,
                    body.full_name,
                )
            except Exception:
                raise HTTPException(status_code=409, detail="Email already registered")

            await conn.execute(
                """
                INSERT INTO user_roles (user_id, role_id)
                SELECT $1, id FROM roles WHERE name = 'viewer'
                """,
                user_id,
            )

        await log_action(
            conn,
            user_id=user_id,
            action="user_registered_pending",
            detail={"email": body.email},
            ip_address=ip_address,
            user_agent=user_agent,
        )

        row = await conn.fetchrow(
            "SELECT id, email, full_name, is_active, last_login_at FROM users WHERE id = $1",
            user_id,
        )

    return UserOut(
        id=row["id"],
        email=row["email"],
        full_name=row["full_name"],
        roles=["viewer"],
        is_active=row["is_active"],
        last_login_at=row["last_login_at"],
    )


@router.post("/api/auth/login", response_model=TokenResponse, dependencies=[Depends(_auth_rate_limit)])
async def login(body: LoginRequest, request: Request, response: Response):
    pool = get_pool()
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, password_hash, is_active, failed_login_count, locked_until
            FROM users WHERE email = $1
            """,
            body.email,
        )

        if row is None:
            verify_dummy(body.password)
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if row["locked_until"] is not None and row["locked_until"] > datetime.now(timezone.utc):
            await log_action(
                conn, user_id=row["id"], action="login_blocked_locked", detail={},
                ip_address=ip_address, user_agent=user_agent,
            )
            raise HTTPException(status_code=423, detail="Account temporarily locked, try again later")

        if not row["is_active"]:
            await log_action(
                conn, user_id=row["id"], action="login_blocked_inactive", detail={},
                ip_address=ip_address, user_agent=user_agent,
            )
            # is_active=FALSE covers both "self-registered, awaiting approval" and
            # "suspended by an admin" — deliberately one neutral message for both, so
            # the response doesn't reveal which case applies.
            raise HTTPException(
                status_code=403,
                detail="Account is not active. An administrator must approve or re-enable it.",
            )

        if not verify_password(body.password, row["password_hash"]):
            new_count = row["failed_login_count"] + 1
            if new_count >= MAX_FAILED_ATTEMPTS:
                await conn.execute(
                    """
                    UPDATE users
                    SET failed_login_count = $2, locked_until = now() + make_interval(mins => $3)
                    WHERE id = $1
                    """,
                    row["id"], new_count, LOCKOUT_MINUTES,
                )
            else:
                await conn.execute(
                    "UPDATE users SET failed_login_count = $2 WHERE id = $1",
                    row["id"], new_count,
                )
            await log_action(
                conn, user_id=row["id"], action="login_failed", detail={"attempt_count": new_count},
                ip_address=ip_address, user_agent=user_agent,
            )
            raise HTTPException(status_code=401, detail="Invalid email or password")

        await conn.execute(
            """
            UPDATE users
            SET failed_login_count = 0, locked_until = NULL, last_login_at = now()
            WHERE id = $1
            """,
            row["id"],
        )

        roles = await _fetch_roles(conn, row["id"])
        access_token = create_access_token(str(row["id"]), body.email, roles)
        refresh_token = create_refresh_token(str(row["id"]))

        await log_action(
            conn, user_id=row["id"], action="login_success", detail={},
            ip_address=ip_address, user_agent=user_agent,
        )

    _set_refresh_cookie(response, refresh_token)
    return TokenResponse(access_token=access_token, expires_in=settings.jwt_access_ttl_min * 60)


@router.post("/api/auth/refresh", response_model=TokenResponse)
async def refresh(request: Request, response: Response):
    token = request.cookies.get(REFRESH_COOKIE_NAME)
    if token is None:
        raise HTTPException(status_code=401, detail="No refresh token")

    try:
        payload = decode_token(token)
    except pyjwt.PyJWTError:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Invalid token type")

    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, email, is_active FROM users WHERE id = $1", payload["sub"]
        )
        if row is None or not row["is_active"]:
            _clear_refresh_cookie(response)
            raise HTTPException(status_code=401, detail="Account unavailable")

        roles = await _fetch_roles(conn, row["id"])

    access_token = create_access_token(str(row["id"]), row["email"], roles)
    return TokenResponse(access_token=access_token, expires_in=settings.jwt_access_ttl_min * 60)


@router.post("/api/auth/logout", status_code=204)
async def logout(request: Request, response: Response, current_user: CurrentUser = Depends(get_current_user)):
    pool = get_pool()
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    async with pool.acquire() as conn:
        await log_action(
            conn, user_id=current_user.id, action="logout", detail={},
            ip_address=ip_address, user_agent=user_agent,
        )

    _clear_refresh_cookie(response)


@router.get("/api/auth/me", response_model=UserOut)
async def me(current_user: CurrentUser = Depends(get_current_user)):
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT full_name, is_active, last_login_at FROM users WHERE id = $1",
            current_user.id,
        )
        if row is None:
            raise HTTPException(status_code=401, detail="User no longer exists")

    return UserOut(
        id=current_user.id,
        email=current_user.email,
        full_name=row["full_name"],
        roles=current_user.roles,
        is_active=row["is_active"],
        last_login_at=row["last_login_at"],
    )
