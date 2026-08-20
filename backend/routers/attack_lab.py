import json
from datetime import datetime, timezone

from fastapi import APIRouter, Request

from database import get_pool
from models.attack_lab import LoginAttemptIn, LoginAttemptResult, SearchResult

router = APIRouter(prefix="/api/attack-lab", tags=["attack-lab"])

# Fixed decoy credentials for the practice login form — not a real account,
# just something for a brute-force/dictionary attack to occasionally "win" against.
DECOY_USER = "admin"
DECOY_PASS = "letmein123"

_INSERT_SQL = """
    INSERT INTO events (
        event_time, source_type, source_ip, dest_port, username,
        action, status_code, method, url, user_agent, raw_message
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
"""


async def _log_event(conn, **fields) -> None:
    await conn.execute(
        _INSERT_SQL,
        datetime.now(timezone.utc),
        fields.get("source_type"),
        fields.get("source_ip"),
        fields.get("dest_port"),
        fields.get("username"),
        fields.get("action"),
        fields.get("status_code"),
        fields.get("method"),
        fields.get("url"),
        fields.get("user_agent"),
        fields.get("raw_message"),
    )


@router.post("/login", response_model=LoginAttemptResult)
async def practice_login(body: LoginAttemptIn, request: Request):
    source_ip = request.client.host if request.client else None
    success = body.username == DECOY_USER and body.password == DECOY_PASS
    action = "login_success" if success else "login_failed"

    pool = get_pool()
    async with pool.acquire() as conn:
        await _log_event(
            conn,
            source_type="app",
            source_ip=source_ip,
            dest_port=443,
            username=body.username,
            action=action,
            status_code=200 if success else 401,
            raw_message=f"attack-lab login attempt for '{body.username}' -> {action}",
        )

    if success:
        return LoginAttemptResult(success=True, message="Login successful.")
    return LoginAttemptResult(success=False, message="Invalid username or password.")


@router.get("/search", response_model=SearchResult)
async def practice_search(q: str, request: Request):
    source_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    pool = get_pool()
    async with pool.acquire() as conn:
        await _log_event(
            conn,
            source_type="nginx",
            source_ip=source_ip,
            method="GET",
            url=f"/search?q={q}",
            user_agent=user_agent,
            action="request",
            status_code=200,
            raw_message=f'"GET /search?q={q} HTTP/1.1" 200',
        )

    # Deliberately never touches a real query — nothing here is actually
    # searchable or executable. The point is the logged event, not the result.
    return SearchResult(query=q, results=[])
