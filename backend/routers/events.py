import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Query

from auth.deps import CurrentUser, get_current_user
from database import get_pool
from models.events import EventListResponse, EventOut

router = APIRouter()


@router.get("/api/events", response_model=EventListResponse)
async def list_events(
    source_type: str | None = Query(None),
    action: str | None = Query(None),
    source_ip: str | None = Query(None),
    q: str | None = Query(None, description="Full-text search over raw_message"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: CurrentUser = Depends(get_current_user),
):
    pool = get_pool()
    where: list[str] = []
    params: list = []

    if source_type:
        params.append(source_type)
        where.append(f"source_type = ${len(params)}")
    if action:
        params.append(action)
        where.append(f"action = ${len(params)}")
    if source_ip:
        # Validated before it reaches the ${n}::inet cast — an unparseable value
        # would otherwise raise asyncpg DataError as an unhandled 500. The value
        # is still passed as a bound parameter either way; this is about
        # returning a clean error, not about injection.
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            raise HTTPException(
                status_code=422, detail="source_ip must be a valid IPv4 or IPv6 address"
            )
        params.append(source_ip)
        where.append(f"source_ip = ${len(params)}::inet")
    if q:
        params.append(q)
        where.append(f"to_tsvector('english', coalesce(raw_message,'')) @@ plainto_tsquery('english', ${len(params)})")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    async with pool.acquire() as conn:
        total = await conn.fetchval(f"SELECT COUNT(*) FROM events {where_sql}", *params)
        rows = await conn.fetch(
            f"""
            SELECT id, event_time, source_type, source_ip, dest_ip, dest_port, username,
                   action, status_code, method, url, user_agent, country, raw_message
            FROM events {where_sql}
            ORDER BY event_time DESC
            LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}
            """,
            *params, limit, offset,
        )

    events = [
        EventOut(
            id=r["id"], event_time=r["event_time"], source_type=r["source_type"],
            source_ip=str(r["source_ip"]) if r["source_ip"] else None,
            dest_ip=str(r["dest_ip"]) if r["dest_ip"] else None,
            dest_port=r["dest_port"], username=r["username"], action=r["action"],
            status_code=r["status_code"], method=r["method"], url=r["url"],
            user_agent=r["user_agent"], country=r["country"], raw_message=r["raw_message"],
        )
        for r in rows
    ]
    return EventListResponse(events=events, total=total)
