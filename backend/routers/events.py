import ipaddress
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import AwareDatetime

from auth.deps import CurrentUser, get_current_user
from database import get_pool
from models.events import EventListResponse, EventOut

router = APIRouter()

# Country comes from the event itself when a parser found one, otherwise from
# the cached location of its source IP (enrichment/geo.py).
_FROM = "FROM events e LEFT JOIN ip_geo g ON g.ip = e.source_ip"


@router.get("/api/events", response_model=EventListResponse)
async def list_events(
    source_type: str | None = Query(None),
    action: str | None = Query(None),
    source_ip: str | None = Query(None),
    q: str | None = Query(None, description="Full-text search over raw_message"),
    batch_id: UUID | None = Query(None, description="Only events from this upload"),
    time_from: AwareDatetime | None = Query(None, alias="from"),
    time_to: AwareDatetime | None = Query(None, alias="to"),
    username: str | None = Query(None, max_length=256),
    host: str | None = Query(None, max_length=256, description="Case-insensitive exact host name"),
    event_code: str | None = Query(None, max_length=64),
    dest_port: int | None = Query(None, ge=0, le=65535),
    country: str | None = Query(None, pattern=r"^[A-Z]{2}$", description="Two-letter country code"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: CurrentUser = Depends(get_current_user),
):
    if time_from is not None and time_to is not None and time_to <= time_from:
        raise HTTPException(status_code=422, detail="to must be after from")

    pool = get_pool()
    where: list[str] = []
    params: list = []

    def add(condition: str, value) -> None:
        params.append(value)
        where.append(condition.replace("$?", f"${len(params)}"))

    if source_type:
        add("e.source_type = $?", source_type)
    if action:
        add("e.action = $?", action)
    if source_ip:
        # Validated before it reaches the ::inet cast — an unparseable value
        # would otherwise raise asyncpg DataError as an unhandled 500. The value
        # is still passed as a bound parameter either way; this is about
        # returning a clean error, not about injection.
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            raise HTTPException(
                status_code=422, detail="source_ip must be a valid IPv4 or IPv6 address"
            )
        add("e.source_ip = $?::inet", source_ip)
    if q:
        add("to_tsvector('english', coalesce(e.raw_message,'')) @@ plainto_tsquery('english', $?)", q)
    if batch_id:
        add("e.batch_id = $?", batch_id)
    if time_from is not None:
        add("e.event_time >= $?", time_from)
    if time_to is not None:
        add("e.event_time <= $?", time_to)
    if username:
        add("e.username = $?", username)
    if host:
        add("lower(e.host) = lower($?)", host)
    if event_code:
        add("e.event_code = $?", event_code)
    if dest_port is not None:
        add("e.dest_port = $?", dest_port)
    if country:
        add("COALESCE(e.country, g.country) = $?", country)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    async with pool.acquire() as conn:
        total = await conn.fetchval(f"SELECT COUNT(*) {_FROM} {where_sql}", *params)
        rows = await conn.fetch(
            f"""
            SELECT e.id, e.event_time, e.source_type, e.source_ip, e.dest_ip, e.dest_port, e.username,
                   e.action, e.status_code, e.method, e.url, e.user_agent,
                   COALESCE(e.country, g.country) AS country, e.raw_message,
                   e.host, e.event_code, e.outcome, e.protocol, e.src_port, e.parser, e.batch_id
            {_FROM} {where_sql}
            ORDER BY e.event_time DESC
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
            host=r["host"], event_code=r["event_code"], outcome=r["outcome"], protocol=r["protocol"],
            src_port=r["src_port"], parser=r["parser"], batch_id=r["batch_id"],
        )
        for r in rows
    ]
    return EventListResponse(events=events, total=total)
