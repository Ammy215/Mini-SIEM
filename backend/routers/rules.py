import json

from fastapi import APIRouter, Depends, HTTPException

from auth.deps import CurrentUser, get_current_user
from auth.rbac import require_role
from database import get_pool
from models.rules import RuleListResponse, RuleOut, RuleUpdate, ToggleResult

router = APIRouter()


def _row_to_rule(row) -> RuleOut:
    return RuleOut(
        id=row["id"], rule_key=row["rule_key"], title=row["title"], description=row["description"],
        rule_type=row["rule_type"], severity=row["severity"], mitre_technique=row["mitre_technique"],
        definition=json.loads(row["definition"]), enabled=row["enabled"], created_at=row["created_at"],
    )


@router.get("/api/rules", response_model=RuleListResponse)
async def list_rules(current_user: CurrentUser = Depends(get_current_user)):
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM rules ORDER BY rule_type, rule_key"
        )
    return RuleListResponse(rules=[_row_to_rule(r) for r in rows])


@router.put("/api/rules/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: int,
    body: RuleUpdate,
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    pool = get_pool()
    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT * FROM rules WHERE id = $1", rule_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Rule not found")

        row = await conn.fetchrow(
            """
            UPDATE rules SET
                title = COALESCE($2, title),
                description = COALESCE($3, description),
                severity = COALESCE($4, severity),
                definition = COALESCE($5::jsonb, definition)
            WHERE id = $1
            RETURNING *
            """,
            rule_id, body.title, body.description, body.severity,
            json.dumps(body.definition) if body.definition is not None else None,
        )
    return _row_to_rule(row)


@router.post("/api/rules/{rule_id}/toggle", response_model=ToggleResult)
async def toggle_rule(
    rule_id: int,
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE rules SET enabled = NOT enabled WHERE id = $1 RETURNING id, enabled",
            rule_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Rule not found")
    return ToggleResult(id=row["id"], enabled=row["enabled"])
