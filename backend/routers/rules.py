import json

from fastapi import APIRouter, Depends, HTTPException, Request

from auth.audit import log_action
from auth.deps import CurrentUser, get_current_user
from auth.rbac import require_role
from database import get_pool
from detection.seeding import builtin_rules
from models.rule_definitions import InvalidDefinition, validate_definition
from models.rules import RuleListResponse, RuleOut, RuleUpdate, ToggleResult

router = APIRouter()


def _row_to_rule(row) -> RuleOut:
    return RuleOut(
        id=row["id"], rule_key=row["rule_key"], title=row["title"], description=row["description"],
        rule_type=row["rule_type"], severity=row["severity"], mitre_technique=row["mitre_technique"],
        definition=json.loads(row["definition"]), enabled=row["enabled"], origin=row["origin"],
        user_modified=row["user_modified"], updated_at=row["updated_at"], created_at=row["created_at"],
    )


def _client_info(request: Request) -> tuple[str | None, str | None]:
    return (request.client.host if request.client else None), request.headers.get("user-agent")


def _changes(existing, body: RuleUpdate, definition: dict | None) -> dict:
    """What this update actually changes, as {field: {from, to}}, for the audit log."""
    changes = {}
    for name in ("title", "description", "severity"):
        new = getattr(body, name)
        if new is not None and new != existing[name]:
            changes[name] = {"from": existing[name], "to": new}
    if definition is not None:
        current = json.loads(existing["definition"])
        if definition != current:
            changes["definition"] = {"from": current, "to": definition}
    return changes


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
    request: Request,
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    # Title, description and severity are presentation and triage. The
    # definition decides which traffic raises an alert at all, so changing it
    # is reserved for admins.
    if body.definition is not None and "admin" not in current_user.roles:
        raise HTTPException(status_code=403, detail="Only admins can change a rule's detection logic")

    pool = get_pool()
    ip_address, user_agent = _client_info(request)

    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT * FROM rules WHERE id = $1", rule_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Rule not found")

        definition = None
        if body.definition is not None:
            try:
                definition = validate_definition(
                    existing["rule_type"], body.definition, builtin_rules().get(existing["rule_key"])
                )
            except InvalidDefinition as exc:
                raise HTTPException(status_code=422, detail=str(exc))

        changes = _changes(existing, body, definition)
        if not changes:
            return _row_to_rule(existing)

        # user_modified tells startup seeding to leave this rule alone from now
        # on, instead of overwriting the edit with the shipped definition.
        row = await conn.fetchrow(
            """
            UPDATE rules SET
                title = COALESCE($2, title),
                description = COALESCE($3, description),
                severity = COALESCE($4, severity),
                definition = COALESCE($5::jsonb, definition),
                user_modified = TRUE,
                updated_at = now(),
                updated_by = $6
            WHERE id = $1
            RETURNING *
            """,
            rule_id, body.title, body.description, body.severity,
            json.dumps(definition) if definition is not None else None,
            current_user.id,
        )

        await log_action(
            conn, user_id=current_user.id, action="rule_updated",
            detail={"rule_id": rule_id, "rule_key": row["rule_key"], "changes": changes},
            ip_address=ip_address, user_agent=user_agent,
        )
    return _row_to_rule(row)


@router.post("/api/rules/{rule_id}/reset", response_model=RuleOut)
async def reset_rule(
    rule_id: int,
    request: Request,
    current_user: CurrentUser = Depends(require_role("admin")),
):
    """Puts a built-in rule back to the definition the app ships with. Its
    enabled/disabled state is left as it is — that's an operational choice,
    not part of the rule's default."""
    pool = get_pool()
    ip_address, user_agent = _client_info(request)

    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT rule_key, origin FROM rules WHERE id = $1", rule_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Rule not found")

        builtin = builtin_rules().get(existing["rule_key"])
        if existing["origin"] != "builtin" or builtin is None:
            raise HTTPException(status_code=400, detail="Only built-in rules have a default to reset to")

        row = await conn.fetchrow(
            """
            UPDATE rules SET
                title = $2, description = $3, severity = $4, mitre_technique = $5, definition = $6::jsonb,
                user_modified = FALSE, updated_at = now(), updated_by = $7
            WHERE id = $1
            RETURNING *
            """,
            rule_id, builtin["title"], builtin["description"], builtin["severity"],
            builtin["mitre_technique"], json.dumps(builtin["definition"]), current_user.id,
        )

        await log_action(
            conn, user_id=current_user.id, action="rule_reset",
            detail={"rule_id": rule_id, "rule_key": row["rule_key"]},
            ip_address=ip_address, user_agent=user_agent,
        )
    return _row_to_rule(row)


@router.post("/api/rules/{rule_id}/toggle", response_model=ToggleResult)
async def toggle_rule(
    rule_id: int,
    request: Request,
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    pool = get_pool()
    ip_address, user_agent = _client_info(request)

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE rules SET enabled = NOT enabled WHERE id = $1 RETURNING id, rule_key, enabled",
            rule_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Rule not found")

        await log_action(
            conn, user_id=current_user.id, action="rule_toggled",
            detail={"rule_id": rule_id, "rule_key": row["rule_key"], "enabled": row["enabled"]},
            ip_address=ip_address, user_agent=user_agent,
        )
    return ToggleResult(id=row["id"], enabled=row["enabled"])
