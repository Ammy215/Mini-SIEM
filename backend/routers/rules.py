import json

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from auth.audit import log_action
from auth.deps import CurrentUser, get_current_user
from auth.rate_limit import rate_limit
from auth.rbac import require_role
from database import get_pool
from detection import rule_engine
from detection.mitre import TECHNIQUES
from detection.rule_checks import check_regexes
from detection.rule_fields import FIELD_TYPES, GROUP_FIELDS, JOIN_FIELDS, OPERATORS
from detection.scorer import THREAT_WEIGHTS
from detection.seeding import builtin_rules
from models import rule_definitions
from models.rule_definitions import InvalidDefinition, validate_definition
from models.rules import (
    RuleCreate, RuleDefinitionRequest, RuleListResponse, RuleMetaOut, RuleOut, RulePreviewOut, RulePreviewRequest,
    RuleUpdate, RuleValidateOut, TechniqueOut, ToggleResult,
)

router = APIRouter()

# A preview scans up to a week of events, so it gets its own, tighter limit.
_preview_rate_limit = rate_limit("rule_preview", limit=20, window_minutes=1)

_SELECT_RULE = """
    SELECT r.*, s.last_run_at, s.last_alerts, s.last_error, s.last_error_at
    FROM rules r LEFT JOIN rule_state s ON s.rule_id = r.id
"""


def _row_to_rule(row) -> RuleOut:
    return RuleOut(
        id=row["id"], rule_key=row["rule_key"], title=row["title"], description=row["description"],
        rule_type=row["rule_type"], severity=row["severity"], mitre_technique=row["mitre_technique"],
        definition=json.loads(row["definition"]), enabled=row["enabled"], origin=row["origin"],
        user_modified=row["user_modified"], updated_at=row["updated_at"], created_at=row["created_at"],
        last_run_at=row.get("last_run_at"), last_alerts=row.get("last_alerts"),
        last_error=row.get("last_error"), last_error_at=row.get("last_error_at"),
    )


async def _fetch_rule(conn, rule_id: int) -> RuleOut:
    return _row_to_rule(await conn.fetchrow(f"{_SELECT_RULE} WHERE r.id = $1", rule_id))


def _client_info(request: Request) -> tuple[str | None, str | None]:
    return (request.client.host if request.client else None), request.headers.get("user-agent")


async def _validated(conn, definition: dict) -> tuple[dict, str]:
    """A definition the engine can run, or a 422 saying why not."""
    try:
        definition, rule_type = validate_definition(definition)
        await check_regexes(conn, definition)
    except InvalidDefinition as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return definition, rule_type


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
        rows = await conn.fetch(f"{_SELECT_RULE} ORDER BY r.rule_type, r.rule_key")
    return RuleListResponse(rules=[_row_to_rule(r) for r in rows])


@router.get("/api/rules/meta", response_model=RuleMetaOut)
async def rule_meta(current_user: CurrentUser = Depends(get_current_user)):
    return RuleMetaOut(
        fields=FIELD_TYPES,
        operators={kind: list(ops) for kind, ops in OPERATORS.items()},
        group_fields=list(GROUP_FIELDS),
        join_fields=list(JOIN_FIELDS),
        signals=sorted(THREAT_WEIGHTS),
        techniques=[TechniqueOut(id=key, **info) for key, info in sorted(TECHNIQUES.items())],
        title_placeholders=list(rule_definitions.TITLE_PLACEHOLDERS),
        limits={
            "max_depth": rule_definitions.MAX_DEPTH,
            "max_conditions": rule_definitions.MAX_CONDITIONS,
            "max_list_values": rule_definitions.MAX_LIST_VALUES,
            "max_value_chars": rule_definitions.MAX_VALUE_CHARS,
            "max_regex_chars": rule_definitions.MAX_REGEX_CHARS,
            "max_window_minutes": rule_definitions.MAX_WINDOW_MINUTES,
            "max_threshold": rule_definitions.MAX_THRESHOLD,
            "max_preview_hours": 168,
        },
    )


@router.post("/api/rules", response_model=RuleOut, status_code=201)
async def create_rule(
    body: RuleCreate,
    request: Request,
    current_user: CurrentUser = Depends(require_role("admin")),
):
    if body.mitre_technique is not None and body.mitre_technique not in TECHNIQUES:
        raise HTTPException(
            status_code=422,
            detail=f"mitre_technique: not a technique this SIEM knows; expected one of {', '.join(sorted(TECHNIQUES))}",
        )
    if body.rule_key in builtin_rules():
        raise HTTPException(status_code=409, detail="This rule key belongs to a built-in rule")

    pool = get_pool()
    ip_address, user_agent = _client_info(request)
    async with pool.acquire() as conn:
        definition, rule_type = await _validated(conn, body.definition)
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                INSERT INTO rules (rule_key, title, description, rule_type, severity, mitre_technique, definition,
                                   enabled, origin, updated_at, updated_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, 'custom', now(), $9)
                ON CONFLICT (rule_key) DO NOTHING
                RETURNING id
                """,
                body.rule_key, body.title, body.description, rule_type, body.severity, body.mitre_technique,
                json.dumps(definition), body.enabled, current_user.id,
            )
            if row is None:
                raise HTTPException(status_code=409, detail="A rule with this key already exists")
            await log_action(
                conn, user_id=current_user.id, action="rule_created",
                detail={"rule_id": row["id"], "rule_key": body.rule_key, "rule_type": rule_type, "definition": definition},
                ip_address=ip_address, user_agent=user_agent,
            )
        return await _fetch_rule(conn, row["id"])


@router.post("/api/rules/validate", response_model=RuleValidateOut)
async def validate_rule(body: RuleDefinitionRequest, current_user: CurrentUser = Depends(require_role("admin"))):
    pool = get_pool()
    async with pool.acquire() as conn:
        _, rule_type = await _validated(conn, body.definition)
    return RuleValidateOut(rule_type=rule_type)


@router.post("/api/rules/preview", response_model=RulePreviewOut)
async def preview_rule(
    body: RulePreviewRequest,
    current_user: CurrentUser = Depends(require_role("admin")),
    _: None = Depends(_preview_rate_limit),
):
    """What a definition would have matched over recent events. Writes nothing."""
    pool = get_pool()
    async with pool.acquire() as conn:
        definition, rule_type = await _validated(conn, body.definition)
        try:
            result = await rule_engine.preview_rule(conn, definition, rule_type, body.hours)
        except asyncpg.QueryCanceledError:
            raise HTTPException(
                status_code=422,
                detail=f"Testing this rule over {body.hours} h took longer than {rule_engine.PREVIEW_TIMEOUT}; "
                       "narrow its conditions or test a shorter range",
            )
    return RulePreviewOut(**result)


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
            definition, rule_type = await _validated(conn, body.definition)
            if rule_type != existing["rule_type"]:
                raise HTTPException(
                    status_code=422,
                    detail=f"definition: describes a {rule_type} rule, but this is a {existing['rule_type']} rule",
                )

        changes = _changes(existing, body, definition)
        if not changes:
            return await _fetch_rule(conn, rule_id)

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
            RETURNING rule_key
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
        return await _fetch_rule(conn, rule_id)


@router.delete("/api/rules/{rule_id}", status_code=204, response_class=Response)
async def delete_rule(
    rule_id: int,
    request: Request,
    current_user: CurrentUser = Depends(require_role("admin")),
):
    pool = get_pool()
    ip_address, user_agent = _client_info(request)

    async with pool.acquire() as conn:
        async with conn.transaction():
            existing = await conn.fetchrow("SELECT id, rule_key, origin FROM rules WHERE id = $1 FOR UPDATE", rule_id)
            if existing is None:
                raise HTTPException(status_code=404, detail="Rule not found")
            if existing["origin"] != "custom":
                raise HTTPException(status_code=400, detail="Built-in rules can't be deleted; switch them off instead")
            alert_count = await conn.fetchval("SELECT count(*) FROM alerts WHERE rule_id = $1", rule_id)
            if alert_count:
                raise HTTPException(
                    status_code=409,
                    detail=f"This rule has raised {alert_count} alert(s). Switch it off instead, so those alerts "
                           "stay linked to the rule that raised them.",
                )
            await conn.execute("DELETE FROM rules WHERE id = $1", rule_id)
            await log_action(
                conn, user_id=current_user.id, action="rule_deleted",
                detail={"rule_id": rule_id, "rule_key": existing["rule_key"]},
                ip_address=ip_address, user_agent=user_agent,
            )
    return Response(status_code=204)


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
                title = $2, description = $3, rule_type = $4, severity = $5, mitre_technique = $6,
                definition = $7::jsonb, user_modified = FALSE, updated_at = now(), updated_by = $8
            WHERE id = $1
            RETURNING rule_key
            """,
            rule_id, builtin["title"], builtin["description"], builtin["rule_type"], builtin["severity"],
            builtin["mitre_technique"], json.dumps(builtin["definition"]), current_user.id,
        )

        await log_action(
            conn, user_id=current_user.id, action="rule_reset",
            detail={"rule_id": rule_id, "rule_key": row["rule_key"]},
            ip_address=ip_address, user_agent=user_agent,
        )
        return await _fetch_rule(conn, rule_id)


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
