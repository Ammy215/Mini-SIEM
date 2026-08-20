from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, field_validator


class AdminUserOut(BaseModel):
    id: UUID
    email: str
    full_name: str | None
    is_active: bool
    roles: list[str]
    last_login_at: datetime | None
    created_at: datetime


class AdminUserListResponse(BaseModel):
    users: list[AdminUserOut]


class AdminUserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None
    role: str = "viewer"

    @field_validator("password")
    @classmethod
    def check_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        if len(v.encode("utf-8")) > 72:
            raise ValueError("password must be at most 72 bytes")
        return v

    @field_validator("role")
    @classmethod
    def check_role(cls, v: str) -> str:
        if v not in ("viewer", "analyst", "admin"):
            raise ValueError("role must be one of viewer, analyst, admin")
        return v


class AdminUserUpdate(BaseModel):
    full_name: str | None = None
    is_active: bool | None = None
    role: str | None = None

    @field_validator("role")
    @classmethod
    def check_role(cls, v: str | None) -> str | None:
        if v is not None and v not in ("viewer", "analyst", "admin"):
            raise ValueError("role must be one of viewer, analyst, admin")
        return v


class AuditLogEntry(BaseModel):
    id: int
    user_id: UUID | None
    user_email: str | None
    action: str
    detail: dict
    ip_address: str | None
    user_agent: str | None
    created_at: datetime


class AuditLogResponse(BaseModel):
    entries: list[AuditLogEntry]
    total: int
