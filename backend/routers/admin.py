from fastapi import APIRouter, Depends

from auth.deps import CurrentUser
from auth.rbac import require_role

router = APIRouter()


@router.get("/api/admin/ping")
async def ping(current_user: CurrentUser = Depends(require_role("admin"))):
    return {"ok": True, "as": current_user.email}
