from fastapi import Depends, HTTPException

from auth.deps import CurrentUser, get_current_user


def require_role(*allowed_roles: str):
    async def _dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if "admin" in current_user.roles:
            return current_user
        if not set(current_user.roles) & set(allowed_roles):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user

    return _dependency
