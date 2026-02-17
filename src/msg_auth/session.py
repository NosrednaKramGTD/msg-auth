"""
Session-based role helpers and FastAPI dependencies.

Reads roles from request.session (set by the auth callback) and provides
dependency factories for route protection: require_role, require_roles, require_any_role.
"""

from typing import Set

from fastapi import HTTPException, Request


def get_roles(request: Request) -> Set[str]:
    """Return the set of role names stored in the session (empty if not authenticated)."""
    raw = request.session.get("roles", [])
    return set(raw) if isinstance(raw, list) else set()


def require_roles(*required_roles: str):
    """
    Dependency: user must have ALL of the given roles (AND semantics).
    Use as: Depends(require_roles("admin", "editor")).
    """
    required = {role.lower() for role in required_roles if role}

    async def _dep(request: Request):
        if "user" not in request.session:
            raise HTTPException(status_code=401, detail="Not authenticated")

        user_roles = {role.lower() for role in get_roles(request)}
        missing = required - user_roles
        if missing:
            raise HTTPException(status_code=403, detail="Forbidden (missing required roles)")
        return True

    return _dep


def require_role(role: str):
    """Dependency: user must have the given role. Use as: Depends(require_role('admin'))."""
    role = role.lower()

    async def _dep(request: Request):
        if "user" not in request.session:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if role not in get_roles(request):
            raise HTTPException(status_code=403, detail="Forbidden (missing role)")
        return True

    return _dep


def require_any_role(*roles: str):
    """Dependency: user must have at least one of the given roles (OR semantics)."""
    required = {r.lower() for r in roles if r}

    async def _dep(request: Request):
        if "user" not in request.session:
            raise HTTPException(status_code=401, detail="Not authenticated")
        user_roles = get_roles(request)
        if not (required & user_roles):
            raise HTTPException(status_code=403, detail="Forbidden (no acceptable role)")
        return True

    return _dep
