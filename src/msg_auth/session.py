"""
Session-based role helpers and FastAPI dependencies.

Reads roles from request.session (set by the auth callback) and provides
dependency factories for route protection: require_role, require_roles, require_any_role.

Optional: set ROLE_REFRESH_INTERVAL_SECONDS to require re-login when roles are older
than that (default 0 = no refresh). Set SESSION_MAX_IDLE_SECONDS to treat the user
as inactive after that long without a request (default 0 = disabled).
"""

import os
import time
from typing import Set

from fastapi import HTTPException, Request


def _role_refresh_interval_seconds() -> int:
    """Seconds after which roles are considered stale and re-auth is required. 0 = disabled."""
    return int(os.getenv("ROLE_REFRESH_INTERVAL_SECONDS", "0"))


def _session_max_idle_seconds() -> int:
    """Max seconds without a request before user is considered inactive. 0 = disabled."""
    return int(os.getenv("SESSION_MAX_IDLE_SECONDS", "0"))


def get_roles(request: Request) -> Set[str]:
    """Return the set of role names stored in the session (empty if not authenticated)."""
    raw = request.session.get("roles", [])
    return set(raw) if isinstance(raw, list) else set()


def is_session_stale(request: Request) -> bool:
    """
    Return True if the session should be considered stale: either roles are older
    than ROLE_REFRESH_INTERVAL_SECONDS or the user has been idle longer than
    SESSION_MAX_IDLE_SECONDS. When True, the app should require re-authentication.
    """
    interval = _role_refresh_interval_seconds()
    max_idle = _session_max_idle_seconds()
    now = int(time.time())

    if interval > 0:
        fetched_at = request.session.get("groups_fetched_at", 0)
        if now - fetched_at >= interval:
            return True

    if max_idle > 0:
        last_at = request.session.get("last_activity_at", now)
        if now - last_at >= max_idle:
            return True

    return False


def touch_session_activity(request: Request) -> None:
    """Update last_activity_at in the session so idle timeout is based on recent requests."""
    request.session["last_activity_at"] = int(time.time())


def require_roles(*required_roles: str):
    """
    Dependency: user must have ALL of the given roles (AND semantics).
    Use as: Depends(require_roles("admin", "editor")).
    """
    required = {role.lower() for role in required_roles if role}

    async def _dep(request: Request):
        if "user" not in request.session:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if is_session_stale(request):
            raise HTTPException(
                status_code=401,
                detail="Session expired or inactive; please log in again",
            )
        touch_session_activity(request)
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
        if is_session_stale(request):
            raise HTTPException(
                status_code=401,
                detail="Session expired or inactive; please log in again",
            )
        touch_session_activity(request)
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
        if is_session_stale(request):
            raise HTTPException(
                status_code=401,
                detail="Session expired or inactive; please log in again",
            )
        touch_session_activity(request)
        user_roles = get_roles(request)
        if not (required & user_roles):
            raise HTTPException(status_code=403, detail="Forbidden (no acceptable role)")
        return True

    return _dep
