"""
Auth module for the application.

Exposes session helpers (get_roles, require_*), authz config (get_all_config_group_ids,
compute_roles), and the FastAPI auth router factory (create_auth_router).
"""

from .authz_config import compute_roles, get_all_config_group_ids
from .router import create_auth_router
from .session import (
    get_roles,
    is_session_stale,
    require_any_role,
    require_role,
    require_roles,
    touch_session_activity,
)

__all__ = [
    "get_roles",
    "is_session_stale",
    "require_roles",
    "require_role",
    "require_any_role",
    "touch_session_activity",
    "get_all_config_group_ids",
    "compute_roles",
    "create_auth_router",
]
