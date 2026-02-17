"""
FastAPI app: Microsoft Entra (Azure AD) OAuth + session-based role auth.

Decisions:
- .env is loaded before importing msg_auth so AZURE_* and SESSION_SECRET are
  available when the auth router is created (Ruff E402 suppressed for that).
- ROLE_GROUPS: role name -> set of Azure AD group GUIDs; total distinct groups
  must be <= 20 (Graph checkMemberGroups accepts max 20 IDs per request).
- ROLE_INHERITS: e.g. admin -> support, user; used to expand roles after
  resolving membership. Only groups in ROLE_GROUPS are sent to Graph.
- Session secret from SESSION_SECRET env; default "change-me" is for dev only.
"""

import os

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

# Load .env before msg_auth so AZURE_* and SESSION_SECRET are set; Ruff E402.
from src.msg_auth import require_any_role, require_roles, touch_session_activity  # noqa: E402
from src.msg_auth.router import create_auth_router  # noqa: E402

SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me")

# Role -> Azure AD group IDs. Any membership in one of these groups grants the role.
# Decision: keep total distinct group count <= 20 (Graph checkMemberGroups limit).
ROLE_GROUPS = {
    "admin": {
        os.getenv("admin_group_id"),
    },
    "support": {
        os.getenv("support_group_id"),
    },
    "user": {
        os.getenv("user_group_id"),
    },
}

# Inheritance: admin implies support & user; support implies user.
ROLE_INHERITS = {
    "admin": {"support", "user"},
    "support": {"user"},
    "user": set(),
}

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)


@app.middleware("http")
async def update_activity(request: Request, call_next):
    """Update last_activity_at for logged-in users so idle timeout is accurate."""
    response = await call_next(request)
    if "user" in request.session:
        touch_session_activity(request)
    return response

app.include_router(create_auth_router(ROLE_GROUPS, ROLE_INHERITS))


@app.get("/")
async def home(request: Request):
    user = request.session.get("user")
    return {"logged_in": bool(user), "user": user}


# Example protected route (requires membership in a specific security group GUID)
@app.get("/admin")
async def admin_area(_=Depends(require_roles("admin"))):
    return {"ok": True, "area": "admin"}


@app.get("/support")
async def support_area(_=Depends(require_roles("support"))):
    return {"ok": True, "area": "support"}


@app.get("/support-or-admin")
async def support_or_admin_area(_=Depends(require_any_role("support", "admin"))):
    return {"ok": True, "area": "support or admin"}
