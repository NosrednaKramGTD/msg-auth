"""
FastAPI auth router: login, callback, /me, logout.

Builds an APIRouter with Microsoft OAuth and session-based roles from
role_groups and role_inherits configuration.
"""

import os
import time

from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from src.msg_auth import compute_roles
from src.msg_auth.microsoft import MicrosoftOAuthProvider


def create_auth_router(role_groups: dict, role_inherits: dict):
    """Create an APIRouter with /login, /auth/callback, /me, and /logout endpoints."""
    provider = MicrosoftOAuthProvider(role_groups, role_inherits)
    router = APIRouter()

    @router.get("/login")
    async def login(request: Request):
        """Redirect the user to the IdP (Microsoft) login page."""
        return await provider.login_redirect(request, request.url_for("auth_callback"))

    @router.get("/auth/callback", name="auth_callback")
    async def auth_callback(request: Request):
        """Handle OAuth callback: exchange code for token, store user and roles, redirect to /me."""
        try:
            userinfo, member_groups = await provider.handle_callback(request)
        except OAuthError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

        # Persist user identity in session
        request.session["user"] = {
            "name": userinfo.get("name"),
            "preferred_username": userinfo.get("preferred_username"),
            "oid": userinfo.get("oid"),
            "tid": userinfo.get("tid"),
        }
        # In DEBUG, expose raw group IDs for troubleshooting
        if os.getenv("DEBUG"):
            request.session["group_ids"] = list[str](member_groups)
        request.session["groups_fetched_at"] = int(time.time())
        request.session["roles"] = compute_roles(member_groups, role_groups, role_inherits)
        return RedirectResponse(url="/me")

    @router.get("/me")
    async def me(request: Request):
        """Return current user and roles; redirect to /login if not authenticated."""
        if "user" not in request.session:
            return RedirectResponse(url="/login")
        return {
            "user": request.session["user"],
            "group_count": len(request.session.get("roles", [])),
            "group_ids": request.session.get("roles", []),
            "groups_fetched_at": request.session.get("groups_fetched_at"),
        }

    @router.get("/logout")
    async def logout(request: Request):
        """Clear session and redirect to home."""
        request.session.clear()
        return RedirectResponse(url="/")

    return router
