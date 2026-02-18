"""
Microsoft Entra (Azure AD) OAuth provider.

Uses Authlib for OAuth2/OIDC and Microsoft Graph to resolve user group membership
for role computation. Requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET.
"""

import os
from typing import Set

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi.responses import JSONResponse

from msg_auth.authz_config import get_all_config_group_ids
from msg_auth.protocol import OAuthProvider

# Azure AD / Entra app registration env vars
TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")

# OIDC discovery URL for the tenant
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
METADATA_URL = f"{AUTHORITY}/.well-known/openid-configuration"  # OIDC discovery [8](https://merill.net/2024/09/graph-api-minimal-permissions-for-user-group-data/)


# Authlib OAuth client registered for Microsoft (Entra) using OIDC metadata
oauth = OAuth()
oauth.register(
    name="microsoft",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=METADATA_URL,
    client_kwargs={
        # OIDC + Graph delegated scopes; keep least-privileged in your tenant policy. [8](https://merill.net/2024/09/graph-api-minimal-permissions-for-user-group-data/)[3](https://learn.microsoft.com/en-us/entra/identity-platform/sample-v2-code)
        "scope": "openid profile email offline_access User.Read GroupMember.Read.All"
    },
)


class MicrosoftOAuthProvider(OAuthProvider):
    """OAuth provider that uses Microsoft Entra (Azure AD) and Graph for user + group data."""

    name: str = "microsoft"

    def __init__(self, role_groups: dict, role_inherits: dict):
        """Store role config used later to resolve which groups to check and how to map to roles."""
        self.name = "microsoft"
        self.role_groups = role_groups
        self.role_inherits = role_inherits

    async def login_redirect(self, request, redirect_uri: str):
        """Return RedirectResponse to IdP."""
        return await oauth.microsoft.authorize_redirect(request, redirect_uri)

    async def _check_member_groups(self, access_token: str, group_ids: Set[str]) -> Set[str]:
        """
        Call Graph API POST /me/checkMemberGroups.
        Checks membership in up to 20 group IDs per request; returns the subset
        of group IDs where the current user is a member. [1](https://learn.microsoft.com/en-us/entra/identity-platform/sample-v2-code)
        """
        GRAPH_BASE: str = "https://graph.microsoft.com/v1.0"
        url = f"{GRAPH_BASE}/me/checkMemberGroups"
        headers = {"Authorization": f"Bearer {access_token}"}
        # Graph expects lowercase group IDs; dedupe and sort for stable requests
        body = {"groupIds": sorted({gid.lower() for gid in group_ids})}

        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(url, headers=headers, json=body)
            r.raise_for_status()
            data = r.json()

        return {gid.lower() for gid in data.get("value", [])}

    async def handle_callback(self, request) -> tuple[dict, list[str]]:
        """Exchange code for token, fetch userinfo and member groups. Return (user_info, member_groups)."""
        try:
            token = await oauth.microsoft.authorize_access_token(request)
        except OAuthError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

        # Prefer userinfo from token; fall back to parsing ID token
        userinfo = token.get("userinfo")
        if not userinfo:
            userinfo = await oauth.microsoft.parse_id_token(request, token)

        # Resolve membership only for groups referenced in role_groups config
        member_groups: Set[str] = await self._check_member_groups(
            token["access_token"], await get_all_config_group_ids(self.role_groups)
        )

        return userinfo, member_groups
