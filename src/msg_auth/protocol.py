"""
Protocol for OAuth providers used by the auth router.

Implementations (e.g. MicrosoftOAuthProvider) must support redirecting to the IdP
and handling the callback to return user info and group/role data.
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class OAuthProvider(Protocol):
    """Protocol for an OAuth/OIDC provider (e.g. Microsoft, GitHub)."""

    name: str

    async def login_redirect(self, request, redirect_uri: str):
        """Redirect the user to the identity provider login page."""
        ...

    async def handle_callback(self, request) -> tuple[dict, list[str]]:
        """Handle the OAuth callback: exchange code for token, return (user_info, member_groups)."""
        ...
