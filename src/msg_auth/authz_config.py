"""
Authz configuration module for the application.

Role-to-group mapping is configured in ROLE_GROUPS (each role maps to a set of
Azure AD group IDs). Role inheritance is configured in ROLE_INHERITS (a role
can imply other roles). This module provides helpers to collect all configured
group IDs and to compute the final list of roles for a user from their member groups.
"""

from typing import Set


async def get_all_config_group_ids(role_groups: dict) -> Set[str]:
    """Return the union of all group IDs referenced in role_groups (for Graph API checks)."""
    ids = set()
    for group_set in role_groups.values():
        ids |= group_set
    return ids


def compute_roles(member_group_ids: Set[str], role_groups: dict, role_inherits: dict) -> Set[str]:
    """
    Compute roles for a user from their member group IDs.

    First assigns roles whose configured groups intersect member_group_ids, then
    expands with role_inherits (e.g. "admin" -> ["viewer"]) so inherited roles
    are included. Returns a list of role names.
    """
    roles = set()
    for role, groups in role_groups.items():
        role_group_set = {g.lower() for g in groups}
        if member_group_ids & role_group_set:
            roles.add(role)

    # Expand with inherited roles via a simple traversal (no cycles assumed)
    expanded = set(roles)
    stack = list(roles)
    while stack:
        r = stack.pop()
        for implied in role_inherits.get(r, set()):
            if implied not in expanded:
                expanded.add(implied)
                stack.append(implied)

    return list[str](expanded)
