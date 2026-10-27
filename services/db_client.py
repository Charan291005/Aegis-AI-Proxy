"""Asynchronous Supabase Client and Database Operations for Aegis Gateway.

Manages connection pooling and queries for:
1. Role-Based Access Control (RBAC):
   - `user_roles`: Maps active session_id to user role (e.g., 'admin', 'standard').
   - `role_permissions`: Maps role to permissible tool_name (or wildcard '*').
2. Non-blocking asynchronous query execution via `supabase.acreate_client`.
3. Resilient development fallback for disconnected / testing environments.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Set
from supabase import AsyncClient, acreate_client

from security.config import get_settings

logger = logging.getLogger("aegis.services.db_client")

# ------------------------------------------------------------------------------
# In-Memory Mock Store (Active during offline testing & dev without live DB)
# ------------------------------------------------------------------------------
MOCK_USER_ROLES: Dict[str, str] = {
    "sess-admin-001": "admin",
    "sess-operator-002": "operator",
    "sess-standard-003": "standard",
    "sess-unauthorized-999": "unauthorized",
    "default-session": "standard",
}

MOCK_ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "admin": {"*"},
    "operator": {
        "read_file",
        "query_database",
        "fetch_metrics",
        "simulate_tool",
        "ping",
        "echo",
    },
    "standard": {
        "read_file",
        "fetch_metrics",
        "query_database",
        "simulate_tool",
        "ping",
        "echo",
    },
    "read_only": {
        "ping",
        "echo",
        "simulate_tool",
    },
    "unauthorized": set(),
}

# Singleton Supabase AsyncClient instance
_supabase_client: Optional[AsyncClient] = None


async def get_supabase_client() -> Optional[AsyncClient]:
    """Retrieve or initialize the asynchronous Supabase client singleton.

    Uses `SUPABASE_URL` and `SUPABASE_KEY` from the environment or settings.
    """
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    settings = get_settings()
    url: Optional[str] = os.getenv("SUPABASE_URL") or settings.supabase_url
    key: Optional[str] = os.getenv("SUPABASE_KEY") or settings.effective_supabase_key

    if not url or not key:
        logger.warning(
            "SUPABASE_URL or SUPABASE_KEY missing. Asynchronous Supabase client disabled."
        )
        return None

    try:
        _supabase_client = await acreate_client(url, key)
        logger.info("Initialized asynchronous Supabase client for %s", url)
        return _supabase_client
    except Exception as exc:
        logger.error(
            "Failed to initialize Supabase AsyncClient: %s. Using resilient fallback.",
            str(exc),
        )
        return None


async def verify_tool_permission(session_id: str, tool_name: str) -> bool:
    """Verify whether a session holds authorization to invoke a requested tool.

    Workflow:
    1. Query Supabase table `user_roles` using session_id to retrieve the user's role.
    2. Query Supabase table `role_permissions` using the role to retrieve allowed tool_names.
    3. Return True if the tool_name or wildcard '*' is mapped to the role; False otherwise.

    Args:
        session_id: Active session correlation identifier.
        tool_name: MCP tool requested for execution.

    Returns:
        bool: True if authorized, False otherwise.
    """
    effective_session = session_id or "default-session"
    client = await get_supabase_client()

    if client:
        try:
            # 1. Query `user_roles` table: SELECT role FROM user_roles WHERE session_id = ? LIMIT 1
            user_roles_query = (
                client.table("user_roles")
                .select("role")
                .eq("session_id", effective_session)
                .limit(1)
            )
            user_role_res = await user_roles_query.execute()

            role: Optional[str] = None
            if user_role_res.data and len(user_role_res.data) > 0:
                role = user_role_res.data[0].get("role")

            if not role:
                logger.warning(
                    "RBAC Denied: No role found in user_roles for session '%s'",
                    effective_session,
                )
                return False

            # 2. Query `role_permissions` table: SELECT tool_name FROM role_permissions WHERE role = ?
            perm_query = (
                client.table("role_permissions")
                .select("tool_name")
                .eq("role", role)
            )
            perm_res = await perm_query.execute()

            if perm_res.data:
                allowed_tools = {item.get("tool_name") for item in perm_res.data if item.get("tool_name")}
                if "*" in allowed_tools or tool_name in allowed_tools:
                    logger.info(
                        "RBAC Granted (Supabase): session='%s', role='%s', tool='%s'",
                        effective_session,
                        role,
                        tool_name,
                    )
                    return True

            logger.warning(
                "RBAC Denied (Supabase): session='%s', role='%s' lacks permission for tool '%s'",
                effective_session,
                role,
                tool_name,
            )
            return False

        except Exception as exc:
            logger.warning(
                "Supabase query failed (%s). Falling back to mock RBAC store.",
                str(exc),
            )

    # Resilient fallback for testing and development environments
    role = MOCK_USER_ROLES.get(effective_session, "standard")
    allowed_tools = MOCK_ROLE_PERMISSIONS.get(role, set())

    if "*" in allowed_tools or tool_name in allowed_tools:
        logger.info(
            "RBAC Granted (Mock): session='%s', role='%s', tool='%s'",
            effective_session,
            role,
            tool_name,
        )
        return True

    logger.warning(
        "RBAC Denied (Mock): session='%s', role='%s' not authorized for tool '%s'",
        effective_session,
        role,
        tool_name,
    )
    return False
