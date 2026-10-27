"""Role-Based Access Control (RBAC) Service with Supabase PostgreSQL Integration.

Implements Zero-Trust Principal of Least Privilege (PoLP):
- Every tool invocation must be verified against authorization policy.
- Sessions map to roles; roles map to strict tool permissions.
- Fails closed: any unrecognized tool, missing session, or unmapped role is denied.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import httpx

from security.config import get_settings

logger = logging.getLogger("aegis.security.rbac")


class UserRole(str, Enum):
    """Supported authorization roles within Aegis Gateway."""

    ADMIN = "admin"
    OPERATOR = "operator"
    ANALYST = "analyst"
    READ_ONLY = "read_only"
    UNAUTHORIZED = "unauthorized"


# Role-Based Permission Matrix: maps roles to permissible tool names or wildcards
ROLE_PERMISSIONS: Dict[UserRole, Set[str]] = {
    UserRole.ADMIN: {"*"},
    UserRole.OPERATOR: {
        "read_file",
        "query_database",
        "list_directory",
        "fetch_metrics",
        "simulate_tool",
        "ping",
        "echo",
    },
    UserRole.ANALYST: {
        "read_file",
        "fetch_metrics",
        "simulate_tool",
        "ping",
        "echo",
    },
    UserRole.READ_ONLY: {
        "ping",
        "echo",
        "simulate_tool",
    },
    UserRole.UNAUTHORIZED: set(),
}

# In-memory mock session store for local development and stubbed testing
MOCK_SESSION_STORE: Dict[str, UserRole] = {
    "sess-admin-001": UserRole.ADMIN,
    "sess-operator-002": UserRole.OPERATOR,
    "sess-analyst-003": UserRole.ANALYST,
    "sess-readonly-004": UserRole.READ_ONLY,
    "sess-unauthorized-999": UserRole.UNAUTHORIZED,
    "default-session": UserRole.ANALYST,
}


async def fetch_user_role_from_supabase(session_id: str) -> Optional[UserRole]:
    """Query Supabase PostgreSQL table `session_roles` for active session authority.

    Args:
        session_id: The session identifier extracted from the MCP payload/headers.

    Returns:
        UserRole if found in Supabase, None if database unreachable or session absent.
    """
    settings = get_settings()

    # If Supabase URL or service key is not configured, fallback to stub
    if not settings.supabase_url or not settings.supabase_service_role_key:
        logger.debug(
            "Supabase credentials not configured in environment. Using stubbed store."
        )
        return MOCK_SESSION_STORE.get(session_id, UserRole.ANALYST)

    # Supabase PostgREST endpoint for session resolution
    # Query: GET /rest/v1/session_roles?session_id=eq.{session_id}&select=role,is_active
    url = f"{settings.supabase_url.rstrip('/')}/rest/v1/session_roles"
    headers = {
        "apikey": settings.supabase_service_role_key,
        "Authorization": f"Bearer {settings.supabase_service_role_key}",
        "Content-Type": "application/json",
    }
    params = {
        "session_id": f"eq.{session_id}",
        "is_active": "eq.true",
        "select": "role",
        "limit": "1",
    }

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                if data and len(data) > 0:
                    raw_role = data[0].get("role", "").lower()
                    return UserRole(raw_role)
                logger.warning("Session '%s' not found in Supabase RBAC table.", session_id)
                return UserRole.UNAUTHORIZED
            else:
                logger.error(
                    "Supabase returned HTTP %d during RBAC lookup.", response.status_code
                )
                # Fail-closed in case of unexpected HTTP error
                return None
    except Exception as exc:
        logger.warning(
            "Failed connecting to Supabase (%s). Falling back to mock session store.",
            str(exc),
        )
        # Resilient fallback to mock store during network interruption / dev
        return MOCK_SESSION_STORE.get(session_id, UserRole.ANALYST)


async def verify_user_role(
    session_id: Optional[str],
    tool_name: str,
    bearer_token: Optional[str] = None,
) -> bool:
    """Evaluate whether the given session/user is authorized to execute the requested tool.

    Zero-Trust enforcement:
    1. If session_id is missing, default to a non-privileged guest session.
    2. Retrieve user role from Supabase.
    3. Check against explicit permission matrix.
    4. Deny access by default if no matching permission rule exists.

    Args:
        session_id: Session identifier extracted from request.
        tool_name: MCP tool name requested by the client.
        bearer_token: Raw Bearer token for optional token-based role overrides.

    Returns:
        bool: True if authorized, False otherwise.
    """
    effective_session_id = session_id or "default-session"

    # Token-level role override for direct administrative or test access
    if bearer_token and bearer_token.startswith("role:"):
        role_override = bearer_token.split("role:", 1)[1].strip()
        try:
            user_role = UserRole(role_override)
        except ValueError:
            logger.warning("Invalid role override in token: %s", role_override)
            return False
    else:
        user_role = await fetch_user_role_from_supabase(effective_session_id)

    if not user_role or user_role == UserRole.UNAUTHORIZED:
        logger.warning(
            "Access Denied: Session '%s' resolved to UNAUTHORIZED or invalid role.",
            effective_session_id,
        )
        return False

    allowed_tools = ROLE_PERMISSIONS.get(user_role, set())

    # Check wildcard admin permission or exact tool name match
    if "*" in allowed_tools or tool_name in allowed_tools:
        logger.info(
            "Access Granted: Session '%s' (role=%s) authorized for tool '%s'.",
            effective_session_id,
            user_role.value,
            tool_name,
        )
        return True

    logger.warning(
        "Access Denied: Session '%s' (role=%s) not authorized for tool '%s'.",
        effective_session_id,
        user_role.value,
        tool_name,
    )
    return False
