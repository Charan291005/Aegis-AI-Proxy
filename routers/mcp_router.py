"""MCP Gateway Execution Router.

Provides:
- `/mcp/execute`: Direct tool execution endpoint (strictly validates tools/call).
- `/mcp/dispatch`: General MCP JSON-RPC 2.0 endpoint (supporting initialize, ping, tools/list, tools/call).

Integrates upstream MCP server reverse proxying, dynamic RBAC filtering, and Presidio DLP.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from fastapi import APIRouter, Request, status

from models.mcp_schemas import (
    MCPGenericRequest,
    MCPResponse,
    MCPToolCallRequest,
)
from services.mcp_proxy_service import dispatch_mcp_request

logger = logging.getLogger("aegis.routers.mcp")

router = APIRouter(prefix="/mcp", tags=["MCP Tool Execution"])


@router.post(
    "/execute",
    response_model=MCPResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Model Context Protocol (MCP) Tool Call",
    description=(
        "Intercepted tool invocation endpoint protected by forward-path RBAC, "
        "upstream reverse proxying, and return-path DLP sanitization."
    ),
)
async def execute_tool_call(
    request: Request,
    payload: MCPToolCallRequest,
) -> MCPResponse:
    """Execute tool call via upstream proxy or standalone engine."""
    session_id = getattr(request.state, "session_id", None) or "default-session"
    result_dict = await dispatch_mcp_request(
        session_id=session_id,
        payload=payload.model_dump(by_alias=True, exclude_none=True),
        headers=dict(request.headers),
    )
    return MCPResponse.model_validate(result_dict)


@router.post(
    "/dispatch",
    response_model=MCPResponse,
    status_code=status.HTTP_200_OK,
    summary="General Model Context Protocol (MCP) Endpoint",
    description=(
        "Full JSON-RPC 2.0 gateway endpoint handling initialize, ping, "
        "tools/list (with Zero-Trust RBAC filtering), and tools/call."
    ),
)
async def dispatch_mcp(
    request: Request,
    payload: MCPGenericRequest,
) -> MCPResponse:
    """Dispatch any standard MCP JSON-RPC request."""
    session_id = getattr(request.state, "session_id", None) or "default-session"
    result_dict = await dispatch_mcp_request(
        session_id=session_id,
        payload=payload.model_dump(by_alias=True, exclude_none=True),
        headers=dict(request.headers),
    )
    return MCPResponse.model_validate(result_dict)
