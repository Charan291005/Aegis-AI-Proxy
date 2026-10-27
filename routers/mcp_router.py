"""MCP Gateway Execution Router.

Provides the `/mcp/execute` endpoint for dispatching tool calls.
Demonstrates end-to-end forward path authorization, argument sanitization,
tool simulation, and return path DLP PII redaction.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse

from models.mcp_schemas import (
    CallToolResult,
    MCPResponse,
    MCPToolCallRequest,
    TextContent,
    create_mcp_text_response,
)
from services.dlp_engine import sanitize_tool_response

logger = logging.getLogger("aegis.routers.mcp")

router = APIRouter(prefix="/mcp", tags=["MCP Tool Execution"])


@router.post(
    "/execute",
    response_model=MCPResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Model Context Protocol (MCP) Tool Call",
    description="Intercepted tool invocation endpoint protected by forward-path RBAC and return-path DLP.",
)
async def execute_tool_call(
    request: Request,
    payload: MCPToolCallRequest,
) -> MCPResponse:
    """Simulate tool execution and enforce return-path DLP sanitization.

    Workflow:
    1. The payload is strictly validated against `MCPToolCallRequest` (extra='forbid').
    2. Forward-path middleware has already verified the Bearer token, blocked shell injection,
       and confirmed RBAC permissions.
    3. Simulated tool execution produces output (which may contain raw PII).
    4. The return-path DLP engine redacts CREDIT_CARD, EMAIL_ADDRESS, and PHONE_NUMBER.
    5. Clean, sanitized MCP response is returned to the client.
    """
    tool_name = payload.params.name
    tool_args = payload.params.arguments
    request_id = payload.id

    logger.info("Executing simulated tool '%s' (ID: %s)", tool_name, request_id)

    # Simulated tool logic with realistic output including PII to test return-path DLP
    if tool_name == "query_database":
        simulated_output = (
            f"Database query successful for args: {tool_args}. "
            "Found record: Customer Jane Doe, Email: jane.doe@example.com, "
            "Phone: +1-555-019-2834, Billing Card: 4111-1111-1111-1111."
        )
    elif tool_name == "read_file":
        path = tool_args.get("path", "unknown.txt")
        simulated_output = (
            f"Contents of {path}: Server admin contact is security-team@aegis.internal, "
            "direct phone is +1 (415) 555-0142. Emergency backup card on file: 4532-0150-0000-0008."
        )
    elif tool_name == "fetch_metrics":
        simulated_output = (
            "System status: HEALTHY. CPU: 12%, Memory: 44%. "
            "On-call engineer: ops-lead@aegis.corp, cell: 555-123-4567."
        )
    else:
        simulated_output = (
            f"Tool '{tool_name}' executed successfully with arguments: {tool_args}."
        )

    # Construct and return compliant MCP response structure
    # Return-path interceptor middleware applies Microsoft Presidio DLP and logs audit events
    return create_mcp_text_response(
        request_id=request_id,
        text=simulated_output,
        is_error=False,
    )
