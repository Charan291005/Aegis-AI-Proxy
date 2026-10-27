"""Asynchronous MCP Reverse Proxy and Upstream Forwarding Engine.

Handles:
1. Dynamic reverse proxy forwarding to real upstream MCP servers (`UPSTREAM_MCP_URL`).
2. Protocol-level Zero-Trust RBAC filtering for `tools/list` (agent only discovers permitted tools).
3. Standard MCP 2024-11-05 handshakes (`initialize`, `ping`).
4. Standalone tool execution fallback when no upstream server is specified.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import httpx

from models.mcp_schemas import (
    CallToolResult,
    InitializeResult,
    MCPResponse,
    MCPToolDefinition,
    TextContent,
    ToolsListResult,
    create_mcp_error_response,
    create_mcp_text_response,
)
from security.config import get_settings
from services.db_client import verify_tool_permission

logger = logging.getLogger("aegis.services.proxy")

# Baseline tool registry for standalone execution and demonstration
STANDALONE_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "query_database",
        "description": "Executes a secure read query on the internal business database.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "customer_id": {"type": "string", "description": "Customer record identifier."}
            },
            "required": ["customer_id"],
        },
    },
    {
        "name": "read_file",
        "description": "Reads system configuration or documentation files.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative file path."}
            },
            "required": ["path"],
        },
    },
    {
        "name": "fetch_metrics",
        "description": "Fetches operational server telemetry and on-call engineer contacts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metric_type": {"type": "string", "description": "Type of telemetry to fetch."}
            },
        },
    },
    {
        "name": "simulate_tool",
        "description": "General diagnostic simulation tool.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "description": "Status payload to echo."}
            },
        },
    },
    {
        "name": "ping",
        "description": "MCP connectivity probe.",
        "inputSchema": {"type": "object"},
    },
    {
        "name": "echo",
        "description": "Echoes back input arguments for validation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Message to echo."}
            },
        },
    },
]

# Shared HTTP client singleton for upstream proxying
_HTTP_CLIENT: Optional[httpx.AsyncClient] = None


def get_proxy_http_client() -> httpx.AsyncClient:
    """Retrieve or initialize the high-performance connection-pooled HTTP client."""
    global _HTTP_CLIENT
    if _HTTP_CLIENT is None or _HTTP_CLIENT.is_closed:
        settings = get_settings()
        _HTTP_CLIENT = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.upstream_timeout_seconds),
            limits=httpx.Limits(max_keepalive_connections=50, max_connections=200),
            follow_redirects=True,
        )
    return _HTTP_CLIENT


async def close_proxy_http_client() -> None:
    """Close upstream HTTP client connection pool cleanly."""
    global _HTTP_CLIENT
    if _HTTP_CLIENT is not None and not _HTTP_CLIENT.is_closed:
        await _HTTP_CLIENT.aclose()
        _HTTP_CLIENT = None


async def dispatch_mcp_request(
    session_id: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Route an incoming MCP JSON-RPC 2.0 request either to upstream MCP server or standalone engine.

    Args:
        session_id: Correlated caller session ID for RBAC enforcement.
        payload: Full JSON-RPC request dictionary.
        headers: Forwarded client HTTP headers.

    Returns:
        Dict[str, Any]: JSON-RPC response dictionary.
    """
    settings = get_settings()
    method = payload.get("method", "")
    request_id = payload.get("id")
    params = payload.get("params") or {}

    logger.info("Dispatching MCP method '%s' (ID: %s, Session: %s)", method, request_id, session_id)

    # If upstream MCP URL is configured, forward to real upstream server
    if settings.upstream_mcp_url:
        return await forward_to_upstream(
            upstream_url=settings.upstream_mcp_url,
            session_id=session_id,
            payload=payload,
            headers=headers,
        )

    # Otherwise execute with standalone built-in MCP engine
    return await execute_standalone_mcp(
        session_id=session_id,
        method=method,
        request_id=request_id,
        params=params,
    )


async def forward_to_upstream(
    upstream_url: str,
    session_id: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Forward validated JSON-RPC payload to real upstream MCP server via HTTP."""
    client = get_proxy_http_client()
    method = payload.get("method", "")
    request_id = payload.get("id")

    req_headers = {"Content-Type": "application/json"}
    if headers:
        for k in ("X-Session-ID", "x-session-id", "User-Agent", "user-agent"):
            if k in headers:
                req_headers[k] = headers[k]

    try:
        logger.info("Forwarding '%s' to upstream MCP server: %s", method, upstream_url)
        resp = await client.post(upstream_url, json=payload, headers=req_headers)
        resp_data = resp.json()

        # If method was tools/list, apply Zero-Trust RBAC filtering to upstream tool manifest!
        if method == "tools/list" and isinstance(resp_data.get("result"), dict):
            raw_tools = resp_data["result"].get("tools", [])
            filtered_tools = []
            for tool in raw_tools:
                t_name = tool.get("name")
                if t_name and await verify_tool_permission(session_id, t_name):
                    filtered_tools.append(tool)
            resp_data["result"]["tools"] = filtered_tools
            logger.info(
                "Filtered upstream tools for session '%s': %d of %d tools permitted.",
                session_id,
                len(filtered_tools),
                len(raw_tools),
            )

        return resp_data

    except httpx.RequestError as exc:
        logger.error("Upstream MCP server connection failed (%s): %s", upstream_url, str(exc))
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32603,
                "message": f"Upstream MCP Gateway forwarding error: {str(exc)}",
            },
        }


async def execute_standalone_mcp(
    session_id: str,
    method: str,
    request_id: Optional[Any],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute standard MCP methods locally when running without an external upstream server."""
    # 1. MCP Handshake: initialize
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": True},
                    "logging": {},
                },
                "serverInfo": {
                    "name": "aegis-mcp-gateway",
                    "version": "1.0.0",
                },
            },
        }

    # 2. MCP Connectivity Probe: ping
    if method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {},
        }

    # 3. MCP Capability Discovery: tools/list (Enforces Zero-Trust RBAC Filtering)
    if method == "tools/list":
        permitted_tools = []
        for tool in STANDALONE_TOOLS:
            is_allowed = await verify_tool_permission(session_id, tool["name"])
            if is_allowed:
                permitted_tools.append(tool)

        logger.info(
            "tools/list discovery for session '%s': returning %d permitted tools.",
            session_id,
            len(permitted_tools),
        )
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": permitted_tools,
            },
        }

    # 4. MCP Tool Execution: tools/call
    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        if not tool_name:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": "Missing 'name' in tools/call params."},
            }

        # Simulated tool logic with realistic output (tested against Presidio DLP)
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
        elif tool_name == "ping":
            simulated_output = "pong"
        elif tool_name == "echo":
            msg = tool_args.get("message", "")
            simulated_output = f"Echo: {msg}"
        else:
            simulated_output = f"Tool '{tool_name}' executed successfully with arguments: {tool_args}."

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": simulated_output}],
                "isError": False,
                "_meta": None,
            },
            "error": None,
        }

    # Unsupported or unknown method
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32601,
            "message": f"Method '{method}' not found or unsupported by Aegis Gateway.",
        },
    }
