"""Strict Model Context Protocol (MCP) Pydantic Schemas.

Compliant with the official Model Context Protocol (JSON-RPC 2.0 based) specification.
Enforces zero-trust boundary constraints:
- All models explicitly forbid undeclared / extraneous fields (`extra = "forbid"`).
- Strict typing across request envelopes, parameters, content payloads, and responses.
- Injection vectors via prototype pollution or shadow fields are blocked at the schema layer.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field


class StrictBaseModel(BaseModel):
    """Base model enforcing zero-trust strictness across all derived MCP models.

    Any additional or unmapped properties in payloads are rejected with validation errors.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


class MCPMetadata(StrictBaseModel):
    """MCP Request / Response metadata block.

    Carries non-standardized context such as session tokens, traces, or security annotations.
    """

    session_id: Optional[str] = Field(
        default=None,
        description="Active session tracking identifier for rate limiting and RBAC correlation.",
    )
    user_id: Optional[str] = Field(
        default=None,
        description="Associated user or agent principal identity.",
    )
    client_version: Optional[str] = Field(
        default=None,
        description="Client agent implementation version.",
    )


class CallToolRequestParams(StrictBaseModel):
    """Parameters payload for `tools/call` method in MCP specification."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Identifier of the specific tool requested for execution.",
    )
    arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Dictionary of input parameters passed into the target tool.",
    )
    meta: Optional[MCPMetadata] = Field(
        default=None,
        alias="_meta",
        description="Optional session and context metadata.",
    )


class MCPToolCallRequest(StrictBaseModel):
    """Standard MCP Tool Execution Request Envelope.

    Conforms to JSON-RPC 2.0 protocol specifications for `tools/call`.
    """

    jsonrpc: Literal["2.0"] = Field(
        default="2.0",
        description="JSON-RPC protocol version specifier.",
    )
    id: Union[str, int] = Field(
        ...,
        description="Unique request correlation ID assigned by the invoking client/LLM.",
    )
    method: Literal["tools/call"] = Field(
        default="tools/call",
        description="Method name for invoking a registered MCP tool.",
    )
    params: CallToolRequestParams = Field(
        ...,
        description="Tool name and argument payload.",
    )


class TextContent(StrictBaseModel):
    """Text-based content return block for MCP tool execution results."""

    type: Literal["text"] = Field(
        default="text",
        description="Content block type indicator.",
    )
    text: str = Field(
        ...,
        description="Text content returned by the executed tool.",
    )


class ImageContent(StrictBaseModel):
    """Binary/Image content return block for MCP tool execution results."""

    type: Literal["image"] = Field(
        default="image",
        description="Content block type indicator.",
    )
    data: str = Field(
        ...,
        description="Base64-encoded representation of the image data.",
    )
    mimeType: str = Field(
        ...,
        description="MIME type of the encoded image data (e.g. 'image/png').",
    )


class EmbeddedResource(StrictBaseModel):
    """Resource content return block for MCP tool execution results."""

    type: Literal["resource"] = Field(
        default="resource",
        description="Content block type indicator.",
    )
    resource: Dict[str, Any] = Field(
        ...,
        description="Raw structured resource payload.",
    )


MCPContentBlock = Union[TextContent, ImageContent, EmbeddedResource]


class CallToolResult(StrictBaseModel):
    """Result payload container returned on successful tool execution."""

    content: List[MCPContentBlock] = Field(
        default_factory=list,
        description="Sequential list of content blocks returned from the tool.",
    )
    isError: bool = Field(
        default=False,
        description="Boolean flag indicating if the tool execution returned an error.",
    )
    meta: Optional[Dict[str, Any]] = Field(
        default=None,
        alias="_meta",
        description="Optional tool output metadata.",
    )


class MCPError(StrictBaseModel):
    """JSON-RPC 2.0 Error Object definition."""

    code: int = Field(
        ...,
        description="Integer error code conforming to JSON-RPC or MCP error categories.",
    )
    message: str = Field(
        ...,
        description="Human-readable summary of the error condition.",
    )
    data: Optional[Any] = Field(
        default=None,
        description="Optional structured debug or policy diagnostic payload.",
    )


class ToolInputSchema(StrictBaseModel):
    """Schema definition for tool input arguments."""

    type: str = "object"
    properties: Optional[Dict[str, Any]] = None
    required: Optional[List[str]] = None


class MCPToolDefinition(StrictBaseModel):
    """MCP Tool Capability definition."""

    name: str
    description: Optional[str] = None
    inputSchema: Dict[str, Any] = Field(default_factory=lambda: {"type": "object"})


class ToolsListResult(StrictBaseModel):
    """Result payload for tools/list method."""

    tools: List[MCPToolDefinition] = Field(default_factory=list)


class InitializeResult(StrictBaseModel):
    """Result payload for initialize handshake."""

    protocolVersion: str = "2024-11-05"
    capabilities: Dict[str, Any] = Field(default_factory=lambda: {"tools": {"listChanged": True}})
    serverInfo: Dict[str, str] = Field(default_factory=lambda: {"name": "aegis-mcp-gateway", "version": "1.0.0"})


class MCPGenericRequest(StrictBaseModel):
    """General MCP JSON-RPC 2.0 Request Envelope supporting all MCP methods."""

    jsonrpc: Literal["2.0"] = Field(
        default="2.0",
        description="JSON-RPC protocol version specifier.",
    )
    id: Optional[Union[str, int]] = Field(
        default=None,
        description="Request correlation ID.",
    )
    method: str = Field(
        ...,
        description="Method name (e.g., 'tools/call', 'tools/list', 'initialize', 'ping').",
    )
    params: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Parameters payload for the method.",
    )


class MCPResponse(StrictBaseModel):
    """Full MCP Response Envelope for Tool Execution & Protocol Operations.

    Guarantees strict bidirectional conformance with JSON-RPC 2.0 standard.
    """

    jsonrpc: Literal["2.0"] = Field(
        default="2.0",
        description="JSON-RPC protocol version specifier.",
    )
    id: Optional[Union[str, int]] = Field(
        default=None,
        description="Matching correlation ID from the initial tool request.",
    )
    result: Optional[Union[CallToolResult, ToolsListResult, InitializeResult, Dict[str, Any]]] = Field(
        default=None,
        description="Populated upon successful execution.",
    )
    error: Optional[MCPError] = Field(
        default=None,
        description="Populated upon execution or protocol failure.",
    )


def create_mcp_text_response(
    request_id: Union[str, int],
    text: str,
    is_error: bool = False,
) -> MCPResponse:
    """Helper factory to construct a strictly compliant MCP text response."""
    return MCPResponse(
        id=request_id,
        result=CallToolResult(
            content=[TextContent(type="text", text=text)],
            isError=is_error,
        ),
    )


def create_mcp_error_response(
    request_id: Union[str, int],
    code: int,
    message: str,
    data: Optional[Any] = None,
) -> MCPResponse:
    """Helper factory to construct a strictly compliant JSON-RPC error response."""
    return MCPResponse(
        id=request_id,
        error=MCPError(code=code, message=message, data=data),
    )
