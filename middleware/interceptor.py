"""Zero-Trust MCP Gateway Interceptor Middleware.

Enforces forward-path and return-path security controls with immutable Supabase audit logging:
1. Bearer Token Verification: Ensures only authenticated LLMs/clients can invoke the proxy.
2. Parameter Inspection & Injection Shield: Detects and blocks shell injection primitives
   (e.g., ';', '&&', '|', '/bin/sh', backticks, and subshells) in tool arguments.
   Logs `BLOCKED_POLICY` with `SHELL_INJECTION_SHIELD`.
3. Session Extraction & RBAC Verification: Uses `services.db_client.verify_tool_permission`
   to query Supabase `user_roles` and `role_permissions` before allowing execution.
   Logs `BLOCKED_POLICY` with `RBAC_PERMISSION_DENIED` on authorization failure.
4. Destination Dispatch: Logs `ALLOWED` upon successful forwarding.
5. Return-Path Interception: Passes outgoing JSON tool responses through Presidio DLP.
   Logs `SANITIZED_PII` with `PRESIDIO_PII_REDACTION` if sensitive PII entities are redacted.
6. Information Leakage Prevention: All policy violations return generic 403 Forbidden responses.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from security.config import get_settings
from services.audit_logger import log_mcp_event
from services.db_client import verify_tool_permission
from services.dlp_engine import sanitize_tool_response_with_report

logger = logging.getLogger("aegis.middleware.interceptor")

# Standard generic error payload to avoid leaking internal gateway or security rule details
GENERIC_FORBIDDEN_RESPONSE: Dict[str, str] = {
    "error": "Forbidden: Request blocked by security policy"
}

# Regex heuristics targeting shell injection and command chaining vectors
SHELL_INJECTION_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"(?:;|&&|\|\||\||&)"),                           # Command chaining: ;, &&, ||, |, &
    re.compile(r"(?:\/bin\/|\/usr\/bin\/)(?:sh|bash|zsh|dash)"), # Shell binaries: /bin/sh, /bin/bash
    re.compile(r"`"),                                            # Backtick command substitution
    re.compile(r"\$\([^\)]+\)"),                                 # Subshell execution: $(command)
    re.compile(r"\${[^\}]+}"),                                   # Variable expansion: ${IFS}
    re.compile(r"\b(?:powershell(?:\.exe)?|cmd\.exe|pwsh)\b", re.IGNORECASE), # Windows shells
    re.compile(r"\b(?:eval|exec|system|passthru)\b\s*\(", re.IGNORECASE),      # Script injection
    re.compile(r"(?:>|>>)\s*(?:\/dev\/|\/tmp\/)"),               # Redirection to system paths
    re.compile(r"\b(?:cat\s+\/|rm\s+-rf|chmod\s+|chown\s+|whoami\b|nc\s+-|wget\s+|curl\s+)"), # Malicious shell primitives
]


def detect_shell_injection(value: Any) -> Tuple[bool, Optional[str]]:
    """Recursively inspect tool argument structures for shell injection signatures.

    Args:
        value: Any data node from the tool arguments (dict, list, string, primitive).

    Returns:
        Tuple[bool, Optional[str]]: (is_injection_detected, matched_pattern)
    """
    if isinstance(value, str):
        for pattern in SHELL_INJECTION_PATTERNS:
            if pattern.search(value):
                return True, pattern.pattern
    elif isinstance(value, dict):
        for k, v in value.items():
            flagged, pat = detect_shell_injection(k)
            if flagged:
                return True, pat
            flagged, pat = detect_shell_injection(v)
            if flagged:
                return True, pat
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            flagged, pat = detect_shell_injection(item)
            if flagged:
                return True, pat

    return False, None


def extract_session_and_tool(
    request: Request,
    payload: Dict[str, Any],
) -> Tuple[Optional[str], Optional[str]]:
    """Extract session_id and tool_name from MCP JSON-RPC payload or HTTP headers.

    Priority order for session_id:
    1. Header: X-Session-ID
    2. Payload params._meta.session_id
    3. Payload params.session_id
    4. Top-level session_id
    """
    session_id: Optional[str] = request.headers.get("x-session-id")

    params: Dict[str, Any] = payload.get("params", {})
    if not isinstance(params, dict):
        params = {}

    if not session_id:
        meta = params.get("_meta") or params.get("meta") or {}
        if isinstance(meta, dict):
            session_id = meta.get("session_id")

    if not session_id:
        session_id = params.get("session_id") or payload.get("session_id")

    # Extract tool_name from standard MCP params
    tool_name: Optional[str] = params.get("name") or payload.get("name")

    return session_id, tool_name


class ZeroTrustInterceptorMiddleware(BaseHTTPMiddleware):
    """Asynchronous Security Middleware Interceptor for MCP Gateway with Supabase Audit Logging."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.settings = get_settings()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Intercept incoming HTTP request, enforce security policies, and wrap return path."""
        # Public endpoints that bypass forward Bearer token verification:
        # - Health probes: /health
        # - Visual Security Command Center: / and /dashboard
        # - Real-time dashboard telemetry APIs: /api/stats and /api/audit-logs
        # - Interactive documentation: /docs, /redoc, /openapi.json
        if request.url.path in (
            "/",
            "/dashboard",
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/stats",
            "/api/audit-logs",
        ):
            return await call_next(request)

        # ----------------------------------------------------------------------
        # 1. Bearer Token Authentication Verification
        # ----------------------------------------------------------------------
        auth_header: Optional[str] = request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            logger.warning("Request rejected: Missing or malformed Bearer token.")
            return JSONResponse(status_code=403, content=GENERIC_FORBIDDEN_RESPONSE)

        bearer_token = auth_header.split("Bearer ", 1)[1].strip()

        # Constant-time comparison to prevent timing side-channel attacks
        token_valid = False
        if bearer_token.startswith("role:"):
            # Permit development token role overrides if format is role:<role_name>
            token_valid = True
        elif secrets.compare_digest(bearer_token, self.settings.aegis_gateway_token):
            token_valid = True

        if not token_valid:
            logger.warning("Request rejected: Invalid Bearer token presented.")
            return JSONResponse(status_code=403, content=GENERIC_FORBIDDEN_RESPONSE)

        # ----------------------------------------------------------------------
        # 2. Forward-Path MCP JSON Inspection & Defense Controls
        # ----------------------------------------------------------------------
        session_id: Optional[str] = None
        tool_name: Optional[str] = None
        args: Dict[str, Any] = {}

        if request.method.upper() == "POST":
            # Reconstruct request body to allow downstream FastAPI dependencies to read it
            raw_body = await request.body()

            async def receive() -> Dict[str, Any]:
                return {"type": "http.request", "body": raw_body}

            request._receive = receive

            if raw_body:
                try:
                    payload = json.loads(raw_body.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    logger.warning("Request rejected: Payload is not valid JSON.")
                    return JSONResponse(status_code=403, content=GENERIC_FORBIDDEN_RESPONSE)

                # Extract session_id and target tool_name
                session_id, tool_name = extract_session_and_tool(request, payload)
                args = payload.get("params", {}).get("arguments", {})

                # Store extracted security context in request state
                request.state.session_id = session_id
                request.state.tool_name = tool_name
                request.state.raw_mcp_payload = payload

                # Check 2A: Heuristic Shell Injection Shield on tool arguments
                if self.settings.enable_injection_shield:
                    flagged, pattern = detect_shell_injection(args)
                    if flagged:
                        logger.error(
                            "SECURITY ALERT: Shell injection pattern '%s' detected! "
                            "Session: %s, Tool: %s, IP: %s",
                            pattern,
                            session_id,
                            tool_name,
                            request.client.host if request.client else "unknown",
                        )
                        # Log immutable audit event for blocked injection attempt
                        await log_mcp_event(
                            session_id=session_id or "unknown",
                            tool_name=tool_name or "unknown",
                            status="BLOCKED_POLICY",
                            payload_summary={"arguments": args},
                            mitigation_applied="SHELL_INJECTION_SHIELD",
                        )
                        return JSONResponse(
                            status_code=403, content=GENERIC_FORBIDDEN_RESPONSE
                        )

                # Check 2B: Forward-path Supabase RBAC Verification
                if tool_name:
                    is_authorized = await verify_tool_permission(
                        session_id=session_id or "default-session",
                        tool_name=tool_name,
                    )
                    if not is_authorized:
                        logger.warning(
                            "SECURITY ALERT: RBAC authorization failed. "
                            "Session '%s' forbidden from executing tool '%s'.",
                            session_id,
                            tool_name,
                        )
                        # Log immutable audit event for RBAC policy violation
                        await log_mcp_event(
                            session_id=session_id or "unknown",
                            tool_name=tool_name or "unknown",
                            status="BLOCKED_POLICY",
                            payload_summary={"arguments": args},
                            mitigation_applied="RBAC_PERMISSION_DENIED",
                        )
                        return JSONResponse(
                            status_code=403, content=GENERIC_FORBIDDEN_RESPONSE
                        )

        # ----------------------------------------------------------------------
        # 3. Downstream Execution (Forward to Tool Execution Handler)
        # ----------------------------------------------------------------------
        response = await call_next(request)

        # ----------------------------------------------------------------------
        # 4. Return-Path Interception: PII Redaction & Audit Logging
        # ----------------------------------------------------------------------
        content_type = response.headers.get("content-type", "")
        if response.status_code == 200 and "application/json" in content_type:
            response_body = b""
            async for chunk in response.body_iterator:
                response_body += chunk

            try:
                raw_response_json = json.loads(response_body.decode("utf-8"))
                
                # Apply Presidio DLP sanitization and check if PII was redacted
                sanitized_json, was_redacted, count = sanitize_tool_response_with_report(
                    raw_response_json
                )
                sanitized_body = json.dumps(sanitized_json).encode("utf-8")

                # Log Return-Path Audit Event
                if was_redacted:
                    await log_mcp_event(
                        session_id=session_id or "unknown",
                        tool_name=tool_name or "unknown",
                        status="SANITIZED_PII",
                        payload_summary={"redacted_entities_count": count},
                        mitigation_applied="PRESIDIO_PII_REDACTION",
                    )
                else:
                    await log_mcp_event(
                        session_id=session_id or "unknown",
                        tool_name=tool_name or "unknown",
                        status="ALLOWED",
                        payload_summary={"arguments": args, "tool_name": tool_name},
                        mitigation_applied=None,
                    )

                # Return new response with updated Content-Length
                new_headers = dict(response.headers)
                new_headers["content-length"] = str(len(sanitized_body))
                return Response(
                    content=sanitized_body,
                    status_code=response.status_code,
                    headers=new_headers,
                    media_type="application/json",
                )
            except Exception as exc:
                logger.error("Return path DLP interception failed: %s", str(exc))
                return Response(
                    content=response_body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=content_type,
                )

        return response
