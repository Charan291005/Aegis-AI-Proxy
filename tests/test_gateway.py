"""Comprehensive Test Suite for Aegis Zero-Trust MCP Gateway.

Phase 1 & Phase 2 Validations:
1. Strict schema validation (extra='forbid').
2. Forward path: Bearer token authentication enforcement.
3. Forward path: Shell injection blocking (&&, |, ;, /bin/sh, powershell, backticks, subshells).
4. Forward path: Supabase RBAC authorization (`user_roles` & `role_permissions`).
5. Return path: Presidio DLP redaction (credit card, email, phone number).
6. Return path & Forward path: Immutable Supabase audit logging (`ALLOWED`, `BLOCKED_POLICY`, `SANITIZED_PII`).
7. Information leakage prevention: generic 403 Forbidden responses.
"""

import pytest
from fastapi.testclient import TestClient
from main import app
from security.config import get_settings
from services.audit_logger import clear_audit_log_buffer, get_audit_log_buffer
from services.db_client import verify_tool_permission

client = TestClient(app)
settings = get_settings()

VALID_TOKEN = settings.aegis_gateway_token
VALID_HEADERS = {
    "Authorization": f"Bearer {VALID_TOKEN}",
    "Content-Type": "application/json",
}


@pytest.fixture(autouse=True)
def reset_audit_logs():
    """Reset the audit buffer before each test."""
    clear_audit_log_buffer()
    yield


def test_health_check_endpoint():
    """Verify health endpoint is publicly accessible for probes."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_missing_bearer_token_blocked():
    """Verify that requests without Bearer token are blocked with generic 403."""
    payload = {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {
            "name": "fetch_metrics",
            "arguments": {},
        },
    }
    response = client.post("/mcp/execute", json=payload)
    assert response.status_code == 403
    assert response.json() == {"error": "Forbidden: Request blocked by security policy"}


def test_invalid_bearer_token_blocked():
    """Verify that requests with invalid Bearer token are rejected with generic 403."""
    headers = {
        "Authorization": "Bearer invalid_malicious_token",
        "Content-Type": "application/json",
    }
    payload = {
        "jsonrpc": "2.0",
        "id": "req-2",
        "method": "tools/call",
        "params": {
            "name": "fetch_metrics",
            "arguments": {},
        },
    }
    response = client.post("/mcp/execute", json=payload, headers=headers)
    assert response.status_code == 403
    assert response.json() == {"error": "Forbidden: Request blocked by security policy"}


def test_strict_schema_forbids_extra_fields():
    """Verify that submitting unmapped / extra fields is rejected."""
    payload = {
        "jsonrpc": "2.0",
        "id": "req-3",
        "method": "tools/call",
        "params": {
            "name": "fetch_metrics",
            "arguments": {},
            "malicious_shadow_field": "exploit_payload",  # Extra field!
        },
    }
    response = client.post("/mcp/execute", json=payload, headers=VALID_HEADERS)
    # Generic 403 validation handler blocks extra fields
    assert response.status_code == 403
    assert response.json() == {"error": "Forbidden: Request blocked by security policy"}


@pytest.mark.parametrize(
    "malicious_arg",
    [
        "hello && rm -rf /",
        "test; cat /etc/passwd",
        "query | /bin/sh",
        "/bin/bash -c 'id'",
        "`cat /etc/shadow`",
        "$(whoami)",
        "powershell.exe -c calc",
        "data > /dev/null",
    ],
)
def test_shell_injection_blocking_and_audit(malicious_arg):
    """Verify that shell injection vectors in tool arguments are intercepted and logged as BLOCKED_POLICY."""
    payload = {
        "jsonrpc": "2.0",
        "id": "req-inject",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": malicious_arg},
        },
    }
    response = client.post("/mcp/execute", json=payload, headers=VALID_HEADERS)
    assert response.status_code == 403
    assert response.json() == {"error": "Forbidden: Request blocked by security policy"}

    # Verify audit log was recorded
    logs = get_audit_log_buffer()
    assert len(logs) >= 1
    latest = logs[-1]
    assert latest["status"] == "BLOCKED_POLICY"
    assert latest["mitigation_applied"] == "SHELL_INJECTION_SHIELD"
    assert latest["tool_name"] == "read_file"


def test_rbac_unauthorized_session_blocked_and_audited():
    """Verify that unauthorized sessions are denied tool execution and logged as BLOCKED_POLICY."""
    payload = {
        "jsonrpc": "2.0",
        "id": "req-unauth",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "docs.txt"},
            "_meta": {"session_id": "sess-unauthorized-999"},
        },
    }
    response = client.post("/mcp/execute", json=payload, headers=VALID_HEADERS)
    assert response.status_code == 403
    assert response.json() == {"error": "Forbidden: Request blocked by security policy"}

    # Verify audit log was recorded
    logs = get_audit_log_buffer()
    assert len(logs) >= 1
    latest = logs[-1]
    assert latest["status"] == "BLOCKED_POLICY"
    assert latest["mitigation_applied"] == "RBAC_PERMISSION_DENIED"
    assert latest["session_id"] == "sess-unauthorized-999"


def test_return_path_pii_redaction_and_audit():
    """Verify tool responses with sensitive PII are redacted on return path and logged as SANITIZED_PII."""
    headers = dict(VALID_HEADERS)
    headers["X-Session-ID"] = "sess-operator-002"

    payload = {
        "jsonrpc": "2.0",
        "id": "req-dlp",
        "method": "tools/call",
        "params": {
            "name": "query_database",
            "arguments": {"customer_id": "cust_123"},
        },
    }
    response = client.post("/mcp/execute", json=payload, headers=headers)
    assert response.status_code == 200

    data = response.json()
    assert data["jsonrpc"] == "2.0"
    assert data["id"] == "req-dlp"

    # Verify content returned
    content_text = data["result"]["content"][0]["text"]

    # Verify that raw PII was completely redacted
    assert "jane.doe@example.com" not in content_text
    assert "4111-1111-1111-1111" not in content_text
    assert "555-019-2834" not in content_text

    # Verify redaction marker is present
    assert "<REDACTED_PII>" in content_text

    # Verify audit log was recorded with status 'SANITIZED_PII'
    logs = get_audit_log_buffer()
    assert len(logs) >= 1
    latest = logs[-1]
    assert latest["status"] == "SANITIZED_PII"
    assert latest["mitigation_applied"] == "PRESIDIO_PII_REDACTION"
    assert latest["tool_name"] == "query_database"
    assert latest["payload_summary"]["redacted_entities_count"] > 0


def test_successful_request_logged_as_allowed():
    """Verify tool invocation without PII records an ALLOWED audit log entry."""
    headers = dict(VALID_HEADERS)
    headers["X-Session-ID"] = "sess-operator-002"

    payload = {
        "jsonrpc": "2.0",
        "id": "req-allowed",
        "method": "tools/call",
        "params": {
            "name": "simulate_tool",
            "arguments": {"status": "ok"},
        },
    }
    response = client.post("/mcp/execute", json=payload, headers=headers)
    assert response.status_code == 200

    logs = get_audit_log_buffer()
    assert len(logs) >= 1
    latest = logs[-1]
    assert latest["status"] == "ALLOWED"
    assert latest["mitigation_applied"] is None
    assert latest["tool_name"] == "simulate_tool"


def test_db_client_verify_tool_permission_unit():
    """Unit test for verify_tool_permission function in services/db_client.py."""
    import asyncio

    async def run_checks():
        # Admin allowed any tool
        assert await verify_tool_permission("sess-admin-001", "any_random_tool") is True
        # Operator allowed permitted tools
        assert await verify_tool_permission("sess-operator-002", "query_database") is True
        # Operator denied unmapped tool
        assert await verify_tool_permission("sess-operator-002", "forbidden_root_exec") is False
        # Unauthorized session denied
        assert await verify_tool_permission("sess-unauthorized-999", "read_file") is False

    asyncio.run(run_checks())


def test_secrets_redaction_api_keys_and_tokens():
    """Verify return-path DLP automatically masks OpenAI keys and AWS tokens as <REDACTED_SECRET>."""
    from services.dlp_engine import sanitize_text

    secret_text = (
        "Server config: OpenAI Key is sk-abcdef1234567890abcdef1234567890, "
        "AWS Access Key is AKIAIOSFODNN7EXAMPLE, and contact is admin@aegis.corp."
    )
    sanitized = sanitize_text(secret_text)
    assert "sk-abcdef1234567890" not in sanitized
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "<REDACTED_SECRET>" in sanitized
    assert "<REDACTED_PII>" in sanitized


def test_tools_list_rbac_filtering_via_dispatch():
    """Verify that tools/list endpoint dynamically filters tools based on the caller's RBAC role."""
    # 1. Operator session: should see query_database and read_file
    headers_operator = dict(VALID_HEADERS)
    headers_operator["X-Session-ID"] = "sess-operator-002"

    payload = {
        "jsonrpc": "2.0",
        "id": "list-1",
        "method": "tools/list",
        "params": {},
    }
    resp = client.post("/mcp/dispatch", json=payload, headers=headers_operator)
    assert resp.status_code == 200
    tools = resp.json()["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "query_database" in tool_names
    assert "read_file" in tool_names

    # 2. Unauthorized session: should see 0 tools
    headers_unauth = dict(VALID_HEADERS)
    headers_unauth["X-Session-ID"] = "sess-unauthorized-999"
    resp_unauth = client.post("/mcp/dispatch", json=payload, headers=headers_unauth)
    assert resp_unauth.status_code == 200
    assert len(resp_unauth.json()["result"]["tools"]) == 0


def test_initialize_handshake():
    """Verify official MCP 2024-11-05 initialize handshake response."""
    payload = {
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {},
    }
    resp = client.post("/mcp/dispatch", json=payload, headers=VALID_HEADERS)
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["protocolVersion"] == "2024-11-05"
    assert "tools" in result["capabilities"]
    assert result["serverInfo"]["name"] == "aegis-mcp-gateway"


def test_security_and_rate_limit_headers():
    """Verify standard security headers and rate-limiting quota headers are injected."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"

    # Rate limiting headers on MCP endpoints
    payload = {
        "jsonrpc": "2.0",
        "id": "probe-rl",
        "method": "ping",
        "params": {},
    }
    mcp_resp = client.post("/mcp/dispatch", json=payload, headers=VALID_HEADERS)
    assert mcp_resp.status_code == 200
    assert "X-RateLimit-Limit" in mcp_resp.headers
    assert "X-RateLimit-Remaining" in mcp_resp.headers

