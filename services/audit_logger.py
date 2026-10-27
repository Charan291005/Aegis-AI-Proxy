"""Immutable Audit Logger for Aegis MCP Gateway.

Records every tool interaction to Supabase table `mcp_audit_logs` for regulatory compliance,
forensics, and zero-trust verification.

Event Statuses:
- 'ALLOWED': Tool call authorized and safely passed to execution.
- 'BLOCKED_POLICY': Rejected due to RBAC denial or shell injection detection.
- 'SANITIZED_PII': Tool response contained sensitive data; PII was redacted via Presidio DLP.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.db_client import get_supabase_client

logger = logging.getLogger("aegis.services.audit_logger")

# In-memory buffer for local auditing and test assertion verification
AUDIT_LOG_BUFFER: List[Dict[str, Any]] = []


async def log_mcp_event(
    session_id: str,
    tool_name: str,
    status: str,
    payload_summary: Dict[str, Any],
    mitigation_applied: Optional[str] = None,
) -> Dict[str, Any]:
    """Insert an immutable audit event into Supabase table `mcp_audit_logs`.

    Args:
        session_id: Session identifier linked to the calling principal.
        tool_name: Requested MCP tool name.
        status: Interaction outcome ('ALLOWED', 'BLOCKED_POLICY', or 'SANITIZED_PII').
        payload_summary: Non-sensitive summary of request/response payload parameters.
        mitigation_applied: Security mitigation label (e.g. 'SHELL_INJECTION_SHIELD', 'PRESIDIO_PII_REDACTION').

    Returns:
        Dict[str, Any]: The audit record structured for persistence.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    record: Dict[str, Any] = {
        "session_id": session_id or "anonymous",
        "tool_name": tool_name or "unknown",
        "status": status,
        "payload_summary": payload_summary if isinstance(payload_summary, dict) else {"summary": str(payload_summary)},
        "mitigation_applied": mitigation_applied,
        "timestamp": timestamp,
    }

    # Always preserve locally for testing/diagnostics
    AUDIT_LOG_BUFFER.append(record)

    logger.info(
        "AUDIT EVENT [%s]: session='%s', tool='%s', mitigation='%s'",
        status,
        record["session_id"],
        record["tool_name"],
        mitigation_applied or "none",
    )

    client = await get_supabase_client()
    if client:
        try:
            # Asynchronously insert into Supabase table `mcp_audit_logs`
            insert_query = client.table("mcp_audit_logs").insert(record)
            await insert_query.execute()
            logger.debug("Successfully persisted audit event to Supabase.")
        except Exception as exc:
            logger.warning(
                "Failed to write audit log to Supabase (%s). Record kept in memory buffer.",
                str(exc),
            )

    return record


def get_audit_log_buffer() -> List[Dict[str, Any]]:
    """Retrieve recorded in-memory audit logs (useful for testing and monitoring)."""
    return list(AUDIT_LOG_BUFFER)


def clear_audit_log_buffer() -> None:
    """Clear recorded audit logs (used between test cases)."""
    AUDIT_LOG_BUFFER.clear()
