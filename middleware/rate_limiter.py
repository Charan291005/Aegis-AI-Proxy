"""Asynchronous In-Memory Rate Limiting and DoS Shield Middleware.

Protects Aegis Gateway and downstream MCP tools from:
1. Malfunctioning / runaway LLM agent loops.
2. Distributed Denial of Service (DoS) and brute-force probing.
3. Rapid token credential exhaustion.

Employs a sliding-window algorithm tracking request frequencies per Session ID and Client IP.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Tuple
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from security.config import get_settings

logger = logging.getLogger("aegis.middleware.rate_limiter")


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """Sliding-window request rate limiter per session and client IP."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.settings = get_settings()
        # Map tracking key -> deque of epoch timestamps
        self._history: Dict[str, Deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Enforce rate limits on incoming requests."""
        # Bypass rate limiting for static dashboard assets and health probes
        if not self.settings.enable_rate_limiting or request.url.path in (
            "/health",
            "/",
            "/dashboard",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/stats",
            "/api/audit-logs",
        ):
            return await call_next(request)

        # Derive rate-limiting tracking key from session ID or client IP
        session_id = request.headers.get("x-session-id")
        client_ip = request.client.host if request.client else "unknown"
        tracking_key = f"sess:{session_id}" if session_id else f"ip:{client_ip}"

        now = time.time()
        window_seconds = 60.0
        limit = self.settings.rate_limit_per_minute

        history = self._history[tracking_key]

        # Purge timestamps older than the sliding window
        while history and (now - history[0]) > window_seconds:
            history.popleft()

        # Check rate threshold
        if len(history) >= limit:
            logger.warning(
                "Rate limit exceeded for key '%s' (%d req / %ds). Request blocked.",
                tracking_key,
                len(history),
                int(window_seconds),
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests: Rate limit exceeded. Please back off.",
                    "limit_per_minute": limit,
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        # Record this request
        history.append(now)

        # Add remaining quota headers to response
        response = await call_next(request)
        remaining = max(0, limit - len(history))
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
