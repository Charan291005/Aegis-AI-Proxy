"""HTTP Security Headers Hardening Middleware.

Enforces zero-trust defense by applying standard security headers to all responses:
- Prevent MIME sniffing (`X-Content-Type-Options: nosniff`)
- Prevent clickjacking (`X-Frame-Options: DENY`)
- Cross-Site Scripting protection (`X-XSS-Protection: 1; mode=block`)
- Referrer policy (`Referrer-Policy: strict-origin-when-cross-origin`)
"""

from __future__ import annotations

from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects essential security headers into every outgoing response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
