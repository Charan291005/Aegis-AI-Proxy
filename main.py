"""Aegis Zero-Trust MCP Gateway - Main Application Entrypoint.

Architecture Overview:
- Fast, asynchronous reverse proxy for Model Context Protocol (MCP) tool calls.
- Enforces Zero-Trust forward-path controls:
    1. Mandatory Bearer Token Authentication.
    2. Heuristic Shell Injection Shield (blocking ';', '&&', '|', '/bin/sh', subshells).
    3. Session and Tool Role-Based Access Control (RBAC) via Supabase PostgreSQL.
- Enforces Zero-Trust return-path controls:
    1. Data Loss Prevention (DLP) using Microsoft Presidio (AnalyzerEngine & AnonymizerEngine).
    2. Automatic redaction of CREDIT_CARD, EMAIL_ADDRESS, and PHONE_NUMBER.
- Generic 403 Forbidden responses for all policy violations to eliminate information disclosure.
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict

from dotenv import load_dotenv

# Load environment configuration from .env prior to importing internal modules
load_dotenv()

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
import uvicorn

from middleware.interceptor import (
    GENERIC_FORBIDDEN_RESPONSE,
    ZeroTrustInterceptorMiddleware,
)
from routers.dashboard_router import router as dashboard_router
from routers.mcp_router import router as mcp_router
from security.config import get_settings

# ------------------------------------------------------------------------------
# Logging Infrastructure Configuration
# ------------------------------------------------------------------------------
settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("aegis.gateway")


# ------------------------------------------------------------------------------
# Application Lifespan Events
# ------------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize security subsystems and warm up DLP models at startup."""
    logger.info("Initializing Aegis Zero-Trust MCP Gateway...")
    logger.info("Environment: %s", settings.aegis_env)
    logger.info("PII Redaction: %s", "ENABLED" if settings.enable_pii_redaction else "DISABLED")
    logger.info("Injection Shield: %s", "ENABLED" if settings.enable_injection_shield else "DISABLED")
    logger.info("RBAC Supabase Endpoint: %s", settings.supabase_url)
    yield
    logger.info("Aegis Zero-Trust MCP Gateway shutting down cleanly.")


# ------------------------------------------------------------------------------
# FastAPI Application Initialization
# ------------------------------------------------------------------------------
app = FastAPI(
    title="Aegis Zero-Trust MCP Gateway",
    description=(
        "Production-grade security middleware proxy intercepting and sanitizing "
        "bidirectional Model Context Protocol (MCP) payloads between LLMs and external tools."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Enforce OpenAPI Bearer Auth documentation
bearer_scheme = HTTPBearer(auto_error=False)

# ------------------------------------------------------------------------------
# Middleware Pipeline
# ------------------------------------------------------------------------------
# 1. CORS: Strict origin filtering
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to specific trusted origins in production
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# 2. Zero-Trust Interceptor Middleware (Forward auth, injection checks & Return DLP)
app.add_middleware(ZeroTrustInterceptorMiddleware)


# ------------------------------------------------------------------------------
# Global Exception Handlers (Preventing Information Leakage)
# ------------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Mask validation errors with generic 403 response to avoid schema enumeration."""
    logger.warning(
        "Request schema validation rejected for %s from %s: %s",
        request.url.path,
        request.client.host if request.client else "unknown",
        exc.errors(),
    )
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content=GENERIC_FORBIDDEN_RESPONSE,
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request, exc: HTTPException
) -> JSONResponse:
    """Normalize HTTP policy exceptions to generic 403 Forbidden responses."""
    if exc.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=GENERIC_FORBIDDEN_RESPONSE,
        )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Catch-all unhandled exceptions to prevent stack trace leakage."""
    logger.critical("Unhandled server exception: %s", str(exc), exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content=GENERIC_FORBIDDEN_RESPONSE,
    )


# ------------------------------------------------------------------------------
# Core Endpoints
# ------------------------------------------------------------------------------
@app.get(
    "/health",
    tags=["System Health"],
    summary="Gateway Health Check",
    description="Public liveness and readiness probe for container orchestrators.",
)
async def health_check() -> Dict[str, Any]:
    """Gateway health check probe."""
    return {
        "status": "healthy",
        "service": "aegis-mcp-gateway",
        "version": "1.0.0",
        "pii_redaction": settings.enable_pii_redaction,
        "injection_shield": settings.enable_injection_shield,
    }


# Register MCP router containing /mcp/execute
app.include_router(mcp_router)

# Register Visual Security Dashboard and Telemetry APIs
app.include_router(dashboard_router)


# ------------------------------------------------------------------------------
# Local Server Execution
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.aegis_host,
        port=settings.aegis_port,
        reload=(settings.aegis_env == "development"),
        log_level=settings.log_level.lower(),
    )
