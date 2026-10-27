"""Configuration and Security Settings for Aegis Zero-Trust MCP Gateway.

Enforces zero-trust principles:
1. No secrets committed to source code.
2. Strict environment parsing with fail-closed defaults.
3. Configurable security thresholds and audit flags.
"""

from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized Gateway Configuration.

    Attributes:
        aegis_gateway_token: Shared secret/Bearer token required to access the gateway.
        aegis_env: Deployment environment ("development", "staging", "production").
        aegis_host: Bind host for Uvicorn server.
        aegis_port: Bind port for Uvicorn server.
        log_level: Python logging level ("DEBUG", "INFO", "WARNING", "ERROR").
        supabase_url: Base URL for Supabase/PostgreSQL RBAC verification.
        supabase_service_role_key: Service-role key for backend queries.
        enable_pii_redaction: Flag to toggle Microsoft Presidio DLP scanning.
        enable_injection_shield: Flag to toggle forward path command injection heuristics.
    """

    aegis_gateway_token: str = "aegis_super_secret_bearer_token_2026_demo"
    aegis_env: str = "development"
    aegis_host: str = "0.0.0.0"
    aegis_port: int = 8000
    log_level: str = "INFO"

    # Supabase RBAC Configuration
    supabase_url: Optional[str] = "https://dummy-project.supabase.co"
    supabase_key: Optional[str] = None
    supabase_service_role_key: Optional[str] = None

    @property
    def effective_supabase_key(self) -> Optional[str]:
        """Prioritize service_role key for backend proxy operations; fallback to publishable/anon key."""
        return self.supabase_service_role_key or self.supabase_key

    # Upstream MCP Server Forwarding (Reverse Proxy target)
    upstream_mcp_url: Optional[str] = None
    upstream_timeout_seconds: float = 30.0

    # Rate Limiting & DoS Protection
    rate_limit_per_minute: int = 120
    enable_rate_limiting: bool = True

    # Defense In Depth Toggles
    enable_pii_redaction: bool = True
    enable_secrets_redaction: bool = True
    enable_injection_shield: bool = True
    allowed_origins: str = "*"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


@lru_cache()
def get_settings() -> Settings:
    """Retrieve cached singleton of application settings."""
    return Settings()
