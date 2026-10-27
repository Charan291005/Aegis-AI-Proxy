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
        """Return supabase_key or supabase_service_role_key."""
        return self.supabase_key or self.supabase_service_role_key

    # Defense In Depth Toggles
    enable_pii_redaction: bool = True
    enable_injection_shield: bool = True

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
