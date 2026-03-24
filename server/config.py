"""Application configuration — loaded from environment variables or .env file."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    DATABASE_URL: str = "postgresql+asyncpg://scanner:scanner@localhost:5432/claude_scanner"

    # ------------------------------------------------------------------
    # Redis / Celery
    # ------------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"

    # ------------------------------------------------------------------
    # JWT Auth
    # ------------------------------------------------------------------
    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours

    # ------------------------------------------------------------------
    # 1Password Connect Server
    # ------------------------------------------------------------------
    OP_CONNECT_HOST: str = "http://localhost:8080"
    OP_CONNECT_TOKEN: str = ""
    OP_VAULT_ID: str = ""   # Default vault UUID; empty = search all vaults

    # ------------------------------------------------------------------
    # NVD API  (key stored in 1Password — populated at runtime)
    # ------------------------------------------------------------------
    NVD_API_KEY: str = ""
    NVD_API_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # With an API key: 50 req / 30 s; without: 5 req / 30 s
    NVD_RATE_LIMIT_REQUESTS: int = 50
    NVD_RATE_LIMIT_WINDOW: int = 30

    # ------------------------------------------------------------------
    # OSV API
    # ------------------------------------------------------------------
    OSV_API_BASE_URL: str = "https://api.osv.dev/v1"

    # ------------------------------------------------------------------
    # EPSS API (FIRST.org)
    # ------------------------------------------------------------------
    EPSS_API_BASE_URL: str = "https://api.first.org/data/v1"

    # ------------------------------------------------------------------
    # Scanner Agent (Go binary deployed to target hosts)
    # ------------------------------------------------------------------
    AGENT_PORT: int = 9443
    AGENT_TOKEN: str = "change-me-agent-token"   # Shared secret for agent auth

    # ------------------------------------------------------------------
    # Scanning defaults
    # ------------------------------------------------------------------
    SCAN_TIMEOUT: int = 30          # seconds per host connection
    SCAN_CONCURRENCY: int = 100     # max parallel host scans
    VULN_CACHE_TTL_HOURS: int = 24  # how long to cache CVE records

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    # Comma-separated origins, e.g. "http://localhost:3000,https://scanner.example.com"
    CORS_ORIGINS: str = "http://localhost:3000"
    APP_TITLE: str = "Claude Scanner"
    APP_VERSION: str = "0.1.0"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
