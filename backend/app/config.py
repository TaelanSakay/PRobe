import os
from typing import Optional

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except Exception:
    # Minimal fallback for test environments where pydantic_settings isn't installed.
    class BaseSettings:
        pass

    SettingsConfigDict = dict


class Settings(BaseSettings):
    # App Settings
    PROJECT_NAME: str = "PRobe"
    DEBUG: bool = True

    # Services
    DATABASE_URL: str = "postgresql://postgres:postgres@db:5432/probe"
    REDIS_URL: str = "redis://redis:6379/0"

    # GitHub App Integration
    GITHUB_APP_ID: Optional[str] = None
    GITHUB_PRIVATE_KEY: Optional[str] = None
    GITHUB_WEBHOOK_SECRET: Optional[str] = None
    VERIFY_GITHUB_WEBHOOKS: bool = True

    # LLM Configuration
    ANTHROPIC_API_KEY: Optional[str] = None
    # Claude review settings
    CLAUDE_MODEL_NAME: str = "claude-v1"  # default compact model
    CLAUDE_TIMEOUT: int = 15
    CLAUDE_MAX_FINDINGS_PER_CALL: int = 10

    model_config = SettingsConfigDict(
        env_file=[".env", "../.env"],
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
