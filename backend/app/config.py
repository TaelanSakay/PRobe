import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    model_config = SettingsConfigDict(
        env_file=[".env", "../.env"],
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
