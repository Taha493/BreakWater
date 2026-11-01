"""Gateway settings, loaded from environment variables (spec section 11)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_DATABASE_URL = "sqlite:///./gateway.db"
DEFAULT_RULES_DIR = Path(__file__).parent / "rules"
DEFAULT_POLICIES_PATH = DEFAULT_RULES_DIR / "policies.yaml"

_ASYNC_DRIVERS = {
    "sqlite": "sqlite+aiosqlite",
    "postgres": "postgresql+psycopg",
    "postgresql": "postgresql+psycopg",
}


def to_async_database_url(url: str) -> str:
    """Map a plain SQLAlchemy URL to its async driver. URLs that name a driver are kept."""
    scheme, sep, rest = url.partition("://")
    if not sep:
        raise ValueError("database URL must contain '://'")
    if "+" in scheme:
        return url
    driver = _ASYNC_DRIVERS.get(scheme)
    if driver is None:
        raise ValueError(f"unsupported database scheme: {scheme}")
    return f"{driver}://{rest}"


class DatabaseSettings(BaseSettings):
    """The subset needed by migrations, which must run without the rest of the config."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    gateway_database_url: str = DEFAULT_DATABASE_URL

    @field_validator("gateway_database_url")
    @classmethod
    def _check_database_url(cls, value: str) -> str:
        to_async_database_url(value)
        return value


class Settings(DatabaseSettings):
    upstream_base_url: str
    upstream_api_key: SecretStr
    upstream_timeout_seconds: float = Field(default=60.0, gt=0)
    admin_bootstrap_key: SecretStr | None = None
    gateway_hash_secret: SecretStr
    policies_path: Path = DEFAULT_POLICIES_PATH
    rules_dir: Path = DEFAULT_RULES_DIR
    config_reload_seconds: float = Field(default=2.0, ge=0)
    store_full_text: bool = False
    retention_days: int = Field(default=30, ge=1)
    stream_holdback_chars: int = Field(default=200, ge=0)
    max_body_bytes: int = Field(default=1_048_576, gt=0)
    cors_origins: str = ""
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    @field_validator("upstream_base_url")
    @classmethod
    def _check_upstream_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("UPSTREAM_BASE_URL must start with http:// or https://")
        return value.rstrip("/")

    @field_validator("admin_bootstrap_key", mode="before")
    @classmethod
    def _empty_means_unset(cls, value: object) -> object:
        return None if value == "" else value

    @field_validator("gateway_hash_secret", "admin_bootstrap_key")
    @classmethod
    def _check_secret_length(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 32:
            raise ValueError("must be at least 32 characters")
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper_log_level(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @property
    def async_database_url(self) -> str:
        return to_async_database_url(self.gateway_database_url)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
