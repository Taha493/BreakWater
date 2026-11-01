"""Gateway settings, loaded from environment variables (spec section 11)."""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_DATABASE_URL = "sqlite:///./gateway.db"
DEFAULT_RULES_DIR = Path(__file__).parent / "rules"
DEFAULT_POLICIES_PATH = DEFAULT_RULES_DIR / "policies.yaml"
DEFAULT_REDTEAM_TARGETS_PATH = Path(__file__).parent / "redteam" / "targets.yaml"
# Apache-2.0, checked 2026-10-31 (see docs/DECISIONS.md). The revision pins the exact files.
DEFAULT_CLASSIFIER_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
DEFAULT_CLASSIFIER_REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"
# OpenAI-compatible endpoints of hosted judge providers (from their docs, 2026-10-31).
JUDGE_BASE_URLS = {
    "groq": "https://api.groq.com/openai/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
}

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


class ClassifierModelSettings(BaseSettings):
    """Layer 2 settings; also all ``gateway classifier download`` needs."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Off by default so the gateway starts without the model; when on, the model loads at
    # startup and the gateway refuses to start if it cannot.
    classifier_enabled: bool = False
    # A Hugging Face repo id (files fetched at classifier_revision into the Hugging Face
    # cache) or a local directory with config.json, tokenizer.json, and model.onnx.
    classifier_model: str = DEFAULT_CLASSIFIER_MODEL
    classifier_revision: str | None = DEFAULT_CLASSIFIER_REVISION
    classifier_onnx_subfolder: str = "onnx"
    classifier_injection_label: str = "INJECTION"
    classifier_threads: int = Field(default=2, ge=1, le=64)


class Settings(DatabaseSettings, ClassifierModelSettings):
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
    # How often the gateway deletes data past retention_days (0: never; use
    # `gateway db cleanup` from a scheduler instead).
    retention_check_minutes: int = Field(default=60, ge=0)
    stream_holdback_chars: int = Field(default=200, ge=0)
    max_body_bytes: int = Field(default=1_048_576, gt=0)
    cors_origins: str = ""
    # Requests per minute per API key, per gateway process (0: no limit).
    rate_limit_client_per_minute: int = Field(default=3000, ge=0)
    rate_limit_admin_per_minute: int = Field(default=120, ge=0)
    # Comma-separated IPs or CIDR ranges allowed to use admin routes (empty: any). Behind a
    # reverse proxy, run uvicorn with --forwarded-allow-ips so the client address is real.
    admin_ip_allowlist: str = ""
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    redteam_targets_path: Path = DEFAULT_REDTEAM_TARGETS_PATH
    # A client key for protected red-team runs. Unset: each run mints one and revokes it.
    redteam_gateway_key: SecretStr | None = None
    # Layer 3, the LLM judge. Runs only when this is on and the policy's judge.enabled is
    # too. The model is never built in: set JUDGE_PROVIDER and JUDGE_MODEL.
    judge_enabled: bool = False
    # anthropic (Messages API), groq or gemini (their OpenAI-compatible endpoints), or
    # openai_compatible (any other /chat/completions endpoint, hosted or local).
    judge_provider: Literal["anthropic", "groq", "gemini", "openai_compatible"] | None = None
    judge_model: str | None = None
    judge_api_key: SecretStr | None = None
    # Required for openai_compatible (for example http://localhost:11434/v1); optional for
    # the others, to override their default endpoint.
    judge_base_url: str | None = None
    judge_max_tokens: int = Field(default=2048, ge=64, le=64_000)
    # Anthropic models that take output_config.effort; unset leaves the model's default.
    judge_effort: Literal["low", "medium", "high", "xhigh", "max"] | None = None
    # Providers other than anthropic: how to ask for JSON. json_schema sends the schema
    # (strict); json_object asks for any JSON object, for models without schema support
    # (some Groq models); none relies on the prompt. The reply is validated either way.
    judge_json_mode: Literal["json_schema", "json_object", "none"] = "json_schema"

    @field_validator("upstream_base_url")
    @classmethod
    def _check_upstream_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("UPSTREAM_BASE_URL must start with http:// or https://")
        return value.rstrip("/")

    @model_validator(mode="after")
    def _check_judge(self) -> Settings:
        if not self.judge_enabled:
            return self
        if self.judge_provider is None or not self.judge_model:
            raise ValueError("JUDGE_ENABLED needs JUDGE_PROVIDER and JUDGE_MODEL")
        if self.judge_provider != "openai_compatible" and self.judge_api_key is None:
            raise ValueError(f"the {self.judge_provider} judge needs JUDGE_API_KEY")
        if self.judge_provider == "openai_compatible" and not self.judge_base_url:
            raise ValueError("the openai_compatible judge needs JUDGE_BASE_URL")
        return self

    @field_validator(
        "admin_bootstrap_key",
        "redteam_gateway_key",
        "judge_api_key",
        "judge_base_url",
        "judge_provider",
        "judge_model",
        "judge_effort",
        mode="before",
    )
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

    @field_validator("admin_ip_allowlist")
    @classmethod
    def _check_allowlist(cls, value: str) -> str:
        for item in value.split(","):
            if item.strip():
                ipaddress.ip_network(item.strip(), strict=False)
        return value

    @property
    def admin_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [
            ipaddress.ip_network(item.strip(), strict=False)
            for item in self.admin_ip_allowlist.split(",")
            if item.strip()
        ]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
