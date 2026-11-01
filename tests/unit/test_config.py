from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from breakwater.config import DEFAULT_POLICIES_PATH, Settings, to_async_database_url
from tests.conftest import make_settings


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("sqlite:///./gateway.db", "sqlite+aiosqlite:///./gateway.db"),
        ("postgresql://u:p@db:5432/g", "postgresql+psycopg://u:p@db:5432/g"),
        ("postgres://u:p@db/g", "postgresql+psycopg://u:p@db/g"),
        ("postgresql+psycopg://u@db/g", "postgresql+psycopg://u@db/g"),
        ("sqlite+aiosqlite:///x.db", "sqlite+aiosqlite:///x.db"),
    ],
)
def test_database_url_maps_to_async_driver(url: str, expected: str) -> None:
    assert to_async_database_url(url) == expected


@pytest.mark.parametrize("url", ["mysql://u@h/db", "not-a-url"])
def test_unsupported_database_url_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        to_async_database_url(url)


def test_defaults_match_spec(tmp_path: Path) -> None:
    s = make_settings(tmp_path)
    assert s.store_full_text is False
    assert s.retention_days == 30
    assert s.stream_holdback_chars == 200
    assert s.max_body_bytes == 1_048_576
    assert s.log_level == "INFO"
    assert s.policies_path == DEFAULT_POLICIES_PATH
    assert DEFAULT_POLICIES_PATH.is_file()


def test_required_variables_missing() -> None:
    with pytest.raises(ValidationError) as info:
        Settings(_env_file=None)
    missing = {e["loc"][0] for e in info.value.errors()}
    assert {"upstream_base_url", "upstream_api_key", "gateway_hash_secret"} <= missing


def test_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UPSTREAM_BASE_URL", "https://api.example.com/v1/")
    monkeypatch.setenv("UPSTREAM_API_KEY", "k")
    monkeypatch.setenv("GATEWAY_HASH_SECRET", "s" * 32)
    monkeypatch.setenv("STORE_FULL_TEXT", "true")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173, https://dash.example.com")
    monkeypatch.setenv("LOG_LEVEL", "debug")
    s = Settings(_env_file=None)
    assert s.upstream_base_url == "https://api.example.com/v1"
    assert s.store_full_text is True
    assert s.cors_origin_list == ["http://localhost:5173", "https://dash.example.com"]
    assert s.log_level == "DEBUG"


def test_short_secrets_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="at least 32"):
        make_settings(tmp_path, gateway_hash_secret="short")
    with pytest.raises(ValidationError, match="at least 32"):
        make_settings(tmp_path, admin_bootstrap_key="short")


def test_upstream_url_needs_http_scheme(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="http"):
        make_settings(tmp_path, upstream_base_url="ftp://upstream")


def test_secrets_hidden_in_repr(tmp_path: Path) -> None:
    s = make_settings(tmp_path)
    assert s.gateway_hash_secret.get_secret_value() not in repr(s)
    assert s.upstream_api_key.get_secret_value() not in repr(s)


def test_empty_bootstrap_key_means_unset(tmp_path: Path) -> None:
    assert make_settings(tmp_path, admin_bootstrap_key="").admin_bootstrap_key is None
