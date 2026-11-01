from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastapi import FastAPI

from gateway.config import DEFAULT_POLICIES_PATH, DEFAULT_RULES_DIR, Settings
from gateway.core.keys import KeyRole
from gateway.core.pipeline import Pipeline
from gateway.core.runtime import Runtime, build_runtime
from gateway.detectors.base import Detector
from gateway.main import create_app
from gateway.storage import repo
from gateway.storage.db import make_engine
from gateway.storage.models import Base

UPSTREAM_URL = "http://upstream.test/v1"
UPSTREAM_KEY = "upstream-test-key"
HASH_SECRET = "test-hash-secret-" + "x" * 32
BOOTSTRAP_KEY = "test-bootstrap-key-" + "y" * 32


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep the developer's shell environment and .env file out of the tests."""
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)
    monkeypatch.chdir(tmp_path)


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "gateway_database_url": f"sqlite:///{tmp_path}/gateway.db",
        "upstream_base_url": UPSTREAM_URL,
        "upstream_api_key": UPSTREAM_KEY,
        "gateway_hash_secret": HASH_SECRET,
        "admin_bootstrap_key": BOOTSTRAP_KEY,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


async def create_schema(settings: Settings) -> None:
    engine = make_engine(settings.gateway_database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()


@pytest.fixture
async def app(settings: Settings) -> AsyncIterator[FastAPI]:
    await create_schema(settings)
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest.fixture
def sim_upstream() -> httpx.AsyncBaseTransport:
    """The mock upstream in-process; the model ``sim-obedient`` follows injected text."""
    from scripts import mock_upstream

    return httpx.ASGITransport(app=mock_upstream.app)


@pytest.fixture
async def sim_app(
    settings: Settings, sim_upstream: httpx.AsyncBaseTransport
) -> AsyncIterator[FastAPI]:
    """The gateway with the mock upstream behind it instead of respx."""
    await create_schema(settings)
    application = create_app(settings, upstream_transport=sim_upstream)
    async with application.router.lifespan_context(application):
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway.test") as c:
        yield c


@pytest.fixture
def upstream() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=UPSTREAM_URL, assert_all_called=False) as router:
        yield router


async def make_key(app: FastAPI, role: KeyRole, name: str = "test") -> str:
    services = app.state.services
    async with services.sessionmaker() as session:
        _, plaintext = await repo.create_api_key(session, services.hasher, name, role)
        await session.commit()
    return plaintext


@pytest.fixture
async def client_key(app: FastAPI) -> str:
    return await make_key(app, KeyRole.CLIENT)


@pytest.fixture
def auth(client_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {client_key}"}


def completion(content: str, model: str = "test-model") -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }


def chat_body(text: str, **extra: Any) -> dict[str, Any]:
    return {
        "model": "test-model",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": text},
        ],
        **extra,
    }


def default_runtime(policy_raw: bytes | None = None) -> Runtime:
    return build_runtime(
        policy_raw or DEFAULT_POLICIES_PATH.read_bytes(),
        (DEFAULT_RULES_DIR / "injection.yaml").read_bytes(),
        (DEFAULT_RULES_DIR / "secrets.yaml").read_bytes(),
        (DEFAULT_RULES_DIR / "tools.yaml").read_bytes(),
    )


def runtime_with(*extra: Detector, policy_raw: bytes | None = None) -> Runtime:
    """The default runtime plus extra detectors."""
    base = default_runtime(policy_raw)
    detectors = [d for layer in base.pipeline._layers for d in layer] + list(extra)
    return Runtime(
        base.policy, Pipeline(detectors, base.policy), base.redactor, base.tool_guard, base.version
    )


def pin_runtime(app: FastAPI, runtime: Runtime) -> None:
    app.state.services.store.pin(runtime)
