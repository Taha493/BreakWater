from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, inspect

from breakwater.cli import main
from breakwater.core.redact import Hasher
from breakwater.storage import migrate
from breakwater.storage.db import make_engine, make_sessionmaker
from breakwater.storage.models import ApiKey
from tests.conftest import HASH_SECRET


def test_upgrade_empty_database_to_head(tmp_path: Path) -> None:
    db = tmp_path / "fresh.db"
    url = f"sqlite:///{db}"
    migrate.upgrade(url)

    tables = set(inspect(create_engine(url)).get_table_names())
    assert {"events", "findings", "api_keys", "audit_log", "alembic_version"} <= tables
    # Fails if the models have drifted from the migrations.
    command.check(migrate.alembic_config(url))


def test_upgrade_is_repeatable(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path}/again.db"
    migrate.upgrade(url)
    migrate.upgrade(url)


def test_cli_upgrade_and_key_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    url = f"sqlite:///{tmp_path}/cli.db"
    monkeypatch.setenv("GATEWAY_DATABASE_URL", url)
    monkeypatch.setenv("UPSTREAM_BASE_URL", "http://upstream.test/v1")
    monkeypatch.setenv("UPSTREAM_API_KEY", "k")
    monkeypatch.setenv("GATEWAY_HASH_SECRET", HASH_SECRET)

    from breakwater.config import get_settings

    get_settings.cache_clear()
    try:
        assert main(["db", "upgrade"]) == 0
        assert main(["keys", "create", "--name", "cli-app", "--role", "client"]) == 0
        plaintext = capsys.readouterr().out.strip().splitlines()[-1]
        key_id = plaintext.split(".")[1]

        async def stored() -> ApiKey | None:
            engine = make_engine(url)
            async with make_sessionmaker(engine)() as session:
                row = await session.get(ApiKey, key_id)
            await engine.dispose()
            return row

        row = asyncio.run(stored())
        assert row is not None
        assert row.key_hash == Hasher(HASH_SECRET).api_key(plaintext)
        assert plaintext not in row.key_hash

        assert main(["keys", "revoke", key_id]) == 0
        assert main(["keys", "revoke", "0000000000000000"]) == 1
    finally:
        get_settings.cache_clear()
