"""``gateway`` command line: database migrations and retention cleanup, API keys, per-user
data export and deletion, the classifier model download, and red-team runs."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from gateway.config import ClassifierModelSettings, DatabaseSettings, get_settings
from gateway.core.classifier import model_directory
from gateway.core.keys import KeyRole
from gateway.core.redact import Hasher
from gateway.redteam import cli as redteam_cli
from gateway.storage import maintenance, migrate, repo
from gateway.storage.db import make_engine, make_sessionmaker

CLI_ACTOR = "cli"


async def _create_key(name: str, role: KeyRole) -> str:
    settings = get_settings()
    engine = make_engine(settings.gateway_database_url)
    try:
        async with make_sessionmaker(engine)() as session:
            hasher = Hasher(settings.gateway_hash_secret.get_secret_value())
            row, plaintext = await repo.create_api_key(session, hasher, name, role)
            repo.add_audit(session, CLI_ACTOR, "api_key.create", row.id, f"role={role}")
            await session.commit()
            return f"id={row.id} role={role}\n{plaintext}"
    finally:
        await engine.dispose()


async def _revoke_key(key_id: str) -> bool:
    settings = get_settings()
    engine = make_engine(settings.gateway_database_url)
    try:
        async with make_sessionmaker(engine)() as session:
            row, changed = await repo.revoke_api_key(session, key_id)
            if row is None:
                return False
            if changed:
                repo.add_audit(session, CLI_ACTOR, "api_key.revoke", row.id)
                await session.commit()
            return True
    finally:
        await engine.dispose()


async def _cleanup() -> dict[str, int]:
    settings = get_settings()
    engine = make_engine(settings.gateway_database_url)
    try:
        async with make_sessionmaker(engine)() as session:
            counts = await maintenance.cleanup(session, settings.retention_days)
            repo.add_audit(session, CLI_ACTOR, "retention.cleanup", None, json.dumps(counts))
            await session.commit()
            return counts
    finally:
        await engine.dispose()


async def _user_data(action: str, user: str | None, user_hash: str | None) -> dict[str, Any]:
    settings = get_settings()
    if user is not None:
        user_hash = Hasher(settings.gateway_hash_secret.get_secret_value()).user(user)
    if not user_hash:
        raise ValueError("give --user or --user-hash")
    engine = make_engine(settings.gateway_database_url)
    try:
        async with make_sessionmaker(engine)() as session:
            if action == "export":
                data = await maintenance.export_user(session, user_hash)
                repo.add_audit(session, CLI_ACTOR, "user_data.export", user_hash)
            else:
                data = {
                    "user_hash": user_hash,
                    "deleted": await maintenance.delete_user(session, user_hash),
                }
                repo.add_audit(
                    session, CLI_ACTOR, "user_data.delete", user_hash, json.dumps(data["deleted"])
                )
            await session.commit()
            return data
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gateway")
    commands = parser.add_subparsers(dest="command", required=True)

    db = commands.add_parser("db", help="database migrations")
    db_commands = db.add_subparsers(dest="db_command", required=True)
    db_commands.add_parser("upgrade", help="apply all migrations")
    db_commands.add_parser("cleanup", help="delete data older than RETENTION_DAYS")

    data = commands.add_parser("data", help="export or delete everything stored for a user")
    data_commands = data.add_subparsers(dest="data_command", required=True)
    for name in ("export", "delete"):
        command = data_commands.add_parser(name, help=f"{name} a user's events (JSON out)")
        who = command.add_mutually_exclusive_group(required=True)
        who.add_argument("--user", help="the user id the client sent (X-Gateway-User)")
        who.add_argument("--user-hash", help="the stored user_hash")

    keys = commands.add_parser("keys", help="API keys")
    key_commands = keys.add_subparsers(dest="key_command", required=True)
    create = key_commands.add_parser("create", help="create a key and print it once")
    create.add_argument("--name", required=True)
    create.add_argument("--role", choices=[r.value for r in KeyRole], default=KeyRole.CLIENT.value)
    revoke = key_commands.add_parser("revoke", help="revoke a key by id")
    revoke.add_argument("key_id")

    classifier = commands.add_parser("classifier", help="the layer 2 injection classifier")
    classifier_commands = classifier.add_subparsers(dest="classifier_command", required=True)
    classifier_commands.add_parser(
        "download", help="fetch the CLASSIFIER_MODEL files at CLASSIFIER_REVISION"
    )

    redteam_cli.add_parser(commands)

    args = parser.parse_args(argv)

    if args.command == "db" and args.db_command == "upgrade":
        # Migrations need only the database URL, not the full gateway configuration.
        migrate.upgrade(DatabaseSettings().gateway_database_url)
        return 0
    if args.command == "db":
        print(json.dumps(asyncio.run(_cleanup())))
        return 0
    if args.command == "data":
        result = asyncio.run(_user_data(args.data_command, args.user, args.user_hash))
        print(json.dumps(result, indent=2))
        return 0
    if args.command == "classifier":
        config = ClassifierModelSettings()
        directory = model_directory(
            config.classifier_model,
            config.classifier_revision,
            config.classifier_onnx_subfolder,
        )
        print(directory)
        return 0
    if args.command == "redteam":
        return asyncio.run(redteam_cli.redteam_run(args))
    if args.key_command == "create":
        print(asyncio.run(_create_key(args.name, KeyRole(args.role))))
        return 0
    if not asyncio.run(_revoke_key(args.key_id)):
        print(f"no such key: {args.key_id}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
