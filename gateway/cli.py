"""``gateway`` command line: database migrations, API key management, and red-team runs."""

from __future__ import annotations

import argparse
import asyncio
import sys

from gateway.config import DatabaseSettings, get_settings
from gateway.core.keys import KeyRole
from gateway.core.redact import Hasher
from gateway.redteam import cli as redteam_cli
from gateway.storage import migrate, repo
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gateway")
    commands = parser.add_subparsers(dest="command", required=True)

    db = commands.add_parser("db", help="database migrations")
    db_commands = db.add_subparsers(dest="db_command", required=True)
    db_commands.add_parser("upgrade", help="apply all migrations")

    keys = commands.add_parser("keys", help="API keys")
    key_commands = keys.add_subparsers(dest="key_command", required=True)
    create = key_commands.add_parser("create", help="create a key and print it once")
    create.add_argument("--name", required=True)
    create.add_argument("--role", choices=[r.value for r in KeyRole], default=KeyRole.CLIENT.value)
    revoke = key_commands.add_parser("revoke", help="revoke a key by id")
    revoke.add_argument("key_id")

    redteam_cli.add_parser(commands)

    args = parser.parse_args(argv)

    if args.command == "db":
        # Migrations need only the database URL, not the full gateway configuration.
        migrate.upgrade(DatabaseSettings().gateway_database_url)
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
