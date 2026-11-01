"""Request dependencies: shared services, database sessions, and API key auth."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from gateway.api.errors import GatewayError
from gateway.config import Settings
from gateway.core.keys import KeyRole, hashes_match, parse_key_id
from gateway.core.pipeline import Pipeline
from gateway.core.providers import OpenAICompatibleProvider
from gateway.core.redact import Hasher
from gateway.storage import repo

BOOTSTRAP_ACTOR = "bootstrap"


@dataclass
class Services:
    settings: Settings
    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]
    hasher: Hasher
    pipeline: Pipeline
    provider: OpenAICompatibleProvider


@dataclass(frozen=True)
class Principal:
    key_id: str
    name: str
    role: KeyRole


def get_services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services


ServicesDep = Annotated[Services, Depends(get_services)]


async def get_session(services: ServicesDep) -> AsyncIterator[AsyncSession]:
    async with services.sessionmaker() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]

_bearer = HTTPBearer(auto_error=False)


def _unauthorized(message: str = "Missing or invalid API key") -> GatewayError:
    return GatewayError(
        401, "unauthorized", "invalid_api_key", message, headers={"WWW-Authenticate": "Bearer"}
    )


async def _authenticate(
    credentials: HTTPAuthorizationCredentials | None,
    services: Services,
    session: AsyncSession,
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()
    presented = credentials.credentials
    presented_hash = services.hasher.api_key(presented)

    # The bootstrap key works only until the first admin key exists (spec section 11).
    bootstrap = services.settings.admin_bootstrap_key
    if bootstrap is not None and hashes_match(
        services.hasher.api_key(bootstrap.get_secret_value()), presented_hash
    ):
        if await repo.has_active_admin_key(session):
            raise _unauthorized("The bootstrap key is disabled once an admin key exists")
        return Principal(key_id=BOOTSTRAP_ACTOR, name=BOOTSTRAP_ACTOR, role=KeyRole.ADMIN)

    key_id = parse_key_id(presented)
    if key_id is not None:
        row = await repo.get_api_key(session, key_id)
        if (
            row is not None
            and row.revoked_at is None
            and hashes_match(row.key_hash, presented_hash)
        ):
            return Principal(key_id=row.id, name=row.name, role=KeyRole(row.role))
    raise _unauthorized()


def _require(role: KeyRole) -> Any:
    async def dependency(
        services: ServicesDep,
        session: SessionDep,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    ) -> Principal:
        principal = await _authenticate(credentials, services, session)
        if principal.role is not role:
            raise GatewayError(
                403, "unauthorized", "wrong_key_role", f"This route needs a {role} key"
            )
        return principal

    return Depends(dependency)


ClientPrincipal = Annotated[Principal, _require(KeyRole.CLIENT)]
AdminPrincipal = Annotated[Principal, _require(KeyRole.ADMIN)]
