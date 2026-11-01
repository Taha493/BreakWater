"""Request dependencies: shared services, database sessions, and API key auth."""

from __future__ import annotations

import ipaddress
import math
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from gateway.api.errors import GatewayError
from gateway.config import Settings
from gateway.core.keys import KeyRole, hashes_match, parse_key_id
from gateway.core.providers import OpenAICompatibleProvider
from gateway.core.ratelimit import KeyRateLimiter
from gateway.core.redact import Hasher
from gateway.core.runtime import ConfigStore
from gateway.storage import repo

BOOTSTRAP_ACTOR = "bootstrap"


@dataclass
class Services:
    settings: Settings
    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]
    hasher: Hasher
    store: ConfigStore
    provider: OpenAICompatibleProvider
    limiter: KeyRateLimiter = field(default_factory=KeyRateLimiter)


@dataclass(frozen=True)
class Principal:
    key_id: str
    name: str
    role: KeyRole
    max_layer: int | None = None


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
            return Principal(
                key_id=row.id, name=row.name, role=KeyRole(row.role), max_layer=row.max_layer
            )
    raise _unauthorized()


def _admin_ip_allowed(request: Request, settings: Settings) -> bool:
    networks = settings.admin_networks
    if not networks:
        return True
    host = request.client.host if request.client else None
    try:
        address = ipaddress.ip_address(host or "")
    except ValueError:
        return False
    return any(address in network for network in networks)


def _require(role: KeyRole) -> Any:
    async def dependency(
        request: Request,
        services: ServicesDep,
        session: SessionDep,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    ) -> Principal:
        settings = services.settings
        # Checked before the key, so a caller outside the allowlist learns nothing about it.
        if role is KeyRole.ADMIN and not _admin_ip_allowed(request, settings):
            raise GatewayError(
                403,
                "unauthorized",
                "admin_ip_not_allowed",
                "Admin routes are not open to this address",
            )
        principal = await _authenticate(credentials, services, session)
        if principal.role is not role:
            raise GatewayError(
                403, "unauthorized", "wrong_key_role", f"This route needs a {role} key"
            )
        per_minute = (
            settings.rate_limit_admin_per_minute
            if role is KeyRole.ADMIN
            else settings.rate_limit_client_per_minute
        )
        wait = services.limiter.take(principal.key_id, per_minute)
        if wait is not None:
            raise GatewayError(
                429,
                "rate_limited",
                "key_rate_limited",
                "Too many requests for this key",
                headers={"Retry-After": str(max(1, math.ceil(wait)))},
            )
        return principal

    return Depends(dependency)


ClientPrincipal = Annotated[Principal, _require(KeyRole.CLIENT)]
AdminPrincipal = Annotated[Principal, _require(KeyRole.ADMIN)]
