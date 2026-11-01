"""FastAPI app factory."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from gateway import __version__
from gateway.api import routes_admin, routes_proxy, routes_redteam, routes_scan
from gateway.api.deps import Services, ServicesDep
from gateway.api.errors import install_error_handlers
from gateway.api.middleware import BodySizeLimitMiddleware, RequestIdMiddleware
from gateway.api.policy_sync import PolicySync
from gateway.config import Settings, get_settings
from gateway.core.providers import OpenAICompatibleProvider
from gateway.core.redact import Hasher
from gateway.core.runtime import ConfigStore, load_models
from gateway.log import configure_logging
from gateway.storage import maintenance, repo
from gateway.storage.db import make_engine, make_sessionmaker

log = logging.getLogger("gateway")


def create_app(
    settings: Settings | None = None,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
    redteam_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """``redteam_transport`` lets tests route red-team target traffic in-process."""
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(settings.log_level)
        engine = make_engine(settings.gateway_database_url)
        sessionmaker = make_sessionmaker(engine)
        try:
            async with sessionmaker() as session:
                admin_exists = await repo.has_active_admin_key(session)
        except SQLAlchemyError as exc:
            await engine.dispose()
            raise RuntimeError(
                "Database unreachable or not migrated. Run `gateway db upgrade` first."
            ) from exc
        if settings.admin_bootstrap_key is None and not admin_exists:
            await engine.dispose()
            raise RuntimeError("No admin key exists. Set ADMIN_BOOTSTRAP_KEY for the first run.")
        try:
            models = await asyncio.to_thread(load_models, settings)
        except Exception as exc:
            await engine.dispose()
            raise RuntimeError(f"Could not load the detection models: {exc}") from exc
        try:
            store = ConfigStore(
                settings.policies_path,
                settings.rules_dir,
                settings.config_reload_seconds,
                models=models,
            )
        except Exception as exc:
            await engine.dispose()
            raise RuntimeError(f"Invalid policy or rule files: {exc}") from exc
        provider = OpenAICompatibleProvider(
            settings.upstream_base_url,
            settings.upstream_api_key.get_secret_value(),
            settings.upstream_timeout_seconds,
            transport=upstream_transport,
        )
        app.state.services = Services(
            settings=settings,
            engine=engine,
            sessionmaker=sessionmaker,
            hasher=Hasher(settings.gateway_hash_secret.get_secret_value()),
            store=store,
            provider=provider,
        )
        policy_sync = PolicySync(app.state.services)
        try:
            await policy_sync.sync()
        except Exception as exc:
            await provider.aclose()
            await models.aclose()
            await engine.dispose()
            raise RuntimeError(
                "Could not load the policy from the database. Run `gateway db upgrade` first."
            ) from exc
        log.info(
            "gateway started",
            extra={"ruleset_version": store.current().version, "layers": store.current().layers},
        )
        app.state.redteam_tasks = set()
        app.state.redteam_transport = redteam_transport
        app.state.policy_sync = policy_sync
        background = [asyncio.create_task(policy_sync.run(settings.config_reload_seconds))]
        if settings.retention_check_minutes:
            background.append(asyncio.create_task(retention_loop(app.state.services)))
        try:
            yield
        finally:
            for task in background:
                task.cancel()
            await asyncio.gather(*background, return_exceptions=True)
            # Interrupted red-team runs are marked failed by their own error handling.
            tasks: set[asyncio.Task[None]] = app.state.redteam_tasks
            for task in list(tasks):
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await provider.aclose()
            await models.aclose()
            await engine.dispose()

    app = FastAPI(title="AI Security Gateway", version=__version__, lifespan=lifespan)
    install_error_handlers(app)
    app.include_router(routes_proxy.router)
    app.include_router(routes_scan.router)
    app.include_router(routes_admin.router)
    app.include_router(routes_redteam.router)

    @app.get("/healthz", response_model=None)
    async def healthz(services: ServicesDep) -> dict[str, str] | JSONResponse:
        try:
            async with services.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception:
            log.exception("health check: database unavailable")
            return JSONResponse({"status": "error", "database": "unavailable"}, status_code=503)
        return {"status": "ok", "database": "ok"}

    # Each add_middleware wraps the previous ones, so RequestIdMiddleware (added last) runs
    # first and every response, including a 413 from the size limit, carries a request id.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_methods=["GET", "POST", "PUT"],
            allow_headers=["Authorization", "Content-Type"],
        )
    app.add_middleware(RequestIdMiddleware)
    return app


async def retention_loop(services: Services) -> None:
    """Delete data past RETENTION_DAYS now and then every RETENTION_CHECK_MINUTES."""
    while True:
        try:
            async with services.sessionmaker() as session:
                counts = await maintenance.cleanup(session, services.settings.retention_days)
                if any(counts.values()):
                    repo.add_audit(
                        session, "retention", "retention.cleanup", None, json.dumps(counts)
                    )
                await session.commit()
            if any(counts.values()):
                log.info("retention cleanup", extra={"deleted": counts})
        except Exception:
            log.exception("retention cleanup failed")
        await asyncio.sleep(services.settings.retention_check_minutes * 60)


_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    # Built on first access so `uvicorn gateway.main:app` works while importing this
    # module (in tests or tools) does not require the environment to be configured.
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
