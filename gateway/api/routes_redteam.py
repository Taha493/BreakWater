"""Red-team routes (spec section 5): start a run, list runs, read one, download its report.

A run takes only the name of a target from the targets file, never a URL, so the gateway
calls nothing a caller chooses. Runs execute in the background inside the gateway process.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from gateway.api.deps import AdminPrincipal, Services, ServicesDep, SessionDep
from gateway.api.errors import GatewayError
from gateway.redteam.models import Category, TargetNotAllowed, load_targets
from gateway.redteam.report import build_report, render
from gateway.redteam.service import Harness, RunOptions, execute_run, start_run
from gateway.storage import repo
from gateway.storage.models import RedteamRun

log = logging.getLogger("gateway.redteam")
router = APIRouter(prefix="/redteam")

_MEDIA_TYPES = {
    "json": "application/json",
    "md": "text/markdown; charset=utf-8",
    "html": "text/html; charset=utf-8",
}


class StartRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=128)
    seed: int = Field(default=1, ge=0, le=2**31 - 1)
    mutations: int = Field(default=1, ge=0, le=5)
    limit: int | None = Field(default=None, ge=1, le=1000)
    categories: list[Category] = Field(default_factory=list)


class RunInfo(BaseModel):
    id: str
    target: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    seed: int
    previous_run_id: str | None
    asr_unprotected: float | None
    asr_protected: float | None
    false_positive_rate: float | None
    regressed: list[str]


class RunDetail(RunInfo):
    error: str | None
    config_snapshot: dict[str, Any]
    summary: dict[str, Any] | None


def _info(run: RedteamRun) -> dict[str, Any]:
    summary = run.summary or {}
    overall = summary.get("asr", {}).get("overall", {})
    return {
        "id": run.id,
        "target": run.target,
        "status": run.status,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "seed": run.seed,
        "previous_run_id": run.previous_run_id,
        "asr_unprotected": overall.get("unprotected", {}).get("rate"),
        "asr_protected": overall.get("protected", {}).get("rate"),
        "false_positive_rate": summary.get("false_positives", {}).get("rate"),
        "regressed": summary.get("regression", {}).get("regressed", []),
    }


def _harness(services: Services, request: Request) -> Harness:
    key = services.settings.redteam_gateway_key
    return Harness(
        sessionmaker=services.sessionmaker,
        hasher=services.hasher,
        runtime=services.store.current,
        targets=load_targets(services.settings.redteam_targets_path),
        gateway_key=key.get_secret_value() if key else None,
        transport=request.app.state.redteam_transport,
    )


async def _run_in_background(harness: Harness, run_id: str, options: RunOptions) -> None:
    try:
        await execute_run(harness, run_id, options)
    except Exception:
        log.exception("red-team run failed", extra={"run_id": run_id})


@router.post("/runs", status_code=202)
async def start(
    payload: StartRunRequest,
    request: Request,
    principal: AdminPrincipal,
    services: ServicesDep,
    session: SessionDep,
) -> RunInfo:
    options = RunOptions(
        target=payload.target,
        seed=payload.seed,
        mutations=payload.mutations,
        limit=payload.limit,
        categories=tuple(c.value for c in payload.categories),
    )
    try:
        harness = _harness(services, request)
        run = await start_run(harness, options)
    except TargetNotAllowed as exc:
        raise GatewayError(400, "invalid_request", "target_not_allowed", str(exc)) from exc
    except (OSError, ValueError) as exc:
        log.exception("invalid red-team configuration")
        raise GatewayError(
            500, "server_error", "redteam_config_error", "Invalid red-team targets file"
        ) from exc
    repo.add_audit(session, principal.key_id, "redteam.run", run.id, f"target={run.target}")
    await session.commit()
    task = asyncio.create_task(_run_in_background(harness, run.id, options))
    tasks: set[asyncio.Task[None]] = request.app.state.redteam_tasks
    tasks.add(task)
    task.add_done_callback(tasks.discard)
    return RunInfo(**_info(run))


@router.get("/runs")
async def list_runs(
    principal: AdminPrincipal,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[RunInfo]:
    return [RunInfo(**_info(run)) for run in await repo.list_redteam_runs(session, limit)]


async def _run(session: SessionDep, run_id: str) -> RedteamRun:
    run = await session.get(RedteamRun, run_id)
    if run is None:
        raise GatewayError(404, "invalid_request", "run_not_found", "No such red-team run")
    return run


@router.get("/runs/{run_id}")
async def get_run(run_id: str, principal: AdminPrincipal, session: SessionDep) -> RunDetail:
    run = await _run(session, run_id)
    return RunDetail(
        **_info(run), error=run.error, config_snapshot=run.config_snapshot, summary=run.summary
    )


@router.get("/runs/{run_id}/report")
async def get_report(
    run_id: str,
    principal: AdminPrincipal,
    session: SessionDep,
    format: Literal["json", "md", "html"] = "json",
) -> Response:
    run = await _run(session, run_id)
    report = build_report(run, await repo.redteam_results(session, run_id))
    headers = {"Content-Disposition": f'attachment; filename="redteam-{run.id}.{format}"'}
    if format == "html":
        # The report is self-contained: no scripts, no external loads.
        headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    return Response(render(report, format), media_type=_MEDIA_TYPES[format], headers=headers)
