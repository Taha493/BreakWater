"""A red-team run end to end: validate the target, mint a temporary gateway key, run the
probes, attribute blocks to detectors from the event log, store redacted results, and
compare with the previous run. Shared by the CLI and the API.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from gateway import __version__
from gateway.core.keys import KeyRole
from gateway.core.redact import Hasher
from gateway.core.runtime import Runtime
from gateway.redteam import metrics
from gateway.redteam.models import (
    Category,
    HttpChatTarget,
    TargetsFile,
    library_hash,
    load_attacks,
    load_benign,
    owned_target,
)
from gateway.redteam.mutators import MUTATORS
from gateway.redteam.runner import CaseResult, build_probes, run_probes
from gateway.redteam.targets import build_target
from gateway.storage import repo
from gateway.storage.models import Event, RedteamResult, RedteamRun, utcnow

log = logging.getLogger("gateway.redteam")

SIMULATED_MODELS = {"sim-obedient"}
TRANSCRIPT_FIELD_CHARS = 2000
REDTEAM_ACTOR = "redteam"


@dataclass(frozen=True)
class RunOptions:
    target: str
    seed: int = 1
    mutations: int = 1
    # Keep only the first N attacks per category and the first N benign cases (smoke runs).
    limit: int | None = None
    categories: tuple[str, ...] = ()


@dataclass
class Harness:
    """What a run needs from its host (the CLI or the gateway app)."""

    sessionmaker: async_sessionmaker[AsyncSession]
    hasher: Hasher
    runtime: Callable[[], Runtime]
    targets: TargetsFile
    gateway_key: str | None = None
    transport: httpx.AsyncBaseTransport | None = None
    progress: Callable[[int, int], None] | None = field(default=None)


def _selected(options: RunOptions) -> tuple[list[Any], list[Any]]:
    attacks = load_attacks()
    benign = load_benign()
    if options.categories:
        wanted = {Category(c) for c in options.categories}
        attacks = [a for a in attacks if a.category in wanted]
    if options.limit is not None:
        per_category: dict[Category, int] = {}
        kept = []
        for attack in attacks:
            per_category[attack.category] = per_category.get(attack.category, 0) + 1
            if per_category[attack.category] <= options.limit:
                kept.append(attack)
        attacks = kept
        benign = benign[: options.limit]
    return attacks, benign


def config_snapshot(harness: Harness, options: RunOptions) -> dict[str, Any]:
    target = owned_target(harness.targets, options.target)
    attacks, benign = _selected(options)
    runtime = harness.runtime()
    model = getattr(target, "model", None)
    return {
        "gateway_version": __version__,
        "target": options.target,
        "target_type": target.type,
        "model": model,
        "model_simulated": model in SIMULATED_MODELS,
        "seed": options.seed,
        "mutations_per_attack": options.mutations,
        "mutators": sorted(MUTATORS),
        "categories": list(options.categories) or [c.value for c in Category],
        "limit": options.limit,
        "attacks": len(attacks),
        "benign": len(benign),
        "library_hash": library_hash(attacks, benign),
        "ruleset_version": runtime.version,
        "policy": runtime.policy.config.model_dump(mode="json"),
        "layers": ["normalize (0)", "rules (1)"],
        "judge_available": False,
        "limits": harness.targets.limits_for(options.target).model_dump(),
        "regression_tolerance": harness.targets.regression_tolerance,
    }


async def start_run(harness: Harness, options: RunOptions) -> RedteamRun:
    """Create the run row. Raises TargetNotAllowed before anything is written."""
    snapshot = config_snapshot(harness, options)
    async with harness.sessionmaker() as session:
        run = RedteamRun(
            target=options.target,
            status="running",
            started_at=utcnow(),
            seed=options.seed,
            config_snapshot=snapshot,
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        return run


async def _mint_key(harness: Harness, run_id: str) -> tuple[str, str | None]:
    if harness.gateway_key:
        return harness.gateway_key, None
    async with harness.sessionmaker() as session:
        row, plaintext = await repo.create_api_key(
            session, harness.hasher, f"redteam-run-{run_id[:8]}", KeyRole.CLIENT
        )
        repo.add_audit(session, REDTEAM_ACTOR, "api_key.create", row.id, f"run={run_id}")
        await session.commit()
        return plaintext, row.id


async def _revoke_key(harness: Harness, key_id: str | None, run_id: str) -> None:
    if key_id is None:
        return
    async with harness.sessionmaker() as session:
        _, changed = await repo.revoke_api_key(session, key_id)
        if changed:
            repo.add_audit(session, REDTEAM_ACTOR, "api_key.revoke", key_id, f"run={run_id}")
        await session.commit()


async def attribute(harness: Harness, results: list[CaseResult]) -> None:
    """Which layer and detectors caught each protected probe, from the gateway's event log.
    Works when the run shares the gateway's database (the CLI and the API do)."""
    wanted = {rid for r in results if r.blocked for rid in r.outcome.request_ids}
    if not wanted:
        return
    by_request: dict[str, list[tuple[int, str, str | None]]] = {}
    async with harness.sessionmaker() as session:
        ids = sorted(wanted)
        for start in range(0, len(ids), 500):
            rows = await session.scalars(
                select(Event)
                .where(Event.request_id.in_(ids[start : start + 500]), Event.action != "allow")
                .options(selectinload(Event.findings))
            )
            for event in rows:
                by_request.setdefault(event.request_id, []).extend(
                    (f.layer, f.detector, f.rule_id) for f in event.findings
                )
    for result in results:
        if not result.blocked:
            continue
        found = [f for rid in result.outcome.request_ids for f in by_request.get(rid, [])]
        if found:
            result.caught_by_layer = min(layer for layer, _, _ in found)
            result.detectors = sorted({detector for _, detector, _ in found})
            result.rule_ids = sorted({rule for _, _, rule in found if rule})


def _redact(value: Any, harness: Harness) -> Any:
    if isinstance(value, str):
        return harness.runtime().redactor.redact(value[:TRANSCRIPT_FIELD_CHARS])
    if isinstance(value, dict):
        return {k: _redact(v, harness) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, harness) for v in value]
    return value


def transcript(result: CaseResult, harness: Harness) -> str:
    """What was sent and what came back, secrets and PII redacted (spec section 8)."""
    probe, outcome = result.probe, result.outcome
    raw = {
        "question": probe.question,
        "history": probe.history,
        "documents": probe.documents,
        "tool_result": probe.tool_result,
        "response": outcome.response,
        "tool_calls": [vars(c) for c in outcome.tool_calls],
        "interventions": outcome.interventions,
        "matched": list(result.matched),
        "skipped": list(result.skipped),
        "rule_ids": result.rule_ids,
        "error": outcome.error,
        **outcome.detail,
    }
    return json.dumps(_redact(raw, harness), ensure_ascii=False)


# Runs are compared only when they ran the same probes: same attack and benign sets, seed,
# and number of mutations. A smaller smoke run is never the baseline for a full run.
COMPARABLE_FIELDS = ("library_hash", "seed", "mutations_per_attack")


def comparable(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return all(a.get(k) is not None and a.get(k) == b.get(k) for k in COMPARABLE_FIELDS)


async def previous_run(session: AsyncSession, target: str, before: RedteamRun) -> RedteamRun | None:
    """The latest completed, comparable run against the same target."""
    candidates = await session.scalars(
        select(RedteamRun)
        .where(
            RedteamRun.target == target,
            RedteamRun.status == "completed",
            RedteamRun.id != before.id,
            RedteamRun.started_at <= before.started_at,
        )
        .order_by(RedteamRun.started_at.desc())
        .limit(100)
    )
    return next(
        (run for run in candidates if comparable(run.config_snapshot, before.config_snapshot)),
        None,
    )


def _upstream_key(harness: Harness, options: RunOptions) -> str | None:
    target = harness.targets.targets[options.target]
    if isinstance(target, HttpChatTarget) and target.upstream_key_env:
        return os.environ.get(target.upstream_key_env)
    return None


async def execute_run(harness: Harness, run_id: str, options: RunOptions) -> RedteamRun:
    """Run the probes for a started run and store everything. A failure marks the run
    failed (with the reason) and is re-raised."""
    try:
        return await _execute(harness, run_id, options)
    except BaseException as exc:
        async with harness.sessionmaker() as session:
            run = await session.get(RedteamRun, run_id)
            if run is not None:
                run.status = "failed"
                run.finished_at = utcnow()
                run.error = f"{type(exc).__name__}: {exc}"[:1000]
                await session.commit()
        raise


async def _execute(harness: Harness, run_id: str, options: RunOptions) -> RedteamRun:
    config = owned_target(harness.targets, options.target)
    attacks, benign = _selected(options)
    probes = build_probes(attacks, benign, options.seed, options.mutations)
    key, key_id = await _mint_key(harness, run_id)
    target = build_target(
        config,
        harness.targets.limits_for(options.target),
        key,
        upstream_key=_upstream_key(harness, options),
        transport=harness.transport,
    )
    try:
        results = await run_probes(target, probes, run_id[:8], harness.progress)
    finally:
        await target.aclose()
        await _revoke_key(harness, key_id, run_id)
    await attribute(harness, results)
    summary = metrics.summarize(results)

    async with harness.sessionmaker() as session:
        run = await session.get(RedteamRun, run_id)
        if run is None:
            raise LookupError(f"run {run_id} disappeared")
        previous = await previous_run(session, options.target, run)
        summary["regression"] = {
            "previous_run_id": previous.id if previous else None,
            **metrics.regression(
                summary,
                previous.summary if previous else None,
                harness.targets.regression_tolerance,
            ),
        }
        session.add_all(
            RedteamResult(
                run_id=run_id,
                position=position,
                kind=r.probe.kind,
                attack_id=r.probe.source_id,
                variant=r.probe.variant,
                category=r.probe.category,
                mode=r.mode,
                success=r.success,
                blocked=r.blocked,
                caught_by_layer=r.caught_by_layer,
                detectors=r.detectors,
                latency_ms=round(r.outcome.latency_ms, 3),
                error=r.outcome.error,
                transcript_redacted=transcript(r, harness),
            )
            for position, r in enumerate(results)
        )
        run.summary = summary
        run.previous_run_id = previous.id if previous else None
        run.status = "completed"
        run.finished_at = utcnow()
        await session.commit()
        await session.refresh(run)
        return run
