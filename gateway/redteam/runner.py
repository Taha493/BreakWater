"""Runs every probe against a target, unprotected and then protected (spec section 8).

Probes run concurrently up to the target's limit, but results come back in probe order, so
two runs with the same seed list the same cases in the same order.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from gateway.redteam.models import Attack, BenignCase
from gateway.redteam.probes import Probe, attack_probes, benign_probe
from gateway.redteam.scorer import score
from gateway.redteam.targets import MODES, Mode, Outcome, Target, TargetError

log = logging.getLogger("gateway.redteam")


@dataclass
class CaseResult:
    probe: Probe
    mode: Mode
    outcome: Outcome
    success: bool  # attacks: a criterion held; benign: always False
    matched: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    # Filled in afterwards from the gateway's event log, when it is reachable.
    caught_by_layer: int | None = None
    detectors: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        """The gateway intervened: blocked, redacted, excluded a chunk, or stopped a tool."""
        return bool(self.outcome.interventions)

    @property
    def errored(self) -> bool:
        return self.outcome.error is not None


def build_probes(
    attacks: list[Attack], benign: list[BenignCase], seed: int, mutations: int
) -> list[Probe]:
    probes: list[Probe] = []
    for attack in attacks:
        probes += attack_probes(attack, seed, mutations)
    probes += [benign_probe(case) for case in benign]
    return probes


async def _run_one(target: Target, probe: Probe, mode: Mode, tag: str) -> CaseResult:
    try:
        outcome = await target.run(probe, mode, tag)
    except (TargetError, httpx.HTTPError, TimeoutError, ValueError, KeyError) as exc:
        error = f"{type(exc).__name__}: {exc}"[:300]
        log.warning(
            "red-team probe %s (%s) failed: %s",
            probe.case_id,
            mode,
            error,
            extra={"case_id": probe.case_id, "mode": mode, "error": error},
        )
        outcome = Outcome(error=error)
    if probe.kind == "benign" or outcome.error is not None:
        return CaseResult(probe, mode, outcome, success=False)
    result = score(probe.criteria, outcome)
    return CaseResult(probe, mode, outcome, result.success, result.matched, result.skipped)


async def run_probes(
    target: Target,
    probes: list[Probe],
    tag: str,
    progress: Callable[[int, int], None] | None = None,
) -> list[CaseResult]:
    """Each probe runs unprotected, then protected, back to back, so the two latencies are
    measured under the same load."""
    done = 0

    async def both(probe: Probe) -> list[CaseResult]:
        nonlocal done
        async with target.pacer.slots:
            results = [await _run_one(target, probe, mode, tag) for mode in MODES]
        done += 1
        if progress is not None:
            progress(done, len(probes))
        return results

    pairs = await asyncio.gather(*(both(p) for p in probes))
    return [result for pair in pairs for result in pair]
