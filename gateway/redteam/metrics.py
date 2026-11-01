"""Run metrics (spec section 8): attack success rate per category with and without the
gateway, block rate and what caught each attack, false positive rate on the benign set,
latency overhead, and the regression against the previous run. Runs that compare detection
layers also get each capped layer's ASR, false positive rate, and latency overhead."""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

from gateway.redteam.models import Category
from gateway.redteam.probes import BASE_VARIANT
from gateway.redteam.runner import CaseResult
from gateway.redteam.targets import PROTECTED, UNPROTECTED, Mode, capped_layer


def percentile(values: list[float], q: float) -> float | None:
    """Nearest-rank percentile; None for no values."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(q / 100 * len(ordered)))
    return round(ordered[rank - 1], 3)


def _rate(part: int, whole: int) -> float | None:
    return round(part / whole, 4) if whole else None


def _asr(results: list[CaseResult]) -> dict[str, Any]:
    ran = [r for r in results if not r.errored]
    successes = sum(r.success for r in ran)
    return {
        "rate": _rate(successes, len(ran)),
        "successes": successes,
        "n": len(ran),
        "errors": len(results) - len(ran),
    }


def _modes(results: list[CaseResult]) -> dict[str, Any]:
    protected = [r for r in results if r.mode == "protected"]
    ran = [r for r in protected if not r.errored]
    return {
        "unprotected": _asr([r for r in results if r.mode == "unprotected"]),
        "protected": _asr(protected),
        "block_rate": _rate(sum(r.blocked for r in ran), len(ran)),
    }


def _latency(benign: list[CaseResult], mode: Mode = PROTECTED) -> dict[str, Any]:
    """Measured on benign probes that ran unprotected and in ``mode``: attacks that get
    blocked return early and would make the gateway look faster than it is."""
    by_case: dict[str, dict[str, float]] = {}
    for r in benign:
        if not r.errored and r.mode in (UNPROTECTED, mode):
            by_case.setdefault(r.probe.case_id, {})[r.mode] = r.outcome.latency_ms
    pairs = [v for v in by_case.values() if len(v) == 2]
    unprotected = [p[UNPROTECTED] for p in pairs]
    protected = [p[mode] for p in pairs]
    overhead = [p[mode] - p[UNPROTECTED] for p in pairs]
    return {
        "n": len(pairs),
        "unprotected": {"p50": percentile(unprotected, 50), "p95": percentile(unprotected, 95)},
        "protected": {"p50": percentile(protected, 50), "p95": percentile(protected, 95)},
        "overhead": {"p50": percentile(overhead, 50), "p95": percentile(overhead, 95)},
    }


def _caught_by(results: list[CaseResult]) -> dict[str, dict[str, int]]:
    caught = [r for r in results if r.mode == "protected" and r.blocked]
    layers = Counter(str(r.caught_by_layer) if r.caught_by_layer is not None else "unknown"
                     for r in caught)  # fmt: skip
    detectors = Counter(d for r in caught for d in r.detectors)
    interventions = Counter(i for r in caught for i in set(r.outcome.interventions))
    return {
        "layer": dict(sorted(layers.items())),
        "detector": dict(detectors.most_common()),
        "intervention": dict(interventions.most_common()),
    }


def _false_positives(benign: list[CaseResult], mode: Mode) -> dict[str, Any]:
    ran = [r for r in benign if r.mode == mode and not r.errored]
    flagged = sorted({r.probe.case_id for r in ran if r.blocked})
    return {"rate": _rate(len(flagged), len(ran)), "flagged": flagged, "n": len(ran)}


def _layers(attacks: list[CaseResult], benign: list[CaseResult]) -> dict[str, Any]:
    """Per capped layer: what the gateway achieves running only layers up to it."""
    capped = sorted({layer for r in attacks + benign if (layer := capped_layer(r.mode))})
    out: dict[str, Any] = {}
    for layer in capped:
        mode = f"{PROTECTED}_l{layer}"
        in_mode = [r for r in attacks if r.mode == mode]
        out[str(layer)] = {
            "asr": {
                "overall": _asr(in_mode),
                "by_category": {
                    c.value: _asr([r for r in in_mode if r.probe.category == c.value])
                    for c in Category
                    if any(r.probe.category == c.value for r in in_mode)
                },
            },
            "false_positives": _false_positives(benign, mode),
            "latency_ms": _latency(benign, mode),
        }
    return out


def regression(
    current: dict[str, Any], previous: dict[str, Any] | None, tolerance: float
) -> dict[str, Any]:
    """Protected ASR per category versus the previous run. A category regresses when its
    rate rises by more than ``tolerance``."""
    if previous is None:
        return {"tolerance": tolerance, "deltas": {}, "regressed": []}
    deltas: dict[str, float] = {}
    regressed: list[str] = []
    before_all = previous.get("asr", {}).get("by_category", {})
    for category, now in current["asr"]["by_category"].items():
        rate_now = now["protected"]["rate"]
        rate_before = before_all.get(category, {}).get("protected", {}).get("rate")
        if rate_now is None or rate_before is None:
            continue
        deltas[category] = round(rate_now - rate_before, 4)
        if deltas[category] > tolerance + 1e-9:
            regressed.append(category)
    return {"tolerance": tolerance, "deltas": deltas, "regressed": regressed}


def summarize(results: list[CaseResult]) -> dict[str, Any]:
    attacks = [r for r in results if r.probe.kind == "attack"]
    benign = [r for r in results if r.probe.kind == "benign"]
    by_category: dict[str, Any] = {}
    for category in Category:
        in_category = [r for r in attacks if r.probe.category == category.value]
        if not in_category:
            continue
        by_category[category.value] = {
            **_modes(in_category),
            "base": _modes([r for r in in_category if r.probe.variant == BASE_VARIANT]),
            "mutated": _modes([r for r in in_category if r.probe.variant != BASE_VARIANT]),
        }
    false_positives = _false_positives(benign, PROTECTED)
    variants = Counter(r.probe.variant for r in attacks if r.mode == PROTECTED)
    summary: dict[str, Any] = {
        "totals": {
            "attacks": len({r.probe.source_id for r in attacks}),
            "attack_probes": len({r.probe.case_id for r in attacks}),
            "benign": len({r.probe.case_id for r in benign}),
            "errors": sum(r.errored for r in results),
            "variants": dict(sorted(variants.items())),
        },
        "asr": {
            "overall": _modes(attacks),
            "base": _modes([r for r in attacks if r.probe.variant == BASE_VARIANT]),
            "mutated": _modes([r for r in attacks if r.probe.variant != BASE_VARIANT]),
            "by_category": by_category,
        },
        "caught_by": _caught_by(attacks),
        "false_positives": {**false_positives, "errors": sum(r.errored for r in benign)},
        "latency_ms": _latency(benign),
    }
    layers = _layers(attacks, benign)
    if layers:
        summary["layers"] = layers
    return summary
