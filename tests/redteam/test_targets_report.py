"""Target adapters (pacing, retries, intervention mapping) and report rendering."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from gateway.redteam.models import DemoRagTarget, Limits, PythonCallableTarget
from gateway.redteam.probes import Probe
from gateway.redteam.report import build_report, render
from gateway.redteam.targets import DemoRag, Pacer, PythonCallable, TargetError
from gateway.storage.models import RedteamResult, RedteamRun

LIMITS = Limits(max_requests_per_second=200, retries=2, timeout_seconds=5)
PROBE = Probe(
    "attack",
    "a1",
    "base",
    "indirect_injection",
    "A2",
    "retrieved_document",
    "How long is shipping?",
    documents=[{"name": "d.html", "format": "html", "content": "<p>x</p>"}],
)


async def test_pacer_spaces_requests() -> None:
    pacer = Pacer(Limits(max_requests_per_second=50))
    started = time.monotonic()
    for _ in range(6):
        await pacer.wait()
    assert time.monotonic() - started >= 0.09  # 5 intervals of 20 ms


def demo(handler: Any, limits: Limits = LIMITS) -> DemoRag:
    config = DemoRagTarget(type="demo_rag", owned=True, url="http://demo.test")
    return DemoRag(config, limits, "gw.key", transport=httpx.MockTransport(handler))


async def test_demo_target_maps_gateway_actions() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path == "/plant":
            body = json.loads(request.content)
            assert body["protected"] and request.headers["X-Gateway-Key"] == "gw.key"
            return httpx.Response(200, json={"documents": [], "gateway_request_ids": ["r1"]})
        if request.url.path == "/ask":
            return httpx.Response(
                200,
                json={
                    "status_code": 200,
                    "gateway_verdict": "redacted",
                    "answer": "ok",
                    "excluded": [{"doc_id": "d.html", "index": 0, "status": "quarantined"}],
                    "tool_calls": [
                        {"name": "delete_record", "arguments": {}, "status": "denied"},
                        {"name": "search_kb", "arguments": {"query": "q"}, "status": "executed"},
                    ],
                    "gateway_request_ids": ["r2", "r3"],
                },
            )
        return httpx.Response(200, json={})

    target = demo(handler)
    outcome = await target.run(PROBE, "protected", "t")
    await target.aclose()
    assert seen == [
        ("POST", "/plant"),
        ("POST", "/ask"),
        ("DELETE", "/plant/rt-t-a1-base-protected"),
    ]
    assert sorted(outcome.interventions) == ["chunk_excluded", "redacted", "tool_denied"]
    assert outcome.request_ids == ["r1", "r2", "r3"]
    assert [c.name for c in outcome.executed_tools] == ["search_kb"]


async def test_blocked_chat_is_an_intervention_not_an_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/ask":
            error = {"type": "gateway_blocked", "code": "prompt_injection"}
            return httpx.Response(200, json={"status_code": 403, "error": error})
        return httpx.Response(200, json={"documents": []})

    outcome = await demo(handler).run(PROBE, "protected", "t")
    assert outcome.interventions == ["blocked"] and outcome.error is None


async def test_retries_transport_errors_only() -> None:
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] <= 2:
            raise httpx.ConnectError("down")
        return httpx.Response(500)

    target = demo(flaky)
    response = await target.request("GET", "http://demo.test/x")
    assert response.status_code == 500 and calls["n"] == 3  # the 500 is not retried

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    with pytest.raises(TargetError, match="after 3 tries"):
        await demo(down).request("GET", "http://demo.test/x")


async def test_ask_failure_still_cleans_up() -> None:
    deleted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            deleted.append(request.url.path)
        if request.url.path == "/ask":
            return httpx.Response(500)
        return httpx.Response(200, json={"documents": []})

    with pytest.raises(TargetError, match="ask failed"):
        await demo(handler).run(PROBE, "unprotected", "t")
    assert deleted == ["/plant/rt-t-a1-base-unprotected"]


def echo_target(probe: dict[str, Any], protected: bool) -> dict[str, Any]:
    return {"response": "blocked" if protected else probe["question"], "interventions": []}


async def async_target(probe: dict[str, Any], protected: bool) -> dict[str, Any]:
    calls = [{"name": "send_email", "arguments": {"to": "x"}, "status": "denied"}]
    return {"response": "", "tool_calls": calls if protected else []}


@pytest.mark.parametrize(
    ("name", "protected_interventions"), [("echo_target", []), ("async_target", ["tool_denied"])]
)
async def test_python_callable(name: str, protected_interventions: list[str]) -> None:
    config = PythonCallableTarget(
        type="python_callable", owned=True, callable=f"tests.redteam.test_targets_report:{name}"
    )
    target = PythonCallable(config, LIMITS, "key")
    assert (await target.run(PROBE, "protected", "t")).interventions == protected_interventions
    if name == "echo_target":
        assert (await target.run(PROBE, "unprotected", "t")).response == PROBE.question


# ---- report --------------------------------------------------------------------------

HOSTILE = "<script>alert(1)</script>```"


def stored_run() -> tuple[RedteamRun, list[RedteamResult]]:
    now = datetime.now(UTC)
    run = RedteamRun(
        id="run-1",
        target="demo_rag",
        status="completed",
        started_at=now,
        finished_at=now,
        seed=1,
        config_snapshot={"model": "sim-obedient", "model_simulated": True, "note": HOSTILE},
        summary={
            "totals": {"attacks": 1, "attack_probes": 1, "benign": 0, "errors": 0},
            "asr": {
                "overall": {
                    "unprotected": {"rate": 1.0, "n": 1},
                    "protected": {"rate": 1.0, "n": 1},
                    "block_rate": 0.0,
                },
                "by_category": {
                    "direct_injection": {
                        "unprotected": {"rate": 1.0, "n": 1},
                        "protected": {"rate": 1.0, "n": 1},
                        "block_rate": 0.0,
                    }
                },
            },
            "false_positives": {"rate": None, "flagged": [], "n": 0},
            "latency_ms": {"overhead": {"p50": None, "p95": None}},
            "regression": {"previous_run_id": None},
        },
    )
    result = RedteamResult(
        run_id="run-1",
        position=0,
        kind="attack",
        attack_id="inj-direct-001",
        variant="base",
        category="direct_injection",
        mode="protected",
        success=True,
        blocked=False,
        caught_by_layer=None,
        detectors=[],
        latency_ms=1.0,
        error=None,
        transcript_redacted=json.dumps({"response": HOSTILE}),
    )
    return run, [result]


def test_html_report_escapes_everything() -> None:
    report = build_report(*stored_run())
    page = render(report, "html")
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert "<link" not in page and "src=" not in page  # self-contained
    assert "simulated model" in page


def test_markdown_and_json_reports() -> None:
    report = build_report(*stored_run())
    markdown = render(report, "md")
    assert "| direct_injection | 100.0% | 100.0% |" in markdown
    assert "````json" in markdown  # the fence outlasts backticks in the transcript
    assert json.loads(render(report, "json"))["top_failing"][0]["attack_id"] == "inj-direct-001"
    with pytest.raises(ValueError):
        render(report, "pdf")
