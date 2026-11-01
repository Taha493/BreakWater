"""M4 acceptance: the red-team harness runs every attack and benign case end to end against
the demo app (with and without the gateway), reports ASR per category, false positive rate,
and latency overhead, and --fail-on-regression exits non-zero when ASR rises."""

from __future__ import annotations

import argparse
import asyncio
import copy
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from demo_app.vulnerable_rag import DemoSettings
from demo_app.vulnerable_rag import create_app as create_demo
from gateway.config import Settings, get_settings
from gateway.core.keys import KeyRole
from gateway.redteam.cli import EXIT_REFUSED, EXIT_REGRESSION, redteam_run
from gateway.redteam.models import Category, load_targets
from gateway.redteam.report import build_report, render
from gateway.redteam.service import Harness, RunOptions, execute_run, start_run
from gateway.storage import repo
from gateway.storage.models import ApiKey, AuditLog, RedteamResult, RedteamRun
from tests.conftest import (
    BOOTSTRAP_KEY,
    HASH_SECRET,
    UPSTREAM_KEY,
    UPSTREAM_URL,
    create_schema,
    make_key,
    make_settings,
)

TARGETS = """
defaults: {max_requests_per_second: 200, max_concurrency: 4, timeout_seconds: 30}
regression_tolerance: 0.02
targets:
  demo_rag: {type: demo_rag, owned: true, url: "http://demo.test"}
  borrowed: {type: demo_rag, owned: false, url: "http://demo.test"}
  always_fooled:
    type: python_callable
    owned: true
    callable: "tests.integration.test_redteam:always_fooled"
"""


def always_fooled(probe: dict[str, Any], protected: bool) -> dict[str, Any]:
    """A target that repeats whatever it is told, gateway or not."""
    return {"response": probe["question"]}


@pytest.fixture
def targets_path(tmp_path: Path) -> Path:
    path = tmp_path / "targets.yaml"
    path.write_text(TARGETS, "utf-8")
    return path


@pytest.fixture
def settings(tmp_path: Path, targets_path: Path) -> Settings:
    return make_settings(tmp_path, redteam_targets_path=targets_path)


@pytest.fixture
async def stack(sim_app: FastAPI, sim_upstream: httpx.AsyncBaseTransport) -> AsyncIterator[FastAPI]:
    """Gateway + demo app + simulated model, all in-process. The gateway's red-team runs
    reach the demo app through ``redteam_transport``."""
    demo = create_demo(
        DemoSettings(
            gateway_url="http://gateway.test",
            upstream_base_url=UPSTREAM_URL,
            qdrant_url=":memory:",
            _env_file=None,
        ),
        gateway_transport=httpx.ASGITransport(app=sim_app),
        upstream_transport=sim_upstream,
    )
    async with demo.router.lifespan_context(demo):
        sim_app.state.redteam_transport = httpx.ASGITransport(app=demo)
        yield sim_app


def harness(app: FastAPI, targets_path: Path) -> Harness:
    services = app.state.services
    return Harness(
        sessionmaker=services.sessionmaker,
        hasher=services.hasher,
        runtime=services.store.current,
        targets=load_targets(targets_path),
        transport=app.state.redteam_transport,
    )


async def test_full_run_meets_m4_acceptance(stack: FastAPI, targets_path: Path) -> None:
    h = harness(stack, targets_path)
    options = RunOptions(target="demo_rag", seed=1, mutations=1)
    run = await execute_run(h, (await start_run(h, options)).id, options)
    assert run.status == "completed" and run.summary is not None
    summary = run.summary

    # At least 75 attacks and 100 benign cases ran end to end, in both modes.
    totals = summary["totals"]
    assert (totals["attacks"], totals["attack_probes"], totals["benign"]) == (75, 150, 100)
    assert totals["errors"] == 0

    # ASR protected versus unprotected, per category.
    by_category = summary["asr"]["by_category"]
    assert set(by_category) == {c.value for c in Category}
    for name, row in by_category.items():
        unprotected, protected = row["unprotected"]["rate"], row["protected"]["rate"]
        assert unprotected >= 0.85, name  # the simulated model falls for nearly everything
        assert protected < unprotected, name  # the gateway stops some of it in every class
    assert by_category["tool_abuse"]["protected"]["rate"] == 0.0

    # False positive rate on the benign set, and latency overhead.
    fp = summary["false_positives"]
    assert fp["n"] == 100 and fp["rate"] <= 0.02
    latency = summary["latency_ms"]
    assert latency["n"] == 100
    assert latency["overhead"]["p50"] is not None and latency["overhead"]["p95"] is not None

    # Every block is attributed to a detector and layer from the event log.
    caught = summary["caught_by"]
    assert "unknown" not in caught["layer"] and caught["detector"]

    async with stack.state.services.sessionmaker() as session:
        results = await repo.redteam_results(session, run.id)
        keys = list(await session.scalars(select(ApiKey).where(ApiKey.name.like("redteam-%"))))
        audit = [a.action for a in await session.scalars(select(AuditLog))]
    assert len(results) == (150 + 100) * 2
    assert all(r.caught_by_layer is not None for r in results if r.blocked and r.kind == "attack")
    # Transcripts are stored redacted.
    transcripts = "\n".join(r.transcript_redacted for r in results)
    for raw in ("dana.ruiz@example.org", "4111 1111 1111 1111", "+1 415 555 0134"):
        assert raw not in transcripts
    assert "[REDACTED:" in transcripts
    # The temporary gateway key is revoked when the run ends.
    assert len(keys) == 1 and keys[0].revoked_at is not None
    assert audit.count("api_key.create") == 1 and audit.count("api_key.revoke") == 1

    report = build_report(run, results)
    successes = sum(row["protected"]["successes"] for row in by_category.values())
    assert report["failing_total"] == successes > 0
    for fmt in ("json", "md", "html"):
        assert render(report, fmt)


async def test_runs_are_reproducible(stack: FastAPI, targets_path: Path) -> None:
    h = harness(stack, targets_path)
    options = RunOptions(target="demo_rag", seed=3, mutations=1, limit=2)
    first = await execute_run(h, (await start_run(h, options)).id, options)
    second = await execute_run(h, (await start_run(h, options)).id, options)
    async with stack.state.services.sessionmaker() as session:
        a = await repo.redteam_results(session, first.id)
        b = await repo.redteam_results(session, second.id)
    signature = [(r.attack_id, r.variant, r.mode, r.success, r.blocked) for r in a]
    assert signature == [(r.attack_id, r.variant, r.mode, r.success, r.blocked) for r in b]
    assert second.previous_run_id == first.id
    assert second.summary and second.summary["regression"]["regressed"] == []


# ---- CLI and the regression gate -------------------------------------------------------


def cli_args(tmp_path: Path, target: str, *flags: str) -> argparse.Namespace:
    from gateway.redteam import cli as redteam_cli

    parser = argparse.ArgumentParser()
    redteam_cli.add_parser(parser.add_subparsers(dest="command"))
    return parser.parse_args(
        ["redteam", "run", "--target", target, "--limit", "3", "--out", str(tmp_path / "out"),
         *flags]
    )  # fmt: skip


@pytest.fixture
async def cli_env(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, targets_path: Path
) -> AsyncIterator[None]:
    await create_schema(settings)
    env = {
        "GATEWAY_DATABASE_URL": settings.gateway_database_url,
        "UPSTREAM_BASE_URL": UPSTREAM_URL,
        "UPSTREAM_API_KEY": UPSTREAM_KEY,
        "GATEWAY_HASH_SECRET": HASH_SECRET,
        "ADMIN_BOOTSTRAP_KEY": BOOTSTRAP_KEY,
        "REDTEAM_TARGETS_PATH": str(targets_path),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def lower_latest_run(settings: Settings, rate: float) -> None:
    """Rewrite the latest run's protected ASR, as if the gateway had stopped more then."""
    from gateway.storage.db import make_engine, make_sessionmaker

    engine = make_engine(settings.gateway_database_url)
    async with make_sessionmaker(engine)() as session:
        run = await session.scalar(select(RedteamRun).order_by(RedteamRun.started_at.desc()))
        assert run is not None and run.summary is not None
        summary = copy.deepcopy(run.summary)
        for row in summary["asr"]["by_category"].values():
            row["protected"]["rate"] = rate
        run.summary = summary
        await session.commit()
    await engine.dispose()


async def latest_regression(settings: Settings) -> dict[str, Any]:
    from gateway.storage.db import make_engine, make_sessionmaker

    engine = make_engine(settings.gateway_database_url)
    async with make_sessionmaker(engine)() as session:
        run = await session.scalar(select(RedteamRun).order_by(RedteamRun.started_at.desc()))
    await engine.dispose()
    assert run is not None and run.summary is not None
    regression: dict[str, Any] = run.summary["regression"]
    return regression


async def test_fail_on_regression_exit_codes(
    cli_env: None, settings: Settings, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    flag = "--fail-on-regression"
    # A baseline run, then pretend the gateway stopped everything back then.
    assert await redteam_run(cli_args(tmp_path, "always_fooled", flag)) == 0
    assert sorted(p.suffix for p in (tmp_path / "out").iterdir()) == [".html", ".json", ".md"]
    await lower_latest_run(settings, 0.0)
    # Now protected ASR jumps from 0 to near 100%.
    assert await redteam_run(cli_args(tmp_path, "always_fooled", flag)) == EXIT_REGRESSION
    assert "regression in: direct_injection" in capsys.readouterr().err
    # Again: compared with the run just above, nothing rose.
    assert await redteam_run(cli_args(tmp_path, "always_fooled", flag)) == 0
    # Without the flag, or within the tolerance, a regression is reported but does not fail.
    await lower_latest_run(settings, 0.0)
    assert await redteam_run(cli_args(tmp_path, "always_fooled")) == 0
    assert (await latest_regression(settings))["regressed"]
    await lower_latest_run(settings, 0.0)
    assert await redteam_run(cli_args(tmp_path, "always_fooled", flag, "--tolerance", "1")) == 0


async def test_only_comparable_runs_are_compared(
    cli_env: None, settings: Settings, tmp_path: Path
) -> None:
    assert await redteam_run(cli_args(tmp_path, "always_fooled")) == 0
    await lower_latest_run(settings, 0.0)
    for different in (["--seed", "2"], ["--mutations", "0"], ["--category", "data_leakage"]):
        args = cli_args(tmp_path, "always_fooled", "--fail-on-regression", *different)
        assert await redteam_run(args) == 0, different
        assert (await latest_regression(settings))["previous_run_id"] is None


@pytest.mark.parametrize("target", ["borrowed", "nowhere"])
async def test_cli_refuses_targets_not_owned(
    cli_env: None, settings: Settings, tmp_path: Path, target: str
) -> None:
    assert await redteam_run(cli_args(tmp_path, target)) == EXIT_REFUSED
    from gateway.storage.db import make_engine, make_sessionmaker

    engine = make_engine(settings.gateway_database_url)
    async with make_sessionmaker(engine)() as session:
        assert list(await session.scalars(select(RedteamRun))) == []
    await engine.dispose()


# ---- API -------------------------------------------------------------------------------


@pytest.fixture
async def api(stack: FastAPI) -> AsyncIterator[tuple[httpx.AsyncClient, dict[str, str]]]:
    admin = await make_key(stack, KeyRole.ADMIN)
    transport = httpx.ASGITransport(app=stack)
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway.test") as client:
        yield client, {"Authorization": f"Bearer {admin}"}


async def wait_for_runs(app: FastAPI) -> None:
    await asyncio.gather(*list(app.state.redteam_tasks))


async def test_api_run_lifecycle(
    stack: FastAPI, api: tuple[httpx.AsyncClient, dict[str, str]]
) -> None:
    client, admin = api
    started = await client.post(
        "/redteam/runs",
        json={"target": "demo_rag", "limit": 1, "categories": ["direct_injection"]},
        headers=admin,
    )
    assert started.status_code == 202 and started.json()["status"] == "running"
    run_id = started.json()["id"]
    await wait_for_runs(stack)

    listed = (await client.get("/redteam/runs", headers=admin)).json()
    assert [r["id"] for r in listed] == [run_id] and listed[0]["status"] == "completed"
    detail = (await client.get(f"/redteam/runs/{run_id}", headers=admin)).json()
    assert detail["config_snapshot"]["model_simulated"] is True
    totals = detail["summary"]["totals"]
    assert (totals["attacks"], totals["attack_probes"], totals["benign"]) == (1, 2, 1)

    html = await client.get(f"/redteam/runs/{run_id}/report?format=html", headers=admin)
    assert html.headers["content-type"].startswith("text/html")
    assert "default-src 'none'" in html.headers["content-security-policy"]
    assert "attachment" in html.headers["content-disposition"]
    md = await client.get(f"/redteam/runs/{run_id}/report?format=md", headers=admin)
    assert md.text.startswith("# Red-team report: demo_rag")
    data = (await client.get(f"/redteam/runs/{run_id}/report", headers=admin)).json()
    assert data["run"]["id"] == run_id and len(data["results"]) == 6

    async with stack.state.services.sessionmaker() as session:
        actions = [a.action for a in await session.scalars(select(AuditLog))]
    assert "redteam.run" in actions


async def test_api_auth_and_errors(
    stack: FastAPI, api: tuple[httpx.AsyncClient, dict[str, str]]
) -> None:
    client, admin = api
    client_key = await make_key(stack, KeyRole.CLIENT)
    as_client = {"Authorization": f"Bearer {client_key}"}
    assert (await client.get("/redteam/runs")).status_code == 401
    assert (await client.get("/redteam/runs", headers=as_client)).status_code == 403
    denied = await client.post("/redteam/runs", json={"target": "demo_rag"}, headers=as_client)
    assert denied.status_code == 403

    refused = await client.post("/redteam/runs", json={"target": "borrowed"}, headers=admin)
    assert refused.status_code == 400 and refused.json()["error"]["code"] == "target_not_allowed"
    url = await client.post(
        "/redteam/runs", json={"target": "demo_rag", "url": "http://elsewhere"}, headers=admin
    )
    assert url.status_code == 422  # targets come from config only
    assert (await client.get("/redteam/runs/nope", headers=admin)).status_code == 404
    bad = await client.get("/redteam/runs/nope/report?format=pdf", headers=admin)
    assert bad.status_code == 422


async def test_failed_run_is_recorded(
    stack: FastAPI, targets_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = harness(stack, targets_path)
    options = RunOptions(target="demo_rag", limit=1)
    run = await start_run(h, options)

    async def explode(*args: object, **kwargs: object) -> list[object]:
        raise RuntimeError("target exploded")

    monkeypatch.setattr("gateway.redteam.service.run_probes", explode)
    with pytest.raises(RuntimeError):
        await execute_run(h, run.id, options)
    async with stack.state.services.sessionmaker() as session:
        stored = await session.get(RedteamRun, run.id)
        keys = list(await session.scalars(select(ApiKey)))
        results = list(await session.scalars(select(RedteamResult)))
    assert stored is not None and stored.status == "failed"
    assert stored.error == "RuntimeError: target exploded"
    assert stored.config_snapshot["ruleset_version"]
    assert all(k.revoked_at is not None for k in keys if k.name.startswith("redteam-"))
    assert results == []


# ---- http_chat target -------------------------------------------------------------------


class ByHost(httpx.AsyncBaseTransport):
    """Routes each request to an in-process app by host name."""

    def __init__(self, routes: dict[str, httpx.AsyncBaseTransport]) -> None:
        self.routes = routes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self.routes[request.url.host].handle_async_request(request)


async def test_http_chat_target(
    sim_app: FastAPI, sim_upstream: httpx.AsyncBaseTransport, tmp_path: Path
) -> None:
    targets = tmp_path / "chat.yaml"
    targets.write_text(
        "targets:\n"
        "  chat:\n"
        "    type: http_chat\n"
        "    owned: true\n"
        "    gateway_url: http://gateway.test\n"
        f"    upstream_url: {UPSTREAM_URL}\n"
        "    model: sim-obedient\n",
        "utf-8",
    )
    services = sim_app.state.services
    h = Harness(
        sessionmaker=services.sessionmaker,
        hasher=services.hasher,
        runtime=services.store.current,
        targets=load_targets(targets),
        transport=ByHost(
            {"gateway.test": httpx.ASGITransport(app=sim_app), "upstream.test": sim_upstream}
        ),
    )
    options = RunOptions(target="chat", mutations=0, limit=3)
    run = await execute_run(h, (await start_run(h, options)).id, options)
    assert run.summary is not None
    summary = run.summary
    assert summary["totals"]["errors"] == 0
    by_category = summary["asr"]["by_category"]
    assert by_category["tool_abuse"]["unprotected"]["rate"] == 1.0
    assert by_category["tool_abuse"]["protected"]["rate"] == 0.0
    assert summary["caught_by"]["intervention"].get("tool_denied")
    assert summary["false_positives"]["n"] == 3
