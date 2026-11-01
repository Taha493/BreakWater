"""``breakwater redteam run``: run the harness from the command line, write the reports, and
optionally fail on a regression (spec section 8), so a CI job can gate on it.

Exit codes: 0 done, 1 regression (with --fail-on-regression), 2 refused or misconfigured,
3 the run failed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import httpx

from breakwater.config import get_settings
from breakwater.core.redact import Hasher
from breakwater.core.runtime import ConfigStore, configured_layers
from breakwater.redteam.models import Category, TargetNotAllowed, load_targets
from breakwater.redteam.report import FORMATS, build_report, render
from breakwater.redteam.service import (
    LAYER_NAMES,
    Harness,
    RunNotPossible,
    RunOptions,
    execute_run,
    start_run,
)
from breakwater.storage import repo
from breakwater.storage.db import make_engine, make_sessionmaker

EXIT_REGRESSION = 1
EXIT_REFUSED = 2
EXIT_FAILED = 3


def add_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    redteam = commands.add_parser("redteam", help="red-team harness")
    sub = redteam.add_subparsers(dest="redteam_command", required=True)
    run = sub.add_parser("run", help="run attacks and benign cases against a target")
    run.add_argument("--target", required=True, help="a target name from the targets file")
    run.add_argument("--targets-file", type=Path, help="default: REDTEAM_TARGETS_PATH")
    run.add_argument("--seed", type=int, default=1)
    run.add_argument("--mutations", type=int, default=1, choices=range(6), metavar="0-5")
    run.add_argument("--limit", type=int, help="first N attacks per category and N benign")
    run.add_argument("--category", action="append", choices=[c.value for c in Category])
    run.add_argument("--out", type=Path, default=Path("reports"), help="report directory")
    run.add_argument("--fail-on-regression", action="store_true")
    run.add_argument("--tolerance", type=float, help="override regression_tolerance")
    run.add_argument(
        "--compare-layers",
        action="store_true",
        help="also run with only the lower detection layers, to show what each one adds",
    )


def _progress(done: int, total: int) -> None:
    if done == total or done % 25 == 0:
        print(f"  {done}/{total} probes", file=sys.stderr)


async def redteam_run(
    args: argparse.Namespace, transport: httpx.AsyncBaseTransport | None = None
) -> int:
    settings = get_settings()
    try:
        targets = load_targets(args.targets_file or settings.redteam_targets_path)
    except (OSError, ValueError) as exc:
        print(f"invalid targets file: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    if args.tolerance is not None:
        targets = targets.model_copy(update={"regression_tolerance": args.tolerance})
    store = ConfigStore(settings.policies_path, settings.rules_dir, settings.config_reload_seconds)
    engine = make_engine(settings.gateway_database_url)
    key = settings.redteam_gateway_key
    harness = Harness(
        sessionmaker=make_sessionmaker(engine),
        hasher=Hasher(settings.gateway_hash_secret.get_secret_value()),
        runtime=store.current,
        targets=targets,
        layers=configured_layers(settings),
        gateway_key=key.get_secret_value() if key else None,
        transport=transport,
        progress=_progress,
    )
    options = RunOptions(
        target=args.target,
        seed=args.seed,
        mutations=args.mutations,
        limit=args.limit,
        categories=tuple(args.category or ()),
        compare_layers=args.compare_layers,
    )
    try:
        # The policy the gateway runs is the active database version, not the file.
        async with harness.sessionmaker() as session:
            active = await repo.active_policy(session)
        if active is not None:
            store.set_policy(active.content.encode("utf-8"), active.id)
        try:
            run = await start_run(harness, options)
        except (TargetNotAllowed, RunNotPossible) as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        print(f"red-team run {run.id} against {args.target}", file=sys.stderr)
        try:
            run = await execute_run(harness, run.id, options)
        except Exception as exc:
            print(f"run failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return EXIT_FAILED
        async with harness.sessionmaker() as session:
            report = build_report(run, await repo.redteam_results(session, run.id))
    finally:
        await engine.dispose()

    args.out.mkdir(parents=True, exist_ok=True)
    for fmt in FORMATS:
        (args.out / f"redteam-{run.id}.{fmt}").write_text(render(report, fmt), "utf-8")
    print(_headline(report))
    errors = report["summary"]["totals"]["errors"]
    if errors:
        print(f"warning: {errors} probes failed and are left out of the rates", file=sys.stderr)
    print(f"reports: {args.out}/redteam-{run.id}.{{{','.join(FORMATS)}}}")
    regressed = report["summary"].get("regression", {}).get("regressed", [])
    if regressed:
        print(f"regression in: {', '.join(regressed)}", file=sys.stderr)
        if args.fail_on_regression:
            return EXIT_REGRESSION
    return 0


def _pct(value: float | None) -> str:
    return "  n/a" if value is None else f"{value * 100:5.1f}%"


def _headline(report: dict[str, Any]) -> str:
    summary = report["summary"]
    layers: dict[str, Any] = summary.get("layers", {})
    capped = [f"<={LAYER_NAMES[int(n)]}" for n in layers]
    header = f"{'category':<20} {'unprotected':>11}"
    header += "".join(f" {name:>13}" for name in capped)
    lines = [header + f" {'protected':>10} {'n':>5}"]
    rows = [*summary["asr"]["by_category"].items(), ("all", summary["asr"]["overall"])]
    for name, row in rows:
        line = f"{name:<20} {_pct(row['unprotected']['rate']):>11}"
        for layer in layers.values():
            asr = layer["asr"]
            cell = asr["overall"] if name == "all" else asr["by_category"].get(name, {})
            line += f" {_pct(cell.get('rate')):>13}"
        lines.append(line + f" {_pct(row['protected']['rate']):>10} {row['protected']['n']:>5}")
    fp = summary["false_positives"]
    overhead = summary["latency_ms"]["overhead"]
    lines.append(f"false positive rate {_pct(fp['rate'])} ({len(fp['flagged'])}/{fp['n']})")
    lines.append(f"latency overhead p50 {overhead['p50']} ms, p95 {overhead['p95']} ms")
    for n, layer in layers.items():
        fp, overhead = layer["false_positives"], layer["latency_ms"]["overhead"]
        lines.append(
            f"  up to {LAYER_NAMES[int(n)]}: false positives {_pct(fp['rate'])}, "
            f"overhead p50 {overhead['p50']} ms, p95 {overhead['p95']} ms"
        )
    return "\n".join(lines)
