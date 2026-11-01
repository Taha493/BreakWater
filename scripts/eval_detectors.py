"""Detector evaluation on the labeled set in tests/data (spec section 12).

Reports recall per attack class, the false positive rate on the benign set, and precision
and recall per detector. Targets from the spec (recall >= 0.90, FPR <= 0.02) are shown for
reference; the script does not fail on them.

With --classifier, layer 2 runs too (the model in CLASSIFIER_MODEL at CLASSIFIER_REVISION,
which must be downloaded first: uv run gateway classifier download).

Usage: uv run python scripts/eval_detectors.py [--classifier] [--json] [--show-misses]
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from gateway.config import DEFAULT_POLICIES_PATH, DEFAULT_RULES_DIR, ClassifierModelSettings
from gateway.core.classifier import OnnxScorer, model_directory
from gateway.core.context import CallContext
from gateway.core.runtime import Models, Runtime, build_runtime
from gateway.core.verdict import Action, Role

DATA_DIR = Path(__file__).resolve().parent.parent / "tests" / "data"
RECALL_TARGET = 0.90
FPR_TARGET = 0.02
_REPEAT = re.compile(r"\{repeat:(.):(\d+)\}")
_B64 = re.compile(r"\{b64:([^{}]*)\}")


@dataclass(frozen=True)
class Example:
    id: str
    role: Role
    text: str
    attack_class: str | None = None  # None for benign examples
    system_prompt: str | None = None
    canary: str | None = None


def expand(text: str) -> str:
    text = _REPEAT.sub(lambda m: m.group(1) * int(m.group(2)), text)
    return _B64.sub(lambda m: base64.b64encode(m.group(1).encode()).decode(), text)


def load(name: str) -> list[Example]:
    raw: list[dict[str, Any]] = yaml.safe_load((DATA_DIR / name).read_text())
    return [
        Example(
            id=item["id"],
            role=Role(item["role"]),
            text=expand(item["text"]),
            attack_class=item.get("attack_class"),
            system_prompt=item.get("system_prompt"),
            canary=item.get("canary"),
        )
        for item in raw
    ]


def default_runtime(models: Models | None = None) -> Runtime:
    return build_runtime(
        DEFAULT_POLICIES_PATH.read_bytes(),
        (DEFAULT_RULES_DIR / "injection.yaml").read_bytes(),
        (DEFAULT_RULES_DIR / "secrets.yaml").read_bytes(),
        (DEFAULT_RULES_DIR / "tools.yaml").read_bytes(),
        models=models,
    )


def classifier_models() -> Models:
    config = ClassifierModelSettings()
    directory = model_directory(
        config.classifier_model,
        config.classifier_revision,
        config.classifier_onnx_subfolder,
        download=False,
    )
    scorer = OnnxScorer(
        directory,
        config.classifier_model,
        config.classifier_injection_label,
        config.classifier_threads,
    )
    return Models(classifier=scorer)


@dataclass
class Report:
    recall: dict[str, float] = field(default_factory=dict)
    attack_counts: dict[str, int] = field(default_factory=dict)
    false_positive_rate: float = 0.0
    benign_count: int = 0
    detectors: dict[str, dict[str, float]] = field(default_factory=dict)
    misses: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)


async def evaluate(runtime: Runtime, attacks: list[Example], benign: list[Example]) -> Report:
    block_at = runtime.policy.config.thresholds.block_at
    report = Report()
    detected: dict[str, list[bool]] = defaultdict(list)
    fired: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0})

    async def run(example: Example) -> tuple[bool, set[str]]:
        call = CallContext(system_prompt=example.system_prompt, canary=example.canary)
        verdict = (await runtime.pipeline.inspect(example.text, example.role, call, "eval")).verdict
        detectors = {
            f.detector for f in verdict.findings if runtime.policy.weighted_score(f) >= block_at
        }
        return verdict.action is not Action.ALLOW, detectors

    for example in attacks:
        hit, detectors = await run(example)
        detected[example.attack_class or "?"].append(hit)
        if not hit:
            report.misses.append(example.id)
        for name in detectors:
            fired[name]["tp"] += 1

    flagged = 0
    for example in benign:
        hit, detectors = await run(example)
        flagged += hit
        if hit:
            report.false_positives.append(example.id)
        for name in detectors:
            fired[name]["fp"] += 1

    for attack_class, hits in sorted(detected.items()):
        report.recall[attack_class] = sum(hits) / len(hits)
        report.attack_counts[attack_class] = len(hits)
    report.recall["all"] = sum(sum(h) for h in detected.values()) / max(1, len(attacks))
    report.attack_counts["all"] = len(attacks)
    report.benign_count = len(benign)
    report.false_positive_rate = flagged / max(1, len(benign))
    for name, counts in sorted(fired.items()):
        tp, fp = counts["tp"], counts["fp"]
        report.detectors[name] = {
            "fired_on_attacks": tp,
            "fired_on_benign": fp,
            "precision": tp / (tp + fp) if tp + fp else 0.0,
        }
    return report


def render(report: Report, show_misses: bool, layers: str) -> str:
    def mark(ok: bool) -> str:
        return "meets target" if ok else "below target"

    lines = [f"Detector evaluation ({layers})", ""]
    lines.append(f"{'attack class':<14}{'n':>5}{'recall':>9}")
    for attack_class, recall in report.recall.items():
        n = report.attack_counts[attack_class]
        lines.append(f"{attack_class:<14}{n:>5}{recall:>9.2f}")
    lines.append(
        f"recall target {RECALL_TARGET:.2f}: {mark(report.recall['all'] >= RECALL_TARGET)}"
    )
    lines.append("")
    fpr = report.false_positive_rate
    lines.append(
        f"false positive rate: {fpr:.3f} on {report.benign_count} benign examples "
        f"(target <= {FPR_TARGET:.2f}: {mark(fpr <= FPR_TARGET)})"
    )
    lines.append("")
    lines.append(f"{'detector':<22}{'on attacks':>11}{'on benign':>11}{'precision':>11}")
    for name, stats in report.detectors.items():
        lines.append(
            f"{name:<22}{stats['fired_on_attacks']:>11.0f}{stats['fired_on_benign']:>11.0f}"
            f"{stats['precision']:>11.2f}"
        )
    if show_misses:
        lines += ["", f"missed attacks: {', '.join(report.misses) or 'none'}"]
        lines += [f"false positives: {', '.join(report.false_positives) or 'none'}"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--show-misses", action="store_true", help="list missed and false ids")
    parser.add_argument("--classifier", action="store_true", help="add the layer 2 classifier")
    args = parser.parse_args(argv)
    runtime = default_runtime(classifier_models() if args.classifier else None)
    report = asyncio.run(evaluate(runtime, load("attacks.yaml"), load("benign.yaml")))
    if args.json:
        print(json.dumps(report.__dict__, indent=2))
    else:
        layers = "rules + classifier, layers 0-2" if args.classifier else "rules only, layers 0-1"
        print(render(report, args.show_misses, layers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
