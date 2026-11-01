"""The labeled evaluation set stays well-formed and the evaluation script runs.

Recall and false positive targets are reported by scripts/eval_detectors.py, not enforced
here (spec section 12 calls them initial targets).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import eval_detectors

ATTACKS = eval_detectors.load("attacks.yaml")
BENIGN = eval_detectors.load("benign.yaml")


def test_dataset_sizes() -> None:
    assert len(BENIGN) >= 100  # spec section 12: at least 100 benign examples
    assert len(ATTACKS) >= 60
    assert {a.attack_class for a in ATTACKS} == {"A1", "A2", "A3"}


def test_ids_are_unique() -> None:
    ids = [e.id for e in ATTACKS + BENIGN]
    assert len(ids) == len(set(ids))


def test_templates_are_expanded() -> None:
    assert not any("{repeat:" in e.text or "{b64:" in e.text for e in ATTACKS + BENIGN)


def test_script_runs(capsys: pytest.CaptureFixture[str]) -> None:
    assert eval_detectors.main(["--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert set(report["recall"]) == {"A1", "A2", "A3", "all"}
    assert report["benign_count"] == len(BENIGN)
    assert 0.0 <= report["false_positive_rate"] <= 1.0
