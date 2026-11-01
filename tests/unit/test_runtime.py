"""Hot reload of policies and rules."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from breakwater.config import DEFAULT_RULES_DIR
from breakwater.core.runtime import ConfigStore
from tests.conftest import default_runtime


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    target = tmp_path / "rules"
    shutil.copytree(DEFAULT_RULES_DIR, target)
    return target


def touch_edit(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    assert old in text
    path.write_text(text.replace(old, new))
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))


def store(rules_dir: Path, clock: Clock) -> ConfigStore:
    return ConfigStore(rules_dir / "policies.yaml", rules_dir, check_interval=2.0, clock=clock)


def test_version_matches_build_runtime(rules_dir: Path) -> None:
    assert store(rules_dir, Clock()).current().version == default_runtime().version


def test_reloads_after_interval(rules_dir: Path) -> None:
    clock = Clock()
    s = store(rules_dir, clock)
    first = s.current()
    touch_edit(rules_dir / "policies.yaml", "block_at: 0.70", "block_at: 0.80")

    clock.now = 1.0
    assert s.current() is first  # not checked yet

    clock.now = 2.5
    reloaded = s.current()
    assert reloaded is not first
    assert reloaded.version != first.version
    assert reloaded.policy.config.thresholds.block_at == 0.80


def test_rule_file_changes_reload(rules_dir: Path) -> None:
    clock = Clock()
    s = store(rules_dir, clock)
    touch_edit(rules_dir / "injection.yaml", "score: 0.9\n", "score: 0.95\n")
    clock.now = 3
    assert s.current().version != default_runtime().version


def test_invalid_change_keeps_last_good(rules_dir: Path, caplog: pytest.LogCaptureFixture) -> None:
    clock = Clock()
    s = store(rules_dir, clock)
    good = s.current()
    touch_edit(rules_dir / "policies.yaml", "block_at: 0.70", "block_at: banana")
    clock.now = 3
    assert s.current() is good
    assert "reload failed" in caplog.text

    # Fixing the file is picked up on the next check.
    touch_edit(rules_dir / "policies.yaml", "block_at: banana", "block_at: 0.75")
    clock.now = 6
    assert s.current().policy.config.thresholds.block_at == 0.75


def test_invalid_files_fail_at_startup(rules_dir: Path) -> None:
    touch_edit(rules_dir / "secrets.yaml", "rules:", "rulez:")
    with pytest.raises(ValueError):
        store(rules_dir, Clock())


def test_pin_stops_reloading(rules_dir: Path) -> None:
    clock = Clock()
    s = store(rules_dir, clock)
    pinned = default_runtime()
    s.pin(pinned)
    touch_edit(rules_dir / "policies.yaml", "block_at: 0.70", "block_at: 0.80")
    clock.now = 10
    assert s.current() is pinned
