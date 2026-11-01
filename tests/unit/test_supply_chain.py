"""Supply chain (spec section 11): images pinned by digest, containers run as non-root,
dependencies pinned by lock files with exact dashboard versions."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILES = [ROOT / "Dockerfile", ROOT / "dashboard" / "Dockerfile"]
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\b")


def test_base_images_are_pinned_by_digest() -> None:
    for dockerfile in DOCKERFILES:
        text = dockerfile.read_text()
        refs = re.findall(r"^FROM\s+(\S+)", text, re.M) + re.findall(r"COPY --from=(\S+)", text)
        external = [r for r in refs if "/" in r or ":" in r]
        assert external, dockerfile
        for ref in external:
            assert DIGEST.search(ref), f"{dockerfile.name}: {ref} is not pinned by digest"


def test_compose_images_are_pinned_by_digest() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    images = [s["image"] for s in compose["services"].values() if "image" in s]
    assert images
    assert all(DIGEST.search(image) for image in images), images


def test_containers_run_as_non_root() -> None:
    gateway = (ROOT / "Dockerfile").read_text()
    users = re.findall(r"^USER\s+(\S+)", gateway, re.M)
    assert users and users[-1] not in ("root", "0")
    dashboard = (ROOT / "dashboard" / "Dockerfile").read_text()
    final_stage = dashboard.rsplit("FROM ", 1)[1]
    assert final_stage.startswith("nginxinc/nginx-unprivileged:")  # runs as uid 101


def test_non_root_user_can_write_the_default_report_directory() -> None:
    # `gateway redteam run` writes to ./reports by default; /app itself belongs to root.
    gateway = (ROOT / "Dockerfile").read_text()
    assert re.search(r"^WORKDIR /app$", gateway, re.M)
    assert re.search(r"chown gateway [^\n]*/app/reports", gateway)


def test_dependencies_are_locked() -> None:
    assert (ROOT / "uv.lock").exists()
    package = json.loads((ROOT / "dashboard" / "package.json").read_text())
    assert (ROOT / "dashboard" / "package-lock.json").exists()
    for section in ("dependencies", "devDependencies"):
        for name, version in package[section].items():
            assert re.fullmatch(r"\d+\.\d+\.\d+", version), f"{name} {version} is not exact"
