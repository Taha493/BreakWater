from __future__ import annotations

import pytest

from breakwater.core.context import CallContext, ScanContext
from breakwater.core.verdict import AttackClass, Finding, Role
from breakwater.detectors.hidden_content import HiddenContent

DETECTOR = HiddenContent()


async def scan(text: str, hidden_kind: str | None = None) -> list[Finding]:
    call = CallContext(hidden_kind=hidden_kind)
    return await DETECTOR.scan(text, Role.RETRIEVED, ScanContext.for_text(text, call))


@pytest.mark.parametrize(
    ("kind", "rule", "score"),
    [
        ("html_css_hidden", "hidden-html-css-hidden", 0.5),
        ("pdf_white_text", "hidden-pdf-white-text", 0.5),
        ("docx_hidden_text", "hidden-docx-hidden-text", 0.5),
        ("html_comment", "hidden-html-comment", 0.35),
    ],
)
async def test_hidden_source_reported(kind: str, rule: str, score: float) -> None:
    (finding,) = await scan("some text", kind)
    assert (finding.rule_id, finding.score) == (rule, score)
    assert finding.attack_class is AttackClass.A2
    assert finding.span == (0, 9)


async def test_scores_stay_below_default_block_threshold() -> None:
    findings = await scan("x​​​y <!-- c -->", "pdf_tiny_text")
    assert len(findings) == 3
    assert max(f.score for f in findings) < 0.6


async def test_invisible_characters_and_comments() -> None:
    assert [f.rule_id for f in await scan("a​b​c​d")] == ["hidden-invisible-chars"]
    assert [f.rule_id for f in await scan("ok <!-- note -->")] == ["hidden-comment"]


async def test_plain_text_and_ordinary_kinds_have_no_findings() -> None:
    assert await scan("Plain visible text.") == []
    assert await scan("a​b") == []  # a couple of stray characters is normal
    assert await scan("alt text", "alt_text") == []
    assert await scan("title", "metadata") == []


def test_roles() -> None:
    assert DETECTOR.roles == {Role.RETRIEVED, Role.TOOL_RESULT}
