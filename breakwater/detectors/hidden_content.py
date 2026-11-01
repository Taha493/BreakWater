"""Hidden content in retrieved text (A2). The presence of hidden text is itself a finding
(spec section 7); what the hidden text says is judged by the other detectors.

Scores stay below the default block threshold, so hidden text alone marks a document
suspicious. Lower-trust sources use lower document thresholds (``trust_levels``), and hidden
text that carries an injection is caught at full strength by ``injection_rules``.
"""

from __future__ import annotations

from breakwater.core.context import ScanContext
from breakwater.core.verdict import AttackClass, Finding, Role, Severity
from breakwater.detectors.base import Detector

MIN_INVISIBLE_CHARS = 3
HIDDEN_SOURCE_SCORE = 0.5
INVISIBLE_CHARS_SCORE = 0.4
COMMENT_SCORE = 0.35

# Hidden-text kinds from rag/extract.py, with a reason and score.
_SOURCE_REASONS = {
    "html_css_hidden": ("Text hidden with CSS", HIDDEN_SOURCE_SCORE),
    "html_hidden_attribute": ("Text in an element with the hidden attribute", HIDDEN_SOURCE_SCORE),
    "pdf_tiny_text": ("Text too small to read in a PDF", HIDDEN_SOURCE_SCORE),
    "pdf_white_text": ("White text in a PDF", HIDDEN_SOURCE_SCORE),
    "pdf_offpage_text": ("Text placed outside the PDF page", HIDDEN_SOURCE_SCORE),
    "docx_hidden_text": ("Text marked hidden in a Word document", HIDDEN_SOURCE_SCORE),
    "docx_white_text": ("White text in a Word document", HIDDEN_SOURCE_SCORE),
    "docx_tiny_text": ("Text too small to read in a Word document", HIDDEN_SOURCE_SCORE),
    "html_comment": ("HTML comment", COMMENT_SCORE),
    "markdown_comment": ("Markdown comment", COMMENT_SCORE),
}


class HiddenContent(Detector):
    name = "hidden_content"
    layer = 1
    roles = frozenset({Role.RETRIEVED, Role.TOOL_RESULT})

    async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        kind = context.call.hidden_kind
        if kind in _SOURCE_REASONS:
            reason, score = _SOURCE_REASONS[kind]
            findings.append(
                self._finding(f"hidden-{kind.replace('_', '-')}", reason, score, (0, len(text)))
            )
        views = context.views
        if views.removed_chars >= MIN_INVISIBLE_CHARS:
            findings.append(
                self._finding(
                    "hidden-invisible-chars",
                    f"{views.removed_chars} invisible or control characters",
                    INVISIBLE_CHARS_SCORE,
                    None,
                )
            )
        if views.comment_count:
            findings.append(
                self._finding("hidden-comment", "HTML or markdown comment", COMMENT_SCORE, None)
            )
        return findings

    def _finding(
        self, rule_id: str, reason: str, score: float, span: tuple[int, int] | None
    ) -> Finding:
        return Finding(
            detector=self.name,
            attack_class=AttackClass.A2,
            severity=Severity.MEDIUM if score >= 0.5 else Severity.LOW,
            score=score,
            reason=reason,
            rule_id=rule_id,
            span=span,
            layer=self.layer,
        )
