"""Layer 2: a text classifier's injection score (A1, A2). See core/classifier.py for the
model; this detector picks what to score and turns the highest window score into a
finding."""

from __future__ import annotations

import asyncio

from breakwater.core.classifier import InjectionScorer
from breakwater.core.context import ScanContext
from breakwater.core.normalize import View
from breakwater.core.policy import ClassifierSettings
from breakwater.core.verdict import AttackClass, Finding, Role, Severity
from breakwater.detectors.base import Detector, view_note


def _severity(score: float) -> Severity:
    if score >= 0.9:
        return Severity.HIGH
    if score >= 0.7:
        return Severity.MEDIUM
    return Severity.LOW


class InjectionClassifier(Detector):
    name = "injection_classifier"
    layer = 2
    roles = frozenset({Role.USER, Role.RETRIEVED, Role.TOOL_RESULT})
    failure_mode = "classifier_error"

    def __init__(self, scorer: InjectionScorer, settings: ClassifierSettings) -> None:
        self._scorer = scorer
        self._settings = settings

    @staticmethod
    def _views(context: ScanContext) -> list[View]:
        # The normalized text stands in for the original (they differ only in obfuscation);
        # comments and decoded segments are scored on their own.
        views = list(context.views.all)
        if len(views) > 1 and views[1].kind == "normalized":
            views = views[1:]
        return [v for v in views if v.text.strip()]

    async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
        views = self._views(context)
        if not views:
            return []
        scores = await asyncio.to_thread(
            self._scorer.score, [v.text for v in views], self._settings.max_windows
        )
        best = max(scores, key=lambda w: w.score, default=None)
        if best is None or best.score < self._settings.min_score:
            return []
        view = views[best.text_index]
        return [
            Finding(
                detector=self.name,
                attack_class=AttackClass.A1 if role is Role.USER else AttackClass.A2,
                severity=_severity(best.score),
                score=round(best.score, 4),
                reason=f"Classifier scored the text {best.score:.2f} for prompt injection"
                + view_note(view),
                rule_id="classifier-injection",
                span=view.to_original(best.start, best.end),
                layer=self.layer,
            )
        ]
