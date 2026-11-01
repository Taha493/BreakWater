"""Secrets: provider key formats, private key blocks, JWTs, and high-entropy strings (A3)."""

from __future__ import annotations

import math
import re
from collections import Counter

from breakwater.core.context import ScanContext
from breakwater.core.normalize import Views
from breakwater.core.policy import SecretsSettings
from breakwater.core.rules import Rule
from breakwater.core.verdict import AttackClass, Finding, Role, Severity
from breakwater.detectors.base import Detector, view_note

ENTROPY_RULE_ID = "secret-high-entropy"
ENTROPY_SCORE = 0.6  # judge band: logged, not acted on, since hashes and ids look similar
_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]+")


def shannon_entropy(token: str) -> float:
    counts = Counter(token)
    return -sum(n / len(token) * math.log2(n / len(token)) for n in counts.values())


def _overlaps(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    return any(span[0] < end and start < span[1] for start, end in taken)


class LeakSecrets(Detector):
    name = "leak_secrets"
    layer = 1
    # Spec section 6 lists assistant and tool_result; user is included so that secrets
    # pasted into prompts can be blocked under the ``A3.secrets`` policy action.
    roles = frozenset({Role.ASSISTANT, Role.TOOL_RESULT, Role.USER})

    def __init__(self, rules: tuple[Rule, ...], settings: SecretsSettings) -> None:
        self._rules = rules
        self._settings = settings

    def hits(self, views: Views) -> list[Finding]:
        findings: list[Finding] = []
        taken: list[tuple[int, int]] = []
        for rule in self._rules:
            for view in views.all:
                for start, end in rule.regex.spans(view.text):
                    span = view.to_original(start, end)
                    if _overlaps(span, taken):
                        continue
                    taken.append(span)
                    findings.append(
                        Finding(
                            detector=self.name,
                            attack_class=AttackClass.A3,
                            severity=rule.spec.severity,
                            score=rule.spec.score,
                            reason=rule.spec.description + view_note(view),
                            rule_id=rule.id,
                            span=span,
                            layer=self.layer,
                        )
                    )
        text = views.original.text
        for match in _TOKEN.finditer(text):
            token = match.group()
            span = match.span()
            if len(token) < self._settings.min_entropy_length or _overlaps(span, taken):
                continue
            if not (any(c.isdigit() for c in token) and any(c.isalpha() for c in token)):
                continue
            if shannon_entropy(token) >= self._settings.entropy_threshold:
                taken.append(span)
                findings.append(
                    Finding(
                        detector=self.name,
                        attack_class=AttackClass.A3,
                        severity=Severity.MEDIUM,
                        score=ENTROPY_SCORE,
                        reason="High-entropy string that may be a credential",
                        rule_id=ENTROPY_RULE_ID,
                        span=span,
                        layer=self.layer,
                    )
                )
        return findings

    async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
        return self.hits(context.views)
