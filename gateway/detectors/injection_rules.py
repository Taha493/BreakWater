"""Instruction-override, role-reassignment, prompt-reveal, and fake-delimiter rules (A1, A2)."""

from __future__ import annotations

from gateway.core.context import ScanContext
from gateway.core.rules import Rule
from gateway.core.verdict import AttackClass, Finding, Role
from gateway.detectors.base import Detector, view_note

MAX_HITS_PER_RULE = 10


class InjectionRules(Detector):
    name = "injection_rules"
    layer = 1
    roles = frozenset({Role.USER, Role.RETRIEVED, Role.TOOL_RESULT})

    def __init__(self, rules: tuple[Rule, ...]) -> None:
        self._rules = rules

    async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
        # The same phrasing is direct injection from a user and indirect from anything else.
        attack_class = AttackClass.A1 if role is Role.USER else AttackClass.A2
        findings: dict[tuple[str, tuple[int, int]], Finding] = {}
        for rule in self._rules:
            hits = 0
            for view in context.views.all:
                for start, end in rule.regex.spans(view.text):
                    span = view.to_original(start, end)
                    if (rule.id, span) in findings:
                        continue
                    findings[(rule.id, span)] = Finding(
                        detector=self.name,
                        attack_class=attack_class,
                        severity=rule.spec.severity,
                        score=rule.spec.score,
                        reason=rule.spec.description + view_note(view),
                        rule_id=rule.id,
                        span=span,
                        layer=self.layer,
                    )
                    hits += 1
                    if hits >= MAX_HITS_PER_RULE:
                        break
                if hits >= MAX_HITS_PER_RULE:
                    break
        return list(findings.values())
