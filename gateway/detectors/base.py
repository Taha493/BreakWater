"""The interface every detector implements (spec section 3)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from gateway.core.verdict import Finding, Role, ScanContext


class Detector(ABC):
    """A detector inspects one piece of text and returns findings.

    Detectors should be pure: text in, findings out, no hidden global state.
    Detectors in the same layer run concurrently.
    """

    name: ClassVar[str]
    layer: ClassVar[int]
    roles: ClassVar[frozenset[Role]]

    def applies_to(self, role: Role) -> bool:
        return role in self.roles

    @abstractmethod
    async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
        """Return findings whose spans point into ``text``."""
