from __future__ import annotations

from typing import Protocol

from .contracts import ReasonerOutcome, SecurityCase


class ReasoningProvider(Protocol):
    def assess(self, case: SecurityCase) -> ReasonerOutcome: ...
