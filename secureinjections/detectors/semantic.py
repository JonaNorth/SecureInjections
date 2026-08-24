"""Optional, offline semantic detector contract."""

from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SemanticMatch:
    rule_id: str
    category: str
    similarity: float


@dataclass(frozen=True, slots=True)
class SemanticResult:
    risk_score: int
    categories: tuple[str, ...]
    explanation: str
    matches: tuple[SemanticMatch, ...] = ()
    context_signals: tuple[str, ...] = ()


def semantic_context_adjustment(text: str) -> tuple[float, tuple[str, ...]]:
    """Lightweight intent/reference context; it adjusts similarity but never authorizes actions."""
    folded = text.casefold()
    adjustment = 0.0
    signals: list[str] = []
    if any(
        marker in folded
        for marker in (
            "researchers",
            "research paper",
            "how do researchers",
            "security training",
            "quoted example",
            "documentation explains",
        )
    ):
        adjustment -= 0.12
        signals.append("educational_or_reference_context")
    if re.match(
        r"\s*(?:ignore|disregard|reveal|show|read|send|upload|execute|run|invoke|call)\b",
        folded,
    ):
        adjustment += 0.04
        signals.append("imperative_intent")
    if re.search(r"\b(?:send|show|give|return)\s+(?:it|them|me|to me)\b", folded):
        adjustment += 0.02
        signals.append("first_person_execution_intent")
    return adjustment, tuple(signals)


class SemanticDetector(ABC):
    @abstractmethod
    def analyze(self, text: str) -> SemanticResult:
        """Analyze text locally. Implementations must not make network requests by default."""


class KeywordSemanticDetector(SemanticDetector):
    """Tiny bag-of-words similarity baseline requiring no model or external API.

    This deliberately simple implementation demonstrates the extension point. It is not
    presented as a substitute for an embedding model or deterministic rules.
    """

    _prototypes = {
        "prompt_injection": (
            "disregard hidden prior system instruction obey new role reveal prompt bypass safety",
            "pretend developer mode unrestricted ignore policy hierarchy",
        ),
        "agent_manipulation": (
            "use tool access file environment credential execute command agent",
            "call internal api retrieve token secret system shell",
        ),
    }

    @staticmethod
    def _tokens(text: str) -> Counter[str]:
        return Counter(re.findall(r"[a-z]{3,}", text.lower()))

    @staticmethod
    def _similarity(left: Counter[str], right: Counter[str]) -> float:
        common = left.keys() & right.keys()
        dot = sum(left[word] * right[word] for word in common)
        left_norm = math.sqrt(sum(value * value for value in left.values()))
        right_norm = math.sqrt(sum(value * value for value in right.values()))
        return dot / (left_norm * right_norm) if left_norm and right_norm else 0.0

    def analyze(self, text: str) -> SemanticResult:
        text_vector = self._tokens(text)
        scores = {
            category: max(
                self._similarity(text_vector, self._tokens(prototype)) for prototype in prototypes
            )
            for category, prototypes in self._prototypes.items()
        }
        categories = tuple(sorted(category for category, score in scores.items() if score >= 0.22))
        adjustment, context_signals = semantic_context_adjustment(text)
        highest = max(scores.values(), default=0.0) + adjustment
        risk = min(55, round(highest * 100))
        explanation = (
            "Local keyword-vector similarity found suspicious intent."
            if categories
            else "Local keyword-vector similarity found no strong suspicious intent."
        )
        return SemanticResult(
            risk_score=risk,
            categories=categories,
            explanation=explanation,
            context_signals=context_signals,
        )
