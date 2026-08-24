"""Secret detector interface and rule-backed local implementation."""

from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Iterable

from ..models import Rule, RuleMatch
from ..rule_engine import RuleEngine


class SecretDetector(ABC):
    @abstractmethod
    def detect(self, variants: Iterable[str]) -> tuple[RuleMatch, ...]:
        """Return metadata-only matches. Implementations must not expose secret values."""


class RuleBasedSecretDetector(SecretDetector):
    def __init__(self, rules: Iterable[Rule]):
        secret_rules = tuple(rule for rule in rules if rule.category == "secret_leakage")
        entropy_rules = tuple(rule for rule in secret_rules if "entropy-check" in rule.tags)
        self._engine = RuleEngine(rule for rule in secret_rules if rule not in entropy_rules)
        self._entropy_rules = tuple(
            (rule, tuple(re.compile(pattern) for pattern in rule.patterns))
            for rule in entropy_rules
        )

    @staticmethod
    def _entropy(value: str) -> float:
        counts = Counter(value)
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def detect(self, variants: Iterable[str]) -> tuple[RuleMatch, ...]:
        texts = tuple(variants)
        matches = list(self._engine.match(texts))
        for rule, patterns in self._entropy_rules:
            found = False
            for text in texts:
                for pattern in patterns:
                    for candidate in pattern.findall(text):
                        classes = sum(
                            (
                                any(char.islower() for char in candidate),
                                any(char.isupper() for char in candidate),
                                any(char.isdigit() for char in candidate),
                                any(not char.isalnum() for char in candidate),
                            )
                        )
                        if classes >= 3 and self._entropy(candidate) >= 4.0:
                            found = True
                            break
                    if found:
                        break
                if found:
                    break
            if found:
                matches.append(
                    RuleMatch(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        description=rule.description,
                        confidence=rule.confidence,
                        taxonomy=rule.taxonomy,
                        legacy_rule_id=rule.legacy_id,
                    )
                )
        return tuple(matches)
