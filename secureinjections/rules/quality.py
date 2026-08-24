"""Community rule quality gates, mutation metrics, and duplicate warnings."""

from __future__ import annotations

import math
import random
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..corpus import CorpusCase, load_corpus, mutate_cases, mutate_text
from ..detectors.patterns import text_variants
from ..rule_engine import RuleEngine
from .loader import load_threat_rules, threat_rule_to_legacy
from .models import ThreatRule
from .validator import lint_threat_rule, test_threat_rule


@dataclass(frozen=True, slots=True)
class QualityGateReport:
    rule_count: int
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    max_rule_latency_ms: float

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "rule_count": self.rule_count,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "max_rule_latency_ms": self.max_rule_latency_ms,
        }


def quality_gate(path: Path, *, max_rule_latency_ms: float = 25.0) -> QualityGateReport:
    rules = load_threat_rules((path,), quality_gate=True)
    errors = [failure for rule in rules for failure in test_threat_rule(rule)]
    warnings = [warning for rule in rules for warning in lint_threat_rule(rule)]
    errors.extend(warnings)
    pathological = "a" * 20_000 + "!" + "../" * 2_000
    maximum = 0.0
    for rule in rules:
        engine = RuleEngine((threat_rule_to_legacy(rule),))
        started = time.perf_counter_ns()
        engine.match((pathological,))
        elapsed = (time.perf_counter_ns() - started) / 1_000_000
        maximum = max(maximum, elapsed)
        if elapsed > max_rule_latency_ms:
            errors.append(
                f"{rule.id}: pathological input latency {elapsed:.3f} ms exceeds "
                f"{max_rule_latency_ms:.3f} ms"
            )
        if rule.status == "published" and (
            not rule.references
            or any(not reference.startswith("https://") for reference in rule.references)
        ):
            errors.append(f"{rule.id}: published references must use public HTTPS URLs")
        if not rule.taxonomy:
            errors.append(f"{rule.id}: taxonomy metadata is required")
        mutation_hits = 0
        mutation_count = 0
        for example in rule.attack_patterns:
            for mutation in ("random_casing", "zero_width", "base64", "markdown", "json"):
                changed = mutate_text(
                    example,
                    mutation,
                    random.Random(f"quality:{rule.id}:{mutation}"),
                )
                mutation_count += 1
                mutation_hits += bool(engine.match(text_variants(changed)))
        if mutation_count and mutation_hits / mutation_count < 0.6:
            errors.append(
                f"{rule.id}: embedded mutation detection rate "
                f"{mutation_hits / mutation_count:.3f} is below 0.600"
            )
    duplicates = find_duplicates(rules)
    warnings.extend(duplicates)
    return QualityGateReport(len(rules), tuple(errors), tuple(warnings), round(maximum, 6))


def _features(rule: ThreatRule) -> Counter[str]:
    text = " ".join((rule.name, rule.description, *rule.semantic_examples)).casefold()
    tokens = re.findall(r"[\w-]{3,}", text)
    return Counter(tokens + [text[index : index + 3] for index in range(max(0, len(text) - 2))])


def _cosine(left: Counter[str], right: Counter[str]) -> float:
    common = left.keys() & right.keys()
    dot = sum(left[key] * right[key] for key in common)
    norm_left = math.sqrt(sum(value * value for value in left.values()))
    norm_right = math.sqrt(sum(value * value for value in right.values()))
    return dot / (norm_left * norm_right) if norm_left and norm_right else 0.0


def find_duplicates(rules: tuple[ThreatRule, ...], *, threshold: float = 0.82) -> tuple[str, ...]:
    """Return maintenance warnings only; this never mutates or merges rules."""
    features = {rule.id: _features(rule) for rule in rules}
    warnings: list[str] = []
    for index, left in enumerate(rules):
        for right in rules[index + 1 :]:
            if left.category != right.category:
                continue
            similarity = _cosine(features[left.id], features[right.id])
            if similarity >= threshold:
                warnings.append(
                    f"potential duplicate {left.id} / {right.id} "
                    f"(local similarity {similarity:.3f})"
                )
    return tuple(warnings)


def rule_metrics(
    rules: tuple[ThreatRule, ...], corpus_path: Path, *, seed: int = 42
) -> dict[str, Any]:
    cases = load_corpus(corpus_path)
    malicious = tuple(
        case for case in cases if case.label == "malicious" and case.parent_case_id is None
    )
    benign = tuple(case for case in cases if case.label == "benign" and case.parent_case_id is None)
    mutations = mutate_cases(malicious, seed=seed)
    engine = RuleEngine(tuple(threat_rule_to_legacy(rule) for rule in rules))

    expected: dict[str, list[CorpusCase]] = defaultdict(list)
    for case in malicious:
        for rule_id in case.expected_rule_ids:
            expected[rule_id].append(case)
    mutation_expected: dict[str, list[CorpusCase]] = defaultdict(list)
    for case in mutations:
        for rule_id in case.expected_rule_ids:
            mutation_expected[rule_id].append(case)

    def detected(rule_id: str, selected: list[CorpusCase]) -> int:
        return sum(
            rule_id in {match.rule_id for match in engine.match(text_variants(case.text))}
            for case in selected
        )

    benign_matches: Counter[str] = Counter()
    for case in benign:
        benign_matches.update(match.rule_id for match in engine.match(text_variants(case.text)))
    report: dict[str, Any] = {}
    for rule in rules:
        base_cases = expected[rule.id]
        mutated_cases = mutation_expected[rule.id]
        base_hits = detected(rule.id, base_cases)
        mutation_hits = detected(rule.id, mutated_cases)
        report[rule.id] = {
            "base_detection_rate": round(base_hits / len(base_cases), 6) if base_cases else None,
            "mutation_detection_rate": (
                round(mutation_hits / len(mutated_cases), 6) if mutated_cases else None
            ),
            "false_positive_rate": round(benign_matches[rule.id] / len(benign), 6),
            "coverage_count": len(base_cases),
            "base_detected": base_hits,
            "mutations_detected": mutation_hits,
            "mutation_count": len(mutated_cases),
        }
    return report
