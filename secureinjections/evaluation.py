"""Reproducible corpus evaluation with stratified quality and latency metrics."""

from __future__ import annotations

import statistics
import time
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .corpus import CorpusCase, CorpusError, load_corpus
from .models import Decision, ScanContext
from .scanner import Scanner


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def _rates(counts: Counter[str]) -> dict[str, float | int]:
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "false_positive_rate": round(fpr, 6),
        "false_negative_rate": round(fnr, 6),
        "f1": round(f1, 6),
        "case_count": tp + fp + tn + fn,
    }


def evaluate_cases(
    scanner: Scanner,
    cases: Iterable[CorpusCase],
    *,
    deep_scan: bool = False,
    reveal_failures: bool = True,
) -> dict[str, Any]:
    case_list = tuple(cases)
    if not case_list:
        raise CorpusError("corpus is empty")
    overall: Counter[str] = Counter()
    confusion: Counter[tuple[str, str]] = Counter()
    category_counts: dict[str, Counter[str]] = defaultdict(Counter)
    strata: dict[str, dict[str, Counter[str]]] = {
        name: defaultdict(Counter) for name in ("language", "difficulty", "source_type")
    }
    latencies: list[float] = []
    failures: list[dict[str, Any]] = []
    started_total = time.perf_counter_ns()
    for case in case_list:
        context = ScanContext(
            source=case.source_type,
            trust_level="untrusted",
            language=case.language,
        )
        result = scanner.scan(case.text, deep_scan=deep_scan, context=context)
        latencies.append(result.scan_duration_ms)
        expected_positive = (
            case.label == "malicious" or case.expected_decision is not Decision.ALLOW
        )
        actual_positive = result.decision is not Decision.ALLOW
        outcome = (
            "tp"
            if expected_positive and actual_positive
            else "fn"
            if expected_positive
            else "fp"
            if actual_positive
            else "tn"
        )
        overall[outcome] += 1
        confusion[(case.expected_decision.value, result.decision.value)] += 1
        for field, value in (
            ("language", case.language),
            ("difficulty", case.difficulty),
            ("source_type", case.source_type),
        ):
            strata[field][value][outcome] += 1
        expected_categories = set(case.categories)
        actual_categories = set(result.detected_categories)
        for category in expected_categories | actual_categories:
            counts = category_counts[category]
            if category in expected_categories and category in actual_categories:
                counts["tp"] += 1
            elif category in actual_categories:
                counts["fp"] += 1
            elif category in expected_categories:
                counts["fn"] += 1
            else:
                counts["tn"] += 1
        matched_ids = {match.rule_id for match in result.matched_rules}
        semantic_ids = set(
            result.semantic_analysis.get("matched_rule_ids", []) if result.semantic_analysis else []
        )
        missing_ids = sorted(set(case.expected_rule_ids) - matched_ids - semantic_ids)
        if result.decision is not case.expected_decision or missing_ids:
            failure: dict[str, Any] = {
                "expected": case.expected_decision.value,
                "actual": result.decision.value,
                "missing_rule_ids": missing_ids,
            }
            if reveal_failures:
                failure["id"] = case.id
            failures.append(failure)
    elapsed = (time.perf_counter_ns() - started_total) / 1_000_000_000
    decisions = tuple(decision.value for decision in Decision)
    for counts in category_counts.values():
        counts["tn"] = len(case_list) - counts["tp"] - counts["fp"] - counts["fn"]
    metrics = _rates(overall)
    return {
        "total_cases": len(case_list),
        "true_positives": overall["tp"],
        "false_positives": overall["fp"],
        "true_negatives": overall["tn"],
        "false_negatives": overall["fn"],
        **metrics,
        "decision_confusion_matrix": {
            expected: {actual: confusion[(expected, actual)] for actual in decisions}
            for expected in decisions
        },
        "per_category": {name: _rates(counts) for name, counts in sorted(category_counts.items())},
        "per_language": {
            name: _rates(counts) for name, counts in sorted(strata["language"].items())
        },
        "per_difficulty": {
            name: _rates(counts) for name, counts in sorted(strata["difficulty"].items())
        },
        "per_source_type": {
            name: _rates(counts) for name, counts in sorted(strata["source_type"].items())
        },
        "latency_ms": {
            "p50": round(statistics.median(latencies), 6),
            "median": round(statistics.median(latencies), 6),
            "p95": round(_percentile(latencies, 0.95), 6),
            "p99": round(_percentile(latencies, 0.99), 6),
            "throughput_per_second": round(len(case_list) / elapsed, 3),
        },
        "holdout_case_ids_redacted": not reveal_failures,
        "failures": failures,
    }


def evaluate_corpus(
    scanner: Scanner,
    corpus_path: Path,
    *,
    include_semantic: bool = False,
    split: str | None = None,
    include_generated: bool = False,
) -> dict[str, Any]:
    cases = load_corpus(corpus_path, split=split)
    if corpus_path.is_dir() and not include_generated:
        cases = tuple(case for case in cases if case.parent_case_id is None)
    reveal = split != "holdout"
    report = {
        "deterministic_only": evaluate_cases(
            scanner, cases, deep_scan=False, reveal_failures=reveal
        )
    }
    if include_semantic:
        report["deterministic_plus_semantic"] = evaluate_cases(
            scanner, cases, deep_scan=True, reveal_failures=reveal
        )
    return report


def markdown_report(report: dict[str, Any]) -> str:
    lines = ["# SecureInjections evaluation", ""]
    for mode, values in report.items():
        lines.extend(
            [
                f"## {mode.replace('_', ' ').title()}",
                "",
                "| Metric | Value |",
                "| --- | ---: |",
            ]
        )
        for key in (
            "total_cases",
            "precision",
            "recall",
            "f1",
            "false_positive_rate",
            "false_negative_rate",
        ):
            lines.append(f"| {key} | {values[key]} |")
        lines.append("")
    return "\n".join(lines)
