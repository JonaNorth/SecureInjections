"""Evaluation and benchmark harness for optional local classifiers."""

from __future__ import annotations

import statistics
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path

from .classifier import ATTACK_LABELS, IntentClassifier, IntentLabel
from .classifier_data import ClassifierCase
from .models import Decision, ScanContext
from .scanner import Scanner


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * percentile))]


def _binary_metrics(actual: list[bool], predicted: list[bool]) -> dict[str, float | int]:
    tp = sum(a and p for a, p in zip(actual, predicted, strict=True))
    fp = sum(not a and p for a, p in zip(actual, predicted, strict=True))
    tn = sum(not a and not p for a, p in zip(actual, predicted, strict=True))
    fn = sum(a and not p for a, p in zip(actual, predicted, strict=True))
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "cases": len(actual),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "recall": recall,
        "benign_fpr": fpr,
        "precision": precision,
        "f1": f1,
    }


def evaluate_classifier(
    classifier: IntentClassifier, cases: Iterable[ClassifierCase]
) -> dict[str, object]:
    materialized = tuple(cases)
    actual_binary: list[bool] = []
    predicted_binary: list[bool] = []
    latencies: list[float] = []
    confusion: dict[str, Counter[str]] = defaultdict(Counter)
    records: list[tuple[ClassifierCase, bool, bool]] = []
    for case in materialized:
        started = time.perf_counter_ns()
        result = classifier.classify(case.text, ScanContext(language=case.language))
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        actual = case.label in ATTACK_LABELS
        predicted = result.malicious_probability > classifier.thresholds.allow_max
        actual_binary.append(actual)
        predicted_binary.append(predicted)
        confusion[case.label.value][result.predicted_family.value] += 1
        records.append((case, actual, predicted))

    def dimensions(field: str) -> dict[str, object]:
        values: dict[str, object] = {}
        for key in sorted({getattr(case, field) for case in materialized}):
            selected = [
                (actual, predicted)
                for case, actual, predicted in records
                if getattr(case, field) == key
            ]
            values[key] = _binary_metrics(
                [item[0] for item in selected], [item[1] for item in selected]
            )
        return values

    family_f1 = []
    for label in IntentLabel:
        tp = confusion[label.value][label.value]
        total_actual = sum(confusion[label.value].values())
        total_predicted = sum(row[label.value] for row in confusion.values())
        precision = tp / total_predicted if total_predicted else 0.0
        recall = tp / total_actual if total_actual else 0.0
        family_f1.append(
            2 * precision * recall / (precision + recall) if precision + recall else 0.0
        )
    return {
        "overall": _binary_metrics(actual_binary, predicted_binary),
        "macro_family_f1": sum(family_f1) / len(family_f1),
        "per_language": dimensions("language"),
        "per_family": dimensions("attack_family"),
        "family_confusion_matrix": {
            actual: dict(sorted(row.items())) for actual, row in sorted(confusion.items())
        },
        "inference_ms": {
            "p50": statistics.median(latencies) if latencies else 0.0,
            "p95": _percentile(latencies, 0.95),
            "p99": _percentile(latencies, 0.99),
        },
    }


def evaluate_combined(
    deterministic_scanner: Scanner,
    combined_scanner: Scanner,
    cases: Iterable[ClassifierCase],
) -> dict[str, object]:
    materialized = tuple(cases)
    actual: list[bool] = []
    deterministic_predictions: list[bool] = []
    combined_predictions: list[bool] = []
    deterministic_times: list[float] = []
    classifier_times: list[float] = []
    combined_times: list[float] = []
    contribution: Counter[str] = Counter()
    for case in materialized:
        context = ScanContext(language=case.language)
        deterministic = deterministic_scanner.scan(case.text, context=context)
        combined = combined_scanner.scan(case.text, context=context)
        is_malicious = case.label in ATTACK_LABELS
        det_positive = deterministic.decision is not Decision.ALLOW
        combined_positive = combined.decision is not Decision.ALLOW
        classifier_ran = combined.classifier_analysis is not None
        actual.append(is_malicious)
        deterministic_predictions.append(det_positive)
        combined_predictions.append(combined_positive)
        deterministic_times.append(deterministic.deterministic_duration_ms or 0.0)
        combined_times.append(combined.scan_duration_ms)
        if combined.classifier_duration_ms is not None:
            classifier_times.append(combined.classifier_duration_ms)
        if is_malicious:
            if det_positive and combined_positive:
                contribution["caught_by_both"] += int(classifier_ran)
                contribution["deterministic_only_caught"] += int(not classifier_ran)
            elif not det_positive and combined_positive:
                contribution["classifier_recovered"] += 1
            elif not det_positive and not combined_positive:
                contribution["missed_by_both"] += 1
        elif det_positive:
            contribution["deterministic_benign_false_positive"] += 1
        elif combined_positive:
            contribution["classifier_benign_false_positive"] += 1
    return {
        "deterministic": _binary_metrics(actual, deterministic_predictions),
        "combined": _binary_metrics(actual, combined_predictions),
        "contribution": dict(sorted(contribution.items())),
        "performance_ms": {
            "deterministic_p95": _percentile(deterministic_times, 0.95),
            "classifier_p95": _percentile(classifier_times, 0.95),
            "combined_p95": _percentile(combined_times, 0.95),
        },
    }


def model_size_bytes(path: Path) -> int:
    return sum(
        item.stat().st_size for item in path.rglob("*") if item.is_file() and not item.is_symlink()
    )


def peak_rss_bytes() -> int:
    try:
        import resource

        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except (ImportError, ValueError):  # pragma: no cover - platform dependent
        return 0
    return value if sys.platform == "darwin" else value * 1024
