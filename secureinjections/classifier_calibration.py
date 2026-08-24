"""Validation-only calibration for local classifier logits and decision thresholds."""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .classifier import ClassifierThresholds


def _logsumexp(values: Sequence[float]) -> float:
    maximum = max(values)
    return maximum + math.log(sum(math.exp(value - maximum) for value in values))


def negative_log_likelihood(
    logits: Sequence[Sequence[float]], labels: Sequence[int], temperature: float
) -> float:
    if not logits or len(logits) != len(labels) or temperature <= 0:
        raise ValueError("non-empty aligned logits/labels and positive temperature are required")
    total = 0.0
    for row, label in zip(logits, labels, strict=True):
        if not row or not 0 <= label < len(row):
            raise ValueError("invalid logits row or label index")
        scaled = [float(value) / temperature for value in row]
        total += _logsumexp(scaled) - scaled[label]
    return total / len(logits)


def fit_temperature(
    logits: Sequence[Sequence[float]], labels: Sequence[int], *, iterations: int = 80
) -> float:
    """Fit one temperature on validation logits with deterministic golden-section search."""
    if iterations < 1:
        raise ValueError("iterations must be positive")
    left, right = math.log(0.05), math.log(10.0)
    ratio = (math.sqrt(5) - 1) / 2
    c = right - ratio * (right - left)
    d = left + ratio * (right - left)
    for _ in range(iterations):
        c_loss = negative_log_likelihood(logits, labels, math.exp(c))
        d_loss = negative_log_likelihood(logits, labels, math.exp(d))
        if c_loss < d_loss:
            right, d = d, c
            c = right - ratio * (right - left)
        else:
            left, c = c, d
            d = left + ratio * (right - left)
    return round(math.exp((left + right) / 2), 8)


@dataclass(frozen=True, slots=True)
class ThresholdCalibration:
    thresholds: ClassifierThresholds
    recall: float
    false_positive_rate: float
    precision: float
    f1: float
    validation_cases: int

    def to_dict(self) -> dict[str, object]:
        return {
            "allow_max": self.thresholds.allow_max,
            "block_min": self.thresholds.block_min,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "precision": self.precision,
            "f1": self.f1,
            "validation_cases": self.validation_cases,
        }


def _metrics(
    probabilities: Sequence[float], malicious: Sequence[bool], threshold: float
) -> tuple[float, float, float, float]:
    tp = fp = tn = fn = 0
    for probability, actual in zip(probabilities, malicious, strict=True):
        predicted = probability > threshold
        tp += int(predicted and actual)
        fp += int(predicted and not actual)
        tn += int(not predicted and not actual)
        fn += int(not predicted and actual)
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return recall, fpr, precision, f1


def calibrate_thresholds(
    malicious_probabilities: Iterable[float],
    malicious_labels: Iterable[bool],
    *,
    max_fpr: float = 0.05,
    target_block_precision: float = 0.95,
) -> ThresholdCalibration:
    """Select an ALLOW boundary and conservative BLOCK boundary using validation only.

    REVIEW-or-BLOCK is considered a positive detection for the ALLOW boundary.  Among thresholds
    satisfying ``max_fpr``, selection maximizes F1 then recall.  BLOCK is the lowest higher
    threshold meeting the requested precision; otherwise it is the highest observed probability.
    """
    probabilities = tuple(float(value) for value in malicious_probabilities)
    labels = tuple(bool(value) for value in malicious_labels)
    if not probabilities or len(probabilities) != len(labels):
        raise ValueError("non-empty aligned probabilities and labels are required")
    if any(not math.isfinite(value) or not 0 <= value <= 1 for value in probabilities):
        raise ValueError("probabilities must be finite and between 0 and 1")
    if not 0 <= max_fpr <= 1 or not 0 <= target_block_precision <= 1:
        raise ValueError("calibration targets must be between 0 and 1")
    candidates = sorted({0.0, 1.0, *probabilities})
    feasible: list[tuple[float, float, float, float, float]] = []
    for threshold in candidates:
        recall, fpr, precision, f1 = _metrics(probabilities, labels, threshold)
        if fpr <= max_fpr:
            feasible.append((f1, recall, -fpr, -threshold, threshold))
    selected = (
        max(feasible)
        if feasible
        else max(
            (
                (*_metrics(probabilities, labels, threshold)[::-1], -threshold, threshold)
                for threshold in candidates
            ),
            key=lambda item: item,
        )
    )
    allow_max = float(selected[-1])
    block_candidates = []
    for threshold in candidates:
        if threshold <= allow_max:
            continue
        recall, fpr, precision, f1 = _metrics(probabilities, labels, threshold)
        if precision >= target_block_precision:
            block_candidates.append((threshold, -recall, fpr, f1))
    block_min = block_candidates[0][0] if block_candidates else 1.0
    if block_min <= allow_max:
        block_min = min(1.0, math.nextafter(allow_max, 1.0))
    if block_min <= allow_max:  # all validation probabilities were exactly 1.0
        allow_max = math.nextafter(1.0, 0.0)
        block_min = 1.0
    recall, fpr, precision, f1 = _metrics(probabilities, labels, allow_max)
    return ThresholdCalibration(
        thresholds=ClassifierThresholds(round(allow_max, 8), round(block_min, 8)),
        recall=recall,
        false_positive_rate=fpr,
        precision=precision,
        f1=f1,
        validation_cases=len(labels),
    )
