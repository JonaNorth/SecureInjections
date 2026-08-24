"""Semantic model registry and SecureInjections-specific local evaluation."""

from __future__ import annotations

import resource
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .corpus import CorpusCase, load_corpus
from .detectors.semantic import semantic_context_adjustment
from .detectors.semantic_embeddings import SentenceTransformerEmbeddingModel
from .models import Decision
from .rules.models import ThreatRule
from .semantic_registry import load_model_registry as load_model_registry


@dataclass(frozen=True, slots=True)
class CalibrationRow:
    threshold: float
    precision: float
    recall: float
    false_positive_rate: float
    false_negative_rate: float
    f1: float

    def to_dict(self) -> dict[str, float]:
        return {
            "threshold": self.threshold,
            "precision": self.precision,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "f1": self.f1,
        }


def _normalize(matrix: Any) -> Any:
    import numpy as np

    values = np.asarray(matrix, dtype=np.float32)
    if values.ndim != 2 or not np.isfinite(values).all():
        raise ValueError("embedding model returned an invalid matrix")
    norms = np.linalg.norm(values, axis=1, keepdims=True)
    if np.any(norms == 0):
        raise ValueError("embedding model returned a zero vector")
    return values / norms


def _reference_examples(rules: tuple[ThreatRule, ...]) -> tuple[list[str], list[str]]:
    texts: list[str] = []
    ids: list[str] = []
    for rule in rules:
        for example in rule.semantic_examples:
            texts.append(example)
            ids.append(rule.id)
    if not texts:
        raise ValueError("rules contain no semantic examples")
    return texts, ids


def _validation_with_rule_negatives(
    validation: tuple[CorpusCase, ...], rules: tuple[ThreatRule, ...]
) -> tuple[CorpusCase, ...]:
    """Add rule-owned hard negatives to semantic calibration only, never to holdout."""
    negatives: list[CorpusCase] = []
    for rule in sorted(rules, key=lambda item: item.id):
        for index, text in enumerate(rule.negative_examples, 1):
            negatives.append(
                CorpusCase(
                    id=f"SEM-NEG-{rule.id}-{index:03d}",
                    text=text,
                    label="benign",
                    expected_decision=Decision.ALLOW,
                    categories=(),
                    attack_family="semantic-rule-hard-negative",
                    language="en",
                    source_type="user",
                    difficulty="hard",
                    notes="Rule-owned semantic calibration hard negative.",
                    provenance=f"Threat Rule v1 {rule.id}",
                    license=rule.license,
                    split="validation",
                )
            )
    return (*validation, *negatives)


def select_calibration_threshold(
    rows: tuple[CalibrationRow, ...], *, maximum_false_positive_rate: float = 0.05
) -> CalibrationRow:
    """Maximize recall subject to a usability FPR ceiling; F1 is only a tie-breaker."""
    eligible = tuple(row for row in rows if row.false_positive_rate <= maximum_false_positive_rate)
    candidates = eligible or rows
    return max(
        candidates,
        key=lambda row: (row.recall, row.precision, row.f1, -row.false_positive_rate),
    )


def similarity_scores(
    model: Any, rules: tuple[ThreatRule, ...], cases: tuple[CorpusCase, ...]
) -> tuple[Any, Any, list[str]]:
    import numpy as np

    reference_texts, reference_ids = _reference_examples(rules)
    encode_documents = getattr(model, "encode_documents", model.encode)
    encode_queries = getattr(model, "encode_queries", model.encode)
    reference = _normalize(encode_documents(reference_texts))
    queries = _normalize(encode_queries([case.text for case in cases]))
    similarities = queries @ reference.T
    nearest = np.argmax(similarities, axis=1)
    scores = similarities[np.arange(len(cases)), nearest]
    scores = np.asarray(
        [
            max(-1.0, min(1.0, float(score) + semantic_context_adjustment(case.text)[0]))
            for score, case in zip(scores, cases, strict=True)
        ],
        dtype=np.float32,
    )
    predicted_ids = [reference_ids[int(index)] for index in nearest]
    return scores, similarities, predicted_ids


def calibrate_scores(scores: Any, cases: tuple[CorpusCase, ...]) -> tuple[CalibrationRow, ...]:
    rows: list[CalibrationRow] = []
    for integer in range(30, 96):
        threshold = integer / 100
        tp = fp = tn = fn = 0
        for score, case in zip(scores, cases, strict=True):
            expected = case.label == "malicious"
            actual = float(score) >= threshold
            tp += expected and actual
            fn += expected and not actual
            fp += not expected and actual
            tn += not expected and not actual
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        fnr = fn / (fn + tp) if fn + tp else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        rows.append(
            CalibrationRow(
                threshold,
                round(precision, 6),
                round(recall, 6),
                round(fpr, 6),
                round(fnr, 6),
                round(f1, 6),
            )
        )
    return tuple(rows)


def evaluate_local_model(
    model_path: Path,
    rules: tuple[ThreatRule, ...],
    corpus_path: Path,
    *,
    iterations: int = 30,
) -> dict[str, Any]:
    before_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    started = time.perf_counter_ns()
    model = SentenceTransformerEmbeddingModel(model_path)
    load_ms = (time.perf_counter_ns() - started) / 1_000_000
    validation = _validation_with_rule_negatives(
        load_corpus(corpus_path, split="validation"), rules
    )
    scores, _, predicted_ids = similarity_scores(model, rules, validation)
    rows = calibrate_scores(scores, validation)
    recommended = select_calibration_threshold(rows)
    sample = validation[0].text
    timings: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        getattr(model, "encode_queries", model.encode)((sample,))
        timings.append((time.perf_counter_ns() - started) / 1_000_000)
    batch_started = time.perf_counter_ns()
    getattr(model, "encode_queries", model.encode)([case.text for case in validation])
    batch_seconds = (time.perf_counter_ns() - batch_started) / 1_000_000_000
    artifact_bytes = sum(
        item.stat().st_size
        for item in model_path.rglob("*")
        if item.is_file() and not item.is_symlink()
    )
    malicious_scores = [
        float(score)
        for score, case in zip(scores, validation, strict=True)
        if case.label == "malicious"
    ]
    benign_scores = [
        float(score)
        for score, case in zip(scores, validation, strict=True)
        if case.label == "benign"
    ]
    retrieval_cases = [
        (case, predicted)
        for case, predicted in zip(validation, predicted_ids, strict=True)
        if case.expected_rule_ids
    ]
    retrieval_accuracy = (
        sum(predicted in case.expected_rule_ids for case, predicted in retrieval_cases)
        / len(retrieval_cases)
        if retrieval_cases
        else 0.0
    )
    per_language: dict[str, dict[str, float | int]] = {}
    for language in sorted({case.language for case in validation}):
        selected = [
            (float(score), case)
            for score, case in zip(scores, validation, strict=True)
            if case.language == language
        ]
        correct = sum(
            (score >= recommended.threshold) == (case.label == "malicious")
            for score, case in selected
        )
        per_language[language] = {
            "case_count": len(selected),
            "accuracy": round(correct / len(selected), 6),
        }
    ordered = sorted(timings)
    after_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {
        "model_identifier": model.identifier,
        "model_load_time_ms": round(load_ms, 3),
        "embedding_latency_ms": {
            "p50": round(statistics.median(timings), 3),
            "p95": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
            "p99": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))], 3),
        },
        "batch_throughput_per_second": round(len(validation) / batch_seconds, 3),
        "memory_high_water_delta": max(0, after_memory - before_memory),
        "artifact_size_bytes": artifact_bytes,
        "semantic_retrieval_accuracy": round(retrieval_accuracy, 6),
        "separation": {
            "malicious_mean_similarity": round(statistics.mean(malicious_scores), 6),
            "benign_mean_similarity": round(statistics.mean(benign_scores), 6),
        },
        "recommended_validation_threshold": recommended.to_dict(),
        "threshold_objective": (
            "maximize validation recall subject to false_positive_rate <= 0.05; "
            "then prefer precision and F1"
        ),
        "rule_hard_negative_count": sum(len(rule.negative_examples) for rule in rules),
        "per_language": per_language,
        "selection_warning": (
            "This evaluates one local artifact. Do not mark it recommended until candidate "
            "models are compared on quality, latency, multilingual behavior, and FPR."
        ),
    }


def calibration_report(
    model_path: Path, rules: tuple[ThreatRule, ...], corpus_path: Path
) -> dict[str, Any]:
    model = SentenceTransformerEmbeddingModel(model_path)
    validation = _validation_with_rule_negatives(
        load_corpus(corpus_path, split="validation"), rules
    )
    scores, _, _ = similarity_scores(model, rules, validation)
    rows = calibrate_scores(scores, validation)
    recommended = select_calibration_threshold(rows)
    return {
        "calibration_version": 1,
        "model_identifier": model.identifier,
        "split": "validation",
        "case_count": len(validation),
        "recommended": recommended.to_dict(),
        "thresholds": [row.to_dict() for row in rows],
        "holdout_used": False,
        "threshold_objective": (
            "maximize validation recall subject to false_positive_rate <= 0.05; "
            "then prefer precision and F1"
        ),
        "rule_hard_negative_count": sum(len(rule.negative_examples) for rule in rules),
    }
