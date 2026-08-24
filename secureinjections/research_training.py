"""First offline, binary, research-only classifier training and active-learning scoring."""

from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import random
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .active_learning import (
    ActiveLearningScore,
    DataTrustState,
    mark_cluster_inconsistency,
    research_grouped_split_analysis,
)
from .classifier_data import (
    BinaryLabel,
    ClassifierCase,
    conceptual_groups,
    corpus_hash,
    duplicate_audit,
    load_classifier_corpus,
    validate_group_isolation,
)
from .model_import import _network_blocked, inspect_local_model, validate_local_model
from .review_workflow import canonical_sha256, load_review_export
from .scanner import Scanner

EXPECTED_TRUST_STATES = frozenset({"REVIEWED", "VERIFIED"})
RESEARCH_SCHEMA_VERSION = 1


class ResearchTrainingError(RuntimeError):
    """The provisional research run violated an integrity or offline constraint."""


@dataclass(frozen=True, slots=True)
class BinaryResearchConfig:
    seed: int = 42
    epochs: int = 3
    batch_size: int = 4
    learning_rate: float = 2e-5
    max_length: int = 256
    score_batch_size: int = 32
    decision_threshold: float = 0.5
    review_units: int = 8
    minimum_validation_concepts_per_class: int | None = None
    sampling_strategy: str = "weighted-random"

    def __post_init__(self) -> None:
        if self.seed < 0 or self.epochs < 1 or self.batch_size < 1 or self.score_batch_size < 1:
            raise ValueError("seed must be non-negative and batch sizes/epochs must be positive")
        if not 0 < self.learning_rate < 1 or not 8 <= self.max_length <= 8192:
            raise ValueError("learning rate or maximum length is invalid")
        if not 0 < self.decision_threshold < 1 or not 1 <= self.review_units <= 30:
            raise ValueError("decision threshold or review-unit count is invalid")
        if self.minimum_validation_concepts_per_class is not None and (
            self.minimum_validation_concepts_per_class < 1
        ):
            raise ValueError("minimum validation concepts per class must be positive")
        if self.sampling_strategy not in {"weighted-random", "seeded-shuffle"}:
            raise ValueError("unsupported research sampling strategy")

    def to_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "seed": self.seed,
            "epochs": self.epochs,
            "batch_size": self.batch_size,
            "learning_rate": self.learning_rate,
            "max_length": self.max_length,
            "score_batch_size": self.score_batch_size,
            "decision_threshold": self.decision_threshold,
            "review_units": self.review_units,
            "device": "cpu",
            "optimizer": "AdamW",
            "loss": "weighted-cross-entropy",
            "labels": ["benign", "malicious"],
            "classifier_head": "newly-initialized-linear-sequence-classification-head",
        }
        if self.minimum_validation_concepts_per_class is not None:
            value["minimum_validation_concepts_per_class"] = (
                self.minimum_validation_concepts_per_class
            )
        if self.sampling_strategy != "weighted-random":
            value["sampling_strategy"] = self.sampling_strategy
        return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_text(path: Path, text: str) -> None:
    if path.is_symlink():
        raise ResearchTrainingError(f"refusing to replace symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise ResearchTrainingError(f"temporary output already exists: {temporary}")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_json(path: Path, value: object) -> None:
    _atomic_text(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _write_jsonl(path: Path, values: list[dict[str, object]]) -> None:
    if not values:
        raise ResearchTrainingError("refusing to write an empty JSONL artifact")
    _atomic_text(
        path,
        "".join(json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n" for value in values),
    )


def _versions() -> dict[str, str]:
    versions = {"python": platform.python_version()}
    for package in ("torch", "transformers", "safetensors"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "not-installed"
    return versions


def _trusted_gold(path: Path) -> tuple[ClassifierCase, ...]:
    cases = load_classifier_corpus(path)
    if not cases:
        raise ResearchTrainingError("trusted gold is empty")
    if any(not case.trusted for case in cases):
        raise ResearchTrainingError("training corpus contains a non-trusted row")
    states = {case.review_status.value for case in cases}
    if not states <= EXPECTED_TRUST_STATES:
        raise ResearchTrainingError("training corpus contains an inadmissible trust state")
    if any(case.effective_binary_label is BinaryLabel.AMBIGUOUS for case in cases):
        raise ResearchTrainingError("binary research training cannot use ambiguous labels")
    if len({case.id for case in cases}) != len(cases):
        raise ResearchTrainingError("training corpus repeats case IDs")
    leakage = duplicate_audit(cases)
    if not leakage["passed"]:
        raise ResearchTrainingError("trusted-gold leakage audit failed")
    return cases


def _assigned_cases(
    cases: tuple[ClassifierCase, ...], analysis: dict[str, object]
) -> tuple[ClassifierCase, ...]:
    raw_assignments = analysis.get("assignments")
    if not isinstance(raw_assignments, dict):
        raise ResearchTrainingError("grouped split assignments are malformed")
    assignments = {str(key): str(value) for key, value in raw_assignments.items()}
    groups = conceptual_groups(cases)
    if set(groups) != set(assignments):
        raise ResearchTrainingError("grouped split membership changed after analysis")
    assigned = tuple(
        replace(case, split=assignments[group_id])
        for group_id, members in groups.items()
        for case in members
    )
    validate_group_isolation(assigned)
    if not duplicate_audit(assigned)["passed"]:
        raise ResearchTrainingError("grouped leakage detected")
    return assigned


def _wilson(successes: int, total: int) -> dict[str, object]:
    if total == 0:
        return {"level": 0.95, "low": None, "high": None, "meaningful": False}
    z = 1.959963984540054
    value = successes / total
    denominator = 1 + (z * z / total)
    center = (value + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((value * (1 - value) / total) + z * z / (4 * total * total))
    margin /= denominator
    return {
        "level": 0.95,
        "method": "Wilson score",
        "low": round(max(0.0, center - margin), 6),
        "high": round(min(1.0, center + margin), 6),
        "meaningful": total >= 20,
    }


def _metrics(actual: list[int], predicted: list[int]) -> dict[str, object]:
    tp = sum(a == 1 and p == 1 for a, p in zip(actual, predicted, strict=True))
    fp = sum(a == 0 and p == 1 for a, p in zip(actual, predicted, strict=True))
    tn = sum(a == 0 and p == 0 for a, p in zip(actual, predicted, strict=True))
    fn = sum(a == 1 and p == 0 for a, p in zip(actual, predicted, strict=True))
    recall = tp / (tp + fn) if tp + fn else None
    precision = tp / (tp + fp) if tp + fp else 0.0 if any(actual) else None
    benign_fpr = fp / (fp + tn) if fp + tn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else 0.0
        if precision is not None and recall is not None
        else None
    )
    return {
        "cases": len(actual),
        "recall": round(recall, 6) if recall is not None else None,
        "precision": round(precision, 6) if precision is not None else None,
        "f1": round(f1, 6) if f1 is not None else None,
        "benign_fpr": round(benign_fpr, 6) if benign_fpr is not None else None,
        "confusion_matrix": {
            "actual_benign": {"predicted_benign": tn, "predicted_malicious": fp},
            "actual_malicious": {"predicted_benign": fn, "predicted_malicious": tp},
        },
        "confidence_intervals": {
            "recall": _wilson(tp, tp + fn),
            "precision": _wilson(tp, tp + fp),
            "benign_fpr": _wilson(fp, fp + tn),
            "f1": {
                "level": 0.95,
                "low": None,
                "high": None,
                "meaningful": False,
                "reason": "validation is too small for a stable F1 interval",
            },
        },
        "statistically_meaningful": False,
    }


def _add_prediction_distribution(
    metrics: dict[str, object],
    probabilities: list[float],
    predicted: list[int],
    actual: list[int],
) -> None:
    ordered = sorted(probabilities)
    midpoint = len(ordered) // 2
    median = (
        (ordered[midpoint - 1] + ordered[midpoint]) / 2
        if len(ordered) % 2 == 0
        else ordered[midpoint]
    )
    metrics["malicious_probability_distribution"] = {
        "minimum": round(ordered[0], 6),
        "maximum": round(ordered[-1], 6),
        "mean": round(sum(ordered) / len(ordered), 6),
        "median": round(median, 6),
    }
    metrics["predicted_class_counts"] = {
        "malicious": sum(predicted),
        "benign": len(predicted) - sum(predicted),
    }
    metrics["single_class_collapse"] = len(set(predicted)) == 1
    metrics["malicious_probability_by_true_class"] = {
        label: {
            "count": len(selected),
            "minimum": round(min(selected), 6),
            "maximum": round(max(selected), 6),
            "mean": round(sum(selected) / len(selected), 6),
        }
        for label, target in (("benign", 0), ("malicious", 1))
        if (
            selected := [
                value for value, truth in zip(probabilities, actual, strict=True) if truth == target
            ]
        )
    }


def _diagnostic_stop_conditions(metrics: dict[str, object]) -> dict[str, object]:
    distribution = cast(dict[str, Any], metrics["malicious_probability_distribution"])
    minimum = float(distribution["minimum"])
    maximum = float(distribution["maximum"])
    fpr = metrics.get("benign_fpr")
    matrix = cast(dict[str, dict[str, int]], metrics["confusion_matrix"])
    benign_total = sum(matrix["actual_benign"].values())
    malicious_total = sum(matrix["actual_malicious"].values())
    narrow = maximum - minimum <= 0.1 and minimum >= 0.4 and maximum <= 0.6
    threshold_noise = minimum < 0.5 <= maximum and max(0.5 - minimum, maximum - 0.5) <= 0.1
    unacceptable_fpr = isinstance(fpr, (int, float)) and not isinstance(fpr, bool) and fpr > 0.1
    small_denominators = benign_total < 20 or malicious_total < 20
    conditions = {
        "probabilities_narrowly_clustered_around_0_5": narrow,
        "benign_fpr_clearly_unacceptable": unacceptable_fpr,
        "single_class_collapse": bool(metrics["single_class_collapse"]),
        "validation_dominated_by_threshold_noise": threshold_noise,
        "metrics_depend_on_fewer_than_20_examples_per_class": small_denominators,
    }
    return {
        "triggered": any(conditions.values()),
        "conditions": conditions,
        "policy": "STOP LABELING — training methodology is now the bottleneck",
    }


def _dimension_metrics(
    cases: tuple[ClassifierCase, ...],
    actual: list[int],
    predicted: list[int],
    field: str,
) -> dict[str, object]:
    records = list(zip(cases, actual, predicted, strict=True))
    output: dict[str, object] = {}
    for key in sorted({str(getattr(case, field)) for case in cases}):
        selected = [(a, p) for case, a, p in records if str(getattr(case, field)) == key]
        metric = _metrics([a for a, _p in selected], [p for _a, p in selected])
        metric["reporting_status"] = (
            "DESCRIPTIVE ONLY" if len(selected) >= 2 else "INSUFFICIENT: SINGLE CASE"
        )
        output[key] = metric
    return output


def _baseline_comparison(path: Path, current: dict[str, object]) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8_000_000:
        raise ResearchTrainingError("baseline research report is missing or unsafe")
    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ResearchTrainingError("baseline research report is invalid") from exc
    if not isinstance(baseline, dict) or baseline.get("research_only") is not True:
        raise ResearchTrainingError("baseline is not a research-only report")
    metrics = baseline.get("exploratory_metrics")
    if not isinstance(metrics, dict):
        raise ResearchTrainingError("baseline research metrics are missing")

    def number(source: dict[str, Any], key: str) -> float:
        value = source.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ResearchTrainingError(f"baseline comparison metric is invalid: {key}")
        return float(value)

    current_values = cast(dict[str, Any], current)
    baseline_recall = number(metrics, "recall")
    baseline_precision = number(metrics, "precision")
    baseline_f1 = number(metrics, "f1")
    baseline_fpr = number(metrics, "benign_fpr")
    current_recall = number(current_values, "recall")
    current_precision = number(current_values, "precision")
    current_f1 = number(current_values, "f1")
    current_fpr = number(current_values, "benign_fpr")
    matrix = metrics.get("confusion_matrix")
    baseline_all_benign = bool(
        isinstance(matrix, dict)
        and isinstance(matrix.get("actual_benign"), dict)
        and isinstance(matrix.get("actual_malicious"), dict)
        and matrix["actual_benign"].get("predicted_malicious") == 0
        and matrix["actual_malicious"].get("predicted_malicious") == 0
    )
    return {
        "baseline_report": path.resolve().as_posix(),
        "baseline_report_sha256": _sha256_file(path),
        "baseline": {
            "recall": baseline_recall,
            "precision": baseline_precision,
            "f1": baseline_f1,
            "benign_fpr": baseline_fpr,
            "all_benign_collapse": baseline_all_benign,
        },
        "current": {
            "recall": current_recall,
            "precision": current_precision,
            "f1": current_f1,
            "benign_fpr": current_fpr,
            "single_class_collapse": bool(current.get("single_class_collapse")),
        },
        "recall_delta": round(current_recall - baseline_recall, 6),
        "precision_delta": round(current_precision - baseline_precision, 6),
        "f1_delta": round(current_f1 - baseline_f1, 6),
        "benign_fpr_delta": round(current_fpr - baseline_fpr, 6),
        "escaped_all_benign_collapse": bool(
            baseline_all_benign and not current.get("single_class_collapse")
        ),
        "benign_fpr_unacceptable_for_readiness": current_fpr > 0.1,
        "metrics_label": "EXPLORATORY / DIFFERENT GROUPED VALIDATION COMPOSITION",
    }


def attach_baseline_comparison(
    current_report_path: Path, baseline_report_path: Path
) -> dict[str, object]:
    """Attach an exploratory baseline comparison without modifying either model artifact."""
    if (
        current_report_path.is_symlink()
        or not current_report_path.is_file()
        or current_report_path.stat().st_size > 8_000_000
    ):
        raise ResearchTrainingError("current research report is missing or unsafe")
    try:
        current = json.loads(current_report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ResearchTrainingError("current research report is invalid") from exc
    if (
        not isinstance(current, dict)
        or current.get("research_only") is not True
        or current.get("model_trained") is not True
        or not isinstance(current.get("exploratory_metrics"), dict)
    ):
        raise ResearchTrainingError("current report is not a trained research-only run")
    comparison = _baseline_comparison(
        baseline_report_path, cast(dict[str, object], current["exploratory_metrics"])
    )
    current["baseline_comparison"] = comparison
    _write_json(current_report_path, current)
    markdown_path = current_report_path.with_suffix(".md")
    if markdown_path.is_file() and not markdown_path.is_symlink():
        baseline = cast(dict[str, Any], comparison["baseline"])
        _atomic_text(
            markdown_path,
            markdown_path.read_text(encoding="utf-8")
            + "\n## Baseline comparison\n\n"
            + f"- Recall delta: {comparison['recall_delta']}\n"
            + f"- Precision delta: {comparison['precision_delta']}\n"
            + f"- F1 delta: {comparison['f1_delta']}\n"
            + f"- Benign FPR delta: {comparison['benign_fpr_delta']}\n"
            + "- Escaped all-benign collapse: "
            + ("YES\n" if comparison["escaped_all_benign_collapse"] else "NO\n")
            + f"- Baseline recall/F1/FPR: {baseline['recall']} / {baseline['f1']} / "
            + f"{baseline['benign_fpr']}\n\n"
            + "The validation composition changed and remains too small; deltas are exploratory.\n",
        )
    return comparison


def _runtime_asset_hashes(path: Path) -> dict[str, str]:
    return {
        item.relative_to(path).as_posix(): _sha256_file(item)
        for item in sorted(path.rglob("*"))
        if item.is_file() and not item.is_symlink() and item.name != "research-artifact.json"
    }


def _pool_cases(
    units: tuple[dict[str, Any], ...], gold_ids: set[str]
) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]]]:
    cases: dict[str, dict[str, Any]] = {}
    concepts: dict[str, set[str]] = defaultdict(set)
    for unit in units:
        concept_unit = str(unit.get("review_item_id", "")).startswith("legacy-concept-")
        suggestion = unit.get("machine_suggestion")
        concept = suggestion.get("proposed_concept_id") if isinstance(suggestion, dict) else None
        for raw in unit.get("cases", []):
            if not isinstance(raw, dict) or not isinstance(raw.get("case_id"), str):
                raise ResearchTrainingError("review pool contains a malformed case")
            case_id = raw["case_id"]
            if case_id in gold_ids:
                continue
            previous = cases.get(case_id)
            if previous is not None and canonical_sha256(previous) != canonical_sha256(raw):
                raise ResearchTrainingError(
                    f"review pool has conflicting duplicate case: {case_id}"
                )
            cases[case_id] = raw
            if concept_unit and isinstance(concept, str) and concept:
                concepts[case_id].add(concept)
    return cases, concepts


def _pool_metadata(case: dict[str, Any]) -> tuple[str, str, bool]:
    metadata = case.get("legacy_metadata")
    if not isinstance(metadata, dict):
        return "unknown", "unknown", False
    language = metadata.get("language")
    family = metadata.get("attack_family")
    label = metadata.get("label")
    categories = metadata.get("categories")
    hard_negative = label == "benign" and bool(categories or family not in {None, "normal-benign"})
    return (
        language if isinstance(language, str) else "unknown",
        family if isinstance(family, str) else "unknown",
        hard_negative,
    )


def _model_batch_probabilities(
    model: Any,
    tokenizer: Any,
    texts: list[str],
    *,
    batch_size: int,
    max_length: int,
    torch: Any,
) -> list[float]:
    output: list[float] = []
    model.eval()
    with torch.inference_mode():
        for start in range(0, len(texts), batch_size):
            batch = texts[start : start + batch_size]
            encoded = tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=max_length,
                return_tensors="pt",
            )
            logits = model(**encoded).logits
            output.extend(float(value) for value in torch.softmax(logits, dim=-1)[:, 1].tolist())
            del encoded, logits
    return output


def _score_pool(
    model: Any,
    tokenizer: Any,
    pool_cases: dict[str, dict[str, Any]],
    concepts_by_case: dict[str, set[str]],
    *,
    config: BinaryResearchConfig,
    torch: Any,
) -> tuple[list[dict[str, object]], dict[str, ActiveLearningScore]]:
    ordered_ids = sorted(pool_cases)
    probabilities = _model_batch_probabilities(
        model,
        tokenizer,
        [str(pool_cases[case_id]["text"]) for case_id in ordered_ids],
        batch_size=config.score_batch_size,
        max_length=config.max_length,
        torch=torch,
    )
    scanner = Scanner()
    scores: list[ActiveLearningScore] = []
    for case_id, probability in zip(ordered_ids, probabilities, strict=True):
        case = pool_cases[case_id]
        language, family, hard_negative = _pool_metadata(case)
        if language == "unknown":
            raise ResearchTrainingError(f"pool case has no supported language: {case_id}")
        deterministic = scanner.scan(str(case["text"]))
        concept_values = concepts_by_case.get(case_id, set())
        concept = sorted(concept_values)[0] if len(concept_values) == 1 else None
        scores.append(
            ActiveLearningScore(
                case_id=case_id,
                malicious_probability=probability,
                allow_max=config.decision_threshold,
                block_min=min(1.0, math.nextafter(config.decision_threshold, 1.0)),
                deterministic_decision=deterministic.decision.value,
                deterministic_severity=deterministic.risk_score,
                concept_id=concept,
                paraphrase_group=None,
                translation_group=None,
                language=language,
                family_candidate=family,
                hard_negative_candidate=hard_negative,
                cluster_size=1,
            )
        )
    marked = mark_cluster_inconsistency(tuple(scores))
    by_id = {score.case_id: score for score in marked}
    return [score.to_dict() for score in marked], by_id


def _model_backed_batch(
    units: tuple[dict[str, Any], ...],
    scores: dict[str, ActiveLearningScore],
    trusted_concepts: set[str],
    *,
    count: int,
    batch_number: int,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    batch_id = f"v0.4.2-active-learning-batch-{batch_number:02d}"
    candidates: list[tuple[dict[str, Any], list[ActiveLearningScore], str, str]] = []
    seen_concepts: set[str] = set()
    for unit in units:
        if not str(unit.get("review_item_id", "")).startswith("legacy-concept-"):
            continue
        suggestion = unit.get("machine_suggestion")
        concept = suggestion.get("proposed_concept_id") if isinstance(suggestion, dict) else None
        if not isinstance(concept, str) or concept in trusted_concepts or concept in seen_concepts:
            continue
        unit_scores = [
            scores[str(case["case_id"])]
            for case in unit.get("cases", [])
            if isinstance(case, dict) and str(case.get("case_id")) in scores
        ]
        if not unit_scores:
            continue
        seen_concepts.add(concept)
        family = Counter(score.family_candidate or "unknown" for score in unit_scores).most_common(
            1
        )[0][0]
        candidates.append((unit, unit_scores, concept, family))
    ranked: list[dict[str, Any]] = []
    for unit, unit_scores, concept, family in candidates:
        labels = {score.predicted_label for score in unit_scores}
        languages = {score.language for score in unit_scores}
        uncertainty = max(score.entropy for score in unit_scores)
        disagreement = sum(score.deterministic_disagreement for score in unit_scores) / len(
            unit_scores
        )
        inconsistency = len(labels) > 1
        base = uncertainty * 55 + disagreement * 30 + (20 if inconsistency else 0)
        ranked.append(
            {
                "unit": unit,
                "scores": unit_scores,
                "concept": concept,
                "family": family,
                "languages": languages,
                "uncertainty": uncertainty,
                "disagreement": disagreement,
                "inconsistency": inconsistency,
                "base": base,
            }
        )
    chosen: list[dict[str, Any]] = []
    seen_families: set[str] = set()
    seen_languages: set[str] = set()
    while len(chosen) < count and ranked:
        ranked.sort(
            key=lambda item: (
                -(
                    float(item["base"])
                    + (15 if item["family"] not in seen_families else 0)
                    + 4 * len(set(item["languages"]) - seen_languages)
                ),
                str(item["concept"]),
            )
        )
        selected = ranked.pop(0)
        chosen.append(selected)
        seen_families.add(str(selected["family"]))
        seen_languages.update(selected["languages"])
    if len(chosen) != count:
        raise ResearchTrainingError("pool cannot satisfy minimal concept-diverse batch")
    output: list[dict[str, object]] = []
    all_languages: set[str] = set()
    all_families: set[str] = set()
    for index, item in enumerate(chosen):
        copied = copy.deepcopy(item["unit"])
        unit_scores = item["scores"]
        representative = max(
            unit_scores,
            key=lambda score: (score.priority_score, score.entropy, score.case_id),
        )
        raw_case = next(
            case for case in copied["cases"] if case["case_id"] == representative.case_id
        )
        raw_case["active_learning_review_role"] = "model_priority_representative"
        raw_case["active_learning_outlier_status"] = (
            "CLUSTER_INCONSISTENT" if item["inconsistency"] else "HIGHEST_MODEL_PRIORITY"
        )
        copied["review_unit_index"] = index
        copied["pilot_id"] = batch_id
        copied["case_ids"] = [representative.case_id]
        copied["cases"] = [raw_case]
        reasons = ["predictive uncertainty", "classifier-family diversity", "language diversity"]
        if item["disagreement"]:
            reasons.append("deterministic rule disagreement")
        if item["inconsistency"]:
            reasons.append("concept/cluster inconsistency")
        copied["priority_reasons"] = reasons
        copied["priority_score"] = representative.priority_score
        copied["machine_suggestion_trusted"] = False
        copied["human_decision"] = None
        copied["instruction"] = (
            "RESEARCH MODEL RANKING / UNTRUSTED. Review this hash-bound representative. "
            "Neither its model prediction nor cluster siblings are automatically trusted."
        )
        copied["pilot_summary"] = {
            "review_item_id": copied["review_item_id"],
            "candidate_concept_id": item["concept"],
            "candidate_families": [item["family"]],
            "candidate_paraphrase_group": None,
            "candidate_translation_group": None,
            "provisional_binary_labels": [representative.predicted_label.value],
            "languages": [representative.language],
            "hard_negative_categories": (
                [item["family"]] if representative.hard_negative_candidate else []
            ),
            "rows": 1,
            "source_cluster_rows": len(unit_scores),
            "case_ids": [representative.case_id],
            "original_language_status": "unknown-unreviewed",
            "translation_derived_candidate": False,
            "uncertainty_flags": reasons,
        }
        copied["active_learning"] = {
            "schema_version": 1,
            "trust_state": DataTrustState.PROVISIONAL.value,
            "selection_mode": "RESEARCH_MODEL_UNCERTAINTY_V1",
            "why_selected": reasons,
            "classifier_probability": round(representative.malicious_probability, 6),
            "classifier_confidence": round(representative.confidence, 6),
            "entropy": round(representative.entropy, 6),
            "deterministic_disagreement": representative.deterministic_disagreement,
            "cluster_inconsistent": bool(item["inconsistency"]),
            "family_candidate": item["family"],
            "concept_candidate": item["concept"],
            "language": representative.language,
            "representative_case": representative.case_id,
            "machine_suggestion_trusted": False,
        }
        all_languages.add(representative.language)
        all_families.add(str(item["family"]))
        output.append(copied)
    return output, {
        "schema_version": 1,
        "batch_id": batch_id,
        "selection_mode": "RESEARCH_MODEL_UNCERTAINTY_V1",
        "machine_suggestions_trusted": False,
        "review_units": len(output),
        "review_rows": len(output),
        "concepts": len(output),
        "candidate_pool_concepts_ranked": len(candidates),
        "languages": sorted(all_languages),
        "candidate_families": sorted(all_families),
        "pseudo_labels_created": 0,
        "factors": [
            "predictive uncertainty",
            "deterministic rule disagreement",
            "classifier-family diversity",
            "language diversity",
            "concept/cluster inconsistency",
        ],
    }


def train_binary_research_classifier(
    base_model_path: Path,
    gold_path: Path,
    pool_path: Path,
    artifact_path: Path,
    output_directory: Path,
    *,
    expected_base_freeze_sha256: str,
    config: BinaryResearchConfig | None = None,
    run_label: str = "first",
    next_batch_number: int = 4,
    baseline_report_path: Path | None = None,
) -> dict[str, Any]:
    """Train one provisional binary classifier, evaluate, score, and optionally rank review."""
    config = config or BinaryResearchConfig()
    if run_label not in {"first", "second", "third"} or not 1 <= next_batch_number <= 99:
        raise ResearchTrainingError("research run label or next batch number is invalid")
    if artifact_path.exists():
        raise ResearchTrainingError("research artifact path already exists")
    base_report = inspect_local_model(base_model_path)
    if base_report.get("directory_freeze_sha256") != expected_base_freeze_sha256:
        raise ResearchTrainingError("base model freeze hash changed")
    validated = validate_local_model(base_model_path)
    if validated.get("validation") != "PASS" or not validated.get(
        "secureinjections_offline_loadable"
    ):
        raise ResearchTrainingError("base model no longer passes offline validation")
    if validated.get("directory_freeze_sha256") != expected_base_freeze_sha256:
        raise ResearchTrainingError("validated base model freeze hash changed")
    gold_file_hash_before = _sha256_file(gold_path)
    cases = _trusted_gold(gold_path)
    gold_semantic_hash = corpus_hash(cases)
    split = research_grouped_split_analysis(
        cases,
        seed=config.seed,
        minimum_validation_concepts_per_class=(config.minimum_validation_concepts_per_class),
    )
    if not split["structurally_possible"] or not split["leakage_passed"]:
        raise ResearchTrainingError("grouped binary training split is not structurally valid")
    assigned = _assigned_cases(cases, split)
    training = tuple(case for case in assigned if case.split == "train")
    validation = tuple(case for case in assigned if case.split == "validation")
    if not training or not validation:
        raise ResearchTrainingError("grouped train and validation must both be non-empty")
    config_dict = config.to_dict()
    config_hash = canonical_sha256(config_dict)
    try:
        import torch
        from torch.utils.data import DataLoader, Dataset, WeightedRandomSampler
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:
        raise ResearchTrainingError(
            "local classifier training dependencies are unavailable"
        ) from exc
    random.seed(config.seed)
    torch.manual_seed(config.seed)
    torch.set_num_threads(1)
    if hasattr(torch, "use_deterministic_algorithms"):
        torch.use_deterministic_algorithms(True, warn_only=True)

    class ResearchDataset(Dataset):  # type: ignore[misc]
        def __init__(self, selected: tuple[ClassifierCase, ...]) -> None:
            self.selected = selected

        def __len__(self) -> int:
            return len(self.selected)

        def __getitem__(self, index: int) -> tuple[str, int]:
            case = self.selected[index]
            return case.text, int(case.effective_binary_label is BinaryLabel.MALICIOUS)

    started = time.perf_counter()
    with _network_blocked():
        tokenizer = AutoTokenizer.from_pretrained(
            str(base_model_path.resolve()),
            local_files_only=True,
            trust_remote_code=False,
            use_fast=True,
        )
        model = AutoModelForSequenceClassification.from_pretrained(
            str(base_model_path.resolve()),
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
            num_labels=2,
            id2label={0: "benign", 1: "malicious"},
            label2id={"benign": 0, "malicious": 1},
            ignore_mismatched_sizes=True,
        )
        model.to("cpu")

        def collate(batch: list[tuple[str, int]]) -> dict[str, Any]:
            texts, labels = zip(*batch, strict=True)
            encoded = tokenizer(
                list(texts),
                padding=True,
                truncation=True,
                max_length=config.max_length,
                return_tensors="pt",
            )
            encoded["labels"] = torch.tensor(labels, dtype=torch.long)
            return encoded

        counts = Counter(
            int(case.effective_binary_label is BinaryLabel.MALICIOUS) for case in training
        )
        class_weights = {
            label: len(training) / (2 * count) for label, count in counts.items() if count
        }
        generator = torch.Generator().manual_seed(config.seed)
        if config.sampling_strategy == "weighted-random":
            sample_weights = [
                class_weights[int(case.effective_binary_label is BinaryLabel.MALICIOUS)]
                for case in training
            ]
            sampler = WeightedRandomSampler(
                sample_weights,
                num_samples=len(sample_weights),
                replacement=True,
                generator=generator,
            )
            loader = DataLoader(
                ResearchDataset(training),
                batch_size=config.batch_size,
                sampler=sampler,
                collate_fn=collate,
            )
        else:
            loader = DataLoader(
                ResearchDataset(training),
                batch_size=config.batch_size,
                shuffle=True,
                generator=generator,
                collate_fn=collate,
            )
        optimizer = torch.optim.AdamW(model.parameters(), lr=config.learning_rate)
        loss_weights = torch.tensor(
            [class_weights.get(0, 1.0), class_weights.get(1, 1.0)], dtype=torch.float32
        )
        criterion = torch.nn.CrossEntropyLoss(weight=loss_weights)
        losses: list[float] = []
        model.train()
        for _epoch in range(config.epochs):
            running = 0.0
            batches = 0
            for training_batch in loader:
                optimizer.zero_grad(set_to_none=True)
                targets = training_batch.pop("labels")
                logits = model(**training_batch).logits
                loss = criterion(logits, targets)
                loss.backward()
                optimizer.step()
                running += float(loss.detach())
                batches += 1
            losses.append(running / max(1, batches))

        validation_probabilities = _model_batch_probabilities(
            model,
            tokenizer,
            [case.text for case in validation],
            batch_size=config.score_batch_size,
            max_length=config.max_length,
            torch=torch,
        )
        actual = [int(case.effective_binary_label is BinaryLabel.MALICIOUS) for case in validation]
        predicted = [int(value >= config.decision_threshold) for value in validation_probabilities]
        metrics = _metrics(actual, predicted)
        _add_prediction_distribution(metrics, validation_probabilities, predicted, actual)
        metrics["per_language"] = _dimension_metrics(validation, actual, predicted, "language")
        metrics["per_classifier_family"] = _dimension_metrics(
            validation, actual, predicted, "label"
        )
        metrics["threshold"] = config.decision_threshold
        metrics["probabilities_calibrated"] = False
        metrics["label"] = "EXPLORATORY / STATISTICALLY UNDERPOWERED"
        metrics["validation_predictions"] = [
            {
                "case_id": case.id,
                "concept_id": case.concept_id,
                "language": case.language,
                "classifier_family": case.label.value,
                "actual": case.effective_binary_label.value,
                "malicious_probability": round(probability, 6),
                "predicted": "malicious" if prediction else "benign",
            }
            for case, probability, prediction in zip(
                validation, validation_probabilities, predicted, strict=True
            )
        ]

        units = load_review_export(pool_path)
        pool_cases, concepts_by_case = _pool_cases(units, {case.id for case in cases})
        score_rows, scores_by_id = _score_pool(
            model,
            tokenizer,
            pool_cases,
            concepts_by_case,
            config=config,
            torch=torch,
        )
        artifact_path.mkdir(parents=True)
        model.save_pretrained(artifact_path, safe_serialization=True)
        tokenizer.save_pretrained(artifact_path)

    if _sha256_file(gold_path) != gold_file_hash_before:
        raise ResearchTrainingError("trusted-gold file changed during training")
    if (
        inspect_local_model(base_model_path).get("directory_freeze_sha256")
        != expected_base_freeze_sha256
    ):
        raise ResearchTrainingError("base model changed during training")
    runtime_hashes = _runtime_asset_hashes(artifact_path)
    artifact_freeze_hash = canonical_sha256(runtime_hashes)
    research_identity = (
        "secureinjections-v0.4.2-multilingual-e5-small-binary-" + artifact_freeze_hash[:12]
    )
    artifact_manifest = {
        "schema_version": RESEARCH_SCHEMA_VERSION,
        "research_only": True,
        "production": False,
        "selected": False,
        "classifier_architecture": "BertForSequenceClassification(binary)",
        "classifier_head": "newly initialized and trained",
        "labels": ["benign", "malicious"],
        "identity": research_identity,
        "base_model_path": base_model_path.resolve().as_posix(),
        "base_model_freeze_sha256": expected_base_freeze_sha256,
        "gold_corpus_path": gold_path.resolve().as_posix(),
        "gold_corpus_file_sha256": gold_file_hash_before,
        "gold_corpus_semantic_sha256": gold_semantic_hash,
        "split_sha256": split["split_hash"],
        "training_configuration": config_dict,
        "training_configuration_sha256": config_hash,
        "runtime_asset_hashes": runtime_hashes,
        "artifact_freeze_sha256": artifact_freeze_hash,
        "network_used": False,
        "development_shadow_used": False,
        "blind_set_e_burned": False,
    }
    _write_json(artifact_path / "research-artifact.json", artifact_manifest)

    diagnostic_stop = _diagnostic_stop_conditions(metrics)
    collapsed_to_one_class = bool(metrics["single_class_collapse"])
    useful_ranking = bool(
        not diagnostic_stop["triggered"]
        and len(score_rows) >= config.review_units
        and (
            len({round(cast(float, row["classifier_probability"]), 4) for row in score_rows}) > 1
            or any(bool(row["deterministic_disagreement"]) for row in score_rows)
        )
    )
    batch: list[dict[str, object]] = []
    batch_manifest: dict[str, object] | None = None
    if useful_ranking:
        batch, batch_manifest = _model_backed_batch(
            units,
            scores_by_id,
            {case.concept_id for case in cases},
            count=config.review_units,
            batch_number=next_batch_number,
        )
    output_directory = output_directory.resolve()
    scores_path = output_directory / f"v0.4.2-{run_label}-research-model-scores.jsonl"
    metrics_path = output_directory / f"v0.4.2-{run_label}-research-model-metrics.json"
    report_path = output_directory / f"v0.4.2-{run_label}-multilingual-research-training.json"
    markdown_path = output_directory / f"v0.4.2-{run_label}-multilingual-research-training.md"
    for path in (scores_path, metrics_path, report_path, markdown_path):
        if path.exists():
            raise ResearchTrainingError(f"research output already exists: {path}")
    _write_jsonl(scores_path, score_rows)
    _write_json(metrics_path, metrics)
    batch_path: Path | None = None
    batch_manifest_path: Path | None = None
    if batch_manifest is not None:
        batch_path = (
            output_directory / f"v0.4.2-active-learning-batch-{next_batch_number:02d}.jsonl"
        )
        batch_manifest_path = output_directory / (
            f"v0.4.2-active-learning-batch-{next_batch_number:02d}-manifest.json"
        )
        if batch_path.exists() or batch_manifest_path.exists():
            raise ResearchTrainingError("active-learning Batch 04 already exists")
        _write_jsonl(batch_path, batch)
        batch_manifest.update(
            {
                "batch_sha256": _sha256_file(batch_path),
                "research_model_identity": research_identity,
                "research_model_artifact_freeze_sha256": artifact_freeze_hash,
                "source_pool_path": pool_path.resolve().as_posix(),
                "source_pool_sha256": _sha256_file(pool_path),
                "scores_path": scores_path.as_posix(),
                "scores_sha256": _sha256_file(scores_path),
            }
        )
        _write_json(batch_manifest_path, batch_manifest)

    report: dict[str, Any] = {
        "schema_version": RESEARCH_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "PROVISIONAL RESEARCH MODEL TRAINED",
        "run_label": run_label,
        "research_only": True,
        "model_trained": True,
        "production_model_selected": None,
        "base_model": validated,
        "artifact": artifact_manifest,
        "trusted_gold": {
            "rows": len(cases),
            "concepts": len({case.concept_id for case in cases}),
            "malicious_rows": sum(
                case.effective_binary_label is BinaryLabel.MALICIOUS for case in cases
            ),
            "benign_rows": sum(case.effective_binary_label is BinaryLabel.BENIGN for case in cases),
            "review_states": dict(
                sorted(Counter(case.review_status.value for case in cases).items())
            ),
            "other_trust_states_used": 0,
            "semantic_sha256": gold_semantic_hash,
            "file_sha256": gold_file_hash_before,
        },
        "grouped_split": split,
        "training": {
            "config": config_dict,
            "config_sha256": config_hash,
            "epoch_losses": losses,
            "duration_seconds": round(time.perf_counter() - started, 3),
            "dependencies": _versions(),
        },
        "exploratory_metrics": metrics,
        "active_learning": {
            "untrusted_unique_rows_scored": len(score_rows),
            "useful_uncertainty_ranking": useful_ranking,
            "review_loop_stopped_for_single_class_collapse": collapsed_to_one_class,
            "diagnostic_stop": diagnostic_stop,
            "uncertain_rows_at_entropy_0_9_or_higher": sum(
                cast(float, row["entropy"]) >= 0.9 for row in score_rows
            ),
            "deterministic_disagreements": sum(
                bool(row["deterministic_disagreement"]) for row in score_rows
            ),
            "cluster_inconsistent_rows": sum(
                bool(row["cluster_inconsistent"]) for row in score_rows
            ),
            "next_review_batch_size": len(batch),
            "batch": batch_path.as_posix() if batch_path else None,
            "batch_manifest": batch_manifest_path.as_posix() if batch_manifest_path else None,
            "scores": scores_path.as_posix(),
        },
        "pseudo_labels": {
            "count": 0,
            "trusted": 0,
            "artifact": None,
            "policy": "PSEUDO_LABELED / UNTRUSTED; not generated from an underpowered first run",
        },
        "safety": {
            "leakage": "PASS",
            "network_used": False,
            "downloads": 0,
            "development_shadow_used": False,
            "blind_set_e_burned": False,
            "production_model_selected": None,
        },
    }
    if baseline_report_path is not None:
        report["baseline_comparison"] = _baseline_comparison(baseline_report_path, metrics)
    _write_json(report_path, report)
    overall = metrics
    matrix = overall["confusion_matrix"]
    assert isinstance(matrix, dict)
    train_size = split["sizes"]["train"]  # type: ignore[index]
    validation_size = split["sizes"]["validation"]  # type: ignore[index]
    markdown = f"""# SecureInjections v0.4.2 — {run_label.title()} multilingual research training

Status: **PROVISIONAL RESEARCH ONLY**

The frozen `{validated["path"]}` encoder was revalidated at freeze hash
`{expected_base_freeze_sha256}`. A newly initialized binary sequence-classification head was
trained for {config.epochs} epochs with seed {config.seed}. No network, download, development
shadow, production selection, or Blind Set E use occurred.

## Grouped split

- Train: {train_size["rows"]} rows / {train_size["concepts"]} concepts
- Validation: {validation_size["rows"]} rows / {validation_size["concepts"]} concepts
- Split hash: `{split["split_hash"]}`
- Leakage: PASS

Concept, paraphrase, translation, template, and lineage groups are isolated. Only 21 promoted
`REVIEWED`/`VERIFIED` gold rows entered the run.

## Exploratory metrics

- Recall: {overall["recall"]}
- Precision: {overall["precision"]}
- F1: {overall["f1"]}
- Benign FPR: {overall["benign_fpr"]}
- Confusion matrix: `{json.dumps(matrix, sort_keys=True)}`

These values are **not statistically meaningful**: validation contains only
{validation_size["malicious_rows"]} malicious and {validation_size["benign_rows"]} benign rows
across {validation_size["malicious_concepts"]} and {validation_size["benign_concepts"]} concepts.
Wilson intervals are recorded in the JSON metrics, but every denominator is too small for a stable
claim. Per-language and per-family rows are descriptive or explicitly marked insufficient.
Probabilities are uncalibrated.

## Active learning

- Unique untrusted rows scored: {len(score_rows)}
- Useful uncertainty ranking: {"YES" if useful_ranking else "NO"}
- Next review batch: {len(batch)} units
- Pseudo labels: 0

The ranking combines predictive entropy, deterministic disagreement, candidate-family and language
diversity, and cluster inconsistency. Every result remains machine-suggested and untrusted.

## Next action

{
        (
            "Stop the human-review loop and diagnose the one-class training collapse "
            "before collecting more data."
            if diagnostic_stop["triggered"]
            else f"Human-review the {len(batch)} selected Batch "
            f"{next_batch_number:02d} units only if continuing data acquisition is desired."
        )
    }
Do not select this model for production or use Blind Set E. A later training comparison needs
materially larger independent validation support before its metrics can guide selection.
"""
    _atomic_text(markdown_path, markdown)
    return report


def rescore_binary_research_classifier(
    artifact_path: Path,
    gold_path: Path,
    pool_path: Path,
    output_directory: Path,
    *,
    expected_base_freeze_sha256: str,
) -> dict[str, Any]:
    """Replace derived score/batch reports after verifying an existing frozen research artifact."""
    manifest_path = artifact_path / "research-artifact.json"
    report_path = output_directory / "v0.4.2-first-multilingual-research-training.json"
    if (
        manifest_path.is_symlink()
        or not manifest_path.is_file()
        or manifest_path.stat().st_size > 2_000_000
    ):
        raise ResearchTrainingError("research artifact manifest is missing or unsafe")
    if (
        report_path.is_symlink()
        or not report_path.is_file()
        or report_path.stat().st_size > 8_000_000
    ):
        raise ResearchTrainingError("research training report is missing or unsafe")
    try:
        artifact_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ResearchTrainingError("existing research metadata is invalid") from exc
    if not isinstance(artifact_manifest, dict) or not isinstance(report, dict):
        raise ResearchTrainingError("existing research metadata has an invalid shape")
    if artifact_manifest.get("base_model_freeze_sha256") != expected_base_freeze_sha256:
        raise ResearchTrainingError("research artifact base-model binding changed")
    if artifact_manifest.get("runtime_asset_hashes") != _runtime_asset_hashes(artifact_path):
        raise ResearchTrainingError("research artifact runtime asset hash mismatch")
    runtime_hashes = artifact_manifest["runtime_asset_hashes"]
    if canonical_sha256(runtime_hashes) != artifact_manifest.get("artifact_freeze_sha256"):
        raise ResearchTrainingError("research artifact freeze hash mismatch")
    if report.get("artifact", {}).get("identity") != artifact_manifest.get("identity"):
        raise ResearchTrainingError("research report/artifact identity mismatch")
    if _sha256_file(gold_path) != artifact_manifest.get("gold_corpus_file_sha256"):
        raise ResearchTrainingError("trusted-gold file binding changed")
    cases = _trusted_gold(gold_path)
    if corpus_hash(cases) != artifact_manifest.get("gold_corpus_semantic_sha256"):
        raise ResearchTrainingError("trusted-gold semantic binding changed")
    raw_config = artifact_manifest.get("training_configuration")
    if not isinstance(raw_config, dict):
        raise ResearchTrainingError("research training configuration is malformed")
    config = BinaryResearchConfig(
        seed=int(raw_config["seed"]),
        epochs=int(raw_config["epochs"]),
        batch_size=int(raw_config["batch_size"]),
        learning_rate=float(raw_config["learning_rate"]),
        max_length=int(raw_config["max_length"]),
        score_batch_size=int(raw_config["score_batch_size"]),
        decision_threshold=float(raw_config["decision_threshold"]),
        review_units=int(raw_config["review_units"]),
        minimum_validation_concepts_per_class=(
            int(raw_config["minimum_validation_concepts_per_class"])
            if "minimum_validation_concepts_per_class" in raw_config
            else None
        ),
        sampling_strategy=str(raw_config.get("sampling_strategy", "weighted-random")),
    )
    if canonical_sha256(config.to_dict()) != artifact_manifest.get("training_configuration_sha256"):
        raise ResearchTrainingError("research training configuration hash mismatch")
    split = research_grouped_split_analysis(
        cases,
        seed=config.seed,
        minimum_validation_concepts_per_class=(config.minimum_validation_concepts_per_class),
    )
    if split["split_hash"] != artifact_manifest.get("split_sha256"):
        raise ResearchTrainingError("grouped split binding changed")
    assigned = _assigned_cases(cases, split)
    validation = tuple(case for case in assigned if case.split == "validation")
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:
        raise ResearchTrainingError("local classifier runtime is unavailable") from exc
    with _network_blocked():
        tokenizer = AutoTokenizer.from_pretrained(
            str(artifact_path.resolve()),
            local_files_only=True,
            trust_remote_code=False,
            use_fast=True,
        )
        model = AutoModelForSequenceClassification.from_pretrained(
            str(artifact_path.resolve()),
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        )
        model.to("cpu")
        validation_probabilities = _model_batch_probabilities(
            model,
            tokenizer,
            [case.text for case in validation],
            batch_size=config.score_batch_size,
            max_length=config.max_length,
            torch=torch,
        )
        actual = [int(case.effective_binary_label is BinaryLabel.MALICIOUS) for case in validation]
        predicted = [int(value >= config.decision_threshold) for value in validation_probabilities]
        metrics = _metrics(actual, predicted)
        _add_prediction_distribution(metrics, validation_probabilities, predicted, actual)
        metrics["per_language"] = _dimension_metrics(validation, actual, predicted, "language")
        metrics["per_classifier_family"] = _dimension_metrics(
            validation, actual, predicted, "label"
        )
        metrics["threshold"] = config.decision_threshold
        metrics["probabilities_calibrated"] = False
        metrics["label"] = "EXPLORATORY / STATISTICALLY UNDERPOWERED"
        metrics["validation_predictions"] = [
            {
                "case_id": case.id,
                "concept_id": case.concept_id,
                "language": case.language,
                "classifier_family": case.label.value,
                "actual": case.effective_binary_label.value,
                "malicious_probability": round(probability, 6),
                "predicted": "malicious" if prediction else "benign",
            }
            for case, probability, prediction in zip(
                validation, validation_probabilities, predicted, strict=True
            )
        ]
        units = load_review_export(pool_path)
        pool_cases, concepts_by_case = _pool_cases(units, {case.id for case in cases})
        score_rows, scores_by_id = _score_pool(
            model,
            tokenizer,
            pool_cases,
            concepts_by_case,
            config=config,
            torch=torch,
        )
        del model, tokenizer
    useful_ranking = bool(
        len(score_rows) >= config.review_units
        and (
            len({round(cast(float, row["classifier_probability"]), 4) for row in score_rows}) > 1
            or any(bool(row["deterministic_disagreement"]) for row in score_rows)
        )
    )
    batch: list[dict[str, object]] = []
    batch_manifest: dict[str, object] | None = None
    if useful_ranking:
        batch, batch_manifest = _model_backed_batch(
            units,
            scores_by_id,
            {case.concept_id for case in cases},
            count=config.review_units,
            batch_number=4,
        )
    scores_path = output_directory / "v0.4.2-first-research-model-scores.jsonl"
    metrics_path = output_directory / "v0.4.2-first-research-model-metrics.json"
    batch_path = output_directory / "v0.4.2-active-learning-batch-04.jsonl"
    batch_manifest_path = output_directory / "v0.4.2-active-learning-batch-04-manifest.json"
    _write_jsonl(scores_path, score_rows)
    _write_json(metrics_path, metrics)
    if not batch or batch_manifest is None:
        raise ResearchTrainingError("corrected pool did not yield a useful minimal batch")
    _write_jsonl(batch_path, batch)
    batch_manifest.update(
        {
            "batch_sha256": _sha256_file(batch_path),
            "research_model_identity": artifact_manifest["identity"],
            "research_model_artifact_freeze_sha256": artifact_manifest["artifact_freeze_sha256"],
            "source_pool_path": pool_path.resolve().as_posix(),
            "source_pool_sha256": _sha256_file(pool_path),
            "scores_path": scores_path.resolve().as_posix(),
            "scores_sha256": _sha256_file(scores_path),
        }
    )
    _write_json(batch_manifest_path, batch_manifest)
    report["exploratory_metrics"] = metrics
    report["active_learning"] = {
        "untrusted_unique_rows_scored": len(score_rows),
        "useful_uncertainty_ranking": useful_ranking,
        "uncertain_rows_at_entropy_0_9_or_higher": sum(
            cast(float, row["entropy"]) >= 0.9 for row in score_rows
        ),
        "deterministic_disagreements": sum(
            bool(row["deterministic_disagreement"]) for row in score_rows
        ),
        "cluster_inconsistent_rows": sum(bool(row["cluster_inconsistent"]) for row in score_rows),
        "next_review_batch_size": len(batch),
        "batch": batch_path.resolve().as_posix(),
        "batch_manifest": batch_manifest_path.resolve().as_posix(),
        "scores": scores_path.resolve().as_posix(),
        "source_pool": pool_path.resolve().as_posix(),
        "source_pool_sha256": _sha256_file(pool_path),
        "rescored_from_verified_artifact": True,
    }
    _write_json(report_path, report)
    markdown_path = output_directory / "v0.4.2-first-multilingual-research-training.md"
    markdown = markdown_path.read_text(encoding="utf-8")
    markdown = markdown.replace(
        "- Recall: 0.0\n- Precision: None\n- F1: None\n",
        "- Recall: 0.0\n- Precision: 0.0\n- F1: 0.0\n",
    )
    markdown = markdown.replace(
        "- Unique untrusted rows scored: 1225\n",
        f"- Unique untrusted rows scored: {len(score_rows)}\n",
    )
    _atomic_text(markdown_path, markdown)
    return report
