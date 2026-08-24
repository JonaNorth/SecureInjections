"""Phase 2.1 influential-concept and threshold-policy diagnostics."""

from __future__ import annotations

import hashlib
import json
import os
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .classifier_data import ClassifierCase, conceptual_groups, corpus_hash
from .model_import import inspect_local_model, validate_local_model
from .phase2_validation import (
    CLASSIFIER_SEEDS,
    SPLIT_SEEDS,
    THRESHOLDS,
    Phase2Config,
    _build_split_artifact,
    _inner_oof_logits,
    _ranking_calibration_metrics,
    _summary,
    _threshold_metrics,
    _train_linear_logits,
    _validated_trusted_gold,
)
from .review_workflow import canonical_sha256

PHASE2_1_SCHEMA_VERSION = 1
POLICIES = (
    "A_fixed_050",
    "B_inner_balanced_accuracy",
    "C_inner_recall_fpr_010",
    "D_inner_recall_zero_fp",
    "E_inner_positive_gap_midpoint",
)


class Phase21DiagnosticsError(RuntimeError):
    """A Phase 2.1 integrity or diagnostic constraint failed."""


@dataclass(frozen=True, slots=True)
class Phase21Config:
    folds: int = 5
    inner_folds: int = 4
    classifier_seeds: tuple[int, ...] = CLASSIFIER_SEEDS
    split_seeds: tuple[int, ...] = SPLIT_SEEDS
    threshold_grid: tuple[float, ...] = THRESHOLDS
    linear_epochs: int = 250
    linear_learning_rate: float = 0.01
    weight_decay: float = 1e-4
    top_concepts: int = 3

    def phase2_config(self) -> Phase2Config:
        return Phase2Config(
            folds=self.folds,
            inner_folds=self.inner_folds,
            classifier_seeds=self.classifier_seeds,
            split_seeds=self.split_seeds,
            thresholds=self.threshold_grid,
            linear_epochs=self.linear_epochs,
            linear_learning_rate=self.linear_learning_rate,
            weight_decay=self.weight_decay,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "folds": self.folds,
            "inner_folds": self.inner_folds,
            "classifier_seeds": list(self.classifier_seeds),
            "split_seeds": list(self.split_seeds),
            "threshold_grid": list(self.threshold_grid),
            "linear_epochs": self.linear_epochs,
            "linear_learning_rate": self.linear_learning_rate,
            "weight_decay": self.weight_decay,
            "top_concepts": self.top_concepts,
            "representation": "attention-mask-mean-pooling-plus-l2-normalization",
            "head": "torch-linear-unweighted",
            "probabilities": "raw-sigmoid-no-calibration",
            "encoder_trainable": False,
            "policies": list(POLICIES),
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_text(path: Path, text: str) -> None:
    if path.is_symlink():
        raise Phase21DiagnosticsError(f"refusing to replace symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise Phase21DiagnosticsError(f"temporary artifact already exists: {temporary}")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_json(path: Path, value: object) -> None:
    _atomic_text(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _load_json(path: Path, *, maximum: int = 256 * 1024 * 1024) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise Phase21DiagnosticsError(f"unsafe or missing artifact: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Phase21DiagnosticsError(f"invalid JSON artifact: {path}") from exc


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024 * 1024:
        raise Phase21DiagnosticsError(f"unsafe or missing JSONL artifact: {path}")
    output: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise Phase21DiagnosticsError(f"invalid JSONL row: {path}")
        output.append(value)
    return output


def _phase2_artifacts(output_directory: Path) -> dict[str, Path]:
    return {
        "report": output_directory / "v0.4.2-phase2-frozen-linear-validation.json",
        "splits": output_directory / "v0.4.2-phase2-splits.json",
        "cache": output_directory / "v0.4.2-phase2-embedding-cache.npz",
        "cache_metadata": output_directory / "v0.4.2-phase2-embedding-cache-metadata.json",
        "runs": output_directory / "v0.4.2-phase2-per-run-results.jsonl",
        "predictions": output_directory / "v0.4.2-phase2-per-run-predictions.jsonl",
    }


def _validate_phase2_bindings(
    output_directory: Path,
    gold_path: Path,
    cases: tuple[ClassifierCase, ...],
    expected_freeze: str,
) -> tuple[dict[str, Any], dict[str, Any], Any, list[str], Any, list[dict[str, Any]]]:
    import numpy as np

    paths = _phase2_artifacts(output_directory)
    report = cast(dict[str, Any], _load_json(paths["report"]))
    if report.get("status") != "PHASE 2 FROZEN LINEAR VALIDATION COMPLETE":
        raise Phase21DiagnosticsError("Phase 2 report is not complete")
    if (
        report["gold"]["file_sha256"] != _sha256_file(gold_path)
        or report["gold"]["semantic_sha256"] != corpus_hash(cases)
        or report["encoder"]["directory_freeze_sha256"] != expected_freeze
        or report["safety"]["network_used"] is not False
    ):
        raise Phase21DiagnosticsError("Phase 2 report binding failed")
    for item in report["results"]["artifacts"].values():
        path = Path(item["path"])
        if _sha256_file(path) != item["sha256"]:
            raise Phase21DiagnosticsError(f"Phase 2 artifact hash changed: {path.name}")
    metadata = cast(dict[str, Any], _load_json(paths["cache_metadata"]))
    if (
        metadata["sha256"] != _sha256_file(paths["cache"])
        or metadata["gold_file_sha256"] != _sha256_file(gold_path)
        or metadata["base_model_freeze_sha256"] != expected_freeze
        or metadata["encoder_trainable"] is not False
        or metadata["network_used"] is not False
    ):
        raise Phase21DiagnosticsError("Phase 2 embedding cache binding failed")
    with np.load(paths["cache"], allow_pickle=False) as cache:
        if set(cache.files) != {
            "raw_embeddings",
            "l2_normalized_embeddings",
            "case_ids",
            "labels",
        }:
            raise Phase21DiagnosticsError("Phase 2 cache fields changed")
        matrix = cache["l2_normalized_embeddings"].copy()
        case_ids = cache["case_ids"].tolist()
        labels = cache["labels"].copy()
    if matrix.shape != (len(cases), 384) or not np.allclose(
        np.linalg.norm(matrix, axis=1), 1.0, atol=2e-6
    ):
        raise Phase21DiagnosticsError("Phase 2 normalized embeddings are invalid")
    splits = cast(dict[str, Any], _load_json(paths["splits"]))
    if canonical_sha256(splits["definitions"]) != splits["semantic_sha256"]:
        raise Phase21DiagnosticsError("Phase 2 split semantic hash changed")
    predictions = [
        item
        for item in _load_jsonl(paths["predictions"])
        if item["representation"] == "l2_normalized" and item["calibration"] == "raw"
    ]
    if len(predictions) != len(cases) * len(CLASSIFIER_SEEDS) * len(SPLIT_SEEDS):
        raise Phase21DiagnosticsError("Phase 2 canonical predictions are incomplete")
    return report, metadata, matrix, case_ids, labels, predictions


def _concept_ranking(
    cases: tuple[ClassifierCase, ...], predictions: list[dict[str, Any]]
) -> list[dict[str, object]]:
    by_concept: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in predictions:
        by_concept[str(item["concept_id"])].append(item)
    case_by_id = {case.id: case for case in cases}
    total_errors = sum(item["predicted_050"] != item["label"] for item in predictions)
    output: list[dict[str, object]] = []
    for concept_id, items in by_concept.items():
        concept_cases = [case for case in cases if case.concept_id == concept_id]
        probabilities = [float(item["probability"]) for item in items]
        errors = [item for item in items if item["predicted_050"] != item["label"]]
        false_negatives = sum(item["label"] == 1 for item in errors)
        false_positives = sum(item["label"] == 0 for item in errors)
        error_cells = {(item["split_seed"], item["outer_fold"]) for item in errors}
        output.append(
            {
                "concept_id": concept_id,
                "case_ids": sorted(case.id for case in concept_cases),
                "binary_label": concept_cases[0].effective_binary_label.value,
                "classifier_families": sorted({case.label.value for case in concept_cases}),
                "languages": sorted({case.language for case in concept_cases}),
                "repeated_validation_observations": len(items),
                "repeated_validation_error_count": len(errors),
                "false_negative_count": false_negatives,
                "false_positive_count": false_positives,
                "mean_predicted_score": round(statistics.fmean(probabilities), 6),
                "score_variance": round(statistics.pvariance(probabilities), 8),
                "mean_absolute_distance_from_050": round(
                    statistics.fmean(abs(value - 0.5) for value in probabilities), 6
                ),
                "misclassified_outer_fold_cells": len(error_cells),
                "misclassified_split_seeds": len({item["split_seed"] for item in errors}),
                "error_contribution": round(len(errors) / total_errors, 6) if total_errors else 0.0,
                "score": _summary(probabilities),
                "case_error_counts": {
                    case_id: sum(
                        item["case_id"] == case_id and item["predicted_050"] != item["label"]
                        for item in items
                    )
                    for case_id in sorted({item["case_id"] for item in items})
                },
                "review_ids": sorted(
                    cast(str, case_by_id[item["case_id"]].review_id)
                    for item in items
                    if case_by_id[item["case_id"]].review_id
                )[: len(concept_cases)],
            }
        )
    return sorted(
        output,
        key=lambda item: (
            -cast(int, item["repeated_validation_error_count"]),
            -cast(float, item["error_contribution"]),
            str(item["concept_id"]),
        ),
    )


def _nearest_opposite_concepts(
    concept_id: str,
    cases: tuple[ClassifierCase, ...],
    matrix: Any,
    case_ids: list[str],
    *,
    count: int = 5,
) -> list[dict[str, object]]:
    import numpy as np

    by_id = {case.id: case for case in cases}
    indexes = [
        index for index, case_id in enumerate(case_ids) if by_id[case_id].concept_id == concept_id
    ]
    target = by_id[case_ids[indexes[0]]].effective_binary_label
    centroid = matrix[indexes].mean(axis=0)
    centroid /= np.linalg.norm(centroid)
    values: list[dict[str, object]] = []
    for opposite_id in sorted(
        {case.concept_id for case in cases if case.effective_binary_label is not target}
    ):
        opposite_indexes = [
            index
            for index, case_id in enumerate(case_ids)
            if by_id[case_id].concept_id == opposite_id
        ]
        opposite = matrix[opposite_indexes].mean(axis=0)
        opposite /= np.linalg.norm(opposite)
        values.append(
            {
                "concept_id": opposite_id,
                "case_ids": sorted(case_ids[index] for index in opposite_indexes),
                "binary_label": by_id[case_ids[opposite_indexes[0]]].effective_binary_label.value,
                "cosine_similarity": round(float(centroid @ opposite), 6),
            }
        )
    return sorted(values, key=lambda item: -cast(float, item["cosine_similarity"]))[:count]


def _top_concept_diagnostics(
    ranking: list[dict[str, object]],
    cases: tuple[ClassifierCase, ...],
    matrix: Any,
    case_ids: list[str],
    count: int,
) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for rank, item in enumerate(ranking[:count], 1):
        concept_id = cast(str, item["concept_id"])
        members = [case for case in cases if case.concept_id == concept_id]
        nearest = _nearest_opposite_concepts(concept_id, cases, matrix, case_ids)
        multilingual = len({case.language for case in members}) > 1 or any(
            case.language != "en" for case in members
        )
        collision = bool(nearest and cast(float, nearest[0]["cosine_similarity"]) >= 0.85)
        supported_categories = [
            "A. genuinely difficult but representative",
            "E. sparse-evidence artifact",
        ]
        if collision:
            supported_categories.append("C. possible embedding-neighborhood collision")
        if multilingual:
            supported_categories.append("D. language-specific representation weakness")
        output.append(
            {
                "rank": rank,
                **item,
                "paraphrase_groups": sorted({case.paraphrase_group for case in members}),
                "translation_groups": sorted(
                    {case.translation_group for case in members if case.translation_group}
                ),
                "template_families": sorted({case.template_family for case in members}),
                "lineage": {
                    "parent_case_ids": sorted(
                        {case.parent_case_id for case in members if case.parent_case_id}
                    ),
                    "source_families": sorted({case.source_family for case in members}),
                },
                "hard_negative_categories": sorted(
                    {case.hard_negative_category for case in members if case.hard_negative_category}
                ),
                "nearest_opposite_class_concepts": nearest,
                "supported_diagnostic_categories": supported_categories,
                "taxonomy_ambiguity_B": "NOT INFERRED: unanimous active human review labels",
                "duplicated_semantic_boundary_F": (
                    "NOT INFERRED: formal duplicate and leakage audit passed; similarity alone "
                    "is insufficient"
                ),
                "repeated_error_pattern": (
                    f"{item['repeated_validation_error_count']} errors across "
                    f"{item['misclassified_outer_fold_cells']} outer cells and "
                    f"{item['misclassified_split_seeds']} split seeds"
                ),
            }
        )
    return output


def _candidate_thresholds(config: Phase21Config) -> list[float]:
    return [*config.threshold_grid, 1.0]


def _select_policies(labels: Any, probabilities: Any, config: Phase21Config) -> dict[str, Any]:
    grid = [
        _threshold_metrics(labels, probabilities, threshold) for threshold in config.threshold_grid
    ]
    extended = [
        _threshold_metrics(labels, probabilities, threshold)
        for threshold in _candidate_thresholds(config)
    ]

    def best(values: list[dict[str, object]], key: Any) -> dict[str, object]:
        return min(values, key=key)

    balanced = best(
        grid,
        lambda item: (
            -cast(float, item["balanced_accuracy"]),
            -cast(float, item["recall"]),
            cast(float, item["benign_fpr"]),
            -cast(float, item["threshold"]),
        ),
    )
    constrained = best(
        [item for item in extended if cast(float, item["benign_fpr"]) <= 0.10],
        lambda item: (
            -cast(float, item["recall"]),
            cast(float, item["benign_fpr"]),
            -cast(float, item["threshold"]),
        ),
    )
    zero_fp = best(
        [item for item in extended if cast(dict[str, int], item["confusion_matrix"])["fp"] == 0],
        lambda item: (
            -cast(float, item["recall"]),
            -cast(float, item["threshold"]),
        ),
    )
    highest_benign = float(probabilities[labels == 0].max())
    lowest_malicious = float(probabilities[labels == 1].min())
    gap = lowest_malicious - highest_benign
    midpoint = (highest_benign + lowest_malicious) / 2 if gap > 0 else None
    return {
        "A_fixed_050": {"status": "VALID", "threshold": 0.5},
        "B_inner_balanced_accuracy": {
            "status": "VALID",
            "threshold": balanced["threshold"],
            "inner_metrics": balanced,
        },
        "C_inner_recall_fpr_010": {
            "status": "VALID",
            "threshold": constrained["threshold"],
            "inner_metrics": constrained,
        },
        "D_inner_recall_zero_fp": {
            "status": "VALID",
            "threshold": zero_fp["threshold"],
            "inner_metrics": zero_fp,
        },
        "E_inner_positive_gap_midpoint": {
            "status": "VALID" if midpoint is not None else "FAILED_CLOSED_NO_POSITIVE_GAP",
            "threshold": round(midpoint, 8) if midpoint is not None else None,
            "inner_highest_benign": round(highest_benign, 8),
            "inner_lowest_malicious": round(lowest_malicious, 8),
            "inner_gap": round(gap, 8),
        },
    }


def _policy_run(labels: Any, probabilities: Any, selections: dict[str, Any]) -> dict[str, object]:
    output: dict[str, object] = {}
    for policy, selected in selections.items():
        if selected["status"] != "VALID":
            output[policy] = {
                **selected,
                "outer_metrics": None,
                "reject_all": False,
                "predict_all_malicious": False,
            }
            continue
        threshold = float(selected["threshold"])
        metrics = _threshold_metrics(labels, probabilities, threshold)
        output[policy] = {
            **selected,
            "outer_metrics": metrics,
            "reject_all": cast(int, metrics["predicted_malicious"]) == 0,
            "predict_all_malicious": cast(int, metrics["predicted_benign"]) == 0,
        }
    return output


def _score_separation(
    labels: Any,
    probabilities: Any,
    prediction_rows: list[dict[str, Any]],
) -> dict[str, object]:
    import numpy as np

    benign = probabilities[labels == 0]
    malicious = probabilities[labels == 1]
    highest_benign = float(benign.max())
    lowest_malicious = float(malicious.min())
    gap = lowest_malicious - highest_benign
    reversal_pairs = [
        {
            "benign_case_id": benign_item["case_id"],
            "benign_concept_id": benign_item["concept_id"],
            "benign_score": benign_item["probability"],
            "malicious_case_id": malicious_item["case_id"],
            "malicious_concept_id": malicious_item["concept_id"],
            "malicious_score": malicious_item["probability"],
        }
        for benign_item in prediction_rows
        if benign_item["label"] == 0
        for malicious_item in prediction_rows
        if malicious_item["label"] == 1
        if benign_item["probability"] >= malicious_item["probability"]
    ]

    def distribution(values: Any) -> dict[str, float]:
        return {
            "minimum": round(float(values.min()), 6),
            "maximum": round(float(values.max()), 6),
            "mean": round(float(values.mean()), 6),
            "median": round(float(np.median(values)), 6),
        }

    return {
        "benign": distribution(benign),
        "malicious": distribution(malicious),
        "class_margin_gap": round(gap, 6),
        "positive_ordering_gap": gap > 0,
        "overlap_interval": (
            None
            if gap > 0
            else {"lower": round(lowest_malicious, 6), "upper": round(highest_benign, 6)}
        ),
        "benign_fraction_above_lowest_malicious": round(
            float((benign >= lowest_malicious).mean()), 6
        ),
        "malicious_fraction_below_highest_benign": round(
            float((malicious <= highest_benign).mean()), 6
        ),
        "ranking_reversal_pairs": len(reversal_pairs),
        "reversal_pairs": reversal_pairs,
    }


def _run_repeated_validation(
    cases: tuple[ClassifierCase, ...],
    matrix: Any,
    case_ids: list[str],
    labels: Any,
    config: Phase21Config,
    *,
    excluded_concept: str | None = None,
    collect_separation: bool = False,
) -> list[dict[str, object]]:
    import numpy as np

    selected_cases = tuple(
        case for case in cases if excluded_concept is None or case.concept_id != excluded_concept
    )
    selected_ids = {case.id for case in selected_cases}
    index_by_id = {case_id: index for index, case_id in enumerate(case_ids)}
    splits = _build_split_artifact(selected_cases, config.phase2_config())
    output: list[dict[str, object]] = []
    case_by_id = {case.id: case for case in selected_cases}
    for definition in cast(list[dict[str, Any]], splits["definitions"]):
        outer = cast(dict[str, Any], definition["outer"])
        train_ids = cast(list[str], outer["train_case_ids"])
        validation_ids = cast(list[str], outer["validation_case_ids"])
        if not set(train_ids + validation_ids) <= selected_ids:
            raise Phase21DiagnosticsError("diagnostic split includes an excluded case")
        train_indexes = np.asarray([index_by_id[value] for value in train_ids], dtype="int64")
        validation_indexes = np.asarray(
            [index_by_id[value] for value in validation_ids], dtype="int64"
        )
        for classifier_seed in config.classifier_seeds:
            oof_logits, oof_labels, oof_ids = _inner_oof_logits(
                matrix,
                labels,
                index_by_id,
                cast(dict[str, object], definition["inner"]),
                classifier_seed=classifier_seed,
                config=config.phase2_config(),
            )
            if set(oof_ids) != set(train_ids):
                raise Phase21DiagnosticsError("inner OOF cases do not equal outer training cases")
            selections = _select_policies(oof_labels, _sigmoid(oof_logits), config)
            logits = _train_linear_logits(
                matrix[train_indexes],
                labels[train_indexes],
                matrix[validation_indexes],
                seed=classifier_seed,
                config=config.phase2_config(),
            )
            probabilities = _sigmoid(logits)
            prediction_rows = [
                {
                    "case_id": case_id,
                    "concept_id": case_by_id[case_id].concept_id,
                    "label": int(labels[validation_indexes[position]]),
                    "probability": round(float(probabilities[position]), 8),
                }
                for position, case_id in enumerate(validation_ids)
            ]
            ranking = _ranking_calibration_metrics(
                labels[validation_indexes], probabilities, bins=5
            )
            output.append(
                {
                    "split_seed": definition["split_seed"],
                    "outer_fold": outer["fold"],
                    "classifier_seed": classifier_seed,
                    "excluded_concept": excluded_concept,
                    "train_rows": len(train_indexes),
                    "validation_rows": len(validation_indexes),
                    "ranking": {
                        "roc_auc": ranking["roc_auc"],
                        "pr_auc": ranking["pr_auc"],
                    },
                    "fixed_050": _threshold_metrics(labels[validation_indexes], probabilities, 0.5),
                    "policy_selections": selections,
                    "policies": _policy_run(labels[validation_indexes], probabilities, selections),
                    "predictions": prediction_rows,
                    "score_separation": (
                        _score_separation(
                            labels[validation_indexes], probabilities, prediction_rows
                        )
                        if collect_separation
                        else None
                    ),
                }
            )
    return output


def _sigmoid(values: Any) -> Any:
    import numpy as np

    return 1.0 / (1.0 + np.exp(-np.clip(values, -80.0, 80.0)))


def _aggregate_runs(runs: list[dict[str, object]]) -> dict[str, object]:
    metrics = {
        metric: _summary(
            [
                float(
                    cast(dict[str, Any], run["ranking"])[metric]
                    if metric in {"roc_auc", "pr_auc"}
                    else cast(dict[str, Any], run["fixed_050"])[metric]
                )
                for run in runs
            ]
        )
        for metric in (
            "roc_auc",
            "pr_auc",
            "recall",
            "precision",
            "f1",
            "benign_fpr",
            "balanced_accuracy",
        )
    }
    thresholds = [
        float(cast(dict[str, Any], run["policy_selections"])["C_inner_recall_fpr_010"]["threshold"])
        for run in runs
    ]
    by_case: dict[str, dict[int, list[float]]] = defaultdict(lambda: defaultdict(list))
    for run in runs:
        for item in cast(list[dict[str, Any]], run["predictions"]):
            by_case[item["case_id"]][int(cast(int, run["split_seed"]))].append(
                float(item["probability"])
            )
    disagreement = []
    for split_values in by_case.values():
        decisions = {
            int(statistics.fmean(probabilities) >= 0.5) for probabilities in split_values.values()
        }
        disagreement.append(len(decisions) > 1)
    return {
        "runs": len(runs),
        "metrics_at_fixed_050": metrics,
        "policy_C_threshold": _summary(thresholds),
        "split_disagreement": {
            "cases": len(disagreement),
            "disagreements": sum(disagreement),
            "rate": round(sum(disagreement) / len(disagreement), 6),
        },
    }


def _leave_one_concept_out(
    top: list[dict[str, object]],
    baseline_runs: list[dict[str, object]],
    cases: tuple[ClassifierCase, ...],
    matrix: Any,
    case_ids: list[str],
    labels: Any,
    config: Phase21Config,
) -> dict[str, object]:
    baseline = _aggregate_runs(baseline_runs)
    output: dict[str, object] = {"full_37_row_baseline": baseline, "concepts": {}}
    for item in top:
        concept_id = cast(str, item["concept_id"])
        runs = _run_repeated_validation(
            cases,
            matrix,
            case_ids,
            labels,
            config,
            excluded_concept=concept_id,
        )
        aggregate = _aggregate_runs(runs)
        baseline_metrics = cast(dict[str, Any], baseline["metrics_at_fixed_050"])
        current_metrics = cast(dict[str, Any], aggregate["metrics_at_fixed_050"])
        aggregate["delta_mean_vs_full"] = {
            metric: round(
                float(current_metrics[metric]["mean"]) - float(baseline_metrics[metric]["mean"]),
                6,
            )
            for metric in baseline_metrics
        }
        aggregate["policy_C_threshold_sd_delta"] = round(
            float(cast(dict[str, Any], aggregate["policy_C_threshold"])["standard_deviation"])
            - float(cast(dict[str, Any], baseline["policy_C_threshold"])["standard_deviation"]),
            6,
        )
        aggregate["split_disagreement_rate_delta"] = round(
            float(cast(dict[str, Any], aggregate["split_disagreement"])["rate"])
            - float(cast(dict[str, Any], baseline["split_disagreement"])["rate"]),
            6,
        )
        cast(dict[str, object], output["concepts"])[concept_id] = aggregate
    return output


def _aggregate_separation(runs: list[dict[str, object]]) -> dict[str, object]:
    separations = [cast(dict[str, Any], run["score_separation"]) for run in runs]
    reversal_concepts: Counter[str] = Counter()
    for item in separations:
        for pair in item["reversal_pairs"]:
            reversal_concepts[pair["benign_concept_id"]] += 1
            reversal_concepts[pair["malicious_concept_id"]] += 1
    return {
        "cells": len(separations),
        "positive_gap_cells": sum(item["positive_ordering_gap"] for item in separations),
        "positive_gap_rate": round(
            sum(item["positive_ordering_gap"] for item in separations) / len(separations), 6
        ),
        "class_margin_gap": _summary([float(item["class_margin_gap"]) for item in separations]),
        "benign_fraction_above_lowest_malicious": _summary(
            [float(item["benign_fraction_above_lowest_malicious"]) for item in separations]
        ),
        "malicious_fraction_below_highest_benign": _summary(
            [float(item["malicious_fraction_below_highest_benign"]) for item in separations]
        ),
        "ranking_reversal_pairs": _summary(
            [float(item["ranking_reversal_pairs"]) for item in separations]
        ),
        "concept_participation_in_reversals": dict(reversal_concepts.most_common()),
        "mechanism": (
            "ranking reversals are concentrated in specific concept boundaries"
            if sum(item["ranking_reversal_pairs"] for item in separations)
            else "score translation/offset without ranking reversals"
        ),
    }


def _aggregate_policies(runs: list[dict[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for policy in POLICIES:
        values = [cast(dict[str, Any], run["policies"])[policy] for run in runs]
        valid = [item for item in values if item["status"] == "VALID"]
        metrics = [cast(dict[str, Any], item["outer_metrics"]) for item in valid]
        output[policy] = {
            "runs": len(values),
            "threshold": _summary([float(item["threshold"]) for item in valid]),
            "recall": _summary([float(item["recall"]) for item in metrics]),
            "precision": _summary([float(item["precision"]) for item in metrics]),
            "benign_fpr": _summary([float(item["benign_fpr"]) for item in metrics]),
            "balanced_accuracy": _summary([float(item["balanced_accuracy"]) for item in metrics]),
            "reject_all_frequency": round(
                sum(item["reject_all"] for item in valid) / len(values), 6
            ),
            "predict_all_malicious_frequency": round(
                sum(item["predict_all_malicious"] for item in valid) / len(values), 6
            ),
            "policy_failure_frequency": round((len(values) - len(valid)) / len(values), 6),
        }
    return output


def _metrics_from_predictions(
    labels: Any, probabilities: Any, threshold: float
) -> dict[str, object]:
    return _threshold_metrics(labels, probabilities, threshold)


def _threshold_transfer(runs: list[dict[str, object]]) -> dict[str, object]:
    import numpy as np

    output: dict[str, object] = {}
    for policy in POLICIES:
        transfers: list[dict[str, object]] = []
        source_thresholds: list[float] = []
        for classifier_seed in CLASSIFIER_SEEDS:
            for source_seed in SPLIT_SEEDS:
                source = [
                    run
                    for run in runs
                    if run["classifier_seed"] == classifier_seed
                    and run["split_seed"] == source_seed
                ]
                thresholds = [
                    float(cast(dict[str, Any], run["policies"])[policy]["threshold"])
                    for run in source
                    if cast(dict[str, Any], run["policies"])[policy]["status"] == "VALID"
                ]
                if not thresholds:
                    continue
                transferred_threshold = statistics.median(thresholds)
                source_thresholds.append(transferred_threshold)
                for target_seed in SPLIT_SEEDS:
                    if target_seed == source_seed:
                        continue
                    target = [
                        run
                        for run in runs
                        if run["classifier_seed"] == classifier_seed
                        and run["split_seed"] == target_seed
                    ]
                    prediction_rows = [
                        item
                        for run in target
                        for item in cast(list[dict[str, Any]], run["predictions"])
                    ]
                    labels = np.asarray([item["label"] for item in prediction_rows])
                    probabilities = np.asarray([item["probability"] for item in prediction_rows])
                    transferred = _metrics_from_predictions(
                        labels, probabilities, transferred_threshold
                    )
                    transferred_metrics = cast(dict[str, Any], transferred)
                    local_pairs = [
                        (run, cast(dict[str, Any], run["policies"])[policy])
                        for run in target
                        if cast(dict[str, Any], run["policies"])[policy]["status"] == "VALID"
                    ]
                    if len(local_pairs) != len(target):
                        continue
                    local_labels: list[int] = []
                    local_predictions: list[int] = []
                    for run, selected in local_pairs:
                        threshold = float(selected["threshold"])
                        for item in cast(list[dict[str, Any]], run["predictions"]):
                            local_labels.append(int(item["label"]))
                            local_predictions.append(int(item["probability"] >= threshold))
                    local = _metrics_from_binary(
                        np.asarray(local_labels), np.asarray(local_predictions)
                    )
                    transfers.append(
                        {
                            "classifier_seed": classifier_seed,
                            "source_split_seed": source_seed,
                            "target_split_seed": target_seed,
                            "transferred_threshold": round(transferred_threshold, 8),
                            "recall_degradation": round(
                                float(local["recall"]) - float(transferred_metrics["recall"]),
                                6,
                            ),
                            "fpr_degradation": round(
                                float(transferred_metrics["benign_fpr"])
                                - float(local["benign_fpr"]),
                                6,
                            ),
                            "balanced_accuracy_degradation": round(
                                float(local["balanced_accuracy"])
                                - float(transferred_metrics["balanced_accuracy"]),
                                6,
                            ),
                        }
                    )
        output[policy] = {
            "status": "TRANSFERRED" if transfers else "NO_STRUCTURALLY_TRANSFERABLE_CELLS",
            "transfers": len(transfers),
            "recall_degradation": (
                _summary([cast(float, item["recall_degradation"]) for item in transfers])
                if transfers
                else None
            ),
            "fpr_degradation": (
                _summary([cast(float, item["fpr_degradation"]) for item in transfers])
                if transfers
                else None
            ),
            "balanced_accuracy_degradation": (
                _summary([cast(float, item["balanced_accuracy_degradation"]) for item in transfers])
                if transfers
                else None
            ),
            "threshold_transfer_variance": (
                round(statistics.pvariance(source_thresholds), 8) if source_thresholds else None
            ),
            "source_threshold": _summary(source_thresholds) if source_thresholds else None,
            "per_transfer": transfers,
        }
    return output


def _metrics_from_binary(labels: Any, predicted: Any) -> dict[str, float]:
    tp = int(((labels == 1) & (predicted == 1)).sum())
    fp = int(((labels == 0) & (predicted == 1)).sum())
    tn = int(((labels == 0) & (predicted == 0)).sum())
    fn = int(((labels == 1) & (predicted == 0)).sum())
    recall = tp / (tp + fn)
    precision = tp / (tp + fp) if tp + fp else 0.0
    specificity = tn / (tn + fp)
    fpr = fp / (fp + tn)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "benign_fpr": fpr,
        "balanced_accuracy": (recall + specificity) / 2,
    }


def _decision(
    ranking: list[dict[str, object]],
    separation: dict[str, object],
    policies: dict[str, object],
    transfer: dict[str, object],
    top: list[dict[str, object]],
) -> dict[str, object]:
    top_share = sum(cast(float, item["error_contribution"]) for item in ranking[:3])
    reversal_counts = cast(dict[str, int], separation["concept_participation_in_reversals"])
    top_ids = {cast(str, item["concept_id"]) for item in top}
    reversal_total = sum(reversal_counts.values())
    top_reversal_share = (
        sum(count for concept, count in reversal_counts.items() if concept in top_ids)
        / reversal_total
        if reversal_total
        else 0.0
    )
    best_policy = min(
        POLICIES,
        key=lambda name: (
            float(cast(dict[str, Any], policies[name])["policy_failure_frequency"]),
            float(cast(dict[str, Any], policies[name])["benign_fpr"]["maximum"]),
            -float(cast(dict[str, Any], policies[name])["recall"]["minimum"]),
            (
                float(
                    cast(dict[str, Any], transfer[name])["balanced_accuracy_degradation"][
                        "standard_deviation"
                    ]
                )
                if cast(dict[str, Any], transfer[name])["balanced_accuracy_degradation"] is not None
                else float("inf")
            ),
        ),
    )
    best = cast(dict[str, Any], policies[best_policy])
    stabilized = (
        float(best["policy_failure_frequency"]) == 0
        and float(best["benign_fpr"]["maximum"]) <= 0.25
        and float(best["recall"]["minimum"]) >= 0.5
        and top_share <= 0.5
    )
    reversals_exist = cast(float, separation["positive_gap_rate"]) < 0.9
    embedding_collision = all(
        cast(
            float,
            cast(list[dict[str, object]], item["nearest_opposite_class_concepts"])[0][
                "cosine_similarity"
            ],
        )
        >= 0.85
        for item in top
    )
    offset_dominates = not reversals_exist
    concept_dominates = top_share > 0.75 and top_reversal_share > 0.60
    if stabilized:
        choice = "A. THRESHOLD POLICY STABILIZED"
        next_action = (
            "prepare an independent development evaluation plan without touching Blind Set E"
        )
    elif reversals_exist and embedding_collision:
        choice = "D. REPRESENTATION FAILURE EXISTS IN SPECIFIC CONCEPTS"
        next_action = (
            "design a representation-focused experiment around the three documented concept "
            "boundaries without adding labels or changing production state"
        )
    elif offset_dominates:
        choice = "C. SCORE OFFSET / CALIBRATION PROBLEM DOMINATES"
        next_action = "design calibration-focused Phase 2.2 without changing encoder/head capacity"
    else:
        choice = "B. CONCEPT-LEVEL INSTABILITY DOMINATES"
        next_action = (
            "define, but do not create, the smallest targeted evidence requirement for the "
            "influential concept boundaries"
        )
    return {
        "choice": choice,
        "best_policy_by_preregistered_robustness_order": best_policy,
        "mechanism_evidence": {
            "top_3_error_contribution": round(top_share, 6),
            "top_3_reversal_participation_share": round(top_reversal_share, 6),
            "positive_ordering_gap_rate": separation["positive_gap_rate"],
            "ranking_reversals_exist": reversals_exist,
            "all_top_concepts_have_opposite_class_cosine_at_least_085": embedding_collision,
            "score_offset_dominates": offset_dominates,
            "concept_dominance": concept_dominates,
            "threshold_policy_stabilized": stabilized,
        },
        "next_action": next_action,
    }


def run_phase2_1_diagnostics(
    gold_path: Path,
    model_path: Path,
    output_directory: Path,
    *,
    expected_base_freeze_sha256: str,
    config: Phase21Config | None = None,
) -> dict[str, object]:
    """Run concept influence and preregistered threshold diagnostics offline."""
    config = config or Phase21Config()
    output_directory = output_directory.resolve()
    paths = {
        "ranking": output_directory / "v0.4.2-phase2.1-influential-concept-ranking.json",
        "top": output_directory / "v0.4.2-phase2.1-top-3-concept-diagnostics.json",
        "loco": output_directory / "v0.4.2-phase2.1-leave-one-concept-out.json",
        "separation": output_directory / "v0.4.2-phase2.1-score-separation.json",
        "policies": output_directory / "v0.4.2-phase2.1-threshold-policies.json",
        "transfer": output_directory / "v0.4.2-phase2.1-threshold-transfer.json",
        "decision": output_directory / "v0.4.2-phase2.1-final-decision.json",
        "report": output_directory / "v0.4.2-phase2.1-diagnostics.json",
        "markdown": output_directory / "v0.4.2-phase2.1-diagnostics.md",
    }
    if any(path.exists() or path.is_symlink() for path in paths.values()):
        raise Phase21DiagnosticsError("a Phase 2.1 output artifact already exists")
    if (
        inspect_local_model(model_path).get("directory_freeze_sha256")
        != expected_base_freeze_sha256
    ):
        raise Phase21DiagnosticsError("encoder freeze changed before Phase 2.1")
    validated = validate_local_model(model_path)
    if (
        validated.get("validation") != "PASS"
        or validated.get("network_used") is not False
        or validated.get("directory_freeze_sha256") != expected_base_freeze_sha256
    ):
        raise Phase21DiagnosticsError("encoder failed offline validation")
    gold_hash_before = _sha256_file(gold_path)
    cases, provenance = _validated_trusted_gold(gold_path)
    phase2, cache_metadata, matrix, case_ids, labels, prior_predictions = _validate_phase2_bindings(
        output_directory, gold_path, cases, expected_base_freeze_sha256
    )
    ranking = _concept_ranking(cases, prior_predictions)
    top = _top_concept_diagnostics(ranking, cases, matrix, case_ids, config.top_concepts)
    _write_json(paths["ranking"], {"schema_version": 1, "concepts": ranking})
    _write_json(paths["top"], {"schema_version": 1, "concepts": top})
    started = time.perf_counter()
    baseline_runs = _run_repeated_validation(
        cases,
        matrix,
        case_ids,
        labels,
        config,
        collect_separation=True,
    )
    loco = _leave_one_concept_out(top, baseline_runs, cases, matrix, case_ids, labels, config)
    _write_json(paths["loco"], {"schema_version": 1, **loco})
    separation = {
        "schema_version": 1,
        "per_cell": [
            {
                "split_seed": run["split_seed"],
                "outer_fold": run["outer_fold"],
                "classifier_seed": run["classifier_seed"],
                **cast(dict[str, object], run["score_separation"]),
            }
            for run in baseline_runs
        ],
        "aggregate": _aggregate_separation(baseline_runs),
    }
    _write_json(paths["separation"], separation)
    policies = _aggregate_policies(baseline_runs)
    _write_json(
        paths["policies"],
        {
            "schema_version": 1,
            "selection_scope": "grouped inner OOF predictions from outer training only",
            "aggregate": policies,
            "per_run": [
                {
                    "split_seed": run["split_seed"],
                    "outer_fold": run["outer_fold"],
                    "classifier_seed": run["classifier_seed"],
                    "policies": run["policies"],
                }
                for run in baseline_runs
            ],
        },
    )
    transfer = _threshold_transfer(baseline_runs)
    _write_json(paths["transfer"], {"schema_version": 1, "policies": transfer})
    decision = _decision(
        ranking,
        cast(dict[str, object], separation["aggregate"]),
        policies,
        transfer,
        top,
    )
    _write_json(paths["decision"], {"schema_version": 1, **decision})
    if _sha256_file(gold_path) != gold_hash_before:
        raise Phase21DiagnosticsError("gold changed during Phase 2.1")
    if (
        inspect_local_model(model_path).get("directory_freeze_sha256")
        != expected_base_freeze_sha256
    ):
        raise Phase21DiagnosticsError("encoder changed during Phase 2.1")
    report: dict[str, object] = {
        "schema_version": PHASE2_1_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "PHASE 2.1 INFLUENTIAL-CONCEPT AND THRESHOLD DIAGNOSTICS COMPLETE",
        "gold": {
            "path": gold_path.resolve().as_posix(),
            "file_sha256": gold_hash_before,
            "semantic_sha256": corpus_hash(cases),
            "rows": len(cases),
            "concepts": len(conceptual_groups(cases)),
            "provenance_validation": provenance["validation"],
        },
        "encoder": validated,
        "phase2_binding": {
            "report_sha256": _sha256_file(_phase2_artifacts(output_directory)["report"]),
            "cache_sha256": cache_metadata["sha256"],
            "phase2_configuration_sha256": phase2["configuration_sha256"],
        },
        "configuration": config.to_dict(),
        "configuration_sha256": canonical_sha256(config.to_dict()),
        "top_3_concepts": top,
        "leave_one_concept_out": loco,
        "score_separation": separation["aggregate"],
        "threshold_policies": policies,
        "threshold_transfer": {
            policy: {
                key: value
                for key, value in cast(dict[str, Any], result).items()
                if key != "per_transfer"
            }
            for policy, result in transfer.items()
        },
        "decision": decision,
        "artifacts": {
            name: {"path": path.as_posix(), "sha256": _sha256_file(path)}
            for name, path in paths.items()
            if name not in {"report", "markdown"}
        },
        "runtime_seconds": round(time.perf_counter() - started, 3),
        "safety": {
            "network_used": False,
            "downloads": 0,
            "encoder_updated": False,
            "new_model_families": 0,
            "new_labels": 0,
            "human_review": False,
            "pseudo_labels": 0,
            "batch_06_created": False,
            "development_shadow_used": False,
            "independent_development_evaluation_started": False,
            "production_model_selected": None,
            "blind_set_e_burned": False,
        },
    }
    _write_json(paths["report"], report)
    mechanism = cast(dict[str, Any], decision["mechanism_evidence"])
    outer_cells = config.folds * len(config.split_seeds)
    markdown = f"""# SecureInjections v0.4.2 — Phase 2.1 diagnostics

Decision: **{decision["choice"]}**

- Gold: {len(cases)} rows / {len(conceptual_groups(cases))} independent concepts
- Frozen encoder: `{expected_base_freeze_sha256}`
- Representation/head: L2-normalized frozen embeddings / unweighted linear
- Outer cells / classifier seeds: {outer_cells} / {len(config.classifier_seeds)}
- Top-three error contribution: {mechanism["top_3_error_contribution"]}
- Positive ordering-gap rate: {mechanism["positive_ordering_gap_rate"]}
- Best preregistered policy: `{decision["best_policy_by_preregistered_robustness_order"]}`

The adjacent machine-readable artifacts contain every concept rank, top-three metadata and nearest
neighbors, leave-one-concept-out run, score-separation cell, threshold policy, and cross-split
transfer result.

Next action: {decision["next_action"]}.

No labels, review batch, encoder updates, production model, development shadow, network access, or
Blind Set E use occurred.
"""
    _atomic_text(paths["markdown"], markdown)
    return report
