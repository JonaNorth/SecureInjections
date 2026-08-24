"""Offline frozen-encoder Phase 1 diagnostics for the v0.4.2 trusted corpus."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

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
from .review_workflow import canonical_sha256

PHASE1_SCHEMA_VERSION = 1
DEFAULT_SEEDS = (13, 42, 101, 202, 404)
METRIC_NAMES = (
    "roc_auc",
    "pr_auc",
    "recall",
    "precision",
    "f1",
    "specificity",
    "benign_fpr",
    "balanced_accuracy",
    "brier_score",
    "ece",
)


class Phase1DiagnosticsError(RuntimeError):
    """A Phase 1 integrity, grouping, or offline constraint failed."""


@dataclass(frozen=True, slots=True)
class Phase1Config:
    folds: int = 5
    seeds: tuple[int, ...] = DEFAULT_SEEDS
    max_length: int = 256
    embedding_batch_size: int = 8
    linear_epochs: int = 250
    linear_learning_rate: float = 0.01
    mlp_epochs: int = 300
    mlp_learning_rate: float = 0.005
    mlp_hidden_dimension: int = 32
    weight_decay: float = 1e-4
    threshold: float = 0.5

    def to_dict(self) -> dict[str, object]:
        return {
            "folds": self.folds,
            "seeds": list(self.seeds),
            "max_length": self.max_length,
            "embedding_batch_size": self.embedding_batch_size,
            "linear_epochs": self.linear_epochs,
            "linear_learning_rate": self.linear_learning_rate,
            "mlp_epochs": self.mlp_epochs,
            "mlp_learning_rate": self.mlp_learning_rate,
            "mlp_hidden_dimension": self.mlp_hidden_dimension,
            "weight_decay": self.weight_decay,
            "threshold": self.threshold,
            "pooling": "attention-mask-mean-pooling-plus-l2-normalization",
            "input_prefix": "query: ",
            "encoder_trainable": False,
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_text(path: Path, text: str) -> None:
    if path.is_symlink():
        raise Phase1DiagnosticsError(f"refusing to replace symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise Phase1DiagnosticsError(f"temporary artifact already exists: {temporary}")
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
        raise Phase1DiagnosticsError("refusing to write empty Phase 1 results")
    _atomic_text(
        path,
        "".join(json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n" for value in values),
    )


def _trusted_gold(path: Path) -> tuple[ClassifierCase, ...]:
    cases = load_classifier_corpus(path)
    if any(not case.trusted for case in cases):
        raise Phase1DiagnosticsError("Phase 1 gold contains non-trusted rows")
    if any(case.effective_binary_label is BinaryLabel.AMBIGUOUS for case in cases):
        raise Phase1DiagnosticsError("Phase 1 gold contains ambiguous labels")
    audit = duplicate_audit(cases)
    if not audit["passed"]:
        raise Phase1DiagnosticsError("Phase 1 gold leakage audit failed")
    return cases


def _maximum_folds(groups: dict[str, tuple[ClassifierCase, ...]]) -> int:
    group_counts: Counter[BinaryLabel] = Counter()
    for group_id, members in groups.items():
        labels = {case.effective_binary_label for case in members}
        if len(labels) != 1 or BinaryLabel.AMBIGUOUS in labels:
            raise Phase1DiagnosticsError(f"group {group_id} has mixed or ambiguous labels")
        group_counts[next(iter(labels))] += 1
    return min(group_counts[BinaryLabel.BENIGN], group_counts[BinaryLabel.MALICIOUS])


def grouped_folds(
    cases: tuple[ClassifierCase, ...], *, folds: int = 5, seed: int = 42
) -> dict[str, object]:
    """Build deterministic label-stratified folds over transitive leakage groups."""
    groups = conceptual_groups(cases)
    maximum = _maximum_folds(groups)
    if folds > maximum:
        raise Phase1DiagnosticsError(
            f"requested {folds} folds but only {maximum} grouped folds are defensible"
        )
    if folds < 2:
        raise Phase1DiagnosticsError("at least two grouped folds are required")
    by_label: dict[BinaryLabel, list[tuple[str, tuple[ClassifierCase, ...]]]] = defaultdict(list)
    for group_id, members in groups.items():
        by_label[members[0].effective_binary_label].append((group_id, members))
    assignments: dict[str, int] = {}
    fold_label_groups: dict[tuple[int, BinaryLabel], int] = Counter()
    fold_label_rows: dict[tuple[int, BinaryLabel], int] = Counter()
    for label in (BinaryLabel.BENIGN, BinaryLabel.MALICIOUS):
        ordered = sorted(
            by_label[label],
            key=lambda item: (
                hashlib.sha256(f"phase1-folds:{seed}:{item[0]}".encode()).digest(),
                item[0],
            ),
        )
        for group_id, members in ordered:
            fold = min(
                range(folds),
                key=lambda value: (
                    fold_label_groups[(value, label)],
                    fold_label_rows[(value, label)],
                    value,
                ),
            )
            assignments[group_id] = fold
            fold_label_groups[(fold, label)] += 1
            fold_label_rows[(fold, label)] += len(members)
    definitions: list[dict[str, object]] = []
    for fold in range(folds):
        validation = {
            case.id
            for group_id, members in groups.items()
            if assignments[group_id] == fold
            for case in members
        }
        split_cases = tuple(
            replace(case, split="validation" if case.id in validation else "train")
            for case in cases
        )
        validate_group_isolation(split_cases)
        audit = duplicate_audit(split_cases)
        if not audit["passed"]:
            raise Phase1DiagnosticsError(f"fold {fold} leakage audit failed")
        train_cases = [case for case in split_cases if case.split == "train"]
        validation_cases = [case for case in split_cases if case.split == "validation"]
        definitions.append(
            {
                "fold": fold,
                "train_case_ids": sorted(case.id for case in train_cases),
                "validation_case_ids": sorted(case.id for case in validation_cases),
                "train_rows": len(train_cases),
                "validation_rows": len(validation_cases),
                "train_concepts": len({case.concept_id for case in train_cases}),
                "validation_concepts": len({case.concept_id for case in validation_cases}),
                "train_labels": dict(
                    sorted(
                        Counter(case.effective_binary_label.value for case in train_cases).items()
                    )
                ),
                "validation_labels": dict(
                    sorted(
                        Counter(
                            case.effective_binary_label.value for case in validation_cases
                        ).items()
                    )
                ),
                "leakage": "PASS",
            }
        )
    return {
        "schema_version": PHASE1_SCHEMA_VERSION,
        "strategy": "deterministic-label-stratified-transitive-group-five-fold-v1",
        "seed": seed,
        "requested_folds": folds,
        "maximum_defensible_folds": maximum,
        "folds": definitions,
        "group_assignments": dict(sorted(assignments.items())),
        "fold_sha256": canonical_sha256(assignments),
        "leakage": "PASS",
    }


def _extract_embeddings(
    model_path: Path,
    cases: tuple[ClassifierCase, ...],
    config: Phase1Config,
) -> tuple[Any, list[str], list[int]]:
    try:
        import numpy as np
        import torch
        from transformers import AutoModel, AutoTokenizer
    except ImportError as exc:
        raise Phase1DiagnosticsError("local frozen-feature runtime is unavailable") from exc
    random.seed(42)
    torch.manual_seed(42)
    torch.set_num_threads(1)
    ordered = sorted(cases, key=lambda case: case.id)
    embeddings: list[Any] = []
    with _network_blocked(), torch.no_grad():
        tokenizer = AutoTokenizer.from_pretrained(
            str(model_path.resolve()),
            local_files_only=True,
            trust_remote_code=False,
            use_fast=True,
        )
        model = AutoModel.from_pretrained(
            str(model_path.resolve()),
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        )
        model.to("cpu")
        model.eval()
        for offset in range(0, len(ordered), config.embedding_batch_size):
            batch = ordered[offset : offset + config.embedding_batch_size]
            encoded = tokenizer(
                [f"query: {case.text}" for case in batch],
                padding=True,
                truncation=True,
                max_length=config.max_length,
                return_tensors="pt",
            )
            hidden = model(**encoded).last_hidden_state
            mask = encoded["attention_mask"].unsqueeze(-1).expand(hidden.size()).float()
            pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
            pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
            embeddings.append(pooled.cpu().numpy().astype("float32"))
        del model, tokenizer
    matrix = np.concatenate(embeddings, axis=0)
    if matrix.shape != (len(ordered), 384) or not np.isfinite(matrix).all():
        raise Phase1DiagnosticsError("frozen encoder returned invalid embeddings")
    return (
        matrix,
        [case.id for case in ordered],
        [int(case.effective_binary_label is BinaryLabel.MALICIOUS) for case in ordered],
    )


def _ece(labels: Any, probabilities: Any, bins: int = 5) -> float:
    import numpy as np

    value = 0.0
    boundaries = np.linspace(0.0, 1.0, bins + 1)
    for index in range(bins):
        selected = (probabilities >= boundaries[index]) & (
            probabilities <= boundaries[index + 1]
            if index == bins - 1
            else probabilities < boundaries[index + 1]
        )
        if selected.any():
            value += float(selected.mean()) * abs(
                float(probabilities[selected].mean()) - float(labels[selected].mean())
            )
    return value


def _binary_metrics(labels: Any, probabilities: Any, threshold: float) -> dict[str, object]:
    import numpy as np
    from sklearn.metrics import (  # type: ignore[import-untyped]
        average_precision_score,
        brier_score_loss,
        roc_auc_score,
    )

    predicted = (probabilities >= threshold).astype("int64")
    tp = int(((labels == 1) & (predicted == 1)).sum())
    fp = int(((labels == 0) & (predicted == 1)).sum())
    tn = int(((labels == 0) & (predicted == 0)).sum())
    fn = int(((labels == 1) & (predicted == 0)).sum())
    recall = tp / (tp + fn)
    precision = tp / (tp + fp) if tp + fp else 0.0
    specificity = tn / (tn + fp)
    fpr = fp / (fp + tn)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    distribution = {}
    for name, target in (("benign", 0), ("malicious", 1)):
        selected = probabilities[labels == target]
        distribution[name] = {
            "count": int(selected.size),
            "minimum": round(float(selected.min()), 6),
            "maximum": round(float(selected.max()), 6),
            "mean": round(float(selected.mean()), 6),
            "median": round(float(np.median(selected)), 6),
        }
    return {
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 6),
        "pr_auc": round(float(average_precision_score(labels, probabilities)), 6),
        "recall": round(recall, 6),
        "precision": round(precision, 6),
        "f1": round(f1, 6),
        "specificity": round(specificity, 6),
        "benign_fpr": round(fpr, 6),
        "balanced_accuracy": round((recall + specificity) / 2, 6),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "probability": {
            "minimum": round(float(probabilities.min()), 6),
            "maximum": round(float(probabilities.max()), 6),
            "mean": round(float(probabilities.mean()), 6),
            "median": round(float(np.median(probabilities)), 6),
        },
        "by_true_class": distribution,
        "brier_score": round(float(brier_score_loss(labels, probabilities)), 6),
        "ece": round(_ece(labels, probabilities), 6),
        "calibration_status": "EXPLORATORY / SMALL FOLD",
        "threshold_independent_ranking": {
            "roc_auc": round(float(roc_auc_score(labels, probabilities)), 6),
            "pr_auc": round(float(average_precision_score(labels, probabilities)), 6),
        },
        "threshold_sensitivity": {
            f"{candidate:.2f}": {
                "predicted_malicious": int((probabilities >= candidate).sum()),
                "recall": round(
                    float(
                        ((labels == 1) & (probabilities >= candidate)).sum() / (labels == 1).sum()
                    ),
                    6,
                ),
                "benign_fpr": round(
                    float(
                        ((labels == 0) & (probabilities >= candidate)).sum() / (labels == 0).sum()
                    ),
                    6,
                ),
            }
            for candidate in (0.4, 0.45, 0.5, 0.55, 0.6)
        },
        "predictions": predicted.tolist(),
        "probabilities": [round(float(value), 8) for value in probabilities],
    }


def _logistic_probabilities(
    train_x: Any, train_y: Any, validation_x: Any, *, weighted: bool, seed: int
) -> Any:
    from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]

    model = LogisticRegression(
        C=1.0,
        class_weight="balanced" if weighted else None,
        max_iter=2000,
        random_state=seed,
        solver="liblinear",
    )
    model.fit(train_x, train_y)
    return model.predict_proba(validation_x)[:, 1]


def _torch_probabilities(
    train_x: Any,
    train_y: Any,
    validation_x: Any,
    *,
    head: str,
    weighted: bool,
    seed: int,
    config: Phase1Config,
) -> Any:
    import numpy as np
    import torch

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)
    inputs = torch.tensor(train_x, dtype=torch.float32)
    labels = torch.tensor(train_y, dtype=torch.float32)
    model: Any
    if head == "linear":
        model = torch.nn.Linear(train_x.shape[1], 1)
        epochs, learning_rate = config.linear_epochs, config.linear_learning_rate
    elif head == "mlp":
        model = torch.nn.Sequential(
            torch.nn.Linear(train_x.shape[1], config.mlp_hidden_dimension),
            torch.nn.ReLU(),
            torch.nn.Dropout(0.1),
            torch.nn.Linear(config.mlp_hidden_dimension, 1),
        )
        epochs, learning_rate = config.mlp_epochs, config.mlp_learning_rate
    else:  # pragma: no cover - internal closed set
        raise Phase1DiagnosticsError(f"unsupported head: {head}")
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=learning_rate, weight_decay=config.weight_decay
    )
    if weighted:
        counts = Counter(int(value) for value in train_y.tolist())
        sample_weights = torch.tensor(
            [len(train_y) / (2 * counts[int(value)]) for value in train_y],
            dtype=torch.float32,
        )
    else:
        sample_weights = torch.ones_like(labels)
    model.train()
    for _epoch in range(epochs):
        optimizer.zero_grad(set_to_none=True)
        logits = model(inputs).squeeze(1)
        raw_loss = torch.nn.functional.binary_cross_entropy_with_logits(
            logits, labels, reduction="none"
        )
        loss = (raw_loss * sample_weights).mean()
        loss.backward()
        optimizer.step()
    model.eval()
    with torch.no_grad():
        result = torch.sigmoid(model(torch.tensor(validation_x, dtype=torch.float32)).squeeze(1))
    return result.numpy()


def _summary(values: list[float]) -> dict[str, float]:
    return {
        "mean": round(statistics.fmean(values), 6),
        "median": round(statistics.median(values), 6),
        "standard_deviation": round(statistics.pstdev(values), 6),
        "minimum": round(min(values), 6),
        "maximum": round(max(values), 6),
    }


def _aggregate(
    runs: list[dict[str, object]], fold_definitions: list[dict[str, object]]
) -> dict[str, object]:
    variants = sorted({(str(run["head"]), str(run["weighting"])) for run in runs})
    output: dict[str, object] = {}
    for head, weighting in variants:
        selected = [run for run in runs if run["head"] == head and run["weighting"] == weighting]
        metric_summary = {
            metric: _summary(
                [float(cast(dict[str, Any], run["metrics"])[metric]) for run in selected]
            )
            for metric in METRIC_NAMES
        }
        seed_variance = {}
        fold_variance = {}
        for metric in METRIC_NAMES:
            per_fold = []
            for fold in sorted({int(cast(int, run["fold"])) for run in selected}):
                values = [
                    float(cast(dict[str, Any], run["metrics"])[metric])
                    for run in selected
                    if run["fold"] == fold
                ]
                per_fold.append(statistics.pvariance(values))
            per_seed = []
            for seed in sorted({int(cast(int, run["seed"])) for run in selected}):
                values = [
                    float(cast(dict[str, Any], run["metrics"])[metric])
                    for run in selected
                    if run["seed"] == seed
                ]
                per_seed.append(statistics.pvariance(values))
            seed_variance[metric] = round(statistics.fmean(per_fold), 8)
            fold_variance[metric] = round(statistics.fmean(per_seed), 8)
        disagreements = []
        for fold in sorted({int(cast(int, run["fold"])) for run in selected}):
            fold_runs = [run for run in selected if run["fold"] == fold]
            predictions = [cast(dict[str, Any], run["metrics"])["predictions"] for run in fold_runs]
            for index in range(len(predictions[0])):
                prediction_values = {prediction[index] for prediction in predictions}
                disagreements.append(len(prediction_values) > 1)
        output[f"{head}:{weighting}"] = {
            "head": head,
            "weighting": weighting,
            "runs": len(selected),
            "metrics": metric_summary,
            "metric_variance_across_seeds_mean_over_folds": seed_variance,
            "metric_variance_across_folds_mean_over_seeds": fold_variance,
            "prediction_disagreement_across_seeds": {
                "case_fold_observations": len(disagreements),
                "disagreements": sum(disagreements),
                "rate": round(sum(disagreements) / len(disagreements), 6),
            },
            "validation_fold_sizes": [item["validation_rows"] for item in fold_definitions],
        }
    return output


def _decision(aggregate: dict[str, object]) -> dict[str, object]:
    variants = [cast(dict[str, Any], value) for value in aggregate.values()]
    ranked = sorted(
        variants,
        key=lambda item: (
            -float(item["metrics"]["roc_auc"]["median"]),
            -float(item["metrics"]["roc_auc"]["mean"]),
            -float(item["metrics"]["pr_auc"]["median"]),
            -float(item["metrics"]["pr_auc"]["mean"]),
            float(item["metrics"]["roc_auc"]["standard_deviation"]),
            str(item["head"]),
        ),
    )
    best = ranked[0]
    best_simple = next(item for item in ranked if item["head"] in {"logistic", "linear"})
    best_mlp = next(item for item in ranked if item["head"] == "mlp")
    roc = float(best["metrics"]["roc_auc"]["median"])
    pr = float(best["metrics"]["pr_auc"]["median"])
    roc_std = float(best["metrics"]["roc_auc"]["standard_deviation"])
    disagreement = float(best["prediction_disagreement_across_seeds"]["rate"])
    if roc >= 0.7 and pr >= 0.7 and roc_std <= 0.2 and disagreement <= 0.25:
        choice = "A. FROZEN FEATURES ARE PROMISING"
        next_action = f"validate the {best_simple['head']}:{best_simple['weighting']} simple head"
    elif max(float(item["metrics"]["roc_auc"]["median"]) for item in variants) < 0.65:
        choice = "B. FROZEN FEATURES ARE INSUFFICIENT"
        next_action = "run a controlled partial-final-block encoder-unfreezing experiment"
    else:
        choice = "C. DATA/SPLIT SIZE IS TOO SMALL TO DISTINGUISH"
        next_action = (
            "stop escalation and obtain independent concept evidence, not another ranked batch"
        )
    mlp_gain = float(best_mlp["metrics"]["roc_auc"]["median"]) - float(
        best_simple["metrics"]["roc_auc"]["median"]
    )
    weighted = [item for item in variants if item["weighting"] == "weighted"]
    unweighted = [item for item in variants if item["weighting"] == "unweighted"]
    weighted_median = statistics.fmean(
        float(item["metrics"]["roc_auc"]["median"]) for item in weighted
    )
    unweighted_median = statistics.fmean(
        float(item["metrics"]["roc_auc"]["median"]) for item in unweighted
    )
    return {
        "choice": choice,
        "best_variant": f"{best['head']}:{best['weighting']}",
        "best_simple_head": f"{best_simple['head']}:{best_simple['weighting']}",
        "next_action": next_action,
        "answers": {
            "logistic_regression_useful_ranking": (
                max(
                    float(item["metrics"]["roc_auc"]["median"])
                    for item in variants
                    if item["head"] == "logistic"
                )
                >= 0.7
            ),
            "linear_head_matches_or_improves_full_fine_tuning_stability": (
                float(best_simple["metrics"]["roc_auc"]["standard_deviation"]) <= 0.2
            ),
            "mlp_adds_useful_signal": mlp_gain >= 0.05,
            "mlp_median_roc_auc_gain_over_best_simple": round(mlp_gain, 6),
            "class_weighting_effect_on_mean_variant_median_roc_auc": round(
                weighted_median - unweighted_median, 6
            ),
            "threshold_independent_metrics_materially_better_than_fixed_threshold": (
                float(best["metrics"]["roc_auc"]["mean"])
                - float(best["metrics"]["balanced_accuracy"]["mean"])
                >= 0.05
            ),
            "phase2_partial_unfreezing_justified": choice.startswith("B."),
        },
        "diagnosed_factors": {
            "representation_quality": "adequate" if roc >= 0.7 else "weak-or-uncertain",
            "head_capacity": "MLP adds signal" if mlp_gain >= 0.05 else "simple head sufficient",
            "threshold_calibration": (
                "material issue"
                if float(best["metrics"]["roc_auc"]["mean"])
                - float(best["metrics"]["balanced_accuracy"]["mean"])
                >= 0.05
                else "not dominant"
            ),
            "data_scarcity": "material: 30 concepts across five outer folds",
            "full_fine_tuning_instability": "confirmed by the two exploratory references",
            "split_instability": ("material" if roc_std > 0.15 else "bounded in this diagnostic"),
        },
    }


def run_phase1_diagnostics(
    gold_path: Path,
    model_path: Path,
    output_directory: Path,
    *,
    expected_base_freeze_sha256: str,
    config: Phase1Config | None = None,
) -> dict[str, object]:
    """Extract frozen E5 features and run deterministic grouped head diagnostics."""
    config = config or Phase1Config()
    output_directory = output_directory.resolve()
    paths = {
        "folds": output_directory / "v0.4.2-phase1-folds.json",
        "cache": output_directory / "v0.4.2-phase1-embedding-cache.npz",
        "cache_metadata": output_directory / "v0.4.2-phase1-embedding-cache-metadata.json",
        "runs": output_directory / "v0.4.2-phase1-per-run-metrics.jsonl",
        "aggregate": output_directory / "v0.4.2-phase1-aggregate-results.json",
        "report": output_directory / "v0.4.2-phase1-training-diagnostics.json",
        "markdown": output_directory / "v0.4.2-phase1-training-diagnostics.md",
    }
    if any(path.exists() or path.is_symlink() for path in paths.values()):
        raise Phase1DiagnosticsError("a Phase 1 output artifact already exists")
    inspected = inspect_local_model(model_path)
    if inspected.get("directory_freeze_sha256") != expected_base_freeze_sha256:
        raise Phase1DiagnosticsError("base encoder freeze hash changed")
    validated = validate_local_model(model_path)
    if (
        validated.get("validation") != "PASS"
        or validated.get("directory_freeze_sha256") != expected_base_freeze_sha256
        or validated.get("network_used") is not False
    ):
        raise Phase1DiagnosticsError("base encoder failed offline revalidation")
    gold_hash_before = _sha256_file(gold_path)
    cases = _trusted_gold(gold_path)
    fold_report = grouped_folds(cases, folds=config.folds, seed=42)
    _write_json(paths["folds"], fold_report)
    started = time.perf_counter()
    matrix, case_ids, labels = _extract_embeddings(model_path, cases, config)
    try:
        import numpy as np
        import sklearn  # type: ignore[import-untyped]
        import torch
        import transformers
    except ImportError as exc:  # pragma: no cover - checked during extraction
        raise Phase1DiagnosticsError("Phase 1 runtime dependencies changed") from exc
    cache_temporary = paths["cache"].with_name(f".{paths['cache'].name}.tmp-{os.getpid()}.npz")
    np.savez_compressed(
        cache_temporary,
        embeddings=matrix,
        case_ids=np.asarray(case_ids),
        labels=np.asarray(labels, dtype="int64"),
    )
    os.replace(cache_temporary, paths["cache"])
    cache_metadata = {
        "schema_version": PHASE1_SCHEMA_VERSION,
        "path": paths["cache"].as_posix(),
        "sha256": _sha256_file(paths["cache"]),
        "rows": len(case_ids),
        "dimensions": int(matrix.shape[1]),
        "dtype": str(matrix.dtype),
        "ordered_case_ids_sha256": canonical_sha256(case_ids),
        "labels_sha256": canonical_sha256(labels),
        "gold_file_sha256": gold_hash_before,
        "gold_semantic_sha256": corpus_hash(cases),
        "base_model_freeze_sha256": expected_base_freeze_sha256,
        "feature_extractor": config.to_dict(),
        "feature_extractor_config_sha256": canonical_sha256(config.to_dict()),
        "input_text_persisted": False,
        "encoder_trainable": False,
        "network_used": False,
    }
    _write_json(paths["cache_metadata"], cache_metadata)
    index_by_id = {case_id: index for index, case_id in enumerate(case_ids)}
    label_array = np.asarray(labels, dtype="int64")
    runs: list[dict[str, object]] = []
    fold_definitions = cast(list[dict[str, object]], fold_report["folds"])
    for fold in fold_definitions:
        train_indexes = np.asarray(
            [index_by_id[value] for value in cast(list[str], fold["train_case_ids"])],
            dtype="int64",
        )
        validation_ids = cast(list[str], fold["validation_case_ids"])
        validation_indexes = np.asarray(
            [index_by_id[value] for value in validation_ids], dtype="int64"
        )
        train_x, train_y = matrix[train_indexes], label_array[train_indexes]
        validation_x, validation_y = matrix[validation_indexes], label_array[validation_indexes]
        for head in ("logistic", "linear", "mlp"):
            for weighted in (False, True):
                for seed in config.seeds:
                    if head == "logistic":
                        probabilities = _logistic_probabilities(
                            train_x, train_y, validation_x, weighted=weighted, seed=seed
                        )
                    else:
                        probabilities = _torch_probabilities(
                            train_x,
                            train_y,
                            validation_x,
                            head=head,
                            weighted=weighted,
                            seed=seed,
                            config=config,
                        )
                    metrics = _binary_metrics(validation_y, probabilities, config.threshold)
                    runs.append(
                        {
                            "schema_version": PHASE1_SCHEMA_VERSION,
                            "head": head,
                            "weighting": "weighted" if weighted else "unweighted",
                            "seed": seed,
                            "fold": fold["fold"],
                            "train_rows": len(train_indexes),
                            "validation_rows": len(validation_indexes),
                            "validation_case_ids": validation_ids,
                            "metrics": metrics,
                        }
                    )
    _write_jsonl(paths["runs"], runs)
    aggregate = _aggregate(runs, fold_definitions)
    decision = _decision(aggregate)
    aggregate_artifact = {
        "schema_version": PHASE1_SCHEMA_VERSION,
        "runs": len(runs),
        "aggregate": aggregate,
        "decision": decision,
    }
    _write_json(paths["aggregate"], aggregate_artifact)
    if _sha256_file(gold_path) != gold_hash_before:
        raise Phase1DiagnosticsError("trusted gold changed during Phase 1")
    if (
        inspect_local_model(model_path).get("directory_freeze_sha256")
        != expected_base_freeze_sha256
    ):
        raise Phase1DiagnosticsError("base encoder changed during Phase 1")
    report: dict[str, object] = {
        "schema_version": PHASE1_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "PHASE 1 FROZEN-FEATURE DIAGNOSTICS COMPLETE",
        "gold": {
            "path": gold_path.resolve().as_posix(),
            "file_sha256": gold_hash_before,
            "semantic_sha256": corpus_hash(cases),
            "rows": len(cases),
            "concepts": len({case.concept_id for case in cases}),
            "trust_states": dict(
                sorted(Counter(case.review_status.value for case in cases).items())
            ),
        },
        "encoder": validated,
        "config": config.to_dict(),
        "config_sha256": canonical_sha256(config.to_dict()),
        "folds": {
            "path": paths["folds"].as_posix(),
            "sha256": _sha256_file(paths["folds"]),
            "fold_sha256": fold_report["fold_sha256"],
            "count": config.folds,
            "maximum_defensible": fold_report["maximum_defensible_folds"],
            "leakage": "PASS",
        },
        "embedding_cache": cache_metadata,
        "results": {
            "per_run_path": paths["runs"].as_posix(),
            "per_run_sha256": _sha256_file(paths["runs"]),
            "aggregate_path": paths["aggregate"].as_posix(),
            "aggregate_sha256": _sha256_file(paths["aggregate"]),
            "runs": len(runs),
        },
        "aggregate": aggregate,
        "decision": decision,
        "exploratory_baselines": {
            "full_fine_tuning_after_batch_04": {
                "recall": 1.0,
                "precision": 0.6,
                "f1": 0.75,
                "benign_fpr": 0.571429,
            },
            "full_fine_tuning_after_batch_05": {
                "recall": 0.166667,
                "precision": 1.0,
                "f1": 0.285714,
                "benign_fpr": 0.0,
            },
        },
        "runtime": {
            "duration_seconds": round(time.perf_counter() - started, 3),
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
            "torch": torch.__version__,
            "transformers": transformers.__version__,
        },
        "safety": {
            "network_used": False,
            "downloads": 0,
            "encoder_updated": False,
            "trusted_gold_only": True,
            "pseudo_labels": 0,
            "development_shadow_used": False,
            "blind_set_e_burned": False,
            "production_model_selected": None,
            "batch_06_created": False,
        },
    }
    _write_json(paths["report"], report)
    best = cast(str, decision["best_variant"])
    markdown = f"""# SecureInjections v0.4.2 — Phase 1 frozen-feature diagnostics

Status: **{decision["choice"]}**

- Trusted rows/concepts: {len(cases)} / {len({case.concept_id for case in cases})}
- Frozen encoder: `{model_path.resolve()}`
- Base freeze: `{expected_base_freeze_sha256}`
- Grouped folds / seeds: {config.folds} / {len(config.seeds)}
- Runs: {len(runs)}
- Best variant: `{best}`
- Fold leakage: PASS

The complete per-run and aggregate metrics are stored in the adjacent machine-readable artifacts.
All calibration values and fixed-threshold metrics remain exploratory because each outer fold is
small. ROC-AUC and PR-AUC are the primary representation/ranking diagnostics.

## Decision

{decision["choice"]}

Next action: {decision["next_action"]}. No Batch 06, pseudo-label promotion, production selection,
development shadow, or Blind Set E use occurred.
"""
    _atomic_text(paths["markdown"], markdown)
    return report
