"""Offline Phase 2 validation for the frozen multilingual encoder and linear head."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .active_learning import _validate_promoted_source
from .classifier_data import (
    BinaryLabel,
    ClassifierCase,
    conceptual_groups,
    corpus_hash,
    duplicate_audit,
    load_classifier_corpus,
)
from .model_import import _network_blocked, inspect_local_model, validate_local_model
from .phase1_diagnostics import grouped_folds
from .review_workflow import REVIEW_WORKFLOW_VERSION, canonical_sha256

PHASE2_SCHEMA_VERSION = 1
CLASSIFIER_SEEDS = (13, 42, 101, 202, 404)
SPLIT_SEEDS = (42, 73, 211, 997, 2027)
THRESHOLDS = (0.30, 0.35, 0.40, 0.45, 0.475, 0.50, 0.525, 0.55, 0.60, 0.65, 0.70)
THRESHOLD_METRICS = (
    "recall",
    "precision",
    "f1",
    "specificity",
    "benign_fpr",
    "balanced_accuracy",
    "predicted_malicious",
    "predicted_benign",
)
RANKING_CALIBRATION_METRICS = ("roc_auc", "pr_auc", "brier_score", "ece")


class Phase2ValidationError(RuntimeError):
    """A Phase 2 integrity, leakage, or offline constraint failed."""


@dataclass(frozen=True, slots=True)
class Phase2Config:
    folds: int = 5
    inner_folds: int = 4
    classifier_seeds: tuple[int, ...] = CLASSIFIER_SEEDS
    split_seeds: tuple[int, ...] = SPLIT_SEEDS
    thresholds: tuple[float, ...] = THRESHOLDS
    max_length: int = 256
    embedding_batch_size: int = 8
    linear_epochs: int = 250
    linear_learning_rate: float = 0.01
    weight_decay: float = 1e-4
    ece_bins: int = 5

    def to_dict(self) -> dict[str, object]:
        return {
            "folds": self.folds,
            "inner_folds": self.inner_folds,
            "classifier_seeds": list(self.classifier_seeds),
            "split_seeds": list(self.split_seeds),
            "thresholds": list(self.thresholds),
            "max_length": self.max_length,
            "embedding_batch_size": self.embedding_batch_size,
            "linear_epochs": self.linear_epochs,
            "linear_learning_rate": self.linear_learning_rate,
            "weight_decay": self.weight_decay,
            "pooling": "attention-mask-mean-pooling",
            "input_prefix": "query: ",
            "representations": ["raw", "l2_normalized"],
            "head": "torch-linear-unweighted",
            "encoder_trainable": False,
            "calibration": {
                "raw": "sigmoid-of-linear-logit",
                "platt": "logistic-regression-fit-on-grouped-inner-OOF-logits",
                "isotonic": "rejected-underpowered-before-run",
            },
            "operating_point_selection": "grouped-inner-OOF-only",
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_text(path: Path, text: str) -> None:
    if path.is_symlink():
        raise Phase2ValidationError(f"refusing to replace symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise Phase2ValidationError(f"temporary artifact already exists: {temporary}")
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
        raise Phase2ValidationError("refusing to write empty Phase 2 results")
    _atomic_text(
        path,
        "".join(json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n" for value in values),
    )


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise Phase2ValidationError(f"unsafe or missing JSON artifact: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Phase2ValidationError(f"invalid JSON artifact: {path}") from exc
    if not isinstance(value, dict):
        raise Phase2ValidationError(f"JSON artifact must be an object: {path}")
    return value


def _manifest_for_gold(gold_path: Path) -> Path:
    candidate = gold_path.with_name(f"{gold_path.stem}-manifest.json")
    if not candidate.is_file() or candidate.is_symlink():
        raise Phase2ValidationError("trusted gold manifest is missing or unsafe")
    return candidate


def _validated_trusted_gold(gold_path: Path) -> tuple[tuple[ClassifierCase, ...], dict[str, Any]]:
    """Revalidate the combined manifest and every original promoted source."""
    manifest_path = _manifest_for_gold(gold_path)
    manifest = _load_json(manifest_path)
    cases = load_classifier_corpus(gold_path)
    required_manifest = {
        "schema_version": 1,
        "workflow_version": REVIEW_WORKFLOW_VERSION,
        "classifier_schema_version": 2,
        "review_schema_version": 1,
        "trust_state": "TRUSTED_GOLD",
        "combined_corpus_path": gold_path.resolve().as_posix(),
        "combined_corpus_file_sha256": _sha256_file(gold_path),
        "combined_corpus_semantic_sha256": corpus_hash(cases),
        "trusted_rows": len(cases),
        "source_files_mutated": False,
        "development_shadow_used": False,
        "blind_set_e_burned": False,
        "production_model_selected": None,
    }
    conflicts = [
        name for name, expected in required_manifest.items() if manifest.get(name) != expected
    ]
    if conflicts:
        raise Phase2ValidationError(
            "combined gold manifest binding failed: " + ", ".join(conflicts)
        )
    if any(not case.trusted for case in cases):
        raise Phase2ValidationError("combined gold contains a non-trusted row")
    if any(case.effective_binary_label is BinaryLabel.AMBIGUOUS for case in cases):
        raise Phase2ValidationError("combined gold contains an ambiguous label")
    if any(
        not case.review_id
        or not case.review_record_hash
        or not case.original_content_hash
        or not case.original_metadata_hash
        for case in cases
    ):
        raise Phase2ValidationError("combined gold lacks hash-bound review provenance")
    stale_content = [
        case.id
        for case in cases
        if hashlib.sha256(case.text.encode("utf-8")).hexdigest() != case.original_content_hash
    ]
    if stale_content:
        raise Phase2ValidationError(f"combined gold contains stale content: {stale_content[0]}")
    audit = duplicate_audit(cases)
    if not audit["passed"]:
        raise Phase2ValidationError("combined gold duplicate/leakage audit failed")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        raise Phase2ValidationError("combined gold manifest has no source bindings")
    source_cases: dict[str, ClassifierCase] = {}
    source_audits: list[dict[str, object]] = []
    for source in sources:
        if not isinstance(source, dict):
            raise Phase2ValidationError("combined gold has malformed source binding")
        try:
            corpus_path = Path(source["corpus_path"])
            history_path = Path(source["history_path"])
            promotion_path = Path(source["promotion_manifest_path"])
        except (KeyError, TypeError) as exc:
            raise Phase2ValidationError("combined gold source binding is incomplete") from exc
        expected_hashes = {
            "corpus_file_sha256": _sha256_file(corpus_path),
            "history_sha256": _sha256_file(history_path),
            "promotion_manifest_sha256": _sha256_file(promotion_path),
        }
        mismatches = [name for name, value in expected_hashes.items() if source.get(name) != value]
        if mismatches:
            raise Phase2ValidationError("source binding hash failed: " + ", ".join(mismatches))
        promoted, promotion = _validate_promoted_source(corpus_path, history_path, promotion_path)
        if source.get("corpus_semantic_sha256") != corpus_hash(promoted):
            raise Phase2ValidationError("source semantic hash is stale")
        for case in promoted:
            previous = source_cases.get(case.id)
            if previous is not None and previous.to_dict() != case.to_dict():
                raise Phase2ValidationError(f"conflicting promoted metadata for {case.id}")
            source_cases[case.id] = case
        source_audits.append(
            {
                "corpus_path": corpus_path.as_posix(),
                "rows": len(promoted),
                "active_reviews": promotion["active_reviews"],
                **expected_hashes,
                "validation": "PASS",
            }
        )
    combined_by_id = {case.id: case for case in cases}
    if set(source_cases) != set(combined_by_id):
        raise Phase2ValidationError("combined/source case sets differ")
    for case_id, case in combined_by_id.items():
        if case.to_dict() != source_cases[case_id].to_dict():
            raise Phase2ValidationError(f"combined row differs from promoted source: {case_id}")
    if manifest.get("review_ids") != [case.review_id for case in cases]:
        raise Phase2ValidationError("combined review ID order/binding is stale")
    return cases, {
        "manifest_path": manifest_path.as_posix(),
        "manifest_sha256": _sha256_file(manifest_path),
        "sources": source_audits,
        "active_review_bindings": len(cases),
        "stale_content_hashes": 0,
        "stale_metadata_or_review_bindings": 0,
        "duplicate_audit": audit,
        "validation": "PASS",
    }


def _extract_raw_embeddings(
    model_path: Path, cases: tuple[ClassifierCase, ...], config: Phase2Config
) -> tuple[Any, list[str], list[int]]:
    try:
        import numpy as np
        import torch
        from transformers import AutoModel, AutoTokenizer
    except ImportError as exc:
        raise Phase2ValidationError("local frozen-feature runtime is unavailable") from exc
    random.seed(42)
    torch.manual_seed(42)
    torch.set_num_threads(1)
    ordered = sorted(cases, key=lambda case: case.id)
    embeddings: list[Any] = []
    with _network_blocked(), torch.no_grad():
        tokenizer = AutoTokenizer.from_pretrained(
            str(model_path.resolve()), local_files_only=True, trust_remote_code=False, use_fast=True
        )
        model = AutoModel.from_pretrained(
            str(model_path.resolve()),
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        )
        model.to("cpu")
        model.eval()
        if any(parameter.requires_grad for parameter in model.parameters()):
            for parameter in model.parameters():
                parameter.requires_grad_(False)
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
            embeddings.append(pooled.cpu().numpy().astype("float32"))
        del model, tokenizer
    matrix = np.concatenate(embeddings, axis=0)
    if matrix.shape != (len(ordered), 384) or not np.isfinite(matrix).all():
        raise Phase2ValidationError("frozen encoder returned invalid embeddings")
    return (
        matrix,
        [case.id for case in ordered],
        [int(case.effective_binary_label is BinaryLabel.MALICIOUS) for case in ordered],
    )


def _l2_normalize(matrix: Any) -> Any:
    import numpy as np

    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    if (norms <= 0).any():
        raise Phase2ValidationError("zero-norm frozen embedding")
    return (matrix / norms).astype("float32")


def _train_linear_logits(
    train_x: Any,
    train_y: Any,
    evaluation_x: Any,
    *,
    seed: int,
    config: Phase2Config,
) -> Any:
    import numpy as np
    import torch

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)
    inputs = torch.tensor(train_x, dtype=torch.float32)
    labels = torch.tensor(train_y, dtype=torch.float32)
    model = torch.nn.Linear(train_x.shape[1], 1)
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=config.linear_learning_rate, weight_decay=config.weight_decay
    )
    model.train()
    for _epoch in range(config.linear_epochs):
        optimizer.zero_grad(set_to_none=True)
        logits = model(inputs).squeeze(1)
        loss = torch.nn.functional.binary_cross_entropy_with_logits(logits, labels)
        loss.backward()
        optimizer.step()
    model.eval()
    with torch.no_grad():
        result = model(torch.tensor(evaluation_x, dtype=torch.float32)).squeeze(1)
    return result.numpy()


def _sigmoid(logits: Any) -> Any:
    import numpy as np

    clipped = np.clip(logits, -80.0, 80.0)
    return 1.0 / (1.0 + np.exp(-clipped))


def _fit_platt(logits: Any, labels: Any, *, seed: int) -> Any:
    from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]

    model = LogisticRegression(C=1.0, max_iter=2000, random_state=seed, solver="liblinear")
    model.fit(logits.reshape(-1, 1), labels)
    return model


def _reliability(labels: Any, probabilities: Any, *, bins: int) -> list[dict[str, object]]:
    import numpy as np

    output: list[dict[str, object]] = []
    boundaries = np.linspace(0.0, 1.0, bins + 1)
    for index in range(bins):
        selected = (probabilities >= boundaries[index]) & (
            probabilities <= boundaries[index + 1]
            if index == bins - 1
            else probabilities < boundaries[index + 1]
        )
        count = int(selected.sum())
        output.append(
            {
                "lower": round(float(boundaries[index]), 6),
                "upper": round(float(boundaries[index + 1]), 6),
                "count": count,
                "mean_confidence": (
                    round(float(probabilities[selected].mean()), 6) if count else None
                ),
                "observed_malicious_rate": (
                    round(float(labels[selected].mean()), 6) if count else None
                ),
            }
        )
    return output


def _ece(labels: Any, probabilities: Any, *, bins: int) -> float:
    reliability = _reliability(labels, probabilities, bins=bins)
    total = len(labels)
    return sum(
        cast(int, bucket["count"])
        / total
        * abs(
            cast(float, bucket["mean_confidence"]) - cast(float, bucket["observed_malicious_rate"])
        )
        for bucket in reliability
        if bucket["count"]
    )


def _threshold_metrics(labels: Any, probabilities: Any, threshold: float) -> dict[str, object]:
    predicted = probabilities >= threshold
    tp = int(((labels == 1) & predicted).sum())
    fp = int(((labels == 0) & predicted).sum())
    tn = int(((labels == 0) & ~predicted).sum())
    fn = int(((labels == 1) & ~predicted).sum())
    recall = tp / (tp + fn)
    precision = tp / (tp + fp) if tp + fp else 0.0
    specificity = tn / (tn + fp)
    fpr = fp / (fp + tn)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "threshold": threshold,
        "recall": round(recall, 6),
        "precision": round(precision, 6),
        "f1": round(f1, 6),
        "specificity": round(specificity, 6),
        "benign_fpr": round(fpr, 6),
        "balanced_accuracy": round((recall + specificity) / 2, 6),
        "predicted_malicious": int(predicted.sum()),
        "predicted_benign": int((~predicted).sum()),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def _ranking_calibration_metrics(
    labels: Any, probabilities: Any, *, bins: int
) -> dict[str, object]:
    import numpy as np
    from sklearn.metrics import (  # type: ignore[import-untyped]
        average_precision_score,
        brier_score_loss,
        roc_auc_score,
    )

    by_class: dict[str, object] = {}
    for name, label in (("benign", 0), ("malicious", 1)):
        selected = probabilities[labels == label]
        by_class[name] = {
            "count": int(selected.size),
            "minimum": round(float(selected.min()), 6),
            "maximum": round(float(selected.max()), 6),
            "mean": round(float(selected.mean()), 6),
            "median": round(float(np.median(selected)), 6),
            "standard_deviation": round(float(np.std(selected)), 6),
        }
    benign = probabilities[labels == 0]
    malicious = probabilities[labels == 1]
    interval_overlap = max(
        0.0,
        min(float(benign.max()), float(malicious.max()))
        - max(float(benign.min()), float(malicious.min())),
    )
    signed_margin = (labels * 2 - 1) * (probabilities - 0.5)
    return {
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 6),
        "pr_auc": round(float(average_precision_score(labels, probabilities)), 6),
        "brier_score": round(float(brier_score_loss(labels, probabilities)), 6),
        "ece": round(_ece(labels, probabilities, bins=bins), 6),
        "reliability_buckets": _reliability(labels, probabilities, bins=bins),
        "probability": {
            "minimum": round(float(probabilities.min()), 6),
            "maximum": round(float(probabilities.max()), 6),
            "mean": round(float(probabilities.mean()), 6),
        },
        "by_true_class": by_class,
        "class_mean_separation": round(float(malicious.mean() - benign.mean()), 6),
        "class_score_interval_overlap_width": round(interval_overlap, 6),
        "margin": {
            "signed_mean": round(float(signed_margin.mean()), 6),
            "signed_minimum": round(float(signed_margin.min()), 6),
            "absolute_mean": round(float(np.abs(probabilities - 0.5).mean()), 6),
        },
    }


def _select_operating_points(
    labels: Any, probabilities: Any, thresholds: tuple[float, ...]
) -> dict[str, Any]:
    candidates = [_threshold_metrics(labels, probabilities, threshold) for threshold in thresholds]
    # This fixed reject-all sentinel makes each security constraint total. If it is the only
    # feasible choice, the resulting zero recall records the collapse instead of hiding it.
    constrained_candidates = [*candidates, _threshold_metrics(labels, probabilities, 1.0)]

    def constrained(limit: float) -> dict[str, object]:
        feasible = [
            item for item in constrained_candidates if cast(float, item["benign_fpr"]) <= limit
        ]
        return min(
            feasible,
            key=lambda item: (
                -cast(float, item["recall"]),
                cast(float, item["benign_fpr"]),
                -cast(float, item["threshold"]),
            ),
        )

    balanced = min(
        candidates,
        key=lambda item: (
            -cast(float, item["balanced_accuracy"]),
            -cast(float, item["recall"]),
            cast(float, item["benign_fpr"]),
            -cast(float, item["threshold"]),
        ),
    )
    fixed = next(item for item in candidates if item["threshold"] == 0.5)
    return {
        "A_recall_subject_fpr_005": constrained(0.05),
        "B_recall_subject_fpr_010": constrained(0.10),
        "C_balanced_accuracy": balanced,
        "D_fixed_050": fixed,
    }


def _summary(values: list[float]) -> dict[str, float]:
    return {
        "mean": round(statistics.fmean(values), 6),
        "median": round(statistics.median(values), 6),
        "standard_deviation": round(statistics.pstdev(values), 6),
        "minimum": round(min(values), 6),
        "maximum": round(max(values), 6),
    }


def _build_split_artifact(
    cases: tuple[ClassifierCase, ...], config: Phase2Config
) -> dict[str, object]:
    definitions: list[dict[str, object]] = []
    for split_seed in config.split_seeds:
        report = grouped_folds(cases, folds=config.folds, seed=split_seed)
        folds = cast(list[dict[str, object]], report["folds"])
        for outer in folds:
            train_ids = cast(list[str], outer["train_case_ids"])
            outer_train = tuple(case for case in cases if case.id in set(train_ids))
            inner_seed = split_seed * 1000 + int(cast(int, outer["fold"]))
            inner = grouped_folds(outer_train, folds=config.inner_folds, seed=inner_seed)
            definitions.append(
                {
                    "split_seed": split_seed,
                    "outer_fold": outer["fold"],
                    "outer": outer,
                    "inner_seed": inner_seed,
                    "inner": inner,
                }
            )
    return {
        "schema_version": PHASE2_SCHEMA_VERSION,
        "strategy": "repeated-label-stratified-transitive-grouped-outer-CV-with-inner-OOF-v1",
        "split_seeds": list(config.split_seeds),
        "outer_folds": config.folds,
        "inner_folds": config.inner_folds,
        "definitions": definitions,
        "semantic_sha256": canonical_sha256(definitions),
        "leakage": "PASS",
    }


def _inner_oof_logits(
    matrix: Any,
    labels: Any,
    index_by_id: dict[str, int],
    inner_report: dict[str, object],
    *,
    classifier_seed: int,
    config: Phase2Config,
) -> tuple[Any, Any, list[str]]:
    import numpy as np

    output_logits: list[float] = []
    output_labels: list[int] = []
    output_ids: list[str] = []
    for inner in cast(list[dict[str, object]], inner_report["folds"]):
        train_ids = cast(list[str], inner["train_case_ids"])
        validation_ids = cast(list[str], inner["validation_case_ids"])
        train_indexes = np.asarray([index_by_id[value] for value in train_ids], dtype="int64")
        validation_indexes = np.asarray(
            [index_by_id[value] for value in validation_ids], dtype="int64"
        )
        logits = _train_linear_logits(
            matrix[train_indexes],
            labels[train_indexes],
            matrix[validation_indexes],
            seed=classifier_seed,
            config=config,
        )
        output_logits.extend(float(value) for value in logits)
        output_labels.extend(int(value) for value in labels[validation_indexes])
        output_ids.extend(validation_ids)
    if len(output_ids) != len(set(output_ids)):
        raise Phase2ValidationError("inner OOF prediction contains duplicate cases")
    return np.asarray(output_logits), np.asarray(output_labels, dtype="int64"), output_ids


def _aggregate_variant(
    runs: list[dict[str, object]], *, representation: str, calibration: str
) -> dict[str, object]:
    selected = [
        run
        for run in runs
        if run["representation"] == representation and run["calibration"] == calibration
    ]
    if not selected:
        raise Phase2ValidationError("missing Phase 2 variant results")
    ranking = {
        metric: _summary(
            [float(cast(dict[str, Any], run["ranking_calibration"])[metric]) for run in selected]
        )
        for metric in RANKING_CALIBRATION_METRICS
    }
    score_separation = {
        metric: _summary(
            [float(cast(dict[str, Any], run["ranking_calibration"])[metric]) for run in selected]
        )
        for metric in ("class_mean_separation", "class_score_interval_overlap_width")
    }
    score_separation["signed_margin_mean"] = _summary(
        [
            float(cast(dict[str, Any], run["ranking_calibration"])["margin"]["signed_mean"])
            for run in selected
        ]
    )
    score_separation["absolute_margin_mean"] = _summary(
        [
            float(cast(dict[str, Any], run["ranking_calibration"])["margin"]["absolute_mean"])
            for run in selected
        ]
    )
    for label in ("benign", "malicious"):
        score_separation[f"{label}_score_mean"] = _summary(
            [
                float(
                    cast(dict[str, Any], run["ranking_calibration"])["by_true_class"][label]["mean"]
                )
                for run in selected
            ]
        )
    threshold_sweep: dict[str, object] = {}
    for threshold in THRESHOLDS:
        key = f"{threshold:.3f}"
        threshold_sweep[key] = {
            metric: _summary(
                [
                    float(cast(dict[str, Any], run["threshold_sweep"])[key][metric])
                    for run in selected
                ]
            )
            for metric in THRESHOLD_METRICS
        }
    operating_points: dict[str, object] = {}
    for name in (
        "A_recall_subject_fpr_005",
        "B_recall_subject_fpr_010",
        "C_balanced_accuracy",
        "D_fixed_050",
    ):
        operating_points[name] = {
            "selected_threshold": _summary(
                [
                    float(cast(dict[str, Any], run["operating_points"])[name]["threshold"])
                    for run in selected
                ]
            ),
            "selected_threshold_counts": dict(
                sorted(
                    Counter(
                        format(
                            float(cast(dict[str, Any], run["operating_points"])[name]["threshold"]),
                            ".3f",
                        )
                        for run in selected
                    ).items()
                )
            ),
            "reject_all_sentinel_selection_rate": round(
                sum(
                    float(cast(dict[str, Any], run["operating_points"])[name]["threshold"]) == 1.0
                    for run in selected
                )
                / len(selected),
                6,
            ),
            **{
                metric: _summary(
                    [
                        float(cast(dict[str, Any], run["operating_points"])[name][metric])
                        for run in selected
                    ]
                )
                for metric in THRESHOLD_METRICS
            },
        }
    classifier_disagreements: list[bool] = []
    outer_cells = sorted(
        {(int(cast(int, run["split_seed"])), int(cast(int, run["outer_fold"]))) for run in selected}
    )
    for split_seed, fold in outer_cells:
        cell = [
            run for run in selected if run["split_seed"] == split_seed and run["outer_fold"] == fold
        ]
        by_case: dict[str, list[int]] = defaultdict(list)
        for run in cell:
            for prediction in cast(list[dict[str, Any]], run["predictions"]):
                by_case[prediction["case_id"]].append(int(prediction["probability"] >= 0.5))
        classifier_disagreements.extend(len(set(values)) > 1 for values in by_case.values())
    by_case_split: dict[str, dict[int, list[float]]] = defaultdict(lambda: defaultdict(list))
    for run in selected:
        for prediction in cast(list[dict[str, Any]], run["predictions"]):
            by_case_split[prediction["case_id"]][int(cast(int, run["split_seed"]))].append(
                float(prediction["probability"])
            )
    split_disagreements: list[bool] = []
    for split_values in by_case_split.values():
        decisions = {
            int(statistics.fmean(probabilities) >= 0.5) for probabilities in split_values.values()
        }
        split_disagreements.append(len(decisions) > 1)
    seed_variance: dict[str, float] = {}
    split_fold_variance: dict[str, float] = {}
    for metric in (*RANKING_CALIBRATION_METRICS, "recall", "benign_fpr", "balanced_accuracy"):
        per_cell: list[float] = []
        for split_seed, fold in outer_cells:
            values = []
            for run in selected:
                if run["split_seed"] != split_seed or run["outer_fold"] != fold:
                    continue
                source = cast(dict[str, Any], run["ranking_calibration"])
                if metric not in source:
                    source = cast(dict[str, Any], run["threshold_sweep"])["0.500"]
                values.append(float(source[metric]))
            per_cell.append(statistics.pvariance(values))
        per_seed: list[float] = []
        for classifier_seed in CLASSIFIER_SEEDS:
            values = []
            for run in selected:
                if run["classifier_seed"] != classifier_seed:
                    continue
                source = cast(dict[str, Any], run["ranking_calibration"])
                if metric not in source:
                    source = cast(dict[str, Any], run["threshold_sweep"])["0.500"]
                values.append(float(source[metric]))
            per_seed.append(statistics.pvariance(values))
        seed_variance[metric] = round(statistics.fmean(per_cell), 8)
        split_fold_variance[metric] = round(statistics.fmean(per_seed), 8)
    fixed = cast(dict[str, Any], threshold_sweep["0.500"])
    return {
        "representation": representation,
        "calibration": calibration,
        "runs": len(selected),
        "ranking_calibration": ranking,
        "score_separation": score_separation,
        "threshold_sweep": threshold_sweep,
        "operating_points": operating_points,
        "worst_fold_at_050": {
            "recall": fixed["recall"]["minimum"],
            "benign_fpr": fixed["benign_fpr"]["maximum"],
        },
        "metric_variance_across_classifier_seeds_mean_over_outer_cells": seed_variance,
        "metric_variance_across_splits_and_folds_mean_over_classifier_seeds": split_fold_variance,
        "prediction_disagreement_across_classifier_seeds": {
            "observations": len(classifier_disagreements),
            "disagreements": sum(classifier_disagreements),
            "rate": round(sum(classifier_disagreements) / len(classifier_disagreements), 6),
        },
        "prediction_disagreement_across_split_seeds": {
            "cases": len(split_disagreements),
            "disagreements": sum(split_disagreements),
            "rate": round(sum(split_disagreements) / len(split_disagreements), 6),
        },
    }


def _descriptive_breakdowns(
    predictions: list[dict[str, object]], *, representation: str, calibration: str
) -> dict[str, object]:
    selected = [
        item
        for item in predictions
        if item["representation"] == representation and item["calibration"] == calibration
    ]

    def summarize(field: str) -> dict[str, object]:
        output: dict[str, object] = {}
        for value in sorted({str(item[field]) for item in selected}):
            items = [item for item in selected if str(item[field]) == value]
            unique_rows = {str(item["case_id"]) for item in items}
            errors = sum(
                cast(int, item["predicted_050"]) != cast(int, item["label"]) for item in items
            )
            malicious = [item for item in items if item["label"] == 1]
            benign = [item for item in items if item["label"] == 0]
            output[value] = {
                "unique_rows": len(unique_rows),
                "repeated_validation_observations": len(items),
                "error_rate_at_050": round(errors / len(items), 6),
                "recall_at_050": (
                    round(
                        sum(cast(int, item["predicted_050"]) for item in malicious)
                        / len(malicious),
                        6,
                    )
                    if malicious
                    else None
                ),
                "benign_fpr_at_050": (
                    round(
                        sum(cast(int, item["predicted_050"]) for item in benign) / len(benign),
                        6,
                    )
                    if benign
                    else None
                ),
                "interpretation": "descriptive only; do not infer from sparse subsets",
            }
        return output

    concept_errors: Counter[str] = Counter()
    total_errors = 0
    for item in selected:
        if cast(int, item["predicted_050"]) != cast(int, item["label"]):
            concept_errors[str(item["concept_id"])] += 1
            total_errors += 1
    hard_negative_items = [item for item in selected if item["hard_negative_category"] != "NONE"]
    hard_negative_errors = sum(
        cast(int, item["predicted_050"]) != cast(int, item["label"]) for item in hard_negative_items
    )
    return {
        "languages": summarize("language"),
        "classifier_families": summarize("classifier_family"),
        "hard_negatives": summarize("hard_negative_category"),
        "hard_negative_overall": {
            "unique_rows": len({str(item["case_id"]) for item in hard_negative_items}),
            "repeated_validation_observations": len(hard_negative_items),
            "benign_fpr_at_050": (
                round(hard_negative_errors / len(hard_negative_items), 6)
                if hard_negative_items
                else None
            ),
            "interpretation": "descriptive repeated grouped-validation observations",
        },
        "concept_error_concentration": {
            "total_error_observations": total_errors,
            "concepts_with_errors": len(concept_errors),
            "largest_concept_error_share": (
                round(max(concept_errors.values()) / total_errors, 6) if total_errors else 0.0
            ),
            "errors_by_concept": dict(sorted(concept_errors.items())),
        },
    }


def _per_concept_predictions(predictions: list[dict[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    variants = sorted(
        {(str(item["representation"]), str(item["calibration"])) for item in predictions}
    )
    for representation, calibration in variants:
        selected = [
            item
            for item in predictions
            if item["representation"] == representation and item["calibration"] == calibration
        ]
        concepts: dict[str, object] = {}
        for concept_id in sorted({str(item["concept_id"]) for item in selected}):
            items = [item for item in selected if item["concept_id"] == concept_id]
            labels = {cast(int, item["label"]) for item in items}
            if len(labels) != 1:
                raise Phase2ValidationError(f"mixed labels in concept predictions: {concept_id}")
            probabilities = [cast(float, item["probability"]) for item in items]
            predicted = [cast(int, item["predicted_050"]) for item in items]
            label = next(iter(labels))
            concepts[concept_id] = {
                "case_ids": sorted({str(item["case_id"]) for item in items}),
                "label": label,
                "repeated_validation_observations": len(items),
                "probability": _summary(probabilities),
                "predicted_malicious_rate_at_050": round(statistics.fmean(predicted), 6),
                "error_rate_at_050": round(
                    sum(value != label for value in predicted) / len(predicted), 6
                ),
            }
        output[f"{representation}:{calibration}"] = concepts
    return output


def _decision(aggregate: dict[str, object], breakdowns: dict[str, object]) -> dict[str, object]:
    normalized = cast(dict[str, Any], aggregate["l2_normalized:raw"])
    ranking = normalized["ranking_calibration"]
    op_b = normalized["operating_points"]["B_recall_subject_fpr_010"]
    split_disagreement = float(normalized["prediction_disagreement_across_split_seeds"]["rate"])
    strong_ranking = (
        float(ranking["roc_auc"]["mean"]) >= 0.80
        and float(ranking["pr_auc"]["mean"]) >= 0.80
        and float(ranking["roc_auc"]["median"]) >= 0.80
    )
    mean_constraint_behavior = (
        float(op_b["recall"]["mean"]) >= 0.70 and float(op_b["benign_fpr"]["mean"]) <= 0.10
    )
    controllable = (
        mean_constraint_behavior
        and float(op_b["recall"]["minimum"]) >= 0.50
        and float(op_b["benign_fpr"]["maximum"]) <= 0.10
    )
    threshold_stable = (
        float(op_b["selected_threshold"]["standard_deviation"]) <= 0.10
        and split_disagreement <= 0.20
    )
    fold_range = float(ranking["roc_auc"]["maximum"]) - float(ranking["roc_auc"]["minimum"])
    data_dominates = fold_range > 0.45 or float(ranking["roc_auc"]["minimum"]) < 0.45
    if strong_ranking and controllable and threshold_stable:
        choice = "A. READY FOR INDEPENDENT DEVELOPMENT EVALUATION"
        next_action = (
            "freeze the normalized frozen-encoder plus unweighted linear-head protocol and test "
            "it once on separately collected, provenance-isolated development evidence"
        )
    elif data_dominates:
        choice = "C. NOT READY — DATA SIZE DOMINATES"
        next_action = (
            "stop model iteration and obtain a minimum of two new independent concepts per class "
            "for each currently single-row language/family cell before rerunning Phase 2"
        )
    else:
        choice = "B. NOT READY — THRESHOLD/CALIBRATION STILL UNSTABLE"
        next_action = "continue frozen-linear threshold and calibration diagnostics " + (
            "without more human labeling"
        )
    raw = cast(dict[str, Any], aggregate["raw:raw"])
    platt = cast(dict[str, Any], aggregate["l2_normalized:platt"])
    normalization = {
        metric: round(
            float(ranking[metric]["mean"]) - float(raw["ranking_calibration"][metric]["mean"]),
            6,
        )
        for metric in ("roc_auc", "pr_auc", "brier_score", "ece")
    }
    calibration_brier_delta = round(
        float(platt["ranking_calibration"]["brier_score"]["mean"])
        - float(ranking["brier_score"]["mean"]),
        6,
    )
    concept = cast(dict[str, Any], breakdowns["l2_normalized:raw"])["concept_error_concentration"]
    return {
        "choice": choice,
        "criteria": {
            "strong_ranking": strong_ranking,
            "mean_fpr_10_constraint_behavior_acceptable": mean_constraint_behavior,
            "benign_fpr_controllable_without_recall_collapse": controllable,
            "threshold_stable": threshold_stable,
            "data_size_dominates": data_dominates,
        },
        "answers": {
            "ranking_separation_consistently_strong": strong_ranking,
            "benign_fpr_controllable_without_collapsing_recall": controllable,
            "threshold_choice_stable_across_grouped_splits": threshold_stable,
            "calibration_materially_improves_robustness": calibration_brier_delta <= -0.01,
            "embedding_normalization_helps": any(
                (
                    normalization["roc_auc"] >= 0.01,
                    normalization["pr_auc"] >= 0.01,
                    normalization["brier_score"] <= -0.01,
                    normalization["ece"] <= -0.01,
                )
            ),
            "normalization_mean_metric_deltas_l2_minus_raw": normalization,
            "platt_minus_raw_mean_brier_score": calibration_brier_delta,
            "results_dominated_by_few_concepts": (
                int(concept["total_error_observations"]) > 0
                and float(concept["largest_concept_error_share"]) > 0.35
            ),
            "independent_held_out_development_evaluation_justified": choice.startswith("A."),
            "blind_set_e_protected": True,
        },
        "next_action": next_action,
        "operating_point_constraint_reliability": (
            "UNDERPOWERED: outer-training benign counts are too small to distinguish a 5% rate "
            "from zero errors or a 10% rate from one error reliably"
        ),
    }


def run_phase2_validation(
    gold_path: Path,
    model_path: Path,
    output_directory: Path,
    *,
    expected_base_freeze_sha256: str,
    config: Phase2Config | None = None,
) -> dict[str, object]:
    """Run repeated, nested grouped validation without updating the encoder."""
    import numpy as np

    config = config or Phase2Config()
    if set(CLASSIFIER_SEEDS) - set(config.classifier_seeds):
        raise Phase2ValidationError("all five Phase 1 classifier seeds are required")
    if 0.5 not in config.thresholds:
        raise Phase2ValidationError("the reference threshold 0.5 is required")
    output_directory = output_directory.resolve()
    paths = {
        "splits": output_directory / "v0.4.2-phase2-splits.json",
        "cache": output_directory / "v0.4.2-phase2-embedding-cache.npz",
        "cache_metadata": output_directory / "v0.4.2-phase2-embedding-cache-metadata.json",
        "runs": output_directory / "v0.4.2-phase2-per-run-results.jsonl",
        "predictions": output_directory / "v0.4.2-phase2-per-run-predictions.jsonl",
        "concepts": output_directory / "v0.4.2-phase2-per-concept-predictions.json",
        "thresholds": output_directory / "v0.4.2-phase2-threshold-sweep.json",
        "calibration": output_directory / "v0.4.2-phase2-calibration-results.json",
        "aggregate": output_directory / "v0.4.2-phase2-aggregate-robustness.json",
        "report": output_directory / "v0.4.2-phase2-frozen-linear-validation.json",
        "markdown": output_directory / "v0.4.2-phase2-frozen-linear-validation.md",
    }
    if any(path.exists() or path.is_symlink() for path in paths.values()):
        raise Phase2ValidationError("a Phase 2 output artifact already exists")
    inspected = inspect_local_model(model_path)
    if inspected.get("directory_freeze_sha256") != expected_base_freeze_sha256:
        raise Phase2ValidationError("base encoder freeze hash changed")
    validated = validate_local_model(model_path)
    if (
        validated.get("validation") != "PASS"
        or validated.get("directory_freeze_sha256") != expected_base_freeze_sha256
        or validated.get("network_used") is not False
    ):
        raise Phase2ValidationError("base encoder failed offline revalidation")
    gold_hash_before = _sha256_file(gold_path)
    cases, provenance_audit = _validated_trusted_gold(gold_path)
    split_artifact = _build_split_artifact(cases, config)
    _write_json(paths["splits"], split_artifact)
    started = time.perf_counter()
    raw_matrix, case_ids, label_values = _extract_raw_embeddings(model_path, cases, config)
    normalized_matrix = _l2_normalize(raw_matrix)
    cache_temporary = paths["cache"].with_name(f".{paths['cache'].name}.tmp-{os.getpid()}.npz")
    np.savez_compressed(
        cache_temporary,
        raw_embeddings=raw_matrix,
        l2_normalized_embeddings=normalized_matrix,
        case_ids=np.asarray(case_ids),
        labels=np.asarray(label_values, dtype="int64"),
    )
    os.replace(cache_temporary, paths["cache"])
    cache_metadata = {
        "schema_version": PHASE2_SCHEMA_VERSION,
        "path": paths["cache"].as_posix(),
        "sha256": _sha256_file(paths["cache"]),
        "rows": len(case_ids),
        "dimensions": int(raw_matrix.shape[1]),
        "dtype": str(raw_matrix.dtype),
        "raw_norm": {
            "minimum": round(float(np.linalg.norm(raw_matrix, axis=1).min()), 8),
            "maximum": round(float(np.linalg.norm(raw_matrix, axis=1).max()), 8),
        },
        "normalized_norm": {
            "minimum": round(float(np.linalg.norm(normalized_matrix, axis=1).min()), 8),
            "maximum": round(float(np.linalg.norm(normalized_matrix, axis=1).max()), 8),
        },
        "ordered_case_ids_sha256": canonical_sha256(case_ids),
        "labels_sha256": canonical_sha256(label_values),
        "gold_file_sha256": gold_hash_before,
        "gold_semantic_sha256": corpus_hash(cases),
        "base_model_freeze_sha256": expected_base_freeze_sha256,
        "feature_extractor_config_sha256": canonical_sha256(config.to_dict()),
        "input_text_persisted": False,
        "encoder_trainable": False,
        "network_used": False,
    }
    _write_json(paths["cache_metadata"], cache_metadata)
    index_by_id = {case_id: index for index, case_id in enumerate(case_ids)}
    case_by_id = {case.id: case for case in cases}
    labels = np.asarray(label_values, dtype="int64")
    matrices = {"raw": raw_matrix, "l2_normalized": normalized_matrix}
    runs: list[dict[str, object]] = []
    predictions: list[dict[str, object]] = []
    for definition in cast(list[dict[str, Any]], split_artifact["definitions"]):
        outer = cast(dict[str, Any], definition["outer"])
        train_ids = cast(list[str], outer["train_case_ids"])
        validation_ids = cast(list[str], outer["validation_case_ids"])
        train_indexes = np.asarray([index_by_id[value] for value in train_ids], dtype="int64")
        validation_indexes = np.asarray(
            [index_by_id[value] for value in validation_ids], dtype="int64"
        )
        for representation, matrix in matrices.items():
            for classifier_seed in config.classifier_seeds:
                oof_logits, oof_labels, oof_ids = _inner_oof_logits(
                    matrix,
                    labels,
                    index_by_id,
                    cast(dict[str, object], definition["inner"]),
                    classifier_seed=classifier_seed,
                    config=config,
                )
                if set(oof_ids) != set(train_ids):
                    raise Phase2ValidationError("inner OOF cases do not equal outer training cases")
                platt = _fit_platt(oof_logits, oof_labels, seed=classifier_seed)
                validation_logits = _train_linear_logits(
                    matrix[train_indexes],
                    labels[train_indexes],
                    matrix[validation_indexes],
                    seed=classifier_seed,
                    config=config,
                )
                probabilities = {
                    "raw": _sigmoid(validation_logits),
                    "platt": platt.predict_proba(validation_logits.reshape(-1, 1))[:, 1],
                }
                inner_probabilities = {
                    "raw": _sigmoid(oof_logits),
                    "platt": platt.predict_proba(oof_logits.reshape(-1, 1))[:, 1],
                }
                for calibration, validation_probabilities in probabilities.items():
                    ranking = _ranking_calibration_metrics(
                        labels[validation_indexes], validation_probabilities, bins=config.ece_bins
                    )
                    sweep = {
                        f"{threshold:.3f}": _threshold_metrics(
                            labels[validation_indexes], validation_probabilities, threshold
                        )
                        for threshold in config.thresholds
                    }
                    selected_points = _select_operating_points(
                        oof_labels, inner_probabilities[calibration], config.thresholds
                    )
                    operating_points = {
                        name: {
                            **_threshold_metrics(
                                labels[validation_indexes],
                                validation_probabilities,
                                float(selected["threshold"]),
                            ),
                            "selection_basis": "grouped-inner-OOF-only",
                            "inner_selection_metrics": selected,
                        }
                        for name, selected in selected_points.items()
                    }
                    run_id = canonical_sha256(
                        {
                            "split_seed": definition["split_seed"],
                            "outer_fold": outer["fold"],
                            "representation": representation,
                            "calibration": calibration,
                            "classifier_seed": classifier_seed,
                        }
                    )[:20]
                    run_predictions: list[dict[str, object]] = []
                    for position, case_id in enumerate(validation_ids):
                        case = case_by_id[case_id]
                        item = {
                            "schema_version": PHASE2_SCHEMA_VERSION,
                            "run_id": run_id,
                            "split_seed": definition["split_seed"],
                            "outer_fold": outer["fold"],
                            "classifier_seed": classifier_seed,
                            "representation": representation,
                            "calibration": calibration,
                            "case_id": case_id,
                            "concept_id": case.concept_id,
                            "label": int(labels[validation_indexes[position]]),
                            "language": case.language,
                            "classifier_family": case.label.value,
                            "hard_negative_category": case.hard_negative_category or "NONE",
                            "linear_logit": round(float(validation_logits[position]), 8),
                            "probability": round(float(validation_probabilities[position]), 8),
                            "predicted_050": int(validation_probabilities[position] >= 0.5),
                        }
                        predictions.append(item)
                        run_predictions.append(item)
                    runs.append(
                        {
                            "schema_version": PHASE2_SCHEMA_VERSION,
                            "run_id": run_id,
                            "split_seed": definition["split_seed"],
                            "outer_fold": outer["fold"],
                            "inner_seed": definition["inner_seed"],
                            "classifier_seed": classifier_seed,
                            "representation": representation,
                            "calibration": calibration,
                            "train_rows": len(train_indexes),
                            "validation_rows": len(validation_indexes),
                            "train_case_ids": train_ids,
                            "validation_case_ids": validation_ids,
                            "ranking_calibration": ranking,
                            "threshold_sweep": sweep,
                            "operating_points": operating_points,
                            "predictions": run_predictions,
                        }
                    )
    _write_jsonl(paths["runs"], runs)
    _write_jsonl(paths["predictions"], predictions)
    aggregate: dict[str, object] = {
        f"{representation}:{calibration}": _aggregate_variant(
            runs, representation=representation, calibration=calibration
        )
        for representation in matrices
        for calibration in ("raw", "platt")
    }
    breakdowns: dict[str, object] = {
        f"{representation}:{calibration}": _descriptive_breakdowns(
            predictions, representation=representation, calibration=calibration
        )
        for representation in matrices
        for calibration in ("raw", "platt")
    }
    decision = _decision(aggregate, breakdowns)
    _write_json(
        paths["concepts"],
        {
            "schema_version": 1,
            "variants": _per_concept_predictions(predictions),
        },
    )
    _write_json(
        paths["thresholds"],
        {
            "schema_version": 1,
            "preregistered_grid": list(config.thresholds),
            "aggregate": {
                key: cast(dict[str, Any], value)["threshold_sweep"]
                for key, value in aggregate.items()
            },
            "operating_points": {
                key: cast(dict[str, Any], value)["operating_points"]
                for key, value in aggregate.items()
            },
            "constraint_reliability": decision["operating_point_constraint_reliability"],
        },
    )
    _write_json(
        paths["calibration"],
        {
            "schema_version": 1,
            "raw_and_platt": {
                key: cast(dict[str, Any], value)["ranking_calibration"]
                for key, value in aggregate.items()
            },
            "platt_fitting": "grouped inner OOF predictions from outer training only",
            "isotonic": {
                "attempted": False,
                "status": "REJECTED AS UNDERPOWERED",
                "reason": (
                    "37 total rows and only 28-31 outer-training rows cannot support a stable "
                    "stepwise calibrator"
                ),
            },
        },
    )
    aggregate_artifact = {
        "schema_version": 1,
        "runs": len(runs),
        "prediction_rows": len(predictions),
        "aggregate": aggregate,
        "breakdowns": breakdowns,
        "decision": decision,
    }
    _write_json(paths["aggregate"], aggregate_artifact)
    if _sha256_file(gold_path) != gold_hash_before:
        raise Phase2ValidationError("trusted gold changed during Phase 2")
    if (
        inspect_local_model(model_path).get("directory_freeze_sha256")
        != expected_base_freeze_sha256
    ):
        raise Phase2ValidationError("base encoder changed during Phase 2")
    try:
        import sklearn  # type: ignore[import-untyped]
        import torch
        import transformers
    except ImportError as exc:  # pragma: no cover
        raise Phase2ValidationError("Phase 2 runtime dependencies changed") from exc
    report: dict[str, object] = {
        "schema_version": PHASE2_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "PHASE 2 FROZEN LINEAR VALIDATION COMPLETE",
        "gold": {
            "path": gold_path.resolve().as_posix(),
            "file_sha256": gold_hash_before,
            "semantic_sha256": corpus_hash(cases),
            "rows": len(cases),
            "concepts": len({case.concept_id for case in cases}),
            "labels": dict(
                sorted(Counter(case.effective_binary_label.value for case in cases).items())
            ),
            "provenance_audit": provenance_audit,
        },
        "encoder": validated,
        "config": config.to_dict(),
        "configuration_sha256": canonical_sha256(config.to_dict()),
        "split_artifact": {
            "path": paths["splits"].as_posix(),
            "sha256": _sha256_file(paths["splits"]),
            "semantic_sha256": split_artifact["semantic_sha256"],
            "outer_split_seeds": len(config.split_seeds),
            "outer_fold_cells": len(config.split_seeds) * config.folds,
            "inner_folds": config.inner_folds,
            "leakage": "PASS",
        },
        "embedding_cache": cache_metadata,
        "results": {
            "runs": len(runs),
            "prediction_rows": len(predictions),
            "artifacts": {
                name: {"path": path.as_posix(), "sha256": _sha256_file(path)}
                for name, path in paths.items()
                if name not in {"report", "markdown"}
            },
        },
        "aggregate": aggregate,
        "breakdowns": breakdowns,
        "decision": decision,
        "limitations": [
            "All metrics are exploratory; outer validation folds contain only 6-9 rows.",
            "Most non-English languages and several classifier families contain one trusted row.",
            (
                "Five and ten percent FPR constraints are below or near one benign error per "
                "training split."
            ),
            "Repeated grouped CV measures internal robustness but is not independent evidence.",
        ],
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
            "trusted_gold_only": True,
            "encoder_updated": False,
            "partial_unfreezing": False,
            "full_fine_tuning": False,
            "pseudo_labels": 0,
            "human_review_resumed": False,
            "batch_06_created": False,
            "development_shadow_used": False,
            "blind_set_e_burned": False,
            "production_model_selected": None,
        },
    }
    _write_json(paths["report"], report)
    normalized = cast(dict[str, Any], aggregate["l2_normalized:raw"])
    markdown = f"""# SecureInjections v0.4.2 — Phase 2 frozen linear-head validation

Status: **{decision["choice"]}**

- Trusted rows / independent concepts: {len(cases)} / {len(conceptual_groups(cases))}
- Outer split seeds / folds: {len(config.split_seeds)} / {config.folds}
- Classifier seeds: {len(config.classifier_seeds)}
- Raw plus Platt result runs: {len(runs)}
- Normalized/raw mean ROC-AUC: {normalized["ranking_calibration"]["roc_auc"]["mean"]}
- Normalized/raw mean PR-AUC: {normalized["ranking_calibration"]["pr_auc"]["mean"]}
- Encoder, provenance, and grouped leakage validation: PASS

All threshold, calibration, robustness, language, family, hard-negative, and concept results are in
the adjacent machine-readable artifacts. The results remain exploratory because validation folds
contain only 6-9 rows and most non-English subsets contain a single row.

## Decision

{decision["choice"]}

Next action: {decision["next_action"]}.

No encoder update, human review, Batch 06, pseudo-label use, development shadow, production model
selection, network access, or Blind Set E use occurred.
"""
    _atomic_text(paths["markdown"], markdown)
    return report
