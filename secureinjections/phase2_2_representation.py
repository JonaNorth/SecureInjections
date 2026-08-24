"""Phase 2.2 frozen representation-boundary experiment."""

from __future__ import annotations

import json
import os
import platform
import random
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .classifier_data import ClassifierCase, conceptual_groups, corpus_hash
from .model_import import _network_blocked, inspect_local_model, validate_local_model
from .phase2_1_diagnostics import _sha256_file, _validated_trusted_gold
from .phase2_validation import (
    CLASSIFIER_SEEDS,
    SPLIT_SEEDS,
    Phase2Config,
    _build_split_artifact,
    _ranking_calibration_metrics,
    _summary,
    _threshold_metrics,
    _train_linear_logits,
)
from .review_workflow import canonical_sha256

PHASE2_2_SCHEMA_VERSION = 1
CRITICAL_CONCEPTS = (
    "derived-concept-9f18c0f5c5f38123",
    "derived-concept-2ec0d925781ce53c",
    "derived-concept-362e69993b8e375e",
)
QUOTED_ATTACK_CONCEPT = "derived-concept-d62c55c0c3074721"
EXFIL_NEAREST_SECURITY_DISCUSSION = "derived-concept-def7fd49cba9a007"
BOUNDARIES = {
    "A_exfiltration_vs_multilingual_security_education": (
        "derived-concept-9f18c0f5c5f38123",
        "derived-concept-362e69993b8e375e",
    ),
    "B_direct_override_vs_benign_quoted_attack": (
        "derived-concept-2ec0d925781ce53c",
        QUOTED_ATTACK_CONCEPT,
    ),
    "C_security_education_vs_direct_injection": (
        "derived-concept-2ec0d925781ce53c",
        "derived-concept-362e69993b8e375e",
    ),
}
EXTRA_NEAREST_BOUNDARIES = {
    "exfiltration_vs_specific_nearest_benign_security_discussion": (
        "derived-concept-9f18c0f5c5f38123",
        EXFIL_NEAREST_SECURITY_DISCUSSION,
    ),
}
REPRESENTATIONS = {
    "A_baseline_final_mean": {
        "method": "attention-mask mean of final hidden layer",
        "valid": True,
        "equivalent_to": ["C_non_padding_mean", "D_attention_mask_weighted_mean"],
    },
    "B_final_start_token": {
        "method": "final hidden state at tokenizer start/CLS position 0",
        "valid": True,
        "equivalent_to": [],
    },
    "C_non_padding_mean": {
        "method": "arithmetic mean over tokens with attention mask 1",
        "valid": True,
        "equivalent_to": [
            "A_baseline_final_mean",
            "D_attention_mask_weighted_mean",
        ],
    },
    "D_attention_mask_weighted_mean": {
        "method": "binary attention-mask weighted final-layer mean",
        "valid": True,
        "equivalent_to": ["A_baseline_final_mean", "C_non_padding_mean"],
    },
    "E_last4_layer_mean": {
        "method": "mean of token means from the final four hidden layers",
        "valid": True,
        "equivalent_to": [],
    },
    "F_final_mean_concat_start": {
        "method": "concatenated final-layer token mean and start-token vector",
        "valid": True,
        "equivalent_to": [],
    },
}


class Phase22RepresentationError(RuntimeError):
    """A representation, integrity, or offline constraint failed."""


@dataclass(frozen=True, slots=True)
class Phase22Config:
    folds: int = 5
    split_seeds: tuple[int, ...] = SPLIT_SEEDS
    classifier_seeds: tuple[int, ...] = CLASSIFIER_SEEDS
    max_length: int = 256
    embedding_batch_size: int = 8
    linear_epochs: int = 250
    linear_learning_rate: float = 0.01
    weight_decay: float = 1e-4
    threshold: float = 0.5
    material_ranking_degradation: float = 0.02
    material_split_disagreement_increase: float = 0.05
    material_fpr_increase: float = 0.05
    material_reversal_reduction: float = 0.20
    new_boundary_error_observations: int = 10

    def head_config(self) -> Phase2Config:
        return Phase2Config(
            folds=self.folds,
            classifier_seeds=self.classifier_seeds,
            split_seeds=self.split_seeds,
            max_length=self.max_length,
            embedding_batch_size=self.embedding_batch_size,
            linear_epochs=self.linear_epochs,
            linear_learning_rate=self.linear_learning_rate,
            weight_decay=self.weight_decay,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "folds": self.folds,
            "split_seeds": list(self.split_seeds),
            "classifier_seeds": list(self.classifier_seeds),
            "max_length": self.max_length,
            "embedding_batch_size": self.embedding_batch_size,
            "linear_epochs": self.linear_epochs,
            "linear_learning_rate": self.linear_learning_rate,
            "weight_decay": self.weight_decay,
            "threshold": self.threshold,
            "representations": REPRESENTATIONS,
            "normalizations": ["raw", "l2_normalized"],
            "head": "torch-linear-unweighted",
            "encoder_trainable": False,
            "selection_limits": {
                "material_ranking_degradation": self.material_ranking_degradation,
                "material_split_disagreement_increase": (self.material_split_disagreement_increase),
                "material_fpr_increase": self.material_fpr_increase,
                "material_reversal_reduction": self.material_reversal_reduction,
                "new_boundary_error_observations": self.new_boundary_error_observations,
            },
        }


def _atomic_text(path: Path, text: str) -> None:
    if path.is_symlink():
        raise Phase22RepresentationError(f"refusing to replace symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise Phase22RepresentationError(f"temporary artifact already exists: {temporary}")
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
        raise Phase22RepresentationError("refusing to write empty Phase 2.2 artifact")
    _atomic_text(
        path,
        "".join(json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n" for value in values),
    )


def _load_json(path: Path, *, maximum: int = 64 * 1024 * 1024) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise Phase22RepresentationError(f"unsafe or missing JSON artifact: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Phase22RepresentationError(f"invalid JSON artifact: {path}") from exc
    if not isinstance(value, dict):
        raise Phase22RepresentationError(f"JSON artifact must be an object: {path}")
    return value


def _validate_phase21_binding(
    output_directory: Path, gold_path: Path, freeze: str
) -> dict[str, Any]:
    path = output_directory / "v0.4.2-phase2.1-diagnostics.json"
    report = _load_json(path)
    if (
        report.get("status") != "PHASE 2.1 INFLUENTIAL-CONCEPT AND THRESHOLD DIAGNOSTICS COMPLETE"
        or report["decision"]["choice"] != "D. REPRESENTATION FAILURE EXISTS IN SPECIFIC CONCEPTS"
        or report["gold"]["file_sha256"] != _sha256_file(gold_path)
        or report["encoder"]["directory_freeze_sha256"] != freeze
        or report["safety"]["network_used"] is not False
    ):
        raise Phase22RepresentationError("Phase 2.1 binding or decision failed")
    for item in report["artifacts"].values():
        artifact = Path(item["path"])
        if _sha256_file(artifact) != item["sha256"]:
            raise Phase22RepresentationError(f"Phase 2.1 artifact changed: {artifact.name}")
    return report


def _extract_representations(
    model_path: Path,
    cases: tuple[ClassifierCase, ...],
    config: Phase22Config,
) -> tuple[dict[str, Any], list[str], list[int], dict[str, object]]:
    try:
        import numpy as np
        import torch
        from transformers import AutoModel, AutoTokenizer
    except ImportError as exc:
        raise Phase22RepresentationError("local frozen-feature runtime is unavailable") from exc
    random.seed(42)
    torch.manual_seed(42)
    torch.set_num_threads(1)
    ordered = sorted(cases, key=lambda case: case.id)
    collected: dict[str, list[Any]] = defaultdict(list)
    runtime_validation: dict[str, object] = {}
    with _network_blocked(), torch.no_grad():
        tokenizer = AutoTokenizer.from_pretrained(
            str(model_path.resolve()),
            local_files_only=True,
            trust_remote_code=False,
            use_fast=True,
        )
        if tokenizer.cls_token_id is None and tokenizer.bos_token_id is None:
            raise Phase22RepresentationError("variant B/F invalid: tokenizer has no start token")
        start_token_id = (
            tokenizer.cls_token_id if tokenizer.cls_token_id is not None else tokenizer.bos_token_id
        )
        model = AutoModel.from_pretrained(
            str(model_path.resolve()),
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        )
        model.to("cpu")
        model.eval()
        for parameter in model.parameters():
            parameter.requires_grad_(False)
        hidden_layers = int(getattr(model.config, "num_hidden_layers", 0))
        if hidden_layers < 4:
            raise Phase22RepresentationError(
                "variant E invalid: encoder has fewer than four hidden layers"
            )
        runtime_validation = {
            "model_type": str(getattr(model.config, "model_type", "unknown")),
            "hidden_layers": hidden_layers,
            "hidden_dimension": int(getattr(model.config, "hidden_size", 0)),
            "tokenizer_class": tokenizer.__class__.__name__,
            "start_token_id": start_token_id,
            "variant_B_start_token_semantically_available": True,
            "variant_E_hidden_states_available": True,
            "variant_A_C_D_equivalence": (
                "PROVEN: non-padding arithmetic mean and binary attention-mask weighted mean "
                "are the same operation"
            ),
        }
        for offset in range(0, len(ordered), config.embedding_batch_size):
            batch = ordered[offset : offset + config.embedding_batch_size]
            encoded = tokenizer(
                [f"query: {case.text}" for case in batch],
                padding=True,
                truncation=True,
                max_length=config.max_length,
                return_tensors="pt",
            )
            output = model(**encoded, output_hidden_states=True, return_dict=True)
            final = output.last_hidden_state
            hidden_states = output.hidden_states
            if hidden_states is None or len(hidden_states) < 5:
                raise Phase22RepresentationError("variant E hidden-state output unavailable")
            mask = encoded["attention_mask"].unsqueeze(-1).to(final.dtype)

            denominator = mask.sum(dim=1).clamp(min=1)
            final_mean = (final * mask).sum(dim=1) / denominator
            start = final[:, 0, :]
            last4 = torch.stack(
                [(hidden * mask).sum(dim=1) / denominator for hidden in hidden_states[-4:]],
                dim=0,
            ).mean(dim=0)
            representations = {
                "A_baseline_final_mean": final_mean,
                "B_final_start_token": start,
                "C_non_padding_mean": final_mean.clone(),
                "D_attention_mask_weighted_mean": final_mean.clone(),
                "E_last4_layer_mean": last4,
                "F_final_mean_concat_start": torch.cat((final_mean, start), dim=1),
            }
            for name, values in representations.items():
                collected[name].append(values.cpu().numpy().astype("float32"))
        del model, tokenizer
    matrices = {name: np.concatenate(values, axis=0) for name, values in collected.items()}
    hidden_dimension = cast(int, runtime_validation["hidden_dimension"])
    for name, matrix in matrices.items():
        expected_dimension = (
            hidden_dimension * 2 if name == "F_final_mean_concat_start" else hidden_dimension
        )
        if matrix.shape != (len(ordered), expected_dimension) or not np.isfinite(matrix).all():
            raise Phase22RepresentationError(f"invalid representation matrix: {name}")
    if not (
        np.array_equal(matrices["A_baseline_final_mean"], matrices["C_non_padding_mean"])
        and np.array_equal(
            matrices["A_baseline_final_mean"],
            matrices["D_attention_mask_weighted_mean"],
        )
    ):
        raise Phase22RepresentationError("declared A/C/D equivalence did not hold exactly")
    return (
        matrices,
        [case.id for case in ordered],
        [int(case.effective_binary_label.value == "malicious") for case in ordered],
        runtime_validation,
    )


def _normalize(matrix: Any) -> Any:
    import numpy as np

    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    if (norms <= 0).any():
        raise Phase22RepresentationError("zero-norm representation")
    return (matrix / norms).astype("float32")


def _sigmoid(values: Any) -> Any:
    import numpy as np

    return 1.0 / (1.0 + np.exp(-np.clip(values, -80.0, 80.0)))


def _concept_centroids(
    matrix: Any, case_ids: list[str], cases: tuple[ClassifierCase, ...]
) -> dict[str, Any]:
    import numpy as np

    by_id = {case.id: case for case in cases}
    output: dict[str, Any] = {}
    for concept_id in sorted({case.concept_id for case in cases}):
        indexes = [
            index
            for index, case_id in enumerate(case_ids)
            if by_id[case_id].concept_id == concept_id
        ]
        centroid = matrix[indexes].mean(axis=0)
        norm = np.linalg.norm(centroid)
        if norm <= 0:
            raise Phase22RepresentationError(f"zero concept centroid: {concept_id}")
        output[concept_id] = centroid / norm
    return output


def _similarity_summary(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {
            "mean": None,
            "median": None,
            "standard_deviation": None,
            "minimum": None,
            "maximum": None,
        }
    return {name: value for name, value in _summary(values).items()}


def _representation_geometry(
    matrix: Any,
    case_ids: list[str],
    cases: tuple[ClassifierCase, ...],
) -> dict[str, object]:
    import numpy as np

    normalized = _normalize(matrix)
    by_id = {case.id: case for case in cases}
    labels = {case.id: int(case.effective_binary_label.value == "malicious") for case in cases}
    centroids = _concept_centroids(normalized, case_ids, cases)
    within_concept: list[float] = []
    within_class: list[float] = []
    cross_class: list[float] = []
    for left in range(len(case_ids)):
        for right in range(left + 1, len(case_ids)):
            similarity = float(normalized[left] @ normalized[right])
            if by_id[case_ids[left]].concept_id == by_id[case_ids[right]].concept_id:
                within_concept.append(similarity)
            elif labels[case_ids[left]] == labels[case_ids[right]]:
                within_class.append(similarity)
            else:
                cross_class.append(similarity)
    class_centroids: dict[int, Any] = {}
    for label in (0, 1):
        indexes = [index for index, case_id in enumerate(case_ids) if labels[case_id] == label]
        centroid = normalized[indexes].mean(axis=0)
        class_centroids[label] = centroid / np.linalg.norm(centroid)
    concept_details: dict[str, object] = {}
    for concept_id, centroid in centroids.items():
        target_label = next(labels[case.id] for case in cases if case.concept_id == concept_id)
        neighbors = sorted(
            (
                {
                    "concept_id": other_id,
                    "binary_label": (
                        next(
                            case.effective_binary_label.value
                            for case in cases
                            if case.concept_id == other_id
                        )
                    ),
                    "cosine_similarity": round(float(centroid @ other), 6),
                    "cosine_distance": round(1.0 - float(centroid @ other), 6),
                }
                for other_id, other in centroids.items()
                if other_id != concept_id
            ),
            key=lambda item: -cast(float, item["cosine_similarity"]),
        )
        same = [
            item
            for item in neighbors
            if item["binary_label"] == ("malicious" if target_label else "benign")
        ]
        opposite = [
            item
            for item in neighbors
            if item["binary_label"] != ("malicious" if target_label else "benign")
        ]
        member_indexes = [
            index
            for index, case_id in enumerate(case_ids)
            if by_id[case_id].concept_id == concept_id
        ]
        member_similarities = [
            float(normalized[left] @ normalized[right])
            for position, left in enumerate(member_indexes)
            for right in member_indexes[position + 1 :]
        ]
        concept_details[concept_id] = {
            "case_ids": sorted(case_ids[index] for index in member_indexes),
            "within_concept_cosine": _similarity_summary(member_similarities),
            "nearest_opposite_class_concept": opposite[0],
            "nearest_same_class_concept": same[0],
            "opposite_neighbor_rank_among_all_concepts": neighbors.index(opposite[0]) + 1,
            "margin_to_closest_opposite_class_concept": round(
                float(same[0]["cosine_similarity"]) - float(opposite[0]["cosine_similarity"]),
                6,
            ),
            "top_5_neighbors": neighbors[:5],
        }
    problematic_pairs = {
        name: {
            "left_concept": left,
            "right_concept": right,
            "cosine_similarity": round(float(centroids[left] @ centroids[right]), 6),
            "cosine_distance": round(1.0 - float(centroids[left] @ centroids[right]), 6),
        }
        for name, (left, right) in {**BOUNDARIES, **EXTRA_NEAREST_BOUNDARIES}.items()
    }
    return {
        "global": {
            "within_concept_cosine": _similarity_summary(within_concept),
            "within_class_cosine": _similarity_summary(within_class),
            "cross_class_cosine": _similarity_summary(cross_class),
            "class_centroid_cosine_similarity": round(
                float(class_centroids[0] @ class_centroids[1]), 6
            ),
            "class_centroid_cosine_distance": round(
                1.0 - float(class_centroids[0] @ class_centroids[1]), 6
            ),
        },
        "critical_concepts": {concept: concept_details[concept] for concept in CRITICAL_CONCEPTS},
        "all_concept_nearest_neighbors": concept_details,
        "problematic_concept_pairs": problematic_pairs,
    }


def _run_grouped_evaluation(
    matrices: dict[str, Any],
    case_ids: list[str],
    label_values: list[int],
    cases: tuple[ClassifierCase, ...],
    config: Phase22Config,
) -> tuple[list[dict[str, object]], list[dict[str, object]], dict[str, Any]]:
    import numpy as np

    labels = np.asarray(label_values, dtype="int64")
    index_by_id = {case_id: index for index, case_id in enumerate(case_ids)}
    case_by_id = {case.id: case for case in cases}
    split_artifact = _build_split_artifact(cases, config.head_config())
    runs: list[dict[str, object]] = []
    predictions: list[dict[str, object]] = []
    for representation, raw_matrix in matrices.items():
        variants = {"raw": raw_matrix, "l2_normalized": _normalize(raw_matrix)}
        for normalization, matrix in variants.items():
            for definition in cast(list[dict[str, Any]], split_artifact["definitions"]):
                outer = cast(dict[str, Any], definition["outer"])
                train_ids = cast(list[str], outer["train_case_ids"])
                validation_ids = cast(list[str], outer["validation_case_ids"])
                train_indexes = np.asarray(
                    [index_by_id[value] for value in train_ids], dtype="int64"
                )
                validation_indexes = np.asarray(
                    [index_by_id[value] for value in validation_ids], dtype="int64"
                )
                for classifier_seed in config.classifier_seeds:
                    logits = _train_linear_logits(
                        matrix[train_indexes],
                        labels[train_indexes],
                        matrix[validation_indexes],
                        seed=classifier_seed,
                        config=config.head_config(),
                    )
                    probabilities = _sigmoid(logits)
                    ranking = _ranking_calibration_metrics(
                        labels[validation_indexes], probabilities, bins=5
                    )
                    ranking_values = cast(dict[str, Any], ranking)
                    threshold = _threshold_metrics(
                        labels[validation_indexes], probabilities, config.threshold
                    )
                    run_id = canonical_sha256(
                        {
                            "representation": representation,
                            "normalization": normalization,
                            "split_seed": definition["split_seed"],
                            "outer_fold": outer["fold"],
                            "classifier_seed": classifier_seed,
                        }
                    )[:20]
                    run_predictions: list[dict[str, object]] = []
                    for position, case_id in enumerate(validation_ids):
                        case = case_by_id[case_id]
                        item = {
                            "schema_version": PHASE2_2_SCHEMA_VERSION,
                            "run_id": run_id,
                            "representation": representation,
                            "normalization": normalization,
                            "split_seed": definition["split_seed"],
                            "outer_fold": outer["fold"],
                            "classifier_seed": classifier_seed,
                            "case_id": case_id,
                            "concept_id": case.concept_id,
                            "label": int(labels[validation_indexes[position]]),
                            "probability": round(float(probabilities[position]), 8),
                            "logit": round(float(logits[position]), 8),
                            "predicted_050": int(probabilities[position] >= 0.5),
                        }
                        predictions.append(item)
                        run_predictions.append(item)
                    runs.append(
                        {
                            "schema_version": PHASE2_2_SCHEMA_VERSION,
                            "run_id": run_id,
                            "representation": representation,
                            "normalization": normalization,
                            "dimension": int(matrix.shape[1]),
                            "split_seed": definition["split_seed"],
                            "outer_fold": outer["fold"],
                            "classifier_seed": classifier_seed,
                            "train_rows": len(train_indexes),
                            "validation_rows": len(validation_indexes),
                            "metrics": {
                                "roc_auc": ranking["roc_auc"],
                                "pr_auc": ranking["pr_auc"],
                                **{
                                    name: threshold[name]
                                    for name in (
                                        "recall",
                                        "precision",
                                        "f1",
                                        "benign_fpr",
                                        "balanced_accuracy",
                                    )
                                },
                                "score_minimum": ranking_values["probability"]["minimum"],
                                "score_maximum": ranking_values["probability"]["maximum"],
                                "class_mean_margin": ranking_values["class_mean_separation"],
                            },
                            "predictions": run_predictions,
                        }
                    )
    return runs, predictions, split_artifact


def _pairwise_boundary_analysis(
    predictions: list[dict[str, object]],
    geometry: dict[str, object],
    config: Phase22Config,
) -> dict[str, object]:
    output: dict[str, object] = {}
    representations = sorted(
        {(str(item["representation"]), str(item["normalization"])) for item in predictions}
    )
    for representation, normalization in representations:
        selected = [
            item
            for item in predictions
            if item["representation"] == representation and item["normalization"] == normalization
        ]
        boundaries: dict[str, object] = {}
        for name, (malicious_concept, benign_concept) in BOUNDARIES.items():
            comparisons = 0
            reversals = 0
            margins: list[float] = []
            for split_seed in config.split_seeds:
                for classifier_seed in config.classifier_seeds:
                    malicious = [
                        cast(float, item["probability"])
                        for item in selected
                        if item["split_seed"] == split_seed
                        and item["classifier_seed"] == classifier_seed
                        and item["concept_id"] == malicious_concept
                    ]
                    benign = [
                        cast(float, item["probability"])
                        for item in selected
                        if item["split_seed"] == split_seed
                        and item["classifier_seed"] == classifier_seed
                        and item["concept_id"] == benign_concept
                    ]
                    if not malicious or not benign:
                        raise Phase22RepresentationError(
                            f"incomplete OOF boundary predictions: {name}"
                        )
                    margins.append(statistics.fmean(malicious) - statistics.fmean(benign))
                    for malicious_score in malicious:
                        for benign_score in benign:
                            comparisons += 1
                            reversals += malicious_score <= benign_score
            geometry_variant = cast(dict[str, Any], geometry[representation])
            pair_geometry = geometry_variant["problematic_concept_pairs"][name]
            boundaries[name] = {
                "malicious_concept": malicious_concept,
                "benign_concept": benign_concept,
                "cosine_similarity": pair_geometry["cosine_similarity"],
                "cosine_distance": pair_geometry["cosine_distance"],
                "linear_decision_margin": _summary(margins),
                "pairwise_comparisons": comparisons,
                "pairwise_ordering_accuracy": round(1 - reversals / comparisons, 6),
                "ranking_reversal_count": reversals,
                "ranking_reversal_frequency": round(reversals / comparisons, 6),
            }
        output[f"{representation}:{normalization}"] = boundaries
    return output


def _split_disagreement(selected: list[dict[str, object]]) -> dict[str, object]:
    by_case: dict[str, dict[int, list[int]]] = defaultdict(lambda: defaultdict(list))
    for item in selected:
        by_case[str(item["case_id"])][int(cast(int, item["split_seed"]))].append(
            int(cast(int, item["predicted_050"]))
        )
    disagreements = []
    for split_values in by_case.values():
        decisions = {int(statistics.fmean(values) >= 0.5) for values in split_values.values()}
        disagreements.append(len(decisions) > 1)
    return {
        "cases": len(disagreements),
        "disagreements": sum(disagreements),
        "rate": round(sum(disagreements) / len(disagreements), 6),
    }


def _per_concept_metrics(
    predictions: list[dict[str, object]],
    geometry: dict[str, object],
) -> dict[str, object]:
    output: dict[str, object] = {}
    variants = sorted(
        {(str(item["representation"]), str(item["normalization"])) for item in predictions}
    )
    for representation, normalization in variants:
        selected = [
            item
            for item in predictions
            if item["representation"] == representation and item["normalization"] == normalization
        ]
        concepts: dict[str, object] = {}
        for concept_id in sorted({str(item["concept_id"]) for item in selected}):
            items = [item for item in selected if item["concept_id"] == concept_id]
            labels = {cast(int, item["label"]) for item in items}
            if len(labels) != 1:
                raise Phase22RepresentationError(f"mixed concept labels: {concept_id}")
            label = next(iter(labels))
            scores = [cast(float, item["probability"]) for item in items]
            errors = [item for item in items if item["predicted_050"] != item["label"]]
            geometry_item = cast(dict[str, Any], geometry[representation])[
                "all_concept_nearest_neighbors"
            ][concept_id]
            concepts[concept_id] = {
                "label": label,
                "case_ids": sorted({str(item["case_id"]) for item in items}),
                "observations": len(items),
                "score": _summary(scores),
                "false_negative_rate": (round(len(errors) / len(items), 6) if label == 1 else 0.0),
                "false_positive_rate": (round(len(errors) / len(items), 6) if label == 0 else 0.0),
                "error_count": len(errors),
                "error_split_seeds": len({item["split_seed"] for item in errors}),
                "nearest_opposite_class_concept": geometry_item["nearest_opposite_class_concept"],
                "nearest_same_class_concept": geometry_item["nearest_same_class_concept"],
                "opposite_neighbor_rank": geometry_item[
                    "opposite_neighbor_rank_among_all_concepts"
                ],
                "margin_to_closest_opposite_class_concept": geometry_item[
                    "margin_to_closest_opposite_class_concept"
                ],
            }
        output[f"{representation}:{normalization}"] = concepts
    return output


def _aggregate_runs(
    runs: list[dict[str, object]],
    predictions: list[dict[str, object]],
    pairwise: dict[str, object],
    concepts: dict[str, object],
) -> dict[str, object]:
    output: dict[str, object] = {}
    variants = sorted({(str(run["representation"]), str(run["normalization"])) for run in runs})
    for representation, normalization in variants:
        selected_runs = [
            run
            for run in runs
            if run["representation"] == representation and run["normalization"] == normalization
        ]
        selected_predictions = [
            item
            for item in predictions
            if item["representation"] == representation and item["normalization"] == normalization
        ]
        metrics = {
            metric: _summary(
                [float(cast(dict[str, Any], run["metrics"])[metric]) for run in selected_runs]
            )
            for metric in (
                "roc_auc",
                "pr_auc",
                "recall",
                "precision",
                "f1",
                "benign_fpr",
                "balanced_accuracy",
                "score_minimum",
                "score_maximum",
                "class_mean_margin",
            )
        }
        variant_name = f"{representation}:{normalization}"
        boundary = cast(dict[str, Any], pairwise[variant_name])
        critical_reversals = sum(int(item["ranking_reversal_count"]) for item in boundary.values())
        concept_variant = cast(dict[str, Any], concepts[variant_name])
        critical_errors = sum(
            int(concept_variant[concept]["error_count"]) for concept in CRITICAL_CONCEPTS
        )
        outside_errors = sum(
            int(value["error_count"])
            for concept, value in concept_variant.items()
            if concept not in CRITICAL_CONCEPTS
        )
        output[variant_name] = {
            "representation": representation,
            "normalization": normalization,
            "dimension": selected_runs[0]["dimension"],
            "runs": len(selected_runs),
            "metrics": metrics,
            "split_disagreement": _split_disagreement(selected_predictions),
            "critical_boundary_reversals": critical_reversals,
            "critical_concept_errors": critical_errors,
            "outside_critical_concept_errors": outside_errors,
            "critical_concepts": {
                concept: concept_variant[concept] for concept in CRITICAL_CONCEPTS
            },
        }
    return output


def _selection(
    aggregate: dict[str, object],
    pairwise: dict[str, object],
    config: Phase22Config,
) -> dict[str, object]:
    baseline_name = "A_baseline_final_mean:l2_normalized"
    baseline = cast(dict[str, Any], aggregate[baseline_name])
    baseline_reversals = int(baseline["critical_boundary_reversals"])
    candidates: list[dict[str, object]] = []
    for name, raw in aggregate.items():
        value = cast(dict[str, Any], raw)
        reversal_reduction = (
            (baseline_reversals - int(value["critical_boundary_reversals"])) / baseline_reversals
            if baseline_reversals
            else 0.0
        )
        ranking_ok = (
            float(value["metrics"]["roc_auc"]["mean"])
            >= float(baseline["metrics"]["roc_auc"]["mean"]) - config.material_ranking_degradation
            and float(value["metrics"]["pr_auc"]["mean"])
            >= float(baseline["metrics"]["pr_auc"]["mean"]) - config.material_ranking_degradation
        )
        split_ok = (
            float(value["split_disagreement"]["rate"])
            <= float(baseline["split_disagreement"]["rate"])
            + config.material_split_disagreement_increase
        )
        fpr_ok = (
            float(value["metrics"]["benign_fpr"]["mean"])
            <= float(baseline["metrics"]["benign_fpr"]["mean"]) + config.material_fpr_increase
        )
        new_boundary_ok = (
            int(value["outside_critical_concept_errors"])
            <= int(baseline["outside_critical_concept_errors"])
            + config.new_boundary_error_observations
        )
        baseline_pairs = cast(dict[str, Any], pairwise[baseline_name])
        current_pairs = cast(dict[str, Any], pairwise[name])
        margin_improvements = [
            float(current_pairs[boundary]["linear_decision_margin"]["mean"])
            - float(baseline_pairs[boundary]["linear_decision_margin"]["mean"])
            for boundary in BOUNDARIES
        ]
        margins_improve = statistics.fmean(margin_improvements) > 0
        material_reversals = reversal_reduction >= config.material_reversal_reduction
        qualifies = (
            ranking_ok
            and split_ok
            and fpr_ok
            and new_boundary_ok
            and margins_improve
            and material_reversals
        )
        candidates.append(
            {
                "variant": name,
                "qualifies": qualifies,
                "ranking_not_materially_degraded": ranking_ok,
                "split_disagreement_not_materially_worse": split_ok,
                "benign_fpr_not_materially_worse": fpr_ok,
                "no_new_major_boundary_failure": new_boundary_ok,
                "mean_critical_margin_delta": round(statistics.fmean(margin_improvements), 6),
                "critical_reversal_reduction": round(reversal_reduction, 6),
                "critical_reversal_delta": (
                    int(value["critical_boundary_reversals"]) - baseline_reversals
                ),
            }
        )
    qualified = [item for item in candidates if item["qualifies"]]
    ranked = sorted(
        qualified or candidates,
        key=lambda item: (
            -cast(float, item["critical_reversal_reduction"]),
            -cast(float, item["mean_critical_margin_delta"]),
            -float(
                cast(dict[str, Any], aggregate[cast(str, item["variant"])])["metrics"]["roc_auc"][
                    "mean"
                ]
            ),
            cast(str, item["variant"]),
        ),
    )
    best = ranked[0]
    best_value = cast(dict[str, Any], aggregate[cast(str, best["variant"])])
    remaining_reversals = int(best_value["critical_boundary_reversals"])
    if qualified and remaining_reversals == 0:
        choice = "A. REPRESENTATION EXTRACTION FIXES THE LOCAL BOUNDARIES"
        next_action = (
            "carry the selected frozen representation into one preregistered "
            "threshold-validation pass"
        )
    elif qualified:
        choice = "B. REPRESENTATION EXTRACTION HELPS PARTIALLY"
        next_action = "design one narrowly scoped partial-unfreezing experiment"
    else:
        reversal_values = {
            int(cast(dict[str, Any], value)["critical_boundary_reversals"])
            for value in aggregate.values()
        }
        if len(reversal_values) == 1:
            choice = "C. REPRESENTATION EXTRACTION DOES NOT SOLVE THE COLLISIONS"
            next_action = (
                "justify one partial encoder-unfreezing experiment focused on "
                "representation adaptation"
            )
        else:
            choice = "D. RESULTS ARE TOO SMALL/UNSTABLE TO DISTINGUISH REPRESENTATIONS"
            next_action = (
                "stop model changes; the minimum distinguishing evidence is exactly eight "
                "new independent trusted concepts: two each for malicious exfiltration, "
                "malicious direct override, benign security education, and benign quoted "
                "attack content; every case must be independently authored rather than a "
                "paraphrase, translation, template sibling, or lineage relative"
            )
    return {
        "choice": choice,
        "baseline": baseline_name,
        "selected_variant": best["variant"] if qualified else None,
        "best_observed_variant": best["variant"],
        "selection_candidates": candidates,
        "qualified_variants": [item["variant"] for item in qualified],
        "next_action": next_action,
    }


def run_phase2_2_representation_experiment(
    gold_path: Path,
    model_path: Path,
    output_directory: Path,
    *,
    expected_base_freeze_sha256: str,
    config: Phase22Config | None = None,
) -> dict[str, object]:
    """Compare only the six preregistered frozen representation variants."""
    import numpy as np

    config = config or Phase22Config()
    output_directory = output_directory.resolve()
    paths = {
        "manifest": output_directory / "v0.4.2-phase2.2-representation-manifest.json",
        "cache": output_directory / "v0.4.2-phase2.2-representation-cache.npz",
        "cache_metadata": output_directory / "v0.4.2-phase2.2-cache-metadata.json",
        "runs": output_directory / "v0.4.2-phase2.2-per-run-metrics.jsonl",
        "predictions": output_directory / "v0.4.2-phase2.2-per-run-predictions.jsonl",
        "concepts": output_directory / "v0.4.2-phase2.2-per-concept-metrics.json",
        "geometry": output_directory / "v0.4.2-phase2.2-representation-geometry.json",
        "boundaries": output_directory / "v0.4.2-phase2.2-pairwise-boundaries.json",
        "neighbors": output_directory / "v0.4.2-phase2.2-nearest-neighbors.json",
        "aggregate": output_directory / "v0.4.2-phase2.2-aggregate-comparison.json",
        "decision": output_directory / "v0.4.2-phase2.2-final-decision.json",
        "report": output_directory / "v0.4.2-phase2.2-representation-experiment.json",
        "markdown": output_directory / "v0.4.2-phase2.2-representation-experiment.md",
    }
    if any(path.exists() or path.is_symlink() for path in paths.values()):
        raise Phase22RepresentationError("a Phase 2.2 output artifact already exists")
    inspected = inspect_local_model(model_path)
    if inspected.get("directory_freeze_sha256") != expected_base_freeze_sha256:
        raise Phase22RepresentationError("encoder freeze changed before Phase 2.2")
    validated = validate_local_model(model_path)
    if (
        validated.get("validation") != "PASS"
        or validated.get("network_used") is not False
        or validated.get("directory_freeze_sha256") != expected_base_freeze_sha256
    ):
        raise Phase22RepresentationError("encoder failed offline validation")
    gold_hash_before = _sha256_file(gold_path)
    cases, provenance = _validated_trusted_gold(gold_path)
    phase21 = _validate_phase21_binding(output_directory, gold_path, expected_base_freeze_sha256)
    started = time.perf_counter()
    matrices, case_ids, labels, runtime_validation = _extract_representations(
        model_path, cases, config
    )
    cache_temporary = paths["cache"].with_name(f".{paths['cache'].name}.tmp-{os.getpid()}.npz")
    np.savez_compressed(
        cache_temporary,
        **matrices,
        case_ids=np.asarray(case_ids),
        labels=np.asarray(labels, dtype="int64"),
    )
    os.replace(cache_temporary, paths["cache"])
    cache_metadata = {
        "schema_version": PHASE2_2_SCHEMA_VERSION,
        "path": paths["cache"].as_posix(),
        "sha256": _sha256_file(paths["cache"]),
        "rows": len(case_ids),
        "representations": {
            name: {"dimension": int(matrix.shape[1]), "dtype": str(matrix.dtype)}
            for name, matrix in matrices.items()
        },
        "gold_file_sha256": gold_hash_before,
        "gold_semantic_sha256": corpus_hash(cases),
        "encoder_freeze_sha256": expected_base_freeze_sha256,
        "configuration_sha256": canonical_sha256(config.to_dict()),
        "ordered_case_ids_sha256": canonical_sha256(case_ids),
        "labels_sha256": canonical_sha256(labels),
        "input_text_persisted": False,
        "encoder_trainable": False,
        "network_used": False,
    }
    _write_json(paths["cache_metadata"], cache_metadata)
    manifest = {
        "schema_version": PHASE2_2_SCHEMA_VERSION,
        "configuration": config.to_dict(),
        "configuration_sha256": canonical_sha256(config.to_dict()),
        "runtime_representation_validation": runtime_validation,
        "valid_variants": list(REPRESENTATIONS),
        "rejected_variants": [],
        "equivalence_note": (
            "A, C, and D are reported separately but are exactly identical for a binary "
            "attention mask; they are not independent evidence."
        ),
        "phase2_1_report_sha256": _sha256_file(
            output_directory / "v0.4.2-phase2.1-diagnostics.json"
        ),
        "encoder_freeze_sha256": expected_base_freeze_sha256,
        "gold_file_sha256": gold_hash_before,
    }
    _write_json(paths["manifest"], manifest)
    geometry: dict[str, object] = {
        name: _representation_geometry(matrix, case_ids, cases) for name, matrix in matrices.items()
    }
    _write_json(paths["geometry"], {"schema_version": 1, "representations": geometry})
    _write_json(
        paths["neighbors"],
        {
            "schema_version": 1,
            "representations": {
                name: cast(dict[str, Any], value)["all_concept_nearest_neighbors"]
                for name, value in geometry.items()
            },
            "specific_required_neighbors": {
                "direct_override_nearest_benign_quoted_attack": QUOTED_ATTACK_CONCEPT,
                "exfiltration_nearest_benign_security_discussion": (
                    EXFIL_NEAREST_SECURITY_DISCUSSION
                ),
            },
        },
    )
    runs, predictions, splits = _run_grouped_evaluation(matrices, case_ids, labels, cases, config)
    _write_jsonl(paths["runs"], runs)
    _write_jsonl(paths["predictions"], predictions)
    boundaries = _pairwise_boundary_analysis(predictions, geometry, config)
    _write_json(paths["boundaries"], {"schema_version": 1, "variants": boundaries})
    concepts = _per_concept_metrics(predictions, geometry)
    _write_json(paths["concepts"], {"schema_version": 1, "variants": concepts})
    aggregate = _aggregate_runs(runs, predictions, boundaries, concepts)
    selection = _selection(aggregate, boundaries, config)
    _write_json(
        paths["aggregate"],
        {"schema_version": 1, "variants": aggregate, "selection": selection},
    )
    _write_json(paths["decision"], {"schema_version": 1, **selection})
    if _sha256_file(gold_path) != gold_hash_before:
        raise Phase22RepresentationError("gold changed during Phase 2.2")
    if (
        inspect_local_model(model_path).get("directory_freeze_sha256")
        != expected_base_freeze_sha256
    ):
        raise Phase22RepresentationError("encoder changed during Phase 2.2")
    report: dict[str, object] = {
        "schema_version": PHASE2_2_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "PHASE 2.2 REPRESENTATION BOUNDARY EXPERIMENT COMPLETE",
        "gold": {
            "path": gold_path.resolve().as_posix(),
            "file_sha256": gold_hash_before,
            "semantic_sha256": corpus_hash(cases),
            "rows": len(cases),
            "concepts": len(conceptual_groups(cases)),
            "provenance_validation": provenance["validation"],
        },
        "encoder": validated,
        "phase2_1_binding": {
            "decision": phase21["decision"]["choice"],
            "report_sha256": manifest["phase2_1_report_sha256"],
        },
        "configuration": config.to_dict(),
        "configuration_sha256": canonical_sha256(config.to_dict()),
        "split_binding": {
            "semantic_sha256": splits["semantic_sha256"],
            "outer_cells": config.folds * len(config.split_seeds),
            "leakage": "PASS",
        },
        "cache": cache_metadata,
        "aggregate": aggregate,
        "pairwise_boundaries": boundaries,
        "decision": selection,
        "results": {
            "runs": len(runs),
            "predictions": len(predictions),
            "artifacts": {
                name: {"path": path.as_posix(), "sha256": _sha256_file(path)}
                for name, path in paths.items()
                if name not in {"report", "markdown"}
            },
        },
        "runtime": {
            "duration_seconds": round(time.perf_counter() - started, 3),
            "python": platform.python_version(),
            "numpy": np.__version__,
        },
        "safety": {
            "network_used": False,
            "downloads": 0,
            "encoder_updated": False,
            "new_labels": 0,
            "human_review": False,
            "pseudo_labels": 0,
            "batch_06_created": False,
            "partial_unfreezing": False,
            "full_fine_tuning": False,
            "development_shadow_used": False,
            "production_model_selected": None,
            "blind_set_e_burned": False,
        },
    }
    _write_json(paths["report"], report)
    best_name = cast(str, selection["best_observed_variant"])
    best = cast(dict[str, Any], aggregate[best_name])
    best_roc = best["metrics"]["roc_auc"]["mean"]
    best_pr = best["metrics"]["pr_auc"]["mean"]
    best_recall = best["metrics"]["recall"]["mean"]
    best_fpr = best["metrics"]["benign_fpr"]["mean"]
    markdown = f"""# SecureInjections v0.4.2 — Phase 2.2 representation experiment

Decision: **{selection["choice"]}**

- Gold: {len(cases)} rows / {len(conceptual_groups(cases))} concepts
- Encoder freeze: `{expected_base_freeze_sha256}`
- Frozen representations / normalization variants: 6 / 12
- Grouped runs: {len(runs)}
- Best observed variant: `{best_name}` ({best["dimension"]} dimensions)
- ROC-AUC / PR-AUC: {best_roc} / {best_pr}
- Recall / benign FPR at 0.5: {best_recall} / {best_fpr}
- Split disagreement: {best["split_disagreement"]["rate"]}

A, C, and D are exactly equivalent for this binary attention mask and are not independent evidence.
All detailed representation, geometry, per-concept, nearest-neighbor, and boundary results are in
the adjacent machine-readable artifacts.

Next action: {selection["next_action"]}.

No encoder updates, new labels, review batch, production selection, network access, development
shadow, or Blind Set E use occurred.
"""
    _atomic_text(paths["markdown"], markdown)
    return report
