"""Optional reproducible training pipeline for local multilingual intent classifiers."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .classifier import ATTACK_LABELS, IntentLabel, sha256_file
from .classifier_calibration import calibrate_thresholds, fit_temperature
from .classifier_data import (
    ClassifierCase,
    class_weights,
    corpus_hash,
    corpus_readiness,
    duplicate_audit,
    language_sampling_weights,
    load_classifier_corpus,
    split_report,
    validate_group_isolation,
)
from .model_import import ModelImportError, validate_local_model


class ClassifierTrainingError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TrainingConfig:
    seed: int = 42
    epochs: int = 3
    batch_size: int = 16
    learning_rate: float = 2e-5
    max_length: int = 256
    classifier_version: str = "secureinjections-classifier-0.1"
    max_validation_fpr: float = 0.05

    def __post_init__(self) -> None:
        if self.seed < 0 or self.epochs < 1 or self.batch_size < 1:
            raise ValueError("seed must be non-negative and epochs/batch_size must be positive")
        if not 0 < self.learning_rate < 1 or not 8 <= self.max_length <= 8192:
            raise ValueError("learning_rate or max_length is invalid")
        if not 0 <= self.max_validation_fpr <= 1:
            raise ValueError("max_validation_fpr must be between 0 and 1")


def hash_directory(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(path.rglob("*")):
        if item.is_symlink():
            raise ClassifierTrainingError(f"symlinks are forbidden in model artifacts: {item}")
        if not item.is_file():
            continue
        digest.update(item.relative_to(path).as_posix().encode("utf-8") + b"\0")
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _validate_local_base_model(path: Path) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ClassifierTrainingError("base model path does not exist locally") from exc
    if path.is_symlink() or not resolved.is_dir():
        raise ClassifierTrainingError("base model must be a real local directory")
    try:
        validate_local_model(resolved, smoke_test=False)
    except ModelImportError as exc:
        raise ClassifierTrainingError(str(exc)) from exc
    return resolved


def _versions(packages: tuple[str, ...]) -> dict[str, str]:
    result = {"python": platform.python_version()}
    for package in packages:
        try:
            result[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            result[package] = "not-installed"
    return result


def train_classifier(
    base_model_path: Path,
    corpus_path: Path,
    output_path: Path,
    *,
    config: TrainingConfig | None = None,
    excluded_language: str | None = None,
) -> dict[str, Any]:
    """Fine-tune a local sequence classifier and calibrate using validation only."""
    config = config or TrainingConfig()
    base_model = _validate_local_base_model(base_model_path)
    cases = load_classifier_corpus(corpus_path)
    readiness = corpus_readiness(cases)
    if readiness["status"] != "READY FOR LOCAL MODEL BAKE-OFF":
        raw_reasons = readiness.get("reasons")
        reasons = (
            "; ".join(str(reason) for reason in raw_reasons)
            if isinstance(raw_reasons, list)
            else "unspecified readiness failure"
        )
        raise ClassifierTrainingError(f"classifier corpus is not ready: {reasons}")
    validate_group_isolation(cases)
    leakage = duplicate_audit(cases)
    if not leakage["passed"]:
        raise ClassifierTrainingError(
            "cross-split duplicate leakage detected; inspect leakage report"
        )
    if output_path.exists() and any(output_path.iterdir()):
        raise ClassifierTrainingError("output directory already exists and is not empty")
    training = tuple(
        case
        for case in cases
        if case.split == "train"
        and (excluded_language is None or case.language != excluded_language)
    )
    validation = tuple(
        case
        for case in cases
        if case.split == "validation"
        and (excluded_language is None or case.language == excluded_language)
    )
    if not training or not validation:
        raise ClassifierTrainingError("training and validation selections must both be non-empty")
    try:
        import torch
        from torch.utils.data import DataLoader, Dataset, WeightedRandomSampler
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:  # pragma: no cover - optional environment
        raise ClassifierTrainingError(
            "training dependencies are unavailable; install secureinjections[training]"
        ) from exc

    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    random.seed(config.seed)
    torch.manual_seed(config.seed)
    if hasattr(torch, "use_deterministic_algorithms"):
        torch.use_deterministic_algorithms(True, warn_only=True)
    labels = tuple(IntentLabel)
    label_to_id = {label: index for index, label in enumerate(labels)}
    tokenizer = AutoTokenizer.from_pretrained(
        str(base_model), local_files_only=True, trust_remote_code=False
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        str(base_model),
        local_files_only=True,
        trust_remote_code=False,
        use_safetensors=True,
        num_labels=len(labels),
        id2label={index: label.value for index, label in enumerate(labels)},
        label2id={label.value: index for index, label in enumerate(labels)},
        ignore_mismatched_sizes=True,
    )

    class TextDataset(Dataset):  # type: ignore[misc]
        def __init__(self, selected: tuple[ClassifierCase, ...]) -> None:
            self.selected = selected

        def __len__(self) -> int:
            return len(self.selected)

        def __getitem__(self, index: int) -> tuple[str, int]:
            case = self.selected[index]
            return case.text, label_to_id[case.label]

    def collate(batch: list[tuple[str, int]]) -> dict[str, Any]:
        texts, target_ids = zip(*batch, strict=True)
        encoded = tokenizer(
            list(texts),
            padding=True,
            truncation=True,
            max_length=config.max_length,
            return_tensors="pt",
        )
        encoded["labels"] = torch.tensor(target_ids, dtype=torch.long)
        return encoded

    class_balance = class_weights(training)
    language_balance = language_sampling_weights(training)
    sample_weights = [
        class_balance[case.label] * language_balance[case.language] for case in training
    ]
    generator = torch.Generator().manual_seed(config.seed)
    sampler = WeightedRandomSampler(
        sample_weights, len(sample_weights), replacement=True, generator=generator
    )
    loader = DataLoader(
        TextDataset(training),
        batch_size=config.batch_size,
        sampler=sampler,
        collate_fn=collate,
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=config.learning_rate)
    weights = torch.tensor([class_balance.get(label, 1.0) for label in labels], dtype=torch.float32)
    criterion = torch.nn.CrossEntropyLoss(weight=weights)
    model.train()
    epoch_losses: list[float] = []
    for _ in range(config.epochs):
        running = 0.0
        batches = 0
        for batch in loader:
            optimizer.zero_grad(set_to_none=True)
            targets = batch.pop("labels")
            logits = model(**batch).logits
            loss = criterion(logits, targets)
            loss.backward()
            optimizer.step()
            running += float(loss.detach())
            batches += 1
        epoch_losses.append(running / max(1, batches))

    model.eval()
    validation_loader = DataLoader(
        TextDataset(validation), batch_size=config.batch_size, shuffle=False, collate_fn=collate
    )
    validation_logits: list[list[float]] = []
    validation_labels: list[int] = []
    with torch.inference_mode():
        for batch in validation_loader:
            targets = batch.pop("labels")
            output = model(**batch).logits.detach().cpu()
            validation_logits.extend(output.tolist())
            validation_labels.extend(targets.tolist())
    temperature = fit_temperature(validation_logits, validation_labels)
    malicious_probabilities = []
    malicious_labels = []
    for row, target in zip(validation_logits, validation_labels, strict=True):
        probabilities = torch.softmax(torch.tensor(row) / temperature, dim=-1).tolist()
        malicious_probabilities.append(
            sum(probabilities[label_to_id[label]] for label in ATTACK_LABELS)
        )
        malicious_labels.append(labels[target] in ATTACK_LABELS)
    calibration = calibrate_thresholds(
        malicious_probabilities,
        malicious_labels,
        max_fpr=config.max_validation_fpr,
    )

    output_path.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(output_path, safe_serialization=True)
    tokenizer.save_pretrained(output_path)
    weights_path = output_path / "model.safetensors"
    if not weights_path.is_file():
        raise ClassifierTrainingError("training did not produce model.safetensors")
    trained_languages = sorted({case.language for case in training})
    metadata = {
        "schema_version": 1,
        "classifier_version": config.classifier_version,
        "base_model": base_model.name,
        "base_model_sha256": hash_directory(base_model),
        "weights_sha256": sha256_file(weights_path),
        "labels": [label.value for label in labels],
        "thresholds": {
            "allow_max": calibration.thresholds.allow_max,
            "block_min": calibration.thresholds.block_min,
        },
        "temperature": temperature,
        "max_length": config.max_length,
        "languages": trained_languages,
        "training_corpus_sha256": corpus_hash(cases),
        "license": "See MODEL_CARD.md and base-model license",
    }
    (output_path / "classifier.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    report = {
        "classifier_version": config.classifier_version,
        "seed": config.seed,
        "arguments": {
            "epochs": config.epochs,
            "batch_size": config.batch_size,
            "learning_rate": config.learning_rate,
            "max_length": config.max_length,
            "excluded_language": excluded_language,
        },
        "dependencies": _versions(("torch", "transformers", "safetensors")),
        "hashes": {
            "base_model": metadata["base_model_sha256"],
            "training_corpus": metadata["training_corpus_sha256"],
            "weights": metadata["weights_sha256"],
        },
        "dataset": split_report(cases),
        "leakage_audit": leakage,
        "training_epoch_losses": epoch_losses,
        "validation_calibration": calibration.to_dict(),
    }
    (output_path / "training-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    card = f"""# {config.classifier_version}

## Model details

- Base model: `{base_model.name}`
- Base model SHA-256: `{metadata["base_model_sha256"]}`
- Model weights SHA-256: `{metadata["weights_sha256"]}`
- Training corpus SHA-256: `{metadata["training_corpus_sha256"]}`
- Languages: {", ".join(trained_languages)}
- Labels: {", ".join(label.value for label in labels)}
- Training seed: {config.seed}

## Intended use

Optional local second-stage intent classification for SecureInjections {config.classifier_version}.
It is a defense-in-depth signal and does not guarantee detection of malicious input.

## Non-intended use

Do not use as an authorization decision, as a standalone security boundary, or to process text
under a license incompatible with the base model or training corpus.

## Validation

Calibration used the grouped validation split only. See `training-report.json` for measured values,
dependencies, configuration, provenance, and the duplicate/leakage audit.

## Known limitations

Performance may vary by language, attack family, domain, context, and obfuscation. Review
leave-language-out, shadow, and frozen blind evaluation results before production use.

## License compatibility

The operator must verify compatibility of the base-model license and every corpus source license.
"""
    (output_path / "MODEL_CARD.md").write_text(card, encoding="utf-8")
    return report
