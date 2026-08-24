"""Fail-closed inspection and validation for offline classifier base-model imports."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

MODEL_IMPORT_SCHEMA_VERSION = 1
MODEL_IMPORT_MANIFEST = "secureinjections-model.json"
TARGET_LANGUAGES = frozenset({"da", "de", "en", "es", "fr", "it", "nl", "no", "pl", "pt", "sv"})
SUPPORTED_MODEL_TYPES = frozenset(
    {
        "bert",
        "deberta",
        "deberta-v2",
        "distilbert",
        "electra",
        "rembert",
        "roberta",
        "xlm-roberta",
    }
)
UNSAFE_SUFFIXES = frozenset({".bin", ".ckpt", ".joblib", ".pickle", ".pkl", ".pt", ".pth"})
TOKENIZER_VOCAB_LAYOUTS = (
    frozenset({"tokenizer.json"}),
    frozenset({"vocab.txt"}),
    frozenset({"sentencepiece.bpe.model"}),
    frozenset({"tokenizer.model"}),
    frozenset({"spiece.model"}),
    frozenset({"vocab.json", "merges.txt"}),
)
RECOMMENDED_MAX_BYTES = 750 * 1024 * 1024
HARD_MAX_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILES = 256
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_TOKENIZER_JSON_BYTES = 128 * 1024 * 1024


class ModelImportError(ValueError):
    """A local model cannot satisfy the SecureInjections offline import contract."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(
    path: Path,
    description: str,
    *,
    allow_symlink: bool = False,
    max_bytes: int = MAX_JSON_BYTES,
) -> Any:
    if (
        (path.is_symlink() and not allow_symlink)
        or not path.is_file()
        or path.stat().st_size > max_bytes
    ):
        raise ModelImportError(f"{description} is missing, unsafe, or oversized")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ModelImportError(f"{description} is not valid UTF-8 JSON") from exc


def _safe_relative_name(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ModelImportError("model manifest contains an invalid file name")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value != path.as_posix():
        raise ModelImportError("model manifest file names must be normalized relative paths")
    return value


def _valid_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _safetensors_header(path: Path) -> dict[str, Any]:
    """Validate the bounded JSON header and tensor offsets without loading tensor data."""
    size = path.stat().st_size
    if size < 10:
        raise ModelImportError(f"safetensors file is truncated: {path.name}")
    with path.open("rb") as handle:
        raw_length = handle.read(8)
        header_length = struct.unpack("<Q", raw_length)[0]
        if not 2 <= header_length <= min(MAX_JSON_BYTES, size - 8):
            raise ModelImportError(f"safetensors header is invalid: {path.name}")
        try:
            header = json.loads(handle.read(header_length).decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ModelImportError(f"safetensors header is invalid: {path.name}") from exc
    if not isinstance(header, dict):
        raise ModelImportError(f"safetensors header is invalid: {path.name}")
    tensors = {name: value for name, value in header.items() if name != "__metadata__"}
    if not tensors:
        raise ModelImportError(f"safetensors file contains no tensors: {path.name}")
    data_size = size - 8 - header_length
    for name, value in tensors.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            raise ModelImportError(f"safetensors tensor metadata is invalid: {path.name}")
        offsets = value.get("data_offsets")
        shape = value.get("shape")
        dtype = value.get("dtype")
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or not all(isinstance(item, int) and not isinstance(item, bool) for item in offsets)
            or offsets[0] < 0
            or offsets[0] > offsets[1]
            or offsets[1] > data_size
            or not isinstance(shape, list)
            or not all(isinstance(item, int) and item >= 0 for item in shape)
            or not isinstance(dtype, str)
            or not dtype
        ):
            raise ModelImportError(f"safetensors tensor metadata is invalid: {path.name}")
    return {"tensor_count": len(tensors), "header_bytes": header_length}


def _weight_files(path: Path, names: set[str]) -> tuple[str, ...]:
    if "model.safetensors" in names:
        extras = sorted(
            name for name in names if name.endswith(".safetensors") and name != "model.safetensors"
        )
        if extras:
            raise ModelImportError("unreferenced safetensors files are forbidden")
        return ("model.safetensors",)
    index_name = "model.safetensors.index.json"
    if index_name not in names:
        raise ModelImportError("model.safetensors or a safetensors shard index is required")
    raw = _read_json(path / index_name, "safetensors shard index", allow_symlink=True)
    if not isinstance(raw, dict) or not isinstance(raw.get("weight_map"), dict):
        raise ModelImportError("safetensors shard index is malformed")
    weight_map = raw["weight_map"]
    shards = tuple(sorted({_safe_relative_name(value) for value in weight_map.values()}))
    if not shards or any(not name.endswith(".safetensors") for name in shards):
        raise ModelImportError("safetensors shard index contains invalid shard names")
    actual = {name for name in names if name.endswith(".safetensors")}
    if actual != set(shards) or any("/" in name for name in shards):
        raise ModelImportError("safetensors shard set does not match its index")
    return shards


def _model_dimension(config: dict[str, Any]) -> int | None:
    for key in ("hidden_size", "d_model", "dim", "embedding_size"):
        value = config.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return None


def _local_card_metadata(path: Path) -> tuple[list[str], str | None]:
    card = path / "README.md"
    if not card.is_file() or card.stat().st_size > MAX_JSON_BYTES:
        return [], None
    try:
        head = card.read_text(encoding="utf-8")[:16_384]
    except (OSError, UnicodeError):
        return [], None
    languages: list[str] = []
    license_name: str | None = None
    for line in head.splitlines():
        stripped = line.strip()
        if stripped.startswith("language:"):
            value = stripped.partition(":")[2].strip().strip("[]")
            languages.extend(item.strip().strip("'\"") for item in value.split(",") if item.strip())
        elif stripped.startswith("license:"):
            license_name = stripped.partition(":")[2].strip().strip("'\"") or None
    return sorted(set(languages)), license_name


def _manifest_details(
    path: Path, files: tuple[Path, ...]
) -> tuple[dict[str, Any] | None, list[str]]:
    manifest_path = path / MODEL_IMPORT_MANIFEST
    if not manifest_path.is_file() or manifest_path.is_symlink():
        return None, [f"{MODEL_IMPORT_MANIFEST} is required by the offline import contract"]
    try:
        raw = _read_json(manifest_path, "offline model import manifest")
    except ModelImportError as exc:
        return None, [str(exc)]
    required = {
        "schema_version",
        "model_id",
        "revision",
        "architecture",
        "languages",
        "license",
        "provenance",
        "files",
    }
    issues: list[str] = []
    if not isinstance(raw, dict) or set(raw) != required:
        return None, ["offline model import manifest fields are invalid"]
    if raw["schema_version"] != MODEL_IMPORT_SCHEMA_VERSION:
        issues.append("unsupported offline model import schema")
    for name in ("model_id", "revision", "architecture"):
        if not isinstance(raw[name], str) or not raw[name].strip():
            issues.append(f"manifest {name} is invalid")
    languages = raw["languages"]
    if (
        not isinstance(languages, list)
        or not languages
        or len(languages) != len(set(languages))
        or not all(isinstance(value, str) and value for value in languages)
    ):
        issues.append("manifest languages must be a non-empty unique list")
    license_data = raw["license"]
    if not isinstance(license_data, dict) or set(license_data) != {"spdx", "file"}:
        issues.append("manifest license metadata is invalid")
    else:
        if not isinstance(license_data["spdx"], str) or not license_data["spdx"].strip():
            issues.append("manifest license SPDX expression is invalid")
        try:
            license_file = _safe_relative_name(license_data["file"])
            license_path = path / license_file
            if (
                license_path.is_symlink()
                or not license_path.is_file()
                or license_path.stat().st_size == 0
            ):
                issues.append("manifest license file is missing or unsafe")
        except ModelImportError as exc:
            issues.append(str(exc))
    provenance = raw["provenance"]
    provenance_fields = {"source", "revision", "acquired_at", "acquisition_method"}
    if not isinstance(provenance, dict) or set(provenance) != provenance_fields:
        issues.append("manifest provenance metadata is invalid")
    elif any(
        not isinstance(provenance[name], str) or not provenance[name].strip()
        for name in provenance_fields
    ):
        issues.append("manifest provenance values must be non-empty strings")
    else:
        if raw["revision"] != provenance["revision"]:
            issues.append("manifest and provenance revisions do not match")
        acquired_at = provenance["acquired_at"]
        if (
            len(acquired_at) != 10
            or acquired_at[4] != "-"
            or acquired_at[7] != "-"
            or not acquired_at.replace("-", "").isdigit()
        ):
            issues.append("manifest acquired_at must use YYYY-MM-DD")
    hashes = raw["files"]
    expected_names = {
        item.relative_to(path).as_posix() for item in files if item.name != MODEL_IMPORT_MANIFEST
    }
    if not isinstance(hashes, dict):
        issues.append("manifest files must be a path-to-SHA-256 object")
    else:
        try:
            manifest_names = {_safe_relative_name(name) for name in hashes}
        except ModelImportError as exc:
            issues.append(str(exc))
            manifest_names = set()
        if manifest_names != expected_names:
            issues.append("manifest must hash every model file and no absent file")
        for name, expected in hashes.items():
            if not _valid_sha256(expected) or expected != expected.lower():
                issues.append(f"manifest SHA-256 is invalid: {name}")
            elif name in expected_names and _sha256_file(path / name) != expected:
                issues.append(f"model asset hash mismatch: {name}")
    return raw, issues


def inspect_local_model(model_path: Path) -> dict[str, Any]:
    """Inspect an explicit local model path without importing a runtime or using the network."""
    try:
        resolved = model_path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ModelImportError("model path does not exist locally") from exc
    if model_path.is_symlink():
        raise ModelImportError("model path itself may not be a symlink")
    if resolved.is_file():
        return {
            "schema_version": MODEL_IMPORT_SCHEMA_VERSION,
            "path": resolved.as_posix(),
            "format": resolved.suffix.lower().lstrip(".") or "unknown",
            "architecture": None,
            "embedding_dimension": None,
            "tokenizer": {"available": resolved.suffix.lower() == ".gguf", "files": []},
            "languages": [],
            "multilingual_suitable": False,
            "license": None,
            "artifact_size_bytes": resolved.stat().st_size,
            "asset_sha256": _sha256_file(resolved),
            "config_complete": False,
            "tokenizer_complete": resolved.suffix.lower() == ".gguf",
            "weights_complete": resolved.suffix.lower() == ".gguf",
            "import_contract_complete": False,
            "supported_architecture": False,
            "secureinjections_offline_loadable": False,
            "classification": "unsupported",
            "issues": ["only Transformers safetensors encoder directories are supported"],
            "warnings": [],
            "network_used": False,
        }
    if not resolved.is_dir():
        raise ModelImportError("model path must be a local file or directory")
    files = tuple(
        sorted(
            (item for item in resolved.rglob("*") if item.is_file()),
            key=lambda item: item.relative_to(resolved).as_posix(),
        )
    )
    if len(files) > MAX_FILES:
        raise ModelImportError("model directory contains too many files")
    names = {item.relative_to(resolved).as_posix() for item in files}
    symlinks = sorted(
        item.relative_to(resolved).as_posix() for item in resolved.rglob("*") if item.is_symlink()
    )
    unsafe = sorted(name for name in names if Path(name).suffix.lower() in UNSAFE_SUFFIXES)
    custom_python = sorted(name for name in names if name.endswith(".py"))
    total_bytes = sum(item.stat().st_size for item in files)
    issues: list[str] = []
    warnings: list[str] = []
    if symlinks:
        issues.append("symlinks are forbidden in frozen imported model directories")
    if unsafe:
        issues.append("pickle-capable model serialization is forbidden")
    if custom_python:
        issues.append("repository-supplied Python code is forbidden")
    if total_bytes > HARD_MAX_BYTES:
        issues.append("model exceeds the 2 GiB hard import limit")
    elif total_bytes > RECOMMENDED_MAX_BYTES:
        warnings.append("model exceeds the recommended 750 MiB local research limit")

    config: dict[str, Any] = {}
    config_complete = False
    try:
        raw_config = _read_json(resolved / "config.json", "config.json", allow_symlink=True)
        if not isinstance(raw_config, dict):
            raise ModelImportError("config.json must contain an object")
        config = raw_config
        config_complete = True
    except ModelImportError as exc:
        issues.append(str(exc))
    model_type = config.get("model_type") if isinstance(config.get("model_type"), str) else None
    architectures = config.get("architectures")
    if (
        not isinstance(architectures, list)
        or not architectures
        or not all(isinstance(value, str) and value for value in architectures)
    ):
        issues.append("config architectures must be a non-empty string list")
        architectures = []
        config_complete = False
    dimension = _model_dimension(config)
    if dimension is None:
        issues.append("config does not declare a positive encoder embedding dimension")
        config_complete = False
    if not isinstance(config.get("vocab_size"), int) or config.get("vocab_size", 0) <= 0:
        issues.append("config does not declare a positive vocabulary size")
        config_complete = False
    if "auto_map" in config:
        issues.append("config auto_map/custom remote code is forbidden")
        config_complete = False
    supported = model_type in SUPPORTED_MODEL_TYPES
    if model_type is not None and not supported:
        issues.append(f"unsupported encoder architecture: {model_type}")

    tokenizer_files = sorted(
        name
        for name in names
        if name in {"tokenizer_config.json", "special_tokens_map.json", "added_tokens.json"}
        or any(name in layout for layout in TOKENIZER_VOCAB_LAYOUTS)
    )
    tokenizer_complete = (
        "tokenizer_config.json" in names
        and "special_tokens_map.json" in names
        and any(layout <= names for layout in TOKENIZER_VOCAB_LAYOUTS)
    )
    if tokenizer_complete:
        try:
            tokenizer_config = _read_json(
                resolved / "tokenizer_config.json",
                "tokenizer_config.json",
                allow_symlink=True,
            )
            special_tokens = _read_json(
                resolved / "special_tokens_map.json",
                "special_tokens_map.json",
                allow_symlink=True,
            )
            if not isinstance(tokenizer_config, dict) or not isinstance(special_tokens, dict):
                raise ModelImportError("tokenizer configuration files must contain objects")
            if "tokenizer.json" in names:
                tokenizer_json = _read_json(
                    resolved / "tokenizer.json",
                    "tokenizer.json",
                    allow_symlink=True,
                    max_bytes=MAX_TOKENIZER_JSON_BYTES,
                )
                if not isinstance(tokenizer_json, dict):
                    raise ModelImportError("tokenizer.json must contain an object")
            if "vocab.json" in names:
                vocab_json = _read_json(
                    resolved / "vocab.json",
                    "vocab.json",
                    allow_symlink=True,
                    max_bytes=MAX_TOKENIZER_JSON_BYTES,
                )
                if not isinstance(vocab_json, dict) or not vocab_json:
                    raise ModelImportError("vocab.json must contain a non-empty object")
            for name in set().union(*TOKENIZER_VOCAB_LAYOUTS) & names:
                asset = resolved / name
                if asset.stat().st_size == 0 or asset.stat().st_size > MAX_TOKENIZER_JSON_BYTES:
                    raise ModelImportError(
                        f"tokenizer vocabulary asset is empty or oversized: {name}"
                    )
        except ModelImportError as exc:
            issues.append(str(exc))
            tokenizer_complete = False
    if not tokenizer_complete:
        issues.append(
            "tokenizer_config.json, special_tokens_map.json, and a supported vocabulary "
            "layout are required"
        )
    weights: tuple[str, ...] = ()
    weights_complete = False
    tensor_count = 0
    try:
        weights = _weight_files(resolved, names)
        tensor_count = sum(_safetensors_header(resolved / name)["tensor_count"] for name in weights)
        weights_complete = True
    except ModelImportError as exc:
        issues.append(str(exc))

    card_languages, card_license = _local_card_metadata(resolved)
    manifest, manifest_issues = _manifest_details(resolved, files)
    issues.extend(manifest_issues)
    languages = card_languages
    license_name = card_license
    if manifest is not None:
        raw_languages = manifest.get("languages")
        if isinstance(raw_languages, list) and all(
            isinstance(value, str) for value in raw_languages
        ):
            languages = sorted(set(raw_languages))
        raw_license = manifest.get("license")
        if isinstance(raw_license, dict) and isinstance(raw_license.get("spdx"), str):
            license_name = raw_license["spdx"]
        if manifest.get("architecture") != model_type:
            issues.append("manifest architecture does not match config model_type")
    multilingual = set(languages) >= TARGET_LANGUAGES
    core_complete = config_complete and tokenizer_complete and weights_complete
    contract_complete = manifest is not None and not manifest_issues
    loadable = core_complete and supported and multilingual and contract_complete and not issues
    if loadable:
        classification = "compatible-multilingual"
    elif core_complete and supported and set(languages) == {"en"}:
        classification = "english-only"
    elif model_type is not None and not supported:
        classification = "unsupported"
    else:
        classification = "incomplete"
    freeze_hash = hashlib.sha256()
    for item in files:
        name = item.relative_to(resolved).as_posix()
        freeze_hash.update(
            name.encode("utf-8") + b"\0" + _sha256_file(item).encode("ascii") + b"\n"
        )
    return {
        "schema_version": MODEL_IMPORT_SCHEMA_VERSION,
        "path": resolved.as_posix(),
        "format": "transformers-safetensors",
        "architecture": {"model_type": model_type, "classes": architectures},
        "embedding_dimension": dimension,
        "tokenizer": {"available": tokenizer_complete, "files": tokenizer_files},
        "languages": languages,
        "required_languages": sorted(TARGET_LANGUAGES),
        "multilingual_suitable": multilingual,
        "license": license_name,
        "artifact_size_bytes": total_bytes,
        "asset_count": len(files),
        "directory_freeze_sha256": freeze_hash.hexdigest(),
        "safetensors": {"files": list(weights), "tensor_count": tensor_count},
        "config_complete": config_complete,
        "tokenizer_complete": tokenizer_complete,
        "weights_complete": weights_complete,
        "import_contract_complete": contract_complete,
        "supported_architecture": supported,
        "secureinjections_offline_loadable": loadable,
        "classification": classification,
        "issues": sorted(set(issues)),
        "warnings": sorted(set(warnings)),
        "network_used": False,
    }


@contextmanager
def _network_blocked() -> Iterator[None]:
    environment = {
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_DATASETS_OFFLINE": "1",
        "WANDB_MODE": "offline",
        "TOKENIZERS_PARALLELISM": "false",
        "DO_NOT_TRACK": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
    }
    previous = {name: os.environ.get(name) for name in environment}
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_create_connection = socket.create_connection
    original_getaddrinfo = socket.getaddrinfo

    def deny(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("network access is forbidden during offline model validation")

    os.environ.update(environment)
    socket.socket.connect = deny  # type: ignore[method-assign]
    socket.socket.connect_ex = deny  # type: ignore[assignment]
    socket.create_connection = deny  # type: ignore[assignment]
    socket.getaddrinfo = deny  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.socket.connect = original_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = original_connect_ex  # type: ignore[method-assign]
        socket.create_connection = original_create_connection
        socket.getaddrinfo = original_getaddrinfo
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def validate_local_model(model_path: Path, *, smoke_test: bool = True) -> dict[str, Any]:
    """Validate and optionally smoke-load a frozen model with network calls actively blocked."""
    report = inspect_local_model(model_path)
    if not report["secureinjections_offline_loadable"]:
        issues = report.get("issues", [])
        detail = "; ".join(str(value) for value in issues) or "model is incompatible"
        raise ModelImportError(f"offline model import rejected: {detail}")
    smoke: dict[str, Any] = {"attempted": False, "passed": False}
    if smoke_test:
        try:
            with _network_blocked():
                import torch
                from transformers import AutoModelForSequenceClassification, AutoTokenizer

                tokenizer = AutoTokenizer.from_pretrained(
                    str(model_path.resolve()),
                    local_files_only=True,
                    trust_remote_code=False,
                    use_fast=True,
                )
                model = AutoModelForSequenceClassification.from_pretrained(
                    str(model_path.resolve()),
                    local_files_only=True,
                    trust_remote_code=False,
                    use_safetensors=True,
                    num_labels=2,
                    ignore_mismatched_sizes=True,
                )
                model.eval()
                encoded = tokenizer(
                    ["Sikker lokal test.", "Prueba local segura."],
                    padding=True,
                    truncation=True,
                    max_length=32,
                    return_tensors="pt",
                )
                with torch.inference_mode():
                    logits = model(**encoded).logits
                if tuple(logits.shape) != (2, 2):
                    raise ModelImportError("offline smoke test returned an unexpected logits shape")
                smoke = {
                    "attempted": True,
                    "passed": True,
                    "tokenizer_class": type(tokenizer).__name__,
                    "model_class": type(model).__name__,
                    "logits_shape": list(logits.shape),
                    "network_blocked": True,
                    "input_persisted": False,
                }
                del encoded, logits, model, tokenizer
        except ImportError as exc:
            raise ModelImportError(
                "classifier runtime is unavailable for offline smoke testing"
            ) from exc
        except ModelImportError:
            raise
        except Exception as exc:
            raise ModelImportError(
                f"offline model smoke test failed: {type(exc).__name__}: {exc}"
            ) from exc
    return {**report, "validation": "PASS", "smoke_test": smoke, "network_used": False}
