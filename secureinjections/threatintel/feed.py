"""Deterministic feed bundle building and verification."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from ..classifier import validate_classifier_artifact
from ..detectors.semantic_index import SemanticIndex
from ..rules.loader import load_threat_rules
from ..rules.validator import parse_version
from ..version import ENGINE_VERSION, FEED_MANIFEST_VERSION, THREAT_RULE_SCHEMA_VERSION
from .manifest import FeedManifest, FeedManifestError
from .signatures import SignatureError, load_keyring, sign_ed25519, verify_ed25519

MAX_BUNDLE_BYTES = 768 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_COMPRESSION_RATIO = 200
_FIXED_ZIP_TIME = (2020, 1, 1, 0, 0, 0)


class FeedVerificationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class VerifiedFeed:
    manifest: FeedManifest
    artifacts: dict[str, bytes]


def _safe_member_name(name: str) -> PurePosixPath:
    if "\\" in name or "\x00" in name:
        raise FeedVerificationError(f"unsafe archive member: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise FeedVerificationError(f"unsafe archive member: {name!r}")
    return path


def _validate_zip_members(archive: zipfile.ZipFile, *, max_total: int) -> None:
    infos = archive.infolist()
    if len(infos) > MAX_ARCHIVE_MEMBERS:
        raise FeedVerificationError("archive has too many members")
    names: set[str] = set()
    total = 0
    for info in infos:
        _safe_member_name(info.filename)
        if info.filename in names:
            raise FeedVerificationError(f"duplicate archive member: {info.filename}")
        names.add(info.filename)
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise FeedVerificationError(f"archive symlink is not allowed: {info.filename}")
        file_type = stat.S_IFMT(mode)
        if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise FeedVerificationError(f"archive special file is not allowed: {info.filename}")
        total += info.file_size
        if total > max_total:
            raise FeedVerificationError("archive exceeds uncompressed size limit")
        if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
            raise FeedVerificationError("archive member exceeds compression ratio limit")


def safe_extract_zip(data: bytes, destination: Path, *, max_total: int) -> None:
    if len(data) > MAX_ARTIFACT_BYTES:
        raise FeedVerificationError("compressed artifact exceeds size limit")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            _validate_zip_members(archive, max_total=max_total)
            destination.mkdir(parents=True, exist_ok=False)
            root = destination.resolve(strict=True)
            for info in archive.infolist():
                relative = _safe_member_name(info.filename)
                target = destination.joinpath(*relative.parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                resolved_parent = target.parent.resolve(strict=True)
                if root != resolved_parent and root not in resolved_parent.parents:
                    raise FeedVerificationError("archive extraction escaped staging directory")
                with archive.open(info, "r") as source, target.open("xb") as output:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
    except (zipfile.BadZipFile, OSError) as exc:
        raise FeedVerificationError(f"invalid feed artifact archive: {exc}") from exc


def _zip_directory(root: Path, suffixes: frozenset[str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in suffixes:
                continue
            if path.is_symlink():
                raise ValueError(f"refusing to package symlink: {path}")
            relative = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(relative, _FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    return buffer.getvalue()


class FeedBuilder:
    @staticmethod
    def build(
        *,
        rules_path: Path,
        output_path: Path,
        feed_version: str,
        rules_version: str,
        signing_key_id: str,
        private_key: bytes,
        semantic_index_path: Path | None = None,
        semantic_index_version: str | None = None,
        classifier_model_path: Path | None = None,
        classifier_model_version: str | None = None,
        edition: str = "community",
        minimum_engine_version: str = ENGINE_VERSION,
        created_at: str | None = None,
        quality_metadata: dict[str, object] | None = None,
        provenance: dict[str, object] | None = None,
    ) -> FeedManifest:
        parse_version(feed_version)
        parse_version(rules_version)
        parse_version(minimum_engine_version)
        rules = load_threat_rules((rules_path,), quality_gate=True)
        artifacts = {
            "artifacts/rules.zip": _zip_directory(rules_path, frozenset({".yml", ".yaml", ".json"}))
        }
        if semantic_index_path is not None:
            if semantic_index_version is None:
                raise ValueError("semantic_index_version is required with a semantic index")
            parse_version(semantic_index_version)
            SemanticIndex.load(semantic_index_path)
            artifacts["artifacts/semantic-index.zip"] = _zip_directory(
                semantic_index_path, frozenset({".json", ".npy"})
            )
        if classifier_model_path is not None:
            if classifier_model_version is None:
                raise ValueError("classifier_model_version is required with a classifier model")
            parse_version(classifier_model_version)
            validate_classifier_artifact(classifier_model_path)
            artifacts["artifacts/classifier-model.zip"] = _zip_directory(
                classifier_model_path,
                frozenset({".json", ".safetensors", ".model", ".txt", ".md"}),
            )
        quality = {
            "rules_count": len(rules),
            "semantic_examples_count": sum(len(rule.semantic_examples) for rule in rules),
            "languages": sorted({language for rule in rules for language in rule.languages}),
            **(quality_metadata or {}),
        }
        provenance_data = {
            "rule_database_hash": hashlib.sha256(artifacts["artifacts/rules.zip"]).hexdigest(),
            "semantic_corpus_hash": None,
            "semantic_index_hash": (
                hashlib.sha256(artifacts["artifacts/semantic-index.zip"]).hexdigest()
                if "artifacts/semantic-index.zip" in artifacts
                else None
            ),
            "evaluation_report_hash": None,
            "engine_compatibility": minimum_engine_version,
            "build_tool_version": ENGINE_VERSION,
            "classifier_model_hash": (
                hashlib.sha256(artifacts["artifacts/classifier-model.zip"]).hexdigest()
                if "artifacts/classifier-model.zip" in artifacts
                else None
            ),
            **(provenance or {}),
        }
        manifest = FeedManifest.from_dict(
            {
                "manifest_version": FEED_MANIFEST_VERSION,
                "feed_version": feed_version,
                "edition": edition,
                "schema_version": THREAT_RULE_SCHEMA_VERSION,
                "created_at": created_at or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "minimum_engine_version": minimum_engine_version,
                "rules_version": rules_version,
                "semantic_index_version": semantic_index_version,
                "classifier_model_version": classifier_model_version,
                "artifact_hashes": {
                    name: hashlib.sha256(value).hexdigest() for name, value in artifacts.items()
                },
                "signing_key_id": signing_key_id,
                "quality_metadata": quality,
                "provenance": provenance_data,
            }
        )
        signature = sign_ed25519(manifest.canonical_bytes(), private_key)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists() or output_path.is_symlink():
            raise ValueError(f"refusing to overwrite feed bundle: {output_path}")
        descriptor, temporary_name = tempfile.mkstemp(prefix=".feed-build-", dir=output_path.parent)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            with zipfile.ZipFile(
                temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
            ) as bundle:
                members = {
                    "manifest.json": json.dumps(
                        manifest.to_dict(), sort_keys=True, indent=2
                    ).encode()
                    + b"\n",
                    "signature.ed25519": base64.b64encode(signature) + b"\n",
                    **artifacts,
                }
                for name, value in sorted(members.items()):
                    info = zipfile.ZipInfo(name, _FIXED_ZIP_TIME)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o100644 << 16
                    bundle.writestr(info, value)
            os.replace(temporary, output_path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return manifest


class FeedVerifier:
    def __init__(self, keyring: dict[str, bytes] | Path):
        self.keyring = load_keyring(keyring) if isinstance(keyring, Path) else dict(keyring)

    def verify(self, bundle_path: Path) -> VerifiedFeed:
        if bundle_path.is_symlink() or not bundle_path.is_file():
            raise FeedVerificationError("feed bundle must be a regular file")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(bundle_path, flags)
        except OSError as exc:
            raise FeedVerificationError(f"unable to open feed bundle safely: {exc}") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BUNDLE_BYTES:
                raise FeedVerificationError("feed bundle is not regular or exceeds size limit")
            handle = os.fdopen(descriptor, "rb")
            descriptor = -1
            with handle, zipfile.ZipFile(handle) as bundle:
                _validate_zip_members(bundle, max_total=MAX_BUNDLE_BYTES)
                names = {info.filename for info in bundle.infolist()}
                if not {"manifest.json", "signature.ed25519"} <= names:
                    raise FeedVerificationError("feed bundle lacks manifest or signature")
                if bundle.getinfo("manifest.json").file_size > 1_048_576:
                    raise FeedVerificationError("feed manifest is oversized")
                if bundle.getinfo("signature.ed25519").file_size > 1_024:
                    raise FeedVerificationError("feed signature is oversized")
                try:
                    raw_manifest = json.loads(bundle.read("manifest.json"))
                    manifest = FeedManifest.from_dict(raw_manifest)
                    signature = base64.b64decode(
                        bundle.read("signature.ed25519").strip(), validate=True
                    )
                except (
                    json.JSONDecodeError,
                    UnicodeDecodeError,
                    ValueError,
                    FeedManifestError,
                ) as exc:
                    raise FeedVerificationError(f"invalid feed metadata: {exc}") from exc
                expected_names = {
                    "manifest.json",
                    "signature.ed25519",
                    *manifest.artifact_hashes.keys(),
                }
                if names != expected_names:
                    raise FeedVerificationError(
                        "feed bundle contains undeclared or missing artifacts"
                    )
                public_key = self.keyring.get(manifest.signing_key_id)
                if public_key is None:
                    raise FeedVerificationError(f"untrusted signing key: {manifest.signing_key_id}")
                try:
                    verify_ed25519(manifest.canonical_bytes(), signature, public_key)
                except SignatureError as exc:
                    raise FeedVerificationError(str(exc)) from exc
                if parse_version(manifest.minimum_engine_version) > parse_version(ENGINE_VERSION):
                    raise FeedVerificationError(
                        f"feed requires engine {manifest.minimum_engine_version}"
                    )
                artifacts = {}
                for name, expected_hash in manifest.artifact_hashes.items():
                    value = bundle.read(name)
                    if len(value) > MAX_ARTIFACT_BYTES:
                        raise FeedVerificationError(f"artifact is oversized: {name}")
                    if hashlib.sha256(value).hexdigest() != expected_hash:
                        raise FeedVerificationError(f"artifact hash mismatch: {name}")
                    artifacts[name] = value
        except zipfile.BadZipFile as exc:
            raise FeedVerificationError(f"invalid feed bundle: {exc}") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return VerifiedFeed(manifest, artifacts)
