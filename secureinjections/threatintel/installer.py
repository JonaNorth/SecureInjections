"""Atomic offline feed installation and rollback."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..classifier import validate_classifier_artifact
from ..config import ScannerConfig
from ..detectors.semantic_index import SemanticIndex
from ..rules.loader import load_threat_rules
from ..rules.validator import parse_version
from .feed import FeedVerifier, safe_extract_zip


class FeedInstallError(ValueError):
    pass


class FeedInstaller:
    def __init__(self, root: Path, verifier: FeedVerifier):
        self.root = root.expanduser()
        self.verifier = verifier
        self._lock = threading.RLock()

    @contextmanager
    def _installation_lock(self):
        """Serialize activation in-process and across POSIX administrative processes."""
        with self._lock:
            self._prepare_root()
            lock_path = self.root / ".install.lock"
            flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(lock_path, flags, 0o600)
            try:
                try:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                except ImportError:  # pragma: no cover - Windows uses the process lock
                    pass
                yield
            finally:
                try:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except ImportError:  # pragma: no cover
                    pass
                os.close(descriptor)

    def _prepare_root(self) -> None:
        if self.root.is_symlink():
            raise FeedInstallError("feed root may not be a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.root / "releases").mkdir(exist_ok=True, mode=0o700)

    def _read_pointer(self, name: str) -> dict[str, Any] | None:
        path = self.root / f"{name}.json"
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
            raise FeedInstallError(f"unsafe {name} pointer")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FeedInstallError(f"invalid {name} pointer: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {"feed_version", "release"}:
            raise FeedInstallError(f"invalid {name} pointer fields")
        release = value["release"]
        if not isinstance(release, str) or Path(release).name != release:
            raise FeedInstallError(f"invalid {name} release")
        parse_version(value["feed_version"])
        return value

    def _write_pointer(self, name: str, value: dict[str, str]) -> None:
        target = self.root / f"{name}.json"
        if target.is_symlink():
            raise FeedInstallError(f"refusing to replace symlinked {name} pointer")
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{name}-", dir=self.root)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(value, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def install(self, bundle_path: Path) -> dict[str, Any]:
        # All untrusted bytes are verified before any active-state lock or mutation.
        verified = self.verifier.verify(bundle_path)
        with self._installation_lock():
            active = self._read_pointer("active")
            if active and parse_version(verified.manifest.feed_version) <= parse_version(
                active["feed_version"]
            ):
                raise FeedInstallError("feed downgrade or duplicate version refused")
            releases = self.root / "releases"
            release_name = f"feed-{verified.manifest.feed_version}"
            release_path = releases / release_name
            if release_path.exists():
                raise FeedInstallError("release directory already exists")
            staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
            release_created = False
            try:
                safe_extract_zip(
                    verified.artifacts["artifacts/rules.zip"],
                    staging / "rules",
                    max_total=256 * 1024 * 1024,
                )
                rules = load_threat_rules((staging / "rules",), quality_gate=True)
                semantic_artifact = verified.artifacts.get("artifacts/semantic-index.zip")
                if semantic_artifact is not None:
                    safe_extract_zip(
                        semantic_artifact,
                        staging / "semantic-index",
                        max_total=512 * 1024 * 1024,
                    )
                    SemanticIndex.load(staging / "semantic-index")
                classifier_artifact = verified.artifacts.get("artifacts/classifier-model.zip")
                classifier_metadata = None
                if classifier_artifact is not None:
                    safe_extract_zip(
                        classifier_artifact,
                        staging / "classifier-model",
                        max_total=512 * 1024 * 1024,
                    )
                    classifier_metadata = validate_classifier_artifact(staging / "classifier-model")
                (staging / "manifest.json").write_text(
                    json.dumps(verified.manifest.to_dict(), sort_keys=True, indent=2) + "\n",
                    encoding="utf-8",
                )
                os.rename(staging, release_path)
                release_created = True
                pointer = {
                    "feed_version": verified.manifest.feed_version,
                    "release": release_name,
                }
                if active:
                    self._write_pointer("previous", active)
                self._write_pointer("active", pointer)
            except Exception:
                if staging.exists():
                    shutil.rmtree(staging)
                if release_created and release_path.exists():
                    shutil.rmtree(release_path)
                raise
            return {
                "feed_version": verified.manifest.feed_version,
                "rules_version": verified.manifest.rules_version,
                "rules": len(rules),
                "release": str(release_path),
                "classifier_version": (
                    classifier_metadata.classifier_version if classifier_metadata else None
                ),
            }

    def rollback(self) -> dict[str, str]:
        with self._installation_lock():
            active = self._read_pointer("active")
            previous = self._read_pointer("previous")
            if active is None or previous is None:
                raise FeedInstallError("no previous feed is available for rollback")
            previous_path = self.root / "releases" / previous["release"]
            if not previous_path.is_dir() or previous_path.is_symlink():
                raise FeedInstallError("previous feed release is unavailable or unsafe")
            self._write_pointer("active", previous)
            self._write_pointer("previous", active)
            return {"feed_version": previous["feed_version"], "release": previous["release"]}

    def status(self) -> dict[str, Any]:
        with self._installation_lock():
            active = self._read_pointer("active")
            previous = self._read_pointer("previous")
            return {"root": str(self.root), "active": active, "previous": previous}

    def active_paths(self) -> dict[str, Path | str | None]:
        with self._installation_lock():
            active = self._read_pointer("active")
            if active is None:
                raise FeedInstallError("no active feed")
            release = self.root / "releases" / active["release"]
            if not release.is_dir() or release.is_symlink():
                raise FeedInstallError("active feed release is unavailable or unsafe")
            manifest_path = release / "manifest.json"
            if (
                manifest_path.is_symlink()
                or not manifest_path.is_file()
                or manifest_path.stat().st_size > 1_048_576
            ):
                raise FeedInstallError("active feed manifest is unavailable or unsafe")
            try:
                from .manifest import FeedManifest

                manifest = FeedManifest.from_dict(
                    json.loads(manifest_path.read_text(encoding="utf-8"))
                )
            except (ValueError, OSError, json.JSONDecodeError) as exc:
                raise FeedInstallError(f"active feed manifest is invalid: {exc}") from exc
            semantic = release / "semantic-index"
            classifier = release / "classifier-model"
            return {
                "rules": release / "rules",
                "semantic_index": semantic if semantic.is_dir() else None,
                "classifier_model": classifier if classifier.is_dir() else None,
                "feed_version": active["feed_version"],
                "rules_version": manifest.rules_version,
            }

    def scanner_config(
        self,
        *,
        semantic_model_path: Path | None = None,
        classifier_enabled: bool = False,
        classifier_routing: str = "all_except_strongly_benign",
    ) -> ScannerConfig:
        """Create a ScannerConfig pinned to the currently active immutable release."""
        active = self.active_paths()
        rules_path = active["rules"]
        feed_version = active["feed_version"]
        rules_version = active["rules_version"]
        if (
            not isinstance(rules_path, Path)
            or not isinstance(feed_version, str)
            or not isinstance(rules_version, str)
        ):
            raise FeedInstallError("active feed metadata is invalid")
        semantic_index = active["semantic_index"] if semantic_model_path is not None else None
        classifier_model = active["classifier_model"] if classifier_enabled else None
        classifier_hash = None
        if classifier_enabled:
            if not isinstance(classifier_model, Path):
                raise FeedInstallError("active feed has no classifier artifact")
            classifier_hash = validate_classifier_artifact(classifier_model).weights_sha256
        return ScannerConfig(
            rule_paths=(rules_path,),
            semantic_model_path=semantic_model_path,
            semantic_index_path=Path(semantic_index) if semantic_index is not None else None,
            classifier_enabled=classifier_enabled,
            classifier_model_path=classifier_model if isinstance(classifier_model, Path) else None,
            classifier_weights_sha256=classifier_hash,
            classifier_routing=classifier_routing,
            feed_version=feed_version,
            rules_version=rules_version,
        )
