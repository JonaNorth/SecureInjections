"""Fail-safe local directory and authority-key handling."""

from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from .canonical import sha256_hex
from .models import StateDirectoryError, StoreDirectoryState

DATABASE_NAME = "authority.sqlite3"
KEY_NAME = "authority.key"
ANCHOR_NAME = "authority.anchor"
LOCK_NAME = ".authority.lock"


@dataclass(frozen=True, slots=True)
class StatePaths:
    directory: Path
    database: Path
    key: Path
    anchor: Path
    lock: Path


class AuthorityKeyBackend:
    """Interface reserved for a future keychain-backed implementation."""

    backend_name = "ABSTRACT"

    def create(self, path: Path) -> tuple[bytes, str]:
        raise NotImplementedError

    def load(self, path: Path) -> tuple[bytes, str]:
        raise NotImplementedError


class LocalRestrictedFileKeyBackend(AuthorityKeyBackend):
    backend_name = "LOCAL_RESTRICTED_FILE"

    def create(self, path: Path) -> tuple[bytes, str]:
        _require_posix_security()
        _reject_symlink(path)
        key = secrets.token_bytes(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise StateDirectoryError("authority key could not be created exclusively") from exc
        try:
            view = memoryview(key)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise StateDirectoryError("authority key write did not complete")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, 0o600)
        _verify_key_file(path)
        _fsync_directory(path.parent)
        return key, _key_id(key)

    def load(self, path: Path) -> tuple[bytes, str]:
        _require_posix_security()
        _reject_symlink(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise StateDirectoryError("authority key is unavailable") from exc
        try:
            _verify_key_descriptor(descriptor)
            key = os.read(descriptor, 33)
            if os.read(descriptor, 1):
                raise StateDirectoryError("authority key exceeds exactly 32 bytes")
        finally:
            os.close(descriptor)
        if len(key) != 32:
            raise StateDirectoryError("authority key must contain exactly 32 bytes")
        return key, _key_id(key)


def prepare_paths(directory: Path, *, create: bool) -> StatePaths:
    _require_posix_security()
    if not isinstance(directory, Path):
        directory = Path(directory)
    if not directory.is_absolute():
        raise StateDirectoryError("authority state directory must be an explicit absolute path")
    if ".." in directory.parts:
        raise StateDirectoryError("authority state directory must not contain path traversal")
    if directory.exists() and directory.is_symlink():
        raise StateDirectoryError("authority state directory cannot be a symlink")
    try:
        canonical = directory.resolve(strict=False)
    except OSError as exc:
        raise StateDirectoryError("authority state directory cannot be canonicalized") from exc
    if canonical.exists() and not canonical.is_dir():
        raise StateDirectoryError("authority state path conflicts with a non-directory")
    if create and not canonical.exists():
        canonical.mkdir(parents=True, mode=0o700)
        os.chmod(canonical, 0o700)
        _fsync_directory(canonical.parent)
    if not canonical.exists():
        raise StateDirectoryError("authority state directory does not exist")
    _verify_directory_permissions(canonical)
    paths = StatePaths(
        canonical,
        canonical / DATABASE_NAME,
        canonical / KEY_NAME,
        canonical / ANCHOR_NAME,
        canonical / LOCK_NAME,
    )
    for path in (paths.database, paths.key, paths.anchor, paths.lock):
        _reject_symlink(path)
        if path.exists() and not path.is_file():
            raise StateDirectoryError(f"authority path is not a regular file: {path.name}")
    return paths


def classify_state(paths: StatePaths) -> StoreDirectoryState:
    present = tuple(path.exists() for path in (paths.database, paths.key, paths.anchor))
    if not any(present):
        return StoreDirectoryState.EMPTY_NEW_STORE
    if all(present):
        return StoreDirectoryState.COMPLETE_EXISTING_STORE
    return StoreDirectoryState.PARTIAL_STATE


def _require_posix_security() -> None:
    if os.name != "posix":
        raise StateDirectoryError(
            "LOCAL_RESTRICTED_FILE requires tested POSIX permission and locking semantics"
        )


def _verify_directory_permissions(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise StateDirectoryError("authority state directory must not permit group/world access")


def _verify_key_file(path: Path) -> None:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise StateDirectoryError("authority key must be a regular file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise StateDirectoryError("authority key permissions must be exactly 0600")
    if info.st_nlink != 1:
        raise StateDirectoryError("authority key must not have a hard link")


def _verify_key_descriptor(descriptor: int) -> None:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise StateDirectoryError("authority key must be a regular file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise StateDirectoryError("authority key permissions must be exactly 0600")
    if info.st_nlink != 1:
        raise StateDirectoryError("authority key must not have a hard link")


def _reject_symlink(path: Path) -> None:
    try:
        if path.is_symlink():
            raise StateDirectoryError(f"authority path cannot be a symlink: {path.name}")
    except OSError as exc:
        raise StateDirectoryError(f"authority path cannot be inspected: {path.name}") from exc


def _key_id(key: bytes) -> str:
    return "key-" + sha256_hex(key)[:16]


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
