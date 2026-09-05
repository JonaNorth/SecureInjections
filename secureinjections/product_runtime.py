"""Installable macOS product paths, safe defaults, onboarding, and readiness doctor."""

from __future__ import annotations

import fcntl
import json
import os
import platform
import shutil
import socket
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .guard_proxy import ProxyProfile, ProxyProfileError
from .local_profile import LocalGuardProfile, LocalProfileError
from .product_protection import ProductRuntimeConfig, query_product_status
from .version import ENGINE_VERSION

PRODUCT_CONFIG_SCHEMA = "secureinjections-product-config-v0.1"
ONBOARDING_SCHEMA = "secureinjections-onboarding-state-v0.1"
DOCTOR_SCHEMA = "secureinjections-product-doctor-v0.1"
SUPPORTED_MODEL = "qwen2.5:7b"


class ProductInstallationError(RuntimeError):
    """The local product installation cannot be used safely."""


@dataclass(frozen=True, slots=True)
class ProductPaths:
    root: Path
    config: Path
    state: Path
    audit: Path
    cache: Path
    data: Path

    @classmethod
    def default(cls, *, root: Path | None = None) -> ProductPaths:
        product_root = (
            root.expanduser()
            if root is not None
            else Path.home() / "Library" / "Application Support" / "SecureInjections"
        )
        product_root = product_root.resolve()
        return cls(
            product_root,
            product_root / "Config",
            product_root / "State",
            product_root / "Audit",
            product_root / "Cache",
            product_root / "Data",
        )

    @property
    def product_config(self) -> Path:
        return self.config / "product.json"

    @property
    def proxy_config(self) -> Path:
        return self.config / "guard-proxy.yaml"

    @property
    def local_profile(self) -> Path:
        return self.config / "local-agent.yaml"

    @property
    def onboarding_state(self) -> Path:
        return self.state / "onboarding.json"

    @property
    def instance_lock(self) -> Path:
        return self.state / "product.lock"

    @property
    def activity(self) -> Path:
        return self.audit / "product-activity.jsonl"

    @property
    def uploads(self) -> Path:
        return self.cache / "Uploads"


class ProductInstallation:
    """Create and validate one user's local operational product state."""

    def __init__(self, paths: ProductPaths | None = None) -> None:
        self.paths = paths or ProductPaths.default()

    def initialize(self) -> tuple[str, ...]:
        created: list[str] = []
        for directory in (
            self.paths.root,
            self.paths.config,
            self.paths.state,
            self.paths.audit,
            self.paths.cache,
            self.paths.data,
            self.paths.uploads,
            self.paths.data / "workspace",
            self.paths.data / "retrieval",
            self.paths.audit / "guard-proxy",
            self.paths.audit / "local-agent",
        ):
            _secure_directory(directory)
        for resource_name, destination in (
            ("product.json", self.paths.product_config),
            ("guard-proxy.yaml", self.paths.proxy_config),
            ("local-agent.yaml", self.paths.local_profile),
        ):
            if destination.is_symlink():
                raise ProductInstallationError(
                    f"Product configuration must not be a symlink: {destination.name}"
                )
            if not destination.exists():
                raw = (
                    files("secureinjections.product_defaults").joinpath(resource_name).read_bytes()
                )
                _atomic_write(destination, raw)
                created.append(destination.name)
            _require_private_file(destination)
        if not self.paths.onboarding_state.exists():
            self.write_onboarding(completed=False)
            created.append(self.paths.onboarding_state.name)
        else:
            _require_private_file(self.paths.onboarding_state)
        self.runtime_config()
        return tuple(created)

    def runtime_config(self) -> ProductRuntimeConfig:
        payload = _read_product_config(self.paths.product_config)
        profiles = payload["profiles"]
        proxy = _confined_profile(self.paths.config, profiles["guard_proxy"])
        local = _confined_profile(self.paths.config, profiles["local_agent"])
        ProxyProfile.from_path(proxy)
        LocalGuardProfile.from_path(local)
        listen = payload["listen"]
        return ProductRuntimeConfig(
            listen_host=listen["host"],
            listen_port=listen["port"],
            proxy_config=proxy,
            local_profile=local,
            activity_path=self.paths.activity,
            file_ingest_root=self.paths.uploads,
        )

    def onboarding(self) -> dict[str, Any]:
        try:
            value = json.loads(self.paths.onboarding_state.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return _onboarding_payload(False, error="Onboarding state needs attention.")
        if not isinstance(value, dict) or value.get("schema_version") != ONBOARDING_SCHEMA:
            return _onboarding_payload(False, error="Onboarding state needs attention.")
        if not isinstance(value.get("completed"), bool):
            return _onboarding_payload(False, error="Onboarding state needs attention.")
        return {
            "schema_version": ONBOARDING_SCHEMA,
            "completed": value["completed"],
            "completed_at": value.get("completed_at"),
            "product_version": value.get("product_version"),
            "state_classification": "PERSISTENT_UI_PREFERENCE_NOT_AUTHORITY",
            "error": None,
        }

    def write_onboarding(self, *, completed: bool) -> dict[str, Any]:
        payload = _onboarding_payload(completed)
        _atomic_write(
            self.paths.onboarding_state,
            (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(),
        )
        return payload

    def doctor(self) -> dict[str, Any]:
        checks: list[dict[str, str]] = []
        supported_platform = platform.system() == "Darwin" and platform.machine() == "arm64"
        _check(
            checks,
            "platform",
            "PASS" if supported_platform else "WARN",
            "macOS Apple Silicon is supported."
            if supported_platform
            else "This platform is unvalidated for SecureInjections Community.",
        )
        supported_python = sys.version_info >= (3, 11)
        _check(
            checks,
            "python_runtime",
            "PASS" if supported_python else "FAIL",
            f"Python {platform.python_version()} detected; 3.11 or newer is required.",
        )
        try:
            self.initialize()
        except (
            OSError,
            ValueError,
            ProductInstallationError,
            ProxyProfileError,
            LocalProfileError,
        ):
            _check(checks, "product_state", "FAIL", "Product configuration or storage is invalid.")
            return _doctor_payload(checks)
        _check(checks, "product_state", "PASS", "Product directories and safe defaults are valid.")
        config = self.runtime_config()
        service = query_product_status(_origin(config.listen_host, config.listen_port))
        port_free = _port_available(config.listen_host, config.listen_port)
        _check(
            checks,
            "product_service",
            "PASS" if service is not None or port_free else "FAIL",
            "Product service is running with verified status."
            if service is not None
            else "Product loopback port is ready."
            if port_free
            else "Product port is occupied by an unverified process.",
        )
        _check(
            checks,
            "activity_audit",
            "PASS" if _writable_private_directory(self.paths.audit) else "FAIL",
            "Private activity and audit storage is writable."
            if _writable_private_directory(self.paths.audit)
            else "Activity or audit storage is not private and writable.",
        )
        binary = shutil.which("ollama")
        _check(
            checks,
            "ollama_binary",
            "PASS" if binary else "WARN",
            "Ollama is installed."
            if binary
            else "Ollama is required for the validated local guarded-agent workflow.",
        )
        models = _ollama_models("http://127.0.0.1:11434")
        _check(
            checks,
            "ollama_service",
            "PASS" if models is not None else "WARN",
            "Local Ollama is reachable."
            if models is not None
            else "Start local Ollama; no cloud connection was attempted.",
        )
        _check(
            checks,
            "supported_model",
            "PASS" if models is not None and SUPPORTED_MODEL in models else "WARN",
            f"Validated model {SUPPORTED_MODEL} is installed."
            if models is not None and SUPPORTED_MODEL in models
            else f"Install the validated model explicitly: ollama pull {SUPPORTED_MODEL}",
        )
        proxy = ProxyProfile.from_path(config.proxy_config)  # type: ignore[arg-type]
        proxy_free = _port_available(proxy.listen_host, proxy.listen_port)
        proxy_status = query_guard_proxy_status(proxy.listen_url)
        proxy_verified = bool(
            proxy_status
            and proxy_status.get("service") == "guard-proxy"
            and proxy_status.get("enforcement_mode") == "ENFORCE"
            and isinstance(proxy_status.get("profile"), dict)
            and proxy_status["profile"].get("hash") == proxy.profile_hash
        )
        _check(
            checks,
            "guard_proxy",
            "PASS" if proxy_free or proxy_verified else "FAIL",
            "Guard Proxy profile and port are ready."
            if proxy_free
            else "A matching ENFORCE Guard Proxy is active."
            if proxy_verified
            else "Guard Proxy port is occupied by an unverified process.",
        )
        return _doctor_payload(checks)


class ProductInstanceLock:
    """Process-held single-instance lock; stale file contents grant no ownership."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None

    def acquire(self) -> None:
        if self.path.is_symlink():
            raise ProductInstallationError("Product instance lock must not be a symbolic link.")
        descriptor = os.open(
            self.path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            state = json.dumps(
                {
                    "schema_version": "secureinjections-product-runtime-lock-v0.1",
                    "pid": os.getpid(),
                    "started_at": _now(),
                },
                sort_keys=True,
            ).encode()
            os.ftruncate(descriptor, 0)
            os.write(descriptor, state)
            os.fsync(descriptor)
        except OSError as exc:
            os.close(descriptor)
            raise ProductInstallationError(
                "Another product instance holds the local runtime lock."
            ) from exc
        self._descriptor = descriptor

    def release(self) -> None:
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is None:
            return
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    def __enter__(self) -> ProductInstanceLock:
        self.acquire()
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()


def query_guard_proxy_status(base_url: str) -> dict[str, Any] | None:
    origin = base_url.removesuffix("/v1")
    try:
        with urlopen(  # noqa: S310 - validated ProxyProfile is loopback-only
            Request(origin + "/v1/secureinjections/status", headers={"Accept": "application/json"}),
            timeout=0.4,
        ) as response:
            value = json.loads(response.read(256_000))
    except (HTTPError, URLError, OSError, TimeoutError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _read_product_config(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductInstallationError("Product configuration is unreadable.") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "listen",
        "profiles",
        "expected_model",
        "raw_content_logging",
    }:
        raise ProductInstallationError("Product configuration has unknown or missing fields.")
    listen, profiles = payload.get("listen"), payload.get("profiles")
    if (
        payload.get("schema_version") != PRODUCT_CONFIG_SCHEMA
        or payload.get("expected_model") != SUPPORTED_MODEL
        or payload.get("raw_content_logging") is not False
        or not isinstance(listen, dict)
        or set(listen) != {"host", "port"}
        or listen.get("host") not in {"127.0.0.1", "::1", "localhost"}
        or not isinstance(listen.get("port"), int)
        or not 1 <= listen["port"] <= 65_535
        or not isinstance(profiles, dict)
        or set(profiles) != {"guard_proxy", "local_agent"}
        or not all(isinstance(item, str) and item for item in profiles.values())
    ):
        raise ProductInstallationError("Product configuration violates safe defaults.")
    return payload


def _confined_profile(root: Path, value: str) -> Path:
    candidate = (root / value).resolve(strict=True)
    try:
        candidate.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ProductInstallationError("Product profile must remain inside Config.") from exc
    _require_private_file(candidate)
    return candidate


def _secure_directory(path: Path) -> None:
    if path.is_symlink():
        raise ProductInstallationError(
            f"Product directory must not be a symbolic link: {path.name}"
        )
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.stat()
    if not path.is_dir() or (hasattr(os, "getuid") and metadata.st_uid != os.getuid()):
        raise ProductInstallationError(f"Product directory ownership is invalid: {path.name}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ProductInstallationError(f"Product directory is not private: {path.name}")


def _require_private_file(path: Path) -> None:
    if path.is_symlink():
        raise ProductInstallationError(f"Product configuration must not be a symlink: {path.name}")
    metadata = path.stat()
    if not path.is_file() or (hasattr(os, "getuid") and metadata.st_uid != os.getuid()):
        raise ProductInstallationError(f"Product configuration ownership is invalid: {path.name}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ProductInstallationError(f"Product configuration is not private: {path.name}")


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def _writable_private_directory(path: Path) -> bool:
    try:
        metadata = path.stat()
    except OSError:
        return False
    return bool(
        path.is_dir() and not stat.S_IMODE(metadata.st_mode) & 0o077 and os.access(path, os.W_OK)
    )


def _port_available(host: str, port: int) -> bool:
    probe = socket.socket(socket.AF_INET6 if host == "::1" else socket.AF_INET)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
    except OSError:
        return False
    finally:
        probe.close()
    return True


def _ollama_models(origin: str) -> set[str] | None:
    try:
        with urlopen(  # noqa: S310 - fixed loopback Ollama origin
            Request(origin + "/api/tags", headers={"Accept": "application/json"}), timeout=0.5
        ) as response:
            value = json.loads(response.read(1_000_000))
    except (HTTPError, URLError, OSError, TimeoutError, ValueError):
        return None
    rows = value.get("models") if isinstance(value, dict) else None
    if not isinstance(rows, list):
        return None
    return {
        str(item.get("name"))
        for item in rows
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }


def _onboarding_payload(completed: bool, *, error: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": ONBOARDING_SCHEMA,
        "completed": completed,
        "completed_at": _now() if completed else None,
        "product_version": ENGINE_VERSION,
        "state_classification": "PERSISTENT_UI_PREFERENCE_NOT_AUTHORITY",
        "error": error,
    }


def _check(checks: list[dict[str, str]], check_id: str, status: str, message: str) -> None:
    checks.append({"id": check_id, "status": status, "message": message})


def _doctor_payload(checks: list[dict[str, str]]) -> dict[str, Any]:
    result = (
        "FAIL"
        if any(item["status"] == "FAIL" for item in checks)
        else "WARN"
        if any(item["status"] == "WARN" for item in checks)
        else "PASS"
    )
    return {
        "schema_version": DOCTOR_SCHEMA,
        "result": result,
        "supported_platform": "macOS Apple Silicon",
        "checks": checks,
        "cloud_calls_performed": False,
        "raw_content_retained": False,
    }


def _origin(host: str, port: int) -> str:
    rendered = f"[{host}]" if host == "::1" else host
    return f"http://{rendered}:{port}"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
