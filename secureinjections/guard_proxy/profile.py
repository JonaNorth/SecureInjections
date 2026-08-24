"""Typed, fail-closed configuration for the local OpenAI-compatible Guard Proxy."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..guard import GuardPolicy
from ..guard.audit import record_hash
from ..local_agent import OpenAICompatibleLoopbackTransport
from ..safe_yaml import bounded_safe_load


class ProxyProfileError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProxyLimits:
    request_bytes: int
    response_bytes: int
    message_count: int
    message_bytes: int
    tool_count: int
    tool_schema_bytes: int
    tool_argument_bytes: int
    timeout_seconds: float
    concurrency: int


@dataclass(frozen=True, slots=True)
class ProxyProfile:
    profile_id: str
    profile_version: str
    listen_host: str
    listen_port: int
    upstream_base_url: str
    upstream_model_policy: str
    upstream_doctor_model: str
    policy_path: Path | None
    enforcement_mode: str
    limits: ProxyLimits
    raw_content_logging: bool
    audit_enabled: bool
    audit_directory: Path
    config_path: Path
    profile_hash: str

    @classmethod
    def from_path(cls, path: Path) -> ProxyProfile:
        config_path = path.resolve()
        try:
            raw = bounded_safe_load(config_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ProxyProfileError(f"could not safely load proxy profile: {exc}") from exc
        if not isinstance(raw, Mapping):
            raise ProxyProfileError("proxy profile root must be a mapping")
        _exact(
            raw, {"profile", "listen", "upstream", "guard", "limits", "privacy", "audit"}, "root"
        )
        profile = _map(raw["profile"], "profile")
        _exact(profile, {"id", "version"}, "profile")
        if profile.get("id") != "openai-guard-proxy-profile" or profile.get("version") != "v0.1":
            raise ProxyProfileError("profile identity must be openai-guard-proxy-profile/v0.1")
        listen = _map(raw["listen"], "listen")
        _exact(listen, {"host", "port"}, "listen")
        host = _str(listen["host"], "listen.host")
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ProxyProfileError("proxy listener must be an explicit loopback host")
        port = _int(listen["port"], "listen.port")
        if not 1 <= port <= 65_535:
            raise ProxyProfileError("listen.port must be between 1 and 65535")
        upstream = _map(raw["upstream"], "upstream")
        _exact(upstream, {"provider", "base_url", "model_policy", "doctor_model"}, "upstream")
        if upstream.get("provider") != "openai_compatible_local":
            raise ProxyProfileError("proxy upstream provider must be openai_compatible_local")
        base_url = _str(upstream["base_url"], "upstream.base_url")
        model_policy = _str(upstream["model_policy"], "upstream.model_policy")
        if model_policy != "configured":
            raise ProxyProfileError("upstream.model_policy must be configured")
        doctor_model = _str(upstream["doctor_model"], "upstream.doctor_model")
        guard = _map(raw["guard"], "guard")
        _exact(guard, {"policy", "enforcement"}, "guard")
        policy_value = _str(guard["policy"], "guard.policy")
        policy_path = (
            None if policy_value == "default" else (config_path.parent / policy_value).resolve()
        )
        mode = _str(guard["enforcement"], "guard.enforcement").lower()
        if mode not in {"enforce", "observe"}:
            raise ProxyProfileError("guard.enforcement must be enforce or observe")
        limits_raw = _map(raw["limits"], "limits")
        fields = {
            "request_bytes",
            "response_bytes",
            "message_count",
            "message_bytes",
            "tool_count",
            "tool_schema_bytes",
            "tool_argument_bytes",
            "timeout_seconds",
            "concurrency",
        }
        _exact(limits_raw, fields, "limits")
        limits = ProxyLimits(
            _bounded_int(limits_raw, "request_bytes", 1_024, 10_000_000),
            _bounded_int(limits_raw, "response_bytes", 1_024, 10_000_000),
            _bounded_int(limits_raw, "message_count", 1, 256),
            _bounded_int(limits_raw, "message_bytes", 1, 1_000_000),
            _bounded_int(limits_raw, "tool_count", 0, 256),
            _bounded_int(limits_raw, "tool_schema_bytes", 1, 1_000_000),
            _bounded_int(limits_raw, "tool_argument_bytes", 1, 1_000_000),
            _bounded_number(limits_raw, "timeout_seconds", 0.1, 600),
            _bounded_int(limits_raw, "concurrency", 1, 128),
        )
        privacy = _map(raw["privacy"], "privacy")
        _exact(privacy, {"raw_content_logging"}, "privacy")
        if privacy.get("raw_content_logging") is not False:
            raise ProxyProfileError("privacy.raw_content_logging must be false in proxy v0.1")
        audit = _map(raw["audit"], "audit")
        _exact(audit, {"enabled", "directory"}, "audit")
        if not isinstance(audit.get("enabled"), bool):
            raise ProxyProfileError("audit.enabled must be boolean")
        directory = (config_path.parent / _str(audit["directory"], "audit.directory")).resolve()
        try:
            transport = OpenAICompatibleLoopbackTransport(
                base_url,
                timeout_seconds=limits.timeout_seconds,
                max_response_bytes=limits.response_bytes,
            )
        except ValueError as exc:
            raise ProxyProfileError(
                "upstream must be a safe loopback OpenAI-compatible API"
            ) from exc
        listen_origin = f"http://{host}:{port}"
        if transport.api_root.removesuffix("/v1") == listen_origin:
            raise ProxyProfileError("proxy listener and upstream may not be the same endpoint")
        effective = json.loads(json.dumps(raw))
        profile_hash = record_hash(effective)
        return cls(
            "openai-guard-proxy-profile",
            "v0.1",
            host,
            port,
            base_url,
            model_policy,
            doctor_model,
            policy_path,
            mode,
            limits,
            False,
            bool(audit["enabled"]),
            directory,
            config_path,
            profile_hash,
        )

    def load_policy(self) -> GuardPolicy:
        return (
            GuardPolicy.default()
            if self.policy_path is None
            else GuardPolicy.from_path(self.policy_path)
        )

    @property
    def audit_path(self) -> Path:
        return self.audit_directory / "proxy-audit.jsonl"

    @property
    def listen_url(self) -> str:
        host = f"[{self.listen_host}]" if self.listen_host == "::1" else self.listen_host
        return f"http://{host}:{self.listen_port}/v1"


def _map(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProxyProfileError(f"{name} must be a mapping")
    return value


def _exact(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ProxyProfileError(f"{name} fields must be exactly {sorted(expected)}")


def _str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1_000:
        raise ProxyProfileError(f"{name} must be a bounded non-empty string")
    return value


def _int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProxyProfileError(f"{name} must be an integer")
    return value


def _bounded_int(value: Mapping[str, Any], key: str, low: int, high: int) -> int:
    result = _int(value[key], f"limits.{key}")
    if not low <= result <= high:
        raise ProxyProfileError(f"limits.{key} must be between {low} and {high}")
    return result


def _bounded_number(value: Mapping[str, Any], key: str, low: float, high: float) -> float:
    result = value[key]
    if (
        not isinstance(result, (int, float))
        or isinstance(result, bool)
        or not low <= result <= high
    ):
        raise ProxyProfileError(f"limits.{key} must be between {low} and {high}")
    return float(result)
