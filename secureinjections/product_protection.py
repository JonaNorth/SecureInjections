"""Truthful local product status and privacy-preserving activity projection."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .guard import Guard
from .guard.audit import append_audit, record_hash
from .guard_proxy import GuardProxyHTTPServer, ProxyProfile, ProxyProfileError
from .integrations import IntegrationProfileError, OpenWebUIIntegrationProfile
from .integrations.open_webui import VALIDATED_OPEN_WEBUI_VERSION
from .local_agent import OpenAICompatibleLoopbackTransport
from .local_profile import LocalGuardProfile, LocalProfileError

PROTECTION_STATUS_SCHEMA = "local-protection-status-v0.1"
ACTIVITY_SCHEMA = "local-protection-activity-v0.1"
ACTIVITY_FEED_SCHEMA = "local-protection-activity-feed-v0.1"
SURFACE_STATES = {
    "ACTIVE",
    "AVAILABLE_NOT_CONNECTED",
    "ATTENTION_REQUIRED",
    "UNSUPPORTED",
}
_MAX_AUDIT_BYTES = 4_000_000
_MAX_AUDIT_LINES = 1_000


@dataclass(frozen=True, slots=True)
class ProductRuntimeConfig:
    """Host-owned product configuration; paths are never returned by the API."""

    listen_host: str = "127.0.0.1"
    listen_port: int = 8000
    proxy_config: Path | None = None
    local_profile: Path | None = None
    open_webui_config: Path | None = None
    activity_path: Path | None = None
    file_ingest_root: Path | None = None

    def __post_init__(self) -> None:
        if self.listen_host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("the product service must bind to an explicit loopback host")
        if not 1 <= self.listen_port <= 65_535:
            raise ValueError("listen_port must be between 1 and 65535")

    @classmethod
    def from_environment(cls, *, activity_path: Path) -> ProductRuntimeConfig:
        def configured(name: str) -> Path | None:
            value = os.environ.get(name)
            return Path(value).resolve() if value else None

        return cls(
            proxy_config=configured("SECUREINJECTIONS_PROXY_CONFIG"),
            local_profile=configured("SECUREINJECTIONS_LOCAL_PROFILE"),
            open_webui_config=configured("SECUREINJECTIONS_OPEN_WEBUI_CONFIG"),
            activity_path=activity_path,
            file_ingest_root=configured("SECUREINJECTIONS_FILE_INGEST_ROOT"),
        )


Probe = Callable[[str, str], Mapping[str, Any] | None]


class ProductProtectionState:
    """Build product state from service, profiles, loopback probes, and safe audits."""

    def __init__(
        self,
        config: ProductRuntimeConfig,
        guard: Guard,
        *,
        probe: Probe | None = None,
        proxy_lifecycle: GuardProxyLifecycle | None = None,
    ) -> None:
        self.config = config
        self.guard = guard
        self.activity_path = config.activity_path
        self._probe = probe or _loopback_json_probe
        self.proxy_lifecycle = proxy_lifecycle or GuardProxyLifecycle(
            config.proxy_config, identity_probe=self._probe
        )

    def status(self) -> dict[str, Any]:
        proxy, proxy_error = self._proxy_profile()
        local, local_error = self._local_profile()
        open_webui, open_webui_error = self._open_webui_profile()
        connection = self.proxy_lifecycle.status()
        proxy_active = connection["state"] == "ACTIVE"
        proxy_enforce = proxy_active
        proxy_state = (
            "ACTIVE"
            if proxy_enforce
            else "ATTENTION_REQUIRED"
            if connection["state"] == "ATTENTION_REQUIRED" or proxy_error
            else "AVAILABLE_NOT_CONNECTED"
        )
        local_connected = self._local_runtime_connected(local)
        open_webui_connected = bool(
            self._open_webui_connected(open_webui)
            and open_webui is not None
            and proxy is not None
            and open_webui.proxy_config == proxy.config_path
        )

        surfaces = [
            _surface("ai_traffic", "Prompts / model traffic", proxy_state),
            _surface("files", "Files", "ACTIVE"),
            _surface("tool_actions", "Tool actions", proxy_state),
            _surface("memory", "Memory", "AVAILABLE_NOT_CONNECTED"),
            _surface("agent_actions", "Agent actions", "AVAILABLE_NOT_CONNECTED"),
            _surface("external_actions", "External actions", "AVAILABLE_NOT_CONNECTED"),
        ]
        integrations = [
            _integration(
                "gateway",
                "Gateway",
                "SUPPORTED",
                False,
                "AVAILABLE_NOT_CONNECTED",
                "Protection is active when an application embeds GuardedToolGateway.",
            ),
            _integration(
                "guard_proxy",
                "Guard Proxy",
                "SUPPORTED",
                proxy_active,
                proxy_state,
                "Route a supported client through the configured loopback proxy.",
                endpoint=proxy.listen_url if proxy else None,
                enforcement=(proxy.enforcement_mode.upper() if proxy else None),
                configuration_error=proxy_error,
                setup_state=connection["state"],
                owned=connection["owned"],
                can_start=connection["can_start"],
                can_stop=connection["can_stop"],
                upstream=connection["upstream"],
            ),
            _integration(
                "native_ollama",
                "Native Ollama",
                "SUPPORTED",
                False,
                "AVAILABLE_NOT_CONNECTED",
                (
                    "Local Ollama is ready for a guarded-agent run. Reachability alone is not "
                    "active protection."
                    if local_connected
                    else "Start the configured local Ollama runtime before a guarded-agent run."
                ),
                configuration_error=local_error,
                setup_state="READY_TO_CONNECT" if local_connected else "NOT_READY",
                guarded_agent_available=local is not None,
                runtime_ready=local_connected,
            ),
            _integration(
                "open_webui",
                "Open WebUI",
                "SUPPORTED_EXACT",
                open_webui_connected and proxy_enforce,
                "ACTIVE"
                if open_webui_connected and proxy_enforce
                else "ATTENTION_REQUIRED"
                if open_webui_error
                else "AVAILABLE_NOT_CONNECTED",
                "Validated only for Open WebUI 0.11.0, stream off, through Guard Proxy.",
                validated_version=VALIDATED_OPEN_WEBUI_VERSION,
                configuration_error=open_webui_error,
                setup_state=(
                    "PROXY_ACTIVE_CONFIGURATION_VERIFIED"
                    if open_webui_connected and proxy_enforce
                    else "PROXY_ACTIVE_CONFIGURATION_NOT_VERIFIED"
                    if proxy_enforce
                    else "NOT_READY"
                ),
                proxy_endpoint=proxy.listen_url if proxy else None,
                streaming_required="OFF",
                provider_required="native Ollama through Guard Proxy",
            ),
            _integration(
                "generic_openai_compatible",
                "Generic OpenAI-compatible local runtime",
                "EXPERIMENTAL",
                False,
                "UNSUPPORTED",
                "Experimental and outside the current supported product scope.",
            ),
        ]
        activity = self.activity(limit=100)
        attention = any(item["state"] == "ATTENTION_REQUIRED" for item in surfaces)
        return {
            "schema_version": PROTECTION_STATUS_SCHEMA,
            "service_running": True,
            "service": {
                "state": "ACTIVE",
                "binding": "configured-loopback",
                "endpoint": _display_endpoint(self.config.listen_host, self.config.listen_port),
            },
            "overall": "ATTENTION_REQUIRED" if attention else "PROTECTED",
            "policy": {
                "id": self.guard.policy.policy_id,
                "version": self.guard.policy.version,
            },
            "protection_mode": "ENFORCE",
            "surfaces": surfaces,
            "integrations": integrations,
            "activity": activity["counts"],
            "audit": {
                "state": self._audit_state(),
                "raw_content_retained": False,
            },
            "file_ingestion_ready": True,
            "always_on_scope": (
                "Configured supported integrations routed through local SecureInjections services."
            ),
        }

    def record_activity(
        self,
        *,
        surface: str,
        decision: str,
        reason: str,
        correlation_id: str | None,
        audit_reference: str | None,
    ) -> None:
        if self.activity_path is None or decision not in {"ALLOW", "REVIEW", "BLOCK"}:
            return
        record: dict[str, Any] = {
            "schema_version": ACTIVITY_SCHEMA,
            "event_id": "product-activity-" + uuid.uuid4().hex,
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "surface": surface,
            "decision": decision,
            "reason": reason[:240],
            "correlation_id": correlation_id,
            "audit_reference": audit_reference,
            "policy": {
                "id": self.guard.policy.policy_id,
                "version": self.guard.policy.version,
            },
            "raw_content_retained": False,
        }
        record["record_hash"] = record_hash(record)
        append_audit(self.activity_path, record)

    def activity(self, *, limit: int = 50) -> dict[str, Any]:
        bounded_limit = max(1, min(limit, 200))
        records = [row for row in _read_jsonl(self.activity_path) if _record_integrity_valid(row)]
        proxy, _error = self._proxy_profile()
        if proxy is not None:
            records.extend(
                _proxy_activity(row)
                for row in _read_jsonl(proxy.audit_path)
                if _record_integrity_valid(row)
            )
        local, _error = self._local_profile()
        if local is not None:
            records.extend(
                _guard_activity(row)
                for row in _read_jsonl(local.guard.audit)
                if _record_integrity_valid(row)
            )
        unique: dict[tuple[Any, ...], dict[str, Any]] = {}
        for row in records:
            if _valid_activity(row):
                event_key = (
                    row.get("event_id"),
                    row["timestamp"],
                    row["surface"],
                    row["decision"],
                )
                unique[event_key] = row
        events = list(unique.values())
        events.sort(key=lambda item: str(item["timestamp"]), reverse=True)
        today = datetime.now(UTC).date().isoformat()
        counts = {"allowed": 0, "review": 0, "blocked": 0}
        for item in events:
            if str(item["timestamp"]).startswith(today):
                count_key = {"ALLOW": "allowed", "REVIEW": "review", "BLOCK": "blocked"}[
                    str(item["decision"])
                ]
                counts[count_key] += 1
        return {
            "schema_version": ACTIVITY_FEED_SCHEMA,
            "counts": counts,
            "events": events[:bounded_limit],
            "raw_content_retained": False,
        }

    def _proxy_profile(self) -> tuple[ProxyProfile | None, str | None]:
        if self.config.proxy_config is None:
            return None, None
        try:
            return ProxyProfile.from_path(self.config.proxy_config), None
        except (OSError, ProxyProfileError, ValueError):
            return None, "Proxy configuration needs attention."

    def _local_profile(self) -> tuple[LocalGuardProfile | None, str | None]:
        if self.config.local_profile is None:
            return None, None
        try:
            return LocalGuardProfile.from_path(self.config.local_profile), None
        except (OSError, LocalProfileError, ValueError):
            return None, "Local runtime configuration needs attention."

    def _open_webui_profile(
        self,
    ) -> tuple[OpenWebUIIntegrationProfile | None, str | None]:
        if self.config.open_webui_config is None:
            return None, None
        try:
            return OpenWebUIIntegrationProfile.from_path(self.config.open_webui_config), None
        except (OSError, IntegrationProfileError, ValueError):
            return None, "Open WebUI configuration needs attention."

    def _local_runtime_connected(self, profile: LocalGuardProfile | None) -> bool:
        if profile is None:
            return False
        if profile.runtime.provider == "ollama" and profile.runtime.host:
            return self._probe(profile.runtime.host, "/api/tags") is not None
        if profile.runtime.base_url:
            return self._probe(profile.runtime.base_url, "/models") is not None
        return False

    def _open_webui_connected(self, profile: OpenWebUIIntegrationProfile | None) -> bool:
        if profile is None or profile.open_webui_port == 0:
            return False
        origin = f"http://{profile.open_webui_host}:{profile.open_webui_port}"
        response = self._probe(origin, "/api/version")
        return bool(response and response.get("version") == VALIDATED_OPEN_WEBUI_VERSION)

    def _audit_state(self) -> str:
        if self.activity_path is None:
            return "ATTENTION_REQUIRED"
        parent = self.activity_path.parent
        if not parent.is_dir() or not os.access(parent, os.W_OK):
            return "ATTENTION_REQUIRED"
        if self.activity_path.exists() and not self.activity_path.is_file():
            return "ATTENTION_REQUIRED"
        return "ACTIVE"


class GuardProxyLifecycle:
    """Own at most one in-process Guard Proxy and never stop an unrelated listener."""

    def __init__(
        self,
        config_path: Path | None,
        *,
        identity_probe: Probe | None = None,
        upstream_probe: Callable[[ProxyProfile], bool] | None = None,
        server_factory: Callable[[ProxyProfile], GuardProxyHTTPServer] | None = None,
    ) -> None:
        self.config_path = config_path
        self._identity_probe = identity_probe or _loopback_json_probe
        self._upstream_probe = upstream_probe or _proxy_upstream_ready
        self._server_factory = server_factory or GuardProxyHTTPServer
        self._server: GuardProxyHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()

    def status(self) -> dict[str, Any]:
        with self._lock:
            profile, error = self._load_profile()
            if profile is None:
                return _connection_state("NOT_READY", error or "Configure a Guard Proxy profile.")
            health = self._identity_probe(profile.listen_url, "/v1/secureinjections/status")
            if health is not None and health.get("service") == "guard-proxy":
                health_profile = health.get("profile")
                exact = bool(
                    isinstance(health_profile, Mapping)
                    and health_profile.get("hash") == profile.profile_hash
                )
                enforcing = health.get("enforcement_mode") == "ENFORCE"
                if exact and enforcing:
                    owned = self._owned_running()
                    upstream_ready = self._upstream_probe(profile)
                    return _connection_state(
                        "ACTIVE" if upstream_ready else "ATTENTION_REQUIRED",
                        (
                            "Guard Proxy identity, profile, enforcement, and upstream verified."
                            if upstream_ready
                            else (
                                "Guard Proxy is verified, but its local model upstream "
                                "is unavailable."
                            )
                        ),
                        owned=owned,
                        can_stop=owned,
                        endpoint=profile.listen_url,
                        upstream="CONNECTED" if upstream_ready else "UNAVAILABLE",
                    )
                return _connection_state(
                    "ATTENTION_REQUIRED",
                    "The listener is Guard Proxy but its profile or enforcement mode differs.",
                    endpoint=profile.listen_url,
                )
            if not _port_available(profile.listen_host, profile.listen_port):
                return _connection_state(
                    "ATTENTION_REQUIRED",
                    "The configured port is occupied by an unverified process.",
                    endpoint=profile.listen_url,
                )
            if profile.enforcement_mode != "enforce":
                return _connection_state(
                    "ATTENTION_REQUIRED",
                    "Guard Proxy must use ENFORCE mode for product activation.",
                    endpoint=profile.listen_url,
                )
            if not self._upstream_probe(profile):
                return _connection_state(
                    "NOT_READY",
                    "The configured local model upstream is unavailable.",
                    endpoint=profile.listen_url,
                    upstream="UNAVAILABLE",
                )
            return _connection_state(
                "READY_TO_CONNECT",
                "Local upstream and proxy profile are ready.",
                can_start=True,
                endpoint=profile.listen_url,
                upstream="CONNECTED",
            )

    def start(self) -> dict[str, Any]:
        with self._lock:
            before = self.status()
            if before["state"] == "ACTIVE":
                return before
            if before["state"] != "READY_TO_CONNECT":
                raise ProductRuntimeError(str(before["message"]), status_code=409)
            profile, error = self._load_profile()
            if profile is None:
                raise ProductRuntimeError(error or "Guard Proxy profile is unavailable.")
            profile.audit_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                server = self._server_factory(profile)
            except OSError as exc:
                raise ProductRuntimeError(
                    "The Guard Proxy port became unavailable.", status_code=409
                ) from exc
            thread = threading.Thread(
                target=server.serve_forever,
                name="secureinjections-owned-guard-proxy",
                daemon=True,
            )
            self._server, self._thread = server, thread
            thread.start()
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                current = self.status()
                if current["state"] == "ACTIVE" and current["owned"]:
                    return current
                time.sleep(0.02)
            self._stop_owned()
            raise ProductRuntimeError("Owned Guard Proxy did not become healthy.", status_code=503)

    def stop(self) -> dict[str, Any]:
        with self._lock:
            current = self.status()
            if current["state"] == "ACTIVE" and not current["owned"]:
                raise ProductRuntimeError(
                    "The active Guard Proxy is not owned by this product session.", status_code=409
                )
            self._stop_owned()
            return self.status()

    def close(self) -> None:
        with self._lock:
            self._stop_owned()

    def _owned_running(self) -> bool:
        return bool(
            self._server is not None and self._thread is not None and self._thread.is_alive()
        )

    def _stop_owned(self) -> None:
        server, thread = self._server, self._thread
        self._server, self._thread = None, None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=2)

    def _load_profile(self) -> tuple[ProxyProfile | None, str | None]:
        if self.config_path is None:
            return None, None
        try:
            return ProxyProfile.from_path(self.config_path), None
        except (OSError, ProxyProfileError, ValueError):
            return None, "Guard Proxy configuration needs attention."


class ProductRuntimeError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 503) -> None:
        super().__init__(message)
        self.status_code = status_code


def _connection_state(
    state: str,
    message: str,
    *,
    owned: bool = False,
    can_start: bool = False,
    can_stop: bool = False,
    endpoint: str | None = None,
    upstream: str = "UNKNOWN",
) -> dict[str, Any]:
    return {
        "state": state,
        "message": message,
        "owned": owned,
        "can_start": can_start,
        "can_stop": can_stop,
        "endpoint": endpoint,
        "upstream": upstream,
    }


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


def _proxy_upstream_ready(profile: ProxyProfile) -> bool:
    transport = OpenAICompatibleLoopbackTransport(
        profile.upstream_base_url,
        timeout_seconds=min(profile.limits.timeout_seconds, 0.5),
        max_response_bytes=min(profile.limits.response_bytes, 256_000),
    )
    try:
        payload = transport.request("GET", "/models")
    except Exception:
        return False
    return isinstance(payload, Mapping) and isinstance(payload.get("data"), list)


def _surface(surface_id: str, label: str, state: str) -> dict[str, str]:
    assert state in SURFACE_STATES
    return {"id": surface_id, "label": label, "state": state}


def _integration(
    integration_id: str,
    name: str,
    support: str,
    connected: bool,
    protection_state: str,
    guidance: str,
    **details: Any,
) -> dict[str, Any]:
    value = {
        "id": integration_id,
        "name": name,
        "support": support,
        "connected": connected,
        "protection_state": protection_state,
        "guidance": guidance,
    }
    value.update({key: item for key, item in details.items() if item is not None})
    return value


def _display_endpoint(host: str, port: int) -> str:
    rendered = f"[{host}]" if host == "::1" else host
    return f"http://{rendered}:{port}"


def query_product_status(endpoint: str) -> Mapping[str, Any] | None:
    """Read the product status only from a verified loopback endpoint."""

    return _loopback_json_probe(endpoint, "/v1/protection/status")


def _loopback_json_probe(base_url: str, path: str) -> Mapping[str, Any] | None:
    parsed = urlsplit(base_url)
    if parsed.scheme != "http" or parsed.username is not None or parsed.password is not None:
        return None
    try:
        addresses = {str(item[4][0]) for item in socket.getaddrinfo(parsed.hostname, parsed.port)}
    except (OSError, TypeError):
        return None
    if not addresses or any(not _is_loopback(address) for address in addresses):
        return None
    origin = f"{parsed.scheme}://{parsed.netloc}"
    request = Request(origin + path, headers={"Accept": "application/json"})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=0.35) as response:
            raw = response.read(256_000)
    except (HTTPError, URLError, OSError, TimeoutError, ValueError):
        return None
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, Mapping) else None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _is_loopback(address: str) -> bool:
    return address == "::1" or address.startswith("127.")


def _read_jsonl(path: Path | None) -> tuple[dict[str, Any], ...]:
    if path is None:
        return ()
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            handle.seek(max(0, size - _MAX_AUDIT_BYTES))
            raw = handle.read(_MAX_AUDIT_BYTES)
    except OSError:
        return ()
    if size > _MAX_AUDIT_BYTES:
        raw = raw.split(b"\n", 1)[-1]
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines()[-_MAX_AUDIT_LINES:]:
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            rows.append(value)
    return tuple(rows)


def _valid_activity(value: Mapping[str, Any]) -> bool:
    return bool(
        value.get("schema_version") == ACTIVITY_SCHEMA
        and isinstance(value.get("timestamp"), str)
        and value.get("decision") in {"ALLOW", "REVIEW", "BLOCK"}
        and isinstance(value.get("surface"), str)
        and isinstance(value.get("reason"), str)
        and value.get("raw_content_retained") is False
    )


def _record_integrity_valid(value: Mapping[str, Any]) -> bool:
    expected = value.get("record_hash")
    if not isinstance(expected, str):
        return False
    unsigned = {key: item for key, item in value.items() if key != "record_hash"}
    return record_hash(unsigned) == expected


def _proxy_activity(value: Mapping[str, Any]) -> dict[str, Any]:
    events = value.get("guard_events")
    reason = "Protected model traffic completed."
    if isinstance(events, list):
        codes: list[str] = []
        for event in events:
            reason_codes = event.get("reason_codes") if isinstance(event, Mapping) else None
            if isinstance(reason_codes, list):
                codes.extend(code for code in reason_codes if isinstance(code, str))
        if codes:
            reason = ", ".join(dict.fromkeys(codes))[:240]
    return {
        "schema_version": ACTIVITY_SCHEMA,
        "event_id": value.get("record_hash"),
        "timestamp": value.get("timestamp"),
        "surface": "ai_traffic",
        "decision": value.get("final_decision"),
        "reason": reason,
        "correlation_id": value.get("correlation_id"),
        "audit_reference": value.get("record_hash"),
        "policy": {"id": "guard-proxy", "version": value.get("proxy_version")},
        "raw_content_retained": False,
    }


def _guard_activity(value: Mapping[str, Any]) -> dict[str, Any]:
    source = value.get("source")
    destination = value.get("destination")
    surface = _guard_surface(str(source), str(destination))
    policy_value = value.get("policy")
    policy: Mapping[str, Any] = policy_value if isinstance(policy_value, Mapping) else {}
    return {
        "schema_version": ACTIVITY_SCHEMA,
        "event_id": value.get("audit_id"),
        "timestamp": value.get("timestamp"),
        "surface": surface,
        "decision": value.get("decision"),
        "reason": str(policy.get("reason_code", "Policy decision"))[:240],
        "correlation_id": value.get("request_id"),
        "audit_reference": value.get("audit_id"),
        "policy": {"id": policy.get("policy_id"), "version": policy.get("policy_version")},
        "raw_content_retained": False,
    }


def _guard_surface(source: str, destination: str) -> str:
    if source == "file":
        return "files"
    if "memory" in {source, destination}:
        return "memory"
    if destination == "tool" or source in {"tool_input", "tool_output"}:
        return "tool_actions"
    if destination == "external" or source == "external":
        return "external_actions"
    if source in {"user", "retrieved_content"} and destination == "model":
        return "ai_traffic"
    if source == "model" and destination == "user":
        return "ai_traffic"
    return "agent_actions"
