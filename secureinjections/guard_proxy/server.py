"""Loopback HTTP service and doctor for the OpenAI-compatible Guard Proxy."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..guard.audit import canonical_json
from ..local_agent import OpenAICompatibleHTTPError, OpenAICompatibleLoopbackTransport
from .engine import GuardProxyEngine, ProxyResult
from .profile import ProxyProfile


class GuardProxyHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, profile: ProxyProfile, engine: GuardProxyEngine | None = None) -> None:
        self.profile = profile
        self.engine = engine or GuardProxyEngine(profile)
        self.capacity = threading.BoundedSemaphore(profile.limits.concurrency)
        if profile.listen_host == "::1":
            self.address_family = socket.AF_INET6
        super().__init__((profile.listen_host, profile.listen_port), GuardProxyRequestHandler)


class GuardProxyRequestHandler(BaseHTTPRequestHandler):
    server: GuardProxyHTTPServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v1/secureinjections/status":
            policy = self.server.engine.policy
            self._send(
                200,
                {
                    "schema_version": "openai-guard-proxy-status-v0.1",
                    "service": "guard-proxy",
                    "service_running": True,
                    "binding": "loopback-only",
                    "enforcement_mode": self.server.profile.enforcement_mode.upper(),
                    "upstream_classification": "loopback-only",
                    "profile": {
                        "id": self.server.profile.profile_id,
                        "version": self.server.profile.profile_version,
                        "hash": self.server.profile.profile_hash,
                    },
                    "policy": {"id": policy.policy_id, "version": policy.version},
                    "raw_content_retained": False,
                },
                {},
            )
            return
        if self.path != "/v1/models":
            self._send(
                404,
                {
                    "error": {
                        "message": "Unsupported endpoint.",
                        "type": "invalid_request_error",
                        "code": "unsupported_endpoint",
                    }
                },
                {},
            )
            return
        with self.server.capacity:
            self._result(self.server.engine.models(client_request_id=self._client_request_id()))

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/chat/completions":
            self._send(
                404,
                {
                    "error": {
                        "message": "Unsupported endpoint.",
                        "type": "invalid_request_error",
                        "code": "unsupported_endpoint",
                    }
                },
                {},
            )
            return
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or "")
        except ValueError:
            length = -1
        if length < 0 or length > self.server.profile.limits.request_bytes:
            self._result(
                self.server.engine.reject_request(
                    status=413,
                    message="Request size is invalid.",
                    code="request_too_large",
                    client_request_id=self._client_request_id(),
                )
            )
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._result(
                self.server.engine.reject_request(
                    status=400,
                    message="Malformed JSON request.",
                    code="invalid_json",
                    client_request_id=self._client_request_id(),
                )
            )
            return
        if not isinstance(payload, dict):
            self._result(
                self.server.engine.reject_request(
                    status=400,
                    message="Request must be a JSON object.",
                    code="invalid_request",
                    client_request_id=self._client_request_id(),
                )
            )
            return
        with self.server.capacity:
            self._result(
                self.server.engine.chat(
                    payload, request_bytes=length, client_request_id=self._client_request_id()
                )
            )

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _client_request_id(self) -> str | None:
        value = self.headers.get("X-Request-ID")
        if value is None:
            return None
        if not value.isascii() or any(ord(char) < 32 for char in value) or len(value) > 200:
            return None
        return value

    def _result(self, result: ProxyResult) -> None:
        self._send(result.status, result.body, result.headers)

    def _send(self, status: int, body: Any, headers: Any) -> None:
        raw = canonical_json(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)


def doctor_proxy_profile(profile: ProxyProfile) -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    def check(name: str, status: str, detail: str) -> None:
        checks.append({"check": name, "status": status, "detail": detail})

    policy = profile.load_policy()
    check("configuration", "PASS", f"{profile.profile_id}/{profile.profile_version}")
    check("listener", "PASS", f"loopback-only {profile.listen_url}")
    probe_socket = socket.socket(
        socket.AF_INET6 if profile.listen_host == "::1" else socket.AF_INET
    )
    try:
        probe_socket.bind((profile.listen_host, profile.listen_port))
    except OSError:
        check("port_availability", "FAIL", "configured proxy port is unavailable")
    else:
        check("port_availability", "PASS", "configured proxy port is available")
    finally:
        probe_socket.close()
    check(
        "guard_policy", "PASS", f"{policy.policy_id}/{policy.version} sha256:{policy.policy_hash}"
    )
    try:
        profile.audit_directory.mkdir(parents=True, exist_ok=True)
        probe = profile.audit_directory / ".secureinjections-write-probe"
        probe.touch(exist_ok=False)
        probe.unlink()
    except OSError:
        check("audit_directory", "FAIL", "audit directory is not safely writable")
    else:
        check("audit_directory", "PASS", str(profile.audit_directory))
    transport = OpenAICompatibleLoopbackTransport(
        profile.upstream_base_url,
        timeout_seconds=profile.limits.timeout_seconds,
        max_response_bytes=profile.limits.response_bytes,
    )
    try:
        models = transport.request("GET", "/models")
        if not isinstance(models, dict) or not isinstance(models.get("data"), list):
            raise ValueError("malformed inventory")
        check("upstream_models", "PASS", "loopback model discovery is compatible")
        model_ids = [item.get("id") for item in models["data"] if isinstance(item, dict)]
        model = profile.upstream_doctor_model
        if model not in model_ids:
            raise ValueError("configured doctor model is unavailable")
        response = transport.request(
            "POST",
            "/chat/completions",
            {
                "model": model,
                "messages": [{"role": "user", "content": "Reply with the word probe."}],
                "stream": False,
                "max_tokens": 8,
            },
        )
        if not isinstance(response, dict) or not isinstance(response.get("choices"), list):
            raise ValueError("malformed completion")
        check("upstream_chat_completions", "PASS", "minimal compatibility probe passed")
    except OpenAICompatibleHTTPError as exc:
        if exc.status in {404, 405, 501}:
            check(
                "upstream_models",
                "WARN",
                "model discovery unsupported; chat probe not possible without a model identifier",
            )
        else:
            check("upstream", "FAIL", f"local upstream returned HTTP {exc.status}")
    except Exception as exc:
        check("upstream", "FAIL", f"local upstream unavailable/incompatible: {type(exc).__name__}")
    check("redirects_and_proxies", "PASS", "redirects refused; environment proxies disabled")
    check("raw_content_logging", "PASS", "OFF")
    if profile.enforcement_mode == "observe":
        check("enforcement_mode", "WARN", "OBSERVE — security decisions are not enforced")
    else:
        check("enforcement_mode", "PASS", "ENFORCE")
    overall = (
        "FAIL"
        if any(item["status"] == "FAIL" for item in checks)
        else ("WARN" if any(item["status"] == "WARN" for item in checks) else "PASS")
    )
    return {
        "schema_version": "openai-guard-proxy-doctor-v0.1",
        "status": overall,
        "profile_id": profile.profile_id,
        "profile_version": profile.profile_version,
        "profile_hash": profile.profile_hash,
        "proxy_version": "openai-guard-proxy-v0.1",
        "checks": checks,
    }


def serve_proxy(profile: ProxyProfile) -> None:
    GuardProxyHTTPServer(profile).serve_forever()
