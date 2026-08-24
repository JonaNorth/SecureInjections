"""Loopback-only Ollama transport and local model adapter."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any, Protocol
from urllib.parse import urlsplit

from .model import (
    GenerationConfig,
    LocalAgentModel,
    ModelIdentity,
    ModelMessage,
    ModelResponse,
)

OLLAMA_ADAPTER_VERSION = "ollama-agent-adapter-v0.1"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class OllamaAdapterError(RuntimeError):
    pass


class OllamaUnavailableError(OllamaAdapterError):
    pass


class OllamaProtocolError(OllamaAdapterError):
    pass


class JsonTransport(Protocol):
    def request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any: ...


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise OllamaProtocolError("Ollama transport refuses redirects")


class LoopbackJsonTransport:
    """Bounded JSON transport with proxies and redirects disabled."""

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:11434",
        *,
        timeout_seconds: float = 120.0,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in _LOOPBACK_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Ollama endpoint must be a plain HTTP loopback origin")
        try:
            port = parsed.port or 11434
        except ValueError as exc:
            raise ValueError("Ollama endpoint contains an invalid port") from exc
        if not 1 <= port <= 65_535:
            raise ValueError("Ollama endpoint contains an invalid port")
        if not 0.1 <= timeout_seconds <= 600:
            raise ValueError("Ollama timeout must be between 0.1 and 600 seconds")
        if not 1_024 <= max_response_bytes <= 10_000_000:
            raise ValueError("Ollama response bound is outside the supported range")
        host = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
        self.endpoint = f"http://{host}:{port}"
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.proxies_disabled = True
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _RejectRedirects(),
        )

    def request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any:
        if method not in {"GET", "POST"} or not path.startswith("/api/") or "?" in path:
            raise ValueError("unsupported Ollama request")
        body = None
        headers = {"Accept": "application/json", "User-Agent": OLLAMA_ADAPTER_VERSION}
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if len(body) > 2_000_000:
                raise OllamaProtocolError("Ollama request exceeds size limit")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.endpoint + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                declared = response.headers.get("Content-Length")
                if declared is not None and int(declared) > self.max_response_bytes:
                    raise OllamaProtocolError("Ollama response exceeds declared size limit")
                raw = response.read(self.max_response_bytes + 1)
        except OllamaProtocolError:
            raise
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError) as exc:
            raise OllamaUnavailableError(
                f"local Ollama request failed: {type(exc).__name__}"
            ) from exc
        if len(raw) > self.max_response_bytes:
            raise OllamaProtocolError("Ollama response exceeds size limit")
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OllamaProtocolError("Ollama returned malformed JSON") from exc


class OllamaAgentAdapter(LocalAgentModel):
    def __init__(
        self,
        transport: JsonTransport,
        identity: ModelIdentity,
        *,
        generation_config: GenerationConfig | None = None,
    ) -> None:
        self._transport = transport
        self._identity = identity
        self._generation_config = generation_config or GenerationConfig()

    @classmethod
    def connect(
        cls,
        *,
        endpoint: str = "http://127.0.0.1:11434",
        model: str | None = None,
        timeout_seconds: float = 120.0,
        generation_config: GenerationConfig | None = None,
    ) -> OllamaAgentAdapter:
        transport = LoopbackJsonTransport(endpoint, timeout_seconds=timeout_seconds)
        version_payload = transport.request("GET", "/api/version")
        tags_payload = transport.request("GET", "/api/tags")
        version = _required_string(version_payload, "version", "Ollama version")
        if not isinstance(tags_payload, Mapping) or not isinstance(
            tags_payload.get("models"), list
        ):
            raise OllamaProtocolError("Ollama model inventory is malformed")
        models = [item for item in tags_payload["models"] if isinstance(item, Mapping)]
        selected = _select_model(models, model)
        name = _required_string(selected, "name", "model name")
        digest = _required_string(selected, "digest", "model digest")
        tag = name.partition(":")[2] or "latest"
        identity = ModelIdentity(
            "ollama",
            version,
            name,
            tag,
            digest,
            OLLAMA_ADAPTER_VERSION,
            "ollama-native",
            "loopback-only",
        )
        return cls(
            transport,
            identity,
            generation_config=generation_config,
        )

    @property
    def identity(self) -> ModelIdentity:
        return self._identity

    @property
    def generation_config(self) -> GenerationConfig:
        return self._generation_config

    def generate(
        self,
        messages: Sequence[ModelMessage],
        *,
        response_schema: Mapping[str, Any],
    ) -> ModelResponse:
        if not messages or len(messages) > 64:
            raise OllamaProtocolError("model conversation must contain between 1 and 64 messages")
        if sum(len(message.content.encode("utf-8")) for message in messages) > 256_000:
            raise OllamaProtocolError("model conversation exceeds size limit")
        config = self._generation_config
        payload = {
            "model": self._identity.model_name,
            "messages": [message.to_dict() for message in messages],
            "stream": False,
            "format": dict(response_schema),
            "options": {
                "temperature": config.temperature,
                "seed": config.seed,
                "num_predict": config.max_tokens,
            },
            "keep_alive": "5m",
        }
        started = time.perf_counter_ns()
        response = self._transport.request("POST", "/api/chat", payload)
        latency_ms = (time.perf_counter_ns() - started) / 1_000_000
        if not isinstance(response, Mapping) or not isinstance(response.get("message"), Mapping):
            raise OllamaProtocolError("Ollama chat response is malformed")
        content = response["message"].get("content")
        if not isinstance(content, str) or len(content.encode("utf-8")) > 65_536:
            raise OllamaProtocolError("Ollama message content is missing or exceeds limits")
        total_duration = response.get("total_duration")
        model_duration_ms = (
            float(total_duration) / 1_000_000
            if isinstance(total_duration, (int, float)) and not isinstance(total_duration, bool)
            else None
        )
        overhead = (
            max(0.0, latency_ms - model_duration_ms) if model_duration_ms is not None else None
        )
        return ModelResponse(content, latency_ms, model_duration_ms, overhead)


def _select_model(models: list[Mapping[str, Any]], requested: str | None) -> Mapping[str, Any]:
    by_name = {
        item.get("name"): item
        for item in models
        if isinstance(item.get("name"), str) and item.get("name")
    }
    if requested is not None:
        if requested not in by_name:
            raise OllamaUnavailableError("requested model is not installed locally")
        return by_name[requested]
    for prefix in ("qwen", "llama", "gemma", "mistral", "phi"):
        for name, item in by_name.items():
            if str(name).casefold().startswith(prefix):
                return item
    raise OllamaUnavailableError("no suitable installed local chat/instruction model found")


def _required_string(payload: Any, key: str, label: str) -> str:
    if not isinstance(payload, Mapping):
        raise OllamaProtocolError(f"{label} response is malformed")
    value = payload.get(key)
    if not isinstance(value, str) or not value or len(value) > 500:
        raise OllamaProtocolError(f"{label} is missing or invalid")
    return value
