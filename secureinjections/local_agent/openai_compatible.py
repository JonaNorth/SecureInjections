"""Loopback-only adapter for the minimal OpenAI-compatible local chat API subset."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any, Protocol
from urllib.parse import urlsplit

from ..guard.audit import canonical_json
from .model import GenerationConfig, LocalAgentModel, ModelIdentity, ModelMessage, ModelResponse
from .protocol import ACTION_SCHEMA, ALLOWED_MODEL_TOOLS, parse_action

OPENAI_COMPATIBLE_LOCAL_ADAPTER_VERSION = "openai-compatible-local-adapter-v0.1"
OPENAI_COMPATIBLE_PROTOCOL_VERSION = "openai-compatible-chat-completions-v1"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class OpenAICompatibleLocalError(RuntimeError):
    pass


class OpenAICompatibleUnavailableError(OpenAICompatibleLocalError):
    pass


class OpenAICompatibleProtocolError(OpenAICompatibleLocalError):
    pass


class OpenAICompatibleHTTPError(OpenAICompatibleUnavailableError):
    def __init__(self, status: int) -> None:
        super().__init__(f"local OpenAI-compatible endpoint returned HTTP {status}")
        self.status = status


class OpenAICompatibleTransport(Protocol):
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
        raise OpenAICompatibleProtocolError("local model transport refuses redirects")


class OpenAICompatibleLoopbackTransport:
    """Bounded, credential-free HTTP transport constrained to a loopback /v1 API root."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 120.0,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in _LOOPBACK_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/", "/v1", "/v1/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "OpenAI-compatible local base URL must be a plain HTTP loopback origin or /v1 root"
            )
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("OpenAI-compatible local base URL contains an invalid port") from exc
        if port is None or not 1 <= port <= 65_535:
            raise ValueError("OpenAI-compatible local base URL requires an explicit valid port")
        if not 0.1 <= timeout_seconds <= 600:
            raise ValueError("local model timeout must be between 0.1 and 600 seconds")
        if not 1_024 <= max_response_bytes <= 10_000_000:
            raise ValueError("local model response bound is outside the supported range")
        host = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
        self.api_root = f"http://{host}:{port}/v1"
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.proxies_disabled = True
        self.credentials_used = False
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _RejectRedirects(),
        )

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> Any:
        if method not in {"GET", "POST"} or path not in {"/models", "/chat/completions"}:
            raise ValueError("unsupported OpenAI-compatible local API request")
        body = None
        headers = {
            "Accept": "application/json",
            "User-Agent": OPENAI_COMPATIBLE_LOCAL_ADAPTER_VERSION,
        }
        if payload is not None:
            body = canonical_json(payload).encode("utf-8")
            if len(body) > 2_000_000:
                raise OpenAICompatibleProtocolError("local model request exceeds size limit")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.api_root + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                declared = response.headers.get("Content-Length")
                if declared is not None and int(declared) > self.max_response_bytes:
                    raise OpenAICompatibleProtocolError(
                        "local model response exceeds declared size limit"
                    )
                raw = response.read(self.max_response_bytes + 1)
        except OpenAICompatibleProtocolError:
            raise
        except urllib.error.HTTPError as exc:
            raise OpenAICompatibleHTTPError(exc.code) from exc
        except (OSError, urllib.error.URLError, ValueError) as exc:
            raise OpenAICompatibleUnavailableError(
                f"local OpenAI-compatible request failed: {type(exc).__name__}"
            ) from exc
        if len(raw) > self.max_response_bytes:
            raise OpenAICompatibleProtocolError("local model response exceeds size limit")
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OpenAICompatibleProtocolError(
                "local OpenAI-compatible endpoint returned malformed JSON"
            ) from exc


class OpenAICompatibleLocalAgentAdapter(LocalAgentModel):
    def __init__(
        self,
        transport: OpenAICompatibleTransport,
        identity: ModelIdentity,
        *,
        generation_config: GenerationConfig | None = None,
        model_discovery_supported: bool = True,
    ) -> None:
        self._transport = transport
        self._identity = identity
        self._generation_config = generation_config or GenerationConfig()
        self.model_discovery_supported = model_discovery_supported

    @classmethod
    def connect(
        cls,
        *,
        base_url: str,
        model: str,
        timeout_seconds: float = 120.0,
        max_response_bytes: int = 2_000_000,
        generation_config: GenerationConfig | None = None,
    ) -> OpenAICompatibleLocalAgentAdapter:
        if not model or len(model) > 500:
            raise ValueError("an explicit bounded local model name is required")
        transport = OpenAICompatibleLoopbackTransport(
            base_url,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        model_record: Mapping[str, Any] | None = None
        discovery_supported = True
        try:
            inventory = transport.request("GET", "/models")
            model_record = _find_model(inventory, model)
        except OpenAICompatibleHTTPError as exc:
            if exc.status not in {404, 405, 501}:
                raise
            discovery_supported = False
        digest = _model_digest(model_record)
        identity = ModelIdentity(
            "openai_compatible_local",
            "v1",
            model,
            model.partition(":")[2] or "local",
            digest,
            OPENAI_COMPATIBLE_LOCAL_ADAPTER_VERSION,
            OPENAI_COMPATIBLE_PROTOCOL_VERSION,
            "loopback-only",
        )
        return cls(
            transport,
            identity,
            generation_config=generation_config,
            model_discovery_supported=discovery_supported,
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
        if response_schema != ACTION_SCHEMA:
            raise OpenAICompatibleProtocolError("unsupported application response schema")
        if not messages or len(messages) > 64:
            raise OpenAICompatibleProtocolError(
                "model conversation must contain between 1 and 64 messages"
            )
        if sum(len(message.content.encode("utf-8")) for message in messages) > 256_000:
            raise OpenAICompatibleProtocolError("model conversation exceeds size limit")
        config = self._generation_config
        payload = {
            "model": self._identity.model_name,
            "messages": [message.to_dict() for message in messages],
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "seed": config.seed,
            "stream": False,
            "response_format": {"type": "json_object"},
            "tools": _tool_descriptions(),
            "tool_choice": "auto",
        }
        started = time.perf_counter_ns()
        response = self._transport.request("POST", "/chat/completions", payload)
        latency_ms = (time.perf_counter_ns() - started) / 1_000_000
        content = normalize_openai_chat_response(response)
        return ModelResponse(content, latency_ms, None, None)


def normalize_openai_chat_response(response: Any) -> str:
    if not isinstance(response, Mapping):
        raise OpenAICompatibleProtocolError("chat completion response must be an object")
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise OpenAICompatibleProtocolError("chat completion must contain exactly one choice")
    choice = choices[0]
    if not isinstance(choice, Mapping) or not isinstance(choice.get("message"), Mapping):
        raise OpenAICompatibleProtocolError("chat completion message is malformed")
    return normalize_openai_message(choice["message"])


def normalize_openai_message(message: Mapping[str, Any]) -> str:
    allowed = {"role", "content", "tool_calls", "refusal"}
    if set(message) - allowed:
        raise OpenAICompatibleProtocolError("chat message contains unsupported fields")
    content = message.get("content")
    tool_calls = message.get("tool_calls")
    has_content = isinstance(content, str) and bool(content.strip())
    has_tools = isinstance(tool_calls, list) and bool(tool_calls)
    if has_content == has_tools:
        raise OpenAICompatibleProtocolError(
            "assistant message must contain exactly one content or tool-call action"
        )
    if has_content:
        assert isinstance(content, str)
        if len(content.encode("utf-8")) > 65_536:
            raise OpenAICompatibleProtocolError("assistant content exceeds size limit")
        parse_action(content)
        return content
    if not isinstance(tool_calls, list) or len(tool_calls) != 1:
        raise OpenAICompatibleProtocolError("exactly one tool call is required")
    call = tool_calls[0]
    if not isinstance(call, Mapping) or set(call) - {"id", "type", "function", "index"}:
        raise OpenAICompatibleProtocolError("tool call structure is malformed")
    if call.get("type", "function") != "function" or not isinstance(call.get("function"), Mapping):
        raise OpenAICompatibleProtocolError("only function tool calls are supported")
    function = call["function"]
    if set(function) != {"name", "arguments"}:
        raise OpenAICompatibleProtocolError("function call fields are malformed")
    name = function["name"]
    arguments_raw = function["arguments"]
    if not isinstance(name, str) or not isinstance(arguments_raw, str):
        raise OpenAICompatibleProtocolError("function name and arguments must be strings")
    if len(arguments_raw.encode("utf-8")) > 32_768:
        raise OpenAICompatibleProtocolError("function arguments exceed size limit")
    try:
        arguments = json.loads(arguments_raw)
    except json.JSONDecodeError as exc:
        raise OpenAICompatibleProtocolError("function arguments are malformed JSON") from exc
    if not isinstance(arguments, dict):
        raise OpenAICompatibleProtocolError("function arguments must be one JSON object")
    if name in ALLOWED_MODEL_TOOLS:
        action = {"action": "TOOL_CALL", "tool": name, "arguments": arguments}
    elif name == "memory_write":
        action = {"action": "MEMORY_WRITE", "memory": arguments}
    elif name == "external_send":
        action = {"action": "EXTERNAL_SEND", "external": arguments}
    else:
        raise OpenAICompatibleProtocolError("unknown local function tool")
    normalized = canonical_json(action)
    parse_action(normalized)
    return normalized


def _find_model(payload: Any, requested: str) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping) or not isinstance(payload.get("data"), list):
        raise OpenAICompatibleProtocolError("model inventory is malformed")
    records = [item for item in payload["data"] if isinstance(item, Mapping)]
    for item in records:
        if item.get("id") == requested:
            return item
    raise OpenAICompatibleUnavailableError(
        f"Configured model {requested} is not available from the local endpoint."
    )


def _model_digest(record: Mapping[str, Any] | None) -> str:
    if record is None:
        return "unavailable"
    for key in ("digest", "sha256"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return "unavailable"


def _tool_descriptions() -> list[dict[str, Any]]:
    definitions: tuple[tuple[str, str, dict[str, Any]], ...] = (
        (
            "calculator",
            "Add or multiply two numbers through the guarded calculator.",
            {
                "type": "object",
                "properties": {
                    "operation": {"enum": ["add", "multiply"]},
                    "left": {"type": "number"},
                    "right": {"type": "number"},
                },
                "required": ["operation", "left", "right"],
                "additionalProperties": False,
            },
        ),
        (
            "workspace_reader",
            "Propose reading one path inside the configured local workspace.",
            {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        ),
        (
            "document_retriever",
            "Retrieve one configured local document by identifier.",
            {
                "type": "object",
                "properties": {"document_id": {"type": "string"}},
                "required": ["document_id"],
                "additionalProperties": False,
            },
        ),
        (
            "memory_write",
            "Propose a guarded local memory record.",
            {"type": "object", "additionalProperties": True},
        ),
        (
            "external_send",
            "Propose a guarded send to the simulated external sink.",
            {"type": "object", "additionalProperties": True},
        ),
    )
    return [
        {
            "type": "function",
            "function": {"name": name, "description": description, "parameters": parameters},
        }
        for name, description, parameters in definitions
    ]
