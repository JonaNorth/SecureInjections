"""Protocol validation and Guard enforcement for the local reverse proxy."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from ..guard import Guard, GuardDecision, InspectionRequest
from ..guard.audit import append_audit, canonical_json, record_hash
from ..local_agent import OpenAICompatibleLoopbackTransport
from .profile import ProxyProfile

PROXY_VERSION = "openai-guard-proxy-v0.1"
PROXY_PROTOCOL_VERSION = "openai-compatible-guard-proxy-v0.1"


class ProxyProtocolError(ValueError):
    pass


class ProxyUpstream(Protocol):
    def request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any: ...


@dataclass(frozen=True, slots=True)
class ProxyResult:
    status: int
    body: Mapping[str, Any]
    headers: Mapping[str, str]
    upstream_dispatched: bool
    decision: str
    correlation_id: str
    timings_ms: Mapping[str, float]


@dataclass(frozen=True, slots=True)
class _GuardEvent:
    boundary: str
    decision: GuardDecision
    audit_id: str
    record_hash: str
    finding_types: tuple[str, ...]
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "boundary": self.boundary,
            "decision": self.decision.value,
            "audit_id": self.audit_id,
            "guard_record_hash": self.record_hash,
            "finding_types": list(self.finding_types),
            "reason_codes": list(self.reason_codes),
        }


class GuardProxyEngine:
    def __init__(self, profile: ProxyProfile, upstream: ProxyUpstream | None = None) -> None:
        self.profile = profile
        self.policy = profile.load_policy()
        self.guard = Guard(policy=self.policy)
        self.upstream = upstream or OpenAICompatibleLoopbackTransport(
            profile.upstream_base_url,
            timeout_seconds=profile.limits.timeout_seconds,
            max_response_bytes=profile.limits.response_bytes,
        )

    def reject_request(
        self,
        *,
        status: int,
        message: str,
        code: str,
        client_request_id: str | None = None,
        error_type: str = "ProxyProtocolError",
    ) -> ProxyResult:
        correlation_id = _correlation_id()
        body = _error(message, code)
        headers = _headers("BLOCK", correlation_id, ())
        timings = {"end_to_end": 0.0}
        self._audit(
            correlation_id,
            client_request_id,
            "POST /v1/chat/completions",
            None,
            body,
            (),
            False,
            "BLOCK",
            status,
            timings,
            error_type,
        )
        return ProxyResult(status, body, headers, False, "BLOCK", correlation_id, timings)

    def models(self, *, client_request_id: str | None = None) -> ProxyResult:
        correlation_id = _correlation_id()
        started = time.perf_counter_ns()
        error_type: str | None
        try:
            body = self.upstream.request("GET", "/models")
            if not isinstance(body, Mapping) or not isinstance(body.get("data"), list):
                raise ProxyProtocolError("upstream models response is malformed")
            status, decision = 200, "ALLOW"
        except Exception as exc:
            body = _error(
                "The local model upstream is unavailable.", "secureinjections_upstream_error"
            )
            status, decision = 502, "BLOCK"
            error_type = type(exc).__name__
        else:
            error_type = None
        elapsed = _elapsed(started)
        headers = _headers(decision, correlation_id, ())
        self._audit(
            correlation_id,
            client_request_id,
            "GET /v1/models",
            None,
            body,
            (),
            status == 200,
            decision,
            status,
            {"end_to_end": elapsed},
            error_type,
        )
        return ProxyResult(
            status, body, headers, status == 200, decision, correlation_id, {"end_to_end": elapsed}
        )

    def chat(
        self,
        payload: Mapping[str, Any],
        *,
        request_bytes: int | None = None,
        client_request_id: str | None = None,
    ) -> ProxyResult:
        correlation_id = _correlation_id()
        started = time.perf_counter_ns()
        guard_started = time.perf_counter_ns()
        try:
            validated = self._validate_request(payload, request_bytes=request_bytes)
            ingress = self._inspect_request(validated, correlation_id)
        except ProxyProtocolError as exc:
            return self._failure(
                correlation_id,
                client_request_id,
                payload,
                (),
                400,
                "Malformed OpenAI-compatible request.",
                "secureinjections_invalid_request",
                started,
                error_type=type(exc).__name__,
            )
        guard_ingress_ms = _elapsed(guard_started)
        ingress_decision = _maximum_decision(ingress)
        if (
            ingress_decision is not GuardDecision.ALLOW
            and self.profile.enforcement_mode == "enforce"
        ):
            status = 403 if ingress_decision is GuardDecision.BLOCK else 409
            code = (
                "secureinjections_blocked" if status == 403 else "secureinjections_review_required"
            )
            return self._failure(
                correlation_id,
                client_request_id,
                validated,
                ingress,
                status,
                "Request blocked by SecureInjections security policy.",
                code,
                started,
                upstream_dispatched=False,
                timings={"guard_ingress": guard_ingress_ms},
            )
        upstream_started = time.perf_counter_ns()
        try:
            response = self.upstream.request(
                "POST", "/chat/completions", _upstream_payload(validated)
            )
        except Exception as exc:
            return self._failure(
                correlation_id,
                client_request_id,
                validated,
                ingress,
                502,
                "The local model upstream failed safely.",
                "secureinjections_upstream_error",
                started,
                upstream_dispatched=True,
                timings={"guard_ingress": guard_ingress_ms, "upstream": _elapsed(upstream_started)},
                error_type=type(exc).__name__,
            )
        upstream_ms = _elapsed(upstream_started)
        guard_started = time.perf_counter_ns()
        try:
            downstream = self._inspect_response(response, correlation_id)
        except ProxyProtocolError as exc:
            return self._failure(
                correlation_id,
                client_request_id,
                validated,
                ingress,
                502,
                "The local model returned an invalid response.",
                "secureinjections_invalid_upstream_response",
                started,
                upstream_dispatched=True,
                response=response,
                timings={"guard_ingress": guard_ingress_ms, "upstream": upstream_ms},
                error_type=type(exc).__name__,
            )
        guard_downstream_ms = _elapsed(guard_started)
        events = (*ingress, *downstream)
        decision = _maximum_decision(events)
        if decision is not GuardDecision.ALLOW and self.profile.enforcement_mode == "enforce":
            status = 403 if decision is GuardDecision.BLOCK else 409
            code = (
                "secureinjections_blocked" if status == 403 else "secureinjections_review_required"
            )
            return self._failure(
                correlation_id,
                client_request_id,
                validated,
                events,
                status,
                "Response blocked by SecureInjections security policy.",
                code,
                started,
                upstream_dispatched=True,
                response=response,
                timings={
                    "guard_ingress": guard_ingress_ms,
                    "upstream": upstream_ms,
                    "guard_downstream": guard_downstream_ms,
                },
            )
        final_decision = decision.value
        headers = _headers(final_decision, correlation_id, events)
        timings = {
            "guard_ingress": guard_ingress_ms,
            "upstream": upstream_ms,
            "guard_downstream": guard_downstream_ms,
            "end_to_end": _elapsed(started),
        }
        self._audit(
            correlation_id,
            client_request_id,
            "POST /v1/chat/completions",
            validated,
            response,
            events,
            True,
            final_decision,
            200,
            timings,
            None,
        )
        return ProxyResult(200, response, headers, True, final_decision, correlation_id, timings)

    def _validate_request(
        self, payload: Mapping[str, Any], *, request_bytes: int | None
    ) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ProxyProtocolError("request must be an object")
        encoded = canonical_json(payload).encode("utf-8")
        if len(encoded) > self.profile.limits.request_bytes or (
            request_bytes is not None and request_bytes > self.profile.limits.request_bytes
        ):
            raise ProxyProtocolError("request exceeds size limit")
        allowed = {
            "model",
            "messages",
            "tools",
            "tool_choice",
            "temperature",
            "max_tokens",
            "seed",
            "stream",
            "response_format",
            "stop",
            "frequency_penalty",
            "presence_penalty",
            "n",
            "user",
        }
        if set(payload) - allowed:
            raise ProxyProtocolError("request contains unsupported fields")
        model = payload.get("model")
        messages = payload.get("messages")
        if not isinstance(model, str) or not model or len(model) > 500:
            raise ProxyProtocolError("model must be a bounded string")
        if (
            not isinstance(messages, list)
            or not 1 <= len(messages) <= self.profile.limits.message_count
        ):
            raise ProxyProtocolError("messages count is invalid")
        for message in messages:
            self._validate_message(message)
        if payload.get("stream", False) is not False:
            raise ProxyProtocolError("streaming is unsupported")
        temperature = payload.get("temperature", 0)
        if (
            not isinstance(temperature, (int, float))
            or isinstance(temperature, bool)
            or not 0 <= temperature <= 2
        ):
            raise ProxyProtocolError("temperature is invalid")
        max_tokens = payload.get("max_tokens", 256)
        if (
            not isinstance(max_tokens, int)
            or isinstance(max_tokens, bool)
            or not 1 <= max_tokens <= 4096
        ):
            raise ProxyProtocolError("max_tokens is invalid")
        if payload.get("n", 1) != 1:
            raise ProxyProtocolError("only one completion choice is supported")
        tools = payload.get("tools", [])
        if not isinstance(tools, list) or len(tools) > self.profile.limits.tool_count:
            raise ProxyProtocolError("tools count is invalid")
        for tool in tools:
            self._validate_tool_schema(tool)
        return dict(payload)

    def _validate_message(self, message: Any) -> None:
        if not isinstance(message, Mapping):
            raise ProxyProtocolError("message must be an object")
        allowed = {"role", "content", "name", "tool_call_id", "tool_calls", "metadata"}
        if set(message) - allowed:
            raise ProxyProtocolError("message contains unsupported fields")
        role = message.get("role")
        if role not in {"system", "developer", "user", "assistant", "tool"}:
            raise ProxyProtocolError("unsupported message role")
        content = message.get("content")
        if content is not None and (
            not isinstance(content, str)
            or len(content.encode("utf-8")) > self.profile.limits.message_bytes
        ):
            raise ProxyProtocolError("message content is invalid")
        if content is None and not (role == "assistant" and message.get("tool_calls")):
            raise ProxyProtocolError("message content is required")
        metadata = message.get("metadata")
        if metadata is not None:
            if not isinstance(metadata, Mapping) or set(metadata) != {"secureinjections_source"}:
                raise ProxyProtocolError("trust metadata is malformed")
            if metadata["secureinjections_source"] not in {
                "retrieved_content",
                "external",
                "tool_output",
            }:
                raise ProxyProtocolError("trust metadata source is not allowed")

    def _validate_tool_schema(self, tool: Any) -> None:
        if (
            not isinstance(tool, Mapping)
            or set(tool) != {"type", "function"}
            or tool.get("type") != "function"
        ):
            raise ProxyProtocolError("only function tools are supported")
        function = tool.get("function")
        if not isinstance(function, Mapping) or set(function) - {
            "name",
            "description",
            "parameters",
            "strict",
        }:
            raise ProxyProtocolError("function schema is malformed")
        name = function.get("name")
        if not isinstance(name, str) or not name or len(name) > 200:
            raise ProxyProtocolError("function name is invalid")
        if len(canonical_json(tool).encode("utf-8")) > self.profile.limits.tool_schema_bytes:
            raise ProxyProtocolError("function schema exceeds size limit")
        _validate_json_shape(tool)

    def _inspect_request(
        self, payload: Mapping[str, Any], correlation_id: str
    ) -> tuple[_GuardEvent, ...]:
        events: list[_GuardEvent] = []
        for index, message in enumerate(payload["messages"]):
            assert isinstance(message, Mapping)
            content = message.get("content")
            if not isinstance(content, str) or not content:
                continue
            role = message["role"]
            source = {
                "system": "system",
                "developer": "system",
                "user": "user",
                "assistant": "internal",
                "tool": "tool_output",
            }[role]
            metadata = message.get("metadata")
            if isinstance(metadata, Mapping):
                source = str(metadata["secureinjections_source"])
            result = self.guard.inspect(
                InspectionRequest(
                    content,
                    source,
                    "model",
                    {"request_id": correlation_id, "metadata": {"message_index": str(index)}},
                )
            )
            events.append(_event(f"ingress_message_{index}", result))
        for index, tool in enumerate(payload.get("tools", [])):
            content = canonical_json(tool)
            result = self.guard.inspect(
                InspectionRequest(
                    content,
                    "external",
                    "model",
                    {"request_id": correlation_id, "metadata": {"tool_index": str(index)}},
                )
            )
            events.append(_event(f"ingress_tool_schema_{index}", result))
        return tuple(events)

    def _inspect_response(self, response: Any, correlation_id: str) -> tuple[_GuardEvent, ...]:
        if not isinstance(response, Mapping):
            raise ProxyProtocolError("response must be an object")
        if len(canonical_json(response).encode("utf-8")) > self.profile.limits.response_bytes:
            raise ProxyProtocolError("response exceeds size limit")
        choices = response.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise ProxyProtocolError("response must contain exactly one choice")
        choice = choices[0]
        if not isinstance(choice, Mapping) or not isinstance(choice.get("message"), Mapping):
            raise ProxyProtocolError("response message is malformed")
        message = choice["message"]
        if message.get("role") != "assistant" or set(message) - {
            "role",
            "content",
            "tool_calls",
            "refusal",
        }:
            raise ProxyProtocolError("assistant response is malformed")
        content = message.get("content")
        calls = message.get("tool_calls")
        has_content = isinstance(content, str) and bool(content)
        has_calls = isinstance(calls, list) and bool(calls)
        if has_content == has_calls:
            raise ProxyProtocolError("response must contain content or tool calls, not both")
        events: list[_GuardEvent] = []
        if has_content:
            result = self.guard.inspect(
                InspectionRequest(content, "model", "user", {"request_id": correlation_id})
            )
            events.append(_event("egress_content", result))
        else:
            assert isinstance(calls, list)
            if len(calls) > self.profile.limits.tool_count:
                raise ProxyProtocolError("response tool count exceeds limit")
            for index, call in enumerate(calls):
                name, arguments = self._parse_tool_call(call)
                result = self.guard.inspect_tool_call(
                    name, arguments, context={"request_id": correlation_id}
                )
                events.append(_event(f"egress_tool_call_{index}", result))
        return tuple(events)

    def _parse_tool_call(self, call: Any) -> tuple[str, Mapping[str, Any]]:
        if not isinstance(call, Mapping) or set(call) - {"id", "type", "function", "index"}:
            raise ProxyProtocolError("tool call is malformed")
        if call.get("type", "function") != "function" or not isinstance(
            call.get("function"), Mapping
        ):
            raise ProxyProtocolError("only function calls are supported")
        function = call["function"]
        if set(function) != {"name", "arguments"}:
            raise ProxyProtocolError("function call fields are malformed")
        name, raw = function["name"], function["arguments"]
        if not isinstance(name, str) or not name or not isinstance(raw, str):
            raise ProxyProtocolError("function call values are invalid")
        if len(raw.encode("utf-8")) > self.profile.limits.tool_argument_bytes:
            raise ProxyProtocolError("function arguments exceed size limit")
        try:
            arguments = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProxyProtocolError("function arguments are malformed") from exc
        if not isinstance(arguments, Mapping):
            raise ProxyProtocolError("function arguments must be an object")
        _validate_json_shape(arguments)
        # Guard's typed ToolCallRequest performs the canonical bounded shape validation.
        return name, arguments

    def _failure(
        self,
        correlation_id: str,
        client_request_id: str | None,
        request: Mapping[str, Any],
        events: tuple[_GuardEvent, ...],
        status: int,
        message: str,
        code: str,
        started: int,
        *,
        upstream_dispatched: bool = False,
        response: Any = None,
        timings: Mapping[str, float] | None = None,
        error_type: str | None = None,
    ) -> ProxyResult:
        body = _error(message, code)
        decision = _maximum_decision(events).value if events else "BLOCK"
        if status == 409:
            decision = "REVIEW"
        elif status in {400, 403, 502}:
            decision = "BLOCK"
        measured = dict(timings or {})
        measured["end_to_end"] = _elapsed(started)
        headers = _headers(decision, correlation_id, events)
        self._audit(
            correlation_id,
            client_request_id,
            "POST /v1/chat/completions",
            request,
            response if response is not None else body,
            events,
            upstream_dispatched,
            decision,
            status,
            measured,
            error_type,
        )
        return ProxyResult(
            status, body, headers, upstream_dispatched, decision, correlation_id, measured
        )

    def _audit(
        self,
        correlation_id: str,
        client_request_id: str | None,
        endpoint: str,
        request: Mapping[str, Any] | None,
        response: Any,
        events: tuple[_GuardEvent, ...],
        upstream_dispatched: bool,
        decision: str,
        http_status: int,
        timings: Mapping[str, float],
        error_type: str | None,
    ) -> None:
        if not self.profile.audit_enabled:
            return
        record: dict[str, Any] = {
            "schema_version": "openai-guard-proxy-audit-v0.1",
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "correlation_id": correlation_id,
            "client_request_id_hash": _hash_text(client_request_id) if client_request_id else None,
            "endpoint": endpoint,
            "request_hash": record_hash(request) if request is not None else None,
            "response_hash": record_hash(response)
            if isinstance(response, Mapping)
            else _hash_text(str(type(response).__name__)),
            "guard_events": [event.to_dict() for event in events],
            "upstream_dispatch": upstream_dispatched,
            "upstream_classification": "loopback-only",
            "upstream_model": (
                request.get("model")
                if request is not None and isinstance(request.get("model"), str)
                else None
            ),
            "final_decision": decision,
            "http_status": http_status,
            "enforcement_mode": self.profile.enforcement_mode.upper(),
            "enforcement_disabled": self.profile.enforcement_mode == "observe",
            "profile_id": self.profile.profile_id,
            "profile_version": self.profile.profile_version,
            "profile_hash": self.profile.profile_hash,
            "policy_hash": self.policy.policy_hash,
            "proxy_version": PROXY_VERSION,
            "protocol_version": PROXY_PROTOCOL_VERSION,
            "timings_ms": {key: round(value, 4) for key, value in timings.items()},
            "error_type": error_type,
            "raw_content_retained": False,
        }
        record["record_hash"] = record_hash(record)
        append_audit(self.profile.audit_path, record)


def _event(boundary: str, result: Any) -> _GuardEvent:
    return _GuardEvent(
        boundary,
        result.decision,
        result.audit_id,
        result.audit_record_hash,
        tuple(item.finding_type.value for item in result.findings),
        tuple(
            dict.fromkeys(
                [result.policy.reason_code, *(item.reason_code for item in result.findings)]
            )
        ),
    )


def _maximum_decision(events: tuple[_GuardEvent, ...]) -> GuardDecision:
    return max(
        (event.decision for event in events),
        default=GuardDecision.ALLOW,
        key=lambda item: {GuardDecision.ALLOW: 0, GuardDecision.REVIEW: 1, GuardDecision.BLOCK: 2}[
            item
        ],
    )


def _headers(decision: str, correlation_id: str, events: tuple[_GuardEvent, ...]) -> dict[str, str]:
    audit_ids = [event.audit_id for event in events]
    return {
        "X-SecureInjections-Decision": decision,
        "X-SecureInjections-Correlation-ID": correlation_id,
        "X-SecureInjections-Audit-ID": audit_ids[-1] if audit_ids else "none",
    }


def _error(message: str, code: str) -> dict[str, Any]:
    return {"error": {"message": message, "type": "secureinjections_policy_error", "code": code}}


def _correlation_id() -> str:
    return "proxy-run-" + uuid.uuid4().hex


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _elapsed(started: int) -> float:
    return (time.perf_counter_ns() - started) / 1_000_000


def _upstream_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Remove proxy-only trust metadata before forwarding the standard protocol request."""
    value = dict(payload)
    value["messages"] = [
        {key: item for key, item in message.items() if key != "metadata"}
        for message in payload["messages"]
    ]
    return value


def _validate_json_shape(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> None:
    remaining = budget if budget is not None else [2_000]
    remaining[0] -= 1
    if remaining[0] < 0 or depth > 12:
        raise ProxyProtocolError("structured value exceeds complexity limit")
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise ProxyProtocolError("structured object is too large")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 200:
                raise ProxyProtocolError("structured key is invalid")
            _validate_json_shape(child, depth=depth + 1, budget=remaining)
    elif isinstance(value, list):
        if len(value) > 256:
            raise ProxyProtocolError("structured array is too large")
        for child in value:
            _validate_json_shape(child, depth=depth + 1, budget=remaining)
    elif value is not None and not isinstance(value, (str, bool, int, float)):
        raise ProxyProtocolError("structured value contains an unsupported type")
