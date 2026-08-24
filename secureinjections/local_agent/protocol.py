"""Strict application-side action protocol for untrusted model output."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ActionProtocolError(ValueError):
    pass


class ActionType(StrEnum):
    FINAL_RESPONSE = "FINAL_RESPONSE"
    TOOL_CALL = "TOOL_CALL"
    MEMORY_WRITE = "MEMORY_WRITE"
    EXTERNAL_SEND = "EXTERNAL_SEND"


@dataclass(frozen=True, slots=True)
class FinalResponseAction:
    action: ActionType
    response: str


@dataclass(frozen=True, slots=True)
class ToolCallAction:
    action: ActionType
    tool: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class MemoryWriteAction:
    action: ActionType
    memory: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ExternalSendAction:
    action: ActionType
    external: Mapping[str, Any]


AgentAction = FinalResponseAction | ToolCallAction | MemoryWriteAction | ExternalSendAction

ALLOWED_MODEL_TOOLS = frozenset({"calculator", "workspace_reader", "document_retriever"})
ACTION_PROTOCOL_VERSION = "local-agent-action-v0.1"

ACTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {"enum": [item.value for item in ActionType]},
        "response": {"type": "string"},
        "tool": {"enum": sorted(ALLOWED_MODEL_TOOLS)},
        "arguments": {"type": "object"},
        "memory": {"type": "object"},
        "external": {"type": "object"},
    },
    "required": ["action"],
    "additionalProperties": False,
}


def parse_action(
    content: str,
    *,
    max_bytes: int = 32_768,
    max_depth: int = 12,
    max_nodes: int = 2_000,
) -> AgentAction:
    if not isinstance(content, str):
        raise ActionProtocolError("model action must be text containing one JSON object")
    if len(content.encode("utf-8")) > max_bytes:
        raise ActionProtocolError("model action exceeds size limit")
    try:
        payload = json.loads(content)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ActionProtocolError("model action is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ActionProtocolError("model action must be one JSON object")
    _validate_shape(payload, depth=0, max_depth=max_depth, budget=[max_nodes])
    raw_action = payload.get("action")
    if not isinstance(raw_action, str):
        raise ActionProtocolError("unknown model action type")
    try:
        action = ActionType(raw_action)
    except (TypeError, ValueError) as exc:
        raise ActionProtocolError("unknown model action type") from exc
    if action is ActionType.FINAL_RESPONSE:
        _exact(payload, {"action", "response"})
        response = payload["response"]
        if not isinstance(response, str) or not response or len(response) > 16_384:
            raise ActionProtocolError("final response must be a bounded non-empty string")
        return FinalResponseAction(action, response)
    if action is ActionType.TOOL_CALL:
        _exact(payload, {"action", "tool", "arguments"})
        tool = payload["tool"]
        arguments = payload["arguments"]
        if not isinstance(tool, str) or tool not in ALLOWED_MODEL_TOOLS:
            raise ActionProtocolError("unknown or unavailable tool")
        if not isinstance(arguments, dict):
            raise ActionProtocolError("tool arguments must be an object")
        _validate_tool_arguments(tool, arguments)
        return ToolCallAction(action, tool, arguments)
    if action is ActionType.MEMORY_WRITE:
        _exact(payload, {"action", "memory"})
        memory = payload["memory"]
        if not isinstance(memory, dict):
            raise ActionProtocolError("memory must be an object")
        return MemoryWriteAction(action, memory)
    _exact(payload, {"action", "external"})
    external = payload["external"]
    if not isinstance(external, dict):
        raise ActionProtocolError("external transfer must be an object")
    return ExternalSendAction(action, external)


def _exact(payload: Mapping[str, Any], expected: set[str]) -> None:
    if set(payload) != expected:
        raise ActionProtocolError(f"action fields must be exactly {sorted(expected)}")


def _validate_tool_arguments(tool: str, arguments: Mapping[str, Any]) -> None:
    if tool == "calculator":
        _exact(arguments, {"operation", "left", "right"})
        if arguments["operation"] not in {"add", "multiply"}:
            raise ActionProtocolError("calculator operation must be add or multiply")
        if any(
            not isinstance(arguments[key], (int, float)) or isinstance(arguments[key], bool)
            for key in ("left", "right")
        ):
            raise ActionProtocolError("calculator operands must be numbers")
        return
    field = "path" if tool == "workspace_reader" else "document_id"
    _exact(arguments, {field})
    value = arguments[field]
    if not isinstance(value, str) or not value or len(value) > 500:
        raise ActionProtocolError(f"{tool} {field} must be a bounded string")


def _validate_shape(value: Any, *, depth: int, max_depth: int, budget: list[int]) -> None:
    budget[0] -= 1
    if budget[0] < 0:
        raise ActionProtocolError("model action exceeds node limit")
    if depth > max_depth:
        raise ActionProtocolError("model action exceeds nesting limit")
    if isinstance(value, dict):
        if len(value) > 256:
            raise ActionProtocolError("model action object is too large")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 200:
                raise ActionProtocolError("model action keys must be bounded strings")
            _validate_shape(child, depth=depth + 1, max_depth=max_depth, budget=budget)
    elif isinstance(value, list):
        if len(value) > 256:
            raise ActionProtocolError("model action array is too large")
        for child in value:
            _validate_shape(child, depth=depth + 1, max_depth=max_depth, budget=budget)
    elif value is not None and not isinstance(value, (str, bool, int, float)):
        raise ActionProtocolError("model action contains an unsupported value")
    elif isinstance(value, str) and len(value) > 16_384:
        raise ActionProtocolError("model action string is too large")
