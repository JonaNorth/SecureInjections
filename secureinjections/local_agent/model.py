"""Transport-neutral contracts for an untrusted local agent model."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class ModelMessage:
    role: str
    content: str

    def __post_init__(self) -> None:
        if self.role not in {"system", "user", "assistant", "tool"}:
            raise ValueError(f"unsupported model message role: {self.role}")
        if not isinstance(self.content, str):
            raise TypeError("model message content must be a string")

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass(frozen=True, slots=True)
class GenerationConfig:
    temperature: float = 0.0
    seed: int = 42
    max_tokens: int = 256

    def __post_init__(self) -> None:
        if not 0.0 <= self.temperature <= 2.0:
            raise ValueError("temperature must be between 0 and 2")
        if not 1 <= self.max_tokens <= 4_096:
            raise ValueError("max_tokens must be between 1 and 4096")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ModelIdentity:
    runtime: str
    runtime_version: str
    model_name: str
    model_tag: str
    model_digest: str
    adapter_version: str
    runtime_protocol: str = "native"
    endpoint_classification: str = "loopback"

    def to_dict(self) -> dict[str, str]:
        value = asdict(self)
        value["runtime_provider"] = self.runtime
        return value


@dataclass(frozen=True, slots=True)
class ModelResponse:
    content: str
    latency_ms: float
    model_duration_ms: float | None = None
    transport_overhead_ms: float | None = None


class LocalAgentModel(Protocol):
    @property
    def identity(self) -> ModelIdentity: ...

    @property
    def generation_config(self) -> GenerationConfig: ...

    def generate(
        self,
        messages: Sequence[ModelMessage],
        *,
        response_schema: Mapping[str, Any],
    ) -> ModelResponse: ...
