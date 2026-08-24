"""Single composition point for supported local model providers."""

from __future__ import annotations

from .model import GenerationConfig, LocalAgentModel
from .ollama import OllamaAgentAdapter
from .openai_compatible import OpenAICompatibleLocalAgentAdapter


def create_local_agent_model(
    *,
    provider: str,
    host: str | None,
    base_url: str | None,
    model: str | None,
    timeout_seconds: float,
    max_response_bytes: int,
    generation_config: GenerationConfig | None = None,
) -> LocalAgentModel:
    if provider == "ollama":
        if host is None or base_url is not None:
            raise ValueError("Ollama runtime requires host and does not accept base_url")
        return OllamaAgentAdapter.connect(
            endpoint=host,
            model=model,
            timeout_seconds=timeout_seconds,
            generation_config=generation_config,
        )
    if provider == "openai_compatible_local":
        if base_url is None or host is not None or model is None:
            raise ValueError(
                "OpenAI-compatible local runtime requires base_url and an explicit model"
            )
        return OpenAICompatibleLocalAgentAdapter.connect(
            base_url=base_url,
            model=model,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            generation_config=generation_config,
        )
    raise ValueError(f"unsupported local runtime provider: {provider}")
