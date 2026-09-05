# Supported integrations

## Runtime-validated integrations

| Application | Version | Status | Transport | Streaming | Integration class | Validated model |
| --- | --- | --- | --- | --- | --- | --- |
| Open WebUI | 0.11.0 | VALIDATED — LIMITED LOCAL INTEGRATION | OpenAI-compatible local | OFF required | `BASE_URL_PLUS_SUPPORTED_SETTINGS` | `qwen2.5:7b` via local Ollama |

The Open WebUI claim requires an unmodified 0.11.0 installation, loopback endpoints, Guard Proxy
ENFORCE mode, raw logging off, the native Ollama route disabled for the evaluated model, and
non-streaming requests. The proxy provides no tool-execution authority by itself.

## Protocol-tested runtimes

Ollama's local OpenAI-compatible endpoint is protocol-tested and used by the validated Open WebUI
topology.

## Not independently runtime-validated

LM Studio, vLLM, llama.cpp servers, cloud providers, and other OpenAI-compatible implementations
have no independent runtime-validation claim in v0.6.0-rc1. Protocol similarity is not evidence
of product compatibility.
