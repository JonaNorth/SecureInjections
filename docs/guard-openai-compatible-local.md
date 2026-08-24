# OpenAI-compatible local API adapter

SecureInjections supports the small, common chat API shape implemented by several local model servers. “OpenAI-compatible local API” describes a wire protocol; it does not configure or call OpenAI cloud services.

The adapter is loopback-only, credential-free, and implemented behind the same `LocalAgentModel` interface as Ollama. Only model transport changes. Guard, Gateway, policy, tools, memory, the simulated external sink, egress inspection, and audit behavior are provider-independent.

## Supported protocol subset

The adapter supports:

- `GET /v1/models` when the server implements discovery;
- `POST /v1/chat/completions`;
- one non-streaming assistant choice;
- standard assistant text containing one strict SecureInjections JSON action; and
- one standard function `tool_call`, normalized into the canonical action protocol.

The canonical actions remain `FINAL_RESPONSE`, `TOOL_CALL`, `MEMORY_WRITE`, and `EXTERNAL_SEND`. Standard calls for `calculator`, `workspace_reader`, `document_retriever`, `memory_write`, and `external_send` are normalized into those actions and passed through the existing application parser. Vendor tool arguments never execute during parsing and are rejected if malformed, ambiguous, over-limit, unknown, or structurally invalid.

Streaming, authentication, API keys, OAuth, multimodal inputs, embeddings, remote RAG, arbitrary extensions, and cloud fallback are intentionally unsupported.

## Loopback security

The base URL must use plain HTTP, an explicit port, and exactly `127.0.0.1`, `::1`, or `localhost`. An optional `/v1` path is accepted. Public addresses, private LAN addresses, arbitrary hostnames, credentials/userinfo, query strings, fragments, other paths, and HTTPS endpoints are rejected.

Environment proxies are disabled for adapter requests. Redirects are refused rather than followed. Requests use explicit timeouts and bounded payloads/responses. The adapter does not read `OPENAI_API_KEY` or any equivalent credential, emit telemetry, download models, or contact a non-loopback host.

## Configuration and quick start

Start the local server yourself and configure the exact model it already serves. Then edit [secureinjections.openai-compatible-local.yaml](../examples/secureinjections.openai-compatible-local.yaml) with the local port and model identifier.

```console
secureinjections guard doctor \
  --config examples/secureinjections.openai-compatible-local.yaml

secureinjections guard demo-local-agent \
  --config examples/secureinjections.openai-compatible-local.yaml

secureinjections guard local-agent \
  --config examples/secureinjections.openai-compatible-local.yaml \
  --prompt "What is 2 + 3? Use the calculator."
```

Audit inspection is unchanged:

```console
secureinjections guard audit show gateway-run-... \
  --config examples/secureinjections.openai-compatible-local.yaml
```

The profile selects the adapter. No runtime-specific CLI branch is required.

## Doctor behavior

Doctor validates the profile, loopback URL, timeout and response limits, policy, audit and tool roots, endpoint reachability, model discovery, configured model, and a minimal structured chat-completions probe. The probe contains no user content.

If `/v1/models` returns an explicit “not implemented” response but the chat probe works, doctor reports `WARN`. A missing discoverable model, incompatible chat response, unreachable endpoint, redirect, or unsafe URL is a blocking `FAIL`. Doctor never starts a server, downloads a model, changes policy, or writes test memory.

## Security architecture

The local model receives messages and declarative function schemas—not Python callbacks, file handles, registry capabilities, memory objects, external sinks, or Guard execution internals. A proposal follows one path:

```text
local assistant response
  -> provider normalization
  -> canonical SecureInjections action
  -> strict parser and schema validation
  -> Guard/Gateway
  -> capability lookup and permitted execution
```

`REVIEW` and `BLOCK` stop execution. Tool output and retrieved content remain untrusted. Memory and external proposals keep their dedicated boundaries. The external sink remains simulated, and final model text still passes egress Guard.

## Protocol compatibility versus runtime validation

Automated compatibility uses a minimal deterministic loopback server implementing only the documented subset. It proves protocol handling without requiring LM Studio, llama.cpp, vLLM, Ollama, a model download, or internet access.

The live protocol smoke uses the already-installed Ollama model through Ollama’s OpenAI-compatible loopback endpoint when no independent server is available. That validates the transport and protocol path, but it is not evidence that an independent LM Studio, llama.cpp, or vLLM installation was tested.

Common local URL shapes include `http://127.0.0.1:1234/v1` for some LM Studio setups and `http://127.0.0.1:8000/v1` for some llama.cpp or vLLM setups. These are configuration examples, not runtime-specific validation claims. Server behavior varies, and only the documented subset is supported.

## Limitations

- No OpenAI cloud connectivity or credential management exists.
- Runtime-specific vendor extensions are not supported.
- Model digests may be unavailable when `/v1/models` does not expose one.
- Deterministic Guard can produce false reviews and is not perfect prompt-injection detection.
- Only operations routed through instrumented Guard/Gateway boundaries are protected.
- No production ML classifier or interactive approval UI is present.
