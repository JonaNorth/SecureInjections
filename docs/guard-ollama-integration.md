# Guarded local Ollama integration

SecureInjections can run a bounded local agent against an already-installed Ollama model. The local model is untrusted. Model refusal is not a security boundary, and model system prompts are not a security boundary. Only Guard and Gateway enforcement control protected side effects.

## Architecture and trust assumptions

The runtime path is:

```text
user -> Guard ingress -> LocalAgentModel -> action parser -> GuardedToolGateway
     -> local tool -> Guard post-tool/retrieval -> LocalAgentModel
     -> Guard egress -> user
```

Memory writes and external sends use dedicated Gateway boundaries. The external sink is simulated; this integration has no real outbound sink. The model receives text and JSON data, never registry capabilities, filesystem handles, callbacks, memory-store handles, or external-sink handles. Trusted application code performs capability lookup only after parsing, schema validation, and Guard approval.

`LocalAgentModel` is the transport-neutral interface. `OllamaAgentAdapter` is its first implementation. The Ollama transport accepts only plain HTTP loopback origins (`127.0.0.1`, `::1`, or `localhost`), disables environment proxies, refuses redirects, uses explicit timeouts, and bounds request and response sizes. It inventories local models through Ollama and never downloads a model or falls back to a cloud provider.

## Action protocol and bounded loop

Each model turn must contain exactly one JSON object with one of these actions:

- `FINAL_RESPONSE`
- `TOOL_CALL`
- `MEMORY_WRITE`
- `EXTERNAL_SEND`

The application parser rejects malformed JSON, multiple actions, unknown actions or tools, extra top-level fields, invalid tool arguments, and over-limit structures. The model-facing JSON schema improves reliability, but the application parser remains authoritative. Invalid output fails safely and executes nothing.

Default limits are six model turns, three tool calls, 64 KiB model responses, 64 KiB retrieved content, and 64 KiB tool output. A limit or transport failure stops the run safely. `REVIEW` and `BLOCK` both stop execution; there is no automatic approval path.

## Guarded boundaries

- User input is inspected before it reaches the model.
- `calculator`, `workspace_reader`, and `document_retriever` proposals pass pre-tool Guard before registry dispatch.
- Every tool result passes post-tool Guard. Retrieved documents also pass the retrieved-content boundary and are not forwarded on `REVIEW` or `BLOCK`.
- Structured memory writes pass `gateway.write_memory`; rejected records cannot change the store.
- Structured external proposals pass `gateway.send_external`; only the simulated sink exists.
- Final model text passes model-to-user egress inspection. Rejected raw text is not returned to the user.

The model instruction labels retrieved content and tool output as data and says Guard is authoritative. This is defense in depth, not the enforcement mechanism. SecureInjections does not claim control over arbitrary model behavior outside these instrumented boundaries.

## CLI

Ollama must be listening locally and the requested model must already be installed:

```console
secureinjections guard agent \
  --runtime ollama \
  --model qwen2.5:7b \
  --workspace-root tests/fixtures/gateway \
  --text "Use the calculator to add 8 and 13, then answer."

secureinjections guard evaluate-ollama \
  --model qwen2.5:7b \
  --workspace-root tests/fixtures/gateway \
  --output evaluation/guard-ollama-e2e.json
```

If Ollama or the selected local model is unavailable, the command returns a fail-closed `NOT_RUN` report. It does not pull a model.

## Evaluation methodology

The live suite contains 12 benign and 13 adversarial fixture scenarios. It records model/runtime identity, digest, generation settings, adapter and fixture versions, prompt/schema hashes, boundary decisions, side-effect deltas, and correlated audit IDs. Reports store fixture hashes rather than full prompts or model outputs. Model latency, transport overhead, end-to-end latency, and deterministic Guard/Gateway overhead are reported separately.

Adversarial outcomes are classified as `MODEL_CONTAINED`, `GUARD_CONTAINED`, or `UNSAFE_PASSED`. A model refusal is never credited to Guard. The live suite is supplemented by deterministic forced-unsafe-proposal tests so Guard authority is tested even when a model complies with its instructions.

The first live run exposed a structured persistent-memory bypass and is preserved as `evaluation/guard-ollama-e2e-initial-miss.json`. A narrow detector and regression test were added, and the identical suite was replayed into `evaluation/guard-ollama-e2e.json`. The history is retained rather than hiding the initial hard failure.

## Limitations

This is a local product-runtime integration, not classifier research or evidence generation. Model protocol adherence can still affect benign task completion. Guard rules can produce review decisions or false positives, and review currently stops rather than presenting an approval UI. The workspace tools are deliberately small, the external sink is simulated, and the integration does not protect capabilities or transports that an embedding application exposes outside the Gateway.
