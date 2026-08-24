# Local Guard Profile v0.1

The Local Guard Profile is the first user-facing SecureInjections integration profile. It packages a transport-neutral local model adapter, deterministic Guard, guarded tool gateway, safe demo fixtures, and privacy-preserving audit records behind one configuration file. Supported providers are native Ollama and the separate loopback-only OpenAI-compatible local API adapter.

The local model is untrusted. It cannot directly invoke capabilities. Model refusal and the model system prompt are not security boundaries. `REVIEW` and `BLOCK` both stop an operation; only Guard/Gateway enforcement can authorize instrumented tools or side effects.

## Quick start

Install SecureInjections, install and start Ollama separately, and ensure the configured model already exists locally. SecureInjections never downloads a model.

```console
ollama list
secureinjections guard doctor --config examples/secureinjections.local.yaml
secureinjections guard demo-local-agent --config examples/secureinjections.local.yaml
secureinjections guard local-agent \
  --config examples/secureinjections.local.yaml \
  --prompt "What is 12 times 7? Use the calculator."
```

Standard input is also supported:

```console
echo "Summarize the ordinary document." | \
  secureinjections guard local-agent --config examples/secureinjections.local.yaml
```

The command prints a correlation ID. Inspect its audit chain without revealing raw prompts or model output:

```console
secureinjections guard audit show gateway-run-... \
  --config examples/secureinjections.local.yaml
```

All four commands support `--json`; agent and audit inspection also support `--verbose` for bounded local diagnostics. Verbose output adds decisions, reason codes, hashes, and finding types—not detector evidence or raw retained content.

## Configuration

The example profile is [secureinjections.local.yaml](../examples/secureinjections.local.yaml). It identifies `local-guard-profile-v0.1` through `profile.id` and `profile.version`, binds an Ollama loopback endpoint and optional explicit model, selects the Guard policy and audit path, applies agent limits, restricts enabled tools and filesystem roots, and controls guarded memory and the simulated external sink.

Configuration is closed and typed. Unknown fields, unknown tools, unsupported providers, non-loopback endpoints, real external networking, raw-content logging, unsafe filesystem roots, invalid policies, and impossible limits fail closed. Relative paths resolve against the configuration file. The canonical effective configuration is SHA-256 bound without timestamps.

If `runtime.model` is omitted, the existing deterministic adapter preference may select an already-installed chat model. Doctor warns when it chooses among multiple models. The selected name, tag, digest, and Ollama version are always reported and recorded.

## Doctor

`guard doctor` checks the package version, profile validity/hash, policy version/hash, audit-directory writability, workspace and retrieval roots, Ollama CLI, loopback service and version, installed models, selected model, external-network state, raw-content logging, and shell availability. It performs only loopback requests, does not start Ollama, does not write memory, and does not mutate policy. Blocking failures return a non-zero exit code with an actionable message.

## Architecture

```text
USER
  -> GUARD INGRESS
  -> LOCAL MODEL
  -> STRUCTURED ACTION PROPOSAL
  -> GUARD / GATEWAY
  -> TOOLS / GUARDED MEMORY / SIMULATED EXTERNAL
  -> POST-TOOL / RETRIEVAL GUARD
  -> LOCAL MODEL
  -> EGRESS GUARD
  -> USER
```

The model receives JSON and text data only. It receives no filesystem handles, registry capabilities, memory handles, arbitrary callbacks, real network sink, or shell. Enabled tools are limited to the profile's closed subset of `calculator`, `workspace_reader`, and `document_retriever`. Workspace reads are constrained to the configured root. Tool output and retrieved content remain untrusted and are inspected before model forwarding.

The demo's external sink is simulated and has no real outbound implementation. Memory writes are persisted only after the dedicated Guard boundary allows them. Raw prompt and model-response logging is disabled and unsupported in v0.1.

## Demo and audit

The one-command demo runs four benign model scenarios and four adversarial scenarios. Direct injection and poisoned retrieval use the real local model path. The unsafe external-transfer and memory-poisoning cases inject explicitly labeled deterministic proposal fixtures into the real Gateway so Guard authority is tested without coercing the model or fabricating model behavior.

Each result distinguishes `MODEL_CONTAINED`, `GUARD_CONTAINED`, and `UNSAFE_PASSED`. A Guard finding counts as containment only when enforcement stops the operation. Any `UNSAFE_PASSED` produces a prominent failed summary and a non-zero exit status.

Guard audit records contain timestamps, source/destination, decisions, reason codes, normalized content hashes, policy/detector bindings, and record hashes. Session records add the profile hash, model digest, adapter version, system-instruction/tool-schema hashes, start/end times, correlation ID, and outcome summary. Neither record type retains full prompts or model output.

## Security defaults and limitations

- Guard enforcement is always on.
- Raw-content audit logging, cloud fallback, telemetry, automatic model download, real external networking, and arbitrary shell execution are unavailable.
- Review and block decisions stop execution.
- External sends use only the simulated sink.
- The workspace and retrieval tools operate only inside configured roots.
- The deterministic Guard may produce false reviews.
- No production ML classifier has been selected.
- This is not a claim of perfect prompt-injection detection.
- Only operations routed through the instrumented Guard/Gateway boundaries are protected.
- No interactive user-approval UI is implemented.

Live adversarial testing found a structured persistence bypass. The original miss remains preserved in `evaluation/guard-ollama-e2e-initial-miss.json`; a narrow deterministic rule fixed it and the identical replay passed. The artifact is retained as regression evidence rather than rewritten history.
