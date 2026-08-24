# Changelog

## v0.5.0-rc1 — 2026-08-24

First public-facing release candidate for the local deterministic enforcement product track.

### Product

- Added the typed deterministic Guard with `ALLOW`, `REVIEW`, and `BLOCK` decisions, policy
  enforcement, and privacy-preserving audit.
- Added the Guarded Agent/Tool Gateway for instrumented tool execution, local resources, memory,
  and simulated external sends.
- Added local Ollama and loopback OpenAI-compatible adapters, doctor commands, and runtime audit.
- Added the OpenAI-compatible Guard Proxy with request, tool-output, assistant-output, and
  model-generated tool-call inspection.
- Validated Open WebUI 0.11.0 through the proxy with streaming disabled.
- Added the one-command isolated Open WebUI integration smoke and static integration registry.

### Security

- Validated profiles reject non-loopback model endpoints and have no cloud fallback.
- Raw prompt, model-response, and tool-argument logging is off in validated paths.
- The product never downloads a model automatically and exposes no arbitrary shell capability.
- Tool outputs are inspected before model dispatch; model tool calls are inspected before client
  release.
- Gateway memory writes and simulated external actions require Guard authorization.

### Validation

- Guard/Gateway: 21/21 benign scenarios completed and 21/21 adversarial scenarios prevented.
- Live Ollama final run: 13/13 adversarial cases Guard-contained with zero unsafe passes.
- Preserved the initial Ollama persistence miss and verified the narrow regression fix.
- Open WebUI precision re-evaluation: 10/10 benign completed, zero false REVIEW/BLOCK.
- Packaged installed-wheel Open WebUI smoke: 5/5 passed, zero bypass, zero unsafe passes.

### Limitations

- This is a release candidate, not a stable or production-readiness declaration.
- Guard Proxy streaming is unsupported and rejected.
- The third-party validation claim is limited to Open WebUI exactly 0.11.0.
- Deterministic detection can miss attacks and can produce false positives.
- No production ML classifier is selected.
- The proxy cannot control side effects that bypass the proxied model boundary.
- Open WebUI 0.11.0 displays REVIEW and BLOCK with similar generic failure UX.

Research classifier and Evidence Factory work remains experimental and is not the lead product
claim. Machine evidence promotion remains disabled.
