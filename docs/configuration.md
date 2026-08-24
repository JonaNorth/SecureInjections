# Public configuration reference

Public product profiles are closed, typed, and fail closed on unknown or malformed
security-critical values. Relative paths resolve from the profile file.

## Guard policy

`secureinjections/guard/default-policy.yaml` maps typed content boundaries and findings to
`ALLOW`, `REVIEW`, or `BLOCK`. The loaded policy is hash-bound in audit. Custom policy files are
trusted executable-adjacent configuration and require review.

## Local Guard Profile

`examples/secureinjections.local.yaml` configures:

- a loopback Ollama runtime and already-installed model;
- Guard policy, enforcement, and audit location;
- turn, response, retrieval, and tool-output limits;
- a closed tool subset and confined workspace/retrieval roots;
- guarded memory; and
- a simulated-only external destination.

Non-loopback runtimes, unknown tools, unsafe roots, real external sends, raw logging, and invalid
limits are rejected.

## OpenAI-compatible local profile

`examples/secureinjections.openai-compatible-local.yaml` uses the same Gateway contract with a
generic loopback OpenAI-compatible endpoint. It is protocol support, not independent validation of
every server implementation.

## Guard Proxy profile

`examples/secureinjections.proxy.yaml` defines the loopback listener and upstream, configured
model, ENFORCE policy, resource limits, raw-logging state, and audit directory.

`guard.enforcement: enforce` is the secure default. `observe` forwards traffic and is measurement
only; it must not be described as protection. `privacy.raw_content_logging` must remain `false` in
the validated v0.1 proxy.

## Open WebUI integration profile

`examples/integrations/open-webui.yaml` composes the proxy profile with the exact Open WebUI
version, ephemeral or configured loopback ports, isolated data-directory behavior, Ollama model,
timeout, and fixed smoke fixtures. The official smoke accepts only Open WebUI 0.11.0 and requires
streaming off.

Use doctors before runtime:

```bash
secureinjections guard doctor --config examples/secureinjections.local.yaml
secureinjections guard proxy-doctor --config examples/secureinjections.proxy.yaml
```
