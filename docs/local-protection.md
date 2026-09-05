# SecureInjections Community local AI protection

SecureInjections is a local protection service for explicitly configured AI workflows. It does
not intercept system-wide network traffic. A surface is shown as **Active** only when the product
service can verify that its real enforcement path is running.

## Start the product

Community supports macOS on Apple Silicon. After the GitHub prerelease is published, download
its wheel and verify the release-note checksum. Install that wheel into an isolated `pipx`
environment; no source checkout or activated development virtual environment is required:

```console
pipx install '/path/to/secureinjections-0.6.0rc1-py3-none-any.whl[service]'
secureinjections doctor
secureinjections start
```

The primary command creates private safe defaults, starts the loopback service, and opens
`http://127.0.0.1:8000`. Stop cleanly with `Ctrl-C`. It owns and shuts down only Guard Proxy
processes started from this product session.

Check a running service without opening the UI:

```console
secureinjections status
```

Configuration, state, audits, cache, and working data live under
`~/Library/Application Support/SecureInjections/` in separate private directories. Reinstalling
the package does not replace that directory. Safe file references and process ownership remain
session-only; onboarding completion and privacy-bounded activity are persistent. A restart never
restores a stale Active claim and an old file reference fails closed.

The generated profile uses loopback-only endpoints, Guard Proxy ENFORCE mode, the validated
`qwen2.5:7b` Ollama model, no cloud provider, no raw-content logging, and narrow product-owned file
roots. SecureInjections never downloads Ollama or a model. `secureinjections doctor` reports missing
dependencies and port conflicts without changing third-party configuration.

The product accepts only explicit loopback hosts. Startup fails instead of falling back to
an external binding. On the Integrations page, **Start protection** starts a Guard Proxy owned by
that product-service process after checking its profile, ENFORCE mode, free port, and local model
upstream. The product stops only the instance it owns. Community intentionally exposes this
lifecycle through the product UI rather than its private development command tree.

Point a supported AI client at the protected endpoint shown in the product. This is an explicit
configuration step: SecureInjections does not rewrite Open WebUI, Ollama, application, or shell
settings. A listening port alone is never treated as SecureInjections; the service identity,
profile hash, and enforcement mode must match.

## Protected agent and file handoff

The generated installed profile enables the small guarded-agent workflow on the Protection and
Files pages. A benign file produces a host-held, session-scoped safe reference. **Use in agent** sends
only that opaque reference and the user's question; the backend resolves the original
SafeFileReader envelope and preserves its provenance through Gateway enforcement. The browser does
not upload the file again or decide that it is allowed.

References expire when the product restarts or when the bounded reference cache evicts them.
Forged, stale, REVIEW, and BLOCK references fail closed. REVIEW remains visible but cannot be
approved in this version because there is no suitable host-owned approval primitive yet.

## First run and recovery

The first-run UI explains scope, renders the same local doctor checks as the CLI, and allows an
optional integration to be skipped without claiming it is active. Completion is a UI preference,
not a capability or security decision. Invalid configuration, non-private files, corrupted
onboarding state, an unrelated port listener, or a second live instance fails safely with an
actionable status. SecureInjections never terminates an unidentified process.

Community has no automatic updater. Installing a newer wheel preserves the external product
directory; future incompatible state formats require an explicit migration path. Package, engine,
UI, policy/profile, integration compatibility, and evidence versions must be aligned before a
release candidate is prepared.

## Exact integration guidance

- **Guard Proxy + local Ollama** is the primary connectable traffic path. Start Ollama and an
  already-installed model first; SecureInjections does not download models.
- **Open WebUI** support remains exact to 0.11.0, with its native Ollama provider disabled,
  streaming off, and Base URL set to the displayed Guard Proxy `/v1` endpoint. The UI distinguishes
  an active proxy from verified Open WebUI configuration.
- **Native Ollama guarded agent** runs only through the configured product agent in the product
  UI; arbitrary Ollama clients are not implicitly protected.

## What the states mean

- **Active**: a real enforcement path is currently in use.
- **Available, not connected**: the protection exists, but no continuously routed integration was
  verified.
- **Attention required**: configured protection is reachable but not enforcing, or configuration
  could not be loaded safely.
- **Experimental**: outside the current supported product scope.

Native Ollama is protected during a guarded local-agent run. Reachability by itself does not make
that path active. Open WebUI support is limited to the validated 0.11.0, loopback, non-streaming
topology routed through Guard Proxy in enforce mode. Generic OpenAI-compatible local runtimes are
experimental.

## Privacy and authority

Activity is a bounded projection of real local decisions. It contains timestamps, surfaces,
decisions, safe reason codes, and audit references. It does not retain raw prompts, model output,
or file content. Dashboard state is read-only: UI fields cannot grant capabilities, change a Guard
decision, or authorize a tool, memory, agent, or external action.
