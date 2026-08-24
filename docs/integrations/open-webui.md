# Open WebUI integration

**Status: VALIDATED — LIMITED LOCAL INTEGRATION**

SecureInjections was validated against Open WebUI 0.11.0 installed from PyPI as
`open-webui==0.11.0`. The validated path is:

```text
Open WebUI (loopback)
  -> SecureInjections Guard Proxy (http://127.0.0.1:8765/v1)
  -> Ollama OpenAI-compatible API (loopback)
  -> qwen2.5:7b
```

The integration uses supported Open WebUI configuration only. No Open WebUI
source, frontend bundle, request-generation code, package file, or database row
is patched.

## Requirements

- Open WebUI 0.11.0 in an isolated Python 3.11 environment
- Ollama listening on `127.0.0.1:11434` with `qwen2.5:7b` already installed
- SecureInjections installed in the current environment

Do not expose any local service beyond loopback. The validated proxy profile
uses enforcement mode and keeps raw-content logging off. The smoke command does
not install Open WebUI, download a model, call a cloud model API, or change an
existing Open WebUI installation or data directory.

## One-command validation

With Ollama running and the model already present, run:

```bash
secureinjections integrations open-webui smoke \
  --config examples/integrations/open-webui.yaml \
  --open-webui-executable /path/to/open-webui-0.11.0-venv/bin/open-webui
```

The executable override may be omitted when `open-webui` already resolves to an
isolated 0.11.0 environment. The command validates the thin integration profile,
Ollama inventory, proxy enforcement and privacy settings, and the Open WebUI
package RECORD. It allocates loopback ports, starts a fresh Open WebUI data
directory and task-owned Guard proxies, exercises five scenarios, writes
`evaluation/open-webui-integration-smoke.json`, and terminates only the processes
it started. An occupied configured port causes a safe failure; the occupying
process is never stopped.

The smoke uses Open WebUI's supported runtime configuration and backend API. It
does not configure an existing browser session, mutate Open WebUI's database, or
patch its Python or frontend files. If Open WebUI 0.11.0 is unavailable, the
command returns an actionable prerequisite failure and performs no installation.

The static support contract is available without third-party prerequisites:

```bash
secureinjections integrations list
secureinjections integrations open-webui status
```

The official smoke fails closed for any Open WebUI version other than exactly
0.11.0, public listeners, direct native Ollama routing, streaming, non-enforcing
proxy configuration, raw-content logging, cloud upstreams, missing audit
correlation, or incomplete request accounting.

## Smoke coverage and artifact

The smoke covers an ordinary benign question, quoted prompt-injection security
discussion, direct instruction override, poisoned `role=tool` content, and a
deterministic unsafe downstream `shell` proposal. The downstream fixture only
proposes a tool call; SecureInjections does not execute it.

The JSON artifact binds the integration, proxy, and Guard policy hashes; exact
Open WebUI and SecureInjections versions; Ollama version; model name and digest;
effective loopback ports; per-scenario decisions and audit correlations; bypass
accounting; package integrity; privacy; process ownership; cleanup; and safety
assertions. It contains no full prompts or raw model content.

## Start the proxy

For normal interactive use after the isolated smoke passes, prepare a proxy
profile whose upstream is the local Ollama OpenAI-compatible endpoint, then run:

```bash
secureinjections guard proxy-doctor --config examples/secureinjections.proxy.yaml
secureinjections guard proxy --config examples/secureinjections.proxy.yaml
```

The doctor must pass its listener, policy, upstream, redirect/proxy, and privacy
checks before Open WebUI is started.

## Configure Open WebUI

Use Open WebUI's supported OpenAI-compatible provider configuration:

```text
OpenAI API base URL: http://127.0.0.1:8765/v1
API key:             sk-secureinjections-local-test
Native Ollama API:   disabled
```

The placeholder key is not a credential. Disable the native Ollama provider so
the evaluated model cannot bypass SecureInjections. Also keep signup, web
search, code interpretation, image generation, community sharing, terminal
features, and external tools disabled unless they are separately assessed.

Select `qwen2.5:7b` from the models returned by the protected OpenAI-compatible
connection. Do not select a model from a direct Ollama connection.

The concise supported user flow is:

1. Start Ollama with the already-installed `qwen2.5:7b` model.
2. Provide an isolated Open WebUI 0.11.0 executable.
3. Run the one-command integration smoke and require `Result: PASS`.
4. Start the Guard Proxy for normal use.
5. Set Open WebUI's OpenAI-compatible URL to the proxy and disable native Ollama.
6. Set **Stream chat response** to **Off** in each new chat.
7. Select `qwen2.5:7b` and chat normally.
8. Use proxy audit correlation IDs when investigation is needed.

## Required non-streaming setting

Guard Proxy v0.1 intentionally rejects `stream=true`; it does not release
uninspected tokens. Open WebUI's default browser chat therefore fails with a
malformed-request message until streaming is disabled for that chat.

In each new chat, open:

```text
Controls -> Advanced settings -> Stream chat response -> Off
```

This is a supported Open WebUI model/chat parameter. In Open WebUI 0.11.0 the
choice is chat-scoped, so repeat it for each new chat. With it set to Off, both
the browser chat and `POST /api/chat/completions` use non-streaming JSON and are
compatible with the proxy. The resulting integration class is
`BASE_URL_PLUS_SUPPORTED_SETTINGS`.

## Behavior and audit lookup

Allowed non-streaming responses display normally. Each provider request has a
corresponding append-only proxy audit record containing a correlation ID,
request and response hashes, Guard boundary decisions, upstream-dispatch flag,
timings, and a record hash. Raw request or response content is not retained.

When Guard returns REVIEW, Open WebUI 0.11.0 displays the generic message
`Request blocked by SecureInjections security policy.` It does not distinguish
REVIEW from BLOCK. BLOCK uses the same understandable but generic message.
Default streaming failures appear as `Malformed OpenAI-compatible request.`

## Tool and retrieved-content boundaries

The supported Open WebUI application API was used to validate two protocol
boundaries without installing or executing a tool:

- A harmless calculator tool proposal from qwen2.5:7b passed downstream
  inspection and reached Open WebUI.
- A simulated poisoned `role=tool` result was blocked before Ollama dispatch.

A repository-owned deterministic OpenAI-compatible fixture also returned an
unsafe `shell` tool call. SecureInjections intercepted it downstream before
Open WebUI received it. This is deterministic fixture behavior, not observed
qwen2.5:7b behavior. UI-level tool execution and retrieval were not enabled.

## Validation result and limitations

Browser and backend/API protocol compatibility passed after the supported
per-chat streaming setting was disabled. The initial controlled ten-case benign
matrix completed 6/10: one quoted injection discussion was sent to REVIEW and
three security discussions were blocked by downstream credential-access false
positives.

The subsequent precision pass corrected those four specific context errors. A
rerun of the same ten benign scenarios completed 10/10 with zero false REVIEW
and zero false BLOCK. The changes distinguish explanatory quotations,
security discussion, and developer security guidance from operative attack
instructions; paired adversarial regressions preserve the corresponding attack
boundaries. This result supports a limited documented local rollout, not an
unrestricted or production-ready claim.

Of four adversarial user-input cases, three were stopped before Ollama and one
policy-replacement prompt reached qwen2.5:7b, which refused it safely. No unsafe
content crossed a boundary that SecureInjections was expected to enforce.

This validation applies only to Open WebUI 0.11.0. Streaming passthrough,
browser-level tool execution, retrieval, uploads, web search, Open Terminal,
arbitrary Python execution, cloud providers, and non-loopback deployment were
not enabled or validated.
