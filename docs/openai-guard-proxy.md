# OpenAI-compatible Guard Proxy

SecureInjections Guard Proxy v0.1 protects the OpenAI-compatible HTTP boundary between an existing local application and a local model server. The application changes its model `base_url`; it does not need to import SecureInjections or adopt the SecureInjections agent loop.

```text
existing local application
  -> http://127.0.0.1:8765/v1
  -> SecureInjections Guard Proxy
  -> configured loopback model endpoint
```

This is a local reverse proxy, not an OpenAI cloud client. It accepts no cloud credentials, performs no model download, and permits only loopback listeners and upstreams.

## Quick start

1. Start your already-installed local OpenAI-compatible model server.
2. Edit [secureinjections.proxy.yaml](../examples/secureinjections.proxy.yaml), including its upstream port and an already-installed `doctor_model` used only for the compatibility probe.
3. Run doctor:

   ```console
   secureinjections guard proxy-doctor \
     --config examples/secureinjections.proxy.yaml
   ```

4. Start the proxy:

   ```console
   secureinjections guard proxy \
     --config examples/secureinjections.proxy.yaml
   ```

5. Point the existing application at the proxy:

   ```console
   OPENAI_BASE_URL=http://127.0.0.1:8765/v1
   ```

   No cloud API key is required or consumed.

6. Send the application’s ordinary non-streaming `POST /v1/chat/completions` request. Proxy audit records are written beneath the configured audit directory.

The deterministic offline evaluation is available with:

```console
secureinjections guard evaluate-proxy \
  --config examples/secureinjections.proxy.yaml \
  --output evaluation/guard-proxy-evaluation.json
```

## Supported API

v0.1 supports only:

- `GET /v1/models`;
- `POST /v1/chat/completions`;
- one non-streaming completion choice;
- assistant text responses; and
- standard function `tool_calls` with bounded JSON-object arguments.

`stream=true` is rejected before upstream dispatch. Buffering a complete response is necessary because tool calls and final content must be inspected before any part reaches the client. Other endpoints, authentication, embeddings, multimodal requests, remote RAG, and vendor extensions are not supported.

## Protected boundaries

For client-to-model traffic, the proxy validates the request and inspects each message according to its role. User, tool, retrieved, and external content are untrusted. Assistant history is internal but untrusted for security-sensitive instructions. System and developer messages use the configured Guard policy’s system trust semantics.

All `role: tool` content is inspected as `tool_output -> model`. A poisoned result that produces `REVIEW` or `BLOCK` is not forwarded in enforce mode.

Clients may mark embedded untrusted material with this closed metadata convention:

```json
{
  "role": "user",
  "content": "retrieved text",
  "metadata": {
    "secureinjections_source": "retrieved_content"
  }
}
```

Allowed metadata sources are `retrieved_content`, `external`, and `tool_output`. Metadata cannot elevate content to trusted. Unknown keys, unknown values, or malformed metadata fail conservatively.

Function names, descriptions, and parameter schemas are treated as potentially untrusted external content. Tool-description or schema poisoning can therefore stop the request before it reaches the model.

For model-to-client traffic, assistant final text is inspected as `model -> user`. Every returned function call is structurally validated and inspected through Guard’s typed tool-call boundary. The proxy never executes a tool. If any response element is `REVIEW` or `BLOCK`, enforce mode rejects the entire protected response; it does not return a partially edited `200` response that a client might dispatch accidentally.

## HTTP enforcement

- `ALLOW`: the validated request is forwarded or the validated response is returned unchanged.
- `REVIEW`: enforce mode returns HTTP `409` with `secureinjections_review_required`.
- `BLOCK`: enforce mode returns HTTP `403` with `secureinjections_blocked`.
- malformed client input returns HTTP `400`; malformed or unavailable upstream behavior returns HTTP `502`.

Security errors use a bounded OpenAI-style `error` object and do not contain blocked excerpts or tool arguments. Responses include:

- `X-SecureInjections-Decision`;
- `X-SecureInjections-Audit-ID`; and
- `X-SecureInjections-Correlation-ID`.

Client request IDs are bounded and hashed for audit; SecureInjections always generates its own correlation ID.

## Enforce and observe modes

`guard.enforcement: enforce` is the default example and stops `REVIEW` and `BLOCK` traffic.

`guard.enforcement: observe` forwards traffic while recording the decision and returning observation headers. Audit records set `enforcement_disabled: true`, and doctor reports a prominent `WARN`. Observe mode is measurement only and is not secure enforcement.

## Network and resource security

The listener and upstream accept only `127.0.0.1`, `::1`, or `localhost`. Public binds, private LAN upstreams, arbitrary hostnames, userinfo, HTTPS, unsafe paths, redirects, and proxy-environment routing are rejected. Listener and upstream cannot be the same endpoint.

Profiles impose bounds on request and response bytes, message count and size, tool count, schema bytes, function-argument bytes, timeout, and concurrent handler count. Malformed or excessive traffic fails before protected content crosses the relevant boundary.

## Privacy and audit

Each request receives a correlation chain containing request acceptance, Guard boundary results, upstream-dispatch status, downstream results, final decision, HTTP result, timing, and record hashes. It binds the profile, policy, protocol, proxy version, request hash, response hash, and loopback upstream classification.

Raw prompts, model responses, tool arguments, API credentials, and client request IDs are not retained. Guard findings in the proxy audit are represented by closed finding/reason codes and hashes, not excerpts. Raw-content logging is fixed OFF in v0.1.

## Limits of the guarantee

Changing `base_url` protects only operations and content that cross this proxied model boundary. The proxy can prove that a blocked prompt or tool result did not reach its upstream and that a blocked final response or tool call did not reach its client.

It cannot prove that the client has no unrelated path to execute a capability. For authoritative control over tool execution, memory writes, and external side effects, use the SecureInjections Guarded Gateway integration or ensure model-generated tool calls cannot bypass the proxy.

The deterministic test server validates the documented wire subset. A live smoke through Ollama’s OpenAI-compatible endpoint validates that protocol path but is not independent LM Studio, llama.cpp, or vLLM validation.
