# Security policy

## Native macOS product security boundary

SecureInjections is a local runtime security boundary for supported AI-agent actions. Its current
protected MCP surface is exactly:

- `read_workspace_file`
- `write_workspace_file`

When a supported client routes one of these operations through SecureInjections, the native host
holds the selected workspace authority and the Gateway applies an `ALLOW`, `REVIEW`, or `BLOCK`
decision before the protected operation continues. A REVIEW decision waits for a decision in the
SecureInjections app. **Approve Once** is bound to the exact action, workspace, resource, and
runtime session and is single-use. Stop, Quit, timeout, denial, session replacement, or relevant
restart invalidates it. A BLOCK decision cannot be overridden through the AI client.

The current supported client integrations are Cursor, Claude Code, Codex CLI, and the local Codex
Desktop task/workspace surface. Codex Desktop support does not imply support for ordinary hosted
ChatGPT chats, ChatGPT web, or Business/Work MCP configuration. Tool selection remains
model-driven where a client provides no deterministic routing mechanism.

Client setup, tool descriptions, prompts, and approval preferences help route an operation. They
are not filesystem authority. The selected workspace, macOS authorization, Gateway capability,
and exact REVIEW decision remain host-controlled.

### Current limitations

SecureInjections currently protects only operations routed through its two supported workspace
file tools. Supported clients retain alternate capabilities that may bypass this boundary,
including native file readers and editors, patch tools, and shell or terminal commands.

SecureInjections therefore does **not** currently provide:

- whole-Mac protection or system-wide interception;
- guaranteed prevention of every prompt injection, false positive, or false negative;
- universal MCP-client or third-party-tool compatibility;
- enforced confinement of client-native filesystem or shell access;
- network or arbitrary egress control;
- browser, GitHub, or email action protection; or
- generic protection for arbitrary MCP servers and tools.

macOS Endpoint Security filesystem enforcement is being researched, and the required entitlement
request is pending Apple review. It is not present in the shipped product and must not be claimed
until Apple approval and technical feasibility—including safe client process separation—are both
proven.

The customer build is Developer ID signed, Apple notarized, and Gatekeeper accepted. Notarization
means Apple's automated notary service accepted the submitted signed artifact. It does not mean
Apple approved, audited, certified, or endorsed SecureInjections or its security claims.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could put users at immediate risk. Use
GitHub's private security-advisory reporting flow for this repository. Include the affected
version, impact, a minimal reproduction using synthetic data, and any suggested mitigation. Never
include real credentials, private data, or customer prompts.

Maintainers should acknowledge a report within seven days. Validation, remediation, and
coordinated-disclosure timing depends on severity and reproducibility.

**Publication prerequisite:** a human maintainer must verify that GitHub private vulnerability
reporting is enabled for the public repository before publishing this release. Repository-local
configuration cannot prove that hosted setting is active, and this document does not claim that it
is enabled.

## Community candidate security claims

The private SecureInjections Community v0.6.0-rc1 candidate has a local,
loopback-only, non-streaming, deterministic-first enforcement for instrumented LLM and agent
boundaries. Detection and enforcement are distinct.

### Guaranteed by architecture and enforcement

When the documented configuration and instrumented boundary are used:

- `REVIEW` and `BLOCK` operations do not execute through the unattended Guarded Gateway.
- A blocked or review-required proxy request is not forwarded to the configured model upstream.
- Blocked `role=tool` content is not forwarded to the model.
- Blocked model-generated tool calls and assistant output are not returned to the proxy client.
- The proxy never executes a tool.
- Raw prompts, model responses, and tool arguments are not retained in validated audit paths.
- Validated local profiles reject non-loopback model endpoints and have no cloud fallback.
- Arbitrary shell execution is not a capability in the validated product path.
- The model receives structured data, not Gateway capability objects.
- Closed, security-critical configuration rejects unknown or malformed fields.

These claims apply only at boundaries actually routed through SecureInjections. The Guard Proxy
controls model HTTP traffic; the Guarded Gateway controls application side effects only when it is
integrated as the capability authority.

### Best-effort detection

The deterministic detectors make finite, testable attempts to identify prompt and indirect
instruction injection, credential and secret access, exfiltration intent, tool-schema and
tool-output poisoning, persistence and memory poisoning, and operative versus quoted,
explanatory, or developer-security context.

Detection is not perfect. `ALLOW` does not certify safety, and `BLOCK` does not prove malicious
intent. False negatives and false positives remain possible.

## Claims not made

SecureInjections does not claim to prevent all prompt injection, make LLMs secure, guarantee no
data exfiltration, protect side effects that bypass its boundaries, validate cloud providers,
provide network perimeter controls, or establish a local model's provenance. No production ML
prompt-injection classifier is selected in this release candidate.

## Security failure behavior

In unattended Guard/Gateway execution, both `REVIEW` and `BLOCK` stop the operation. For the Guard
Proxy in enforce mode, `REVIEW` returns HTTP 409 and `BLOCK` returns HTTP 403. Open WebUI 0.11.0
currently renders both with similar generic failure UX; this does not change enforcement.

Malformed security-critical profiles and protected protocol objects fail closed. Observe mode is
explicit measurement-only behavior and is not secure enforcement.

## Trusted configuration and supply chain

The host OS, SecureInjections process and code, configured policies, and explicitly selected local
runtime artifacts are trusted assumptions. Rule files are executable-adjacent configuration
because they contain regular expressions. Deploy only reviewed, authenticated policies and rules.

The Community candidate excludes the private research/classifier stack and research-oriented
threat-feed distribution tooling. It does not download remote detector models or execute remote
code.

Application owners remain responsible for authentication, authorization, sandboxing,
parameterized queries, output encoding, least privilege, secret management, egress controls,
dependency security, and safe logging. See the [threat model](docs/threat-model.md) and
[candidate claims matrix](docs/release-claims-v0.6.0-rc1.md).
