# Security policy

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

## Supported security claims

SecureInjections v0.5.0-rc1 is a release candidate. Its validated product path is local,
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

Signed threat-feed installation verifies the Ed25519 key, canonical manifest, artifact hashes,
engine compatibility, archive safety, and downgrade rules before atomic activation. Optional local
semantic/classifier artifacts are explicit operator-supplied dependencies; remote model loading
and remote code are disabled.

Application owners remain responsible for authentication, authorization, sandboxing,
parameterized queries, output encoding, least privilege, secret management, egress controls,
dependency security, and safe logging. See the [threat model](docs/threat-model.md) and
[release claims matrix](docs/release-claims-v0.5.0-rc1.md).
