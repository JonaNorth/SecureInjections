# SecureInjections

**A local runtime security boundary for supported AI coding-agent actions.**

SecureInjections adds an independent decision point between supported AI clients and two protected
workspace file operations. It runs on the user's Mac and applies `ALLOW`, `REVIEW`, or `BLOCK`
before an operation routed through its boundary continues.

> **Beta / pre-release:** The native macOS product is currently version `0.1.0`. A Developer ID
> signed, Apple-notarized, Gatekeeper-accepted DMG distribution path exists, but this repository
> does not announce a public download, beta enrollment, or stable release.

## What it protects today

The current protected MCP surface is exactly:

- `read_workspace_file`
- `write_workspace_file`

`ALLOW` lets an eligible operation proceed. `REVIEW` pauses the exact action for a decision in the
SecureInjections app. **Approve Once** is narrow, session-bound, and single-use. `BLOCK` stops the
operation and cannot be overridden through the AI client.

SecureInjections controls these operations at runtime through its Gateway. It does not treat model
instructions, MCP metadata, client configuration, or routing preferences as authority.

## Supported clients

The native beta supports local MCP integration with:

- Cursor
- Claude Code
- Codex CLI
- Codex Desktop's local task/workspace surface

Codex Desktop and Codex CLI share one local Codex MCP registration. Codex Desktop support does not
include ordinary hosted ChatGPT chats, ChatGPT web, or Business/Work MCP configuration. Tool
selection remains model-driven where a client has no deterministic routing control, and support
does not imply compatibility with every client version or feature.

## How it works

1. **Choose a workspace.** The native host retains the macOS authorization for that workspace.
2. **Connect a supported client.** SecureInjections registers a bundled local stdio bridge; no
   workspace authority or runtime bearer token is stored in client configuration.
3. **Use the client normally.** Supported routed reads and writes pass through the authenticated
   local Gateway and receive an ALLOW, REVIEW, or BLOCK decision.

```text
Supported AI client
  → bundled stdio bridge
  → private same-user broker
  → authenticated loopback MCP Gateway
  → host-held workspace authorization
  → Guard and bounded file implementation
```

Processing and REVIEW handling occur locally. SecureInjections has no product telemetry or
SecureInjections-operated cloud service in the current native runtime. Third-party AI clients may
send data to their own providers under their own settings and policies; see [PRIVACY.md](PRIVACY.md).

## Install and onboarding

For an authorized beta build:

1. Open the SecureInjections DMG.
2. Drag SecureInjections to Applications and open it normally.
3. Choose the workspace to protect and start the MCP Gateway.
4. Set up each detected supported client you use.
5. Return to the AI client and ask for ordinary workspace file work. SecureInjections appears when
   REVIEW is required.

The native macOS beta is not currently distributed publicly from this repository.
Installation guidance will accompany authorized beta builds.

## Current limitations

SecureInjections protects only operations routed through its two supported workspace tools.
Supported clients currently retain native readers, editors, patch tools, shell commands, or
terminal capabilities that can bypass this boundary.

SecureInjections is therefore **not**:

- whole-Mac protection or system-wide interception;
- guaranteed prevention of every prompt injection;
- enforced confinement of native client filesystem or shell access;
- universal MCP compatibility; or
- current protection for network/egress, browser, GitHub, email, or arbitrary third-party tools.

Filesystem enforcement using macOS Endpoint Security is being researched, and the required Apple
entitlement request is pending review. It is not included in the current product and will not be
claimed until both entitlement approval and technical feasibility are proven.

Read the complete [security boundary and limitations](SECURITY.md).

## Distribution trust

The customer distribution path produces a Developer ID signed, Apple-notarized, and
Gatekeeper-accepted application and DMG. Notarization means Apple's automated notary service
accepted the submitted signed artifact. It is not Apple App Review, an endorsement, or a security
certification.

No customer DMG, GitHub Release, or public download is published by this README.

## Roadmap direction

Future capability work is expected to proceed in this order, subject to feasibility:

1. Filesystem enforcement for supported clients
2. Shell/process capability protection
3. Network and egress controls
4. Broader MCP capability protection

No delivery dates are promised, and roadmap items are not current features.

## Repository tracks and versions

SecureInjections currently has two distinct product tracks:

- **Native macOS product:** version `0.1.0`, currently under private development as a beta /
  pre-release product. Its proprietary implementation is not included in this public repository.
- **Community package candidate:** Python package version `0.6.0rc1`, sourced from
  [`pyproject.toml`](pyproject.toml), retained as a separate technical candidate and evaluation
  track.

Version numbers are not interchangeable. Neither version implies that a GitHub Release or public
package has been published.

The Community track includes the deterministic Guard, capability-separated Gateway, loopback
Guard Proxy, manual inspection, local Ollama evaluation path, and supporting security research.
Its detailed validation and setup material remains under [`docs/`](docs/).

## Development

This public repository contains the Community Python implementation, security research, and
supporting validation material. Start with [docs/validation.md](docs/validation.md).

Do not use real credentials, customer prompts, or private workspace contents in bug reports or
fixtures.

## Privacy and security

- [Native product privacy baseline](PRIVACY.md)
- [Security policy, boundary, and limitations](SECURITY.md)
- [Threat model](docs/threat-model.md)

Report vulnerabilities using the private security-advisory process described in
[SECURITY.md](SECURITY.md), not a public issue.

## License scope

The prepared Community release boundary is under Apache-2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE). The notice defines the scoped Community grant. It does not automatically extend
that grant to private Pro-only or excluded research source.
