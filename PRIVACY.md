# SecureInjections privacy

This document describes the current SecureInjections native macOS application. It is a product
privacy baseline, not a final lawyer-reviewed privacy policy.

## Local processing

SecureInjections processes protected workspace file operations locally on the Mac. When a
supported client routes a request through SecureInjections, the bundled bridge connects to a
same-user credential broker and an authenticated MCP Gateway on loopback. File inspection,
policy decisions, REVIEW handling, and approved file writes run locally.

The optional Connected Protection runtime also listens on loopback and connects only to its
configured loopback Ollama-compatible model endpoint. The current native runtime has no
SecureInjections-operated cloud service and implements no product telemetry or analytics.

File contents, prompts, and tool inputs can exist in process memory while an operation is being
inspected or completed. They are not retained in the normal Activity or audit records described
below.

## Data stored on the Mac

SecureInjections stores private application state under:

```text
~/Library/Application Support/SecureInjections/Pro/
```

Depending on the features used, this can include:

- the selected workspace's absolute path, filesystem identity, and monitoring preference;
- an opaque macOS security-scoped bookmark created from the user's folder selection;
- schema-bounded Activity and audit metadata, including timestamps, relative paths or filenames,
  decisions, reason or finding codes, action and correlation identifiers, byte counts, and
  cryptographic content or record hashes; and
- local lifecycle metadata needed to validate the configured runtime.

The main workspace Activity snapshot retains at most 100 entries and 1 MiB; oldest entries are
removed first. MCP and Guard JSONL audit files contain bounded fields but are append-only, and the
current native app does not automatically rotate or delete them. Private state directories and
files are created with restrictive same-user permissions. Historical metadata describes past
activity and is never accepted as current workspace authority.

Enabling **Start at Login** also creates the normal macOS login-item registration managed by the
operating system.

## Data deliberately not retained

The normal native privacy-bounded paths do not persist:

- raw prompts or model responses;
- raw file contents or matched secret values;
- full MCP tool request bodies or results;
- API keys, Apple credentials, or third-party account passwords;
- MCP bearer tokens or broker credentials;
- pending REVIEW payloads or Approve Once authority;
- runtime session IDs, live file descriptors, or workspace capabilities; or
- pagination cursors or ephemeral safe-file references.

MCP connection credentials are created for the running Gateway and held in memory. Gateway Stop
or app Quit invalidates them. If a user explicitly chooses the diagnostic **Copy Connection**
action, an ephemeral connection value is placed on the macOS clipboard; ordinary client setup
does not require this action.

Cryptographic hashes and filenames or relative paths can still be sensitive metadata. Anyone with
access to the Mac account and application-support files should treat them accordingly.

## Supported client setup changes

SecureInjections changes only the integration records needed for the client the user chooses to
set up, while preserving unrelated configuration:

- **Cursor:** opens Cursor's MCP installation flow for a named local stdio server; Cursor requires
  confirmation and stores the resulting registration in its local configuration.
- **Claude Code:** creates or updates the named local MCP server in `~/.claude.json`, enables its
  small two-tool server for loading, and adds exact allow entries for the two SecureInjections MCP
  tools in `~/.claude/settings.json`.
- **Codex Desktop and Codex CLI:** share one named local MCP registration in
  `~/.codex/config.toml`; setup limits the server to the two SecureInjections tools and configures
  exact per-tool approval behavior where the installed Codex version supports it.

These records contain the local bridge command, bundled bridge paths, server and tool names, and
the narrow client-side approval or loading settings. They do not contain the selected workspace
path, a runtime bearer token, file contents, prompts, or Apple credentials.

## Third-party AI services

SecureInjections privacy behavior is separate from Cursor, Anthropic, and OpenAI privacy
behavior. A supported AI client may send prompts, workspace context, file contents, diagnostics,
or account data to its own provider under that provider's settings and policies. SecureInjections
does not operate those services and does not claim that configuring its MCP tools prevents a
client from using its own native filesystem, shell, network, or cloud capabilities.

Review each AI client's data controls before using it with sensitive material.

## Developer ID, notarization, and Gatekeeper

The customer application and DMG are Developer ID signed, Apple notarized, and Gatekeeper
accepted. Developer ID identifies the signing developer, and notarization records acceptance by
Apple's automated notary service for the submitted artifact. These checks are not Apple App
Review, a privacy audit, a security certification, or an endorsement by Apple.

## Before a public legal privacy policy

A public legal privacy policy still requires confirmed business and operational information,
including the legal entity name, business address, privacy contact, governing jurisdiction,
website and download hosting providers, payment processor, analytics or support providers if
introduced, and applicable retention or deletion obligations. This document does not invent those
details or claim GDPR or CCPA compliance.
