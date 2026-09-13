# SecureInjections launch copy baseline

This is reusable product copy for a future website or native-product README. It describes the
current product and is not a public release authorization.

## Positioning

SecureInjections is a local runtime security boundary for supported AI coding-agent actions.

## Hero

### Put a local decision boundary between AI agents and workspace files

SecureInjections works with your existing AI coding clients to inspect supported file operations,
pause meaningful actions for review, and block disallowed actions before they execute through its
protected tools.

## Benefits

- **Local-first processing:** workspace inspection, decisions, and REVIEW handling run on your Mac.
- **Use your existing clients:** configure Cursor, Claude Code, Codex CLI, or Codex Desktop in
  minutes, then use ordinary file prompts.
- **Runtime action control:** SecureInjections applies ALLOW, REVIEW, or BLOCK at its protected
  file-operation boundary rather than relying only on prompt scanning.
- **Focused human review:** Approve Once authorizes one exact reviewed action, not a reusable
  client permission.
- **Independent local layer:** one host-held boundary provides the same two protected workspace
  tools across multiple supported AI vendors.

## How it works

1. Choose the workspace you want SecureInjections to protect.
2. Start the local MCP Gateway and set up the supported AI clients you use.
3. Work normally; supported routed reads and writes are allowed, reviewed, or blocked locally.

## Supported clients

SecureInjections currently supports Cursor, Claude Code, Codex CLI, and the local Codex Desktop
task/workspace surface on macOS. Client versions and tool selection behavior can change, so support
means the documented integration—not universal compatibility with every client feature or hosted
chat surface.

## Current limitations

The protected surface is currently limited to `read_workspace_file` and
`write_workspace_file`. Client-native filesystem and shell capabilities can bypass that boundary.
SecureInjections is not whole-Mac protection, system-wide interception, or perfect prompt-injection
prevention. Network, browser, GitHub, email, and generic MCP protection are not currently shipped.
Filesystem enforcement through macOS Endpoint Security is research in progress, not a current
feature.

## Distribution trust wording

Use: **Developer ID signed, Apple notarized, and Gatekeeper accepted.**

Do not describe notarization as Apple approval, endorsement, security certification, or App
Review. It means Apple's automated notary service accepted the signed submitted artifact.

## Internal readiness note

The Endpoint Security entitlement request is pending Apple review. Production filesystem
enforcement must not be advertised until the entitlement is approved and the client-by-client
technical feasibility work passes.
