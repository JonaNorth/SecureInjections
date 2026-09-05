# SecureInjections Community v0.6.0-rc1 candidate claims

This is a non-published Community candidate prepared under Apache-2.0 with signed human rights
evidence recorded privately. Jonathan completed manual RC runtime validation against the Phase 5 candidate: PASS. Runtime validation
is carried forward because the documentation-corrected candidate preserves runtime/UI bytes and
passes clean rebuilt-artifact E2E. Publication requires a separate authorization.

| Capability | Candidate status | Boundary |
| --- | --- | --- |
| Deterministic Guard | Validated Level 1 | Best-effort detection; enforcement only at routed boundaries |
| Guarded Gateway | Validated Level 1 | Capabilities remain host-owned |
| Guard Proxy | Supported | Loopback, ENFORCE, non-streaming |
| Native Ollama guarded agent | Supported | `qwen2.5:7b`; guarded-agent runs only |
| Open WebUI | Supported exact | 0.11.0, streaming off, through Guard Proxy |
| Manual file inspection | Supported | One file at a time through SafeFileReader |
| Safe file handoff | Supported | Session-scoped host reference; ALLOW only |
| Activity | Supported basic | Bounded metadata; raw content withheld |
| Workspace/folder monitoring | Not included | Planned Pro Level 2 capability |

SecureInjections does not claim system-wide interception, universal prompt-injection prevention,
malware detection, protection for uninstrumented side effects, or support for arbitrary local AI
runtimes.
