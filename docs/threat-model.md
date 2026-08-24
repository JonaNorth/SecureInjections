# Threat model

This threat model covers the v0.5.0-rc1 local deterministic Guard, Guarded Gateway, local model
adapters, OpenAI-compatible Guard Proxy, and validated Open WebUI 0.11.0 path.

## Assets

- System and developer instructions
- Credentials, secrets, tokens, and environment data
- Local files, retrieved documents, and resources
- Tool definitions and capability authority
- Memory and persistent state
- External data-transfer operations
- Model, agent, and third-party application integrity
- Audit integrity and privacy

## Trust boundaries

```text
user ------------------------> model
retrieved content -----------> model
tool output -----------------> model
model -----------------------> tool
model -----------------------> memory
model -----------------------> external destination
model -----------------------> user/client
third-party application -----> Guard Proxy -----> local model server
```

The Guard Proxy inspects client messages, tagged retrieved content, tool definitions, tool output,
assistant output, and model-generated tool calls crossing the protected HTTP path. It does not hold
application capability authority.

The Guarded Gateway separately mediates actual tool execution, memory writes, local resource
operations, and simulated/controlled external sends. The model receives descriptions and data but
does not receive filesystem handles, callbacks, registry objects, memory handles, a real network
sink, or a shell.

## Threat actors

- A malicious user supplying direct or obfuscated instructions
- A malicious or compromised retrieved document
- Poisoned output from an integrated tool
- A compromised, untrusted, or unexpectedly behaving local model
- A malicious model-generated tool call
- Malicious content supplied by a third party or upstream data source

## Threats and controls

| Threat | Primary control | Residual risk |
| --- | --- | --- |
| Direct instruction injection | Guard ingress inspection and enforce policy | Novel semantics may evade detection |
| Indirect/retrieval injection | Typed retrieved-content boundary | Untagged or bypassed retrieval is not protected |
| Tool-output poisoning | `tool_output -> model` inspection | Uninstrumented tool paths remain out of scope |
| Unsafe model tool call | Structured response validation and downstream Guard | Client-side bypass can still execute elsewhere |
| Memory poisoning | Gateway memory-write boundary | Other memory stores are not controlled |
| Credential/file access | Deterministic intent and path/secret controls | Detection is best effort |
| External exfiltration | Gateway external boundary and absent real sink in validated path | Proxy alone cannot govern unrelated egress |
| Protocol abuse | Closed schema, size limits, loopback URLs, no redirects | Host-level denial of service is not eliminated |
| Audit leakage | Hashes and bounded codes; raw logging off | Application logs outside SecureInjections may leak data |

## Assumptions

- The host operating system and local account boundary are trusted.
- The SecureInjections process, installed code, and dependencies are trusted.
- Configured Guard policies, rules, and profiles are reviewed and trusted.
- The attacker does not already control the SecureInjections process.
- Loopback isolation is meaningful in the deployment environment.
- Applications route the claimed traffic and capabilities through the documented boundary.

Loopback prevents remote network exposure by default, but it is not a local authentication layer.
Another process or user on the same host may still be able to connect, depending on operating-system
and application controls. SecureInjections v0.5.0-rc1 does not authenticate clients of its loopback
listeners; operators remain responsible for host and account isolation.

## Out of scope

- A compromised host OS or attacker with arbitrary code execution inside SecureInjections
- Side effects or model calls that completely bypass the instrumented Guard/Proxy/Gateway
- A malicious client performing direct unproxied operations
- Network-level protection outside the local process boundary
- Model-provider compromise outside the inspected protocol
- Browser-level extensions, uploads, retrieval, web search, or terminal features not validated
- Streaming proxy protection
- Perfect semantic detection or proof that content is safe or malicious
- Establishing the provenance or safety of separately installed model weights

## Security invariants

- In enforce mode, `REVIEW` and `BLOCK` do not cross the protected boundary.
- The Guarded Gateway alone authorizes its registered capabilities.
- Validated profiles are loopback-only and have no cloud fallback.
- Raw-content audit logging remains off.
- Dangerous or ambiguous security-critical configuration fails closed.

These invariants are covered by deterministic tests and finite integration evaluations. They do
not imply universal protection outside the stated boundary.
