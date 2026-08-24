# Guarded Agent/Tool Gateway v0.1

The Guarded Agent/Tool Gateway is the first concrete runtime integration of SecureInjections Guard.
It places deterministic enforcement on every security-relevant boundary of a local tool-using agent
workflow:

```text
user -> Guard ingress -> planner
     -> Guard retrieved-content boundary
     -> Guard pre-tool -> local tool -> Guard post-tool
     -> Guard memory / simulated-external boundary
     -> final result
```

The integration is fully offline. The evaluation planner is deterministic and inspectable; it is
not represented as an AI model. Guard enforcement is real, while unsafe external and command side
effects are simulated or absent. No production ML classifier, reviewer, evidence consensus, or
network service participates in a decision.

## Gateway API

`GuardedToolGateway` centralizes protected operations:

```python
from pathlib import Path

from secureinjections.gateway import GuardedToolGateway, LocalToolRegistry
from secureinjections.guard import Guard

registry = LocalToolRegistry(
    Path("local-agent-sandbox"),
    documents={"guide": "Local documentation fixture."},
)
gateway = GuardedToolGateway(Guard(audit_path="var/guard-audit.jsonl"), registry)

workflow_id = gateway.new_workflow_id()
ingress = gateway.inspect_user_input("Add two values.", workflow_id=workflow_id)
tool = gateway.dispatch_tool_call(
    "calculator",
    {"operation": "add", "left": 2, "right": 3},
    workflow_id=workflow_id,
)
chain = gateway.reconstruct_audit_chain(workflow_id)
```

The public boundary methods are:

- `inspect_user_input`: `user -> model` ingress;
- `inspect_retrieved_content`: untrusted retrieved content before planning;
- `dispatch_tool_call`: structured pre-tool inspection, dispatch, and mandatory post-tool inspection;
- `process_tool_output`: standalone untrusted tool-output inspection;
- `write_memory`: inspection before structured memory storage;
- `send_external`: inspection before the simulated external sink;
- `reconstruct_audit_chain`: ordered workflow-level audit correlation.

Each returns a `GatewayResult` with `PROCEEDED`, `REVIEW_REQUIRED`, or `BLOCKED`, its boundary stage,
a safe Guard summary, operation metadata, execution/side-effect flags, and correlated audit IDs.
`BLOCKED` and `REVIEW_REQUIRED` never execute the protected operation.

User-facing serialization intentionally excludes detector evidence and content. It returns stable
reason codes and safe messages such as “Operation blocked by security policy.” Detailed bounded
evidence remains in the authorized Guard audit.

## Protected boundaries

### Ingress and retrieval

User input is inspected as `user -> model`. Retrieved content is inspected separately as
`retrieved_content -> model`, so embedded instructions cannot inherit application or tool trust.
The guarded workflow stops before calling the planner on rejected ingress, and stops before using
rejected retrieved content.

### Tool calls and outputs

Every structured call passes `Guard.inspect_tool_call` before registry dispatch. An allowed call is
executed by the local registry, after which the result always passes `Guard.inspect_tool_output`.
Tool output remains untrusted. A blocked output is not returned as ordinary planner context, even
though the harmless local retrieval needed to obtain it has already occurred.

### Memory

`write_memory` renders bounded JSON-like fields into deterministic inspection input before touching
the store. Persistent role overrides, future-approval bypasses, durable exfiltration instructions,
and other behavior-changing records are blocked. An allowed structured preference is stored only
after `ALLOW`.

### External transfer

`send_external` inspects the destination and structured transfer content before reaching the sink.
The MVP sink only records an allowed simulated transfer; it contains no network implementation.
Sensitive or exfiltrating transfers do not reach even that simulated sink.

## Local tool registry

`LocalToolRegistry` contains harmless deterministic tools:

- `calculator`: numeric `add` and `multiply` only;
- `workspace_reader`: UTF-8 files under one dedicated root;
- `document_retriever`: immutable local fixture documents;
- structured memory storage, reachable only through the gateway capability;
- a simulated external sink, also reachable only through the gateway capability.

The workspace reader resolves the requested path and independently rejects anything outside its
configured root, including traversal. This remains necessary even when Guard flags the proposed
path: text inspection does not replace resource authorization.

The registry has no public dispatch, memory-write, or external-send method. Its internal operations
require an identity capability owned by the gateway. The guarded workflow receives only the
gateway, never the registry or capability, keeping protected operations behind a small explicit
surface.

There is no shell tool, arbitrary command execution, `eval`, `exec`, dynamic import, or outbound
HTTP client.

## Deterministic workflow and future adapters

`GuardedAgentWorkflow` accepts an `AgentPlanner` protocol. The bundled `FixturePlanner` returns an
explicit `AgentPlan` containing retrieved content, proposed tool calls, an optional memory write,
an optional external send, and a final response. It exists to exercise enforcement without making
claims about model behavior.

A real local LLM or agent can replace `FixturePlanner` by implementing `plan(user_content) ->
AgentPlan`. The adapter must remain untrusted and must not receive direct registry, memory, or sink
access. All retrieved context, proposed calls, tool output, memory writes, and external transfers
must continue through the gateway. Guard remains authoritative regardless of what the planner
proposes.

## Audit correlation and privacy

Every workflow receives a `gateway-run-*` correlation ID, used as the Guard request ID at each
boundary. `reconstruct_audit_chain` returns ordered, content-free events containing stage, audit ID,
status, decision, reason codes, and operation type. A multi-tool workflow therefore reconstructs:

```text
ingress audit -> retrieval audit(s) -> pre-tool audit -> post-tool audit
              -> memory audit -> external audit
```

The gateway does not log raw content. Guard audit defaults remain unchanged: raw retention is off,
sensitive excerpts are redacted, metadata values are omitted, and records are append-only and
hash-bound.

## Evaluation methodology

Run the complete offline integration evaluation with:

```bash
secureinjections guard evaluate-integration \
  --workspace-root tests/fixtures/gateway \
  --output evaluation/guard-agent-e2e.json
```

The report contains at least 20 benign and 20 adversarial end-to-end scenarios, per-scenario
decisions, baseline would-dispatch behavior, actual guarded dispatch behavior, boundary catches,
side-effect counters, audit completeness, and local overhead measurements.

The counterfactual baseline never calls the registry. It records that the unsafe operation would
have been dispatched without Guard, while performing no command, resource, memory, external, or
network side effect. An attack counts as successful only if the guarded workflow actually lets the
unsafe operation cross its protected boundary; a finding alone is not counted as prevention.

The curated cases are product regression fixtures, not research evidence, human validation, or
classifier-quality evaluation. They do not use Blind Set E.

## Limitations

- Deterministic detection cannot recognize every possible natural-language attack.
- The registry capability and Python encapsulation reduce accidental bypass; they are not an OS
  sandbox against hostile in-process Python code.
- The fixture planner does not measure real-model behavior or latency.
- The external sink proves boundary enforcement but does not implement a production connector.
- Deployments still need authentication, authorization, process isolation, least privilege,
  filesystem controls, egress policy, and safe output handling.
- A real agent adapter must never treat `REVIEW_REQUIRED` as permission to continue automatically.
