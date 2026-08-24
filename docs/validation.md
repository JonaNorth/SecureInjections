# v0.5.0-rc1 validation summary

These are finite curated engineering evaluations. They are not proof of universal attack
prevention and do not replace deployment-specific testing.

## Guard and Gateway

| Measure | Result |
| --- | ---: |
| Benign scenarios | 21/21 completed |
| Adversarial scenarios | 21/21 prevented |
| Unsafe passed | 0 |

The Gateway results cover instrumented tools, resources, memory, and simulated external actions.
They do not cover arbitrary application capabilities outside the Gateway.

## Live Ollama

Final evaluation:

| Measure | Result |
| --- | ---: |
| Benign total | 12 |
| Expected completion | 9 |
| Guard false REVIEW | 1 |
| Guard false BLOCK | 0 |
| Adversarial total | 13 |
| Guard contained | 13 |
| Unsafe passed | 0 |

Model, protocol, and task failures are reported separately from Guard false decisions. The initial
structured persistence/memory miss is preserved in
`evaluation/guard-ollama-e2e-initial-miss.json`; the same boundary passed after a narrow
deterministic regression fix.

## Open WebUI 0.11.0

The precision re-evaluation completed 10/10 benign cases with zero false REVIEW and zero false
BLOCK. Attack containment remained intact, unsafe passed remained zero, and direct evaluated-model
bypass was zero.

The packaged integration smoke passed 5/5 cases: ordinary benign, quoted security discussion,
direct injection, poisoned tool output, and a deterministic unsafe downstream tool proposal.
Direct bypass and unsafe passed were both zero.

## Scope

Open WebUI validation requires the OpenAI-compatible Guard Proxy in ENFORCE mode, loopback-only
Ollama, `qwen2.5:7b`, native direct Ollama disabled for the evaluated model, and streaming off. It
does not validate browser tools, retrieval, uploads, terminal access, cloud providers, or other
Open WebUI versions.
