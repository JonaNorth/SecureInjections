# v0.5.0-rc1 release claims

| Claim | Status | Evidence | Limitation |
| --- | --- | --- | --- |
| Blocked Guarded Gateway operations do not execute | SUPPORTED | Gateway enforcement tests and 21-case adversarial evaluation | Only instrumented Gateway capabilities |
| Blocked proxy requests do not reach the upstream | SUPPORTED | Proxy audit/dispatch tests and smoke correlations | Only traffic routed through the proxy |
| Blocked model tool calls do not reach the client | SUPPORTED | Deterministic downstream fixture and proxy tests | Proxy does not control unrelated client paths |
| Open WebUI 0.11.0 integration | VALIDATED LIMITED | Precision pass and installed-wheel five-case smoke | Exact version, loopback, ENFORCE, stream off |
| OpenAI-compatible protocol portability | SUPPORTED AT PROTOCOL LEVEL | Deterministic server and Ollama endpoint tests | Not proof for every implementation |
| Ollama local runtime | VALIDATED LOCAL | Live local-agent and proxy evaluations | Tested model/runtime versions are finite |
| LM Studio compatibility | NOT VALIDATED | None | No public claim |
| vLLM compatibility | NOT VALIDATED | None | No public claim |
| llama.cpp compatibility | NOT VALIDATED | None | No public claim |
| Streaming proxy protection | NOT SUPPORTED | `stream=true` rejection tests | Non-streaming only |
| Raw-content-free validated audit | SUPPORTED | Privacy and audit regression tests | Application logs remain operator responsibility |
| Cloud inference protection | NOT VALIDATED | None | Validated profiles reject cloud endpoints |
| Production ML prompt-injection classifier | NOT AVAILABLE | Research decision | No model selected |
| Universal prompt-injection prevention | NOT CLAIMED | Detection is explicitly best effort | False negatives remain possible |
| Protection of side effects bypassing proxy | NOT PROVIDED | Boundary architecture | Integrate Gateway or another authority |
| Arbitrary shell execution | NOT PROVIDED | Closed Gateway registry | Host/application capabilities remain separate |

Future documentation and release notes must remain within this matrix unless new validation and a
reviewed claims update are completed.
