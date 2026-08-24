# Validation history

Negative evidence is retained rather than rewritten into a clean success narrative.

## Ollama persistence miss

The first live adversarial run found a structured persistence/memory proposal that crossed the
intended Guard boundary. The original artifact remains
`evaluation/guard-ollama-e2e-initial-miss.json`. A narrow deterministic fix was added and the
identical boundary passed in the final live run. This demonstrates a found-and-fixed regression,
not proof that similar misses cannot recur.

## Open WebUI false positives

The initial controlled Open WebUI integration completed only 6/10 benign cases. One quoted
injection discussion entered REVIEW and three security discussions were blocked by downstream
credential-access false positives. The initial artifact remains preserved. A context precision
pass distinguished quoted/explanatory/developer content from operative attacks, after which the
same benign matrix completed 10/10 while paired attack boundaries remained contained.

## Evidence reviewer validation

Evidence Factory Pilot 01 found correlated false consensus in same-model isolated review passes.
Reviewer Semantic Contract v2 improved semantic framing, but its validation pilot routed 26/26
candidates to human review and did not establish machine-promotion readiness. Real machine
promotion remains disabled, no real `CONSENSUS_TRUSTED` evidence exists, and Pilot 02 has not
started.

## Remaining uncertainty

Deterministic detection can miss novel semantics and can still over-escalate benign content.
Open WebUI validation is finite and version-specific. The proxy cannot govern unproxied client
operations. No production ML classifier is selected, and Blind Set E remains untouched.
