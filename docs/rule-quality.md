# Rule quality

A published community rule must pass schema and category validation, immutable ID uniqueness,
positive and negative examples, regex compilation/lint/length bounds, a pathological-input timing
check, and duplicate warnings. Corpus metrics add coverage, benign FPR, base recall, and seeded
mutation recall. Duplicate similarity is local and warning-only; rules are never auto-merged.

Avoid nested quantifiers, unbounded wildcards, generic security nouns, and patterns that treat
quoted research as execution intent. Python regex has no per-match timeout here, so narrow bounded
expressions and performance tests are mandatory. An optional safer backend should be adopted only
with measured safety and latency evidence.
