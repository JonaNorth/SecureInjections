# Evaluation

`secureinjections evaluate` reports overall precision, recall, F1, FPR, FNR, the
ALLOW/REVIEW/BLOCK confusion matrix, per-category rates, and results by language, difficulty, and
source type. It measures deterministic-only and, when explicitly configured, combined local
semantic behavior. JSON is the default; `--format markdown --output report.md` produces a release
artifact.

Development cases are visible to rule authors. Validation is used for thresholds and release
gates. Holdout is never used for tuning; holdout reports redact case IDs. Generated mutations are
evaluated separately unless `--include-generated` is requested. This policy is procedural as well
as technical: maintainers must not inspect holdout failures while editing rules.

```bash
secureinjections evaluate --corpus corpus --split validation
secureinjections evaluate --corpus corpus --split holdout --output holdout.json
```

Evaluation is a reproducible estimate over a synthetic corpus, not proof of real-world detection.

## Classifier evaluation

Classifier corpora use concept, template, paraphrase, and source-family provenance. Transitive
groups stay within one TRAIN, VALIDATION, or DEVELOPMENT-HOLDOUT split. Before training,
`secureinjections classifier audit` reports exact, normalized, and high-similarity duplicate
candidates and fails cross-split leakage. Split reports include samples, groups, families, labels,
and every supported language.

Temperature and ALLOW/REVIEW/BLOCK boundaries are calibrated on VALIDATION only. The classifier
evaluator reports recall, benign FPR, precision, F1, macro family F1, per-language/family metrics,
the family confusion matrix, inference p50/p95/p99, model size, and load time. With
`--routing-experiments`, it also reports deterministic-only and combined metrics, contribution
counters, and separate stage latency for all four routing policies.

Leave-language-out runs train without one language and evaluate on that language where validation
size permits. A DEVELOPMENT SHADOW set must use unseen conceptual groups. The final Blind Set E is
created and revealed only after the engine, classifier, corpus, thresholds, and generators freeze.
