# Rule databases

The bundled database is in `secureinjections/rules/v1/`. The directory name and each YAML
document's `version` field define the schema version. Scanner code contains scoring and safe
normalization logic; detection signatures and their descriptive metadata remain in rule files.

At startup, `load_rules()` parses trusted YAML with `safe_load`, validates required fields and rule
IDs, rejects duplicate IDs, compiles every expression, and then builds an immutable `RuleEngine`.
Invalid databases fail closed during initialization rather than silently dropping a rule.

An operator can deploy a separately versioned directory and select it with
`ScannerConfig(rule_paths=(Path("/path/to/rules/v1"),))`. This replaces the bundled set. Validate
the exact deployed directory with the CLI before restarting scanner processes.

## Threat Rule v1

SecureInjections 0.2 adds a strict one-rule-per-file format for separately maintained community and
commercial intelligence. The canonical JSON Schema is packaged at
`secureinjections/rules/schema/rule-v1.schema.json`; the Python validator additionally compiles
regexes, validates dates and engine versions, rejects duplicate IDs and symlinks, limits file size,
and enforces publication quality gates.

IDs use `SI-{NAMESPACE}-{SIX_DIGITS}`. Current namespaces are `PI`, `AGENT`, `SECRET`, `SSRF`,
`SHELL`, `SQL`, `TRAVERSAL`, and `NETWORK`. Published IDs are globally unique, never renamed, never
reused, and remain stable when a rule's content is tuned.

Published rules require positive `attack_patterns`, `negative_examples`, and references. Run
`rules validate`, `lint`, `test`, and `stats` before publication. A match against one malicious
example is not sufficient evidence for contribution.

## Severity and scoring

Default base weights are low 10, medium 25, high 45, and critical 70. Independent categories add
more risk than duplicate signatures in one category. The score is capped at 100. Default review
and block thresholds are 30 and 70. This is a prioritization model, not a probability.

## Regex safety

Python's standard regular-expression engine does not guarantee linear-time evaluation. Community
review should reject nested unbounded quantifiers and ambiguous repeated alternation. Keep inputs
bounded, benchmark new signatures against long near misses, and prefer explicit length limits.
