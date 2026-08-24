# Contributing to SecureInjections

Thank you for helping improve text-input security. Contributions should keep the core scanner
offline, deterministic-first, explainable, and safe for hostile input.

## Development setup

Python 3.11 or newer is required.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
ruff check . && ruff format --check . && mypy secureinjections
secureinjections release-gate --corpus corpus
```

Keep changes focused and add tests for expected detections and plausible false positives. Never
put a real credential, private key, customer payload, or other sensitive value in a fixture.

## Contributing rules

Bundled rules live as one-file Threat Rule v1 objects under
`secureinjections/rules/canonical/`. Community changes should be made in the independently
publishable `secureinjections-rules` repository. A minimal object looks like:

```yaml
schema_version: 1
id: SI-PI-000123
name: Concise human-readable name
description: What the signal means, without overstating certainty.
category: prompt_injection
taxonomy: PI.DIRECT
severity: medium
confidence: 0.8
indicator_strength: moderate
status: published
created: '2026-08-09'
updated: '2026-08-09'
author: Contributor name
license: Apache-2.0
attack_patterns: [Synthetic positive example]
regex_patterns: ['\bsuspicious\s+expression\b']
negative_examples: [Nearby benign example]
references: [https://authoritative.example/reference]
enabled: true
```

Rule IDs must be globally unique and namespaced. Severities are `low`, `medium`,
`high`, or `critical`. Patterns are Python regular expressions compiled case-insensitively with
dot matching newlines.

A rule pull request should include:

- a narrow signature with a clear category and rationale;
- positive tests, including encoded variants when relevant;
- benign near-miss regression tests;
- no captured or real-world secrets in code or discussion;
- an authoritative public reference when one exists;
- benchmark results if the change adds numerous or expensive patterns.

Avoid catastrophic-backtracking constructs, unbounded nested repetitions, overly broad keywords,
and signatures that turn normal prose into review traffic. `secureinjections rules validate` checks
schema and regex compilation; review still needs to assess safety and precision.

The deprecated aggregate legacy loader remains available only for migration. New intelligence
must use Threat Rule v1 in [`secureinjections-rules`](secureinjections-rules/). Its
published-rule gate requires globally namespaced immutable IDs, positive and negative examples,
references, confidence, lifecycle metadata, and corpus tests. Run `rules validate`, `lint`, `test`,
`quality-gate`, `find-duplicates`, `metrics`, and validation evaluation before submission.

## Interfaces

New integrations should depend on the public `Scanner`, `RuleEngine`, `SecretDetector`,
`SemanticDetector`, or `QuarantineBackend` contracts. Core scanning must not acquire a network,
database, framework, or model dependency. Framework integrations belong in optional extras.

## Pull requests

By submitting a contribution, you agree that it is licensed under Apache-2.0. Describe the risk
signal or behavior changed, tests performed, and any compatibility or performance impact.
