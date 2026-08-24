# Evidence Factory reviewer semantic contracts

Evidence Factory review records use an explicit semantic-contract version. Historical schema-v1
records without a `reviewer_contract_version` field are contract v1. This preserves the exact
prompt, configuration, response, and review hashes used by Evidence Factory Pilot 01. Contract v2
records use schema version 2 and include `reviewer_contract_version`, `reviewer_contract_hash`, and
the bounded trusted-comparison set and its hash.

Pilot 01 remains **B. AUTO-PROMOTION REMAINS DISABLED — REVIEWER QUALITY ISSUE**. Contract v2 was
introduced because isolated passes using the same model family produced correlated false consensus
on classifier family and semantic independence. Reviewer isolation remains mandatory, but isolation
does not make the judgments statistically independent. Contract v2 is infrastructure and regression
coverage, not production validation or Pilot 02 approval.

## Ordered semantic review

Contract v2 requires each isolated reviewer to determine, in order:

1. semantic context;
2. primary action;
3. primary target;
4. primary security effect;
5. benign or malicious intent;
6. classifier family under the precedence rules;
7. relationship to the bounded trusted-concept comparison set;
8. semantic independence;
9. privacy and usage rights.

The response stores the structured context, action, target, effect, delivery mechanism, family
selection basis, trusted-concept relationships, independence basis, and affirmative novelty
dimensions. These fields are included in canonical response and review hashes.

## Benign-family contract

`BENIGN_DEVELOPER_CONTENT` is for legitimate implementation, coding, configuration, build,
deployment, operational-hardening, and engineering instructions. `BENIGN_SECURITY_DISCUSSION` is
for descriptive vulnerability explanation, threat analysis, incident reporting, research summary,
and conceptual mitigation discussion. Security terminology alone does not select security
discussion; the candidate's primary communicative function controls.

For example, “Configure the worker to verify signed packages before loading them” is developer
content. “The bulletin explains how unsigned packages weaken distribution integrity” is security
discussion. These are synthetic contract examples and are not trusted evidence.

## Attack-family precedence

Target and security effect take precedence over delivery mechanism:

- Authentication tokens, credentials, API keys, session material, or authorization secrets select
  `ATTACK_CREDENTIAL_ACCESS`, including when a metadata service is the access mechanism.
- Metadata selects `ATTACK_METADATA_ACCESS` only when metadata itself is the primary target and
  credential acquisition does not dominate.
- Unauthorized sensitive-data transfer selects `ATTACK_EXFILTRATION`.
- Explicit command, code, process, or tool execution selects `ATTACK_TOOL_EXECUTION`; exploiting
  application syntax alone does not.
- Filesystem or resource traversal/access selects `ATTACK_PATH_ACCESS`.
- Dependency, build, package, CI/CD, or distribution-integrity compromise selects
  `ATTACK_SUPPLY_CHAIN`.
- Embedded instructions in retrieved or intermediary content select `ATTACK_INDIRECT_INJECTION`
  when no more specific target/effect dominates.
- Direct crafted interpretation-changing input selects `ATTACK_DIRECT_INJECTION` when no more
  specific target/effect dominates.

The closed taxonomy is unchanged.

## Semantic independence

Contract v2 treats independence as an affirmative claim. `INDEPENDENT` requires a bounded,
hash-bound comparison against every supplied relevant trusted concept, a `DISTINCT` relationship,
and evidence of a materially different action, target, or security effect. A different source,
wording, syntax, or example—and the absence of an exact duplicate—cannot establish independence.

`NOT_INDEPENDENT` requires a same-concept, paraphrase, translation, or template-sibling
relationship. `UNCERTAIN` is mandatory when relevant comparison evidence is absent, insufficient,
close, or conflicting. Uncertainty continues to route to human review under the unchanged strict
promotion policy.

Review commands opt into the new contract explicitly and provide zero or more local trusted
corpora:

```bash
secureinjections classifier evidence review-auto \
  --input evidence/raw-candidates.jsonl \
  --responses evidence/provider-a-v2.jsonl \
  --reviewer-pass A --reviewer-id model:reviewer-a \
  --reviewer-contract v2 \
  --trusted-corpus evidence/current-human-trusted.jsonl \
  --output evidence/review-a-v2.jsonl
```

No network or new model is used for the comparison envelope. It contains at most five nearest
trusted concepts and records identifiers, grouping metadata, lexical similarity, and a bounded text
excerpt so the relationship decision remains auditable. If the available envelope cannot support
novelty, the response must use `UNCERTAIN` rather than guessing `INDEPENDENT`.

## Relationship-consensus contracts

Reviewer semantic contracts and relationship-consensus contracts are separately versioned.
`relationship-consensus-v1` is the historical behavior: it requires exact equality of
`proposed_concept_id`, `paraphrase_relationship`, `translation_relationship`, and
`template_family`. It remains the default so historical Evidence Factory Pilot 01 and Reviewer v2
Validation Pilot 01 outputs are exactly reproducible.

`relationship-consensus-v2` is opt-in. It compares canonical structured semantics and immutable
trusted concept IDs. Its consensus-critical fields are:

- trusted concept ID supplied by the deterministic comparison envelope;
- closed relationship type (`DISTINCT`, `SAME_CONCEPT`, `PARAPHRASE`, `TRANSLATION`,
  `TEMPLATE_SIBLING`, or `UNCERTAIN`);
- semantic context;
- primary target;
- primary security effect;
- delivery mechanism;
- classifier family;
- semantic independence and affirmative novelty evidence.

Reviewer-authored action prose, proposed concept/display names, paraphrase and translation display
labels, free-form template names, summaries, bases, and rationales remain hash-bound audit fields.
They are not authoritative consensus IDs. A novel candidate receives a deterministic concept ID
derived outside the reviewer prompts from stable candidate identity and canonical semantic fields.
Template identity is likewise derived from canonical context, target, effect, mechanism, and
family. No fuzzy matching, edit distance, arbitrary string normalization, or embeddings are used to
reconcile display names.

The v2 contract hash is
`0d8abc4a8a3e5a0eb9eaa2cfb92d9e59d7a127e107e2e534da1358a328c6e011`.
Every v2 consensus decision and audit records the version and hash. Historical records without an
explicit relationship-consensus version are v1. Mixed v1/v2 decision streams are rejected by the
promotion boundary.

### Compatibility matrix

The matrix is symmetric. `NI` below means any of `SAME_CONCEPT`, `PARAPHRASE`, `TRANSLATION`, or
`TEMPLATE_SIBLING`.

| Reviewer A | Reviewer B | Result |
| --- | --- | --- |
| `DISTINCT` | `DISTINCT` | `EXACT_AGREEMENT` |
| same NI subtype | same NI subtype | `EXACT_AGREEMENT` |
| one NI subtype | another NI subtype | `COMPATIBLE_NON_INDEPENDENT` |
| `DISTINCT` | any NI subtype | `MATERIAL_DISAGREEMENT` |
| `UNCERTAIN` | anything | `UNCERTAIN` |

Compatible non-independent subtypes can establish the conservative binary conclusion that a
candidate is not independent; they do not make a duplicate eligible for promotion. A derivative
relationship found by only one reviewer is `TRUSTED_CONCEPT_RELATIONSHIP_CONFLICT`. Conflicting
independence decisions are `INDEPENDENCE_DISAGREEMENT`. Canonical context, target, effect, or
mechanism conflicts are `MATERIAL_RELATIONSHIP_DISAGREEMENT`. Uncertainty always fails closed.
Harmless display-name differences produce `STRUCTURED_RELATIONSHIP_AGREEMENT` in audit output and
do not become queue reasons.

Machine-consensus `INDEPENDENT` still requires both reviewers to supply affirmative novelty,
complete relationship evidence for their bounded comparison sets, only compatible `DISTINCT`
relationships, no deterministic concept collision, no unresolved conflict, and every existing
deterministic promotion gate. Different nearest-neighbor ordering or different bounded sets do not
create disagreement when every observed relationship is `DISTINCT` and both reviewers meet those
affirmative requirements.

Example opt-in consensus command:

```bash
secureinjections classifier evidence consensus \
  --relationship-consensus v2 \
  --candidates evidence/raw-candidates.jsonl \
  --review-a evidence/review-a-v2.jsonl \
  --review-b evidence/review-b-v2.jsonl \
  --policy policies/classifier-evidence-trust-policy.yaml \
  --trusted-corpus evidence/current-human-trusted.jsonl \
  --output evidence/structured-consensus.jsonl \
  --human-queue-output evidence/structured-human-queue.jsonl \
  --audit evidence/structured-consensus-audit.json
```

## Counterfactual replay scope

The finalized 26-candidate Reviewer v2 Validation Pilot 01 review pairs may be replayed through the
new consensus contract without rerunning either reviewer. Such a replay is diagnostic and
non-mutating. It does not rewrite the final Decision D, validate Reviewer v2, create trusted
evidence, justify machine promotion, or approve Pilot 02. In particular, any replay eligibility for
historical audited case 7 must remain visible because both reviewers selected
`ATTACK_PATH_ACCESS` while the human audit selected `ATTACK_TOOL_EXECUTION`.

Machine promotion remains disabled. Historical Evidence Factory Pilot 01 and Reviewer v2
Validation Pilot 01 artifacts remain unchanged.
