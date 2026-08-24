# Classifier corpus contract (schema v2)

Classifier data is UTF-8 JSONL validated by `secureinjections.classifier_data`. The machine-readable
contract is [`classifier-corpus-schema-v2.json`](../secureinjections/classifier-corpus-schema-v2.json).
Legacy detector corpora are research material only: they are neither classifier-ready nor trusted
until a human reviews provenance, usage basis, labels, grouping, and lineage.

```json
{
  "schema_version": 2,
  "case_id": "unique-case-id",
  "text": "case text",
  "binary_label": "benign",
  "classifier_family": "BENIGN_SECURITY_DISCUSSION",
  "language": "en",
  "attack_family": "hard-negative-security-education",
  "concept_id": "reviewed-concept-id",
  "template_family": "reviewed-template-id",
  "paraphrase_group": "reviewed-paraphrase-origin-id",
  "source_family": "licensed-source-collection",
  "generation_method": "human authored and reviewed",
  "authorship": "human-authored",
  "provenance_reference": "repository:path-or-source-record",
  "license_or_usage_basis": "Apache-2.0",
  "review_status": "REVIEWED",
  "split": "validation",
  "difficulty": "hard",
  "hard_negative_category": "security-education",
  "translation_group": null,
  "parent_case_id": null
}
```

Unknown values are explicit `null` values where the schema permits them. Trust states are
`VERIFIED`, `REVIEWED`, `PROVISIONAL`, `QUARANTINED`, and `REJECTED`; only the first two may enter
training or evaluation. Machine-derived grouping suggestions must stay provisional and may be
recorded as `derived_concept_candidate`, never silently copied into a trusted `concept_id`.

Grouped splitting unions concept, template, paraphrase, translation, and parent/child generation
lineage before assigning a split deterministically. A trusted row missing concept, paraphrase, or
source-family metadata fails closed. The leakage audit separately reports exact, normalized,
structural-marker-stripped, near-duplicate, grouping, source-family, lineage, and conflicting-label
signals. A development shadow must exist and have no concept, template, paraphrase, translation,
or generation-lineage overlap with development data.

Before any local-model bake-off, the readiness gate additionally requires complete trusted
provenance, trusted hard negatives, all 11 supported languages, at least ten malicious and ten
benign trusted concepts per language, clean grouped validation, and an independent development
shadow. Training refuses a corpus unless the gate passes.

Base models must independently satisfy the [offline model import contract](offline-model-import.md)
before the training command will accept them. Model presence in a cache is not sufficient.

## Human review workflow

v0.4.2 keeps machine suggestions and human decisions in separate artifacts. A human decision is
an append-only JSONL record conforming to `evaluation/v0.4.2-review-schema.json`. It must identify
the reviewer as `human:<id>`, include a timezone-aware timestamp, and bind to both the exact text
SHA-256 and canonical source-metadata SHA-256. `APPROVE` records also require explicit accepted
provenance and usage basis plus complete classifier/grouping metadata. No heuristic, queue status,
or machine suggestion can create `REVIEWED` data.

```bash
# Export deterministic concept-oriented review units. Use --mode hard-negatives for that queue.
secureinjections classifier review export \
  --legacy-corpus corpus/benign.jsonl \
  --queue evaluation/v0.4.1-human-review-queue.jsonl \
  --plan evaluation/review-plan.json --output local-review-export.jsonl

# Preferred for repeated review: local interactive mode resumes at the first unresolved case,
# recognizes active decisions, paginates large clusters, previews every write, and calls the same
# canonical validator/appender as `review decide`. Import and promotion are never automatic.
secureinjections classifier review interactive \
  --export local-review-export.jsonl \
  --decisions local-human-decisions.jsonl \
  --history local-review-history.jsonl \
  --reuse-audit local-metadata-reuse-audit.jsonl \
  --reviewer human:YOUR-STABLE-ID

# The explicit non-interactive path remains available for automation and integrity inspection.
# 1. Inspect any unit; changing the index supports forward/back navigation and later resume.
secureinjections classifier review show --export local-review-export.jsonl --index 0

# 2. Preview one explicit human choice. The exact schema-valid record is printed, but the
# decisions file is not created or changed. --case-id is required for a multi-case unit.
secureinjections classifier review decide \
  --export local-review-export.jsonl --index 0 --case-id CASE-ID-FROM-UNIT \
  --decisions local-human-decisions.jsonl \
  --decision DEFER --reviewer human:YOUR-STABLE-ID --dry-run

# 3. If DEFER was genuinely the human choice, repeat without --dry-run to append it. For APPROVE,
# explicitly supply every trusted label/grouping/provenance/usage field shown by --help. Machine
# suggestions remain untrusted unless the human supplies the matching --accept-provisional-* flag.
secureinjections classifier review decide \
  --export local-review-export.jsonl --index 0 --case-id CASE-ID-FROM-UNIT \
  --decisions local-human-decisions.jsonl \
  --decision DEFER --reviewer human:YOUR-STABLE-ID

# 4. Repeat show -> decide --dry-run -> decide for each case actually reviewed. The command locks,
# validates, and appends one record; it never edits review history or truncates the decisions file.

# 5. Import completed decisions into append-only history. Import is atomic and rejects unknown
# case IDs, stale hashes, conflicting active decisions, and reused IDs with changed content.
# Exactly identical records already present in history are safely counted and skipped, allowing
# an accumulated append-only decisions file to be imported after later interactive sessions.
secureinjections classifier review import \
  --legacy-corpus corpus/benign.jsonl \
  --decisions local-human-decisions.jsonl \
  --history local-review-history.jsonl --audit local-review-audit.json

# 6. Inspect the review import audit before promotion.
python -m json.tool local-review-audit.json

# 7. Promotion revalidates hashes and policy; non-approved decisions remain historical only.
secureinjections classifier review promote \
  --legacy-corpus corpus/benign.jsonl \
  --history local-review-history.jsonl \
  --output trusted-corpus.jsonl --manifest trusted-manifest.json

# 8. If promotion produced a non-empty corpus, run its leakage/readiness audit. A small pilot is
# expected to remain not ready and must not be random-split or used for training.
secureinjections classifier audit \
  --corpus trusted-corpus.jsonl --output corpus-readiness.json
```

Review exports can contain corpus text and should remain local unless deliberately selected for
repository review. A later decision may name `supersedes_review_id`; the earlier line remains in
history. `SPLIT` and `MERGE` grouping actions are human decisions represented by the approved group
IDs and cause all downstream hashes to change. Interactive approval never applies to sibling cases:
each selected case still receives its own exact-content and metadata-hash-bound decision record.
Ctrl+C, EOF, declining the write preview, and exiting with `X` leave the unfinished case unchanged.

When an unresolved case has an active, imported, promotable `APPROVE` sibling in the same review
unit, interactive approval offers an explicit default-no reuse step. Only concept, paraphrase,
translation, template, source-family, and generation-method values are reusable. Binary and
classifier labels, language, authorship, provenance, usage basis, hard-negative category,
difficulty, grouping action, target pool, disposition, hashes, and final confirmation remain
case-specific. Conflicting trusted siblings disable reuse. Accepted reuse is traced in a separate
append-only audit record bound to the new decision review ID and current case hashes.

To inventory existing material without promoting it:

```bash
secureinjections classifier foundation \
  --legacy-corpus corpus/benign.jsonl \
  --legacy-corpus corpus/malicious.jsonl \
  --output evaluation \
  --summary evaluation/v0.4.1-foundation-run.json
```

This is offline, accepts only explicit input paths, emits a human-review queue and manifests, and
returns a non-zero status while the corpus is not ready.

## Provisional offline research training

`research-train` is deliberately separate from production classifier training. It accepts only an
explicit frozen local model, an expected freeze hash, trusted gold, and an explicit untrusted pool.
Model loading and inference run with sockets blocked; the resulting binary head is marked
research-only and is bound to the base-model, gold-corpus, grouped-split, and configuration hashes.

```bash
secureinjections classifier research-train \
  --model /absolute/path/to/frozen-model \
  --expected-freeze-hash SHA256 \
  --gold /absolute/path/to/trusted-gold.jsonl \
  --pool /absolute/path/to/untrusted-review-export.jsonl \
  --artifact /absolute/path/to/separate-research-artifact \
  --output evaluation
```

The command never promotes score outputs or pseudo-labels and never selects a production model.
`research-score` can rescore a corrected explicit pool without retraining, but first revalidates all
artifact, gold, split, base-model, and training-configuration bindings. Neither command accepts a
development shadow or Blind Set input.

For small follow-up runs, `--minimum-validation-concepts-per-class 4` enables a deterministic
class-balanced grouped split while preserving every concept/paraphrase/translation/template/lineage
union. `--sampling-strategy seeded-shuffle` pairs ordinary deterministic shuffling with the existing
weighted cross-entropy loss; this avoids simultaneously applying inverse-frequency sampling and
inverse-frequency loss weighting. Both choices become part of the training-configuration hash.
`research-compare` records exploratory deltas against a prior local research report without changing
either model artifact.

Research scoring also applies a stop-labeling gate. A next review batch is suppressed when validation
still shows one-class collapse, unacceptable benign FPR, narrow scores around `0.5`, threshold noise,
or sample-size sensitivity. Scores remain available for diagnostics, but no review queue or trusted
data is created by that path.

`classifier phase1-diagnostics` freezes a validated local encoder, extracts hash-bound mean-pooled
and L2-normalized features with networking blocked, and compares logistic, linear, and small-MLP
heads under weighted and unweighted losses. It uses deterministic label-stratified folds over the
full transitive grouping relation and writes the embedding-cache metadata, fold assignments, all
per-run metrics, and aggregate diagnostics separately. It does not update the encoder, score a human
review batch, or select a production model.

`classifier phase2-validate` keeps the Phase 1 unweighted linear head fixed and compares only raw
mean-pooled embeddings against L2-normalized embeddings. Repeated grouped outer folds measure split
instability. Grouped inner out-of-fold predictions fit Platt scaling and select preregistered
security-oriented operating points without using the corresponding outer validation rows. Isotonic
calibration is rejected for this small corpus. The command revalidates every promoted source and
combined-gold binding, blocks networking, and never trains or mutates the encoder.

`classifier phase2.1-diagnostics` reuses the hash-bound Phase 2 normalized embedding cache and fixed
unweighted linear head. It ranks concept influence, runs controlled leave-one-concept-out
sensitivity, distinguishes score offsets from ranking reversals, and evaluates exactly five
preregistered threshold policies. Every learned threshold comes from grouped inner out-of-fold
scores, and cross-split transfer is reported separately. It never relabels, changes metadata,
creates review data, or touches the encoder.

`classifier phase2.2-representations` keeps the encoder and unweighted linear head frozen while
comparing exactly six extraction choices under raw and L2-normalized vectors. It records global and
critical-concept metrics, cosine geometry, nearest neighbors, and three preregistered pairwise
boundaries. The final selection requires local reversal and margin improvement without material
global ranking, false-positive, split-stability, or other-boundary regressions. Binary-mask mean
pool variants are explicitly marked equivalent rather than treated as independent evidence.
