# Offline classifier model import

SecureInjections does not discover or download classifier models at runtime. An operator must
acquire a model outside the protected environment, review its license and provenance, copy it to
an immutable local directory, and freeze every file by SHA-256 in
`secureinjections-model.json`. Supplying a model never starts training.

Inspect a directory or file without loading model code:

```console
secureinjections classifier model inspect /srv/models/candidate
```

Validate a complete import, then smoke-load it with filesystem-only Transformers settings and
socket connections actively blocked:

```console
secureinjections classifier model validate /srv/models/candidate
```

Both commands inspect only the explicit path. They do not search a model cache, resolve a model
name, contact Hugging Face, or call a hosted API. `inspect` is static and reports why an artifact is
English-only, incomplete, or unsupported. `validate` fails closed unless the model is a complete,
frozen multilingual import, then performs one two-row inference smoke test. It never trains,
calibrates, selects, copies, or promotes a model.

## Directory contract

The directory must contain real files, not symlinks, and no repository-supplied Python or
pickle-capable serialization. It may contain at most 256 files and 2 GiB in total. A model of no
more than 750 MiB is recommended for the research pipeline.

```text
candidate/
├── secureinjections-model.json
├── config.json
├── model.safetensors
│   # or model.safetensors.index.json plus all referenced *.safetensors shards
├── tokenizer_config.json
├── special_tokens_map.json
├── tokenizer.json
│   # or vocab.txt, a SentencePiece model, or vocab.json + merges.txt
├── LICENSE
└── optional model-card or tokenizer metadata, also hash-frozen
```

The bundled schema is `secureinjections/model-import-schema-v1.json`. The validator additionally
enforces semantic constraints that JSON Schema alone cannot express:

- `config.json` declares a supported `model_type`, non-empty `architectures`, positive
  `vocab_size`, and positive encoder dimension (`hidden_size`, `d_model`, `dim`, or
  `embedding_size`). `auto_map` is forbidden.
- The tokenizer has `tokenizer_config.json`, `special_tokens_map.json`, and one complete local
  vocabulary layout. Runtime validation requires a fast tokenizer.
- Weights use only safetensors. The validator parses every bounded safetensors header and checks
  tensor offsets; shard names must exactly match the index. `.bin`, `.pt`, `.pth`, `.pkl`,
  `.pickle`, `.joblib`, and `.ckpt` are rejected.
- Every regular file except the manifest appears exactly once in `files`, keyed by normalized
  relative path with its lowercase SHA-256. Unhashed extra files and missing files fail closed.
- The manifest architecture matches `config.json`. Its explicit languages must include all current
  target languages: `da`, `de`, `en`, `es`, `fr`, `it`, `nl`, `no`, `pl`, `pt`, and `sv`.
- `license` contains an operator-reviewed SPDX expression and an included, non-empty license file.
  `provenance` records the source, immutable upstream revision, acquisition date, and offline
  acquisition method. Validation proves integrity, not legal compatibility; the operator remains
  responsible for the license decision.

Example manifest shape (hashes abbreviated here only; real manifests require 64 lowercase hex
characters):

```json
{
  "schema_version": 1,
  "model_id": "organization/model-name",
  "revision": "immutable-upstream-revision",
  "architecture": "xlm-roberta",
  "languages": ["da", "de", "en", "es", "fr", "it", "nl", "no", "pl", "pt", "sv"],
  "license": {"spdx": "Apache-2.0", "file": "LICENSE"},
  "provenance": {
    "source": "operator-reviewed offline source",
    "revision": "immutable-upstream-revision",
    "acquired_at": "YYYY-MM-DD",
    "acquisition_method": "verified offline media"
  },
  "files": {
    "LICENSE": "<sha256>",
    "config.json": "<sha256>",
    "model.safetensors": "<sha256>",
    "special_tokens_map.json": "<sha256>",
    "tokenizer.json": "<sha256>",
    "tokenizer_config.json": "<sha256>"
  }
}
```

## Supported architecture classes

The v0.4.2 trainer attaches a sequence-classification head through
`AutoModelForSequenceClassification`. The supported encoder `model_type` values are `bert`,
`roberta`, `xlm-roberta`, `distilbert`, `deberta`, `deberta-v2`, `rembert`, and `electra`.
Multilingual suitability is a separate requirement: an architecture being supported does not prove
that a particular checkpoint covers the eleven languages or performs well on security intent.

Examples of architecture families—not endorsed checkpoints—include multilingual BERT/MiniLM
exports (`bert`), XLM-R encoders (`xlm-roberta`), multilingual DistilBERT encoders (`distilbert`),
and RemBERT encoders (`rembert`). Decoder-only causal language models, GGUF/Ollama packages,
ONNX-only exports, remote/custom-code architectures, hosted embeddings, and arbitrary sentence
embedding APIs are outside the training contract.

## Offline smoke test and privacy

Validation sets the Hugging Face, Transformers, Datasets, and experiment-tracking offline flags,
disables telemetry, passes `local_files_only=True` and `trust_remote_code=False`, requires
safetensors, and temporarily replaces socket connection functions with a hard failure. It loads the
tokenizer and sequence-classification architecture, tokenizes two inert multilingual sentences,
runs inference under `torch.inference_mode()`, verifies a two-by-two logits shape, and discards all
input and tensors. It writes no prompts, outputs, weights, cache entries, or validation artifacts.

After a directory passes this command, no network is required to use it locally. Passing the import
contract only establishes packaging, integrity, architecture, declared language coverage, and
offline loadability. It does not establish accuracy, readiness, production suitability, or license
compatibility, and it does not authorize Blind Set E use.

## Existing MiniLM cache

The cached `sentence-transformers/all-MiniLM-L6-v2` bytes are a complete 384-dimensional BERT/
MiniLM sentence encoder with tokenizer and safetensors weights. Its local card declares only
English and Apache-2.0. Raw Transformers can load it with networking blocked, but the Hugging Face
snapshot uses symlinks and has no SecureInjections freeze/provenance manifest, so the strict
pipeline rejects that directory.

An operator may copy those already-local bytes into real files and create a reviewed manifest to
use it as an English-only research baseline or diagnostic. That still cannot support multilingual
claims, production selection, development-shadow substitution, or Blind Set E evaluation.
