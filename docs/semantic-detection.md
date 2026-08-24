# Local semantic detection

`LocalEmbeddingSemanticDetector` compares a temporary request vector with normalized vectors built
from Threat Rule v1 `semantic_examples`. It uses cosine similarity and a NumPy matrix, which is
appropriate for small and medium corpora. The interface allows an HNSW or other ANN backend later
without changing `Scanner.scan()`.

Install the optional dependencies:

```bash
pip install 'secureinjections[semantic]'
```

Only trusted local sentence-transformers model directories are accepted. Model loading sets
`local_files_only=True` and `trust_remote_code=False`; no model is fetched automatically. Model
artifacts are software supply-chain inputs and still require provenance review.

```bash
secureinjections semantic build-index \
  --rules /srv/secureinjections-rules/rules \
  --model /srv/models/sentence-transformer \
  --output /srv/secureinjections/index
secureinjections semantic inspect-index --index /srv/secureinjections/index
secureinjections semantic benchmark \
  --index /srv/secureinjections/index \
  --model /srv/models/sentence-transformer
```

Index construction validates rules, sorts immutable IDs, embeds threat examples, normalizes
float32 vectors, records safe rule/category/severity metadata, and writes a content hash. It does
not retain example text. Loading uses `numpy.load(..., allow_pickle=False)`, validates exact dtype,
shape, finite values, limits, symlinks, and the content hash.

Request embeddings exist only temporarily in process. Similarity does not prove malicious intent;
thresholds require corpus-specific precision testing.
