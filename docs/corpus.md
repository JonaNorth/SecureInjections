# Corpus

Corpus JSONL fields are `id`, `text`, `label`, `expected_decision`, `categories`,
`attack_family`, `language`, `source_type`, `difficulty`, `notes`, `provenance`, `license`, and
`split`; mutations add `parent_case_id`. Labels are malicious, benign, or ambiguous. Difficulty is
easy, medium, hard, or adversarial. The split is a deterministic SHA-256 assignment.

The v0.3 base corpus contains 612 malicious and 612 benign cases across English, Danish, German,
French, Spanish, Swedish, Norwegian, Dutch, Italian, Portuguese, and Polish. It is synthetic and
Apache-2.0 licensed. Never add real secrets, private prompts, customer records, or live targets.

`secureinjections corpus mutate` applies 13 seeded offline transformations including casing,
spacing, punctuation, zero-width characters, Unicode substitutions, URL encoding, Base64, hex
escapes, word splitting, Markdown, HTML, JSON nesting, and repeated delimiters.
