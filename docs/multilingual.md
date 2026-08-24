# Multilingual coverage

The corpus represents 11 European languages. Deterministic coverage is strongest for explicit
instruction overrides and remains uneven for paraphrases, morphology, and languages not listed by
a rule. Language metadata describes tested intent; it is not a guarantee.

Multilingual embedding candidates must be compared on SecureInjections validation data and hard
negatives. A model is not recommended merely because a public benchmark calls it multilingual.
Release reports should include precision, recall, and FPR for every represented language.
