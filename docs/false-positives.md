# False positives and hard negatives

False positives are security failures when they disrupt legitimate work. The benign corpus is as
large as the attack corpus and includes technical documentation, security research, normal SQL,
code references, network terminology, and quoted attack language. A single weak signal cannot
block; repeated or independent evidence increases risk. Educational/reference context can lower
uncertain signals but cannot authorize hostile actions or erase critical evidence.

Use the closest benign examples you can construct, then validate with the application profile.
Do not lower global thresholds to fix one broad rule; narrow the rule or add a contextual signal.

v0.3.2 recognizes bounded educational, descriptive, documentation, quoted-reference,
structured-data, and local-development contexts as negative evidence across eleven maintained
language dictionaries. It distinguishes direct imperatives from quoted/descriptive examples with
lightweight lexical structure, not a claim of natural-language understanding. These signals are
capped and cannot erase critical exfiltration, supply-chain execution, metadata access, or
secret-access combinations. In particular, prepending “for educational purposes” does not make an
active credential-access and upload instruction safe.

v0.3.3 does not classify an isolated multilingual action, target, package name, shell term, or
technical noun as malicious. Abstract concepts raise risk only through explicit compositions.
Educational and descriptive text can therefore mention credentials, metadata, package managers,
agents, paths, or commands without automatically entering REVIEW. Conversely, an educational
preface cannot suppress a complete credential-exfiltration or metadata-exfiltration composition.

Applications with reliable locale metadata may pass `ScanContext(language="fr")`. This helps
inspection and evaluation but does not disable other language signals or make the input trusted.
