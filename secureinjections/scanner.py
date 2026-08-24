"""High-level synchronous scanning API."""

from __future__ import annotations

import time
from collections import Counter

from .classifier import (
    AmbiguityClassifier,
    ClassifierInput,
    IntentClassifier,
    IntentClassifierResult,
    IntentLabel,
    TransformersIntentClassifier,
)
from .config import ScannerConfig
from .detectors.intent import CompositionalIntentDetector, IntentAnalysis
from .detectors.patterns import text_variants
from .detectors.secrets import RuleBasedSecretDetector, SecretDetector
from .detectors.semantic import KeywordSemanticDetector, SemanticDetector
from .detectors.semantic_embeddings import LocalEmbeddingSemanticDetector
from .models import (
    Decision,
    IndicatorStrength,
    RiskEvidence,
    RuleMatch,
    ScanContext,
    ScanResult,
)
from .profiles import PROFILES
from .rule_engine import (
    SEVERITY_WEIGHTS,
    RuleEngine,
    RuleValidationError,
    custom_rules,
    load_rules,
)
from .rules.loader import load_bundled_threat_rules, load_threat_rules, threat_rule_to_legacy
from .rules.models import ThreatRule
from .rules.validator import ThreatRuleValidationError
from .version import ENGINE_VERSION


class Scanner:
    """Offline, deterministic-first text risk classifier.

    Instances are safe to reuse. Initialization performs YAML loading and regex compilation;
    scan calls perform no I/O, logging, telemetry, URL resolution, or code execution.
    """

    def __init__(
        self,
        config: ScannerConfig | None = None,
        *,
        rule_engine: RuleEngine | None = None,
        secret_detector: SecretDetector | None = None,
        semantic_detector: SemanticDetector | None = None,
        ambiguity_classifier: AmbiguityClassifier | None = None,
        intent_classifier: IntentClassifier | None = None,
        intent_detector: CompositionalIntentDetector | None = None,
    ) -> None:
        self.config = config or ScannerConfig()
        self.threat_rules: tuple[ThreatRule, ...] = ()
        if self.config.rule_paths:
            try:
                self.threat_rules = load_threat_rules(self.config.rule_paths)
                rules = tuple(threat_rule_to_legacy(rule) for rule in self.threat_rules)
            except ThreatRuleValidationError as threat_error:
                try:
                    rules = load_rules(self.config.rule_paths)
                except RuleValidationError as legacy_error:
                    raise threat_error from legacy_error
        else:
            self.threat_rules = load_bundled_threat_rules()
            rules = tuple(threat_rule_to_legacy(rule) for rule in self.threat_rules)
        rules += custom_rules(self.config.custom_patterns)
        self.rule_engine = rule_engine or RuleEngine(rules, self.config.disabled_rule_ids)
        self.secret_detector = secret_detector or RuleBasedSecretDetector(
            rule for rule in rules if rule.enabled and rule.id not in self.config.disabled_rule_ids
        )
        self.ambiguity_classifier = ambiguity_classifier
        self.intent_classifier: IntentClassifier | None
        if intent_classifier is not None:
            self.intent_classifier = intent_classifier
        elif self.config.classifier_enabled and self.config.classifier_model_path is not None:
            self.intent_classifier = TransformersIntentClassifier(
                self.config.classifier_model_path,
                expected_weights_sha256=self.config.classifier_weights_sha256,
            )
        else:
            self.intent_classifier = None
        self.intent_detector = intent_detector or CompositionalIntentDetector()
        # The bundled detector is local and lightweight, but it is only invoked by scan()
        # when deep_scan=True or semantic_enabled and the deterministic threshold is met.
        if semantic_detector is not None:
            self.semantic_detector = semantic_detector
        elif self.config.semantic_model_path and self.config.semantic_index_path:
            self.semantic_detector = LocalEmbeddingSemanticDetector(
                model_path=self.config.semantic_model_path,
                model_id=self.config.semantic_model_id,
                index_path=self.config.semantic_index_path,
                similarity_threshold=(
                    None
                    if self.config.semantic_use_index_calibration
                    else self.config.semantic_similarity_threshold
                ),
                top_k=self.config.semantic_top_k,
            )
        else:
            self.semantic_detector = KeywordSemanticDetector()

    def _score(
        self,
        matches: tuple[RuleMatch, ...],
        text: str,
        context: ScanContext,
        intent: IntentAnalysis,
    ) -> tuple[int, tuple[RiskEvidence, ...]]:
        """Build an inspectable deterministic ensemble from sanitized match metadata."""
        score = 0.0
        category_counts: Counter[str] = Counter()
        conceptual_family_counts: Counter[str] = Counter()
        evidence: list[RiskEvidence] = []
        intent_evidence_signals = {item.signal for item in intent.evidence}
        profile = PROFILES[self.config.profile]
        reference_context = bool(
            intent.contexts
            & {
                "educational_context",
                "documentation_context",
                "quoted_reference_context",
            }
        )
        source_multiplier = 1.0
        if context.source in {
            "retrieved_document",
            "webpage",
            "email",
            "log",
            "database",
            "tool_output",
        }:
            source_multiplier = profile.indirect_instruction_multiplier
        if context.trust_level == "untrusted":
            source_multiplier *= 1.05
        elif context.trust_level == "trusted":
            # Trusted provenance lowers uncertain signals only; it never suppresses a critical hit.
            source_multiplier *= 0.9

        ordered_matches = sorted(
            matches, key=lambda item: SEVERITY_WEIGHTS[item.severity], reverse=True
        )
        for match in ordered_matches:
            count = category_counts[match.category]
            raw_conceptual_family = match.taxonomy or match.category
            conceptual_family = raw_conceptual_family
            obfuscation_alias = conceptual_family == "PI.OBFUSCATION"
            if obfuscation_alias:
                conceptual_family = "PI.SYSTEM_OVERRIDE"
            family_count = conceptual_family_counts[conceptual_family]
            confidence = max(0.0, min(1.0, match.confidence))
            strength = {
                "low": IndicatorStrength.WEAK,
                "medium": IndicatorStrength.MODERATE,
                "high": IndicatorStrength.STRONG,
                "critical": IndicatorStrength.CRITICAL,
            }[match.severity]
            if (
                reference_context
                and match.category == "path_traversal"
                and "PATH_TRAVERSAL_ACCESS_INTENT" not in intent_evidence_signals
                and "PATH_TRAVERSAL_EXFILTRATION_INTENT" not in intent_evidence_signals
            ):
                strength = IndicatorStrength.MODERATE
            multiplier = source_multiplier
            if reference_context and match.category in {
                "prompt_injection",
                "shell_command",
                "package_manager",
                "sql_injection",
                "credential_access",
                "file_access",
                "internal_resource_access",
                "agent_manipulation",
                "path_traversal",
            }:
                multiplier *= profile.technical_context_discount * 0.32
            if "local_development_context" in intent.contexts and match.category in {
                "ssrf",
                "shell_command",
                "package_manager",
            }:
                multiplier *= profile.technical_context_discount * 0.25
            if (
                "documentation_context" in intent.contexts
                and match.category in {"file_access", "credential_access"}
                and "SENSITIVE_FILE_ACCESS_INTENT" not in intent_evidence_signals
                and "CREDENTIAL_ACCESS_INTENT" not in intent_evidence_signals
            ):
                multiplier *= 0.25
            if family_count and obfuscation_alias:
                diminishing = 0.1
            else:
                diminishing = 1.0 if count == 0 else 0.55 if count == 1 else 0.25
            base_weight = {"low": 12, "medium": 40, "high": 45, "critical": 78}[match.severity]
            weight = base_weight * confidence * diminishing * multiplier
            score += weight
            evidence.append(
                RiskEvidence(
                    signal="deterministic_rule",
                    weight=round(weight, 3),
                    category=match.taxonomy or match.category,
                    confidence=confidence,
                    strength=strength,
                    rule_id=match.rule_id,
                )
            )
            category_counts[match.category] += 1
            conceptual_family_counts[conceptual_family] += 1

        if len(category_counts) >= 2:
            bonus = min(18.0, 6.0 * (len(category_counts) - 1))
            if reference_context:
                bonus *= 0.35
            score += bonus
            evidence.append(
                RiskEvidence(
                    signal="independent_rule_families",
                    weight=bonus,
                    category="ENSEMBLE.CORROBORATION",
                    confidence=1.0,
                    strength=IndicatorStrength.STRONG,
                )
            )
        if len(conceptual_family_counts) >= 2:
            bonus = min(12.0, 6.0 + len(conceptual_family_counts))
            if reference_context:
                bonus *= 0.35
            score += bonus
            evidence.append(
                RiskEvidence(
                    signal="multi_signal_confirmation",
                    weight=bonus,
                    category="ENSEMBLE.CORROBORATION",
                    confidence=1.0,
                    strength=IndicatorStrength.STRONG,
                )
            )
        matched_taxonomies = {item.taxonomy for item in matches if item.taxonomy}
        positive_intent: list[RiskEvidence] = []
        for item in intent.evidence:
            if item.weight <= 0:
                continue
            if item.category in matched_taxonomies:
                positive_intent.append(
                    RiskEvidence(
                        signal=item.signal,
                        weight=4.0,
                        category=item.category,
                        confidence=item.confidence,
                        strength=item.strength,
                        rule_id=item.rule_id,
                    )
                )
            else:
                positive_intent.append(item)
        negative_intent = tuple(item for item in intent.evidence if item.weight < 0)
        score += sum(item.weight for item in positive_intent)
        # At most 15 points of negative context may affect a scan.
        score += max(-15.0, sum(item.weight for item in negative_intent))
        evidence.extend((*positive_intent, *negative_intent))
        if intent.review_floor:
            review_floor = max(0, self.config.review_threshold + profile.review_adjustment)
            score = max(score, float(review_floor))
        novel_positive_intent = tuple(item for item in positive_intent if item.weight > 4.0)
        if len(novel_positive_intent) >= 2:
            score += 8.0
            evidence.append(
                RiskEvidence(
                    signal="COMPOSITIONAL_INTENT_CORROBORATION",
                    weight=8.0,
                    category="ENSEMBLE.CORROBORATION",
                    confidence=1.0,
                    strength=IndicatorStrength.STRONG,
                )
            )
        if intent.critical or any(
            item.strength is IndicatorStrength.CRITICAL for item in evidence if item.weight > 0
        ):
            score = max(score, 72.0)
        if len(evidence) == 1 and evidence[0].strength is IndicatorStrength.WEAK:
            score = min(score, self.config.review_threshold - 1)
        return max(0, min(100, round(score))), tuple(evidence)

    def _decision(self, score: int) -> Decision:
        profile = PROFILES[self.config.profile]
        block_threshold = min(100, max(1, self.config.block_threshold + profile.block_adjustment))
        review_threshold = min(
            block_threshold - 1,
            max(0, self.config.review_threshold + profile.review_adjustment),
        )
        if score >= block_threshold:
            return Decision.BLOCK
        if score >= review_threshold:
            return Decision.REVIEW
        return Decision.ALLOW

    def _should_run_classifier(
        self,
        *,
        decision: Decision,
        score: int,
        evidence: tuple[RiskEvidence, ...],
        intent: IntentAnalysis,
    ) -> bool:
        """Apply one of the four documented routing experiments."""
        if not self.config.classifier_enabled or self.intent_classifier is None:
            return False
        critical = any(
            item.strength is IndicatorStrength.CRITICAL and item.weight > 0 for item in evidence
        )
        if critical and decision is Decision.BLOCK:
            return False
        policy = self.config.classifier_routing
        if policy == "all":
            return True
        if policy == "deterministic_nontrivial":
            return score > 0 or any(item.weight > 0 for item in evidence)
        if policy == "ambiguous":
            return decision is Decision.REVIEW
        strongly_benign = (
            score == 0 and bool(intent.contexts) and not any(item.weight > 0 for item in evidence)
        )
        return not strongly_benign

    @staticmethod
    def _combine_classifier(
        deterministic_decision: Decision,
        score: int,
        evidence: tuple[RiskEvidence, ...],
        result: IntentClassifierResult,
        classifier: IntentClassifier,
    ) -> tuple[Decision, str]:
        """Monotonic critical precedence plus an explicit, inspectable state policy.

        A classifier-only malicious result produces REVIEW, not BLOCK. Corroboration by at least
        moderate deterministic evidence permits BLOCK. Low malicious probability can resolve a
        non-critical REVIEW downward, while deterministic BLOCK is never reduced below REVIEW.
        """
        critical = any(
            item.strength is IndicatorStrength.CRITICAL and item.weight > 0 for item in evidence
        )
        if critical and deterministic_decision is Decision.BLOCK:
            return Decision.BLOCK, "critical deterministic block has precedence"
        thresholds = classifier.thresholds
        probability = result.malicious_probability
        positive_strength = max(
            (item.strength for item in evidence if item.weight > 0),
            default=IndicatorStrength.WEAK,
            key=lambda value: {
                IndicatorStrength.WEAK: 0,
                IndicatorStrength.MODERATE: 1,
                IndicatorStrength.STRONG: 2,
                IndicatorStrength.CRITICAL: 3,
            }[value],
        )
        corroborated = score > 0 and positive_strength in {
            IndicatorStrength.MODERATE,
            IndicatorStrength.STRONG,
            IndicatorStrength.CRITICAL,
        }
        if result.predicted_family is IntentLabel.AMBIGUOUS or result.uncertain:
            if deterministic_decision is Decision.BLOCK:
                return Decision.BLOCK, "deterministic block retained under classifier abstention"
            return Decision.REVIEW, "classifier abstained in its calibrated review zone"
        if probability >= thresholds.block_min:
            if deterministic_decision is Decision.BLOCK or corroborated:
                return Decision.BLOCK, "high classifier probability corroborates deterministic risk"
            return Decision.REVIEW, "classifier-only malicious evidence requires review by default"
        if probability <= thresholds.allow_max:
            if deterministic_decision is Decision.BLOCK:
                return Decision.REVIEW, "low classifier risk reduced a non-critical block to review"
            return Decision.ALLOW, "low classifier risk and no critical deterministic block"
        return Decision.REVIEW, "classifier probability falls in the calibrated review zone"

    @staticmethod
    def _explanation(
        decision: Decision,
        matches: tuple[RuleMatch, ...],
        semantic: dict | None,
        classifier: dict | None,
    ) -> str:
        if not matches and not semantic and not classifier:
            return (
                "No enabled risk signatures matched. "
                "This is a risk classification, not a guarantee."
            )
        categories = sorted({match.category for match in matches})
        base = (
            f"{len(matches)} rule(s) matched across {len(categories)} category/categories: "
            f"{', '.join(categories) or 'semantic-only'}. Decision: {decision.value}."
        )
        if semantic:
            base += " Optional local semantic analysis also ran."
        if classifier:
            base += " Optional local intent classification also ran under the configured policy."
        return base

    def scan(
        self,
        text: str,
        *,
        deep_scan: bool = False,
        context: ScanContext | None = None,
    ) -> ScanResult:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if len(text) > self.config.max_input_length:
            raise ValueError(f"text exceeds max_input_length ({self.config.max_input_length})")
        scan_context = context or ScanContext()
        if not isinstance(scan_context, ScanContext):
            raise TypeError("context must be a ScanContext")

        started = time.perf_counter_ns()
        variants = text_variants(
            text,
            max_candidates=self.config.max_decode_candidates,
            max_decoded_length=self.config.max_decoded_length,
        )
        intent = self.intent_detector.analyze(variants, text, scan_context)
        deterministic = self.rule_engine.match(
            variants, excluded_categories=frozenset({"secret_leakage"})
        )
        secrets = self.secret_detector.detect(variants)
        matches = tuple({match.rule_id: match for match in (*deterministic, *secrets)}.values())
        score, evidence = self._score(matches, text, scan_context, intent)
        if matches and (len(variants) > 1 or variants[0] != text):
            score = min(100, score + 5)
            evidence += (
                RiskEvidence(
                    signal="bounded_obfuscation_decode",
                    weight=5.0,
                    category="OBFUSCATION.DECODED",
                    confidence=0.8,
                    strength=IndicatorStrength.MODERATE,
                ),
            )
        deterministic_duration_ms = (time.perf_counter_ns() - started) / 1_000_000

        semantic_data: dict[str, object] | None = None
        semantic_categories: tuple[str, ...] = ()
        should_run_semantic = (
            deep_scan
            or self.config.semantic_scan_all
            or (self.config.semantic_enabled and score >= self.config.semantic_threshold)
        )
        if should_run_semantic and self.semantic_detector is not None:
            semantic = self.semantic_detector.analyze(text)
            semantic_categories = semantic.categories
            semantic_data = {
                "risk_score": semantic.risk_score,
                "categories": list(semantic.categories),
                "explanation": semantic.explanation,
                "semantic_score": semantic.risk_score,
                "matches": [
                    {
                        "rule_id": match.rule_id,
                        "category": match.category,
                        "similarity": match.similarity,
                    }
                    for match in semantic.matches
                ],
                "matched_rule_ids": [match.rule_id for match in semantic.matches],
                "context_signals": list(semantic.context_signals),
            }
            corroboration = 5 if matches and semantic.categories else 0
            deterministic_score = score
            score = min(100, max(score, semantic.risk_score) + corroboration)
            evidence += (
                RiskEvidence(
                    signal="local_semantic_similarity",
                    weight=float(max(0, score - deterministic_score)),
                    category="SEMANTIC.SIMILARITY",
                    confidence=min(1.0, semantic.risk_score / 100),
                    strength=(
                        IndicatorStrength.STRONG
                        if semantic.risk_score >= self.config.block_threshold
                        else IndicatorStrength.MODERATE
                    ),
                ),
            )

        decision = self._decision(score)
        has_critical = any(
            item.strength is IndicatorStrength.CRITICAL and item.weight > 0 for item in evidence
        )
        if has_critical:
            decision = Decision.BLOCK
        deterministic_decision = decision
        categories = {match.category for match in matches}
        categories.update(intent.categories)
        categories.update(semantic_categories)
        if categories & {"prompt_injection", "agent_manipulation"} and scan_context.source in {
            "retrieved_document",
            "webpage",
            "email",
            "log",
            "database",
            "tool_output",
        }:
            categories.add("indirect_prompt_injection")
        classifier_data: dict[str, object] | None = None
        classifier_duration_ms: float | None = None
        if self._should_run_classifier(
            decision=decision,
            score=score,
            evidence=evidence,
            intent=intent,
        ):
            assert self.intent_classifier is not None
            classifier_started = time.perf_counter_ns()
            classifier_result = self.intent_classifier.classify(variants[0], scan_context)
            classifier_duration_ms = (time.perf_counter_ns() - classifier_started) / 1_000_000
            decision, policy_reason = self._combine_classifier(
                deterministic_decision,
                score,
                evidence,
                classifier_result,
                self.intent_classifier,
            )
            classifier_data = {
                **classifier_result.to_dict(),
                "routing_policy": self.config.classifier_routing,
                "deterministic_decision": deterministic_decision.value,
                "combined_decision": decision.value,
                "policy_reason": policy_reason,
                "critical_override_prevented": policy_reason.startswith("critical deterministic"),
            }
            if classifier_result.predicted_family.name.startswith("ATTACK_"):
                categories.add(classifier_result.predicted_family.value)
            evidence += (
                RiskEvidence(
                    signal="local_intent_classifier",
                    weight=0.0,
                    category=classifier_result.predicted_family.value,
                    confidence=classifier_result.confidence,
                    strength=(
                        IndicatorStrength.STRONG
                        if classifier_result.malicious_probability
                        >= self.intent_classifier.thresholds.block_min
                        else IndicatorStrength.MODERATE
                    ),
                ),
            )
        if (
            self.config.classifier_enabled
            and self.ambiguity_classifier is not None
            and classifier_data is None
            and decision is Decision.REVIEW
        ):
            legacy_result = self.ambiguity_classifier.classify(
                ClassifierInput(decision, score, evidence, tuple(sorted(categories)))
            )
            critical_precedence = has_critical and decision is Decision.BLOCK
            if not critical_precedence:
                decision = legacy_result.decision
            classifier_data = {
                "legacy_sanitized_evidence_classifier": True,
                "decision": legacy_result.decision.value,
                "confidence": legacy_result.confidence,
                "explanation": legacy_result.explanation,
                "critical_override_prevented": (
                    critical_precedence and legacy_result.decision is not Decision.BLOCK
                ),
            }
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        return ScanResult(
            decision=decision,
            risk_score=score,
            matched_rules=matches,
            detected_categories=tuple(sorted(categories)),
            explanation=self._explanation(decision, matches, semantic_data, classifier_data),
            scan_duration_ms=round(elapsed_ms, 3),
            deterministic_duration_ms=round(deterministic_duration_ms, 3),
            classifier_duration_ms=(
                round(classifier_duration_ms, 3) if classifier_duration_ms is not None else None
            ),
            semantic_analysis=semantic_data,
            classifier_analysis=classifier_data,
            evidence=evidence,
            context={
                "source": scan_context.source,
                "trust_level": scan_context.trust_level,
                "content_type": scan_context.content_type,
                "profile": self.config.profile,
                **({"language": scan_context.language} if scan_context.language else {}),
            },
            context_evidence=intent.context_evidence,
            feed_version=self.config.feed_version,
            rules_version=self.config.rules_version,
            engine_version=ENGINE_VERSION,
        )
