"""Bounded, compositional intent and reference-context detection."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

from ..models import ContextEvidence, IndicatorStrength, RiskEvidence, ScanContext
from .abstract_intent import MultilingualIntentLexicon
from .context import ContextAnalyzer, strip_reference_spans

_MAX_INTENT_CHARS = 65_536
_DOCUMENTATION = re.compile(
    r"\b(?:documentation|manual|guide|reference|policy says|lists?|mentions?|"
    r"(?:for|as an?)\s+example|example\s+(?:of|showing|demonstrat)|"
    r"sample\s+(?:text|code|data)|"
    r"warning label|inert|as data|do not (?:execute|contact|follow)|"
    r"without (?:executing|following))\b",
    re.IGNORECASE,
)
_LOCAL_DEVELOPMENT = re.compile(
    r"\b(?:local|development|developer|dev|staging|test(?:ing)?|loopback)\b.{0,80}"
    r"(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|private (?:network|address))|"
    r"(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b.{0,80}"
    r"\b(?:local|development|developer|dev|staging|test(?:ing)?|runs?|listen)",
    re.IGNORECASE | re.DOTALL,
)
_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)
_LANGUAGE_HINTS = {
    "da": frozenset({"og", "til", "skal", "næste", "værktøj", "hemmelige"}),
    "de": frozenset({"die", "der", "das", "und", "soll", "werkzeug", "geheimnisse"}),
    "fr": frozenset({"le", "la", "les", "et", "doit", "outil", "secrets"}),
    "es": frozenset({"el", "la", "los", "las", "debe", "herramienta", "secretos"}),
    "sv": frozenset({"och", "ska", "nästa", "verktyget", "hemliga"}),
    "no": frozenset({"og", "skal", "neste", "verktøy", "hemmeligheter"}),
    "nl": frozenset({"de", "het", "een", "moet", "hulpmiddel", "geheimen"}),
    "it": frozenset({"il", "lo", "gli", "deve", "strumento", "segreti", "credenziali"}),
    "pt": frozenset({"deve", "ferramenta", "segredos", "credenciais", "instruções"}),
    "pl": frozenset({"musi", "narzędzie", "sekrety", "poświadczenia", "instrukcje"}),
}


@dataclass(frozen=True, slots=True)
class IntentAnalysis:
    evidence: tuple[RiskEvidence, ...]
    categories: tuple[str, ...]
    contexts: frozenset[str]
    signal_names: frozenset[str]
    context_evidence: tuple[ContextEvidence, ...] = ()
    critical: bool = False
    review_floor: bool = False


def _load_signal_patterns() -> tuple[
    re.Pattern[str],
    dict[str, str],
    dict[str, dict[str, re.Pattern[str]]],
    dict[str, re.Pattern[str]],
]:
    path = files("secureinjections").joinpath("intent-signals.json")
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) not in (
        {"schema_version", "signals"},
        {"schema_version", "signals", "language_signals"},
    ):
        raise RuntimeError("intent signal data is invalid")
    if raw["schema_version"] not in {1, 2} or not isinstance(raw["signals"], dict):
        raise RuntimeError("unsupported intent signal data")
    language_signals = raw.get("language_signals", {})
    if not isinstance(language_signals, dict):
        raise RuntimeError("intent language signal data is invalid")
    for signals in language_signals.values():
        if not isinstance(signals, dict):
            raise RuntimeError("intent language entry is invalid")
        for name, patterns in signals.items():
            if name not in raw["signals"] or not isinstance(patterns, list):
                raise RuntimeError("intent language signal is invalid")
    alternatives: list[str] = []
    groups: dict[str, str] = {}
    supplemental_names = {
        "agent_target",
        "downstream_behavior",
        "execution_payload",
        "future_agent_target",
        "future_processing",
        "network_retrieval",
        "package_target",
        "traversal_target",
        "untrusted_package",
    }
    supplemental: dict[str, re.Pattern[str]] = {}
    for index, (name, patterns) in enumerate(raw["signals"].items()):
        if (
            not isinstance(name, str)
            or not isinstance(patterns, list)
            or not patterns
            or not all(isinstance(item, str) and len(item) <= 2048 for item in patterns)
        ):
            raise RuntimeError("intent signal entry is invalid")
        expression = "(?:" + ")|(?:".join(patterns) + ")"
        group = f"signal_{index}"
        alternatives.append(f"(?P<{group}>{expression})")
        groups[group] = name
        if name in supplemental_names:
            supplemental[name] = re.compile(expression, re.IGNORECASE | re.DOTALL)
    compiled_languages: dict[str, dict[str, re.Pattern[str]]] = {}
    for language, signals in language_signals.items():
        if not isinstance(language, str):
            raise RuntimeError("intent language name is invalid")
        compiled_languages[language] = {}
        for name, patterns in signals.items():
            if not patterns or not all(
                isinstance(item, str) and len(item) <= 2048 for item in patterns
            ):
                raise RuntimeError("intent language patterns are invalid")
            expression = "(?:" + ")|(?:".join(patterns) + ")"
            compiled_languages[language][name] = re.compile(expression, re.IGNORECASE | re.DOTALL)
    return (
        re.compile("|".join(alternatives), re.IGNORECASE | re.DOTALL),
        groups,
        compiled_languages,
        supplemental,
    )


(
    _SIGNAL_PATTERN,
    _SIGNAL_GROUPS,
    _LANGUAGE_SIGNAL_PATTERNS,
    _SUPPLEMENTAL_PATTERNS,
) = _load_signal_patterns()


def _evidence(
    signal: str,
    weight: float,
    category: str,
    strength: IndicatorStrength,
    confidence: float = 0.85,
) -> RiskEvidence:
    return RiskEvidence(signal, weight, category, confidence, strength)


class CompositionalIntentDetector:
    """Combine weak lexical signals; individual terms never create a positive decision."""

    def __init__(
        self,
        context_analyzer: ContextAnalyzer | None = None,
        abstract_lexicon: MultilingualIntentLexicon | None = None,
    ) -> None:
        self.context_analyzer = context_analyzer or ContextAnalyzer()
        self.abstract_lexicon = abstract_lexicon or MultilingualIntentLexicon()

    def analyze(
        self, variants: tuple[str, ...], original: str, context: ScanContext
    ) -> IntentAnalysis:
        bounded_original = original[:_MAX_INTENT_CHARS]
        context_analysis = self.context_analyzer.analyze(bounded_original)
        educational_context = "security_explanation" in context_analysis.kinds
        documentation_context = bool(_DOCUMENTATION.search(bounded_original))
        reference_context = context_analysis.reference_framing or documentation_context
        active_variants: list[str] = []
        has_reference_span = False
        for variant in variants[:8]:
            bounded_variant = variant[:_MAX_INTENT_CHARS]
            active, quoted = strip_reference_spans(bounded_variant)
            if not context_analysis.reference_framing:
                active = bounded_variant
            active_variants.append(active)
            has_reference_span |= quoted
        active_text = "\n".join(active_variants)
        abstract = self.abstract_lexicon.match(active_text, language_hint=context.language)
        found_signals = {
            _SIGNAL_GROUPS[match.lastgroup]
            for match in _SIGNAL_PATTERN.finditer(active_text)
            if match.lastgroup is not None
        }
        words = frozenset(_WORD.findall(active_text.casefold()))
        selected_languages = {"en", *(set(context_analysis.languages) - {"en"})}
        selected_languages.update(
            language for language, hints in _LANGUAGE_HINTS.items() if not words.isdisjoint(hints)
        )
        for language in selected_languages:
            language_patterns = _LANGUAGE_SIGNAL_PATTERNS.get(language)
            if language_patterns is None:
                continue
            found_signals.update(
                name for name, pattern in language_patterns.items() if pattern.search(active_text)
            )
        # A small supplemental set preserves overlapping target/qualifier concepts without one
        # full-text regular-expression pass per signal group.
        found_signals.update(
            name for name, pattern in _SUPPLEMENTAL_PATTERNS.items() if pattern.search(active_text)
        )
        # Execution verbs are also relevant when they address a future agent. This alias avoids
        # duplicating the same lexical match in the master regular expression.
        if "tool_action" in found_signals:
            found_signals.add("execution_phrase")
        found_signals.update(abstract.signals)

        def alias(target: str, *abstract_names: str) -> None:
            if not abstract.signals.isdisjoint(abstract_names):
                found_signals.add(target)

        alias("access_action", "ACTION.READ", "ACTION.FETCH")
        alias("send_action", "ACTION.SEND", "ACTION.UPLOAD")
        alias("tool_action", "ACTION.CALL", "ACTION.EXECUTE", "ACTION.INSTALL")
        alias("execution_phrase", "ACTION.CALL", "ACTION.EXECUTE", "ACTION.INSTALL")
        alias("persistence_action", "ACTION.STORE", "ACTION.REMEMBER")
        alias("disclosure_action", "ACTION.REVEAL")
        alias("override_verb", "ACTION.IGNORE", "ACTION.OVERRIDE")
        alias("secret_target", "TARGET.SECRET", "TARGET.CREDENTIAL")
        alias("sensitive_file_target", "TARGET.FILE")
        alias("metadata_target", "TARGET.METADATA")
        alias("package_target", "TARGET.PACKAGE")
        alias("protected_configuration_target", "TARGET.SYSTEM_PROMPT", "TARGET.CONFIGURATION")
        alias("privileged_instruction_target", "TARGET.SYSTEM_PROMPT", "TARGET.CONFIGURATION")
        alias("execution_payload", "TARGET.TOOL", "TARGET.SHELL", "TARGET.PACKAGE")
        alias("shell_target", "TARGET.SHELL")
        alias(
            "agent_target",
            "RECIPIENT.AGENT",
            "RECIPIENT.MODEL",
            "RECIPIENT.ASSISTANT",
            "RECIPIENT.LOG_ANALYZER",
        )
        alias("future_agent_target", "RECIPIENT.FUTURE_AGENT", "PERSISTENCE.NEXT_AGENT")
        alias(
            "future_processing",
            "PERSISTENCE.LATER",
            "PERSISTENCE.NEXT_AGENT",
            "PERSISTENCE.STORE_FOR_FUTURE",
        )
        alias("instruction_noun", "PAYLOAD.INSTRUCTION")
        alias("network_retrieval", "DESTINATION.EXTERNAL_URL", "DESTINATION.REMOTE_SERVICE")
        signal_names = frozenset(found_signals)
        contexts: set[str] = set()
        contexts.update(context_analysis.kinds)
        if educational_context:
            contexts.add("educational_context")
        if documentation_context:
            contexts.add("documentation_context")
        if has_reference_span and reference_context:
            contexts.add("quoted_reference_context")
        if _LOCAL_DEVELOPMENT.search(bounded_original):
            contexts.add("local_development_context")

        evidence: list[RiskEvidence] = []
        categories: set[str] = set()
        critical = False

        def has(*names: str) -> bool:
            return all(name in signal_names for name in names)

        def has_any(*names: str) -> bool:
            return not signal_names.isdisjoint(names)

        if has("override_verb", "privileged_instruction_target"):
            evidence.append(
                _evidence(
                    "INSTRUCTION_OVERRIDE_INTENT",
                    42.0,
                    "PI.SYSTEM_OVERRIDE",
                    IndicatorStrength.STRONG,
                    0.9,
                )
            )
            categories.add("prompt_injection")
        if has("disclosure_action", "protected_configuration_target") and not has("override_verb"):
            evidence.append(
                _evidence(
                    "PROTECTED_CONFIGURATION_EXTRACTION_INTENT",
                    38.0,
                    "PI.POLICY_EXTRACTION",
                    IndicatorStrength.STRONG,
                    0.88,
                )
            )
            categories.add("prompt_injection")
        if has("access_action", "secret_target"):
            evidence.append(
                _evidence(
                    "CREDENTIAL_ACCESS_INTENT",
                    43.0,
                    "AGENT.CREDENTIAL_ACCESS",
                    IndicatorStrength.STRONG,
                    0.9,
                )
            )
            categories.add("credential_access")
        if has("access_action", "TARGET.ENVIRONMENT") and (
            "direct_imperative" in contexts or "agent_target" in signal_names
        ):
            evidence.append(
                _evidence(
                    "ENVIRONMENT_ACCESS_INTENT",
                    43.0,
                    "AGENT.CREDENTIAL_ACCESS",
                    IndicatorStrength.STRONG,
                    0.9,
                )
            )
            categories.add("credential_access")
        if has("access_action", "sensitive_file_target"):
            evidence.append(
                _evidence(
                    "SENSITIVE_FILE_ACCESS_INTENT",
                    43.0,
                    "AGENT.FILE_ACCESS",
                    IndicatorStrength.STRONG,
                    0.9,
                )
            )
            categories.add("file_access")
        if (
            "send_action" in signal_names
            and (
                "secret_target" in signal_names
                or "sensitive_file_target" in signal_names
                or "TARGET.ENVIRONMENT" in signal_names
            )
            and has_any(
                "access_action",
                "shell_target",
                "TARGET.ENVIRONMENT",
                "DESTINATION.EXTERNAL_URL",
                "DESTINATION.REMOTE_SERVICE",
            )
        ):
            evidence.append(
                _evidence(
                    "CREDENTIAL_EXFILTRATION_INTENT",
                    78.0,
                    "AGENT.NETWORK_ACCESS",
                    IndicatorStrength.CRITICAL,
                    0.95,
                )
            )
            categories.add("agent_manipulation")
            critical = True
        elif (
            "send_action" in signal_names
            and has_any("secret_target", "TARGET.ENVIRONMENT")
            and ("direct_imperative" in contexts or "agent_target" in signal_names)
        ):
            evidence.append(
                _evidence(
                    "CREDENTIAL_TRANSFER_INTENT",
                    52.0,
                    "AGENT.NETWORK_ACCESS",
                    IndicatorStrength.STRONG,
                    0.9,
                )
            )
            categories.update(("agent_manipulation", "credential_access"))
        if has("access_action", "metadata_target"):
            weight = 78.0 if "secret_target" in signal_names else 46.0
            strength = (
                IndicatorStrength.CRITICAL
                if "secret_target" in signal_names
                else IndicatorStrength.STRONG
            )
            evidence.append(_evidence("METADATA_ACCESS_INTENT", weight, "NET.SSRF", strength, 0.92))
            categories.add("ssrf")
            critical |= strength is IndicatorStrength.CRITICAL
        if has("access_action", "metadata_target") and has_any(
            "send_action",
            "ACTION.REVEAL",
            "DESTINATION.EXTERNAL_URL",
            "DESTINATION.REMOTE_SERVICE",
        ):
            evidence.append(
                _evidence(
                    "METADATA_EXFILTRATION_INTENT",
                    78.0,
                    "NET.METADATA_EXFILTRATION",
                    IndicatorStrength.CRITICAL,
                    0.95,
                )
            )
            categories.update(("ssrf", "agent_manipulation"))
            critical = True
        if has("tool_action", "package_target"):
            evidence.append(
                _evidence(
                    "PACKAGE_EXECUTION_INTENT",
                    38.0,
                    "AGENT.PACKAGE_MANAGER",
                    IndicatorStrength.STRONG,
                    0.86,
                )
            )
            categories.add("package_manager")
        if (
            "tool_action" in signal_names
            and (
                "execution_payload" in signal_names
                or "shell_target" in signal_names
                or "package_target" in signal_names
            )
            and (
                "agent_target" in signal_names
                or "direct_imperative" in contexts
                or "future_agent_target" in signal_names
            )
        ):
            evidence.append(
                _evidence(
                    "TOOL_EXECUTION_INTENT",
                    46.0,
                    "AGENT.TOOL_EXECUTION",
                    IndicatorStrength.STRONG,
                    0.88,
                )
            )
            categories.add("agent_manipulation")
        if (
            has("tool_action", "package_target")
            and ("untrusted_package" in signal_names or "network_retrieval" in signal_names)
            and ("agent_target" in signal_names or "future_agent_target" in signal_names)
        ):
            evidence.append(
                _evidence(
                    "SUPPLY_CHAIN_EXECUTION_INTENT",
                    72.0,
                    "AGENT.SUPPLY_CHAIN_EXECUTION",
                    IndicatorStrength.CRITICAL,
                    0.92,
                )
            )
            categories.update(("agent_manipulation", "package_manager"))
            critical = True
        if has("access_action", "traversal_target"):
            weight = 54.0 if "sensitive_file_target" in signal_names else 44.0
            evidence.append(
                _evidence(
                    "PATH_TRAVERSAL_ACCESS_INTENT",
                    weight,
                    "FILE.PATH_TRAVERSAL",
                    IndicatorStrength.STRONG,
                    0.9,
                )
            )
            categories.update(("path_traversal", "file_access"))
        if (
            has("access_action", "traversal_target", "sensitive_file_target")
            and "send_action" in signal_names
        ):
            evidence.append(
                _evidence(
                    "PATH_TRAVERSAL_EXFILTRATION_INTENT",
                    78.0,
                    "FILE.PATH_EXFILTRATION",
                    IndicatorStrength.CRITICAL,
                    0.95,
                )
            )
            categories.update(("path_traversal", "file_access", "agent_manipulation"))
            critical = True
        if ("future_agent_target" in signal_names or has("agent_target", "future_processing")) and (
            "execution_phrase" in signal_names
            or "override_verb" in signal_names
            or "instruction_noun" in signal_names
            or "downstream_behavior" in signal_names
        ):
            weight = 38.0 if context.source == "log" else 34.0
            evidence.append(
                _evidence(
                    "INTER_AGENT_INSTRUCTION_INTENT",
                    weight,
                    "AGENT.INTER_AGENT_MESSAGE",
                    IndicatorStrength.STRONG,
                    0.9,
                )
            )
            categories.update(("agent_manipulation", "indirect_prompt_injection"))
        if "persistence_action" in signal_names and (
            "future_agent_target" in signal_names or has("agent_target", "future_processing")
        ):
            evidence.append(
                _evidence(
                    "PERSISTENT_AGENT_INSTRUCTION_INTENT",
                    42.0,
                    "AGENT.PERSISTENCE",
                    IndicatorStrength.STRONG,
                    0.88,
                )
            )
            categories.update(("agent_manipulation", "indirect_prompt_injection"))
        if (
            has_any("RECIPIENT.FUTURE_AGENT", "PERSISTENCE.NEXT_AGENT")
            and has_any("ACTION.STORE", "ACTION.REMEMBER", "PERSISTENCE.STORE_FOR_FUTURE")
            and has_any(
                "PAYLOAD.INSTRUCTION",
                "ACTION.IGNORE",
                "ACTION.OVERRIDE",
                "ACTION.EXECUTE",
                "ACTION.CALL",
            )
        ):
            evidence.append(
                _evidence(
                    "CROSS_AGENT_PERSISTENCE_INTENT",
                    52.0,
                    "AGENT.PERSISTENCE",
                    IndicatorStrength.STRONG,
                    0.93,
                )
            )
            categories.update(("agent_manipulation", "indirect_prompt_injection"))
        if (
            context.source in {"log", "database", "tool_output", "retrieved_document"}
            and context.trust_level == "untrusted"
            and "untrusted_container" in signal_names
            and ("override_verb" in signal_names or "execution_phrase" in signal_names)
            and "privileged_instruction_target" in signal_names
        ):
            evidence.append(
                _evidence(
                    "UNTRUSTED_EMBEDDED_INSTRUCTION_INTENT",
                    34.0,
                    "PI.INDIRECT",
                    IndicatorStrength.STRONG,
                    0.86,
                )
            )
            categories.add("indirect_prompt_injection")
        if (
            context.source
            in {"log", "database", "tool_output", "retrieved_document", "email", "webpage"}
            and context.trust_level == "untrusted"
            and has_any(
                "RECIPIENT.AGENT",
                "RECIPIENT.MODEL",
                "RECIPIENT.ASSISTANT",
                "RECIPIENT.LOG_ANALYZER",
                "RECIPIENT.FUTURE_AGENT",
            )
            and has_any(
                "ACTION.IGNORE",
                "ACTION.OVERRIDE",
                "ACTION.EXECUTE",
                "ACTION.CALL",
                "ACTION.STORE",
                "ACTION.REMEMBER",
            )
        ):
            evidence.append(
                _evidence(
                    "INDIRECT_AGENT_DIRECTIVE_INTENT",
                    46.0,
                    "PI.INDIRECT",
                    IndicatorStrength.STRONG,
                    0.9,
                )
            )
            categories.update(("indirect_prompt_injection", "agent_manipulation"))
        if (
            "tool_action" in signal_names
            and "shell_target" in signal_names
            and "secret_target" in signal_names
        ):
            weight = 62.0 if "send_action" in signal_names else 45.0
            evidence.append(
                _evidence(
                    "SHELL_SECRET_ACCESS_INTENT",
                    weight,
                    "AGENT.SHELL_SECRET_ACCESS",
                    IndicatorStrength.STRONG,
                    0.9,
                )
            )
            categories.update(("shell_command", "credential_access"))

        if abstract.reconstructed_signals and any(
            item.weight > 0
            and item.strength in {IndicatorStrength.STRONG, IndicatorStrength.CRITICAL}
            for item in evidence
        ):
            evidence.append(
                _evidence(
                    "BOUNDED_WORD_SPLIT_INTENT_RECOVERY",
                    5.0,
                    "OBFUSCATION.WORD_SPLIT",
                    IndicatorStrength.MODERATE,
                    0.9,
                )
            )

        # Context is inspectable, but Scanner applies one global negative cap and critical floor.
        context_categories = {
            "security_explanation": "CONTEXT.EDUCATIONAL",
            "descriptive_attack_reference": "CONTEXT.DESCRIPTIVE",
            "question_about_attack": "CONTEXT.QUESTION",
            "quoted_security_example": "CONTEXT.QUOTED_REFERENCE",
            "documentation_code_example": "CONTEXT.DOCUMENTATION",
            "structured_data_example": "CONTEXT.STRUCTURED_DATA",
            "direct_imperative": "CONTEXT.DIRECT_IMPERATIVE",
        }
        for item in context_analysis.evidence:
            evidence.append(
                _evidence(
                    item.kind.upper(),
                    item.weight,
                    context_categories[item.kind],
                    IndicatorStrength.MODERATE if item.weight > 0 else IndicatorStrength.WEAK,
                    item.confidence,
                )
            )
        if "documentation_context" in contexts:
            evidence.append(
                _evidence(
                    "SECURITY_DOCUMENTATION_CONTEXT",
                    -6.0,
                    "CONTEXT.DOCUMENTATION",
                    IndicatorStrength.WEAK,
                    0.75,
                )
            )
        if "quoted_reference_context" in contexts:
            evidence.append(
                _evidence(
                    "QUOTED_REFERENCE_CONTEXT",
                    -10.0,
                    "CONTEXT.QUOTED_REFERENCE",
                    IndicatorStrength.WEAK,
                    0.85,
                )
            )
        if "local_development_context" in contexts:
            evidence.append(
                _evidence(
                    "LOCAL_DEVELOPMENT_CONTEXT",
                    -8.0,
                    "CONTEXT.LOCAL_DEVELOPMENT",
                    IndicatorStrength.WEAK,
                    0.8,
                )
            )

        active_composition_signals = {
            "CREDENTIAL_EXFILTRATION_INTENT",
            "CREDENTIAL_TRANSFER_INTENT",
            "METADATA_EXFILTRATION_INTENT",
            "TOOL_EXECUTION_INTENT",
            "SUPPLY_CHAIN_EXECUTION_INTENT",
            "PATH_TRAVERSAL_ACCESS_INTENT",
            "PATH_TRAVERSAL_EXFILTRATION_INTENT",
            "INTER_AGENT_INSTRUCTION_INTENT",
            "PERSISTENT_AGENT_INSTRUCTION_INTENT",
            "CROSS_AGENT_PERSISTENCE_INTENT",
            "INDIRECT_AGENT_DIRECTIVE_INTENT",
        }
        passive_context = bool(
            educational_context
            or documentation_context
            or context_analysis.reference_framing
            or "descriptive_attack_reference" in context_analysis.kinds
        )
        review_floor = critical or (
            (not passive_context or "direct_imperative" in contexts)
            and any(item.signal in active_composition_signals for item in evidence)
        )
        return IntentAnalysis(
            tuple(evidence),
            tuple(sorted(categories)),
            frozenset(contexts),
            signal_names,
            context_analysis.evidence,
            critical,
            review_floor,
        )
