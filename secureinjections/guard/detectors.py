"""Offline deterministic detectors used by Guard v0.1."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlsplit

from .models import (
    Certainty,
    ClassifierFamily,
    ContentContext,
    EvidenceSpan,
    FindingType,
    GuardFinding,
    InspectionContext,
    InspectionRequest,
    Severity,
    SourceType,
    ToolCallRequest,
    TrustLevel,
)


@dataclass(frozen=True, slots=True)
class DetectorRule:
    rule_id: str
    finding_type: FindingType
    family: ClassifierFamily
    severity: Severity
    certainty: Certainty
    patterns: tuple[str, ...]
    reason_code: str
    reason: str


RULES = (
    DetectorRule(
        "GUARD-PI-001",
        FindingType.DIRECT_PROMPT_INJECTION,
        ClassifierFamily.ATTACK_DIRECT_INJECTION,
        Severity.HIGH,
        Certainty.STRONG,
        (
            r"\bignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions?\b",
            r"\b(?:override|bypass)\s+(?:the\s+)?(?:policy|rules?|safety|role)\b",
            r"\byou\s+are\s+now\s+(?:in|a|an)\b",
        ),
        "DIRECT_PROMPT_INJECTION",
        "Instruction attempts to override governing instructions or role.",
    ),
    DetectorRule(
        "GUARD-SECRET-001",
        FindingType.SYSTEM_SECRET_EXTRACTION,
        ClassifierFamily.ATTACK_CREDENTIAL_ACCESS,
        Severity.HIGH,
        Certainty.STRONG,
        (
            r"\b(?:reveal|show|print|repeat|expose|dump)\b.{0,60}\b"
            r"(?:system prompt|hidden instructions?|developer message|secret prompt)\b",
        ),
        "SYSTEM_SECRET_EXTRACTION",
        "Instruction requests protected system or instruction content.",
    ),
    DetectorRule(
        "GUARD-CRED-001",
        FindingType.CREDENTIAL_ACCESS,
        ClassifierFamily.ATTACK_CREDENTIAL_ACCESS,
        Severity.CRITICAL,
        Certainty.STRONG,
        (
            r"\b(?:read|show|print|dump|steal|extract|retrieve|access)\b.{0,80}\b"
            r"(?:api[_ -]?(?:keys?|tokens?)|credentials?|passwords?|"
            r"auth(?:entication)? tokens?|"
            r"private keys?|secrets?)\b",
            r"\b(?:aws|gcp|azure)\b.{0,40}\b(?:credentials?|tokens?|keys?)\b",
        ),
        "CREDENTIAL_ACCESS",
        "Instruction seeks credential or secret material.",
    ),
    DetectorRule(
        "GUARD-EXFIL-001",
        FindingType.EXFILTRATION,
        ClassifierFamily.ATTACK_EXFILTRATION,
        Severity.CRITICAL,
        Certainty.STRONG,
        (
            r"\b(?:send|upload|post|transmit|exfiltrat(?:e|ion)|forward)\b.{0,100}\b(?:document|file|data|secret|token|credential|contents?|records?)\b.{0,100}\b(?:external|remote|attacker|webhook|https?://)",
            r"\b(?:send|upload|post|transmit|forward)\b.{0,100}\b(?:to|via)\s+https?://",
        ),
        "EXFILTRATION",
        "Sensitive-looking data is directed to an external destination.",
    ),
    DetectorRule(
        "GUARD-TOOL-001",
        FindingType.TOOL_EXECUTION,
        ClassifierFamily.ATTACK_TOOL_EXECUTION,
        Severity.HIGH,
        Certainty.STRONG,
        (
            r"\b(?:run|execute|launch|invoke)\b.{0,50}\b(?:shell|command|bash|powershell|terminal|tool)\b",
            r"(?:^|\s)(?:sudo\s+)?(?:curl|wget|bash|sh|powershell|cmd\.exe)\s+[^\n]+",
        ),
        "TOOL_EXECUTION",
        "Instruction requests command or tool execution.",
    ),
    DetectorRule(
        "GUARD-PATH-001",
        FindingType.PATH_ACCESS,
        ClassifierFamily.ATTACK_PATH_ACCESS,
        Severity.HIGH,
        Certainty.STRONG,
        (
            r"(?:/etc/(?:passwd|shadow)|~/\.ssh|/root/\.ssh|\.\./\.\./|[A-Za-z]:\\Users\\[^\s]+\\\.ssh)",
            r"\b(?:read|open|copy|cat)\b.{0,60}\b(?:\.env|id_rsa|authorized_keys|/proc/self/environ)\b",
        ),
        "SENSITIVE_PATH_ACCESS",
        "Instruction targets a sensitive path or traverses resource boundaries.",
    ),
    DetectorRule(
        "GUARD-META-001",
        FindingType.METADATA_ACCESS,
        ClassifierFamily.ATTACK_METADATA_ACCESS,
        Severity.HIGH,
        Certainty.DEFINITE,
        (r"169\.254\.169\.254", r"metadata\.google\.internal", r"/latest/meta-data/"),
        "METADATA_ACCESS",
        "Request targets a cloud or workload metadata endpoint.",
    ),
    DetectorRule(
        "GUARD-PERSIST-001",
        FindingType.PERSISTENCE,
        ClassifierFamily.ATTACK_PERSISTENCE,
        Severity.CRITICAL,
        Certainty.STRONG,
        (
            r"\b(?:write|store|save|add|persist|remember)\b.{0,80}\b"
            r"(?:memory|profile|persistent|future sessions?)\b.{0,100}\b"
            r"(?:instruction|always|ignore|override|behavior)",
            r"\bfrom now on\b.{0,80}\b(?:ignore|always|must|instruction)",
            r"\b(?:disable|bypass|skip)[_ -]?.{0,60}"
            r"(?:future[_ -]?)?(?:approval|review|safety|policy)[_ -]?(?:checks?)?\b",
        ),
        "PERSISTENCE",
        "Instruction attempts to persist behavioral control in state or memory.",
    ),
    DetectorRule(
        "GUARD-CROSS-001",
        FindingType.CROSS_AGENT_POISONING,
        ClassifierFamily.ATTACK_CROSS_AGENT,
        Severity.HIGH,
        Certainty.STRONG,
        (
            r"\b(?:tell|instruct|command|make)\b.{0,50}\b(?:another|next|other)\s+(?:agent|tool|model)\b",
            r"\bwhen\s+(?:the\s+)?(?:agent|model|tool)\s+(?:reads|uses|sees)\s+this\b",
        ),
        "CROSS_AGENT_POISONING",
        "Content attempts to control a downstream agent, model, or tool.",
    ),
    DetectorRule(
        "GUARD-AUTH-P0-001",
        FindingType.DIRECT_PROMPT_INJECTION,
        ClassifierFamily.ATTACK_DIRECT_INJECTION,
        Severity.HIGH,
        Certainty.STRONG,
        (
            r"\b(?:host|administrator|admin|operator|system)\s+(?:has\s+)?(?:approved|authorized)\b",
            r"\b(?:host|administrator|admin|operator)\s+approval(?:\s+token)?\s+(?:is\s+)?(?:verified|valid|approved)\b",
            r"\b(?:claim|certif(?:y|ies))\b.{0,100}\b(?:request|content|output)\b.{0,100}\btrusted\b",
            r"\b(?:reset|clear|remove)\b.{0,50}\btaint\b",
            r"\b(?:adopt|accept|follow)\b.{0,70}\b(?:agent|peer)\b.{0,50}\bgoal\b.{0,100}\b(?:host\s+policy|privileged\s+action|execute|dispatch|send|perform)\b",
            r"\bretry\b.{0,80}\bexecution[- ]intent[- ][A-Za-z0-9-]+\b",
            r"\b(?:use\s+)?idempotency\s+key\b.{0,100}\b(?:dispatch|retry|send)\b",
            r"\buse\b.{0,80}\bintent\s+id\b.{0,80}\b(?:another|other|prior)\s+workflow\b",
            r"\bquery\b.{0,80}\boperation(?:\s+id)?\b.{0,100}\b(?:effect_confirmed|accept)\b",
            r"\bmark\b.{0,80}\brecovery\b.{0,100}\bcompleted\b.{0,80}\b(?:without|no)\b.{0,30}\bfence\b",
            r"\bauthorize_runtime_recovery\b",
            r"\b(?:use|call|invoke)\b.{0,80}\b(?:document_retriever|workspace_reader|retriev\w*|reader)\b.{0,120}\b(?:act|follow|obey)\b.{0,50}\b(?:output|result|content)\b",
        ),
        "FAKE_OR_TEXTUAL_AUTHORITY",
        "Text claims or selects host authority that only a host-owned capability can grant.",
    ),
    DetectorRule(
        "GUARD-PI-MULTILINGUAL-P0-001",
        FindingType.DIRECT_PROMPT_INJECTION,
        ClassifierFamily.ATTACK_DIRECT_INJECTION,
        Severity.HIGH,
        Certainty.STRONG,
        (
            r"\bignor(?:er|ér)\b.{0,80}\b(?:tidligere\s+instruktioner|sikkerhedsregler)\b",
            r"\bafslør\b.{0,80}\b(?:systemhemmeligheder|hemmeligheder)\b",
            r"\bignoriere\b.{0,80}\b(?:sicherheitsregeln|vorherige\s+anweisungen)\b",
            r"\bsende\b.{0,80}\b(?:die\s+)?geheimnisse\b",
        ),
        "MULTILINGUAL_PROMPT_INJECTION",
        "Supported-language text attempts to override safety or disclose protected material.",
    ),
    DetectorRule(
        "GUARD-DELAYED-P0-001",
        FindingType.DIRECT_PROMPT_INJECTION,
        ClassifierFamily.ATTACK_DIRECT_INJECTION,
        Severity.HIGH,
        Certainty.STRONG,
        (
            r"\b(?:on|after)\s+(?:the\s+)?(?:next|future)\s+(?:run|turn|session|restart)\b.{0,140}\b(?:execute|send|dispatch|retry|invoke|perform)\b",
        ),
        "DELAYED_PRIVILEGED_INSTRUCTION",
        "Instruction defers a privileged action to a later execution context.",
    ),
)

CONTEXT_CLASSIFIER_VERSION = "guard-context-v0.2"

DETECTOR_HASH = hashlib.sha256(
    json.dumps(
        {
            "context_classifier_version": CONTEXT_CLASSIFIER_VERSION,
            "rules": [
                {
                    "id": rule.rule_id,
                    "type": rule.finding_type.value,
                    "patterns": rule.patterns,
                    "severity": rule.severity.value,
                }
                for rule in RULES
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()

_BENIGN_MARKERS: tuple[tuple[ContentContext, tuple[str, ...]], ...] = (
    (
        ContentContext.INCIDENT_REPORT,
        (
            "incident report",
            "a security incident",
            "the attacker",
            "the intruder",
            "was observed",
            "postmortem",
            "forensic analysis",
        ),
    ),
    (
        ContentContext.DEVELOPER_GUIDANCE,
        (
            "developer guide",
            "safe coding",
            "hardening",
            "parameterized quer",
            "validate input",
            "reject requests",
            "defensive example",
            "best practice",
            "best practices",
            "store api key",
            "storing api key",
            "secret manager",
            "avoid hardcoding",
            "least privilege",
        ),
    ),
    (
        ContentContext.SECURITY_DISCUSSION,
        (
            "security article",
            "security discussion",
            "this vulnerability",
            "the report describes",
            "threat model",
            "researchers describe",
            "multi-factor authentication",
            "account security",
            "password reuse",
            "reusing password",
            "reusing passwords",
            "compromised password",
            "password breach",
            "credential hygiene",
        ),
    ),
    (
        ContentContext.QUOTED_ATTACK,
        ("quoted example", "example prompt", 'the phrase "ignore', "the text 'ignore", "quotation"),
    ),
)


_EXPLANATORY_MARKERS = (
    "explain",
    "why",
    "discuss",
    "analyze",
    "analyse",
    "security training",
    "example",
)
_PRECISION_CONTEXT_MARKERS = frozenset(
    {
        "best practice",
        "best practices",
        "store api key",
        "storing api key",
        "secret manager",
        "avoid hardcoding",
        "least privilege",
        "multi-factor authentication",
        "account security",
        "password reuse",
        "reusing password",
        "reusing passwords",
        "compromised password",
        "password breach",
        "credential hygiene",
    }
)
_QUOTED_SPAN = re.compile(r'"[^"\n]*"|\'[^\'\n]*\'')
_FENCED_SPAN = re.compile(r"```[^\n]*\n.*?```", re.DOTALL)
_MARKDOWN_QUOTE_LINE = re.compile(r"(?m)^\s*>[^\n]*(?:\n|$)")
_FIXTURE_JSON_VALUE = re.compile(
    r'"(?:sample_instruction|malicious_sample|attack_sample|quoted_instruction)"\s*:\s*'
    r'"(?P<value>(?:\\.|[^"\\])*)"',
    re.IGNORECASE,
)
_ATTRIBUTED_ATTACK = re.compile(
    r"\b(?:the\s+)?(?:attacker|intruder)\s+(?:said|says|wrote|sent|attempted)\b[^;.!?\n]*",
    re.IGNORECASE,
)
_DOCUMENTED_PREFIX = re.compile(
    r"(?im)(?:^|[.!?]\s+|\n)\s*(?:security\s+(?:discussion|article)|"
    r"developer\s+guide[^:;\n]{0,40}|incident\s+report|postmortem|forensic\s+analysis|"
    r"quoted\s+example)\s*:",
)
_ACTIVE_SENTENCE = re.compile(
    r"[.!?]\s+(?=(?:please\s+|now\s+|then\s+)?"
    r"(?:ignore|override|bypass|send|execute|invoke|reveal|read|open|mark|query|retry|use)\b)",
    re.IGNORECASE,
)
_DESCRIPTIVE_MATCH_PREFIX = re.compile(
    r"(?:\bthe\s+ability\s+to|\b(?:phrase|instruction|directive)\s+to)\s*$",
    re.IGNORECASE,
)
_QUOTE_DATA_MARKERS = (
    "quoted",
    "quotation",
    "phrase",
    "string",
    "example",
    "attacker",
    "intruder",
    "log",
    "incident",
    "defensiv",
    "unsafe",
    "malicious",
    "analyse",
    "analyze",
    "explain",
    "why",
    "warum",
    "sætningen",
)
_DIRECTIVE_PREFACE = re.compile(
    r"(?:(?:please|now|then|next|immediately)(?:\s+|$)|"
    r"(?:can|could|would)\s+you(?:\s+|$)|"
    r"i\s+need\s+you\s+to(?:\s+|$)|"
    r"(?:you|the\s+(?:agent|model|tool))\s+(?:must|should|will)(?:\s+|$))*",
    re.IGNORECASE,
)


def _pattern_matches(content: str) -> tuple[re.Match[str], ...]:
    return tuple(
        match
        for rule in RULES
        for pattern in rule.patterns
        if (match := re.search(pattern, content, re.IGNORECASE | re.DOTALL)) is not None
    )


def _has_explicit_operative_pattern(content: str) -> bool:
    for rule in RULES:
        for pattern in rule.patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                clause_prefix = re.split(r"[.!?;:\n]", content[: match.start()])[-1].strip()
                if _DIRECTIVE_PREFACE.fullmatch(clause_prefix) is not None:
                    return True
    return False


def _is_explanatory_quotation(content: str) -> bool:
    lowered = content.casefold()
    if not any(marker in lowered for marker in _EXPLANATORY_MARKERS):
        return False
    spans = tuple(_QUOTED_SPAN.finditer(content))
    if spans:
        if not any(_pattern_matches(span.group(0)[1:-1]) for span in spans):
            return False
        outside = list(content)
        for span in spans:
            outside[span.start() : span.end()] = " " * (span.end() - span.start())
        return not _pattern_matches("".join(outside))
    if lowered.lstrip().startswith(("quoted example:", "example prompt:")):
        first_boundary = re.search(r"[.!?\n]", content)
        remainder = content[first_boundary.end() :] if first_boundary is not None else ""
        return bool(_pattern_matches(content)) and not _pattern_matches(remainder)
    return False


def classify_context(request: InspectionRequest) -> ContentContext:
    context_object = cast(InspectionContext, request.context)
    if context_object.presentation is not None:
        return context_object.presentation
    lowered = request.content.casefold()
    if _is_explanatory_quotation(request.content):
        return ContentContext.QUOTED_ATTACK
    for context, markers in _BENIGN_MARKERS:
        marker = next((item for item in markers if item in lowered), None)
        if marker is not None:
            if marker in _PRECISION_CONTEXT_MARKERS and _has_explicit_operative_pattern(
                request.content
            ):
                return ContentContext.OPERATIVE
            return context
    if not any(
        re.search(pattern, request.content, re.IGNORECASE | re.DOTALL)
        for rule in RULES
        for pattern in rule.patterns
    ):
        return ContentContext.GENERAL_BENIGN
    return ContentContext.OPERATIVE


def _excerpt(text: str, start: int, end: int, *, sensitive: bool) -> str:
    if sensitive:
        return "[REDACTED]"
    left, right = max(0, start - 30), min(len(text), end + 30)
    value = text[left:right].replace("\n", " ")
    return value[:120]


def _structured_data_spans(content: str) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    spans.extend((match.start(), match.end()) for match in _FENCED_SPAN.finditer(content))
    spans.extend((match.start(), match.end()) for match in _MARKDOWN_QUOTE_LINE.finditer(content))
    spans.extend(
        (match.start("value"), match.end("value"))
        for match in _FIXTURE_JSON_VALUE.finditer(content)
    )
    spans.extend((match.start(), match.end()) for match in _ATTRIBUTED_ATTACK.finditer(content))
    for prefix in _DOCUMENTED_PREFIX.finditer(content):
        line_end = content.find("\n", prefix.end())
        line_end = len(content) if line_end < 0 else line_end
        fragment = content[prefix.start() : line_end]
        boundaries: list[int] = []
        semicolon = fragment.find(";")
        if semicolon >= 0:
            boundaries.append(semicolon)
        boundaries.extend(sentence.end() for sentence in _ACTIVE_SENTENCE.finditer(fragment))
        end = prefix.start() + (min(boundaries) if boundaries else len(fragment))
        spans.append((prefix.start(), end))
    quoted_spans = tuple(_QUOTED_SPAN.finditer(content))
    if _is_explanatory_quotation(content):
        # The explanatory classifier requires every detector match to remain inside a
        # syntactic quote.  Once that structural condition holds, repeated quoted attack
        # phrases remain data even when a long response separates them from the local
        # explanatory marker.  An operative match outside any quote makes the classifier
        # fail and is therefore never suppressed by this branch.
        spans.extend((match.start(), match.end()) for match in quoted_spans)
    else:
        lowered = content.casefold()
        for match in quoted_spans:
            window = lowered[max(0, match.start() - 100) : min(len(content), match.end() + 100)]
            if any(marker in window for marker in _QUOTE_DATA_MARKERS):
                spans.append((match.start(), match.end()))
    return tuple(spans)


def _match_is_nonoperative(
    content: str,
    match: re.Match[str],
    rule: DetectorRule,
    data_spans: tuple[tuple[int, int], ...],
) -> bool:
    if any(start <= match.start() and match.end() <= end for start, end in data_spans):
        return True
    prefix = content[max(0, match.start() - 80) : match.start()]
    if _DESCRIPTIVE_MATCH_PREFIX.search(prefix):
        return True
    if rule.finding_type is FindingType.PATH_ACCESS:
        lowered = content.casefold()
        explanatory = lowered.lstrip().startswith(
            ("discuss ", "explain ", "analyze ", "analyse ", "describe ")
        )
        nearby = lowered[max(0, match.start() - 80) : min(len(content), match.end() + 100)]
        if explanatory and any(
            marker in nearby
            for marker in ("should not", "must not", "do not", "without", "not be opened")
        ):
            return True
    return False


def _direct_finding_for_source(
    finding: GuardFinding, request: InspectionRequest, source_trust: TrustLevel
) -> GuardFinding:
    if finding.finding_type is not FindingType.DIRECT_PROMPT_INJECTION:
        return finding
    if not (
        request.source
        in {
            SourceType.RETRIEVED_CONTENT,
            SourceType.TOOL_OUTPUT,
            SourceType.FILE,
            SourceType.EXTERNAL,
        }
        or source_trust in {TrustLevel.UNTRUSTED, TrustLevel.EXTERNAL}
        and request.source is not SourceType.USER
    ):
        return finding
    return GuardFinding(
        "GUARD-PI-INDIRECT-001",
        FindingType.INDIRECT_PROMPT_INJECTION,
        ClassifierFamily.ATTACK_INDIRECT_INJECTION,
        finding.severity,
        finding.certainty,
        finding.evidence,
        "INDIRECT_PROMPT_INJECTION",
        "Untrusted content contains an instruction that attempts to override downstream control.",
    )


def detect_text(
    request: InspectionRequest, context: ContentContext, source_trust: TrustLevel
) -> tuple[GuardFinding, ...]:
    findings: list[GuardFinding] = []
    data_spans = _structured_data_spans(request.content)
    context_object = cast(InspectionContext, request.context)
    suspicious_encoded = context_object.metadata.get("suspicious_encoded") == "true"
    if (
        context is not ContentContext.OPERATIVE
        and not _has_explicit_operative_pattern(request.content)
        and not data_spans
        and not suspicious_encoded
    ):
        return ()
    for rule in RULES:
        for pattern in rule.patterns:
            matches = re.finditer(pattern, request.content, re.IGNORECASE | re.DOTALL)
            match = next(
                (
                    candidate
                    for candidate in matches
                    if not _match_is_nonoperative(request.content, candidate, rule, data_spans)
                ),
                None,
            )
            if match is None:
                continue
            if (
                rule.rule_id == "GUARD-AUTH-P0-001"
                and request.source is SourceType.MODEL
                and not re.search(
                    r"\b(?:execute|dispatch|send|retry|mark|query|bypass|reset|clear|remove)\b",
                    request.content,
                    re.IGNORECASE,
                )
            ):
                # A model's textual trust claim remains non-authoritative data.  It may be
                # shown to the user when it carries no operative privileged action.
                continue
            finding_type = rule.finding_type
            finding = GuardFinding(
                rule_id=rule.rule_id,
                finding_type=finding_type,
                classifier_family=rule.family,
                severity=rule.severity,
                certainty=rule.certainty,
                evidence=EvidenceSpan(
                    match.start(),
                    match.end(),
                    _excerpt(
                        request.content,
                        match.start(),
                        match.end(),
                        sensitive=finding_type
                        in {
                            FindingType.CREDENTIAL_ACCESS,
                            FindingType.SYSTEM_SECRET_EXTRACTION,
                            FindingType.EXFILTRATION,
                        },
                    ),
                ),
                reason_code=rule.reason_code,
                reason=rule.reason,
            )
            findings.append(_direct_finding_for_source(finding, request, source_trust))
            break
    if suspicious_encoded:
        match = re.search(r"[A-Za-z0-9+/]{14,}={0,2}", request.content)
        start, end = (match.start(), match.end()) if match is not None else (0, 0)
        finding = GuardFinding(
            "GUARD-ENCODED-P0-001",
            FindingType.DIRECT_PROMPT_INJECTION,
            ClassifierFamily.ATTACK_DIRECT_INJECTION,
            Severity.HIGH,
            Certainty.STRONG,
            EvidenceSpan(start, end, "[ENCODED INSTRUCTION]"),
            "ENCODED_INSTRUCTION",
            "Bounded content inspection found instruction-like encoded text.",
        )
        findings.append(_direct_finding_for_source(finding, request, source_trust))
    # Metadata credential endpoints carry both resource and credential semantics.
    if any(item.finding_type is FindingType.METADATA_ACCESS for item in findings) and re.search(
        r"(?:security-credentials|token|identity)", request.content, re.IGNORECASE
    ):
        match = re.search(
            r"(?:security-credentials|token|identity)", request.content, re.IGNORECASE
        )
        assert match is not None
        findings.append(
            GuardFinding(
                "GUARD-META-CRED-001",
                FindingType.CREDENTIAL_ACCESS,
                ClassifierFamily.ATTACK_CREDENTIAL_ACCESS,
                Severity.CRITICAL,
                Certainty.DEFINITE,
                EvidenceSpan(match.start(), match.end(), "[REDACTED]"),
                "CREDENTIAL_ACCESS",
                "Metadata request targets credential-bearing material.",
            )
        )
    return tuple(findings)


def _walk_arguments(
    value: Any, path: str = "arguments", depth: int = 0
) -> Iterable[tuple[str, str]]:
    if depth > 12:
        raise ValueError("tool arguments exceed maximum nesting depth")
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        if len(value) > 1_000:
            raise ValueError("tool argument mapping is too large")
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError("tool argument keys must be strings")
            yield from _walk_arguments(child, f"{path}.{key}", depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > 1_000:
            raise ValueError("tool argument sequence is too large")
        for index, child in enumerate(value):
            yield from _walk_arguments(child, f"{path}[{index}]", depth + 1)
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise TypeError("tool arguments may contain only JSON-like bounded values")


def tool_call_content(request: ToolCallRequest) -> str:
    pieces = [f"tool_name={request.tool_name}"]
    pieces.extend(f"{path}={value}" for path, value in _walk_arguments(request.arguments))
    return "\n".join(pieces)


def suspicious_url_finding(content: str) -> GuardFinding | None:
    match = None
    for candidate in re.finditer(r"https?://[^\s]+", content, re.IGNORECASE):
        host = urlsplit(candidate.group(0)).hostname or ""
        named_suspicious = any(
            token in host.casefold() for token in ("webhook", "requestbin", "ngrok", "attacker")
        )
        try:
            address = ipaddress.ip_address(host)
            address_suspicious = not (
                address.is_loopback
                or address.is_private
                or address.is_link_local
                or address.is_reserved
            )
        except ValueError:
            address_suspicious = False
        if named_suspicious or address_suspicious:
            match = candidate
            break
    if match is None:
        return None
    return GuardFinding(
        "GUARD-URL-001",
        FindingType.SUSPICIOUS_URL_DESTINATION,
        ClassifierFamily.ATTACK_EXFILTRATION,
        Severity.HIGH,
        Certainty.INDICATIVE,
        EvidenceSpan(
            match.start(),
            match.end(),
            _excerpt(content, match.start(), match.end(), sensitive=True),
        ),
        "SUSPICIOUS_URL_DESTINATION",
        "Tool call contains a suspicious external URL destination.",
    )
