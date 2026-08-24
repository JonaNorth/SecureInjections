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
_DIRECTIVE_PREFACE = re.compile(
    r"(?:(?:please|now|then|next|immediately)\s+|"
    r"(?:can|could|would)\s+you\s+|"
    r"i\s+need\s+you\s+to\s+|"
    r"(?:you|the\s+(?:agent|model|tool))\s+(?:must|should|will)\s+)*",
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
    for match in _pattern_matches(content):
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


def detect_text(
    request: InspectionRequest, context: ContentContext, source_trust: TrustLevel
) -> tuple[GuardFinding, ...]:
    if context is not ContentContext.OPERATIVE:
        return ()
    findings: list[GuardFinding] = []
    for rule in RULES:
        for pattern in rule.patterns:
            match = re.search(pattern, request.content, re.IGNORECASE | re.DOTALL)
            if match is None:
                continue
            finding_type = rule.finding_type
            family = rule.family
            rule_id = rule.rule_id
            reason_code = rule.reason_code
            reason = rule.reason
            if finding_type is FindingType.DIRECT_PROMPT_INJECTION and (
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
                finding_type = FindingType.INDIRECT_PROMPT_INJECTION
                family = ClassifierFamily.ATTACK_INDIRECT_INJECTION
                rule_id = "GUARD-PI-INDIRECT-001"
                reason_code = "INDIRECT_PROMPT_INJECTION"
                reason = (
                    "Untrusted content contains an instruction that attempts to override "
                    "downstream control."
                )
            findings.append(
                GuardFinding(
                    rule_id=rule_id,
                    finding_type=finding_type,
                    classifier_family=family,
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
                    reason_code=reason_code,
                    reason=reason,
                )
            )
            break
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
