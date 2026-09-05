"""SecureInjections public API."""

from .classifier_contract import (
    ClassifierThresholds,
    IntentClassifierResult,
    IntentLabel,
)
from .config import ScannerConfig
from .models import (
    ContextEvidence,
    Decision,
    IndicatorStrength,
    RiskEvidence,
    Rule,
    RuleMatch,
    ScanContext,
    ScanResult,
)
from .scanner import Scanner
from .version import ENGINE_VERSION

__all__ = [
    "Decision",
    "ContextEvidence",
    "Rule",
    "RuleMatch",
    "RiskEvidence",
    "ScanResult",
    "ScanContext",
    "IndicatorStrength",
    "Scanner",
    "ScannerConfig",
    "ClassifierThresholds",
    "IntentClassifierResult",
    "IntentLabel",
]
__version__ = ENGINE_VERSION
