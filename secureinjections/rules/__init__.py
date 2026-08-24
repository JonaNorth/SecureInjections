"""Bundled signatures and first-class SecureInjections Threat Rule support."""

from .loader import load_threat_rules, threat_rule_to_legacy
from .models import ThreatRule
from .validator import ThreatRuleValidationError, validate_threat_rule

__all__ = [
    "ThreatRule",
    "ThreatRuleValidationError",
    "load_threat_rules",
    "threat_rule_to_legacy",
    "validate_threat_rule",
]
