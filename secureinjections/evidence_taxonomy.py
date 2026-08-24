"""Closed classifier-evidence taxonomy contract."""

from __future__ import annotations

from .classifier import IntentLabel
from .classifier_data import BinaryLabel, binary_label_for_family

CLASSIFIER_FAMILIES = tuple(item.value for item in IntentLabel)
TAXONOMY_VERSION = "classifier-evidence-taxonomy-v1"


def validate_family(value: object) -> IntentLabel:
    """Reject silent taxonomy expansion."""
    if not isinstance(value, str):
        raise ValueError("classifier_family must be a string")
    try:
        return IntentLabel(value)
    except ValueError as exc:
        raise ValueError(f"unknown classifier family (taxonomy review required): {value}") from exc


def validate_label_family(binary_label: object, family: object) -> tuple[BinaryLabel, IntentLabel]:
    if not isinstance(binary_label, str):
        raise ValueError("binary_label must be a string")
    try:
        label = BinaryLabel(binary_label)
    except ValueError as exc:
        raise ValueError(f"invalid binary_label: {binary_label}") from exc
    parsed_family = validate_family(family)
    if binary_label_for_family(parsed_family) is not label:
        raise ValueError("binary_label conflicts with classifier_family")
    return label, parsed_family
