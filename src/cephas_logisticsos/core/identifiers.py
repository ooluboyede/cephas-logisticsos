"""Validation helpers for opaque CEPHAS domain identifiers."""

from __future__ import annotations

import re

_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\\Z")


def validate_identifier(value: str, *, field_name: str) -> str:
    """Return a valid opaque identifier or raise ``ValueError``.

    Identifiers are deliberately treated as opaque values. This validation does
    not establish identity, authorization, tenant membership, or trust.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if value != value.strip() or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be 1-128 safe identifier characters")
    return value
