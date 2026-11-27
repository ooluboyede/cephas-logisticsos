"""Reference outward error envelope; never expose database exception detail."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PublicDatabaseFailure:
    code: str
    message: str


REJECTED = PublicDatabaseFailure(
    "operation_rejected", "The requested operation could not be applied."
)
UNAVAILABLE = PublicDatabaseFailure(
    "operation_unavailable", "The operation could not be completed."
)


def normalize_database_failure(sqlstate: object) -> PublicDatabaseFailure:
    """Accept only SQLSTATE; do not accept or render SQL, identifiers, or exception text.

    This does not establish transaction outcome or authorize an automatic retry.
    """
    if isinstance(sqlstate, str) and sqlstate in {
        "23502",
        "23503",
        "23505",
        "23514",
        "23P01",
        "42501",
    }:
        return REJECTED
    return UNAVAILABLE
