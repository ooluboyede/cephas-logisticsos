"""Public error normalization reference tests."""

from __future__ import annotations

import pytest

from engineering.database_failure import REJECTED, UNAVAILABLE, normalize_database_failure


@pytest.mark.parametrize("state", ["23502", "23503", "23505", "23514", "23P01", "42501"])
def test_constraint_and_permission_errors_share_public_envelope(state: str) -> None:
    assert normalize_database_failure(state) == REJECTED


@pytest.mark.parametrize("state", [None, 23503, "08006", "40001", "XX000", "sensitive detail"])
def test_unknown_and_transport_failures_do_not_expose_input(state: object) -> None:
    assert normalize_database_failure(state) == UNAVAILABLE
