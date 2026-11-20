import pytest

from cephas_logisticsos.core.identifiers import validate_identifier
from cephas_logisticsos.tenancy import (
    AuthenticatedPrincipal,
    TenantContextError,
    TenantMembership,
    TenantScope,
)


def _valid_principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal("operator-17", is_authenticated=True)


def _valid_membership() -> TenantMembership:
    return TenantMembership("operator-17", "customer-1", "north-hub", True)


def test_scope_is_created_for_matching_active_membership() -> None:
    scope = TenantScope.from_verified_membership(_valid_principal(), _valid_membership())
    assert scope.subject_id == "operator-17"
    assert scope.tenant_id == "customer-1"
    assert scope.business_unit_id == "north-hub"


def test_scope_rejects_unauthenticated_principal() -> None:
    principal = AuthenticatedPrincipal("operator-17", is_authenticated=False)
    with pytest.raises(TenantContextError, match="authenticated principal"):
        TenantScope.from_verified_membership(principal, _valid_membership())


def test_scope_rejects_inactive_membership() -> None:
    membership = TenantMembership("operator-17", "customer-1", "north-hub", False)
    with pytest.raises(TenantContextError, match="inactive"):
        TenantScope.from_verified_membership(_valid_principal(), membership)


def test_scope_rejects_membership_for_another_principal() -> None:
    membership = TenantMembership("operator-99", "customer-1", "north-hub", True)
    with pytest.raises(TenantContextError, match="does not match"):
        TenantScope.from_verified_membership(_valid_principal(), membership)


def test_scope_rejects_direct_construction() -> None:
    with pytest.raises(TypeError, match="cannot be constructed directly"):
        TenantScope(
            subject_id="operator-17",
            tenant_id="customer-999",
            business_unit_id="restricted-hub",
        )


@pytest.mark.parametrize("value", [None, 1, 1.5, [], {}])
def test_identifier_rejects_non_string_values(value: object) -> None:
    with pytest.raises(ValueError, match="must be a string"):
        validate_identifier(value, field_name="identifier")  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["", " leading", "trailing ", "bad/value", "a" * 129])
def test_identifier_rejects_invalid_boundaries(value: str) -> None:
    with pytest.raises(ValueError, match="safe identifier"):
        validate_identifier(value, field_name="identifier")


@pytest.mark.parametrize("value", ["a", "A-1", "unit_1", "hub:west", "x" * 128])
def test_identifier_accepts_valid_opaque_values(value: str) -> None:
    assert validate_identifier(value, field_name="identifier") == value


@pytest.mark.parametrize("value", [1, 0, "true", None])
def test_principal_rejects_non_boolean_authentication_flag(value: object) -> None:
    with pytest.raises(TenantContextError, match="is_authenticated must be a boolean"):
        AuthenticatedPrincipal("operator-17", value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [1, 0, "true", None])
def test_membership_rejects_non_boolean_active_flag(value: object) -> None:
    with pytest.raises(TenantContextError, match="is_active must be a boolean"):
        TenantMembership("operator-17", "customer-1", "north-hub", value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "field_values",
    [
        ("bad/subject", "customer-1", "north-hub"),
        ("operator-17", "bad/tenant", "north-hub"),
        ("operator-17", "customer-1", "bad/business-unit"),
    ],
)
def test_membership_validates_every_identifier_field(
    field_values: tuple[str, str, str],
) -> None:
    with pytest.raises(TenantContextError):
        TenantMembership(*field_values, True)


def test_frozen_contract_objects_reject_mutation() -> None:
    principal = _valid_principal()
    membership = _valid_membership()
    scope = TenantScope.from_verified_membership(principal, membership)

    with pytest.raises(AttributeError):
        principal.subject_id = "operator-99"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        membership.tenant_id = "customer-999"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        scope.tenant_id = "customer-999"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("principal", "membership"),
    [
        (object(), _valid_membership()),
        (_valid_principal(), object()),
    ],
)
def test_factory_rejects_untrusted_object_types(principal: object, membership: object) -> None:
    with pytest.raises(TenantContextError):
        TenantScope.from_verified_membership(principal, membership)  # type: ignore[arg-type]
