import pytest

from cephas_logisticsos.tenancy import (
    AuthenticatedPrincipal,
    TenantContextError,
    TenantMembership,
    TenantScope,
)


def test_scope_is_created_for_matching_active_membership() -> None:
    principal = AuthenticatedPrincipal("operator-17", is_authenticated=True)
    membership = TenantMembership(
        subject_id="operator-17",
        tenant_id="customer-1",
        business_unit_id="north-hub",
        is_active=True,
    )
    scope = TenantScope.from_verified_membership(principal, membership)
    assert scope.subject_id == "operator-17"
    assert scope.tenant_id == "customer-1"
    assert scope.business_unit_id == "north-hub"


def test_scope_rejects_unauthenticated_principal() -> None:
    principal = AuthenticatedPrincipal("operator-17", is_authenticated=False)
    membership = TenantMembership("operator-17", "customer-1", "north-hub", True)
    with pytest.raises(TenantContextError, match="authenticated principal"):
        TenantScope.from_verified_membership(principal, membership)


def test_scope_rejects_inactive_membership() -> None:
    principal = AuthenticatedPrincipal("operator-17", is_authenticated=True)
    membership = TenantMembership("operator-17", "customer-1", "north-hub", False)
    with pytest.raises(TenantContextError, match="inactive"):
        TenantScope.from_verified_membership(principal, membership)


def test_scope_rejects_membership_for_another_principal() -> None:
    principal = AuthenticatedPrincipal("operator-17", is_authenticated=True)
    membership = TenantMembership("operator-99", "customer-1", "north-hub", True)
    with pytest.raises(TenantContextError, match="does not match"):
        TenantScope.from_verified_membership(principal, membership)


def test_membership_rejects_unsafe_identifiers() -> None:
    with pytest.raises(TenantContextError, match="tenant_id"):
        TenantMembership("operator-17", "customer/1", "north-hub", True)
