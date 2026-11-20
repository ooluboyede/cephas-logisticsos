import ast
from pathlib import Path

import pytest

from cephas_logisticsos.core.identifiers import validate_identifier
from cephas_logisticsos.tenancy import (
    AuthenticatedPrincipal,
    TenantContextError,
    TenantMembership,
    TenantScope,
)
from cephas_logisticsos.tenancy._trusted_adapter import TrustedTenantContextAdapter


class FakeAuthentication:
    def __init__(self, principal: AuthenticatedPrincipal) -> None:
        self.principal = principal

    def authenticate(self, credential: object) -> AuthenticatedPrincipal:
        assert credential == "validated-test-credential"
        return self.principal


class FakeMembershipRepository:
    def __init__(self, membership: TenantMembership | None) -> None:
        self.membership = membership

    def get_membership(
        self, *, subject_id: str, tenant_id: str, business_unit_id: str
    ) -> TenantMembership | None:
        if self.membership is not None:
            assert self.membership.subject_id == subject_id
            assert self.membership.tenant_id == tenant_id
            assert self.membership.business_unit_id == business_unit_id
        return self.membership


def _adapter(
    principal: AuthenticatedPrincipal | None = None,
    membership: TenantMembership | None = None,
) -> TrustedTenantContextAdapter:
    return TrustedTenantContextAdapter(
        FakeAuthentication(principal or AuthenticatedPrincipal("operator-17", True)),
        FakeMembershipRepository(
            membership or TenantMembership("operator-17", "customer-1", "north-hub", True)
        ),
    )


def test_trusted_adapter_resolves_scope_after_authentication_and_repository_lookup() -> None:
    scope = _adapter().resolve(
        credential="validated-test-credential",
        tenant_id="customer-1",
        business_unit_id="north-hub",
    )
    assert (scope.subject_id, scope.tenant_id, scope.business_unit_id) == (
        "operator-17", "customer-1", "north-hub"
    )


def test_scope_factory_rejects_public_principal_and_membership_data_carriers() -> None:
    with pytest.raises(TenantContextError, match="trusted adapter-issued"):
        TenantScope.from_verified_membership(
            AuthenticatedPrincipal("operator-17", True)
        )
    with pytest.raises(TenantContextError, match="trusted adapter-issued"):
        TenantScope.from_verified_membership(
            TenantMembership("operator-17", "customer-1", "north-hub", True)
        )


def test_adapter_rejects_unauthenticated_principal() -> None:
    with pytest.raises(TenantContextError, match="validated principal"):
        _adapter(AuthenticatedPrincipal("operator-17", False)).resolve(
            credential="validated-test-credential",
            tenant_id="customer-1",
            business_unit_id="north-hub",
        )


def test_adapter_rejects_inactive_authoritative_membership() -> None:
    with pytest.raises(TenantContextError, match="active authoritative membership"):
        _adapter(membership=TenantMembership("operator-17", "customer-1", "north-hub", False)).resolve(
            credential="validated-test-credential",
            tenant_id="customer-1",
            business_unit_id="north-hub",
        )


def test_adapter_rejects_membership_for_another_subject() -> None:
    with pytest.raises(TenantContextError, match="does not match"):
        _adapter(membership=TenantMembership("operator-99", "customer-1", "north-hub", True)).resolve(
            credential="validated-test-credential",
            tenant_id="customer-1",
            business_unit_id="north-hub",
        )


def test_adapter_rejects_missing_authoritative_membership() -> None:
    with pytest.raises(TenantContextError, match="was not found"):
        _adapter(membership=None).resolve(
            credential="validated-test-credential",
            tenant_id="customer-1",
            business_unit_id="north-hub",
        )


def test_architecture_restricts_private_evidence_module_imports() -> None:
    source_root = Path(__file__).parents[1] / "src"
    violations: list[str] = []
    for path in source_root.rglob("*.py"):
        if path.name == "_trusted_adapter.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "cephas_logisticsos.tenancy._trusted_adapter":
                allowed = path.name == "context.py" and node.names and all(
                    item.name == "_AdapterIssuedTenantMembershipEvidence"
                    for item in node.names
                )
                if not allowed:
                    violations.append(f"{path}:{node.lineno}")
            if isinstance(node, ast.ImportFrom) and node.module == "cephas_logisticsos.tenancy.context":
                if path.name == "_trusted_adapter.py" and any(
                    item.name.startswith("_issue") or item.name.startswith("_TRUSTED")
                    for item in node.names
                ):
                    violations.append(f"{path}:{node.lineno}")
    assert violations == []


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


def test_frozen_contract_objects_reject_mutation() -> None:
    principal = AuthenticatedPrincipal("operator-17", True)
    membership = TenantMembership("operator-17", "customer-1", "north-hub", True)
    scope = _adapter().resolve(
        credential="validated-test-credential",
        tenant_id="customer-1",
        business_unit_id="north-hub",
    )
    with pytest.raises(AttributeError):
        principal.subject_id = "operator-99"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        membership.tenant_id = "customer-999"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        scope.tenant_id = "customer-999"  # type: ignore[misc]
