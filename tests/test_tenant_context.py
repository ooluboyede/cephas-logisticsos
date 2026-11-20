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
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter


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


def _resolve(adapter: TrustedTenantContextAdapter | None = None) -> TenantScope:
    return (adapter or _adapter()).resolve(
        credential="validated-test-credential",
        tenant_id="customer-1",
        business_unit_id="north-hub",
    )


def test_trusted_adapter_resolves_scope_after_authentication_and_repository_lookup() -> None:
    scope = _resolve()
    assert (scope.subject_id, scope.tenant_id, scope.business_unit_id) == (
        "operator-17",
        "customer-1",
        "north-hub",
    )


def test_scope_factory_rejects_public_principal_and_membership_data_carriers() -> None:
    with pytest.raises(TenantContextError, match="trusted adapter-issued"):
        TenantScope.from_verified_membership(AuthenticatedPrincipal("operator-17", True))
    with pytest.raises(TenantContextError, match="trusted adapter-issued"):
        TenantScope.from_verified_membership(
            TenantMembership("operator-17", "customer-1", "north-hub", True)
        )


def test_adapter_rejects_unauthenticated_principal() -> None:
    with pytest.raises(TenantContextError, match="validated principal"):
        _resolve(_adapter(AuthenticatedPrincipal("operator-17", False)))


def test_adapter_rejects_inactive_authoritative_membership() -> None:
    with pytest.raises(TenantContextError, match="active authoritative membership"):
        _resolve(
            _adapter(membership=TenantMembership("operator-17", "customer-1", "north-hub", False))
        )


def test_adapter_rejects_membership_for_another_subject() -> None:
    with pytest.raises(TenantContextError, match="does not match"):
        _resolve(
            _adapter(membership=TenantMembership("operator-99", "customer-1", "north-hub", True))
        )


def test_adapter_rejects_missing_authoritative_membership() -> None:
    with pytest.raises(TenantContextError, match="was not found"):
        _resolve(
            TrustedTenantContextAdapter(
                FakeAuthentication(AuthenticatedPrincipal("operator-17", True)),
                FakeMembershipRepository(None),
            )
        )


def test_adapter_rejects_repository_membership_for_wrong_tenant() -> None:
    adapter = _adapter(
        membership=TenantMembership("operator-17", "customer-victim", "north-hub", True)
    )
    with pytest.raises(TenantContextError, match="membership tenant does not match"):
        _resolve(adapter)


def test_adapter_rejects_repository_membership_for_wrong_business_unit() -> None:
    adapter = _adapter(
        membership=TenantMembership("operator-17", "customer-1", "restricted-unit", True)
    )
    with pytest.raises(TenantContextError, match="membership business unit does not match"):
        _resolve(adapter)


def _private_adapter_import_violations(source: str) -> list[int]:
    """Return lines that reach the private issuer through import/attribute syntax."""
    tree = ast.parse(source)
    violations: list[int] = []
    private_module = "cephas_logisticsos.tenancy._trusted_adapter"
    package_module = "cephas_logisticsos.tenancy"

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(
                alias.name == private_module or alias.name.startswith(private_module + ".")
                for alias in node.names
            ):
                violations.append(node.lineno)
        elif isinstance(node, ast.ImportFrom):
            imports_private = (
                node.module == private_module
                or (
                    node.module == package_module
                    and any(alias.name == "_trusted_adapter" for alias in node.names)
                )
                or (
                    node.level > 0
                    and node.module is None
                    and any(alias.name == "_trusted_adapter" for alias in node.names)
                )
                or (node.level > 0 and node.module == "_trusted_adapter")
            )
            if imports_private:
                violations.append(node.lineno)
        elif isinstance(node, ast.Attribute) and node.attr == "_trusted_adapter":
            violations.append(node.lineno)

    return violations


@pytest.mark.parametrize(
    "source",
    [
        "from cephas_logisticsos.tenancy import _trusted_adapter",
        "from cephas_logisticsos.tenancy import _trusted_adapter as private",
        "from . import _trusted_adapter",
        "from . import _trusted_adapter as private",
        "from ._trusted_adapter import _issue_adapter_evidence",
        "import cephas_logisticsos.tenancy._trusted_adapter as private",
        "import cephas_logisticsos.tenancy as tenancy\nevidence = tenancy._trusted_adapter",
    ],
)
def test_private_adapter_import_guard_detects_package_and_relative_bypasses(
    source: str,
) -> None:
    assert _private_adapter_import_violations(source)


def test_architecture_restricts_private_evidence_module_imports() -> None:
    source_root = Path(__file__).parents[1] / "src"
    violations: list[str] = []
    for path in source_root.rglob("*.py"):
        if path.name == "_trusted_adapter.py":
            continue
        source = path.read_text(encoding="utf-8")
        for line in _private_adapter_import_violations(source):
            tree = ast.parse(source, filename=str(path))
            node = next((n for n in ast.walk(tree) if getattr(n, "lineno", None) == line), None)
            allowed = (
                path.name == "context.py"
                and isinstance(node, ast.ImportFrom)
                and node.module == "cephas_logisticsos.tenancy._trusted_adapter"
                and all(
                    item.name == "_AdapterIssuedTenantMembershipEvidence" for item in node.names
                )
            ) or (
                path.name == "trusted_context.py"
                and isinstance(node, ast.ImportFrom)
                and node.module == "cephas_logisticsos.tenancy._trusted_adapter"
                and all(item.name == "_issue_adapter_evidence" for item in node.names)
            )
            if not allowed:
                violations.append(f"{path}:{line}")
    assert violations == []


def test_adapter_construction_is_confined_to_composition_root() -> None:
    source_root = Path(__file__).parents[1] / "src"
    violations: list[str] = []
    for path in source_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Name) and node.func.id == "TrustedTenantContextAdapter")
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "TrustedTenantContextAdapter"
                )
            ):
                if path.name != "composition.py":
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
    scope = _resolve()
    with pytest.raises(AttributeError):
        principal.subject_id = "operator-99"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        membership.tenant_id = "customer-999"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        scope.tenant_id = "customer-999"  # type: ignore[misc]
