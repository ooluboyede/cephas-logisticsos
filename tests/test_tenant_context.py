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


def _resolve_imported_symbol(
    expression: ast.expr,
    imported_symbols: dict[str, str],
) -> str | None:
    if isinstance(expression, ast.Name):
        return imported_symbols.get(expression.id, expression.id)
    if isinstance(expression, ast.Attribute):
        parent = _resolve_imported_symbol(expression.value, imported_symbols)
        return f"{parent}.{expression.attr}" if parent else None
    return None


def _trusted_boundary_call_violations(
    source: str,
    *,
    module_name: str,
) -> list[tuple[int, str]]:
    """Resolve ordinary Python import/assignment aliases for trusted constructors."""
    tree = ast.parse(source)
    imported_symbols: dict[str, str] = {}
    violations: list[tuple[int, str]] = []
    package_name = module_name.rpartition(".")[0]
    constructor = (
        "cephas_logisticsos.tenancy.trusted_context.TrustedTenantContextAdapter"
    )
    factory = "cephas_logisticsos.composition.build_tenant_context_adapter"
    trusted_modules = {
        "cephas_logisticsos.tenancy.trusted_context",
        "cephas_logisticsos.composition",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                imported_symbols[local_name] = alias.name if alias.asname else local_name
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                package_parts = package_name.split(".") if package_name else []
                keep = max(0, len(package_parts) - node.level + 1)
                prefix = ".".join(package_parts[:keep])
                if node.module:
                    prefix = ".".join(part for part in (prefix, node.module) if part)
            else:
                prefix = node.module or ""
            if any(alias.name == "*" for alias in node.names):
                if prefix in trusted_modules:
                    violations.append((node.lineno, f"star-import:{prefix}"))
                continue
            for alias in node.names:
                local_name = alias.asname or alias.name
                imported_symbols[local_name] = ".".join(
                    part for part in (prefix, alias.name) if part
                )

    # Resolve simple assignment aliases such as AdapterAlias = Adapter.
    for _ in range(len(imported_symbols) + 1):
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if value is None:
                continue
            resolved = _resolve_imported_symbol(value, imported_symbols)
            if not resolved:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and imported_symbols.get(target.id) != resolved:
                    imported_symbols[target.id] = resolved
                    changed = True
        if not changed:
            break

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        resolved = _resolve_imported_symbol(node.func, imported_symbols)
        if resolved == constructor:
            violations.append((node.lineno, "TrustedTenantContextAdapter"))
        elif resolved == factory:
            violations.append((node.lineno, "build_tenant_context_adapter"))
    return violations


@pytest.mark.parametrize(
    ("source", "expected_target"),
    [
        (
            "from cephas_logisticsos.tenancy.trusted_context import "
            "TrustedTenantContextAdapter as Adapter\\nAdapter(auth, memberships)",
            "TrustedTenantContextAdapter",
        ),
        (
            "import cephas_logisticsos.tenancy.trusted_context as tc\\n"
            "tc.TrustedTenantContextAdapter(auth, memberships)",
            "TrustedTenantContextAdapter",
        ),
        (
            "from cephas_logisticsos.tenancy.trusted_context import "
            "TrustedTenantContextAdapter\\n"
            "Adapter = TrustedTenantContextAdapter\\nAdapter(auth, memberships)",
            "TrustedTenantContextAdapter",
        ),
        (
            "from cephas_logisticsos.composition import "
            "build_tenant_context_adapter as compose\\n"
            "compose(authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "import cephas_logisticsos.composition as composition\\n"
            "composition.build_tenant_context_adapter("
            "authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\\n"
            "make_adapter = build_tenant_context_adapter\\n"
            "make_adapter(authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
    ],
)
def test_trusted_boundary_guard_resolves_aliases_and_factory_calls(
    source: str,
    expected_target: str,
) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == expected_target for _, target in violations)


def test_trusted_boundary_guard_allows_constructor_only_in_composition_root() -> None:
    source = (
        "from cephas_logisticsos.tenancy.trusted_context import "
        "TrustedTenantContextAdapter\\n"
        "def build(authentication, memberships):\\n"
        "    return TrustedTenantContextAdapter(authentication, memberships)\\n"
    )
    assert _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.composition",
    ) == []


def test_adapter_construction_and_factory_calls_are_confined_to_composition_root() -> None:
    source_root = Path(__file__).parents[1] / "src"
    violations: list[str] = []
    for path in source_root.rglob("*.py"):
        module_name = ".".join(path.relative_to(source_root).with_suffix("").parts)
        for line, target in _trusted_boundary_call_violations(
            path.read_text(encoding="utf-8"),
            module_name=module_name,
        ):
            if module_name != "cephas_logisticsos.composition":
                violations.append(f"{path}:{line}:{target}")
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
