import ast
from pathlib import Path

import pytest

from cephas_logisticsos.core.identifiers import validate_identifier
from cephas_logisticsos.security.trusted_boundary import (
    _production_source_boundary_violations,
    _trusted_boundary_call_violations,
    scan_source_tree,
)
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


@pytest.mark.parametrize(
    ("source", "expected_target"),
    [
        (
            "from cephas_logisticsos.tenancy.trusted_context import "
            "TrustedTenantContextAdapter as Adapter\nAdapter(auth, memberships)",
            "TrustedTenantContextAdapter",
        ),
        (
            "import cephas_logisticsos.tenancy.trusted_context as tc\n"
            "tc.TrustedTenantContextAdapter(auth, memberships)",
            "TrustedTenantContextAdapter",
        ),
        (
            "from cephas_logisticsos.tenancy.trusted_context import "
            "TrustedTenantContextAdapter\n"
            "Adapter = TrustedTenantContextAdapter\nAdapter(auth, memberships)",
            "TrustedTenantContextAdapter",
        ),
        (
            "from cephas_logisticsos.composition import "
            "build_tenant_context_adapter as compose\n"
            "compose(authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "import cephas_logisticsos.composition as composition\n"
            "composition.build_tenant_context_adapter("
            "authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "make_adapter = build_tenant_context_adapter\n"
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


def test_relative_import_aliases_are_resolved_for_nested_tenancy_modules() -> None:
    source = (
        "from ..trusted_context import TrustedTenantContextAdapter as Adapter\n"
        "Adapter(auth, memberships)"
    )
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.tenancy.handlers.request_handler",
    )
    assert any(target == "TrustedTenantContextAdapter" for _, target in violations)


def test_application_modules_cannot_use_substitute_providers_to_resolve_scope() -> None:
    unauthorized_sources = [
        (
            "from cephas_logisticsos.tenancy.trusted_context import "
            "TrustedTenantContextAdapter as Adapter\n"
            "class FakeAuthentication:\n"
            "    def authenticate(self, credential): return fake_principal\n"
            "class FakeMembershipRepository:\n"
            "    def get_membership(self, **kwargs): return fake_membership\n"
            "adapter = Adapter(FakeAuthentication(), FakeMembershipRepository())\n"
            "scope = adapter.resolve(credential='anything', tenant_id='victim', "
            "business_unit_id='restricted')\n"
        ),
        (
            "from cephas_logisticsos.composition import "
            "build_tenant_context_adapter as compose\n"
            "adapter = compose(authentication=FakeAuthentication(), "
            "memberships=FakeMembershipRepository())\n"
            "scope = adapter.resolve(credential='anything', tenant_id='victim', "
            "business_unit_id='restricted')\n"
        ),
    ]
    for source in unauthorized_sources:
        violations = _trusted_boundary_call_violations(
            source,
            module_name="cephas_logisticsos.handlers.request_handler",
        )
        assert violations


def test_trusted_boundary_guard_allows_constructor_only_in_composition_root() -> None:
    source = (
        "from cephas_logisticsos.tenancy.trusted_context import "
        "TrustedTenantContextAdapter\n"
        "def build(authentication, memberships):\n"
        "    return TrustedTenantContextAdapter(authentication, memberships)\n"
    )
    assert any(
        target == "TrustedTenantContextAdapter"
        for _, target in _trusted_boundary_call_violations(
            source,
            module_name="cephas_logisticsos.composition",
        )
    )


def test_adapter_construction_and_factory_calls_are_confined_to_composition_root() -> None:
    source_root = Path(__file__).parents[1] / "src"
    assert scan_source_tree(source_root) == []


def test_production_source_scan_rejects_tuple_unpacked_factory_and_constructor_aliases() -> None:
    unauthorized_module = """
from cephas_logisticsos.composition import build_tenant_context_adapter
factory, = (build_tenant_context_adapter,)
adapter = factory(authentication=fake_auth, memberships=fake_memberships)

from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
Adapter, = [TrustedTenantContextAdapter]
forbidden = Adapter(fake_auth, fake_memberships)
"""
    violations = _production_source_boundary_violations(
        {"cephas_logisticsos.handlers.request_handler": unauthorized_module}
    )
    assert any("build_tenant_context_adapter" in item for item in violations)
    assert any("TrustedTenantContextAdapter" in item for item in violations)


@pytest.mark.parametrize(
    ("source", "expected_target"),
    [
        (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "factory, = (build_tenant_context_adapter,)\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "Adapter, = [TrustedTenantContextAdapter]\n"
            "Adapter(fake_auth, fake_memberships)",
            "TrustedTenantContextAdapter",
        ),
        (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "factory = (build_tenant_context_adapter,)[0]\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "Adapter = [TrustedTenantContextAdapter][0]\n"
            "Adapter(fake_auth, fake_memberships)",
            "TrustedTenantContextAdapter",
        ),
    ],
)
def test_trusted_boundary_guard_resolves_destructuring_and_literal_index_aliases(
    source: str,
    expected_target: str,
) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == expected_target for _, target in violations)


@pytest.mark.parametrize(
    ("source", "expected_target"),
    [
        (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "factory = (build_tenant_context_adapter,)[-1]\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "Adapter = [TrustedTenantContextAdapter][-1]\n"
            "Adapter(fake_auth, fake_memberships)",
            "TrustedTenantContextAdapter",
        ),
        (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "factory, *remaining = (build_tenant_context_adapter,)\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "Adapter, *remaining = [TrustedTenantContextAdapter]\n"
            "Adapter(fake_auth, fake_memberships)",
            "TrustedTenantContextAdapter",
        ),
        (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "nested, = ((build_tenant_context_adapter,),)\n"
            "factory, = nested\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "nested, = ([TrustedTenantContextAdapter],)\n"
            "Adapter, = nested\n"
            "Adapter(fake_auth, fake_memberships)",
            "TrustedTenantContextAdapter",
        ),
    ],
)
def test_trusted_boundary_guard_resolves_negative_starred_and_nested_aliases(
    source: str,
    expected_target: str,
) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == expected_target for _, target in violations)


def test_production_source_scan_rejects_negative_starred_and_nested_aliases() -> None:
    unauthorized_modules = {
        "cephas_logisticsos.handlers.negative_factory": (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "factory = (build_tenant_context_adapter,)[-1]\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)"
        ),
        "cephas_logisticsos.handlers.starred_constructor": (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "Adapter, *remaining = [TrustedTenantContextAdapter]\n"
            "Adapter(fake_auth, fake_memberships)"
        ),
        "cephas_logisticsos.handlers.nested_factory": (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "nested, = ((build_tenant_context_adapter,),)\n"
            "factory, = nested\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)"
        ),
        "cephas_logisticsos.handlers.nested_constructor": (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "nested, = ([TrustedTenantContextAdapter],)\n"
            "Adapter, = nested\n"
            "Adapter(fake_auth, fake_memberships)"
        ),
    }
    violations = _production_source_boundary_violations(unauthorized_modules)
    assert any("build_tenant_context_adapter" in item for item in violations)
    assert any("TrustedTenantContextAdapter" in item for item in violations)
    assert len(violations) == 4


@pytest.mark.parametrize(
    ("source", "expected_target"),
    [
        (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "factory = build_tenant_context_adapter if condition else safe_factory\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "constructor = TrustedTenantContextAdapter if condition else SafeAdapter\n"
            "constructor(fake_auth, fake_memberships)",
            "TrustedTenantContextAdapter",
        ),
        (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "items = (build_tenant_context_adapter,)\n"
            "factory = items[-1]\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "constructors = [TrustedTenantContextAdapter]\n"
            "Adapter = constructors[0]\n"
            "Adapter(fake_auth, fake_memberships)",
            "TrustedTenantContextAdapter",
        ),
    ],
)
def test_trusted_boundary_guard_resolves_conditional_and_container_name_aliases(
    source: str,
    expected_target: str,
) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == expected_target for _, target in violations)


def test_production_source_scan_rejects_conditional_and_container_name_aliases() -> None:
    unauthorized_modules = {
        "cephas_logisticsos.handlers.conditional_factory": (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "factory = build_tenant_context_adapter if condition else safe_factory\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)"
        ),
        "cephas_logisticsos.handlers.conditional_constructor": (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "constructor = TrustedTenantContextAdapter if condition else SafeAdapter\n"
            "constructor(fake_auth, fake_memberships)"
        ),
        "cephas_logisticsos.handlers.indexed_factory": (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "items = (build_tenant_context_adapter,)\n"
            "factory = items[-1]\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)"
        ),
        "cephas_logisticsos.handlers.indexed_constructor": (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "constructors = [TrustedTenantContextAdapter]\n"
            "Adapter = constructors[0]\n"
            "Adapter(fake_auth, fake_memberships)"
        ),
    }
    violations = _production_source_boundary_violations(unauthorized_modules)
    assert len(violations) == 4
    assert any("build_tenant_context_adapter" in item for item in violations)
    assert any("TrustedTenantContextAdapter" in item for item in violations)


@pytest.mark.parametrize(
    ("source", "expected_target"),
    [
        (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "items = [build_tenant_context_adapter]\n"
            "factory = items[0]\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)",
            "build_tenant_context_adapter",
        ),
        (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "constructors = (TrustedTenantContextAdapter,)\n"
            "Adapter = constructors[-1]\n"
            "Adapter(fake_auth, fake_memberships)",
            "TrustedTenantContextAdapter",
        ),
        (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "constructor = SafeAdapter if condition else TrustedTenantContextAdapter\n"
            "constructor(fake_auth, fake_memberships)",
            "TrustedTenantContextAdapter",
        ),
    ],
)
def test_trusted_boundary_guard_resolves_remaining_container_indices_and_else_branch(
    source: str,
    expected_target: str,
) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == expected_target for _, target in violations)


def test_production_source_scan_rejects_remaining_container_indices_and_else_branch() -> None:
    unauthorized_modules = {
        "cephas_logisticsos.handlers.indexed_factory_positive": (
            "from cephas_logisticsos.composition import build_tenant_context_adapter\n"
            "items = [build_tenant_context_adapter]\n"
            "factory = items[0]\n"
            "factory(authentication=fake_auth, memberships=fake_memberships)"
        ),
        "cephas_logisticsos.handlers.indexed_constructor_negative": (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "constructors = (TrustedTenantContextAdapter,)\n"
            "Adapter = constructors[-1]\n"
            "Adapter(fake_auth, fake_memberships)"
        ),
        "cephas_logisticsos.handlers.conditional_constructor_else": (
            "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
            "constructor = SafeAdapter if condition else TrustedTenantContextAdapter\n"
            "constructor(fake_auth, fake_memberships)"
        ),
    }
    violations = _production_source_boundary_violations(unauthorized_modules)
    assert len(violations) == 3


@pytest.mark.parametrize(
    ("source", "expected_target"),
    [
        (
            """
from cephas_logisticsos.composition import build_tenant_context_adapter
containers = ([build_tenant_context_adapter],)
inner = containers[0]
factory = inner[0]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
            "build_tenant_context_adapter",
        ),
        (
            """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
containers = ([TrustedTenantContextAdapter],)
inner = containers[0]
Adapter = inner[-1]
Adapter(fake_auth, fake_memberships)
""",
            "TrustedTenantContextAdapter",
        ),
        (
            """
from cephas_logisticsos.composition import build_tenant_context_adapter
containers = ([build_tenant_context_adapter],)
factory = containers[0][0]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
            "build_tenant_context_adapter",
        ),
        (
            """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
containers = ([TrustedTenantContextAdapter],)
Adapter = containers[0][-1]
Adapter(fake_auth, fake_memberships)
""",
            "TrustedTenantContextAdapter",
        ),
    ],
)
def test_trusted_boundary_guard_resolves_nested_container_index_aliases(
    source: str,
    expected_target: str,
) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == expected_target for _, target in violations)


def test_production_source_scan_rejects_nested_container_index_aliases() -> None:
    unauthorized_modules = {
        "cephas_logisticsos.handlers.nested_assigned_factory": """
from cephas_logisticsos.composition import build_tenant_context_adapter
containers = ([build_tenant_context_adapter],)
inner = containers[0]
factory = inner[0]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        "cephas_logisticsos.handlers.nested_assigned_constructor": """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
containers = ([TrustedTenantContextAdapter],)
inner = containers[0]
Adapter = inner[-1]
Adapter(fake_auth, fake_memberships)
""",
        "cephas_logisticsos.handlers.nested_chained_factory": """
from cephas_logisticsos.composition import build_tenant_context_adapter
containers = ([build_tenant_context_adapter],)
factory = containers[0][0]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        "cephas_logisticsos.handlers.nested_chained_constructor": """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
containers = ([TrustedTenantContextAdapter],)
Adapter = containers[0][-1]
Adapter(fake_auth, fake_memberships)
""",
    }
    violations = _production_source_boundary_violations(unauthorized_modules)
    assert len(violations) == 4
    assert any("build_tenant_context_adapter" in item for item in violations)
    assert any("TrustedTenantContextAdapter" in item for item in violations)


def test_production_source_scan_preserves_exact_composition_root_exception() -> None:
    source = """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
containers = ([TrustedTenantContextAdapter],)
Adapter = containers[0][-1]
adapter = Adapter(authentication, memberships)
"""
    assert _production_source_boundary_violations({"cephas_logisticsos.composition": source}) == []


@pytest.mark.parametrize(
    ("source", "expected_target"),
    [
        (
            """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
def harmless_helper():
    TrustedTenantContextAdapter = SafeAdapter
adapter = TrustedTenantContextAdapter(fake_auth, fake_memberships)
""",
            "TrustedTenantContextAdapter",
        ),
        (
            """
from cephas_logisticsos.composition import build_tenant_context_adapter
def harmless_helper():
    build_tenant_context_adapter = safe_factory
adapter = build_tenant_context_adapter(authentication=fake_auth, memberships=fake_memberships)
""",
            "build_tenant_context_adapter",
        ),
        (
            """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
def outer():
    def inner():
        TrustedTenantContextAdapter = SafeAdapter
    return TrustedTenantContextAdapter(fake_auth, fake_memberships)
adapter = outer()
""",
            "TrustedTenantContextAdapter",
        ),
        (
            """
from cephas_logisticsos.composition import build_tenant_context_adapter
class Harmless:
    def helper(self):
        build_tenant_context_adapter = safe_factory
adapter = build_tenant_context_adapter(authentication=fake_auth, memberships=fake_memberships)
""",
            "build_tenant_context_adapter",
        ),
        (
            """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
def harmless_helper():
    from safe_module import TrustedTenantContextAdapter
adapter = TrustedTenantContextAdapter(fake_auth, fake_memberships)
""",
            "TrustedTenantContextAdapter",
        ),
    ],
)
def test_trusted_boundary_guard_keeps_module_bindings_separate_from_local_scopes(
    source: str,
    expected_target: str,
) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == expected_target for _, target in violations)


def test_local_shadowing_does_not_create_false_positive_inside_helper() -> None:
    source = """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
def harmless_helper():
    TrustedTenantContextAdapter = SafeAdapter
    return TrustedTenantContextAdapter(fake_auth, fake_memberships)
"""
    assert (
        _trusted_boundary_call_violations(
            source,
            module_name="cephas_logisticsos.handlers.request_handler",
        )
        == []
    )


def test_production_source_scan_rejects_module_calls_after_local_shadowing() -> None:
    unauthorized_modules = {
        "cephas_logisticsos.handlers.local_constructor_shadow": """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
def harmless_helper():
    TrustedTenantContextAdapter = SafeAdapter
adapter = TrustedTenantContextAdapter(fake_auth, fake_memberships)
""",
        "cephas_logisticsos.handlers.local_factory_shadow": """
from cephas_logisticsos.composition import build_tenant_context_adapter
def harmless_helper():
    build_tenant_context_adapter = safe_factory
adapter = build_tenant_context_adapter(authentication=fake_auth, memberships=fake_memberships)
""",
        "cephas_logisticsos.handlers.nested_local_shadow": """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
def outer():
    def inner():
        TrustedTenantContextAdapter = SafeAdapter
    return TrustedTenantContextAdapter(fake_auth, fake_memberships)
""",
        "cephas_logisticsos.handlers.class_local_shadow": """
from cephas_logisticsos.composition import build_tenant_context_adapter
class Harmless:
    build_tenant_context_adapter = safe_factory
adapter = build_tenant_context_adapter(authentication=fake_auth, memberships=fake_memberships)
""",
    }
    violations = _production_source_boundary_violations(unauthorized_modules)
    assert len(violations) == 4
    assert any("TrustedTenantContextAdapter" in item for item in violations)
    assert any("build_tenant_context_adapter" in item for item in violations)


def test_production_source_scan_does_not_confuse_local_import_with_module_import() -> None:
    source = """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
def harmless_helper():
    from safe_module import TrustedTenantContextAdapter
    return TrustedTenantContextAdapter(fake_auth, fake_memberships)
adapter = TrustedTenantContextAdapter(fake_auth, fake_memberships)
"""
    violations = _production_source_boundary_violations(
        {"cephas_logisticsos.handlers.local_import_shadow": source}
    )
    assert len(violations) == 1
    assert "TrustedTenantContextAdapter" in violations[0]


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


@pytest.mark.parametrize(
    ("source", "expected_target"),
    [
        (
            """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
def handler(adapter=TrustedTenantContextAdapter(fake_auth, fake_memberships)):
    pass
""",
            "TrustedTenantContextAdapter",
        ),
        (
            """
from cephas_logisticsos.composition import build_tenant_context_adapter
@build_tenant_context_adapter(authentication=fake_auth, memberships=fake_memberships)
def handler():
    pass
""",
            "build_tenant_context_adapter",
        ),
        (
            """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
class Handler(TrustedTenantContextAdapter(fake_auth, fake_memberships)):
    pass
""",
            "TrustedTenantContextAdapter",
        ),
    ],
)
def test_definition_time_expressions_are_scanned_in_enclosing_scope(
    source: str,
    expected_target: str,
) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == expected_target for _, target in violations)


def test_production_source_scan_rejects_definition_time_trusted_calls() -> None:
    unauthorized_modules = {
        "cephas_logisticsos.handlers.default_constructor": """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
def handler(adapter=TrustedTenantContextAdapter(fake_auth, fake_memberships)):
    pass
""",
        "cephas_logisticsos.handlers.decorator_factory": """
from cephas_logisticsos.composition import build_tenant_context_adapter
@build_tenant_context_adapter(authentication=fake_auth, memberships=fake_memberships)
def handler():
    pass
""",
        "cephas_logisticsos.handlers.class_base_constructor": """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
class Handler(TrustedTenantContextAdapter(fake_auth, fake_memberships)):
    pass
""",
    }
    violations = _production_source_boundary_violations(unauthorized_modules)
    assert len(violations) == 3
    assert any("TrustedTenantContextAdapter" in item for item in violations)
    assert any("build_tenant_context_adapter" in item for item in violations)


def test_definition_time_safe_expressions_and_composition_root_exception() -> None:
    safe_source = """
from safe_module import SafeAdapter, safe_decorator, SafeBase
@safe_decorator
def handler(adapter=SafeAdapter()):
    pass
class Handler(SafeBase):
    pass
"""
    assert (
        _trusted_boundary_call_violations(
            safe_source,
            module_name="cephas_logisticsos.handlers.request_handler",
        )
        == []
    )

    composition_source = """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
@TrustedTenantContextAdapter(authentication, memberships)
def handler():
    pass
"""
    assert (
        _production_source_boundary_violations(
            {"cephas_logisticsos.composition": composition_source}
        )
        == []
    )


@pytest.mark.parametrize(
    "source",
    [
        """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
constructors = [TrustedTenantContextAdapter]
index = choose_constructor()
factory = constructors[index]
factory(fake_auth, fake_memberships)
""",
        """
import cephas_logisticsos.composition as trusted_composition
factory = getattr(trusted_composition, selected_factory_name)
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {"adapter": build_tenant_context_adapter}
factory = registry[selected_name]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
constructors = [TrustedTenantContextAdapter]
first = constructors[choose_index()]
second = first
second(fake_auth, fake_memberships)
""",
    ],
)
def test_unsupported_expressions_referencing_trusted_symbols_are_indeterminate(
    source: str,
) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == "indeterminate-trusted-boundary-call" for _, target in violations)


def test_production_source_scan_fails_closed_for_unsupported_trusted_aliases() -> None:
    sources = {
        "cephas_logisticsos.handlers.dynamic_index": """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
constructors = [TrustedTenantContextAdapter]
index = choose_constructor()
factory = constructors[index]
factory(fake_auth, fake_memberships)
""",
        "cephas_logisticsos.handlers.dynamic_reflection": """
import cephas_logisticsos.composition as trusted_composition
factory = getattr(trusted_composition, selected_factory_name)
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        "cephas_logisticsos.handlers.unresolved_container": """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {"adapter": build_tenant_context_adapter}
factory = registry[selected_name]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
    }
    violations = _production_source_boundary_violations(sources)
    assert len(violations) == 3
    assert all("indeterminate-trusted-boundary-call" in item for item in violations)


@pytest.mark.parametrize(
    "source",
    [
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry:
    pass
registry = Registry()
registry.factory = build_tenant_context_adapter
factory = registry.factory
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
class Registry:
    pass
registry = Registry()
registry.inner = Registry()
registry.inner.constructor = TrustedTenantContextAdapter
constructor = registry.inner.constructor
constructor(fake_auth, fake_memberships)
""",
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
registry["factory"] = build_tenant_context_adapter
factory = registry[selected_name]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
registry = [None]
registry[selected_index] = TrustedTenantContextAdapter
constructor = registry[selected_index]
constructor(fake_auth, fake_memberships)
""",
    ],
)
def test_mutated_attribute_and_container_aliases_are_indeterminate(source: str) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == "indeterminate-trusted-boundary-call" for _, target in violations)


def test_production_source_scan_rejects_mutated_attribute_and_container_aliases() -> None:
    sources = {
        "cephas_logisticsos.handlers.attribute_mutation": """
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry:
    pass
registry = Registry()
registry.factory = build_tenant_context_adapter
factory = registry.factory
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        "cephas_logisticsos.handlers.dictionary_mutation": """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
registry["factory"] = build_tenant_context_adapter
factory = registry[selected_name]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        "cephas_logisticsos.handlers.list_mutation": """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
registry = [None]
registry[selected_index] = TrustedTenantContextAdapter
constructor = registry[selected_index]
constructor(fake_auth, fake_memberships)
""",
    }
    violations = _production_source_boundary_violations(sources)
    assert len(violations) == 3
    assert all("indeterminate-trusted-boundary-call" in item for item in violations)


@pytest.mark.parametrize(
    "source",
    [
        # Alias exists before the trusted write: both names must become tainted.
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
alias = registry
registry[\"factory\"] = build_tenant_context_adapter
factory = alias[selected_name]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
alias = registry
registry.factory = build_tenant_context_adapter
factory = alias.factory
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        # Nested aliases conservatively share the tracked root identity.
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
outer = Registry()
inner = outer
inner.child = Registry()
child = outer.child
child.factory = build_tenant_context_adapter
factory = child.factory
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        # Common mutator methods and setattr must taint pre-existing aliases.
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
alias = registry
registry.update({\"factory\": build_tenant_context_adapter})
factory = alias[selected_name]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = []
alias = registry
registry.append(build_tenant_context_adapter)
factory = alias[selected_index]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = []
alias = registry
registry.extend([build_tenant_context_adapter])
factory = alias[selected_index]
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
alias = registry
setattr(registry, selected_name, build_tenant_context_adapter)
factory = alias.factory
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        # Unsupported storage roots are explicitly indeterminate.
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
get_registry().factory = build_tenant_context_adapter
""",
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
get_registry().update({\"factory\": build_tenant_context_adapter})
""",
    ],
)
def test_r20_alias_aware_storage_and_mutator_flows_fail_closed(source: str) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert violations
    assert any(
        "indeterminate" in target
        or target in {"build_tenant_context_adapter", "TrustedTenantContextAdapter"}
        for _, target in violations
    )


def test_r20_storage_alias_reassignment_and_unrelated_objects_remain_separate() -> None:
    safe_source = """
from safe_module import safe_factory
first = {}
second = {}
alias = first
alias = second
second.update({\"factory\": safe_factory})
factory = first.get if hasattr(first, \"get\") else safe_factory
factory()
"""
    assert (
        _trusted_boundary_call_violations(
            safe_source,
            module_name="cephas_logisticsos.handlers.request_handler",
        )
        == []
    )


def test_r20_production_scanner_rejects_alias_and_mutator_storage_patterns() -> None:
    sources = {
        "cephas_logisticsos.handlers.alias_update": """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
alias = registry
registry.update({\"factory\": build_tenant_context_adapter})
alias[selected_name](authentication=fake_auth, memberships=fake_memberships)
""",
        "cephas_logisticsos.handlers.alias_setattr": """
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
alias = registry
setattr(registry, selected_name, build_tenant_context_adapter)
alias.factory(authentication=fake_auth, memberships=fake_memberships)
""",
        "cephas_logisticsos.handlers.dynamic_root": """
from cephas_logisticsos.composition import build_tenant_context_adapter
get_registry().factory = build_tenant_context_adapter
""",
    }
    violations = _production_source_boundary_violations(sources)
    assert len(violations) >= 3


def test_attribute_and_container_taint_preserves_unrelated_safe_storage() -> None:
    source = """
from safe_module import safe_factory
class Registry:
    pass
registry = Registry()
registry.factory = safe_factory
factory = registry.factory
factory()
items = []
items.append(safe_factory)
other = items[0]
other()
"""
    assert (
        _trusted_boundary_call_violations(
            source,
            module_name="cephas_logisticsos.handlers.request_handler",
        )
        == []
    )


def test_unsupported_alias_taint_propagates_but_unrelated_indirect_calls_remain_allowed() -> None:
    trusted_source = """
from cephas_logisticsos.composition import build_tenant_context_adapter
factory = resolve_from_registry(build_tenant_context_adapter)
another_name = factory
another_name(authentication=fake_auth, memberships=fake_memberships)
"""
    ordinary_source = """
from safe_module import safe_factory
factory = resolve_from_registry(safe_factory)
factory()
"""
    trusted_violations = _trusted_boundary_call_violations(
        trusted_source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    ordinary_violations = _trusted_boundary_call_violations(
        ordinary_source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == "indeterminate-trusted-boundary-call" for _, target in trusted_violations)
    assert ordinary_violations == []


def test_unsupported_expression_taint_respects_local_shadowing() -> None:
    source = """
from cephas_logisticsos.composition import build_tenant_context_adapter
def harmless_helper():
    build_tenant_context_adapter = safe_factory
    factory = resolve_from_registry(build_tenant_context_adapter)
    factory()
"""
    assert (
        _trusted_boundary_call_violations(
            source,
            module_name="cephas_logisticsos.handlers.request_handler",
        )
        == []
    )


def test_unsupported_expression_taint_flows_through_assigned_literal_containers() -> None:
    source = """
from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter
constructors = [TrustedTenantContextAdapter]
index = choose_constructor()
factory = constructors[index]
second = factory
second(fake_auth, fake_memberships)
"""
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert any(target == "indeterminate-trusted-boundary-call" for _, target in violations)


@pytest.mark.parametrize(
    "source",
    [
        """
import operator
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
alias = registry
operator.setitem(registry, "factory", build_tenant_context_adapter)
factory = operator.getitem(alias, "factory")
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from operator import setitem as put, getitem as fetch
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
alias = registry
put(alias, "factory", build_tenant_context_adapter)
factory = fetch(registry, "factory")
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
import operator as op
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
op.setitem(registry, "factory", build_tenant_context_adapter)
op.getitem(registry, "factory")(authentication=fake_auth, memberships=fake_memberships)
""",
        """
import operator
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
registry["factory"] = build_tenant_context_adapter
factory = operator.getitem(registry, dynamic_key)
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
alias = registry
setattr(registry, "factory", build_tenant_context_adapter)
factory = getattr(alias, "factory")
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
setattr(registry, dynamic_name, build_tenant_context_adapter)
getattr(registry, dynamic_name)(authentication=fake_auth, memberships=fake_memberships)
""",
    ],
)
def test_r21_standard_library_storage_mutation_and_retrieval_fail_closed(source: str) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert violations
    assert any("indeterminate" in target for _, target in violations)


def test_r21_direct_storage_assignment_then_operator_getitem_is_rejected() -> None:
    source = """
import operator
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
registry["factory"] = build_tenant_context_adapter
factory = operator.getitem(registry, "factory")
factory(authentication=fake_auth, memberships=fake_memberships)
"""
    assert _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )


def test_r21_production_source_scanner_rejects_complete_standard_library_bypasses() -> None:
    sources = {
        "cephas_logisticsos.handlers.operator_storage": """
import operator
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
alias = registry
operator.setitem(registry, "factory", build_tenant_context_adapter)
factory = operator.getitem(alias, "factory")
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        "cephas_logisticsos.handlers.reflected_storage": """
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
alias = registry
setattr(registry, "factory", build_tenant_context_adapter)
factory = getattr(alias, dynamic_attribute)
factory(authentication=fake_auth, memberships=fake_memberships)
""",
    }
    violations = _production_source_boundary_violations(sources)
    assert len(violations) >= 2


def test_r21_dynamic_retrieval_from_tainted_storage_is_indeterminate() -> None:
    source = """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
registry[selected_key] = build_tenant_context_adapter
factory = registry[another_dynamic_key]
factory(authentication=fake_auth, memberships=fake_memberships)
"""
    assert _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )


def test_r21_unrelated_operator_storage_and_safe_factory_remain_allowed() -> None:
    source = """
import operator
from safe_module import safe_factory
registry = {}
operator.setitem(registry, "factory", safe_factory)
factory = operator.getitem(registry, "factory")
factory()
class Registry: pass
obj = Registry()
setattr(obj, "factory", safe_factory)
getattr(obj, "factory")()
"""
    assert (
        _trusted_boundary_call_violations(
            source,
            module_name="cephas_logisticsos.handlers.request_handler",
        )
        == []
    )


@pytest.mark.parametrize(
    "source",
    [
        """
import builtins as bi
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
alias = registry
bi.setattr(registry, "factory", build_tenant_context_adapter)
factory = bi.getattr(alias, "factory")
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from builtins import setattr as put, getattr as fetch
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
alias = registry
put(alias, "factory", build_tenant_context_adapter)
factory = fetch(registry, "factory")
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
import builtins as bi
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
put = bi.setattr
fetch = bi.getattr
put_alias = put
fetch_alias = fetch
put_alias(registry, dynamic_name, build_tenant_context_adapter)
factory = fetch_alias(registry, dynamic_name)
factory(authentication=fake_auth, memberships=fake_memberships)
""",
        """
from builtins import setattr as put, getattr as fetch
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
put_alias = put
fetch_alias = fetch
put_alias(registry, "factory", build_tenant_context_adapter)
fetch_alias(registry, "factory")(authentication=fake_auth, memberships=fake_memberships)
""",
    ],
)
def test_r22_builtin_storage_aliases_fail_closed_at_final_invocation(source: str) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    final_invocation_line = len(source.splitlines())
    assert (final_invocation_line, "indeterminate-trusted-boundary-call") in violations


def test_r22_shadowed_setattr_and_getattr_names_are_not_treated_as_builtins() -> None:
    source = """
def handler(setattr, getattr):
    setattr = safe_writer
    getattr = safe_reader
    setattr(registry, "factory", safe_factory)
    factory = getattr(registry, "factory")
    factory()
"""
    assert (
        _trusted_boundary_call_violations(
            source,
            module_name="cephas_logisticsos.handlers.request_handler",
        )
        == []
    )


def test_r22_builtin_aliases_are_detected_by_production_source_scanner() -> None:
    sources = {
        "cephas_logisticsos.handlers.builtin_storage": """
import builtins as bi
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
put = bi.setattr
fetch = bi.getattr
put(registry, "factory", build_tenant_context_adapter)
fetch(registry, "factory")(authentication=fake_auth, memberships=fake_memberships)
""",
        "cephas_logisticsos.handlers.imported_builtin_storage": """
from builtins import setattr as put, getattr as fetch
from cephas_logisticsos.composition import build_tenant_context_adapter
class Registry: pass
registry = Registry()
put(registry, "factory", build_tenant_context_adapter)
factory = fetch(registry, "factory")
factory(authentication=fake_auth, memberships=fake_memberships)
""",
    }
    violations = _production_source_boundary_violations(sources)
    assert len(violations) >= 2


def test_r22_safe_builtin_retrieval_without_trusted_storage_remains_allowed() -> None:
    source = """
import builtins as bi
class Registry: pass
registry = Registry()
bi.setattr(registry, "factory", safe_factory)
factory = bi.getattr(registry, "factory")
factory()
"""
    assert (
        _trusted_boundary_call_violations(
            source,
            module_name="cephas_logisticsos.handlers.request_handler",
        )
        == []
    )


@pytest.mark.parametrize(
    "source",
    [
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = {}
registry["factory"] = build_tenant_context_adapter
registry["factory"] = safe_factory
factory = registry["factory"]
factory()
""",
        """
from cephas_logisticsos.composition import build_tenant_context_adapter
registry = [safe_factory]
registry[0] = build_tenant_context_adapter
factory = registry[0]
factory()
""",
        """
registry = {}
registry["factory"] = safe_factory
registry["factory"] = build_tenant_context_adapter
factory = registry["factory"]
factory()
""",
    ],
)
def test_trusted_boundary_storage_replacement_remains_fail_closed(source: str) -> None:
    violations = _trusted_boundary_call_violations(
        source,
        module_name="cephas_logisticsos.handlers.request_handler",
    )
    assert (len(source.splitlines()) - 1, "indeterminate-trusted-boundary-call") in violations


def test_trusted_boundary_scanner_respects_parameter_shadowing() -> None:
    source = """
def handler(setattr, getattr, safe_factory):
    writer = setattr
    reader = getattr
    writer(object(), "factory", safe_factory)
    factory = reader(object(), "factory")
    factory()
"""
    assert (
        _trusted_boundary_call_violations(
            source,
            module_name="cephas_logisticsos.handlers.request_handler",
        )
        == []
    )
