# Gate 0.1.2 — Core Tenant Context Contract

**Status: focused trusted-adapter boundary remediation submitted; independent acceptance pending.**

## Scope

Define immutable untrusted principal and membership data carriers, a dedicated trusted-adapter composition boundary, and an immutable tenant/business-unit scope contract.

## Public data carriers are not proof

`AuthenticatedPrincipal` and `TenantMembership` validate data shape only. Constructing either object does not prove authentication, credential provenance, authoritative membership, or authorization.

Request headers, query parameters, body fields, and client-selected tenant identifiers are not authoritative evidence of identity or membership.

## Trusted adapter responsibilities

`TrustedTenantContextAdapter` is constructed only in `cephas_logisticsos.composition`, the designated application composition root. Its injected authentication provider and membership repository are trusted deployment-controlled dependencies; request handlers and request-scoped code must not construct substitute providers or instantiate the adapter. A source-level AST architecture test enforces that both `TrustedTenantContextAdapter` construction and calls to `build_tenant_context_adapter()` occur only in `composition.py`. The test resolves ordinary imported aliases, module aliases, simple name assignments, tuple/list destructuring aliases, literal tuple/list indexing aliases, and relative imports before checking call targets. Its `resolve` flow:

1. Passes the presented credential to the configured authentication provider.
2. Requires the provider to return a validated principal established from successful credential validation.
3. Queries the configured server-side membership repository using that principal subject and the requested tenant/business-unit selection.
4. Requires an active membership record whose subject matches the authenticated principal and whose tenant/business-unit match the requested scope.
5. Independently compares the returned membership tenant and business-unit IDs with the requested IDs; mismatches are rejected even if a repository implementation returns an incorrect record.
6. Issues `_AdapterIssuedTenantMembershipEvidence` and passes it to the scope factory.

The authentication provider and membership repository are injected dependencies. Their production implementations are not included in Gate 0.1.2 and must be created by deployment-controlled startup wiring and passed to the composition root. Request handlers and ordinary application modules must receive the already-composed adapter; they must not instantiate the adapter or call the composition factory with substitute providers. The repository must be authoritative and server-side; it must not simply echo request-controlled membership claims. Dependency injection is a trust decision: fabricated providers invalidate the contract.

## Enforced source construction boundary

The AST architecture test resolves imported names and module aliases, including simple name assignments, tuple/list destructuring, and literal tuple/list indexing, and rejects calls to `TrustedTenantContextAdapter` or `build_tenant_context_adapter()` outside `cephas_logisticsos.composition`. It also rejects star imports from the trusted adapter and composition modules outside the composition root. Regression fixtures cover aliased constructor calls, module-qualified constructor calls, simple assignment aliases, tuple/list-unpacking aliases, literal tuple/list-indexing aliases, and direct, aliased, and module-qualified composition-factory calls from an ordinary application module. The production-source scan itself is also exercised against an ordinary request-handler fixture containing tuple-unpacked constructor and factory aliases.

This control is intentionally a source-level architecture rule for ordinary statically expressed Python code. It is not a runtime authorization mechanism and does not prevent arbitrary same-process code from dynamically obtaining callables, monkey-patching modules, or executing code outside the reviewed source tree. Deployment startup wiring remains the trusted composition point.

## Enforced source import boundary

The private evidence issuer and capability live only in `tenancy/_trusted_adapter.py`. The scope factory imports only the evidence marker needed for exact-type validation. A source-level AST architecture test rejects direct imports, package-submodule imports, relative package-submodule imports, aliases, and attribute access to the private adapter module from other production modules and is run as part of the ordinary pytest CI suite.

This is a Python application architecture guard, not a security sandbox. Code with arbitrary execution inside the same process can use reflection, dynamic imports, monkey-patching, or other runtime techniques to bypass Python-level conventions. The guard prevents accidental/direct source-level coupling and regression; it is not a cryptographic or process-isolation boundary.

## Implemented in this gate

- Immutable public principal and membership data carriers with strict field validation.
- Dedicated trusted adapter contract separating credential validation from authoritative membership lookup.
- Adapter-issued evidence terminology; evidence itself is not proof unless the configured adapter fulfilled its responsibilities.
- Scope factory accepts only the adapter evidence type; direct scope construction remains disabled.
- CI architecture tests restricting production source imports of the private evidence module and restricting trusted-adapter construction and composition-factory calls to the designated composition root, including ordinary aliases.
- Regression tests for successful adapter flow, untrusted public carriers, unauthenticated principal, inactive/missing membership, mismatched subject, wrong returned tenant, wrong returned business unit, package and relative import bypasses, aliased constructor and factory-call bypasses, composition-root construction boundary, identifier validation and immutability.

## Explicitly not implemented

- Production authentication provider or identity-provider integration.
- Production authoritative membership repository.
- Authorization policy evaluation.
- PostgreSQL Row-Level Security (RLS).
- Transaction-scoped database context or connection-pool isolation.
- Cross-tenant isolation for background jobs, exports, caches or storage.
- Tenant-isolated ML training or model operations.
- Production penetration testing or deployment certification.

These remain mandatory later-gate controls. This contract does not claim production readiness or certify deployed tenant isolation.

## Acceptance evidence

- Trusted adapter flow obtains principal from the authentication provider and membership from the authoritative repository interface.
- Public caller-created data carriers cannot be passed directly to the scope factory.
- Production-source import-boundary regression test passes.
- Negative, boundary, wrong-type and immutability tests pass.
- Ruff lint and formatting, Mypy strict, full test suite and configured coverage pass on the exact submitted commit.
- Independent reassessment accepts the exact commit.
