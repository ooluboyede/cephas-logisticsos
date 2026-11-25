# Gate 0.1.2 — Core Tenant Context Contract

**Status: focused trusted-adapter boundary remediation submitted; independent acceptance pending.**

## Scope

Define immutable untrusted principal and membership data carriers, a dedicated trusted-adapter composition boundary, and an immutable tenant/business-unit scope contract.

## Public data carriers are not proof

`AuthenticatedPrincipal` and `TenantMembership` validate data shape only. Constructing either object does not prove authentication, credential provenance, authoritative membership, or authorization.

Request headers, query parameters, body fields, and client-selected tenant identifiers are not authoritative evidence of identity or membership.

## Trusted adapter responsibilities

`TrustedTenantContextAdapter` is constructed only in `cephas_logisticsos.composition`, the designated application composition root. Its injected authentication provider and membership repository are trusted deployment-controlled dependencies; request handlers and request-scoped code must not construct substitute providers or instantiate the adapter. A source-level AST architecture test enforces that both `TrustedTenantContextAdapter` construction and calls to `build_tenant_context_adapter()` occur only in `composition.py`. The test resolves ordinary imported aliases, module aliases, simple name assignments, tuple/list destructuring aliases, recursively nested literal tuple/list indexing (including chained indexing and indexing through assigned intermediate containers), conditional expressions by examining both branches, and relative imports before checking call targets. Its accepted indexing grammar is restricted to literal tuple/list containers and positive or negative integer literal indices. Dynamic indices, computed containers, calls, attributes used as containers, and other unsupported expressions are not proof of safety and are outside this gate's static alias guarantee. Its `resolve` flow:

1. Passes the presented credential to the configured authentication provider.
2. Requires the provider to return a validated principal established from successful credential validation.
3. Queries the configured server-side membership repository using that principal subject and the requested tenant/business-unit selection.
4. Requires an active membership record whose subject matches the authenticated principal and whose tenant/business-unit match the requested scope.
5. Independently compares the returned membership tenant and business-unit IDs with the requested IDs; mismatches are rejected even if a repository implementation returns an incorrect record.
6. Issues `_AdapterIssuedTenantMembershipEvidence` and passes it to the scope factory.

The authentication provider and membership repository are injected dependencies. Their production implementations are not included in Gate 0.1.2 and must be created by deployment-controlled startup wiring and passed to the composition root. Request handlers and ordinary application modules must receive the already-composed adapter; they must not instantiate the adapter or call the composition factory with substitute providers. The repository must be authoritative and server-side; it must not simply echo request-controlled membership claims. Dependency injection is a trust decision: fabricated providers invalidate the contract.

## Enforced source construction boundary

The AST architecture test resolves imported names and module aliases, including simple name assignments, tuple/list destructuring, recursively nested literal tuple/list indexing (including chained indexing and assigned intermediate containers), and both branches of conditional expressions, and rejects calls to `TrustedTenantContextAdapter` or `build_tenant_context_adapter()` outside `cephas_logisticsos.composition`. It also rejects star imports from the trusted adapter and composition modules outside the composition root. For unsupported expressions, a conservative reference check marks assigned aliases indeterminate when their expression or retained container value references a known trusted constructor, factory, trusted module, or already-indeterminate alias. Attribute and subscript assignments that store a known trusted reference taint the root storage object; subsequent attribute reads, chained attribute reads, and dynamic subscript reads from that object are treated as indeterminate. This covers statically visible object-attribute assignment and dictionary/list item mutation without claiming general heap or Python runtime analysis. Calling an indeterminate alias is rejected. This is intentionally targeted: unrelated indirect calls and locally shadowed safe names remain allowed. Regression fixtures cover all previously accepted alias forms plus dynamic indexing into a trusted literal container, reflection through an imported trusted module alias, unresolved dictionary/container lookup, attribute storage and retrieval, chained attribute storage, dictionary/list item mutation and retrieval, propagation through a second alias, and production-source scan equivalents. A separate fixture verifies that the exception remains limited to the exact `cephas_logisticsos.composition` module. Expressions that never syntactically or statically reference a known trusted symbol (for example, an arbitrary dynamic import or runtime lookup by an externally supplied string) remain outside this bounded source guard and require separate controls.

This control is intentionally a source-level architecture rule for ordinary statically expressed Python code. It is not a runtime authorization mechanism and does not prevent arbitrary same-process code from dynamically obtaining callables, monkey-patching modules, or executing code outside the reviewed source tree. Deployment startup wiring remains the trusted composition point.

## Lexical-scope-aware alias resolution

The source guard maintains independent symbol environments for module, function, and class scopes. Local assignments, imports, parameters, and other statically identified bindings shadow inherited names in that scope without mutating the parent environment. Nested functions are analyzed against their enclosing function/module bindings; methods are not treated as closing over the class namespace.

Regression coverage includes:
- A function-local assignment shadowing the trusted constructor while a module-level constructor call remains detectable.
- A function-local assignment shadowing the trusted factory while a module-level factory call remains detectable.
- Nested function shadowing and local imports.
- Class-body bindings that do not overwrite module-level constructor/factory imports.
- Production-source scan coverage for the same patterns, including module-level calls after local shadowing.
- A negative control proving a local helper call through a locally shadowed safe name is not misclassified as a trusted constructor call.

The resolver is a conservative static architecture check, not a Python sandbox or complete interpreter. Dynamic reflection, dynamic code execution, arbitrary runtime mutation, and complex global/nonlocal rebinding are outside its guarantee and require separate runtime/security controls.

## Enforced source import boundary

The private evidence issuer and capability live only in `tenancy/_trusted_adapter.py`. The scope factory imports only the evidence marker needed for exact-type validation. A source-level AST architecture test rejects direct imports, package-submodule imports, relative package-submodule imports, aliases, and attribute access to the private adapter module from other production modules and is run as part of the ordinary pytest CI suite.

This is a Python application architecture guard, not a security sandbox. Code with arbitrary execution inside the same process can use reflection, dynamic imports, monkey-patching, or other runtime techniques to bypass Python-level conventions. The guard prevents accidental/direct source-level coupling and regression; it is not a cryptographic or process-isolation boundary.

### R-20 — alias-aware storage and mutation analysis

The source guard additionally maintains a bounded, lexical-scope-local may-alias model for statically visible storage names. Direct name aliases and names assigned from statically rooted attribute/subscript expressions are associated with a shared abstract storage identity. When a trusted constructor, factory, trusted module, or already-indeterminate reference is written through an attribute or subscript, the guard marks the shared storage identity indeterminate and propagates that state to known aliases. It then revisits assigned names so callables retrieved from a tainted registry are also rejected at their call sites.

The guard recognises the targeted mutation forms `dict.update()`, `list.append()`, `list.extend()`, `setdefault()`, `__setitem__()`, and the builtin `setattr()` when their statically visible arguments contain a trusted reference. A mutation through a statically rooted receiver taints the receiver's abstract storage identity. A trusted write or mutation through an unsupported receiver/root (for example, `get_registry().factory = trusted_factory` or `get_registry().update(...)`) produces an explicit indeterminate finding and fails the construction-boundary check closed.

The model is intentionally conservative and bounded. It does not implement general Python heap/object-identity analysis, control-flow-sensitive points-to analysis, interprocedural alias analysis, arbitrary descriptor/property semantics, every user-defined mutator, reflection with no statically visible trusted reference, runtime monkey-patching, dynamic imports, or arbitrary same-process code execution. The static alias grouping may conservatively taint related names and is not proof of runtime object identity. Reassignment is handled for the final statically visible name binding in the analyzed scope; complex control-flow-dependent rebinding remains outside the guarantee. These limits must not be described as a runtime authorization or isolation boundary.


## Implemented in this gate

- Immutable public principal and membership data carriers with strict field validation.
- Dedicated trusted adapter contract separating credential validation from authoritative membership lookup.
- Adapter-issued evidence terminology; evidence itself is not proof unless the configured adapter fulfilled its responsibilities.
- Scope factory accepts only the adapter evidence type; direct scope construction remains disabled.
- CI architecture tests restricting production source imports of the private evidence module and restricting trusted-adapter construction and composition-factory calls to the designated composition root, including ordinary aliases.
- Regression tests for successful adapter flow, untrusted public carriers, unauthenticated principal, inactive/missing membership, mismatched subject, wrong returned tenant, wrong returned business unit, package and relative import bypasses, aliased constructor and factory-call bypasses, composition-root construction boundary, identifier validation and immutability.

## Definition-time expression scanning

The source-level trusted-boundary resolver scans function and class definition-time expressions in the enclosing lexical scope, while analyzing function and class bodies in their own scope. Covered expressions include function decorators, positional and keyword defaults, argument and return annotations, class decorators, base expressions and class keyword values. Generic type-parameter nodes are traversed where exposed by the running Python AST.

Regression coverage includes trusted constructor calls in function defaults and class bases, trusted factory calls in decorators, production-source scanner equivalents, safe-expression negative controls, and preservation of the designated composition-root exception.

This remains a bounded AST source guard, not a compiler-equivalent Python scope analyzer. A known trusted reference flowing through an unsupported expression is marked indeterminate and rejected if called; the check does not claim to resolve arbitrary dynamic imports, reflection without a statically visible trusted reference, runtime monkey-patching, or same-process arbitrary code execution. These remain outside the accepted guarantee and require separate controls.

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


## R-21 — standard-library storage mutation and retrieval remediation

R-21 extends the bounded source guard to cover standard-library operations that move trusted references into and out of tainted storage.

Supported mutation coverage includes:
- operator.setitem(container, key, value), including module aliases and imported-symbol aliases, with the first argument treated as the mutated storage receiver.
- Existing targeted method mutators and builtin setattr().

Supported retrieval coverage includes:
- operator.getitem(container, key), including module aliases and imported-symbol aliases.
- builtin getattr(receiver, name), including literal and dynamic attribute names.
- Propagation from a tainted receiver to a name assigned from the retrieval result.
- Rejection when a retrieval expression is invoked directly as the callable.

Dynamic keys and attribute names do not reduce the taint of an already-tainted receiver. The production-source scanner must include complete mutation → retrieval → invocation fixtures and safe negative controls for unrelated storage and safe factories.

This remains a deliberately bounded static analysis. It does not claim to model arbitrary user-defined functions, all Python standard-library APIs, general heap identity, or runtime reflection without a statically visible trusted reference. Exact-head CI and independent reassessment are required; R-21 implementation or green CI alone does not constitute Gate 0.1.2 acceptance.
