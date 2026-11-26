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

## R-22 — canonical builtin storage mutation and retrieval

R-22 extends the bounded source guard's canonical symbol resolver to recognise the builtin mutation and retrieval operations used by R21-01.

Supported builtin identity forms include:
- Direct unshadowed `setattr()` and `getattr()` references.
- Module-qualified `builtins.setattr()` and `builtins.getattr()`, including aliases of the `builtins` module.
- Imported builtin symbols such as `from builtins import setattr as put`.
- Simple assignment aliases of imported or module-qualified builtin references.
- Retrieval propagation and direct retrieval-expression invocation checks using the canonical builtin identity.

Lexical shadowing is preserved: a local or parameter binding named `setattr` or `getattr` is not automatically treated as the builtin. The regression suite must assert that prohibited final callable invocations are rejected, cover the production-source scanner, and retain safe negative controls.

This is a targeted canonical resolver for the reviewed builtin operations, not general Python name resolution or a complete model of monkey-patching, dynamic imports, reflection, arbitrary callables, or same-process execution. Exact-head CI and independent reassessment remain mandatory. R-22 does not establish overall Gate 0.1.2 acceptance.



## R-23 — executable trusted-boundary enforcement

The bounded trusted-boundary AST analyser is maintained in
`src/cephas_logisticsos/security/trusted_boundary.py`, not in the test module.
It exposes a dedicated build-time command:

```bash
python -m cephas_logisticsos.security.trusted_boundary --source src
```

The command scans Python modules beneath the selected source root and exits non-zero
when a trusted tenant-context adapter constructor or composition factory is called
outside the approved composition root. It reports module, source line and violation
classification. Unit tests import this maintained implementation; they do not own a
separate copy of the scanner.

The CI workflow invokes the command after installing the package and before lint,
type checking and pytest. Pull-request triggers now include `security/**` base
branches as well as the existing main and feature branches. This closes the prior
workflow-trigger omission for stacked security PRs.

R-23 also adds CLI pass/fail tests, storage replacement regression fixtures and a
parameter-shadowing negative control. The storage model remains conservative and
bounded: replacement after a trusted write may continue to be classified as
indeterminate. This is intentional fail-closed behaviour, not proof of full Python
runtime alias semantics.

**Release-control limitation:** a workflow step alone does not establish GitHub
branch protection or required-status-check enforcement. Repository administration
must configure the relevant target branches to require the CI job before merge, and
deployment must consume only artifacts produced by the approved workflow. The
current GitHub branch metadata reviewed for this work reports protection disabled;
therefore R-23 does not claim that branch protection is configured.

R-23 is implementation work only. It does not establish PostgreSQL RLS, database
tenant/business-unit isolation, production identity integration, authoritative
membership, central authorization, background-job isolation, or production
certification. Independent reassessment remains required.


## R-24 — fail-closed source discovery and scanner resilience

R-24 addresses the independent reassessment findings that the R-23 source walker could
omit importable modules beneath symlinked package directories and could report success
for an empty or unrelated source root.

The scanner now applies an explicit **no-symlinks** policy beneath the approved source
root. It rejects a symlinked source root, production package root, any symlinked
directory, and any symlinked file before reading Python modules. It does not follow
symlinks. This prevents a symlinked package directory from exposing importable source
that is absent from the scanner's enumerated source set, and avoids traversal cycles
and path-escape decisions.

The scanner also requires:
- An existing, non-symlink source directory.
- The expected `cephas_logisticsos/` production package directory.
- A regular, non-symlink `cephas_logisticsos/__init__.py`.
- At least one discovered Python module, including a module beneath the expected
  production package.

Filesystem walk errors, file-read/decoding errors, syntax errors, invalid source
layouts, and unexpected scanner exceptions cause the CLI to emit an argparse error
and exit non-zero. The CLI does not print a successful scan result unless source
discovery and analysis complete.

Regression tests cover a symlinked package directory containing a prohibited
trusted-adapter construction, a symlinked Python file, empty and unrelated roots,
a package missing its initializer, a missing source root, syntax errors, filesystem
walk errors, and unexpected scanner failures. Existing R-18 through R-23 alias,
storage, shadowing and policy fixtures remain in the suite.

The CI pull-request branch filter now includes `hardening/**`, matching the existing
push filter.

**Scope qualification:** this is a bounded source-tree architecture guard. The
no-symlink policy applies to filesystem entries beneath the supplied source root;
it does not claim to prove every possible runtime import mechanism, dynamically
generated module, or code loaded from outside that root. The expected package-root
validation makes the intended production scan target explicit. Exact-head CI and
independent reassessment remain required. R-24 does not implement branch protection,
required status checks, deployment restrictions, PostgreSQL RLS, production
authentication, authoritative membership, centralized authorization, or the wider
tenant-isolation controls.

 
## R-25 — source-root identity and stable scan workspace

R-25 closes the conditional hardening requirements from the independent R-24
reassessment.

The scanner validates every existing component of the supplied source-root path,
not only its final component. Any symlink in the absolute source-root path is
rejected. Parent-directory (`..`) traversal in the supplied path is also rejected,
so lexical path normalization cannot conceal a symlinked ancestor.

The scanner's filesystem contract requires a quiescent source tree for the entire
scan. A caller must prevent concurrent mutation while scanning. In the GitHub
Actions quality job, the scanner is deliberately invoked immediately after
checkout and Python setup, before dependency installation or execution of project
build code. The workflow removes write permissions from `src` before invoking
the scanner. This is an operational immutability control on the isolated CI
workspace; it is not protection against a privileged or concurrent process that
deliberately changes permissions or mutates the runner filesystem. Such a
process is outside the stated CI threat model. Environments that permit
concurrent untrusted writers must provide a separate immutable snapshot or
stronger descriptor-based filesystem isolation.

Regression tests directly cover symlinked source roots, package roots, package
initializers, symlink cycles, symlinked source-root ancestors, invalid UTF-8 and
file-read failures. All CLI failure cases must exit non-zero. Existing R-18
through R-24 regression tests remain required.

R-25 remains a bounded source-tree architecture control. It does not establish
runtime tenant isolation, PostgreSQL RLS, production authentication, authoritative
membership, centralized authorization, background-job isolation, branch
protection or production certification.
