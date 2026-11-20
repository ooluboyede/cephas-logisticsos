# Gate 0.1.2 — Core Tenant Context Contract

**Status: remediation submitted for CI and independent reassessment; not accepted.**

## Scope

Introduce immutable domain contracts for authenticated principals, trusted
server-side tenant membership records and tenant/business-unit request scope.

## Security properties implemented in this gate

- Reject unauthenticated principals.
- Reject inactive tenant memberships.
- Reject principal/membership subject mismatches.
- Validate opaque identifier syntax and reject whitespace or unsafe characters.
- Keep principal, membership and scope value objects immutable.
- Disable the public TenantScope constructor; the supported application
  construction interface is TenantScope.from_verified_membership.
- Reject unexpected principal and membership object types at the factory boundary.

## Trust boundary and limitations

The principal must be created by a trusted authentication adapter. Membership
must be resolved by a trusted server-side repository or identity adapter against
the authoritative customer-controlled store. Request headers, query parameters
and request-body fields are not authoritative sources for either object.

Python does not provide an absolute private-constructor security boundary.
Advanced introspection or low-level object allocation can bypass ordinary
construction conventions. Downstream authorization must not trust an object
solely because it is a TenantScope instance.

This gate does not implement authentication, trusted membership lookup,
authorization policy evaluation, PostgreSQL Row-Level Security, transaction-
scoped database context, or tenant isolation for jobs, caches, exports, storage
or ML pipelines. The Python value objects are not a security boundary by
themselves.

Those controls remain mandatory in subsequent security and persistence gates.
Trusted authentication and membership adapters must exist before these
contracts are used in a running API.

## Acceptance evidence

- Positive scope construction and fail-closed rejection tests.
- Direct-construction regression test for TenantScope.
- Wrong-type and malformed-input tests.
- Boolean validation, identifier boundary and immutable-object tests.
- Ruff lint and format checks.
- Mypy strict type checking.
- Full test suite and coverage threshold.
- Independent review of the remediated commit and trust-boundary limitations.
