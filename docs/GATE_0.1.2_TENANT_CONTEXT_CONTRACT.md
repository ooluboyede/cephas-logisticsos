# Gate 0.1.2 — Core Tenant Context Contract

**Status: implementation submitted for CI and review; not accepted.**

## Scope

Introduce immutable domain contracts for authenticated principals, trusted
server-side tenant membership records and tenant/business-unit request scope.

## Security properties intended

- Reject unauthenticated principals.
- Reject inactive tenant memberships.
- Reject principal/membership subject mismatches.
- Validate opaque identifier syntax and reject whitespace or unsafe characters.
- Keep scope immutable after construction.
- Require membership to originate from a trusted server-side lookup, never from
  client-controlled headers or request bodies.

## Explicit limitations

This gate does **not** implement authentication, authorization policy evaluation,
PostgreSQL Row-Level Security, transaction-scoped database context, or tenant
isolation for jobs, caches, exports, storage or ML pipelines. The Python value
objects are not a security boundary by themselves.

Those controls remain mandatory in subsequent security and persistence gates. A
trusted membership lookup must be implemented before this contract is used in a
running API.

## Acceptance evidence

- Unit tests for valid scope construction and fail-closed rejection cases.
- Ruff lint and format checks.
- Mypy strict type checking.
- Full test suite and coverage threshold.
- Review of trust-boundary limitations before acceptance.
