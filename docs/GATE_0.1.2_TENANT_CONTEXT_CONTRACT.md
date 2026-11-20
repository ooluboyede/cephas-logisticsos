# Gate 0.1.2 — Core Tenant Context Contract

**Status: provenance-contract remediation submitted for CI and independent reassessment; not accepted.**

## Scope

Define immutable principal and membership data carriers, an internal trusted-adapter evidence issuance boundary, and an immutable tenant/business-unit scope contract.

## Public data carriers are not proof

`AuthenticatedPrincipal` and `TenantMembership` are public immutable data carriers. Their constructors validate field shape and values only.

Constructing either object does **not** prove that:
- authentication actually succeeded;
- the subject identifier came from a validated credential;
- membership exists in the authoritative customer-controlled store; or
- the membership is authorized for the requested operation.

These objects must never be accepted directly as proof of identity or membership by application handlers or the scope factory.

## Trusted-adapter evidence boundary

The scope factory accepts only the internal `_VerifiedTenantMembership` evidence type. It rejects ordinary `AuthenticatedPrincipal` and `TenantMembership` instances, including instances constructed with matching identifiers and `True` flags.

The internal `_issue_verified_membership_from_trusted_adapter` function is a private package interface reserved for the configured authentication and membership adapter. It requires the module's private adapter capability and validates:
- exact principal and membership data-carrier types;
- authenticated principal state;
- active membership state;
- matching subject identifiers; and
- identifier syntax.

The trusted adapter is responsible for obtaining the principal from a validated authentication result and retrieving membership from an authoritative server-side repository. It must not derive either value solely from request headers, query parameters, request-body fields or other client-controlled values.

Application request handlers must receive a `TenantScope` produced by the configured trusted adapter flow. They must not import or call private evidence-issuance interfaces.

## Important security qualification

This is an application-interface and accidental-misuse boundary, not a sandbox against malicious code execution inside the same Python process. Python private names, module state and object construction can be bypassed by sufficiently privileged in-process code. The private capability is not a cryptographic credential and must not be represented as one.

Before a running API uses this contract, the application composition root must wire the actual trusted authentication adapter and authoritative membership repository. The current gate defines that boundary; it does not implement those integrations.

## Security properties implemented in this gate

- Immutable principal and membership data carriers with strict field validation.
- Public principal and membership objects are not accepted directly by the scope factory.
- Internal evidence issuance is capability-gated and reserved for trusted adapter code.
- Scope factory accepts only the internal evidence type.
- Evidence issuance checks authenticated state, active membership and subject equality.
- Direct `TenantScope` construction is disabled.
- Tests prove caller-created public principal and membership objects cannot be passed to the scope factory as verified evidence.
- Negative, boundary, wrong-type and immutability tests cover the contract.

## Explicitly not implemented

This gate does not implement:
- production authentication or identity-provider integration;
- an authoritative membership repository or database lookup;
- authorization policy evaluation;
- PostgreSQL Row-Level Security (RLS);
- transaction-scoped database context or connection-pool isolation;
- cross-tenant isolation for background jobs, exports, caches or storage;
- tenant-isolated ML training or model operations;
- production penetration testing or deployment certification.

These remain mandatory later-gate controls. The private capability must not be used as a substitute for authentication, authorization, database-enforced tenant/business-unit isolation or independent security testing.

## Acceptance evidence

- Tests proving caller-created public principal/membership objects are rejected by the scope factory.
- Tests proving the evidence constructor rejects callers without the private capability.
- Tests covering trusted-issuer validation and scope creation.
- Ruff lint and format checks.
- Mypy strict type checking.
- Full test suite and configured coverage threshold.
- Independent reassessment of the exact remediated commit.
