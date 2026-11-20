# Security Baseline

**Status: requirements baseline; implementation and certification pending.**

## Mandatory controls

### Tenant and business-unit isolation
- Tenant and business-unit identity is derived from authenticated server-side identity and verified membership, never trusted from arbitrary client-supplied headers or request bodies.
- Database-enforced isolation is mandatory. PostgreSQL Row-Level Security (RLS) is the default design where PostgreSQL is used.
- Database roles, transaction-scoped context and policies must fail closed.
- Background jobs, exports, reports, caches, search indexes, object storage and ML pipelines must preserve the same isolation boundary.
- Isolation tests must include cross-tenant and cross-business-unit negative cases.

### Identity and authorization
- Enforce least privilege and deny by default.
- Require MFA for privileged access; support FIDO2/WebAuthn where the identity environment permits.
- Separate authentication, authorization and tenant resolution.
- Use short-lived credentials and auditable privileged actions.

### Cryptographic trust
- TLS 1.3 is the target for external transport; mTLS is required for service-to-service links where supported by the deployment architecture.
- Model artifacts must be integrity-checked and publisher-signature-verified before any deserialization or execution.
- Ed25519 is the preferred model publisher-signing algorithm, subject to key-management review.
- Private signing keys must be held outside the application repository in an approved KMS/HSM or customer-controlled secret store.
- Webhooks must use authenticated signatures, timestamp freshness windows and replay/idempotency controls.

### Audit and monitoring
- Record security-relevant access, authorization failures, privileged actions, model publication and licence events.
- Audit records must be tamper-evident and protected from ordinary application-user modification.
- Sensitive data access and exports require explicit authorization and traceability.
- Never log credentials, secrets, raw payment data or unnecessary personal data.

### Licensing
- Annual signed licensing must bind customer, tenant, edition, modules, environment, validity and approved limits.
- Offline validation must fail closed on invalid, expired, malformed or untrusted licences.
- Licence verification public keys may be distributed; private signing keys must never be shipped with the product.
- Licensing must not be used as a substitute for authentication or authorization.

### Secure development
- Dependency, secret, static-analysis and test checks are CI gates.
- Pin and review dependencies; generate an SBOM for release candidates.
- Threat model every new external integration and privileged workflow.
- No production-readiness claim before independent security review and documented acceptance.
