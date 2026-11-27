# T-02 — PostgreSQL tenant isolation architecture

Status: proposed, documentation only; implementation and independent acceptance pending.
Baseline: R-26 0522c53560b4082b08a0fb379ca50f137253c054 (PR #11). Gate 0.1.2 remains unaccepted.

## Baseline and scope
The inspected architecture, security baseline, package metadata, composition root and tenant contracts establish a modular monolith, opaque identifiers, trusted adapter interfaces and a bounded static scanner. No production database implementation is established by this evidence. Main-to-baseline comparison reports 145 commits ahead, zero behind and 16 changed files; it is not a complete tree inventory. Preserve the accepted stack and do not merge without explicit authorization. The original roadmap places security foundation at Gate 0.4; T-02 is proposed prerequisite work for the broader Gate 0.1.2 acceptance, subject to explicit governance reconciliation before implementation.

## Decisions proposed
- PostgreSQL 16 or 17, Psycopg 3, versioned SQL migrations; supported versions verified in real database CI.
- Preserve opaque case-sensitive 1–128 character identifiers and existing validation semantics; use text with explicit constraints and deterministic collation, not implicit UUID conversion.
- Tenant registry and business-unit registry with composite tenant/business-unit keys. Every scoped operational row carries both identifiers; composite foreign keys include scope to prevent cross-scope references.
- Separate non-login owner, migration identity, restricted runtime identity and narrowly scoped membership lookup identity. Runtime must not own tables, inherit owner privileges, have BYPASSRLS, superuser, role administration, TRUNCATE or DDL privileges. No broad PUBLIC grants. Administrative roles remain outside the runtime threat boundary.
- Enable and FORCE RLS on scoped tables. Explicit SELECT, INSERT, UPDATE, DELETE policies with USING and WITH CHECK as applicable; no permissive broad policy. Missing, empty or malformed context denies access. Scope changes through UPDATE are forbidden.
- Bind subject, tenant and business unit only from trusted adapter output, in an explicit transaction using parameterized transaction-local settings. Never derive context from raw request fields. No session-level scope or autocommit data access. Rollback on failure, reset/verify pooled connections before reuse, discard connections on cleanup failure.
- Custom PostgreSQL settings are not unforgeable credentials: the runtime SQL identity can change them. RLS with these settings protects against omitted filters and accidental scope mistakes, not arbitrary SQL execution or compromised runtime identity. Restrict SQL execution to reviewed parameterized repository operations; no user SQL, no raw connection exposure. Evaluate stronger database-authenticated scope binding before claiming resistance to compromised runtime SQL.
- Membership lookup must be server-authoritative, restricted and separately authorized; no circular dependency on an unverified tenant scope. T-03 defines identity validation and membership revocation semantics; T-04 implements transaction/pool boundary. T-02 test harness must not be presented as production authentication.
- No SECURITY DEFINER functions by default; any exception requires explicit grants, fixed safe search_path, qualified objects and independent review. Avoid owner-executed views bypassing RLS; test effective runtime privileges and policy catalog.
- Customer-controlled deployment, offline signed licensing separate from authorization. No customer credentials or live carrier integration.

## Implementation sequence
1. Review this architecture and reconcile gate scope; complete inventory and branch-protection evidence.
2. Add migrations for roles, schemas, tenant and business-unit keys and a minimal scoped test entity; no carrier domain expansion.
3. Add real PostgreSQL integration harness with distinct migration/runtime identities; test clean installation and upgrade behavior.
4. Implement and test policies and privilege boundaries. Keep runtime transaction binding provisional until T-04.
5. Run existing scanner, lint, format, types, unit and real database integration tests in one validated CI cycle. Integration tests must fail, not silently skip, when required database is unavailable.
6. Independent exact-commit review; no merge or Gate 0.1.2 acceptance implied.

## Acceptance matrix
- Valid scope: allowed CRUD within tenant and business unit.
- Different tenant and same-tenant different unit: reads invisible; inserts and scope-changing updates rejected; update/delete cannot affect foreign rows.
- Missing/empty/malformed scope: no data access; writes rejected.
- Composite FK rejects cross-scope references; test uniqueness and error leakage boundaries.
- Runtime cannot disable RLS, alter policy, assume owner, truncate, or bypass through inherited roles; verify catalog and effective privileges.
- Transaction rollback, commit, pool reuse and concurrent requests: no residual scope; full pool tests in T-04.
- Test membership revocation and unauthorized identity in T-03/T-05; background jobs, exports, caches and object storage remain separate work packages.
- Document residual risks including privileged DB administrators, arbitrary runtime SQL, side channels and deployment misconfiguration.

## Governance
Architecture only. No runtime implementation, production certification, branch protection verification, Maersk authorization or full repository inventory is claimed. PR #11 and prior stack remain unmerged unless separately authorized. R-26 acceptance is limited to reviewed scanner regression scope.

## T-02.1 design refinement — proposed for independent review

This section supersedes the provisional shared runtime role/custom-setting scope binding above. It does not grant implementation authorization or owner approval of the roadmap.

### A01 — database-authenticated tenant and business-unit binding
Use one restricted PostgreSQL login identity per tenant/business-unit pair for the first implementation. The database authenticates the login directly. A protected binding registry maps its authenticated session_user to exactly one tenant/business-unit pair. Use FORCE RLS on the registry, read-only access to the login's own mapping, no runtime registry writes, and fail closed for missing or disabled mappings. Operational policies require the bound pair and matching well-formed transaction-local scope; changing custom settings cannot widen the database login's permitted pair. The subject setting remains trusted application context, not database-authenticated end-user proof. No cross-scope login membership, arbitrary role assumption, shared privileged connection or user SQL. A trusted connection broker selects the pool only after verified identity/membership and verifies session_user and binding before work. Pool keys include deployment, database and scoped identity. A compromised broker/application with access to multiple credentials, privileged DBA, and malicious same-scope SQL remain outside this isolation guarantee. Evaluate credential/pool cardinality and operating cost before scale-out. Do not advertise end-user-level database authentication.
Provisioning must prevent stale mappings and role-name reuse: opaque unique login names, disable binding and revoke login, drain/terminate affected sessions, remove binding and retire credential on deprovisioning. Restore/rotation procedures must revalidate all identity bindings. No raw customer IDs in role names.

### A02 — proposed effective privilege matrix
- Bootstrap administrator: creates roles/database, not an application credential.
- Migration login: tightly controlled owner assumption only for reviewed migrations; no application pooling.
- Object owner: NOLOGIN; owns schemas, tables and policies; no application membership.
- Scoped runtime login: restricted operational CRUD (column-specific UPDATE excluding scope keys); own binding read only. NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION. No ability to assume another scope, membership reader, migration or owner.
- Membership lookup login: read only on separately protected authoritative membership path; no operational data or registry modification. Restrict access to trusted provider; lookup cannot establish end-user authentication by itself.
- Registry provisioner: separately controlled lifecycle operations; not a runtime login.
- PUBLIC: explicitly revoke unnecessary database CONNECT/TEMP, schema CREATE/USAGE, and object privileges; grant only required rights, set safe schema-qualified access and creator-specific default privileges. No blanket grants to existing or future tables. Test effective grants and transitive role memberships using actual logins. Any shared NOLOGIN privilege role must not allow changing login scope.

### A03/A04 — integrity and revocation
Use C-collated opaque identifiers with 1–128 ASCII characters matching the Python contract. Include tenant and business unit in operational primary, unique and foreign keys; prevent scope updates with column privileges. Registry writes require separate provisioning. PostgreSQL referential-integrity checks can bypass RLS; avoid global operational uniqueness and sanitize constraint diagnostics. Do not claim elimination of all timing/error side channels.
The policy must require an active database binding plus syntactically valid matching transaction context, including subject. T-03 must define authoritative membership validation, recheck at transaction start, revocation handling and maximum in-flight authorization lifetime. A transaction already running under a prior snapshot is not instantly revoked. T-04 must implement scoped pool routing, cleanup and cancellation/discard on failure. No application use until T-03/T-04 are verified.

### A05 — required evidence
First target PostgreSQL 16; 17 is unqualified until separately tested. Test direct authentication as each scope login, cross-scope setting changes, SET ROLE/session-authorization escalation denial, missing/disabled mapping, cross-scope CRUD, column privileges, default privileges, RLS catalog and constraint behaviour. Require a real database in integration CI; no silent skips. Verify migrations from clean database, rollback and upgrade. Preserve the existing R-26 checks. Test subject forgery within a scope as an explicit limitation, not a passed end-user authentication control.

### A06 — governance
Full recursive inventory, branch protection and required checks remain unverified. Proposed reconciliation: runtime isolation is a prerequisite for Gate 0.1.2; Gate 0.4 retains broader hardening and revalidation. Owner approval and independent design acceptance remain pending; ROADMAP.md is unchanged. No implementation or merge authority.

Technical references: PostgreSQL 16 documentation, session authorization (https://www.postgresql.org/docs/16/sql-set-session-authorization.html), system information (https://www.postgresql.org/docs/16/functions-info.html), row security (https://www.postgresql.org/docs/16/ddl-rowsecurity.html), and privileges (https://www.postgresql.org/docs/16/ddl-priv.html).
